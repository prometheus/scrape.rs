// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::future::Future;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::write::GzDecoder;
#[cfg(feature = "arrow")]
use prometheus_expfmt::arrow::DecodeError;
use prometheus_expfmt::format::{EscapingScheme, FMT_TEXT, Format, FormatType, response_format};
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, USER_AGENT};

use crate::scrape::{BodyBufferPool, PooledBodyBuffer, ScrapeConfig, ScrapeTarget};

const SCRAPE_TIMEOUT_HEADER: &str = "X-Prometheus-Scrape-Timeout-Seconds";

/// Errors produced while validating configuration, fetching HTTP payloads, or decoding scrapes.
#[derive(Debug, thiserror::Error)]
pub enum ScrapeError {
    /// Invalid scrape pool or target configuration.
    #[error("invalid scrape configuration: {0}")]
    InvalidConfig(String),
    /// Transport or request construction failure from `reqwest`.
    #[error("HTTP scrape request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Target returned a non-2xx HTTP status code.
    #[error("target returned non-2xx HTTP status {status}")]
    UnexpectedStatus {
        /// HTTP status code returned by the target.
        status: u16,
    },
    /// Uncompressed response body exceeded [`ScrapeConfig::max_body_bytes`].
    #[error("scrape response body exceeds max_body_bytes ({limit_bytes} bytes)")]
    BodyTooLarge {
        /// Configured byte cap that was exceeded.
        limit_bytes: usize,
    },
    /// Malformed `gzip` stream on a compressed target response.
    #[error("failed to decompress gzip scrape response: {0}")]
    Decompress(String),
    /// Unsupported `Content-Encoding` returned by target.
    #[error("unsupported scrape Content-Encoding {encoding:?}")]
    UnsupportedEncoding {
        /// Raw `Content-Encoding` header value.
        encoding: String,
    },
    /// Scrape exceeded [`ScrapeConfig::scrape_timeout`].
    #[error("scrape timed out after {timeout:?}")]
    TimedOut {
        /// Configured per-scrape timeout.
        timeout: Duration,
    },
    /// Exposition payload failed syntax or Arrow decoding.
    #[cfg(feature = "arrow")]
    #[error("failed to decode exposition payload: {0}")]
    Decode(#[from] DecodeError),
}

/// Completed HTTP target fetch holding a pooled, uncompressed exposition buffer and timing metadata.
#[derive(Debug)]
pub struct FetchedScrape {
    /// Uncompressed exposition bytes stored in a pooled reusable `Vec<u8>`.
    pub body: PooledBodyBuffer,
    /// Negotiated exposition wire [`Format`].
    pub format: Format,
    /// Unix epoch timestamp in milliseconds recorded immediately after the body finished reading.
    pub scrape_timestamp_ms: i64,
    /// End-to-end HTTP request + body read wall-clock duration.
    pub fetch_duration: Duration,
    /// Compressed (wire) byte count read from the HTTP socket.
    pub wire_bytes: usize,
}

impl FetchedScrape {
    /// Uncompressed exposition payload length in bytes.
    #[must_use]
    pub fn uncompressed_bytes(&self) -> usize {
        self.body.len()
    }
}

/// Asynchronous single-target HTTP or synthetic fetcher used by the scrape scheduler.
///
/// Intentionally omits a `Send` bound on the returned future so thread-per-core `!Send` runtimes
/// (such as Tokio `LocalSet` workers in `otel-arrow`) can drive custom or local fetchers without
/// synchronization overhead.
pub trait TargetFetcher {
    /// Fetches `target`, acquiring a [`PooledBodyBuffer`] from `pool` only once payload bytes are
    /// ready to be written.
    fn fetch(
        &self,
        target: &ScrapeTarget,
        pool: &BodyBufferPool,
    ) -> impl Future<Output = Result<FetchedScrape, ScrapeError>>;
}

/// Builds a Prometheus-compatible `Accept` header value for text and OpenMetrics scraping.
///
/// Mirrors the quality weights in Prometheus `scrape.acceptHeader` while advertising the
/// configured [`EscapingScheme`] when non-default (`allow-utf-8`, `dots`, or `values`).
#[must_use]
pub fn build_accept_header(enable_open_metrics: bool, escaping: EscapingScheme) -> String {
    let esc_param = match escaping {
        EscapingScheme::EscapeUnderscores => String::new(),
        other => format!(";escaping={}", other.as_str()),
    };
    if enable_open_metrics {
        format!(
            "application/openmetrics-text;version=1.0.0{esc_param};q=0.6,\
             application/openmetrics-text;version=0.0.1{esc_param};q=0.5,\
             text/plain;version=0.0.4{esc_param};q=0.4,\
             */*;q=0.1"
        )
    } else {
        format!("text/plain;version=0.0.4{esc_param};q=0.4,*/*;q=0.1")
    }
}

/// Formats `timeout` in seconds for the `X-Prometheus-Scrape-Timeout-Seconds` request header,
/// trimming trailing fractional zeros to match Go `strconv.FormatFloat(..., 'f', -1, 64)`.
#[must_use]
pub fn format_scrape_timeout_seconds(timeout: Duration) -> String {
    let secs = timeout.as_secs();
    let nanos = timeout.subsec_nanos();
    if nanos == 0 {
        return secs.to_string();
    }
    let mut frac = format!("{nanos:09}");
    let trimmed_len = frac.trim_end_matches('0').len();
    frac.truncate(trimmed_len);
    format!("{secs}.{frac}")
}

/// Resolves a response `Content-Type` header into an [`expfmt::format::Format`], falling back to
/// Prometheus classic text (`text/plain; version=0.0.4; charset=utf-8`) when `Content-Type` is
/// omitted or unrecognized, and supplying `charset=utf-8` when omitted on OpenMetrics 1.0/0.0.1.
#[must_use]
pub fn resolve_scrape_format(content_type: Option<&str>) -> Format {
    let Some(raw) = content_type.map(str::trim).filter(|s| !s.is_empty()) else {
        return Format::from(FMT_TEXT);
    };
    let parsed = response_format(raw);
    if parsed.format_type() != FormatType::Unknown {
        return parsed;
    }

    // Non-compliant OpenMetrics exporters occasionally omit `charset=utf-8`; retry with it before
    // falling back to Prometheus text `0.0.4`.
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("application/openmetrics-text") && !lower.contains("charset=") {
        let with_charset = format!("{raw}; charset=utf-8");
        let retried = response_format(&with_charset);
        if retried.format_type() != FormatType::Unknown {
            return retried;
        }
    }

    Format::from(FMT_TEXT)
}

/// Production [`TargetFetcher`] backed by a shared [`reqwest::Client`].
#[derive(Clone, Debug)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
    accept_header: String,
    timeout_header: String,
    user_agent: String,
    scrape_timeout: Duration,
    enable_compression: bool,
    max_body_bytes: usize,
}

impl ReqwestFetcher {
    /// Builds a new [`ReqwestFetcher`] with a default `reqwest::Client` configured from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError`] if `config` fails validation or the HTTP client cannot be built.
    pub fn new(config: &ScrapeConfig) -> Result<Self, ScrapeError> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.scrape_timeout)
            .build()?;
        Self::with_client(client, config)
    }

    /// Wraps an caller-supplied [`reqwest::Client`] (for example, one built from custom TLS or
    /// proxy settings) with scrape request headers and limits from `config`.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `config` fails validation.
    pub fn with_client(
        client: reqwest::Client,
        config: &ScrapeConfig,
    ) -> Result<Self, ScrapeError> {
        config.validate()?;
        Ok(Self {
            client,
            accept_header: build_accept_header(config.enable_open_metrics, config.escaping_scheme),
            timeout_header: format_scrape_timeout_seconds(config.scrape_timeout),
            user_agent: config.user_agent.clone(),
            scrape_timeout: config.scrape_timeout,
            enable_compression: config.enable_compression,
            max_body_bytes: config.effective_max_body_bytes(),
        })
    }
}

impl TargetFetcher for ReqwestFetcher {
    async fn fetch(
        &self,
        target: &ScrapeTarget,
        pool: &BodyBufferPool,
    ) -> Result<FetchedScrape, ScrapeError> {
        let started = Instant::now();
        let timeout = self.scrape_timeout;

        let mut req = self
            .client
            .get(target.url().clone())
            .header(ACCEPT, &self.accept_header)
            .header(SCRAPE_TIMEOUT_HEADER, &self.timeout_header)
            .header(USER_AGENT, &self.user_agent);
        if self.enable_compression {
            req = req.header(ACCEPT_ENCODING, "gzip");
        }

        // NOTE: Do not lease a `PooledBodyBuffer` while awaiting response headers. Slow targets
        // that stall on TCP connect or server-side metric collection hold zero payload memory.
        let mut response = tokio::time::timeout(timeout, req.send())
            .await
            .map_err(|_| ScrapeError::TimedOut { timeout })??;

        let status = response.status();
        if !status.is_success() {
            return Err(ScrapeError::UnexpectedStatus {
                status: status.as_u16(),
            });
        }

        let encoding = classify_content_encoding(
            response
                .headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
        )?;

        let content_length = response.content_length();
        if matches!(encoding, BodyEncoding::Identity)
            && let Some(len) = content_length
            && len > u64::try_from(self.max_body_bytes).unwrap_or(u64::MAX)
        {
            return Err(ScrapeError::BodyTooLarge {
                limit_bytes: self.max_body_bytes,
            });
        }

        let format = resolve_scrape_format(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
        );

        let cap_hint = match (encoding, content_length) {
            (BodyEncoding::Identity, Some(len)) => usize::try_from(len)
                .unwrap_or(0)
                .min(self.max_body_bytes)
                .min(256 * 1024),
            _ => 0,
        };

        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ScrapeError::TimedOut { timeout });
        }

        let (body, wire_bytes) = tokio::time::timeout(remaining, async {
            let mut body = pool.acquire(cap_hint).await;
            let mut wire_bytes = 0usize;

            match encoding {
                BodyEncoding::Identity => {
                    while let Some(chunk) = response.chunk().await? {
                        wire_bytes = wire_bytes.saturating_add(chunk.len());
                        if body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                            return Err(ScrapeError::BodyTooLarge {
                                limit_bytes: self.max_body_bytes,
                            });
                        }
                        body.extend_from_slice(&chunk);
                    }
                }
                BodyEncoding::Gzip => {
                    let mut decoder = GzDecoder::new(BoundedVecWriter {
                        buf: &mut body,
                        limit: self.max_body_bytes,
                    });
                    while let Some(chunk) = response.chunk().await? {
                        wire_bytes = wire_bytes.saturating_add(chunk.len());
                        decoder
                            .write_all(&chunk)
                            .map_err(|err| map_gzip_io_error(err, self.max_body_bytes))?;
                    }
                    decoder
                        .finish()
                        .map_err(|err| map_gzip_io_error(err, self.max_body_bytes))?;
                }
            }

            Ok::<(PooledBodyBuffer, usize), ScrapeError>((body, wire_bytes))
        })
        .await
        .map_err(|_| ScrapeError::TimedOut { timeout })??;

        let scrape_timestamp_ms = current_timestamp_ms();
        let fetch_duration = started.elapsed();

        Ok(FetchedScrape {
            body,
            format,
            scrape_timestamp_ms,
            fetch_duration,
            wire_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyEncoding {
    Identity,
    Gzip,
}

fn classify_content_encoding(raw: Option<&str>) -> Result<BodyEncoding, ScrapeError> {
    let Some(val) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(BodyEncoding::Identity);
    };
    if val.eq_ignore_ascii_case("identity") {
        Ok(BodyEncoding::Identity)
    } else if val.eq_ignore_ascii_case("gzip") || val.eq_ignore_ascii_case("x-gzip") {
        Ok(BodyEncoding::Gzip)
    } else {
        Err(ScrapeError::UnsupportedEncoding {
            encoding: val.to_owned(),
        })
    }
}

struct BoundedVecWriter<'a> {
    buf: &'a mut Vec<u8>,
    limit: usize,
}

#[derive(Debug)]
struct BodyLimitExceededError;

impl std::fmt::Display for BodyLimitExceededError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("body limit exceeded")
    }
}

impl std::error::Error for BodyLimitExceededError {}

impl Write for BoundedVecWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buf.len().saturating_add(data.len()) > self.limit {
            return Err(io::Error::other(BodyLimitExceededError));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn map_gzip_io_error(err: io::Error, limit_bytes: usize) -> ScrapeError {
    if err
        .get_ref()
        .is_some_and(|inner| inner.is::<BodyLimitExceededError>())
    {
        ScrapeError::BodyTooLarge { limit_bytes }
    } else {
        ScrapeError::Decompress(err.to_string())
    }
}

pub(crate) fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::time::Duration;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn timeout_header_formatting_matches_prometheus() {
        assert_eq!(format_scrape_timeout_seconds(Duration::from_secs(10)), "10");
        assert_eq!(
            format_scrape_timeout_seconds(Duration::from_millis(2_500)),
            "2.5"
        );
        assert_eq!(
            format_scrape_timeout_seconds(Duration::from_millis(125)),
            "0.125"
        );
    }

    #[test]
    fn accept_header_respects_openmetrics_and_escaping() {
        let om = build_accept_header(true, EscapingScheme::EscapeUnderscores);
        assert!(om.contains("application/openmetrics-text;version=1.0.0;q=0.6"));
        assert!(om.contains("text/plain;version=0.0.4;q=0.4"));

        let utf8 = build_accept_header(false, EscapingScheme::AllowUtf8);
        assert_eq!(
            utf8,
            "text/plain;version=0.0.4;escaping=allow-utf-8;q=0.4,*/*;q=0.1"
        );
    }

    #[test]
    fn resolve_format_handles_missing_and_bare_openmetrics_headers() {
        assert_eq!(
            resolve_scrape_format(None).format_type(),
            FormatType::TextPlain
        );
        assert_eq!(
            resolve_scrape_format(Some("application/openmetrics-text; version=1.0.0"))
                .format_type(),
            FormatType::OpenMetrics
        );
    }

    #[tokio::test]
    async fn reqwest_fetcher_handles_gzip_headers_and_gzip_bomb_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            // 1. Valid gzip-compressed OpenMetrics payload; verify request headers.
            let (mut sock, _) = listener.accept().await.expect("accept 1");
            let mut req_buf = vec![0u8; 2048];
            let n = sock.read(&mut req_buf).await.expect("read 1");
            let req_str = String::from_utf8_lossy(&req_buf[..n]).to_ascii_lowercase();
            assert!(req_str.contains("accept-encoding: gzip"));
            assert!(req_str.contains("x-prometheus-scrape-timeout-seconds: 2.5"));

            let payload = b"# TYPE demo_requests_total counter\n\
demo_requests_total{instance=\"a\",method=\"GET\"} 10\n\
demo_requests_total{instance=\"a\",method=\"POST\"} 20\n\
demo_requests_total{instance=\"b\",method=\"GET\"} 30\n\
demo_requests_total{instance=\"b\",method=\"POST\"} 40\n\
# EOF\n";
            let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
            gz.write_all(payload).expect("gz write");
            let compressed = gz.finish().expect("gz finish");

            let hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                compressed.len()
            );
            sock.write_all(hdr.as_bytes()).await.expect("write hdr 1");
            sock.write_all(&compressed).await.expect("write body 1");

            // 2. Oversized compressed payload (16 KiB of zeros -> tiny gzip, exceeds 1 KiB limit).
            let (mut sock2, _) = listener.accept().await.expect("accept 2");
            let _ = sock2.read(&mut req_buf).await.expect("read 2");
            let bomb = vec![b'a'; 16 * 1024];
            let mut gz2 = GzEncoder::new(Vec::new(), Compression::best());
            gz2.write_all(&bomb).expect("gz2 write");
            let compressed_bomb = gz2.finish().expect("gz2 finish");
            assert!(compressed_bomb.len() < 256);

            let hdr2 = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                compressed_bomb.len()
            );
            sock2.write_all(hdr2.as_bytes()).await.expect("write hdr 2");
            sock2
                .write_all(&compressed_bomb)
                .await
                .expect("write body 2");
        });

        let cfg = ScrapeConfig::new("test")
            .with_scrape_interval(Duration::from_secs(5))
            .with_scrape_timeout(Duration::from_millis(2_500))
            .with_max_body_bytes(1_024)
            .with_max_retained_body_bytes(512);
        let fetcher = ReqwestFetcher::new(&cfg).expect("fetcher");
        let pool = BodyBufferPool::new(NonZeroUsize::MIN, cfg.max_retained_body_bytes);
        let target = ScrapeTarget::parse(&format!("http://{addr}/metrics")).expect("target");

        let ok = fetcher.fetch(&target, &pool).await.expect("first fetch ok");
        assert_eq!(ok.format.format_type(), FormatType::OpenMetrics);
        assert!(
            ok.body
                .as_slice()
                .starts_with(b"# TYPE demo_requests_total counter\n")
        );
        assert!(ok.wire_bytes < ok.uncompressed_bytes());
        drop(ok);
        assert_eq!(pool.total_buffers_created(), 1);
        assert!(pool.retained_memory_bytes() <= 512);

        let err = fetcher
            .fetch(&target, &pool)
            .await
            .expect_err("gzip bomb must exceed max_body_bytes");
        assert!(matches!(
            err,
            ScrapeError::BodyTooLarge { limit_bytes: 1_024 }
        ));
        assert_eq!(pool.total_buffers_created(), 1);
        assert!(pool.retained_memory_bytes() <= 512);

        server.await.expect("server join");
    }
}
