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
use std::io::{self, BufRead, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::bufread::GzDecoder;
#[cfg(feature = "arrow")]
use prometheus_expfmt::arrow::DecodeError;
use prometheus_expfmt::format::{EscapingScheme, FMT_TEXT, Format, FormatType, response_format};
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, HeaderMap, HeaderValue, USER_AGENT,
};
use tokio::time::Instant;

use crate::scrape::{BodyBufferPool, PooledBodyBuffer, ScrapeConfig, ScrapeTarget};

const SCRAPE_TIMEOUT_HEADER: &str = "X-Prometheus-Scrape-Timeout-Seconds";

/// Errors produced while validating configuration, fetching HTTP payloads, or decoding scrapes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScrapeError {
    /// Invalid scrape pool or target configuration.
    #[error("invalid scrape configuration: {0}")]
    InvalidConfig(String),
    /// Transport or request construction failure from `reqwest` (with any URL password stripped).
    #[error("HTTP scrape request failed: {0}")]
    Http(#[source] reqwest::Error),
    /// Target returned a non-200 HTTP status code.
    #[error("target returned non-200 HTTP status {status}")]
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

impl From<reqwest::Error> for ScrapeError {
    fn from(mut err: reqwest::Error) -> Self {
        // Strip basic-auth passwords from `reqwest::Error`'s embedded URL so error strings and
        // `ScrapeReport::error` never leak credentials.
        if let Some(url) = err.url_mut()
            && url.password().is_some()
        {
            let _ = url.set_password(None);
        }
        Self::Http(err)
    }
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
/// Mirrors Prometheus `scrape.acceptHeader`: appends `;escaping=<scheme>` exclusively to `1.0.0`
/// protocols (`application/openmetrics-text;version=1.0.0` and `text/plain;version=1.0.0`) and
/// omits it on legacy `0.0.1` and `0.0.4` media types.
#[must_use]
pub fn build_accept_header(enable_open_metrics: bool, escaping: EscapingScheme) -> String {
    let esc = escaping.as_str();
    if enable_open_metrics {
        format!(
            "application/openmetrics-text;version=1.0.0;escaping={esc};q=0.7,\
             application/openmetrics-text;version=0.0.1;q=0.6,\
             text/plain;version=1.0.0;escaping={esc};q=0.5,\
             text/plain;version=0.0.4;q=0.4,\
             */*;q=0.3"
        )
    } else {
        format!(
            "text/plain;version=1.0.0;escaping={esc};q=0.7,\
             text/plain;version=0.0.4;q=0.6,\
             */*;q=0.5"
        )
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
    accept_header: HeaderValue,
    timeout_header: HeaderValue,
    user_agent: HeaderValue,
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
        // Disable automatic `reqwest` response decompression even if downstream crates enable
        // `reqwest` compression features via Cargo unification, keeping `wire_bytes` and
        // `max_body_bytes` enforcement exact.
        let client = reqwest::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()?;
        Self::with_client(client, config)
    }

    /// Wraps a caller-supplied [`reqwest::Client`] (for example, one built from custom TLS or
    /// proxy settings) with scrape request headers and limits from `config`.
    ///
    /// Caller-built clients should disable automatic response decompression (`.no_gzip()`,
    /// `.no_brotli()`, `.no_zstd()`, `.no_deflate()`) so [`ReqwestFetcher`] can enforce
    /// [`ScrapeConfig::max_body_bytes`] and measure [`FetchedScrape::wire_bytes`] directly.
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `config` fails validation.
    pub fn with_client(
        client: reqwest::Client,
        config: &ScrapeConfig,
    ) -> Result<Self, ScrapeError> {
        config.validate()?;
        let accept_raw = build_accept_header(config.enable_open_metrics, config.escaping_scheme);
        let accept_header = HeaderValue::from_str(&accept_raw)
            .map_err(|err| ScrapeError::InvalidConfig(format!("invalid Accept header: {err}")))?;
        let timeout_raw = format_scrape_timeout_seconds(config.scrape_timeout);
        let timeout_header = HeaderValue::from_str(&timeout_raw)
            .map_err(|err| ScrapeError::InvalidConfig(format!("invalid timeout header: {err}")))?;
        let user_agent = HeaderValue::from_str(&config.user_agent).map_err(|err| {
            ScrapeError::InvalidConfig(format!("invalid user_agent header: {err}"))
        })?;
        Ok(Self {
            client,
            accept_header,
            timeout_header,
            user_agent,
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

        let accept_encoding = if self.enable_compression {
            HeaderValue::from_static("gzip")
        } else {
            HeaderValue::from_static("identity")
        };
        let req = self
            .client
            .get(target.url().clone())
            .header(ACCEPT, self.accept_header.clone())
            .header(ACCEPT_ENCODING, accept_encoding)
            .header(SCRAPE_TIMEOUT_HEADER, self.timeout_header.clone())
            .header(USER_AGENT, self.user_agent.clone());

        // NOTE: Do not lease a `PooledBodyBuffer` while awaiting response headers. Slow targets
        // that stall on TCP connect or server-side metric collection hold zero payload memory.
        let mut response = tokio::time::timeout(timeout, req.send())
            .await
            .map_err(|_| ScrapeError::TimedOut { timeout })?
            .map_err(|err| map_reqwest_error(err, timeout))?;

        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(ScrapeError::UnexpectedStatus {
                status: status.as_u16(),
            });
        }

        let encoding = classify_content_encoding(response.headers(), self.enable_compression)?;

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

        let header_elapsed = started.elapsed();
        let remaining = timeout.saturating_sub(header_elapsed);
        if remaining.is_zero() {
            return Err(ScrapeError::TimedOut { timeout });
        }

        // NOTE: Acquire the `PooledBodyBuffer` outside the `scrape_timeout` window so downstream
        // sink or pool backpressure never marks healthy HTTP targets as `TimedOut` (`up = false`).
        let mut body = pool.acquire(cap_hint).await;
        let body_started = Instant::now();

        let wire_bytes = tokio::time::timeout(remaining, async {
            let mut wire_bytes = 0usize;

            match encoding {
                BodyEncoding::Identity => {
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|err| map_reqwest_error(err, timeout))?
                    {
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
                    let (out_buf, gzip_slot) = body.parts_mut();
                    let decoder =
                        gzip_slot.get_or_insert_with(|| Box::new(PooledGzipDecoder::new()));
                    decoder.reset_for_scrape();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|err| map_reqwest_error(err, timeout))?
                    {
                        wire_bytes = wire_bytes.saturating_add(chunk.len());
                        decoder.push_chunk(&chunk, out_buf, self.max_body_bytes)?;
                    }
                    decoder.finish(out_buf, self.max_body_bytes)?;
                }
            }

            Ok::<usize, ScrapeError>(wire_bytes)
        })
        .await
        .map_err(|_| ScrapeError::TimedOut { timeout })??;

        let scrape_timestamp_ms = current_timestamp_ms();
        let fetch_duration = header_elapsed.saturating_add(body_started.elapsed());

        Ok(FetchedScrape {
            body,
            format,
            scrape_timestamp_ms,
            fetch_duration,
            wire_bytes,
        })
    }
}

fn map_reqwest_error(err: reqwest::Error, timeout: Duration) -> ScrapeError {
    if err.is_timeout() {
        ScrapeError::TimedOut { timeout }
    } else {
        ScrapeError::from(err)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyEncoding {
    Identity,
    Gzip,
}

fn classify_content_encoding(
    headers: &HeaderMap,
    enable_compression: bool,
) -> Result<BodyEncoding, ScrapeError> {
    let mut resolved = BodyEncoding::Identity;
    for raw_header in headers.get_all(CONTENT_ENCODING) {
        let Ok(raw_str) = raw_header.to_str() else {
            return Err(ScrapeError::UnsupportedEncoding {
                encoding: String::from_utf8_lossy(raw_header.as_bytes()).into_owned(),
            });
        };
        for token in raw_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if token.eq_ignore_ascii_case("identity") {
                continue;
            }
            if (token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip"))
                && enable_compression
                && matches!(resolved, BodyEncoding::Identity)
            {
                resolved = BodyEncoding::Gzip;
            } else {
                return Err(ScrapeError::UnsupportedEncoding {
                    encoding: raw_str.trim().to_owned(),
                });
            }
        }
    }
    Ok(resolved)
}

#[derive(Debug, Default)]
struct ChunkFeed {
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl ChunkFeed {
    fn clear(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.eof = false;
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

impl Read for ChunkFeed {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(dst.len());
        dst[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for ChunkFeed {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos < self.buf.len() {
            Ok(&self.buf[self.pos..])
        } else if self.eof {
            Ok(&[])
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }
    }

    fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.buf.len());
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }
}

/// Reusable streaming gzip inflate state parked alongside a [`PooledBodyBuffer`] so repeated
/// compressed scrapes avoid reallocating `miniz_oxide`'s ~40 KiB dictionary and 32 KiB buffer.
#[derive(Debug)]
pub(crate) struct PooledGzipDecoder {
    decoder: GzDecoder<ChunkFeed>,
    member_started: bool,
    member_finished: bool,
}

impl PooledGzipDecoder {
    pub(crate) fn new() -> Self {
        Self {
            decoder: GzDecoder::new(ChunkFeed::default()),
            member_started: false,
            member_finished: false,
        }
    }

    pub(crate) fn reset_for_scrape(&mut self) {
        let mut feed = self.decoder.reset(ChunkFeed::default());
        feed.clear();
        let _ = self.decoder.reset(feed);
        self.member_started = false;
        self.member_finished = false;
    }

    fn reset_next_member(&mut self) {
        let feed = self.decoder.reset(ChunkFeed::default());
        let _ = self.decoder.reset(feed);
        self.member_finished = false;
    }

    pub(crate) fn shrink_retained(&mut self, max_retained_bytes: usize) {
        let cap = max_retained_bytes.min(64 * 1024);
        let feed = self.decoder.get_mut();
        feed.clear();
        if feed.buf.capacity() > cap {
            feed.buf.shrink_to(cap);
        }
    }

    fn push_chunk(
        &mut self,
        chunk: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<(), ScrapeError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if self.member_finished {
            self.reset_next_member();
        }
        self.member_started = true;
        self.decoder.get_mut().push_bytes(chunk);
        self.drain_into(out, limit)
    }

    fn finish(&mut self, out: &mut Vec<u8>, limit: usize) -> Result<(), ScrapeError> {
        self.decoder.get_mut().eof = true;
        if self.member_finished && self.decoder.get_ref().is_empty() {
            return Ok(());
        }
        self.drain_into(out, limit)
    }

    fn drain_into(&mut self, out: &mut Vec<u8>, limit: usize) -> Result<(), ScrapeError> {
        let mut scratch = [0_u8; 8_192];
        loop {
            match self.decoder.read(&mut scratch) {
                Ok(0) => {
                    if !self.decoder.get_ref().is_empty() {
                        // RFC 1952 §2.2 allows concatenating multiple gzip members in one stream.
                        self.reset_next_member();
                        continue;
                    }
                    self.member_finished = true;
                    return Ok(());
                }
                Ok(n) => {
                    if out.len().saturating_add(n) > limit {
                        return Err(ScrapeError::BodyTooLarge { limit_bytes: limit });
                    }
                    out.extend_from_slice(&scratch[..n]);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(ScrapeError::Decompress(err.to_string())),
            }
        }
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
    use std::io::Write;
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
        assert_eq!(
            om,
            "application/openmetrics-text;version=1.0.0;escaping=underscores;q=0.7,\
             application/openmetrics-text;version=0.0.1;q=0.6,\
             text/plain;version=1.0.0;escaping=underscores;q=0.5,\
             text/plain;version=0.0.4;q=0.4,\
             */*;q=0.3"
        );

        let utf8 = build_accept_header(false, EscapingScheme::AllowUtf8);
        assert_eq!(
            utf8,
            "text/plain;version=1.0.0;escaping=allow-utf-8;q=0.7,\
             text/plain;version=0.0.4;q=0.6,\
             */*;q=0.5"
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

    #[tokio::test]
    async fn body_buffer_pool_wait_does_not_count_against_scrape_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut req_buf = [0u8; 1024];
            let _ = sock.read(&mut req_buf).await.expect("read");
            let body = b"up_metric 1\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.expect("write hdr");
            sock.write_all(body).await.expect("write body");
        });

        let cfg = ScrapeConfig::new("pool-wait")
            .with_scrape_interval(Duration::from_secs(5))
            .with_scrape_timeout(Duration::from_millis(80));
        let fetcher = ReqwestFetcher::new(&cfg).expect("fetcher");
        let pool = BodyBufferPool::new(NonZeroUsize::MIN, cfg.max_retained_body_bytes);
        let target = ScrapeTarget::parse(&format!("http://{addr}/metrics")).expect("target");

        // Hold the sole buffer permit longer than `scrape_timeout` (160ms > 80ms).
        let held = pool.acquire(0).await;
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(160)).await;
            drop(held);
        });

        let fetched = fetcher
            .fetch(&target, &pool)
            .await
            .expect("pool wait must not trigger TimedOut on fast target");
        assert_eq!(fetched.body.as_slice(), b"up_metric 1\n");
        assert!(fetched.fetch_duration < Duration::from_millis(80));
        drop(fetched);

        release.await.expect("release join");
        server.await.expect("server join");
    }

    #[test]
    fn pooled_gzip_decoder_decodes_concatenated_multi_member_streams() {
        let mut member1 = GzEncoder::new(Vec::new(), Compression::fast());
        member1.write_all(b"metric_one 1\n").expect("m1 write");
        let mut combined = member1.finish().expect("m1 finish");

        let mut member2 = GzEncoder::new(Vec::new(), Compression::default());
        member2.write_all(b"metric_two 2\n").expect("m2 write");
        combined.extend_from_slice(&member2.finish().expect("m2 finish"));

        let mut dec = PooledGzipDecoder::new();
        for chunk_size in [combined.len(), 7, 1] {
            dec.reset_for_scrape();
            let mut out = Vec::new();
            for chunk in combined.chunks(chunk_size) {
                dec.push_chunk(chunk, &mut out, 1024).expect("push chunk");
            }
            dec.finish(&mut out, 1024).expect("finish");
            assert_eq!(out, b"metric_one 1\nmetric_two 2\n");
        }
    }

    #[tokio::test]
    async fn reqwest_fetcher_rejects_non_200_bad_encoding_large_content_length_and_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            let mut req_buf = [0u8; 2048];

            // 1. 204 No Content -> UnexpectedStatus { status: 204 } (no buffer allocated).
            let (mut s1, _) = listener.accept().await.expect("accept 1");
            let n1 = s1.read(&mut req_buf).await.expect("read 1");
            let req1 = String::from_utf8_lossy(&req_buf[..n1]).to_ascii_lowercase();
            assert!(req1.contains("accept-encoding: identity"));
            s1.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("write 1");

            // 2. Unsolicited gzip when `enable_compression = false` -> UnsupportedEncoding.
            let (mut s2, _) = listener.accept().await.expect("accept 2");
            let _ = s2.read(&mut req_buf).await.expect("read 2");
            s2.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write 2");

            // 3. Uncompressed Content-Length > max_body_bytes -> fast BodyTooLarge (0 buffers allocated).
            let (mut s3, _) = listener.accept().await.expect("accept 3");
            let _ = s3.read(&mut req_buf).await.expect("read 3");
            s3.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n")
                .await
                .expect("write 3");

            // 4. Stalled headers -> TimedOut, and basic-auth password must not appear in error text.
            let (mut s4, _) = listener.accept().await.expect("accept 4");
            let _ = s4.read(&mut req_buf).await.expect("read 4");
            tokio::time::sleep(Duration::from_millis(180)).await;
        });

        let cfg = ScrapeConfig::new("errors")
            .with_scrape_interval(Duration::from_secs(5))
            .with_scrape_timeout(Duration::from_millis(60))
            .with_enable_compression(false)
            .with_max_body_bytes(512);
        let fetcher = ReqwestFetcher::new(&cfg).expect("fetcher");
        let pool = BodyBufferPool::new(NonZeroUsize::MIN, 512);
        let target = ScrapeTarget::parse(&format!("http://{addr}/metrics")).expect("target");

        let e1 = fetcher.fetch(&target, &pool).await.expect_err("204 fails");
        assert!(matches!(e1, ScrapeError::UnexpectedStatus { status: 204 }));
        assert_eq!(pool.total_buffers_created(), 0);

        let e2 = fetcher
            .fetch(&target, &pool)
            .await
            .expect_err("unsolicited gzip fails");
        assert!(matches!(e2, ScrapeError::UnsupportedEncoding { .. }));
        assert_eq!(pool.total_buffers_created(), 0);

        let e3 = fetcher
            .fetch(&target, &pool)
            .await
            .expect_err("oversized Content-Length fails before buffer lease");
        assert!(matches!(e3, ScrapeError::BodyTooLarge { limit_bytes: 512 }));
        assert_eq!(pool.total_buffers_created(), 0);

        let e4 = fetcher
            .fetch(&target, &pool)
            .await
            .expect_err("stalled headers time out");
        assert!(matches!(e4, ScrapeError::TimedOut { .. }));
        assert_eq!(pool.active_leases(), 0);

        server.await.expect("server join");

        // Closed loopback port with basic-auth credentials must strip password from ScrapeError.
        let closed_target =
            ScrapeTarget::parse("http://admin:super_secret_pw@127.0.0.1:1/metrics").unwrap();
        let conn_err = fetcher
            .fetch(&closed_target, &pool)
            .await
            .expect_err("closed port fails");
        assert!(
            !conn_err.to_string().contains("super_secret_pw"),
            "password leaked in ScrapeError: {conn_err}"
        );
    }
}
