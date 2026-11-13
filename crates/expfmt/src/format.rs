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

//! Prometheus and OpenMetrics `Content-Type` and `Accept` header parsing,
//! format descriptors, and UTF-8 escaping schemes.
//!
//! Mirrors [`prometheus/common/expfmt/expfmt.go`](https://github.com/prometheus/common/blob/main/expfmt/expfmt.go),
//! [`encode.go`](https://github.com/prometheus/common/blob/main/expfmt/encode.go), and
//! [`decode.go`](https://github.com/prometheus/common/blob/main/expfmt/decode.go).
//!
//! Scraper-side request and response handling lives here too, because Prometheus keeps its
//! scraper-side counterparts in `config` and `scrape` rather than in `prometheus/common/expfmt`:
//! [`ScrapeProtocol`] and [`accept_header`] mirror `config.ScrapeProtocol` and
//! `scrape.acceptHeader`, and [`resolve_scrape_format`] mirrors the `fallback_scrape_protocol`
//! handling of `textparse.extractMediaType`.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;
use std::sync::LazyLock;

/// MIME type for Prometheus classic text exposition format.
pub const TEXT_TYPE: &str = "text/plain";

/// Version string for Prometheus classic text format.
pub const TEXT_VERSION: &str = "0.0.4";

/// Version string for Prometheus UTF-8 text format (`text/plain; version=1.0.0`).
pub const TEXT_VERSION_1_0_0: &str = "1.0.0";

/// MIME type for Prometheus protobuf wire format.
pub const PROTO_TYPE: &str = "application/vnd.google.protobuf";

/// Protobuf message type for Prometheus exposition payloads.
pub const PROTO_PROTOCOL: &str = "io.prometheus.client.MetricFamily";

/// Prefix for Prometheus protobuf `Content-Type` headers.
pub const PROTO_FMT: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;";

/// MIME type for OpenMetrics text exposition format.
pub const OPEN_METRICS_TYPE: &str = "application/openmetrics-text";

/// Version string for OpenMetrics 0.0.1.
pub const OPEN_METRICS_VERSION_0_0_1: &str = "0.0.1";

/// Version string for OpenMetrics 1.0.0.
pub const OPEN_METRICS_VERSION_1_0_0: &str = "1.0.0";

/// Version string for OpenMetrics 2.0.0-rc.
pub const OPEN_METRICS_VERSION_2_0_0_RC: &str = "2.0.0-rc";

/// Version string for OpenMetrics 2.0.0.
pub const OPEN_METRICS_VERSION_2_0_0: &str = "2.0.0";

/// Content-Type parameter key specifying the UTF-8 metric and label name escaping scheme.
pub const ESCAPING_KEY: &str = "escaping";

const PROTO_KEY: &str = "proto";
const ENCODING_KEY: &str = "encoding";
const VERSION_KEY: &str = "version";
const CHARSET_KEY: &str = "charset";

const ENCODING_DELIMITED: &str = "delimited";
const ENCODING_TEXT: &str = "text";
const ENCODING_COMPACT_TEXT: &str = "compact-text";
const CHARSET_UTF8: &str = "utf-8";

const ESCAPE_ALLOW_UTF8: &str = "allow-utf-8";
const ESCAPE_UNDERSCORES: &str = "underscores";
const ESCAPE_DOTS: &str = "dots";
const ESCAPE_VALUES: &str = "values";

/// Baseline `Content-Type` string for unknown formats.
pub const FMT_UNKNOWN: &str = "<unknown>";

/// Baseline `Content-Type` string for Prometheus 0.0.4 text format.
pub const FMT_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Baseline `Content-Type` string for Prometheus 1.0.0 (UTF-8) text format.
pub const FMT_TEXT_1_0_0: &str = "text/plain; version=1.0.0; charset=utf-8";

/// Baseline `Content-Type` string for varint length-delimited Prometheus protobuf format.
pub const FMT_PROTO_DELIM: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// Baseline `Content-Type` string for text-encoded Prometheus protobuf format.
pub const FMT_PROTO_TEXT: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text";

/// Baseline `Content-Type` string for compact text-encoded Prometheus protobuf format.
pub const FMT_PROTO_COMPACT: &str = "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text";

/// Baseline `Content-Type` string for OpenMetrics 2.0.0 text format.
pub const FMT_OPEN_METRICS_2_0_0: &str =
    "application/openmetrics-text; version=2.0.0; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 2.0.0-rc text format.
pub const FMT_OPEN_METRICS_2_0_0_RC: &str =
    "application/openmetrics-text; version=2.0.0-rc; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 1.0.0 text format.
pub const FMT_OPEN_METRICS_1_0_0: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 0.0.1 text format.
pub const FMT_OPEN_METRICS_0_0_1: &str =
    "application/openmetrics-text; version=0.0.1; charset=utf-8";

/// UTF-8 metric and label name escaping scheme negotiated via the `escaping=...` parameter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EscapingScheme {
    /// No escaping (`escaping=allow-utf-8`). Full UTF-8 names are allowed (quoted when needed).
    AllowUtf8,
    /// Replace invalid legacy characters with underscores (`escaping=underscores`).
    /// Matches `model.UnderscoreEscaping`, the default `NameEscapingScheme` in `prometheus/common/model`.
    #[default]
    EscapeUnderscores,
    /// Escape dots and other invalid characters (`escaping=dots`).
    EscapeDots,
    /// Prefix and hex-encode invalid characters (`escaping=values`).
    EscapeValues,
}

impl EscapingScheme {
    /// Wire value for `escaping=<scheme>` parameters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowUtf8 => ESCAPE_ALLOW_UTF8,
            Self::EscapeUnderscores => ESCAPE_UNDERSCORES,
            Self::EscapeDots => ESCAPE_DOTS,
            Self::EscapeValues => ESCAPE_VALUES,
        }
    }
}

impl fmt::Display for EscapingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by format parsing and construction helpers.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// An `escaping=...` parameter does not match a known [`EscapingScheme`].
    #[error("unknown escaping scheme: {0}")]
    UnknownEscapingScheme(String),

    /// An OpenMetrics version string passed to [`Format::new_open_metrics`] is not supported.
    #[error("unknown open metrics version string: {0}")]
    UnknownOpenMetricsVersion(String),

    /// A `scrape_protocols` token does not name a known [`ScrapeProtocol`].
    #[error("unknown scrape protocol: {0}")]
    UnknownScrapeProtocol(String),
}

impl FromStr for EscapingScheme {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ESCAPE_ALLOW_UTF8 => Ok(Self::AllowUtf8),
            ESCAPE_UNDERSCORES => Ok(Self::EscapeUnderscores),
            ESCAPE_DOTS => Ok(Self::EscapeDots),
            ESCAPE_VALUES => Ok(Self::EscapeValues),
            other => Err(FormatError::UnknownEscapingScheme(other.to_owned())),
        }
    }
}

/// High-level wire format category deduced from a [`Format`] string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FormatType {
    /// Unrecognized or invalid format.
    #[default]
    Unknown,
    /// Single-line compact protobuf text (`encoding=compact-text`).
    ProtoCompact,
    /// Varint length-delimited binary protobuf (`encoding=delimited`).
    ProtoDelim,
    /// Multi-line protobuf text (`encoding=text`).
    ProtoText,
    /// Classic Prometheus 0.0.4 text (`text/plain`).
    TextPlain,
    /// OpenMetrics text (`application/openmetrics-text`).
    OpenMetrics,
}

/// HTTP `Content-Type` representation of a Prometheus or OpenMetrics wire protocol.
///
/// Because `Content-Type` values on the wire may include dynamic parameters such as
/// `; escaping=...` or whitespace variations, callers should inspect [`Format::format_type`],
/// [`Format::version`], and [`Format::to_escaping_scheme`] rather than comparing raw strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Format(Cow<'static, str>);

impl Format {
    /// Unknown format (`<unknown>`).
    pub const UNKNOWN: Self = Self(Cow::Borrowed(FMT_UNKNOWN));
    /// Prometheus 0.0.4 plain text format.
    pub const TEXT: Self = Self(Cow::Borrowed(FMT_TEXT));
    /// Prometheus 1.0.0 (UTF-8 names) plain text format.
    pub const TEXT_1_0_0: Self = Self(Cow::Borrowed(FMT_TEXT_1_0_0));
    /// Varint length-delimited binary protobuf format.
    pub const PROTO_DELIM: Self = Self(Cow::Borrowed(FMT_PROTO_DELIM));
    /// Multi-line text protobuf format.
    pub const PROTO_TEXT: Self = Self(Cow::Borrowed(FMT_PROTO_TEXT));
    /// Compact text protobuf format.
    pub const PROTO_COMPACT: Self = Self(Cow::Borrowed(FMT_PROTO_COMPACT));
    /// OpenMetrics 2.0.0 text format.
    pub const OPEN_METRICS_2_0_0: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_2_0_0));
    /// OpenMetrics 2.0.0-rc text format.
    pub const OPEN_METRICS_2_0_0_RC: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_2_0_0_RC));
    /// OpenMetrics 1.0.0 text format.
    pub const OPEN_METRICS_1_0_0: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_1_0_0));
    /// OpenMetrics 0.0.1 text format.
    pub const OPEN_METRICS_0_0_1: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_0_0_1));

    /// Creates a [`Format`] from a raw `Content-Type` string.
    #[must_use]
    pub fn new(raw: impl Into<Cow<'static, str>>) -> Self {
        Self(raw.into())
    }

    /// Returns the baseline [`Format`] for the given [`FormatType`], using the latest stable
    /// version when multiple versions exist (`1.0.0` for [`FormatType::OpenMetrics`]).
    #[must_use]
    pub const fn from_type(t: FormatType) -> Self {
        match t {
            FormatType::ProtoCompact => Self::PROTO_COMPACT,
            FormatType::ProtoDelim => Self::PROTO_DELIM,
            FormatType::ProtoText => Self::PROTO_TEXT,
            FormatType::TextPlain => Self::TEXT,
            FormatType::OpenMetrics => Self::OPEN_METRICS_1_0_0,
            FormatType::Unknown => Self::UNKNOWN,
        }
    }

    /// Returns the baseline OpenMetrics [`Format`] for the given version string.
    pub fn new_open_metrics(version: &str) -> Result<Self, FormatError> {
        match version {
            OPEN_METRICS_VERSION_0_0_1 => Ok(Self::OPEN_METRICS_0_0_1),
            OPEN_METRICS_VERSION_1_0_0 => Ok(Self::OPEN_METRICS_1_0_0),
            OPEN_METRICS_VERSION_2_0_0_RC => Ok(Self::OPEN_METRICS_2_0_0_RC),
            OPEN_METRICS_VERSION_2_0_0 => Ok(Self::OPEN_METRICS_2_0_0),
            other => Err(FormatError::UnknownOpenMetricsVersion(other.to_owned())),
        }
    }

    /// Returns the underlying `Content-Type` string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deduces the high-level [`FormatType`] from this format string, matching
    /// `Format.FormatType()` in `prometheus/common/expfmt`.
    #[must_use]
    pub fn format_type(&self) -> FormatType {
        let mut tokens = self.0.split(';');
        let Some(media_type) = tokens.next().map(str::trim) else {
            return FormatType::Unknown;
        };

        let mut params: HashMap<&str, &str> = HashMap::new();
        for token in tokens {
            let mut args = token.split('=');
            let (Some(k), Some(v), None) = (args.next(), args.next(), args.next()) else {
                continue;
            };
            params.insert(k.trim(), v.trim());
        }

        match media_type {
            PROTO_TYPE => {
                if params.get(PROTO_KEY).copied() != Some(PROTO_PROTOCOL) {
                    return FormatType::Unknown;
                }
                match params.get(ENCODING_KEY).copied() {
                    Some(ENCODING_DELIMITED) => FormatType::ProtoDelim,
                    Some(ENCODING_TEXT) => FormatType::ProtoText,
                    Some(ENCODING_COMPACT_TEXT) => FormatType::ProtoCompact,
                    _ => FormatType::Unknown,
                }
            }
            OPEN_METRICS_TYPE => {
                if params.get(CHARSET_KEY).copied() != Some(CHARSET_UTF8) {
                    return FormatType::Unknown;
                }
                FormatType::OpenMetrics
            }
            TEXT_TYPE => match params.get(VERSION_KEY).copied() {
                // `text/plain; version=1.0.0` is the UTF-8 text format Prometheus negotiates
                // through `scrape_protocols`, and it is parsed by the Prometheus text parser.
                None | Some(TEXT_VERSION | TEXT_VERSION_1_0_0) => FormatType::TextPlain,
                Some(_) => FormatType::Unknown,
            },
            _ => FormatType::Unknown,
        }
    }

    /// Returns the `version` parameter of the media type, or `""` if absent or if the media type
    /// cannot be parsed.
    #[must_use]
    pub fn version(&self) -> &str {
        let Some((_, params)) = parse_media_type(&self.0) else {
            return "";
        };
        params.get(VERSION_KEY).copied().unwrap_or("")
    }

    /// Returns whether this format is OpenMetrics 2.0 (`2.0.0` or `2.0.0-rc`).
    #[must_use]
    pub fn is_open_metrics_2_0(&self) -> bool {
        self.format_type() == FormatType::OpenMetrics && is_open_metrics_20_version(self.version())
    }

    /// Returns a copy of this [`Format`] with `escaping=<scheme>` appended to the end, removing
    /// any existing `escaping=...` parameters.
    #[must_use]
    pub fn with_escaping_scheme(&self, scheme: EscapingScheme) -> Self {
        let mut terms: Vec<String> = Vec::new();
        for p in self.0.split(';') {
            let mut tokens = p.split('=');
            let (Some(k), Some(_), None) = (tokens.next(), tokens.next(), tokens.next()) else {
                let trimmed = p.trim();
                if !trimmed.is_empty() {
                    terms.push(trimmed.to_owned());
                }
                continue;
            };
            if k.trim() != ESCAPING_KEY {
                terms.push(p.trim().to_owned());
            }
        }
        terms.push(format!("{ESCAPING_KEY}={scheme}"));
        Self(Cow::Owned(terms.join("; ")))
    }

    /// Extracts the [`EscapingScheme`] from this [`Format`], falling back to
    /// [`EscapingScheme::EscapeUnderscores`] (`model.NameEscapingScheme` default) when absent or invalid.
    #[must_use]
    pub fn to_escaping_scheme(&self) -> EscapingScheme {
        self.to_escaping_scheme_with_default(EscapingScheme::default())
    }

    /// Extracts the [`EscapingScheme`] from this [`Format`], falling back to `default_scheme`
    /// when no valid `escaping=...` term is present.
    #[must_use]
    pub fn to_escaping_scheme_with_default(
        &self,
        default_scheme: EscapingScheme,
    ) -> EscapingScheme {
        for p in self.0.split(';') {
            let mut tokens = p.split('=');
            let (Some(k), Some(v), None) = (tokens.next(), tokens.next(), tokens.next()) else {
                continue;
            };
            if k.trim() == ESCAPING_KEY {
                return v.trim().parse().unwrap_or(default_scheme);
            }
        }
        default_scheme
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for Format {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for Format {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl AsRef<str> for Format {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Standard accepted formats for [`negotiate`], ordered by preference.
pub const DEFAULT_ACCEPTED_FORMATS: &[Format] = &[
    Format::PROTO_DELIM,
    Format::PROTO_TEXT,
    Format::PROTO_COMPACT,
    Format::TEXT,
];

/// Standard accepted formats including stable OpenMetrics formats for
/// [`negotiate_including_open_metrics`], ordered by preference.
pub const DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS: &[Format] = &[
    Format::OPEN_METRICS_1_0_0,
    Format::OPEN_METRICS_0_0_1,
    Format::PROTO_DELIM,
    Format::PROTO_TEXT,
    Format::PROTO_COMPACT,
    Format::TEXT,
];

/// Extracts the baseline [`Format`] from an HTTP response `Content-Type` header value,
/// matching `ResponseFormat` in `prometheus/common/expfmt/decode.go`.
///
/// A valid `escaping=<scheme>` parameter on a format that negotiates one is carried over to the
/// returned [`Format`].
#[must_use]
pub fn response_format(content_type: &str) -> Format {
    let Some((media_type, params)) = parse_media_type(content_type) else {
        return Format::UNKNOWN;
    };

    let format = match media_type.as_str() {
        PROTO_TYPE => {
            if let Some(&p) = params.get(PROTO_KEY)
                && p != PROTO_PROTOCOL
            {
                return Format::UNKNOWN;
            }
            if let Some(&e) = params.get(ENCODING_KEY)
                && e != ENCODING_DELIMITED
            {
                return Format::UNKNOWN;
            }
            Format::PROTO_DELIM
        }
        TEXT_TYPE => match params.get(VERSION_KEY).copied() {
            None | Some(TEXT_VERSION) => Format::TEXT,
            // NOTE: Go's `expfmt.ResponseFormat` predates Prometheus text 1.0.0 and rejects it.
            // Scrapers negotiate that format (`ScrapeProtocol::PrometheusText1_0_0`), so it is
            // resolved here instead of falling through to `Format::UNKNOWN`.
            Some(TEXT_VERSION_1_0_0) => Format::TEXT_1_0_0,
            Some(_) => return Format::UNKNOWN,
        },
        OPEN_METRICS_TYPE => match params.get(VERSION_KEY).copied() {
            None | Some("") | Some(OPEN_METRICS_VERSION_0_0_1) => Format::OPEN_METRICS_0_0_1,
            Some(OPEN_METRICS_VERSION_1_0_0) => Format::OPEN_METRICS_1_0_0,
            Some(_) => return Format::UNKNOWN,
        },
        _ => return Format::UNKNOWN,
    };

    with_declared_escaping(format, &params)
}

/// Metrics wire protocol a scraper advertises to targets and accepts as a
/// `fallback_scrape_protocol`.
///
/// Mirrors `config.ScrapeProtocol` in
/// [`prometheus/prometheus/config/config.go`](https://github.com/prometheus/prometheus/blob/main/config/config.go).
/// Prometheus keeps these scraper-side protocol descriptors outside
/// `prometheus/common/expfmt`, so `scrape.rs` exposes them from [`crate::format`] as well: a scrape
/// pipeline needs both the exporter-side [`Format`] negotiation and the scraper-side request and
/// response handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScrapeProtocol {
    /// Varint length-delimited Prometheus protobuf (`PrometheusProto`).
    PrometheusProto,
    /// Prometheus text `0.0.4` (`PrometheusText0.0.4`).
    PrometheusText0_0_4,
    /// Prometheus UTF-8 text `1.0.0` (`PrometheusText1.0.0`).
    PrometheusText1_0_0,
    /// OpenMetrics text `0.0.1` (`OpenMetricsText0.0.1`).
    OpenMetricsText0_0_1,
    /// OpenMetrics text `1.0.0` (`OpenMetricsText1.0.0`).
    OpenMetricsText1_0_0,
    /// OpenMetrics text `2.0.0-rc` (`OpenMetricsText2.0.0-rc`).
    OpenMetricsText2_0_0Rc,
    /// OpenMetrics text `2.0.0` (`OpenMetricsText2.0.0`).
    OpenMetricsText2_0_0,
}

impl ScrapeProtocol {
    /// Every supported scrape protocol, in [`ScrapeProtocol::as_str`] order.
    pub const ALL: [Self; 7] = [
        Self::PrometheusProto,
        Self::PrometheusText0_0_4,
        Self::PrometheusText1_0_0,
        Self::OpenMetricsText0_0_1,
        Self::OpenMetricsText1_0_0,
        Self::OpenMetricsText2_0_0Rc,
        Self::OpenMetricsText2_0_0,
    ];

    /// Prometheus `scrape_protocols` / `fallback_scrape_protocol` configuration token for this
    /// protocol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrometheusProto => "PrometheusProto",
            Self::PrometheusText0_0_4 => "PrometheusText0.0.4",
            Self::PrometheusText1_0_0 => "PrometheusText1.0.0",
            Self::OpenMetricsText0_0_1 => "OpenMetricsText0.0.1",
            Self::OpenMetricsText1_0_0 => "OpenMetricsText1.0.0",
            Self::OpenMetricsText2_0_0Rc => "OpenMetricsText2.0.0-rc",
            Self::OpenMetricsText2_0_0 => "OpenMetricsText2.0.0",
        }
    }

    /// `Content-Type` header value advertised for this protocol, matching
    /// `config.ScrapeProtocolsHeaders`.
    ///
    /// These values use Prometheus's compact form without spaces after `;` and without
    /// `; charset=utf-8`, unlike the canonical [`Format`] constants, because they are embedded
    /// verbatim in the scrape `Accept` request header.
    #[must_use]
    pub const fn header(self) -> &'static str {
        match self {
            Self::PrometheusProto => {
                "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited"
            }
            Self::PrometheusText0_0_4 => "text/plain;version=0.0.4",
            Self::PrometheusText1_0_0 => "text/plain;version=1.0.0",
            Self::OpenMetricsText0_0_1 => "application/openmetrics-text;version=0.0.1",
            Self::OpenMetricsText1_0_0 => "application/openmetrics-text;version=1.0.0",
            Self::OpenMetricsText2_0_0Rc => "application/openmetrics-text;version=2.0.0-rc",
            Self::OpenMetricsText2_0_0 => "application/openmetrics-text;version=2.0.0",
        }
    }

    /// MIME media type of [`ScrapeProtocol::header`], matching
    /// `config.ScrapeProtocol::HeaderMediaType`.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::PrometheusProto => PROTO_TYPE,
            Self::PrometheusText0_0_4 | Self::PrometheusText1_0_0 => TEXT_TYPE,
            Self::OpenMetricsText0_0_1
            | Self::OpenMetricsText1_0_0
            | Self::OpenMetricsText2_0_0Rc
            | Self::OpenMetricsText2_0_0 => OPEN_METRICS_TYPE,
        }
    }

    /// Canonical [`Format`] that decodes scrapes of this protocol.
    #[must_use]
    pub const fn format(self) -> Format {
        match self {
            Self::PrometheusProto => Format::PROTO_DELIM,
            Self::PrometheusText0_0_4 => Format::TEXT,
            Self::PrometheusText1_0_0 => Format::TEXT_1_0_0,
            Self::OpenMetricsText0_0_1 => Format::OPEN_METRICS_0_0_1,
            Self::OpenMetricsText1_0_0 => Format::OPEN_METRICS_1_0_0,
            Self::OpenMetricsText2_0_0Rc => Format::OPEN_METRICS_2_0_0_RC,
            Self::OpenMetricsText2_0_0 => Format::OPEN_METRICS_2_0_0,
        }
    }

    /// Whether the protocol accepts an `escaping=<scheme>` `Accept` parameter.
    ///
    /// Prometheus only advertises `escaping=...` on text `1.0.0` and OpenMetrics `1.0.0`+ media
    /// types, because legacy `0.0.1` and `0.0.4` formats have no escaping scheme.
    #[must_use]
    pub const fn supports_escaping(self) -> bool {
        matches!(
            self,
            Self::PrometheusText1_0_0
                | Self::OpenMetricsText1_0_0
                | Self::OpenMetricsText2_0_0Rc
                | Self::OpenMetricsText2_0_0
        )
    }

    /// Whether this protocol is decoded by the OpenMetrics 2.0 parser.
    #[must_use]
    pub const fn is_open_metrics_2(self) -> bool {
        matches!(
            self,
            Self::OpenMetricsText2_0_0Rc | Self::OpenMetricsText2_0_0
        )
    }
}

impl fmt::Display for ScrapeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScrapeProtocol {
    type Err = FormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == s)
            .ok_or_else(|| FormatError::UnknownScrapeProtocol(s.to_owned()))
    }
}

/// Scrape protocols a scraper advertises by default, ordered by preference.
///
/// Matches `config.DefaultScrapeProtocols`.
pub const DEFAULT_SCRAPE_PROTOCOLS: &[ScrapeProtocol] = &[
    ScrapeProtocol::OpenMetricsText1_0_0,
    ScrapeProtocol::OpenMetricsText0_0_1,
    ScrapeProtocol::PrometheusText1_0_0,
    ScrapeProtocol::PrometheusText0_0_4,
];

/// Scrape protocols a scraper advertises by default when protobuf comes first, ordered by
/// preference.
///
/// Matches `config.DefaultProtoFirstScrapeProtocols`, which Prometheus uses for
/// `scrape_native_histograms` and feature flags that need `created` timestamps.
pub const DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS: &[ScrapeProtocol] = &[
    ScrapeProtocol::PrometheusProto,
    ScrapeProtocol::OpenMetricsText1_0_0,
    ScrapeProtocol::OpenMetricsText0_0_1,
    ScrapeProtocol::PrometheusText1_0_0,
    ScrapeProtocol::PrometheusText0_0_4,
];

/// Builds the HTTP `Accept` header value a scraper sends to its targets, matching `acceptHeader`
/// in [`scrape/scrape.go`](https://github.com/prometheus/prometheus/blob/main/scrape/scrape.go).
///
/// `protocols` are advertised in caller order with descending `q` weights. The first protocol
/// always weighs `q=0.8`, because Prometheus derives the starting weight from the size of its
/// protocol header map (`len(ScrapeProtocolsHeaders) + 1`) rather than from the number of
/// configured protocols, and `*/*` closes the header with the next weight down.
/// `;escaping=<scheme>` is appended only to protocols that support it, see
/// [`ScrapeProtocol::supports_escaping`].
///
/// Weights are clamped at `q=0.1`. Go derives them from the same fixed base, so an over-long list
/// would advertise `q=0.0` ("not acceptable") past seven protocols and eventually the malformed
/// `q=0.-1`. Validated `scrape_protocols` rejects duplicates, so reachable lists stay below that.
#[must_use]
pub fn accept_header(protocols: &[ScrapeProtocol], scheme: EscapingScheme) -> String {
    let mut weight = ScrapeProtocol::ALL.len() + 1;
    let mut header = String::with_capacity(64 * protocols.len() + 12);
    for (i, protocol) in protocols.iter().enumerate() {
        if i > 0 {
            header.push(',');
        }
        header.push_str(protocol.header());
        if protocol.supports_escaping() {
            header.push(';');
            header.push_str(ESCAPING_KEY);
            header.push('=');
            header.push_str(scheme.as_str());
        }
        let _ = write!(header, ";q=0.{weight}");
        weight = weight.saturating_sub(1).max(1);
    }
    if !protocols.is_empty() {
        header.push(',');
    }
    let _ = write!(header, "*/*;q=0.{weight}");
    header
}

/// A non-fatal `Content-Type` problem found by [`resolve_scrape_format`] that the configured
/// `fallback_scrape_protocol` resolved.
///
/// Prometheus logs these as scrape warnings rather than failing the scrape. [`fmt::Display`]
/// renders the Prometheus log message, including the resolved fallback media type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScrapeFormatWarning {
    /// The target sent an empty `Content-Type` header.
    BlankContentType {
        /// Fallback protocol applied to the scrape.
        fallback: ScrapeProtocol,
    },
    /// The `Content-Type` header is not valid media type syntax.
    UnparsableContentType {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
        /// Why the header could not be parsed as a media type.
        reason: &'static str,
        /// Fallback protocol applied to the scrape.
        fallback: ScrapeProtocol,
    },
    /// The target negotiated OpenMetrics 2.0 while the OpenMetrics 2.0 feature is disabled.
    OpenMetrics2Disabled {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
        /// Fallback protocol applied to the scrape.
        fallback: ScrapeProtocol,
    },
    /// The media type is not a supported Prometheus or OpenMetrics exposition format.
    UnsupportedContentType {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
        /// Fallback protocol applied to the scrape.
        fallback: ScrapeProtocol,
    },
}

impl fmt::Display for ScrapeFormatWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankContentType { fallback } => write!(
                f,
                "non-compliant scrape target sending blank Content-Type, using \
                 fallback_scrape_protocol {fallback_mt:?}",
                fallback_mt = fallback.media_type(),
            ),
            Self::UnparsableContentType {
                content_type,
                reason,
                fallback,
            } => write!(
                f,
                "could not parse received Content-Type {content_type:?} ({reason}), using \
                 fallback_scrape_protocol {fallback_mt:?}",
                fallback_mt = fallback.media_type(),
            ),
            Self::OpenMetrics2Disabled {
                content_type,
                fallback,
            } => write!(
                f,
                "received OpenMetrics 2.0 Content-Type {content_type:?}, but the openmetrics2 \
                 feature flag is not enabled, using fallback_scrape_protocol {fallback_mt:?}",
                fallback_mt = fallback.media_type(),
            ),
            Self::UnsupportedContentType {
                content_type,
                fallback,
            } => write!(
                f,
                "received unsupported Content-Type {content_type:?}, using \
                 fallback_scrape_protocol {fallback_mt:?}",
                fallback_mt = fallback.media_type(),
            ),
        }
    }
}

impl std::error::Error for ScrapeFormatWarning {}

/// A fatal `Content-Type` problem found by [`resolve_scrape_format`] with no
/// `fallback_scrape_protocol` configured.
///
/// [`fmt::Display`] renders the Prometheus scrape error message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScrapeFormatError {
    /// The target sent an empty `Content-Type` header and no fallback protocol is configured.
    BlankContentType,
    /// The `Content-Type` header is not valid media type syntax.
    UnparsableContentType {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
        /// Why the header could not be parsed as a media type.
        reason: &'static str,
    },
    /// The target negotiated OpenMetrics 2.0 while the OpenMetrics 2.0 feature is disabled.
    OpenMetrics2Disabled {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
    },
    /// The media type is not a supported Prometheus or OpenMetrics exposition format.
    UnsupportedContentType {
        /// Raw `Content-Type` header value received from the target.
        content_type: String,
    },
}

impl fmt::Display for ScrapeFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankContentType => f.write_str(
                "non-compliant scrape target sending blank Content-Type and no \
                 fallback_scrape_protocol specified for target",
            ),
            Self::UnparsableContentType {
                content_type,
                reason,
            } => write!(
                f,
                "cannot parse Content-Type {content_type:?} ({reason}) and no \
                 fallback_scrape_protocol for target"
            ),
            Self::OpenMetrics2Disabled { content_type } => write!(
                f,
                "received OpenMetrics 2.0 Content-Type {content_type:?}, but the openmetrics2 \
                 feature flag is not enabled and no fallback_scrape_protocol specified for target"
            ),
            Self::UnsupportedContentType { content_type } => write!(
                f,
                "received unsupported Content-Type {content_type:?} and no \
                 fallback_scrape_protocol specified for target"
            ),
        }
    }
}

impl std::error::Error for ScrapeFormatError {}

/// Scrape response format resolved by [`resolve_scrape_format`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedScrapeFormat {
    /// Wire format to decode the scrape payload with.
    pub format: Format,
    /// Non-fatal `Content-Type` problem that the configured fallback protocol resolved. Callers
    /// should surface it as a scrape warning, like Prometheus does, instead of dropping it.
    pub warning: Option<ScrapeFormatWarning>,
}

/// Resolves the [`Format`] to decode a scrape response with from its `Content-Type` header,
/// matching the `fallback_scrape_protocol` handling of `extractMediaType` in
/// [`model/textparse/interface.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/interface.go).
///
/// Unlike [`response_format`], which mirrors the stricter exporter-side `ResponseFormat` in
/// `prometheus/common/expfmt`, this is the scraper-side resolution Prometheus actually applies:
/// only the media type and `version` parameter determine the format, so non-compliant targets that
/// omit `charset=utf-8` on `application/openmetrics-text` still decode as OpenMetrics, and
/// `text/plain; version=1.0.0` resolves to [`Format::TEXT_1_0_0`]. `proto` and `encoding`
/// parameters are ignored on `application/vnd.google.protobuf`, matching Prometheus, which feeds
/// every protobuf media type to its delimited protobuf parser.
///
/// A valid `escaping=<scheme>` parameter is additionally carried over to the resolved [`Format`]
/// on formats that negotiate one (text `1.0.0`, OpenMetrics `1.0.0`+), see
/// `with_declared_escaping`.
///
/// Resolving an OpenMetrics 2.0 or protobuf format authorizes *negotiation*, not decoding: those
/// layers land in Phase 3, so `arrow::ArrowDecoder` still rejects the resolved format with
/// `DecodeError::UnsupportedFormat`.
///
/// `fallback_protocol` resolves blank, unparsable, unsupported, and OpenMetrics 2.0-without-flag
/// content types to the protocol's own format and returns the problem as a
/// [`ScrapeFormatWarning`]; without a fallback those content types are a [`ScrapeFormatError`].
///
/// # Errors
///
/// Returns [`ScrapeFormatError`] when the `Content-Type` cannot be used and no fallback protocol is
/// configured.
pub fn resolve_scrape_format(
    content_type: Option<&str>,
    fallback_protocol: Option<ScrapeProtocol>,
    enable_open_metrics_2: bool,
) -> Result<ResolvedScrapeFormat, ScrapeFormatError> {
    match resolve_media_type(content_type.unwrap_or_default(), enable_open_metrics_2) {
        Ok(format) => Ok(ResolvedScrapeFormat {
            format,
            warning: None,
        }),
        Err(err) => {
            let Some(fallback) = fallback_protocol else {
                return Err(err);
            };
            let warning = match &err {
                ScrapeFormatError::BlankContentType => {
                    ScrapeFormatWarning::BlankContentType { fallback }
                }
                ScrapeFormatError::UnparsableContentType {
                    content_type,
                    reason,
                } => ScrapeFormatWarning::UnparsableContentType {
                    content_type: content_type.clone(),
                    reason,
                    fallback,
                },
                ScrapeFormatError::OpenMetrics2Disabled { content_type } => {
                    ScrapeFormatWarning::OpenMetrics2Disabled {
                        content_type: content_type.clone(),
                        fallback,
                    }
                }
                ScrapeFormatError::UnsupportedContentType { content_type } => {
                    ScrapeFormatWarning::UnsupportedContentType {
                        content_type: content_type.clone(),
                        fallback,
                    }
                }
            };
            Ok(ResolvedScrapeFormat {
                format: resolve_fallback_format(fallback, enable_open_metrics_2),
                warning: Some(warning),
            })
        }
    }
}

/// Resolves `fallback_scrape_protocol` to a [`Format`], honoring OpenMetrics 2.0 gating.
///
/// Prometheus truncates `fallback_scrape_protocol` to a bare media type (`HeaderMediaType`), which
/// always selects the OpenMetrics 1.0.0 parser for OpenMetrics fallbacks. Keeping the configured
/// version instead means `OpenMetricsText2.0.0` selects the OpenMetrics 2.0 parser, and a 2.x
/// fallback with OpenMetrics 2.0 disabled degrades to [`Format::OPEN_METRICS_1_0_0`], which is the
/// parser Prometheus ends up using for that configuration.
fn resolve_fallback_format(protocol: ScrapeProtocol, enable_open_metrics_2: bool) -> Format {
    if protocol.is_open_metrics_2() && !enable_open_metrics_2 {
        Format::OPEN_METRICS_1_0_0
    } else {
        protocol.format()
    }
}

/// Scraper-side media type resolution behind [`resolve_scrape_format`], matching
/// `extractMediaType` in `prometheus/prometheus/model/textparse/interface.go`.
fn resolve_media_type(
    content_type: &str,
    enable_open_metrics_2: bool,
) -> Result<Format, ScrapeFormatError> {
    if content_type.is_empty() {
        return Err(ScrapeFormatError::BlankContentType);
    }
    let (media_type, params) = parse_media_type_detailed(content_type).map_err(|reason| {
        ScrapeFormatError::UnparsableContentType {
            content_type: content_type.to_owned(),
            reason,
        }
    })?;
    let version = params.get(VERSION_KEY).copied().unwrap_or("");

    let format = match media_type.as_str() {
        OPEN_METRICS_TYPE if is_open_metrics_20_version(version) => {
            // OpenMetrics 2.0 stays experimental in Prometheus, so it is only usable when
            // explicitly enabled.
            if !enable_open_metrics_2 {
                return Err(ScrapeFormatError::OpenMetrics2Disabled {
                    content_type: content_type.to_owned(),
                });
            }
            if version == OPEN_METRICS_VERSION_2_0_0_RC {
                Format::OPEN_METRICS_2_0_0_RC
            } else {
                Format::OPEN_METRICS_2_0_0
            }
        }
        OPEN_METRICS_TYPE => match version {
            "" | OPEN_METRICS_VERSION_0_0_1 => Format::OPEN_METRICS_0_0_1,
            // `1.0.0` and every unknown version are decoded by the OpenMetrics 1.0 parser in
            // Prometheus, so they resolve to the 1.0.0 baseline instead of failing.
            _ => Format::OPEN_METRICS_1_0_0,
        },
        TEXT_TYPE => {
            if version == TEXT_VERSION_1_0_0 {
                Format::TEXT_1_0_0
            } else {
                // Prometheus decodes every `text/plain` version, including unknown ones, with the
                // Prometheus text parser, so the legacy baseline is the faithful resolution.
                Format::TEXT
            }
        }
        // Prometheus ignores `proto` and `encoding` and feeds every protobuf media type to its
        // delimited protobuf parser, so there is no escaping scheme to carry over either.
        PROTO_TYPE => return Ok(Format::PROTO_DELIM),
        _ => {
            return Err(ScrapeFormatError::UnsupportedContentType {
                content_type: content_type.to_owned(),
            });
        }
    };

    Ok(with_declared_escaping(format, &params))
}

/// Carries a valid `escaping=<scheme>` response parameter over to `format`.
///
/// Prometheus never reads escaping from responses, but [`Format`] is this crate's carrier for the
/// escaping scheme, so dropping a scheme a target declared would silently make
/// [`Format::to_escaping_scheme`] report the `underscores` default for, say, an `allow-utf-8`
/// target.
///
/// Only formats that negotiate an escaping scheme are considered, matching
/// [`ScrapeProtocol::supports_escaping`]: legacy `0.0.1` and `0.0.4` media types never advertise
/// `escaping=`, so a stray parameter on such a response must not change how callers interpret its
/// names. Invalid schemes are ignored, as Prometheus does.
fn with_declared_escaping(format: Format, params: &HashMap<String, &str>) -> Format {
    if !carries_escaping_scheme(&format) {
        return format;
    }
    let Some(scheme) = params
        .get(ESCAPING_KEY)
        .copied()
        .and_then(|raw| raw.parse::<EscapingScheme>().ok())
    else {
        return format;
    };
    format.with_escaping_scheme(scheme)
}

/// Whether `format` has a version that negotiates `escaping=<scheme>`, matching
/// [`ScrapeProtocol::supports_escaping`].
fn carries_escaping_scheme(format: &Format) -> bool {
    match format.format_type() {
        FormatType::TextPlain => format.version() == TEXT_VERSION_1_0_0,
        FormatType::OpenMetrics => {
            let version = format.version();
            version == OPEN_METRICS_VERSION_1_0_0 || is_open_metrics_20_version(version)
        }
        _ => false,
    }
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value using
/// [`DEFAULT_ACCEPTED_FORMATS`] and `default_escaping`.
#[must_use]
pub fn negotiate(accept_header: &str, default_escaping: EscapingScheme) -> Format {
    negotiate_accept(accept_header, DEFAULT_ACCEPTED_FORMATS, default_escaping)
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value using
/// [`DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS`] and `default_escaping`.
#[must_use]
pub fn negotiate_including_open_metrics(
    accept_header: &str,
    default_escaping: EscapingScheme,
) -> Format {
    negotiate_accept(
        accept_header,
        DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS,
        default_escaping,
    )
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value and an ordered slice of
/// `accepted` formats, matching `NegotiateAccept` in `prometheus/common/expfmt/encode.go`.
///
/// Clauses with `q=0` (or an invalid `q` weight) are treated as not acceptable per
/// [RFC 9110 Section 12.4.2](https://www.rfc-editor.org/rfc/rfc9110#section-12.4.2) and skipped.
#[must_use]
pub fn negotiate_accept(
    accept_header: &str,
    accepted: &[Format],
    default_escaping: EscapingScheme,
) -> Format {
    let default_suffix = format!("; {ESCAPING_KEY}={default_escaping}");
    for ac in parse_accept(accept_header) {
        if ac.q <= 0.0 {
            continue;
        }
        for f in accepted {
            if match_format(&ac, f) {
                let suffix = escaping_for(&ac, f, default_escaping);
                return Format::new(format!("{f}{suffix}"));
            }
        }
    }
    for f in accepted {
        if f.format_type() == FormatType::TextPlain {
            return Format::new(format!("{f}{default_suffix}"));
        }
    }
    if let Some(first) = accepted.first() {
        return Format::new(format!("{first}{default_suffix}"));
    }
    Format::new(format!("{}{default_suffix}", Format::TEXT))
}

fn is_open_metrics_20_version(v: &str) -> bool {
    v == OPEN_METRICS_VERSION_2_0_0 || v == OPEN_METRICS_VERSION_2_0_0_RC
}

fn escaping_for(ac: &AcceptClause<'_>, f: &Format, default_escaping: EscapingScheme) -> String {
    if let Some(&p) = ac.params.get(ESCAPING_KEY)
        && p.parse::<EscapingScheme>().is_ok()
    {
        // An explicit valid escaping request wins, including for OpenMetrics 2.0.
        return format!("; {ESCAPING_KEY}={p}");
    }
    if f.format_type() == FormatType::OpenMetrics && is_open_metrics_20_version(f.version()) {
        // OpenMetrics 2.0 is UTF-8 native, so requesting it implies UTF-8 name support.
        return format!("; {ESCAPING_KEY}={}", EscapingScheme::AllowUtf8);
    }
    format!("; {ESCAPING_KEY}={default_escaping}")
}

#[derive(Clone, Debug)]
struct AcceptClause<'a> {
    main_type: &'a str,
    sub_type: &'a str,
    q: f64,
    params: HashMap<&'a str, &'a str>,
}

/// Parses an HTTP `Accept` header into quality-ordered clauses matching `goautoneg.ParseAccept`.
fn parse_accept(header: &str) -> Vec<AcceptClause<'_>> {
    if header.trim().is_empty() {
        return Vec::new();
    }
    let mut clauses = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut subparts = part.split(';');
        let Some(media_range) = subparts.next().map(str::trim) else {
            continue;
        };
        let mut type_parts = media_range.split('/');
        let (Some(main_type), Some(sub_type), None) =
            (type_parts.next(), type_parts.next(), type_parts.next())
        else {
            continue;
        };

        let mut q = 1.0_f64;
        let mut params = HashMap::new();
        for sp in subparts {
            let sp = sp.trim();
            if sp.is_empty() {
                continue;
            }
            let mut kv = sp.split('=');
            let (Some(k), Some(v), None) = (kv.next(), kv.next(), kv.next()) else {
                continue;
            };
            let k = k.trim();
            let v = v.trim();
            if k == "q" {
                match v.parse::<f64>() {
                    Ok(parsed_q) if (0.0..=1.0).contains(&parsed_q) => q = parsed_q,
                    _ => q = 0.0,
                }
            } else {
                params.insert(k, v);
            }
        }
        clauses.push(AcceptClause {
            main_type: main_type.trim(),
            sub_type: sub_type.trim(),
            q,
            params,
        });
    }
    // NOTE: Stable sort preserves header order for clauses with equal quality factors.
    clauses.sort_by(|a, b| b.q.total_cmp(&a.q));
    clauses
}

static FORMAT_TO_ACCEPT: LazyLock<HashMap<&'static str, AcceptClause<'static>>> =
    LazyLock::new(|| {
        [
            FMT_TEXT,
            FMT_PROTO_DELIM,
            FMT_PROTO_TEXT,
            FMT_PROTO_COMPACT,
            FMT_OPEN_METRICS_1_0_0,
            FMT_OPEN_METRICS_2_0_0_RC,
            FMT_OPEN_METRICS_2_0_0,
            FMT_OPEN_METRICS_0_0_1,
        ]
        .into_iter()
        .filter_map(|fmt| {
            parse_accept(fmt)
                .into_iter()
                .next()
                .map(|clause| (fmt, clause))
        })
        .collect()
    });

fn match_format(ac: &AcceptClause<'_>, f: &Format) -> bool {
    let parsed;
    let target = if let Some(cached) = FORMAT_TO_ACCEPT.get(f.as_str()) {
        cached
    } else {
        parsed = parse_accept(f.as_str());
        let Some(first) = parsed.first() else {
            return false;
        };
        first
    };

    if ac.main_type != "*" && ac.main_type != target.main_type {
        return false;
    }
    if ac.sub_type != "*" && ac.sub_type != target.sub_type {
        return false;
    }

    let mut ac_version = ac.params.get(VERSION_KEY).copied().unwrap_or("");
    if ac_version.is_empty() && ac.main_type == "application" && ac.sub_type == "openmetrics-text" {
        ac_version = OPEN_METRICS_VERSION_0_0_1;
    }
    if ac_version.is_empty() && ac.main_type == "text" && ac.sub_type == "plain" {
        ac_version = TEXT_VERSION;
    }

    for (&k, &v) in &target.params {
        if k == CHARSET_KEY {
            continue;
        }
        let ac_val = if k == VERSION_KEY {
            ac_version
        } else {
            ac.params.get(k).copied().unwrap_or("")
        };
        if ac_val != v {
            return false;
        }
    }

    true
}

/// Minimal RFC 1521 / `mime.ParseMediaType` parser for `type/subtype; key=val` strings.
fn parse_media_type(input: &str) -> Option<(String, HashMap<String, &str>)> {
    parse_media_type_detailed(input).ok()
}

/// [`parse_media_type`] with a parse reason, so scrape errors can say *why* a target
/// `Content-Type` was rejected, like the `mime.ParseMediaType` error Go joins into its message.
fn parse_media_type_detailed(input: &str) -> Result<(String, HashMap<String, &str>), &'static str> {
    let mut parts = input.split(';');
    let base = parts.next().unwrap_or_default().trim();
    let Some((main_type, sub_type)) = base.split_once('/') else {
        return Err("expected a type/subtype media type");
    };
    if !is_valid_token(main_type) || !is_valid_token(sub_type) {
        return Err("invalid media type token");
    }

    let mut params = HashMap::new();
    for raw_param in parts {
        let trimmed = raw_param.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err("invalid media parameter");
        };
        let k = k.trim();
        let v = v.trim();
        let v = if let Some(inner) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            inner
        } else {
            if v.is_empty() || v.contains('"') {
                return Err("invalid media parameter value");
            }
            v
        };
        if !is_valid_token(k) {
            return Err("invalid media parameter name");
        }
        // NOTE: Duplicate parameter names are last-wins, where Go's `mime.ParseMediaType` rejects
        // them as "duplicate parameter name".
        params.insert(k.to_ascii_lowercase(), v);
    }
    Ok((base.to_ascii_lowercase(), params))
}

fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_format_type() {
        let cases = [
            (Format::PROTO_COMPACT, FormatType::ProtoCompact),
            (Format::PROTO_DELIM, FormatType::ProtoDelim),
            (Format::PROTO_TEXT, FormatType::ProtoText),
            (Format::OPEN_METRICS_2_0_0_RC, FormatType::OpenMetrics),
            (Format::OPEN_METRICS_2_0_0, FormatType::OpenMetrics),
            (Format::OPEN_METRICS_1_0_0, FormatType::OpenMetrics),
            (Format::TEXT, FormatType::TextPlain),
            (Format::OPEN_METRICS_0_0_1, FormatType::OpenMetrics),
            (
                Format::from("application/vnd.google.protobuf; proto=BadProtocol; encoding=text"),
                FormatType::Unknown,
            ),
            (
                Format::from("application/vnd.google.protobuf"),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily=bad",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=textual",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from("application/openmetrics-text; version=1.0.0; charset=ascii"),
                FormatType::Unknown,
            ),
            (Format::from("text/plain"), FormatType::TextPlain),
            (Format::TEXT_1_0_0, FormatType::TextPlain),
            (
                Format::from("text/plain; version=1.0.0; escaping=allow-utf-8"),
                FormatType::TextPlain,
            ),
            (
                Format::from("text/plain; version=invalid"),
                FormatType::Unknown,
            ),
            (Format::from("gobbledygook"), FormatType::Unknown),
        ];

        for (format, expected) in cases {
            assert_eq!(format.format_type(), expected, "format={format}");
        }
    }

    #[test]
    fn to_escaping_scheme() {
        let cases = [
            (
                Format::PROTO_COMPACT,
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::EscapeUnderscores,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=dots",
                ),
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::EscapeDots,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
                ),
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::AllowUtf8,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=invalid",
                ),
                EscapingScheme::EscapeValues,
                EscapingScheme::EscapeValues,
            ),
        ];

        for (format, default_scheme, expected) in cases {
            assert_eq!(
                format.to_escaping_scheme_with_default(default_scheme),
                expected,
                "format={format}"
            );
        }

        assert_eq!(EscapingScheme::default(), EscapingScheme::EscapeUnderscores);
        assert_eq!(
            Format::PROTO_COMPACT.to_escaping_scheme(),
            EscapingScheme::EscapeUnderscores
        );
    }

    #[test]
    fn with_escaping_scheme() {
        let cases = [
            (
                "no existing term, append one",
                Format::PROTO_COMPACT,
                EscapingScheme::EscapeDots,
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=dots",
            ),
            (
                "existing term at end, replace",
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores",
                ),
                EscapingScheme::EscapeValues,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "existing term in middle, replace",
                Format::from(
                    "application/openmetrics-text; escaping=dots; version=1.0.0; charset=utf-8; ",
                ),
                EscapingScheme::AllowUtf8,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "multiple existing terms removed",
                Format::from(
                    "application/openmetrics-text; escaping=dots; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
                ),
                EscapingScheme::EscapeValues,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
        ];

        for (name, format, scheme, expected) in cases {
            assert_eq!(
                format.with_escaping_scheme(scheme).as_str(),
                expected,
                "case={name}"
            );
        }
    }

    #[test]
    fn format_version() {
        let cases = [
            (Format::TEXT, "0.0.4"),
            (
                Format::TEXT.with_escaping_scheme(EscapingScheme::AllowUtf8),
                "0.0.4",
            ),
            (Format::OPEN_METRICS_0_0_1, "0.0.1"),
            (Format::OPEN_METRICS_1_0_0, "1.0.0"),
            (Format::OPEN_METRICS_2_0_0_RC, "2.0.0-rc"),
            (
                Format::OPEN_METRICS_2_0_0_RC.with_escaping_scheme(EscapingScheme::EscapeDots),
                "2.0.0-rc",
            ),
            (Format::OPEN_METRICS_2_0_0, "2.0.0"),
            (
                Format::OPEN_METRICS_2_0_0.with_escaping_scheme(EscapingScheme::EscapeDots),
                "2.0.0",
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=\"\"",
                ),
                "2.0.0",
            ),
            (
                Format::from("application/openmetrics-text; version=\"2.0.0\"; charset=utf-8"),
                "2.0.0",
            ),
            (
                Format::from("application/openmetrics-text; version=2.0.0; escaping="),
                "",
            ),
            (Format::PROTO_DELIM, ""),
            (Format::PROTO_TEXT, ""),
            (Format::PROTO_COMPACT, ""),
            (Format::UNKNOWN, ""),
            (Format::from("invalid"), ""),
        ];

        for (format, expected) in cases {
            assert_eq!(format.version(), expected, "format={format}");
        }
    }

    #[test]
    fn negotiate_default() {
        let prefix = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily";
        let cases = [
            (
                "delimited format",
                format!("{prefix};encoding=delimited"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=underscores",
            ),
            (
                "text format",
                format!("{prefix};encoding=text"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text; escaping=underscores",
            ),
            (
                "compact text format",
                format!("{prefix};encoding=compact-text"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=underscores",
            ),
            (
                "plain text format",
                "text/plain;version=0.0.4".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "delimited format utf-8",
                format!("{prefix};encoding=delimited; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=allow-utf-8",
            ),
            (
                "text format utf-8",
                format!("{prefix};encoding=text; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text; escaping=allow-utf-8",
            ),
            (
                "compact text format utf-8",
                format!("{prefix};encoding=compact-text; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=allow-utf-8",
            ),
            (
                "plain text format 0.0.4 trailing semicolon",
                "text/plain;version=0.0.4;".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "plain text format 0.0.4 escaping=values",
                "text/plain;version=0.0.4; escaping=values;".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */*",
                "*/*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "browser Accept header with wildcard",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "json with wildcard fallback",
                "application/json, */*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
        ];

        for (name, accept, expected) in cases {
            let actual = negotiate(&accept, EscapingScheme::EscapeUnderscores);
            assert_eq!(actual.as_str(), expected, "case={name}");
        }
    }

    #[test]
    fn negotiate_open_metrics() {
        let prefix = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily";
        let cases = [
            (
                "OM format, no version",
                "application/openmetrics-text".to_owned(),
                "application/openmetrics-text; version=0.0.1; charset=utf-8; escaping=values",
            ),
            (
                "OM format, 0.0.1 version",
                "application/openmetrics-text;version=0.0.1; escaping=underscores".to_owned(),
                "application/openmetrics-text; version=0.0.1; charset=utf-8; escaping=underscores",
            ),
            (
                "OM format, 1.0.0 version",
                "application/openmetrics-text;version=1.0.0".to_owned(),
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "OM format, 2.0.0 version not in default OM accepted",
                "application/openmetrics-text;version=2.0.0".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "OM format, invalid version",
                "application/openmetrics-text;version=0.0.4".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "compact text format",
                format!("{prefix};encoding=compact-text; escaping=underscores"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=underscores",
            ),
            (
                "plain text format 0.0.4 allow-utf-8",
                "text/plain;version=0.0.4; escaping=allow-utf-8".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "wildcard */*",
                "*/*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
        ];

        for (name, accept, expected) in cases {
            let actual = negotiate_including_open_metrics(&accept, EscapingScheme::EscapeValues);
            assert_eq!(actual.as_str(), expected, "case={name}");
        }
    }

    #[test]
    fn negotiate_accept_custom() {
        let cases: &[(&str, &str, &[Format], &str)] = &[
            (
                "requested OM 2.0-rc, accepted OM 2.0-rc",
                "application/openmetrics-text;version=2.0.0-rc",
                &[Format::OPEN_METRICS_2_0_0_RC, Format::TEXT],
                "application/openmetrics-text; version=2.0.0-rc; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 2.0-rc with explicit escaping",
                "application/openmetrics-text;version=2.0.0-rc;escaping=underscores",
                &[Format::OPEN_METRICS_2_0_0_RC, Format::TEXT],
                "application/openmetrics-text; version=2.0.0-rc; charset=utf-8; escaping=underscores",
            ),
            (
                "requested OM 2.0, accepted OM 2.0",
                "application/openmetrics-text;version=2.0.0",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 2.0 with explicit escaping",
                "application/openmetrics-text;version=2.0.0;escaping=underscores",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=underscores",
            ),
            (
                "requested OM 2.0 with unknown escaping",
                "application/openmetrics-text;version=2.0.0;escaping=foo",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 1.0 without escaping keeps the default",
                "application/openmetrics-text;version=1.0.0",
                &[
                    Format::OPEN_METRICS_2_0_0,
                    Format::OPEN_METRICS_1_0_0,
                    Format::TEXT,
                ],
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "escaping from a skipped clause is not applied to the match",
                "application/json;escaping=allow-utf-8, text/plain;version=0.0.4",
                &[Format::PROTO_DELIM, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "requested OM 2.0, not accepted, falls back to text",
                "application/openmetrics-text;version=2.0.0",
                &[Format::OPEN_METRICS_1_0_0, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "requested OM 2.0, not accepted, falls back to first format when no text in accepted",
                "application/openmetrics-text;version=2.0.0",
                &[Format::PROTO_DELIM],
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=values",
            ),
            (
                "requested OM 1.0 and 2.0, prefers higher q value",
                "application/openmetrics-text;version=1.0.0;q=0.8, application/openmetrics-text;version=2.0.0;q=0.9",
                &[
                    Format::OPEN_METRICS_1_0_0,
                    Format::OPEN_METRICS_2_0_0,
                    Format::TEXT,
                ],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "q=0 clause is skipped as not acceptable",
                "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0",
                &[Format::PROTO_DELIM, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "q=0 clause is skipped in favor of lower-priority acceptable clause",
                "application/openmetrics-text;version=2.0.0;q=0, application/openmetrics-text;version=1.0.0;q=0.5",
                &[
                    Format::OPEN_METRICS_2_0_0,
                    Format::OPEN_METRICS_1_0_0,
                    Format::TEXT,
                ],
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */* matches text format if present",
                "*/*",
                &[
                    Format::OPEN_METRICS_2_0_0,
                    Format::PROTO_DELIM,
                    Format::TEXT,
                ],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */* with text first in accepted",
                "*/*",
                &[Format::TEXT, Format::PROTO_DELIM],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */* falls back to first format when no text in accepted",
                "*/*",
                &[Format::OPEN_METRICS_2_0_0, Format::PROTO_DELIM],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=values",
            ),
            (
                "unversioned text/plain matches FmtText",
                "text/plain",
                &[Format::PROTO_DELIM, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "empty accepted list defaults to FmtText",
                "application/unknown",
                &[],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
        ];

        for (name, accept, accepted, expected) in cases {
            let actual = negotiate_accept(accept, accepted, EscapingScheme::EscapeValues);
            assert_eq!(actual.as_str(), *expected, "case={name}");
        }
    }

    #[test]
    fn response_format_extraction() {
        assert_eq!(response_format(FMT_TEXT), Format::TEXT);
        assert_eq!(response_format("text/plain"), Format::TEXT);
        assert_eq!(response_format("Text/Plain"), Format::TEXT);
        assert_eq!(response_format("Text/Plain; VERSION=0.0.4"), Format::TEXT);
        // NOTE: unlike Go's `expfmt.ResponseFormat`, `text/plain; version=1.0.0` is recognized
        // because it is a format scrapers negotiate (`ScrapeProtocol::PrometheusText1_0_0`).
        assert_eq!(response_format(FMT_TEXT_1_0_0), Format::TEXT_1_0_0);
        assert_eq!(
            response_format("text/plain; version=1.0.0; escaping=allow-utf-8"),
            Format::TEXT_1_0_0.with_escaping_scheme(EscapingScheme::AllowUtf8)
        );
        assert_eq!(
            response_format("application/openmetrics-text; version=1.0.0; escaping=dots"),
            Format::OPEN_METRICS_1_0_0.with_escaping_scheme(EscapingScheme::EscapeDots)
        );
        // Legacy formats never negotiate `escaping=`, so a stray parameter is ignored.
        assert_eq!(
            response_format("text/plain; version=0.0.4; escaping=allow-utf-8"),
            Format::TEXT
        );
        assert_eq!(
            response_format("application/openmetrics-text; version=1.0.0; escaping=invalid-scheme"),
            Format::OPEN_METRICS_1_0_0
        );
        assert_eq!(response_format("text/plain; version="), Format::UNKNOWN);
        assert_eq!(
            response_format("text/plain; version=0.0.5"),
            Format::UNKNOWN
        );
        assert_eq!(
            response_format(FMT_OPEN_METRICS_0_0_1),
            Format::OPEN_METRICS_0_0_1
        );
        assert_eq!(
            response_format("application/openmetrics-text"),
            Format::OPEN_METRICS_0_0_1
        );
        assert_eq!(
            response_format(FMT_OPEN_METRICS_1_0_0),
            Format::OPEN_METRICS_1_0_0
        );
        assert_eq!(
            response_format("Application/OpenMetrics-Text; VERSION=1.0.0"),
            Format::OPEN_METRICS_1_0_0
        );
        assert_eq!(response_format(FMT_OPEN_METRICS_2_0_0), Format::UNKNOWN);
        assert_eq!(
            response_format("application/openmetrics-text; version=0.0.4"),
            Format::UNKNOWN
        );
        assert_eq!(response_format(FMT_PROTO_DELIM), Format::PROTO_DELIM);
        assert_eq!(response_format(FMT_PROTO_TEXT), Format::UNKNOWN);
        assert_eq!(response_format("invalid"), Format::UNKNOWN);
    }

    #[test]
    fn format_errors() {
        let err = "bogus".parse::<EscapingScheme>().unwrap_err();
        assert_eq!(err, FormatError::UnknownEscapingScheme("bogus".to_owned()));
        assert_eq!(err.to_string(), "unknown escaping scheme: bogus");

        let err = Format::new_open_metrics("9.9.9").unwrap_err();
        assert_eq!(
            err,
            FormatError::UnknownOpenMetricsVersion("9.9.9".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "unknown open metrics version string: 9.9.9"
        );

        let err = "PrometheusText9.9.9".parse::<ScrapeProtocol>().unwrap_err();
        assert_eq!(
            err,
            FormatError::UnknownScrapeProtocol("PrometheusText9.9.9".to_owned())
        );
        assert_eq!(
            err.to_string(),
            "unknown scrape protocol: PrometheusText9.9.9"
        );
    }

    #[test]
    fn scrape_protocol_round_trip() {
        for protocol in ScrapeProtocol::ALL {
            assert_eq!(
                protocol.as_str().parse::<ScrapeProtocol>(),
                Ok(protocol),
                "token={protocol}"
            );
            assert_eq!(protocol.to_string(), protocol.as_str());
            assert_eq!(
                protocol.header().split(';').next(),
                Some(protocol.media_type())
            );
            let format = protocol.format();
            assert_ne!(
                format.format_type(),
                FormatType::Unknown,
                "token={protocol}"
            );
            // The header and format tables are hand-maintained; a version typo in either would
            // otherwise go unnoticed, since every text version maps to the same `FormatType`.
            if protocol != ScrapeProtocol::PrometheusProto {
                let (_, header_params) = parse_media_type(protocol.header()).unwrap();
                assert_eq!(
                    format.version(),
                    header_params.get(VERSION_KEY).copied().unwrap_or_default(),
                    "token={protocol}"
                );
            }
        }

        // The two tables that encode "which versions negotiate `escaping=`" must not drift:
        // the response side infers it from the resolved `Format`, the request side from the
        // protocol.
        for protocol in ScrapeProtocol::ALL {
            assert_eq!(
                carries_escaping_scheme(&protocol.format()),
                protocol.supports_escaping(),
                "token={protocol}"
            );
        }

        // Configuration tokens are case-sensitive, matching `config.ScrapeProtocol.Validate`.
        assert!("prometheustext0.0.4".parse::<ScrapeProtocol>().is_err());
        assert_eq!(
            "PrometheusText1.0.0".parse::<ScrapeProtocol>(),
            Ok(ScrapeProtocol::PrometheusText1_0_0)
        );
    }

    #[test]
    fn accept_header_matches_prometheus() {
        // Cases copied from `TestAcceptHeader` in `scrape/scrape_test.go`.
        let cases: &[(&str, &[ScrapeProtocol], EscapingScheme, &str)] = &[
            (
                "default scrape protocols with underscore escaping",
                DEFAULT_SCRAPE_PROTOCOLS,
                EscapingScheme::EscapeUnderscores,
                "application/openmetrics-text;version=1.0.0;escaping=underscores;q=0.8,\
                 application/openmetrics-text;version=0.0.1;q=0.7,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.6,\
                 text/plain;version=0.0.4;q=0.5,*/*;q=0.4",
            ),
            (
                "default proto first scrape protocols with dots escaping",
                DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS,
                EscapingScheme::EscapeDots,
                "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.8,\
                 application/openmetrics-text;version=1.0.0;escaping=dots;q=0.7,\
                 application/openmetrics-text;version=0.0.1;q=0.6,\
                 text/plain;version=1.0.0;escaping=dots;q=0.5,\
                 text/plain;version=0.0.4;q=0.4,*/*;q=0.3",
            ),
            (
                "default scrape protocols with allow-utf-8 escaping",
                DEFAULT_SCRAPE_PROTOCOLS,
                EscapingScheme::AllowUtf8,
                "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.8,\
                 application/openmetrics-text;version=0.0.1;q=0.7,\
                 text/plain;version=1.0.0;escaping=allow-utf-8;q=0.6,\
                 text/plain;version=0.0.4;q=0.5,*/*;q=0.4",
            ),
            (
                "default proto first scrape protocols with allow-utf-8 escaping",
                DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS,
                EscapingScheme::AllowUtf8,
                "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.8,\
                 application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.7,\
                 application/openmetrics-text;version=0.0.1;q=0.6,\
                 text/plain;version=1.0.0;escaping=allow-utf-8;q=0.5,\
                 text/plain;version=0.0.4;q=0.4,*/*;q=0.3",
            ),
            (
                "openmetrics 2.0.0 and 2.0.0-rc first with allow-utf-8 escaping",
                &[
                    ScrapeProtocol::OpenMetricsText2_0_0,
                    ScrapeProtocol::OpenMetricsText2_0_0Rc,
                    ScrapeProtocol::OpenMetricsText1_0_0,
                ],
                EscapingScheme::AllowUtf8,
                "application/openmetrics-text;version=2.0.0;escaping=allow-utf-8;q=0.8,\
                 application/openmetrics-text;version=2.0.0-rc;escaping=allow-utf-8;q=0.7,\
                 application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.6,\
                 */*;q=0.5",
            ),
            (
                "openmetrics 2.0.0 first with underscore escaping",
                &[
                    ScrapeProtocol::OpenMetricsText2_0_0,
                    ScrapeProtocol::OpenMetricsText1_0_0,
                ],
                EscapingScheme::EscapeUnderscores,
                "application/openmetrics-text;version=2.0.0;escaping=underscores;q=0.8,\
                 application/openmetrics-text;version=1.0.0;escaping=underscores;q=0.7,\
                 */*;q=0.6",
            ),
            (
                "openmetrics 2.0.0 only with allow-utf-8 escaping",
                &[ScrapeProtocol::OpenMetricsText2_0_0],
                EscapingScheme::AllowUtf8,
                "application/openmetrics-text;version=2.0.0;escaping=allow-utf-8;q=0.8,\
                 */*;q=0.7",
            ),
            (
                "empty protocol list only advertises the wildcard",
                &[],
                EscapingScheme::EscapeValues,
                "*/*;q=0.8",
            ),
            (
                "over-long protocol list clamps weights at q=0.1",
                &[ScrapeProtocol::PrometheusText1_0_0; 9],
                EscapingScheme::EscapeUnderscores,
                "text/plain;version=1.0.0;escaping=underscores;q=0.8,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.7,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.6,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.5,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.4,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.3,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.2,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.1,\
                 text/plain;version=1.0.0;escaping=underscores;q=0.1,*/*;q=0.1",
            ),
        ];

        for (name, protocols, scheme, expected) in cases {
            assert_eq!(accept_header(protocols, *scheme), *expected, "case={name}");
        }
    }

    #[test]
    fn resolve_scrape_format_matches_prometheus() {
        // Cases mirror `TestNew` in `model/textparse/interface_test.go`; error and warning text is
        // Prometheus's own wording, because callers relay it in scrape warnings and reports.
        /// `(name, content_type, fallback, openmetrics 2.0 enabled, expected, warning)`.
        struct Case(
            &'static str,
            Option<&'static str>,
            Option<ScrapeProtocol>,
            bool,
            Result<Format, &'static str>,
            Option<&'static str>,
        );

        let cases: &[Case] = &[
            Case(
                "blank content type without fallback",
                None,
                None,
                false,
                Err(
                    "non-compliant scrape target sending blank Content-Type and no fallback_scrape_protocol specified for target",
                ),
                None,
            ),
            Case(
                "empty content type without fallback",
                Some(""),
                None,
                false,
                Err(
                    "non-compliant scrape target sending blank Content-Type and no fallback_scrape_protocol specified for target",
                ),
                None,
            ),
            Case(
                "blank content type with text fallback",
                None,
                Some(ScrapeProtocol::PrometheusText0_0_4),
                false,
                Ok(Format::TEXT),
                Some(
                    "non-compliant scrape target sending blank Content-Type, using fallback_scrape_protocol \"text/plain\"",
                ),
            ),
            Case(
                "unparsable content type without fallback",
                Some("invalid/"),
                None,
                false,
                Err(
                    "cannot parse Content-Type \"invalid/\" (invalid media type token) and no fallback_scrape_protocol for target",
                ),
                None,
            ),
            Case(
                "unparsable content type with text fallback",
                Some("invalid/"),
                Some(ScrapeProtocol::PrometheusText0_0_4),
                false,
                Ok(Format::TEXT),
                Some(
                    "could not parse received Content-Type \"invalid/\" (invalid media type token), using fallback_scrape_protocol \"text/plain\"",
                ),
            ),
            Case(
                "unparsable content type with openmetrics fallback",
                Some("invalid/invalid/invalid"),
                Some(ScrapeProtocol::OpenMetricsText0_0_1),
                false,
                Ok(Format::OPEN_METRICS_0_0_1),
                Some(
                    "could not parse received Content-Type \"invalid/invalid/invalid\" (invalid media type token), using fallback_scrape_protocol \"application/openmetrics-text\"",
                ),
            ),
            Case(
                "unparsable content type with protobuf fallback",
                Some("invalid/"),
                Some(ScrapeProtocol::PrometheusProto),
                false,
                Ok(Format::PROTO_DELIM),
                Some(
                    "could not parse received Content-Type \"invalid/\" (invalid media type token), using fallback_scrape_protocol \"application/vnd.google.protobuf\"",
                ),
            ),
            Case(
                "openmetrics without version or charset",
                Some("application/openmetrics-text"),
                None,
                false,
                Ok(Format::OPEN_METRICS_0_0_1),
                None,
            ),
            Case(
                "openmetrics with charset only",
                Some("application/openmetrics-text; charset=utf-8"),
                None,
                false,
                Ok(Format::OPEN_METRICS_0_0_1),
                None,
            ),
            Case(
                "openmetrics 1.0.0 with charset",
                Some("application/openmetrics-text; version=1.0.0; charset=utf-8"),
                None,
                false,
                Ok(Format::OPEN_METRICS_1_0_0),
                None,
            ),
            Case(
                "openmetrics unknown version uses the 1.0.0 baseline",
                Some("application/openmetrics-text; version=0.0.4"),
                None,
                false,
                Ok(Format::OPEN_METRICS_1_0_0),
                None,
            ),
            Case(
                "openmetrics 2.0.0-rc gated",
                Some("application/openmetrics-text; version=2.0.0-rc"),
                None,
                true,
                Ok(Format::OPEN_METRICS_2_0_0_RC),
                None,
            ),
            Case(
                "openmetrics 2.0.0-rc disabled without fallback",
                Some("application/openmetrics-text; version=2.0.0-rc"),
                None,
                false,
                Err(
                    "received OpenMetrics 2.0 Content-Type \"application/openmetrics-text; version=2.0.0-rc\", but the openmetrics2 feature flag is not enabled and no fallback_scrape_protocol specified for target",
                ),
                None,
            ),
            Case(
                "openmetrics 2.0.0-rc disabled with openmetrics fallback",
                Some("application/openmetrics-text; version=2.0.0-rc"),
                Some(ScrapeProtocol::OpenMetricsText1_0_0),
                false,
                Ok(Format::OPEN_METRICS_1_0_0),
                Some(
                    "received OpenMetrics 2.0 Content-Type \"application/openmetrics-text; version=2.0.0-rc\", but the openmetrics2 feature flag is not enabled, using fallback_scrape_protocol \"application/openmetrics-text\"",
                ),
            ),
            Case(
                "openmetrics 2.0.0 gated",
                Some("application/openmetrics-text; version=2.0.0; charset=utf-8"),
                None,
                true,
                Ok(Format::OPEN_METRICS_2_0_0),
                None,
            ),
            Case(
                "openmetrics 2.0.0 disabled without fallback",
                Some("application/openmetrics-text; version=2.0.0"),
                None,
                false,
                Err(
                    "received OpenMetrics 2.0 Content-Type \"application/openmetrics-text; version=2.0.0\", but the openmetrics2 feature flag is not enabled and no fallback_scrape_protocol specified for target",
                ),
                None,
            ),
            Case(
                "text plain without version",
                Some("text/plain"),
                None,
                false,
                Ok(Format::TEXT),
                None,
            ),
            Case(
                "text plain 0.0.4",
                Some("text/plain; version=0.0.4"),
                None,
                false,
                Ok(Format::TEXT),
                None,
            ),
            Case(
                "text plain 1.0.0",
                Some("text/plain; version=1.0.0"),
                None,
                false,
                Ok(Format::TEXT_1_0_0),
                None,
            ),
            Case(
                "text plain 1.0.0 with allow-utf-8 escaping",
                Some("text/plain; version=1.0.0; escaping=allow-utf-8"),
                None,
                false,
                Ok(Format::TEXT_1_0_0.with_escaping_scheme(EscapingScheme::AllowUtf8)),
                None,
            ),
            Case(
                "openmetrics 1.0.0 with dots escaping",
                Some("application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=dots"),
                None,
                false,
                Ok(Format::OPEN_METRICS_1_0_0.with_escaping_scheme(EscapingScheme::EscapeDots)),
                None,
            ),
            Case(
                "invalid escaping parameter is ignored",
                Some("text/plain; version=1.0.0; escaping=bogus"),
                None,
                false,
                Ok(Format::TEXT_1_0_0),
                None,
            ),
            Case(
                "legacy text 0.0.4 never negotiates escaping",
                Some("text/plain; version=0.0.4; escaping=allow-utf-8"),
                None,
                false,
                Ok(Format::TEXT),
                None,
            ),
            Case(
                "legacy openmetrics 0.0.1 never negotiates escaping",
                Some("application/openmetrics-text; version=0.0.1; escaping=allow-utf-8"),
                None,
                false,
                Ok(Format::OPEN_METRICS_0_0_1),
                None,
            ),
            Case(
                "openmetrics 2.0.0 with allow-utf-8 escaping",
                Some("application/openmetrics-text; version=2.0.0; escaping=allow-utf-8"),
                None,
                true,
                Ok(Format::OPEN_METRICS_2_0_0.with_escaping_scheme(EscapingScheme::AllowUtf8)),
                None,
            ),
            Case(
                "duplicate media type parameters are last-wins",
                Some("application/openmetrics-text; charset=UTF-8; charset=utf-8"),
                None,
                false,
                Ok(Format::OPEN_METRICS_0_0_1),
                None,
            ),
            Case(
                "content type without media type separator",
                Some("gobbledygook"),
                Some(ScrapeProtocol::PrometheusText0_0_4),
                false,
                Ok(Format::TEXT),
                Some(
                    "could not parse received Content-Type \"gobbledygook\" (expected a type/subtype media type), using fallback_scrape_protocol \"text/plain\"",
                ),
            ),
            Case(
                "text plain unknown version uses the 0.0.4 baseline",
                Some("text/plain; version=9.9.9"),
                None,
                false,
                Ok(Format::TEXT),
                None,
            ),
            Case(
                "protobuf without parameters",
                Some("application/vnd.google.protobuf"),
                None,
                false,
                Ok(Format::PROTO_DELIM),
                None,
            ),
            Case(
                "protobuf delimited",
                Some(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
                ),
                None,
                false,
                Ok(Format::PROTO_DELIM),
                None,
            ),
            Case(
                "unsupported content type without fallback",
                Some("text/html"),
                None,
                false,
                Err(
                    "received unsupported Content-Type \"text/html\" and no fallback_scrape_protocol specified for target",
                ),
                None,
            ),
            Case(
                "unsupported content type with text fallback",
                Some("text/html"),
                Some(ScrapeProtocol::PrometheusText0_0_4),
                false,
                Ok(Format::TEXT),
                Some(
                    "received unsupported Content-Type \"text/html\", using fallback_scrape_protocol \"text/plain\"",
                ),
            ),
            Case(
                "openmetrics 2.0.0 fallback stays 2.0.0 when gated on",
                None,
                Some(ScrapeProtocol::OpenMetricsText2_0_0),
                true,
                Ok(Format::OPEN_METRICS_2_0_0),
                Some(
                    "non-compliant scrape target sending blank Content-Type, using fallback_scrape_protocol \"application/openmetrics-text\"",
                ),
            ),
            Case(
                "openmetrics 2.0.0 fallback degrades when gated off",
                None,
                Some(ScrapeProtocol::OpenMetricsText2_0_0),
                false,
                Ok(Format::OPEN_METRICS_1_0_0),
                Some(
                    "non-compliant scrape target sending blank Content-Type, using fallback_scrape_protocol \"application/openmetrics-text\"",
                ),
            ),
        ];

        for Case(name, content_type, fallback, enable_om2, expected, expected_warning) in cases {
            let resolved = resolve_scrape_format(*content_type, *fallback, *enable_om2);
            match expected {
                Ok(format) => {
                    let resolved = resolved.expect(name);
                    assert_eq!(&resolved.format, format, "case={name}");
                    assert_eq!(
                        resolved
                            .warning
                            .as_ref()
                            .map(ToString::to_string)
                            .as_deref(),
                        *expected_warning,
                        "case={name}"
                    );
                }
                Err(message) => {
                    let err = resolved.expect_err(name);
                    assert_eq!(&err.to_string(), message, "case={name}");
                    assert_eq!(*expected_warning, None, "case={name}");
                }
            }
        }
    }
}
