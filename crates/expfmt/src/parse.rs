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

//! Layer 0 zero-copy streaming parsers, mirroring
//! [`prometheus/prometheus/model/textparse`](https://github.com/prometheus/prometheus/tree/main/model/textparse).

use std::borrow::Cow;

mod float;
#[cfg(test)]
mod go_diff_tests;
mod omlex;
mod omparse;
mod promlex;
mod promparse;
#[cfg(feature = "dto")]
mod protobufparse;

pub(crate) use float::parse_go_float;
pub use omparse::OpenMetricsParser;
pub(crate) use omparse::{OmScratch, OpenMetricsParserState};
pub use promparse::PromParser;
pub(crate) use promparse::{ByteSpan, LabelSpan, PromParserState, unescape_bytes_into};
#[cfg(feature = "dto")]
pub use protobufparse::ProtobufParser;

/// Label name under which [`Parser::labels`] stores the metric name.
pub const METRIC_NAME_LABEL: &str = "__name__";

/// Label name for the upper bound of a classic histogram bucket, Go's `model.BucketLabel`.
pub const BUCKET_LABEL: &str = "le";

/// Label name for the quantile of a summary sample, Go's `model.QuantileLabel`.
pub const QUANTILE_LABEL: &str = "quantile";

/// Kind of the entry the parser is positioned on after [`Parser::next_entry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Entry {
    /// A `# TYPE` line. Read it with [`Parser::metric_type`].
    Type,
    /// A `# HELP` line. Read it with [`Parser::help`].
    Help,
    /// A `# UNIT` line. Read it with [`Parser::unit`].
    Unit,
    /// Any other comment line. Read it with [`Parser::comment`].
    Comment,
    /// A sample with a float64 value. Read it with [`Parser::series`] and [`Parser::labels`].
    Series,
    /// A sample with a native histogram value. Read it with [`Parser::histogram`] and
    /// [`Parser::labels`].
    Histogram,
}

/// Bucket span of a native histogram, Go's `histogram.Span`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// Gap to the previous span, or the start index of the first span.
    pub offset: i32,
    /// Number of consecutive buckets.
    pub length: u32,
}

/// Counter reset hint of a native histogram, Go's `histogram.CounterResetHint`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum CounterResetHint {
    /// No hint, Go's `UnknownCounterReset`.
    #[default]
    Unknown = 0,
    /// The histogram is a gauge, Go's `GaugeType`.
    Gauge = 3,
}

/// Native histogram. With `C = u64` and `B = i64` it is Go's `histogram.Histogram`, with
/// delta-encoded bucket counts. With `C = B = f64` it is Go's `histogram.FloatHistogram`,
/// with absolute bucket counts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Histogram<C, B> {
    /// Counter reset hint.
    pub counter_reset_hint: CounterResetHint,
    /// Resolution of the exponential buckets, or -53 for custom buckets (NHCB), where the
    /// spans index the bounds in `custom_values`.
    pub schema: i32,
    /// Width of the zero bucket.
    pub zero_threshold: f64,
    /// Observations in the zero bucket.
    pub zero_count: C,
    /// Total number of observations.
    pub count: C,
    /// Sum of observations.
    pub sum: f64,
    /// Spans of the positive buckets.
    pub positive_spans: Vec<Span>,
    /// Positive bucket counts.
    pub positive_buckets: Vec<B>,
    /// Spans of the negative buckets.
    pub negative_spans: Vec<Span>,
    /// Negative bucket counts.
    pub negative_buckets: Vec<B>,
    /// Upper bounds of the custom buckets, without `+Inf`, when `schema` is -53 (NHCB).
    pub custom_values: Vec<f64>,
}

/// Native histogram value returned by [`Parser::histogram`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HistogramRef<'h> {
    /// Integer counts, Go's `*histogram.Histogram`.
    Int(&'h Histogram<u64, i64>),
    /// Float counts, Go's `*histogram.FloatHistogram`.
    Float(&'h Histogram<f64, f64>),
}

static EMPTY_HISTOGRAM: Histogram<u64, i64> = Histogram {
    counter_reset_hint: CounterResetHint::Unknown,
    schema: 0,
    zero_threshold: 0.0,
    zero_count: 0,
    count: 0,
    sum: 0.0,
    positive_spans: Vec::new(),
    positive_buckets: Vec::new(),
    negative_spans: Vec::new(),
    negative_buckets: Vec::new(),
    custom_values: Vec::new(),
};

/// Metric type declared by a `# TYPE` line.
///
/// Mirrors `model.MetricType` in `prometheus/common/model`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetricType {
    /// `untyped` in Prometheus text, `unknown` in OpenMetrics.
    #[default]
    Unknown,
    /// `counter`.
    Counter,
    /// `gauge`.
    Gauge,
    /// `histogram`.
    Histogram,
    /// `summary`.
    Summary,
    /// OpenMetrics `gaugehistogram`.
    GaugeHistogram,
    /// OpenMetrics `info`.
    Info,
    /// OpenMetrics `stateset`.
    Stateset,
}

impl MetricType {
    /// Returns Go's `model.MetricType` string, for example `"counter"` or `"unknown"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
            Self::Summary => "summary",
            Self::GaugeHistogram => "gaugehistogram",
            Self::Info => "info",
            Self::Stateset => "stateset",
        }
    }
}

/// Error returned by [`Parser`] implementations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input does not match the exposition format grammar.
    #[error("{expected} at byte {offset}")]
    UnexpectedToken {
        /// What the parser expected, for example `"expected label value"`.
        expected: &'static str,
        /// Byte offset of the offending token in the input.
        offset: usize,
    },

    /// A `# TYPE` line names an unknown metric type.
    #[error("invalid metric type {0:?}")]
    InvalidMetricType(String),

    /// A help text, label name, or label value is not valid UTF-8.
    #[error("invalid UTF-8 at byte {offset}")]
    InvalidUtf8 {
        /// Byte offset of the start of the invalid string in the input.
        offset: usize,
    },

    /// A sample value is not a valid float.
    #[error("invalid sample value {0:?}")]
    InvalidValue(String),

    /// A protobuf payload is malformed or holds a value Go's protobuf parser rejects.
    #[error("invalid protobuf: {0}")]
    InvalidProtobuf(String),

    /// A sample timestamp is not a valid int64.
    #[error("invalid timestamp {0:?}")]
    InvalidTimestamp(String),

    /// A series has no metric name, or sets it twice.
    #[error("invalid metric name at byte {offset}")]
    InvalidMetricName {
        /// Byte offset of the start of the series in the input.
        offset: usize,
    },

    /// An OpenMetrics payload does not end with `# EOF`.
    #[error("data does not end with # EOF")]
    MissingEof,

    /// An OpenMetrics payload has data after `# EOF`.
    #[error("unexpected data after # EOF at byte {offset}")]
    DataAfterEof {
        /// Byte offset of the first byte after the `# EOF` line.
        offset: usize,
    },

    /// A `# UNIT` line names a unit that is not a suffix of the metric name.
    #[error("unit {unit:?} is not a suffix of metric {metric:?}")]
    InvalidUnit {
        /// The metric name from the `# UNIT` line.
        metric: String,
        /// The unit from the `# UNIT` line.
        unit: String,
    },
}

/// Reusable buffer that [`Parser::labels`] fills with the labels of the current sample.
///
/// Names and values borrow from the input unless they contain escape sequences
/// or need normalization, so a reused buffer does not allocate per sample.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LabelsBuffer<'a> {
    labels: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> LabelsBuffer<'a> {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all labels and keeps the allocated capacity.
    pub fn clear(&mut self) {
        self.labels.clear();
    }

    /// Appends a label.
    pub fn push(&mut self, name: Cow<'a, str>, value: Cow<'a, str>) {
        self.labels.push((name, value));
    }

    /// Sorts the labels by name.
    pub fn sort(&mut self) {
        self.labels
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
    }

    /// Returns the value of the label `name`, if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(label_name, _)| *label_name == name)
            .map(|(_, value)| value)
    }

    /// Iterates over `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.labels
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
    }

    /// Returns the labels with their `Cow` kind, so callers can keep `Cow::Borrowed`
    /// slices for `'a` after [`LabelsBuffer::clear`].
    pub fn as_slice(&self) -> &[(Cow<'a, str>, Cow<'a, str>)] {
        &self.labels
    }

    /// Returns the number of labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Returns `true` if the buffer holds no labels.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// Streaming parser over an exposition payload, mirroring Go's `textparse.Parser`.
///
/// Accessors return unspecified values when called for a different [`Entry`] kind.
///
/// Byte slices returned by the help, type, unit, series, and histogram accessors borrow from
/// the parser, because the protobuf parser builds them. Text parsers return slices of the input.
pub trait Parser<'a> {
    /// Advances to the next entry in the exposition stream, returning `Ok(None)` at EOF.
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError>;

    /// Returns the current byte offset of the parser cursor in the input slice (`0..=input.len()`).
    fn pos(&self) -> usize;

    /// Returns the metric name and unescaped help text of the current [`Entry::Help`].
    fn help(&self) -> (&[u8], Cow<'_, [u8]>);

    /// Returns the metric name and type of the current [`Entry::Type`].
    fn metric_type(&self) -> (&[u8], MetricType);

    /// Returns the text of the current [`Entry::Comment`], including the leading `#`.
    fn comment(&self) -> &'a [u8];

    /// Returns the metric name and unit of the current [`Entry::Unit`].
    fn unit(&self) -> (&[u8], &[u8]) {
        (b"", b"")
    }

    /// Returns the raw series bytes, optional sample timestamp in ms, and float64 value.
    fn series(&self) -> (&[u8], Option<i64>, f64);

    /// Returns the raw series bytes, optional sample timestamp in ms, and native histogram of
    /// the current [`Entry::Histogram`].
    fn histogram(&self) -> (&[u8], Option<i64>, HistogramRef<'_>) {
        (b"", None, HistogramRef::Int(&EMPTY_HISTOGRAM))
    }

    /// Clears `buf` and fills it with the current sample's labels, sorted by name, matching Go:
    /// the metric name is stored under [`METRIC_NAME_LABEL`], and `le` on histograms and
    /// `quantile` on summaries use OpenMetrics float formatting.
    fn labels(&self, buf: &mut LabelsBuffer<'a>);

    /// Clears `buf`, fills it with the exemplar labels of the current sample sorted by name,
    /// and returns the exemplar value and optional timestamp in ms. Returns `None` when the
    /// sample has no exemplar or it was already returned, like Go. A native histogram can
    /// have several exemplars, so call it until it returns `None`.
    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)> {
        buf.clear();
        None
    }

    /// Returns the start timestamp in ms of the current sample, read from its `_created` line
    /// in OpenMetrics or its `start_timestamp` field in protobuf. Takes `&mut self` because the
    /// OpenMetrics parser, like Go, caches the last hit and turns on `_created` skipping, so
    /// later `_created` lines are not returned as series. The protobuf parser only reads the field.
    fn start_timestamp(&mut self) -> Option<i64> {
        None
    }
}
