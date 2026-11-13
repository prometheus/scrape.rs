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

//! OpenMetrics 2.0 text format parser, a port of
//! [`openmetrics2parse.go`](https://github.com/prometheus/prometheus/blob/v0.315.1/model/textparse/openmetrics2parse.go)
//! with default `ParserOptions`.

use std::borrow::Cow;
use std::ops::Range;

use super::float::{FloatBuf, common_openmetrics_float, format_openmetrics_float, parse_go_float};
use super::omlex::{Lexer, Token};
use super::omparse::{
    NORMAL_NAN, normalize_float_label, parse_metric_type, parse_sample_value, unescape,
    unescape_label,
};
use super::{
    BUCKET_LABEL, ByteSpan, CounterResetHint, Entry, Histogram, HistogramRef, LabelSpan,
    LabelsBuffer, METRIC_NAME_LABEL, MetricType, ParseError, Parser, QUANTILE_LABEL, Span,
};

/// Go's `model.SeparatorByte`, which joins the labels of an exploded composite series.
const SEPARATOR: u8 = 0xff;

type Label<'a> = (Cow<'a, str>, Cow<'a, str>);

struct Exemplar {
    value: f64,
    timestamp: i64,
    labels: Range<usize>,
}

/// Label text of an exploded series, from the input or from `pending_text`.
enum PendingText<'a> {
    Input(&'a str),
    Arena(Range<usize>),
}

impl<'a> PendingText<'a> {
    fn resolve<'s>(&'s self, arena: &'s str) -> &'s str {
        match self {
            Self::Input(text) => text,
            Self::Arena(range) => &arena[range.clone()],
        }
    }
}

/// One flat series of a classic histogram or summary composite value.
struct PendingSeries<'a> {
    series: ByteSpan,
    name: Range<usize>,
    injected: Option<(&'static str, PendingText<'a>)>,
    value: f64,
}

/// Zero-copy parser for the OpenMetrics 2.0 text exposition format. Like Go, it returns native
/// histograms as [`Entry::Histogram`] and explodes classic histogram and summary composite
/// values into `_count`, `_sum`, and `_bucket` or `quantile` [`Entry::Series`] entries.
pub struct OpenMetrics2Parser<'a> {
    lexer: Lexer<'a>,
    done: bool,
    line_start: usize,
    series: ByteSpan,
    text: ByteSpan,
    name: Option<ByteSpan>,
    /// The last metric name seen, Go's `curFamilyName`. A new name resets the type.
    family: Option<ByteSpan>,
    metric_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    start_timestamp: Option<i64>,
    labels: Vec<LabelSpan>,
    exemplars: Vec<Exemplar>,
    exemplar_labels: Vec<LabelSpan>,
    /// Like Go, exemplars are handed out one per call across the series of a composite value.
    exemplar_index: usize,
    float_histogram_kind: bool,
    int_histogram: Histogram<u64, i64>,
    float_histogram: Histogram<f64, f64>,
    pending: Vec<PendingSeries<'a>>,
    /// Number of pending series returned so far; the current one is `pending_index - 1`.
    pending_index: usize,
    /// The unescaped labels of the composite line other than the metric name, sorted by name.
    line_labels: Vec<Label<'a>>,
    pending_text: String,
    pending_series: Vec<u8>,
}

impl<'a> OpenMetrics2Parser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            lexer: Lexer::new_openmetrics2(input),
            done: false,
            line_start: 0,
            series: ByteSpan::default(),
            text: ByteSpan::default(),
            name: None,
            family: None,
            metric_type: MetricType::Unknown,
            value: 0.0,
            timestamp: None,
            start_timestamp: None,
            labels: Vec::new(),
            exemplars: Vec::new(),
            exemplar_labels: Vec::new(),
            exemplar_index: 0,
            float_histogram_kind: false,
            int_histogram: Histogram::default(),
            float_histogram: Histogram::default(),
            pending: Vec::new(),
            pending_index: 0,
            line_labels: Vec::new(),
            pending_text: String::new(),
            pending_series: Vec::new(),
        }
    }

    fn unexpected(&self, expected: &'static str) -> ParseError {
        ParseError::UnexpectedToken {
            expected,
            offset: self.lexer.token_start,
        }
    }

    fn invalid_value(message: impl Into<String>) -> ParseError {
        ParseError::InvalidValue(message.into())
    }

    fn utf8_span(&self, start: usize, end: usize) -> Result<ByteSpan, ParseError> {
        if std::str::from_utf8(&self.lexer.input[start..end]).is_err() {
            return Err(ParseError::InvalidUtf8 {
                offset: self.lexer.token_start,
            });
        }
        Ok(ByteSpan::new(start, end))
    }

    fn bytes(&self, span: ByteSpan) -> &'a [u8] {
        &self.lexer.input[span]
    }

    fn metric_name(&self) -> &'a [u8] {
        self.name.map_or(b"", |span| self.bytes(span))
    }

    /// Go's `resetOnFamilyChange`.
    fn enter_family(&mut self, name: ByteSpan) {
        if self.family.map(|family| self.bytes(family)) != Some(self.bytes(name)) {
            self.metric_type = MetricType::Unknown;
        }
        self.family = Some(name);
    }

    fn parse_metadata(&mut self, kind: Token) -> Result<Entry, ParseError> {
        if self.lexer.lex() != Token::MName {
            return Err(self.unexpected("expected metric name"));
        }
        let (mut start, mut end) = (self.lexer.token_start, self.lexer.pos);
        if self.lexer.input[start] == b'"' && self.lexer.input[end - 1] == b'"' {
            start += 1;
            end -= 1;
        }
        if start == end {
            return Err(ParseError::InvalidMetricName {
                offset: self.line_start,
            });
        }
        let name = self.utf8_span(start, end)?;
        self.name = Some(name);
        self.enter_family(name);
        if self.lexer.lex() != Token::Text {
            return Err(self.unexpected("expected text"));
        }
        let text_span = self.lexer.token_span();
        // The text token starts with a blank and ends with a linebreak, which the lexer
        // can follow with NUL bytes.
        let text = self.bytes(text_span);
        let text_end = text_span.start
            + text
                .iter()
                .position(|&byte| byte == b'\n')
                .unwrap_or(text.len());
        self.text = ByteSpan::new((text_span.start + 1).min(text_end), text_end);
        let raw_text = self.bytes(self.text);
        match kind {
            Token::Type => {
                self.metric_type = parse_metric_type(raw_text)?;
                Ok(Entry::Type)
            }
            Token::Help => {
                if std::str::from_utf8(raw_text).is_err() {
                    return Err(ParseError::InvalidUtf8 {
                        offset: self.lexer.token_start,
                    });
                }
                Ok(Entry::Help)
            }
            // OpenMetrics 2.0 only recommends that the unit is a suffix of the name.
            _ => Ok(Entry::Unit),
        }
    }

    fn parse_series(&mut self, first: Token) -> Result<Entry, ParseError> {
        let mut token = first;
        if first == Token::MName {
            let name = ByteSpan::new(self.line_start, self.lexer.pos);
            self.name = Some(name);
            self.enter_family(name);
            self.series = name;
            token = self.lexer.lex();
        }
        if token == Token::BraceOpen {
            self.parse_label_values(false)?;
            self.series = ByteSpan::new(self.line_start, self.lexer.pos);
            if first == Token::BraceOpen
                && let Some(name) = self.name
            {
                self.enter_family(name);
            }
            token = self.lexer.lex();
        }
        self.parse_series_end_of_line(token)
    }

    /// Parses labels up to and including `}`, into the exemplar labels when `exemplar` is set.
    fn parse_label_values(&mut self, exemplar: bool) -> Result<(), ParseError> {
        let mut token = self.lexer.lex();
        let mut first = true;
        loop {
            let (start, end) = match token {
                Token::BraceClose => return Ok(()),
                Token::LName => (self.lexer.token_start, self.lexer.pos),
                Token::QString => (self.lexer.token_start + 1, self.lexer.pos - 1),
                _ => return Err(self.unexpected("expected label name")),
            };
            let quoted = token == Token::QString;
            let is_first = std::mem::take(&mut first);
            let name = self.utf8_span(start, end)?;
            token = self.lexer.lex();
            if quoted && matches!(token, Token::Comma | Token::BraceClose) {
                if exemplar {
                    return Err(self.unexpected("expected label name"));
                }
                if !is_first || self.name.is_some() || start == end {
                    return Err(ParseError::InvalidMetricName {
                        offset: self.line_start,
                    });
                }
                self.name = Some(name);
                if token == Token::BraceClose {
                    return Ok(());
                }
                token = self.lexer.lex();
                continue;
            }
            if token != Token::Equal {
                return Err(self.unexpected("expected equal"));
            }
            if self.lexer.lex() != Token::LValue {
                return Err(self.unexpected("expected label value"));
            }
            let value_start = self.lexer.token_start;
            let value =
                std::str::from_utf8(self.lexer.token()).map_err(|_| ParseError::InvalidUtf8 {
                    offset: value_start,
                })?;
            // The token can end in NUL bytes after the closing quote, which we drop like the
            // OpenMetrics 1.0 parser.
            let close = value.rfind('"').unwrap_or(0);
            let span = LabelSpan {
                name_start: start,
                name_end: end,
                val_start: value_start + 1,
                val_end: value_start + close.max(1),
            };
            if exemplar {
                self.exemplar_labels.push(span);
            } else {
                self.labels.push(span);
            }
            token = self.lexer.lex();
            match token {
                Token::Comma => token = self.lexer.lex(),
                Token::BraceClose => {}
                _ => return Err(self.unexpected("expected comma or brace close")),
            }
        }
    }

    fn parse_series_end_of_line(&mut self, token: Token) -> Result<Entry, ParseError> {
        if self.name.is_none() {
            return Err(ParseError::InvalidMetricName {
                offset: self.line_start,
            });
        }
        if token != Token::Value {
            return Err(self.unexpected("expected value after metric"));
        }
        let raw_span = ByteSpan::new(self.lexer.token_start + 1, self.lexer.pos);
        let raw = self.bytes(raw_span);
        if raw.first() == Some(&b'{') {
            self.parse_after_value()?;
            let raw = std::str::from_utf8(raw).map_err(|_| ParseError::InvalidUtf8 {
                offset: raw_span.start,
            })?;
            return self.parse_composite_value(raw).map_err(Self::invalid_value);
        }
        if matches!(
            self.metric_type,
            MetricType::Histogram | MetricType::GaugeHistogram | MetricType::Summary
        ) {
            return Err(Self::invalid_value(format!(
                "composite value required for metric type {:?}",
                self.metric_type.as_str()
            )));
        }
        let value = parse_sample_value(raw)
            .ok_or_else(|| Self::invalid_value(String::from_utf8_lossy(raw)))?;
        self.value = if value.is_nan() {
            if self.metric_type == MetricType::Counter {
                return Err(Self::invalid_value("counter sample value must not be NaN"));
            }
            f64::from_bits(NORMAL_NAN)
        } else {
            value
        };
        if self.metric_type == MetricType::Stateset {
            if self.value != 0.0 && self.value != 1.0 {
                return Err(Self::invalid_value("stateset sample value must be 0 or 1"));
            }
            if !self.has_family_name_label() {
                return Err(Self::invalid_value(
                    "stateset sample must have a label matching the metric family name",
                ));
            }
        }
        self.parse_after_value()?;
        Ok(Entry::Series)
    }

    fn has_family_name_label(&self) -> bool {
        let family = self.family.map_or(&b""[..], |family| self.bytes(family));
        self.labels
            .iter()
            .any(|span| &self.lexer.input[span.name_start..span.name_end] == family)
    }

    /// Parses `[timestamp] [st@start] *exemplar` up to and including the linebreak.
    fn parse_after_value(&mut self) -> Result<(), ParseError> {
        loop {
            match self.lexer.lex() {
                Token::Eof => return Err(ParseError::MissingEof),
                Token::Linebreak => return Ok(()),
                Token::Timestamp => {
                    if self.timestamp.is_some() {
                        return Err(self.unexpected("duplicate timestamp"));
                    }
                    if self.start_timestamp.is_some() {
                        return Err(self.unexpected("timestamp must precede start timestamp"));
                    }
                    self.timestamp = Some(self.timestamp_value(1)?);
                }
                Token::StartTimestamp => {
                    if self.start_timestamp.is_some() {
                        return Err(self.unexpected("duplicate start timestamp"));
                    }
                    self.start_timestamp = Some(self.timestamp_value(4)?);
                }
                Token::Comment => return self.parse_exemplars(),
                _ => return Err(self.unexpected("expected timestamp or exemplar")),
            }
        }
    }

    /// Parses exemplars after ` # {` up to and including the linebreak. Each needs a timestamp.
    fn parse_exemplars(&mut self) -> Result<(), ParseError> {
        loop {
            let labels_start = self.exemplar_labels.len();
            self.parse_label_values(true)?;
            if self.lexer.lex() != Token::Value {
                return Err(self.unexpected("expected exemplar value"));
            }
            let raw = &self.lexer.token()[1..];
            let value = parse_sample_value(raw)
                .ok_or_else(|| Self::invalid_value(String::from_utf8_lossy(raw)))?;
            let value = if value.is_nan() {
                f64::from_bits(NORMAL_NAN)
            } else {
                value
            };
            match self.lexer.lex() {
                Token::Eof => return Err(ParseError::MissingEof),
                Token::Timestamp => {}
                _ => return Err(self.unexpected("expected exemplar timestamp")),
            }
            self.exemplars.push(Exemplar {
                value,
                timestamp: self.timestamp_value(1)?,
                labels: labels_start..self.exemplar_labels.len(),
            });
            match self.lexer.lex() {
                Token::Eof => return Err(ParseError::MissingEof),
                Token::Linebreak => return Ok(()),
                Token::Comment => {}
                _ => return Err(self.unexpected("expected end of line or next exemplar")),
            }
        }
    }

    /// Parses float seconds after the first `skip` bytes of the current token into milliseconds.
    fn timestamp_value(&self, skip: usize) -> Result<i64, ParseError> {
        let raw = &self.lexer.token()[skip..];
        let seconds = parse_sample_value(raw)
            .filter(|seconds| seconds.is_finite())
            .ok_or_else(|| {
                ParseError::InvalidTimestamp(String::from_utf8_lossy(raw).into_owned())
            })?;
        // NOTE: Rust saturates out-of-range casts, Go's int64() is platform-specific there.
        Ok((seconds * 1000.0) as i64)
    }

    fn parse_composite_value(&mut self, raw: &'a str) -> Result<Entry, String> {
        let summary = match self.metric_type {
            MetricType::Histogram | MetricType::GaugeHistogram => false,
            MetricType::Summary => true,
            other => {
                return Err(format!(
                    "composite value not supported for metric type {:?}",
                    other.as_str()
                ));
            }
        };
        let fields = CompositeFields::parse(raw, summary)?;
        let gauge = self.metric_type == MetricType::GaugeHistogram;
        if fields.schema.is_some() {
            self.parse_native_histogram(&fields, gauge)?;
            return Ok(Entry::Histogram);
        }
        let input = self.lexer.input;
        let text = |start, end| std::str::from_utf8(&input[start..end]).unwrap_or_default();
        self.line_labels.extend(self.labels.iter().map(|span| {
            (
                unescape_label(text(span.name_start, span.name_end)),
                unescape_label(text(span.val_start, span.val_end)),
            )
        }));
        self.line_labels.sort_by(|left, right| left.0.cmp(&right.0));
        let family = unescape_label(std::str::from_utf8(self.metric_name()).unwrap_or_default());
        let (count_suffix, count, sum_suffix, sum) = if gauge {
            ("_gcount", fields.gcount, "_gsum", fields.gsum)
        } else {
            ("_count", fields.count, "_sum", fields.sum)
        };
        let count = go_float(required(count, &count_suffix[1..])?)?;
        self.push_pending(&family, count_suffix, None, count);
        let sum = go_float(required(sum, &sum_suffix[1..])?)?;
        self.push_pending(&family, sum_suffix, None, sum);
        if summary {
            let quantiles = list_items(required(fields.quantile, "quantile")?)?;
            let mut previous = f64::NEG_INFINITY;
            for part in quantiles {
                let (quantile, value) = part
                    .split_once(':')
                    .ok_or_else(|| format!("quantile missing ':': {part:?}"))?;
                let value = go_float(value.trim())?;
                let quantile = sorted_float_label(
                    quantile.trim(),
                    &mut previous,
                    "quantiles",
                    &mut self.pending_text,
                )?;
                self.push_pending(&family, "", Some((QUANTILE_LABEL, quantile)), value);
            }
        } else {
            let buckets = list_items(required(fields.bucket, "bucket")?)?;
            let mut previous = f64::NEG_INFINITY;
            let mut has_infinity = false;
            for part in buckets {
                let (bound, count) = part
                    .rsplit_once(':')
                    .ok_or_else(|| format!("bucket missing ':': {part:?}"))?;
                let count = go_float(count.trim())?;
                let bound = sorted_float_label(
                    bound.trim(),
                    &mut previous,
                    "classic histogram buckets",
                    &mut self.pending_text,
                )?;
                has_infinity |= bound.resolve(&self.pending_text) == "+Inf";
                self.push_pending(&family, "_bucket", Some((BUCKET_LABEL, bound)), count);
            }
            if !has_infinity {
                return Err("classic histogram buckets must include a +Inf threshold".to_owned());
            }
        }
        self.pending_index = 1;
        Ok(Entry::Series)
    }

    /// Queues a flat series named `family` + `suffix` with Go's `appendSeriesBytes` identity.
    fn push_pending(
        &mut self,
        family: &str,
        suffix: &str,
        injected: Option<(&'static str, PendingText<'a>)>,
        value: f64,
    ) {
        let name_start = self.pending_text.len();
        self.pending_text.push_str(family);
        self.pending_text.push_str(suffix);
        let name = name_start..self.pending_text.len();
        let series_start = self.pending_series.len();
        // `line_labels` is sorted and "__name__" sorts before "le" and "quantile", so merging
        // the two keeps Go's sorted label order without sorting per series.
        let mut special = [(METRIC_NAME_LABEL, &self.pending_text[name.clone()])]
            .into_iter()
            .chain(
                injected
                    .as_ref()
                    .map(|(label, text)| (*label, text.resolve(&self.pending_text))),
            )
            .peekable();
        let out = &mut self.pending_series;
        for (label, label_value) in &self.line_labels {
            while let Some((special_label, special_value)) =
                special.next_if(|(special_label, _)| *special_label <= label.as_ref())
            {
                append_series_label(out, special_label, special_value);
            }
            append_series_label(out, label, label_value);
        }
        for (special_label, special_value) in special {
            append_series_label(out, special_label, special_value);
        }
        self.pending.push(PendingSeries {
            series: ByteSpan::new(series_start, self.pending_series.len()),
            name,
            injected,
            value,
        });
    }

    /// Go's `buildNativeHistogram`, including `Validate`.
    fn parse_native_histogram(
        &mut self,
        fields: &CompositeFields<'_>,
        gauge: bool,
    ) -> Result<(), String> {
        let schema: i64 = go_int(fields.schema.unwrap_or_default())?;
        if !(-4..=8).contains(&schema) {
            return Err(format!("schema must be between -4 and 8, got {schema}"));
        }
        let (count, sum) = if gauge {
            (
                required(fields.gcount, "gcount")?,
                required(fields.gsum, "gsum")?,
            )
        } else {
            (
                required(fields.count, "count")?,
                required(fields.sum, "sum")?,
            )
        };
        let count = go_float(count)?;
        let sum = go_float(sum)?;
        let zero_threshold = go_float(required(fields.zero_threshold, "zero_threshold")?)?;
        if !zero_threshold.is_finite() || zero_threshold < 0.0 {
            return Err(format!(
                "zero_threshold must be a non-negative, finite number, got {zero_threshold}"
            ));
        }
        let zero_count = go_float(required(fields.zero_count, "zero_count")?)?;
        let positive_buckets = fields.positive_buckets.unwrap_or_default();
        let negative_buckets = fields.negative_buckets.unwrap_or_default();
        // Like Go, any non-integer count or a bucket with a decimal point or exponent makes it
        // a float histogram.
        let has_float = |buckets: &str| buckets.contains(['.', 'e', 'E']);
        self.float_histogram_kind = count != count.trunc()
            || zero_count != zero_count.trunc()
            || has_float(positive_buckets)
            || has_float(negative_buckets);
        let counter_reset_hint = if gauge {
            CounterResetHint::Gauge
        } else {
            CounterResetHint::Unknown
        };
        let positive_spans = fields.positive_spans.unwrap_or_default();
        let negative_spans = fields.negative_spans.unwrap_or_default();
        if self.float_histogram_kind {
            let histogram = &mut self.float_histogram;
            parse_spans(positive_spans, &mut histogram.positive_spans)?;
            parse_spans(negative_spans, &mut histogram.negative_spans)?;
            parse_buckets(positive_buckets, &mut histogram.positive_buckets, go_float)?;
            parse_buckets(negative_buckets, &mut histogram.negative_buckets, go_float)?;
            histogram.counter_reset_hint = counter_reset_hint;
            histogram.schema = schema as i32;
            histogram.zero_threshold = zero_threshold;
            histogram.zero_count = zero_count;
            histogram.count = count;
            histogram.sum = sum;
            check_spans(&histogram.positive_spans, histogram.positive_buckets.len())?;
            check_spans(&histogram.negative_spans, histogram.negative_buckets.len())?;
            let negative_count = histogram
                .negative_buckets
                .iter()
                .any(|&bucket| bucket < 0.0);
            let positive_count = histogram
                .positive_buckets
                .iter()
                .any(|&bucket| bucket < 0.0);
            if negative_count || positive_count || zero_count < 0.0 || count < 0.0 {
                return Err("histogram has a negative observation count".to_owned());
            }
            return Ok(());
        }
        let histogram = &mut self.int_histogram;
        parse_spans(positive_spans, &mut histogram.positive_spans)?;
        parse_spans(negative_spans, &mut histogram.negative_spans)?;
        parse_buckets(positive_buckets, &mut histogram.positive_buckets, go_int)?;
        parse_buckets(negative_buckets, &mut histogram.negative_buckets, go_int)?;
        histogram.counter_reset_hint = counter_reset_hint;
        histogram.schema = schema as i32;
        histogram.zero_threshold = zero_threshold;
        // NOTE: Rust saturates out-of-range casts, Go's uint64() is platform-specific there.
        histogram.zero_count = zero_count as u64;
        histogram.count = count as u64;
        histogram.sum = sum;
        check_spans(&histogram.positive_spans, histogram.positive_buckets.len())?;
        check_spans(&histogram.negative_spans, histogram.negative_buckets.len())?;
        let mut observations = histogram.zero_count;
        for &bucket in histogram
            .negative_buckets
            .iter()
            .chain(&histogram.positive_buckets)
        {
            if bucket < 0 {
                return Err(format!("bucket has observation count of {bucket}"));
            }
            observations = observations.wrapping_add(bucket as u64);
        }
        let count_too_small = if sum.is_nan() {
            observations > histogram.count
        } else {
            observations != histogram.count
        };
        if count_too_small {
            return Err(format!(
                "{observations} observations found in buckets, but the Count field is {}",
                histogram.count
            ));
        }
        absolute_to_deltas(&mut histogram.positive_buckets);
        absolute_to_deltas(&mut histogram.negative_buckets);
        Ok(())
    }

    fn pending_series(&self) -> Option<&PendingSeries<'a>> {
        self.pending_index
            .checked_sub(1)
            .and_then(|index| self.pending.get(index))
    }
}

impl<'a> Parser<'a> for OpenMetrics2Parser<'a> {
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        if self.done {
            return Ok(None);
        }
        if self.pending_index < self.pending.len() {
            self.pending_index += 1;
            return Ok(Some(Entry::Series));
        }
        self.pending.clear();
        self.pending_index = 0;
        self.line_labels.clear();
        self.pending_text.clear();
        self.pending_series.clear();
        self.line_start = self.lexer.pos;
        self.name = None;
        self.labels.clear();
        self.exemplars.clear();
        self.exemplar_labels.clear();
        self.exemplar_index = 0;
        self.timestamp = None;
        self.start_timestamp = None;
        let entry = match self.lexer.lex() {
            Token::EofWord => {
                if self.lexer.lex() != Token::Eof {
                    return Err(ParseError::DataAfterEof {
                        offset: self.lexer.token_start,
                    });
                }
                self.done = true;
                return Ok(None);
            }
            Token::Eof => return Err(ParseError::MissingEof),
            kind @ (Token::Help | Token::Type | Token::Unit) => self.parse_metadata(kind)?,
            first @ (Token::BraceOpen | Token::MName) => self.parse_series(first)?,
            _ => return Err(self.unexpected("expected a valid start token")),
        };
        Ok(Some(entry))
    }

    fn pos(&self) -> usize {
        self.lexer.pos.min(self.lexer.input.len())
    }

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>) {
        (self.metric_name(), unescape(self.bytes(self.text)))
    }

    fn metric_type(&self) -> (&'a [u8], MetricType) {
        (self.metric_name(), self.metric_type)
    }

    fn unit(&self) -> (&'a [u8], &'a [u8]) {
        (self.metric_name(), self.bytes(self.text))
    }

    fn comment(&self) -> &'a [u8] {
        self.bytes(self.text)
    }

    fn series(&self) -> (&[u8], Option<i64>, f64) {
        match self.pending_series() {
            Some(pending) => (
                &self.pending_series[pending.series.start..pending.series.end],
                self.timestamp,
                pending.value,
            ),
            None => (self.bytes(self.series), self.timestamp, self.value),
        }
    }

    fn histogram(&self) -> (&[u8], Option<i64>, HistogramRef<'_>) {
        let histogram = if self.float_histogram_kind {
            HistogramRef::Float(&self.float_histogram)
        } else {
            HistogramRef::Int(&self.int_histogram)
        };
        (self.bytes(self.series), self.timestamp, histogram)
    }

    fn labels(&self, buf: &mut LabelsBuffer<'a>) {
        buf.clear();
        if let Some(pending) = self.pending_series() {
            // LabelsBuffer borrows only from the input, so the `__name__` and formatted bound
            // that live in `pending_text` are copied.
            let name = &self.pending_text[pending.name.clone()];
            buf.push(
                Cow::Borrowed(METRIC_NAME_LABEL),
                Cow::Owned(name.to_owned()),
            );
            for (name, value) in &self.line_labels {
                buf.push(name.clone(), value.clone());
            }
            if let Some((label, text)) = &pending.injected {
                let value = match text {
                    PendingText::Input(text) => Cow::Borrowed(*text),
                    PendingText::Arena(range) => {
                        Cow::Owned(self.pending_text[range.clone()].to_owned())
                    }
                };
                buf.push(Cow::Borrowed(label), value);
            }
            buf.sort();
            return;
        }
        let name = std::str::from_utf8(self.metric_name()).unwrap_or_default();
        buf.push(Cow::Borrowed(METRIC_NAME_LABEL), unescape_label(name));
        let input = self.lexer.input;
        let text = |start, end| std::str::from_utf8(&input[start..end]).unwrap_or_default();
        for span in &self.labels {
            let name = unescape_label(text(span.name_start, span.name_end));
            let value = unescape_label(text(span.val_start, span.val_end));
            let value = normalize_float_label(self.metric_type, &name, value);
            buf.push(name, value);
        }
        buf.sort();
    }

    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)> {
        buf.clear();
        let exemplar = self.exemplars.get(self.exemplar_index)?;
        self.exemplar_index += 1;
        let input = self.lexer.input;
        let text = |start, end| std::str::from_utf8(&input[start..end]).unwrap_or_default();
        // Go keeps exemplar label names escaped and unescapes only the values.
        for span in &self.exemplar_labels[exemplar.labels.clone()] {
            buf.push(
                Cow::Borrowed(text(span.name_start, span.name_end)),
                unescape_label(text(span.val_start, span.val_end)),
            );
        }
        buf.sort();
        Some((exemplar.value, Some(exemplar.timestamp)))
    }

    /// Returns the inline `st@` start timestamp of the current sample.
    fn start_timestamp(&mut self) -> Option<i64> {
        self.start_timestamp
    }
}

/// The fields of a composite value, Go's `kvMap` restricted to the known field names.
#[derive(Default)]
struct CompositeFields<'v> {
    count: Option<&'v str>,
    sum: Option<&'v str>,
    gcount: Option<&'v str>,
    gsum: Option<&'v str>,
    bucket: Option<&'v str>,
    quantile: Option<&'v str>,
    schema: Option<&'v str>,
    zero_threshold: Option<&'v str>,
    zero_count: Option<&'v str>,
    positive_spans: Option<&'v str>,
    positive_buckets: Option<&'v str>,
    negative_spans: Option<&'v str>,
    negative_buckets: Option<&'v str>,
}

impl<'v> CompositeFields<'v> {
    fn parse(raw: &'v str, summary: bool) -> Result<Self, String> {
        let inner = raw
            .strip_prefix('{')
            .and_then(|inner| inner.strip_suffix('}'))
            .ok_or_else(|| format!("composite value must be wrapped in {{}}: {raw:?}"))?;
        let mut fields = Self::default();
        for part in split_top_level(inner) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, value) = part
                .split_once(':')
                .ok_or_else(|| format!("invalid composite field (missing ':'): {part:?}"))?;
            let key = key.trim();
            let slot = match (key, summary) {
                ("count", _) => &mut fields.count,
                ("sum", _) => &mut fields.sum,
                ("quantile", true) => &mut fields.quantile,
                ("gcount", false) => &mut fields.gcount,
                ("gsum", false) => &mut fields.gsum,
                ("bucket", false) => &mut fields.bucket,
                ("schema", false) => &mut fields.schema,
                ("zero_threshold", false) => &mut fields.zero_threshold,
                ("zero_count", false) => &mut fields.zero_count,
                ("positive_spans", false) => &mut fields.positive_spans,
                ("positive_buckets", false) => &mut fields.positive_buckets,
                ("negative_spans", false) => &mut fields.negative_spans,
                ("negative_buckets", false) => &mut fields.negative_buckets,
                _ => return Err(format!("unknown composite field {key:?}")),
            };
            if slot.replace(value.trim()).is_some() {
                return Err(format!("duplicate composite field {key:?}"));
            }
        }
        Ok(fields)
    }
}

/// Go's `splitCompositeFields`: splits at commas outside `[]` and `()`.
fn split_top_level(text: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0i32;
    text.split(move |character| {
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ => {}
        }
        character == ',' && depth == 0
    })
}

fn required<'v>(field: Option<&'v str>, key: &str) -> Result<&'v str, String> {
    field.ok_or_else(|| format!("missing required field: {key}"))
}

/// Go's `strconv.ParseFloat`, with Go's NaN bit pattern.
// NOTE: Go also accepts hex floats here, like `0x1p3`; we reject them.
fn go_float(text: &str) -> Result<f64, String> {
    let value = parse_go_float(text).ok_or_else(|| format!("invalid float {text:?}"))?;
    Ok(if value.is_nan() {
        f64::from_bits(NORMAL_NAN)
    } else {
        value
    })
}

/// Go's base 10 `strconv.ParseInt`.
fn go_int<T: std::str::FromStr>(text: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| format!("invalid integer {text:?}"))
}

/// Returns the trimmed items of `[a,b,...]`, or none for an empty string or list.
fn list_items(text: &str) -> Result<impl Iterator<Item = &str>, String> {
    let text = text.trim();
    let inner = match text {
        "" | "[]" => "",
        _ => text
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .ok_or_else(|| format!("list must be wrapped in []: {text:?}"))?,
    };
    Ok(inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty()))
}

fn parse_spans(text: &str, spans: &mut Vec<Span>) -> Result<(), String> {
    spans.clear();
    for part in list_items(text)? {
        let (offset, length) = part
            .split_once(':')
            .ok_or_else(|| format!("span missing ':': {part:?}"))?;
        let length = length.trim();
        // Go's `ParseUint` rejects a sign, Rust's accepts `+`.
        if length.starts_with('+') {
            return Err(format!("invalid span length {length:?}"));
        }
        spans.push(Span {
            offset: go_int(offset.trim())?,
            length: go_int(length)?,
        });
    }
    Ok(())
}

fn parse_buckets<B>(
    text: &str,
    buckets: &mut Vec<B>,
    parse: impl Fn(&str) -> Result<B, String>,
) -> Result<(), String> {
    buckets.clear();
    for part in list_items(text)? {
        buckets.push(parse(part)?);
    }
    Ok(())
}

/// Go's `checkHistogramSpans`.
fn check_spans(spans: &[Span], buckets: usize) -> Result<(), String> {
    if spans.iter().skip(1).any(|span| span.offset < 0) {
        return Err("span has a negative offset".to_owned());
    }
    let needed: u64 = spans.iter().map(|span| u64::from(span.length)).sum();
    if needed != buckets as u64 {
        return Err(format!(
            "spans need {needed} buckets, have {buckets} buckets"
        ));
    }
    Ok(())
}

fn absolute_to_deltas(buckets: &mut [i64]) {
    for index in (1..buckets.len()).rev() {
        buckets[index] = buckets[index].wrapping_sub(buckets[index - 1]);
    }
}

/// Go's `appendSeriesBytes` for one label.
fn append_series_label(out: &mut Vec<u8>, label: &str, value: &str) {
    if label != METRIC_NAME_LABEL {
        out.push(SEPARATOR);
        out.extend_from_slice(label.as_bytes());
        out.push(SEPARATOR);
    }
    out.extend_from_slice(value.as_bytes());
}

/// Formats a parsable `le` or `quantile` value like Go's `FormatOpenMetricsFloat`, after
/// checking it is greater than `previous`. Other values are kept as they are.
fn sorted_float_label<'v>(
    text: &'v str,
    previous: &mut f64,
    what: &str,
    arena: &mut String,
) -> Result<PendingText<'v>, String> {
    let Some(value) = parse_go_float(text) else {
        return Ok(PendingText::Input(text));
    };
    if value <= *previous {
        return Err(format!(
            "{what} must be sorted in increasing order: {text:?}"
        ));
    }
    *previous = value;
    if let Some(common) = common_openmetrics_float(value) {
        return Ok(PendingText::Input(common));
    }
    let mut formatted = FloatBuf::default();
    format_openmetrics_float(value, &mut formatted).map_err(|error| error.to_string())?;
    if formatted.as_str() == text {
        return Ok(PendingText::Input(text));
    }
    let start = arena.len();
    arena.push_str(formatted.as_str());
    Ok(PendingText::Arena(start..arena.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_length_rejects_sign_like_go() {
        let mut spans = Vec::new();
        assert!(parse_spans("[0:+1]", &mut spans).is_err());
        assert_eq!(parse_spans("[+0:1]", &mut spans), Ok(()));
        assert_eq!(
            spans,
            [Span {
                offset: 0,
                length: 1
            }]
        );
    }

    #[test]
    fn returns_each_exemplar_once() {
        let input = b"a_total 1 # {id=\"x\"} 2 3 # {id=\"y\"} 4 5\n# EOF\n";
        let mut parser = OpenMetrics2Parser::new(input);
        let mut buf = LabelsBuffer::new();
        assert_eq!(parser.next_entry(), Ok(Some(Entry::Series)));
        assert_eq!(parser.exemplar(&mut buf), Some((2.0, Some(3000))));
        assert_eq!(buf.get("id"), Some("x"));
        assert_eq!(parser.exemplar(&mut buf), Some((4.0, Some(5000))));
        assert_eq!(buf.get("id"), Some("y"));
        assert_eq!(parser.exemplar(&mut buf), None);
    }

    #[test]
    fn sorted_float_label_borrows_canonical_bounds() {
        let mut previous = f64::NEG_INFINITY;
        let mut arena = String::new();
        assert!(matches!(
            sorted_float_label("0.005", &mut previous, "buckets", &mut arena),
            Ok(PendingText::Input("0.005"))
        ));
        let formatted = sorted_float_label("5", &mut previous, "buckets", &mut arena).unwrap();
        assert!(matches!(formatted, PendingText::Arena(_)));
        assert_eq!(formatted.resolve(&arena), "5.0");
    }

    #[test]
    fn splits_composite_fields_outside_brackets() {
        let parts: Vec<&str> = split_top_level("a:[1,2],b:(3,4),c:5").collect();
        assert_eq!(parts, ["a:[1,2]", "b:(3,4)", "c:5"]);
    }
}
