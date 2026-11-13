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
    label_value_span, metadata_text, normalize_float_label, normalize_nan, parse_metric_type,
    parse_sample_value, timestamp_ms, unescape, unescape_label, unexpected, utf8_span,
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

/// The exemplars of the current line.
#[derive(Default)]
struct Exemplars {
    entries: Vec<Exemplar>,
    labels: Vec<LabelSpan>,
    /// Like Go, exemplars are handed out one per call across the series of a composite value.
    next: usize,
}

impl Exemplars {
    fn clear(&mut self) {
        self.entries.clear();
        self.labels.clear();
        self.next = 0;
    }
}

/// Label text of an exploded series, from the input or from [`Pending::text`].
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
    series: Range<usize>,
    name: Range<usize>,
    injected: Option<(&'static str, PendingText<'a>)>,
    value: f64,
}

/// The flat series of the current classic composite line, Go's `pending`.
#[derive(Default)]
struct Pending<'a> {
    entries: Vec<PendingSeries<'a>>,
    /// Number of entries returned so far; the current one is `returned - 1`.
    returned: usize,
    /// The unescaped labels of the line other than the metric name, sorted by name.
    line_labels: Vec<Label<'a>>,
    /// Series names and formatted bounds, which are not in the input.
    text: String,
    series_bytes: Vec<u8>,
}

impl<'a> Pending<'a> {
    fn clear(&mut self) {
        self.entries.clear();
        self.returned = 0;
        self.line_labels.clear();
        self.text.clear();
        self.series_bytes.clear();
    }

    fn advance(&mut self) -> bool {
        if self.returned < self.entries.len() {
            self.returned += 1;
            return true;
        }
        false
    }

    fn current(&self) -> Option<&PendingSeries<'a>> {
        self.returned
            .checked_sub(1)
            .and_then(|index| self.entries.get(index))
    }

    fn series_bytes(&self, entry: &PendingSeries<'a>) -> &[u8] {
        &self.series_bytes[entry.series.clone()]
    }

    fn set_line_labels(&mut self, input: &'a [u8], labels: &[LabelSpan]) {
        self.line_labels.extend(labels.iter().map(|span| {
            (
                unescape_label(span.name(input)),
                unescape_label(span.value(input)),
            )
        }));
        self.line_labels.sort_by(|left, right| left.0.cmp(&right.0));
    }

    /// Queues one series per `bound:value` item of `list`. Returns whether a bound is `+Inf`.
    fn push_bounds(
        &mut self,
        family: &str,
        field: &BoundsField,
        list: Option<&'a str>,
    ) -> Result<bool, String> {
        let mut previous = f64::NEG_INFINITY;
        let mut has_infinity = false;
        for part in list_items(required(list, field.key)?)? {
            let cut = if field.cut_at_last_colon {
                part.rsplit_once(':')
            } else {
                part.split_once(':')
            };
            let (bound, value) =
                cut.ok_or_else(|| format!("{} missing ':': {part:?}", field.key))?;
            let value = go_float(value.trim())?;
            let bound =
                sorted_float_label(bound.trim(), &mut previous, field.plural, &mut self.text)?;
            has_infinity |= bound.resolve(&self.text) == "+Inf";
            self.push(family, field.suffix, Some((field.label, bound)), value);
        }
        Ok(has_infinity)
    }

    /// Queues a flat series named `family` + `suffix` with Go's `appendSeriesBytes` identity.
    fn push(
        &mut self,
        family: &str,
        suffix: &str,
        injected: Option<(&'static str, PendingText<'a>)>,
        value: f64,
    ) {
        let name_start = self.text.len();
        self.text.push_str(family);
        self.text.push_str(suffix);
        let name = name_start..self.text.len();
        let series_start = self.series_bytes.len();
        // `line_labels` is sorted and "__name__" sorts before "le" and "quantile", so merging
        // the two keeps Go's sorted label order without sorting per series.
        let mut special = [(METRIC_NAME_LABEL, &self.text[name.clone()])]
            .into_iter()
            .chain(
                injected
                    .as_ref()
                    .map(|(label, text)| (*label, text.resolve(&self.text))),
            )
            .peekable();
        let out = &mut self.series_bytes;
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
        self.entries.push(PendingSeries {
            series: series_start..self.series_bytes.len(),
            name,
            injected,
            value,
        });
    }

    fn write_labels(&self, entry: &PendingSeries<'a>, buf: &mut LabelsBuffer<'a>) {
        // LabelsBuffer borrows only from the input, so the `__name__` and formatted bound
        // that live in `text` are copied.
        buf.push(
            Cow::Borrowed(METRIC_NAME_LABEL),
            Cow::Owned(self.text[entry.name.clone()].to_owned()),
        );
        for (name, value) in &self.line_labels {
            buf.push(name.clone(), value.clone());
        }
        if let Some((label, text)) = &entry.injected {
            let value = match text {
                PendingText::Input(text) => Cow::Borrowed(*text),
                PendingText::Arena(range) => Cow::Owned(self.text[range.clone()].to_owned()),
            };
            buf.push(Cow::Borrowed(label), value);
        }
        buf.sort();
    }
}

/// The `quantile` or `bucket` list of a classic composite value.
struct BoundsField {
    key: &'static str,
    label: &'static str,
    suffix: &'static str,
    plural: &'static str,
    /// Go cuts buckets at the last ':' and quantiles at the first.
    cut_at_last_colon: bool,
}

const QUANTILES: BoundsField = BoundsField {
    key: "quantile",
    label: QUANTILE_LABEL,
    suffix: "",
    plural: "quantiles",
    cut_at_last_colon: false,
};

const BUCKETS: BoundsField = BoundsField {
    key: "bucket",
    label: BUCKET_LABEL,
    suffix: "_bucket",
    plural: "classic histogram buckets",
    cut_at_last_colon: true,
};

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
    exemplars: Exemplars,
    float_histogram_kind: bool,
    int_histogram: Histogram<u64, i64>,
    float_histogram: Histogram<f64, f64>,
    pending: Pending<'a>,
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
            exemplars: Exemplars::default(),
            float_histogram_kind: false,
            int_histogram: Histogram::default(),
            float_histogram: Histogram::default(),
            pending: Pending::default(),
        }
    }

    fn unexpected(&self, expected: &'static str) -> ParseError {
        unexpected(&self.lexer, expected)
    }

    fn invalid_value(message: impl Into<String>) -> ParseError {
        ParseError::InvalidValue(message.into())
    }

    fn utf8_span(&self, start: usize, end: usize) -> Result<ByteSpan, ParseError> {
        utf8_span(&self.lexer, start, end)
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
        self.text = metadata_text(&self.lexer);
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
            let span = label_value_span(&self.lexer, start, end)?;
            if exemplar {
                self.exemplars.labels.push(span);
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
        if value.is_nan() && self.metric_type == MetricType::Counter {
            return Err(Self::invalid_value("counter sample value must not be NaN"));
        }
        self.value = normalize_nan(value);
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
            let labels_start = self.exemplars.labels.len();
            self.parse_label_values(true)?;
            if self.lexer.lex() != Token::Value {
                return Err(self.unexpected("expected exemplar value"));
            }
            let raw = &self.lexer.token()[1..];
            let value = parse_sample_value(raw)
                .ok_or_else(|| Self::invalid_value(String::from_utf8_lossy(raw)))?;
            match self.lexer.lex() {
                Token::Eof => return Err(ParseError::MissingEof),
                Token::Timestamp => {}
                _ => return Err(self.unexpected("expected exemplar timestamp")),
            }
            self.exemplars.entries.push(Exemplar {
                value: normalize_nan(value),
                timestamp: self.timestamp_value(1)?,
                labels: labels_start..self.exemplars.labels.len(),
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
        timestamp_ms(&self.lexer.token()[skip..])
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
        self.pending.set_line_labels(self.lexer.input, &self.labels);
        let family = unescape_label(std::str::from_utf8(self.metric_name()).unwrap_or_default());
        for (key, suffix, field) in fields.count_and_sum(gauge) {
            let value = required_float(field, key)?;
            self.pending.push(&family, suffix, None, value);
        }
        if summary {
            self.pending
                .push_bounds(&family, &QUANTILES, fields.quantile)?;
        } else if !self.pending.push_bounds(&family, &BUCKETS, fields.bucket)? {
            return Err("classic histogram buckets must include a +Inf threshold".to_owned());
        }
        self.pending.advance();
        Ok(Entry::Series)
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
        let [(count_key, _, count), (sum_key, _, sum)] = fields.count_and_sum(gauge);
        let count = required_float(count, count_key)?;
        let sum = required_float(sum, sum_key)?;
        let zero_threshold = required_float(fields.zero_threshold, "zero_threshold")?;
        if !zero_threshold.is_finite() || zero_threshold < 0.0 {
            return Err(format!(
                "zero_threshold must be a non-negative, finite number, got {zero_threshold}"
            ));
        }
        let zero_count = required_float(fields.zero_count, "zero_count")?;
        // Like Go, any non-integer count or a bucket with a decimal point or exponent makes it
        // a float histogram.
        let has_float =
            |buckets: Option<&str>| buckets.unwrap_or_default().contains(['.', 'e', 'E']);
        self.float_histogram_kind = count != count.trunc()
            || zero_count != zero_count.trunc()
            || has_float(fields.positive_buckets)
            || has_float(fields.negative_buckets);
        let header = NativeHeader {
            counter_reset_hint: if gauge {
                CounterResetHint::Gauge
            } else {
                CounterResetHint::Unknown
            },
            schema: schema as i32,
            zero_threshold,
            sum,
        };
        if self.float_histogram_kind {
            let histogram = &mut self.float_histogram;
            fill_histogram(histogram, fields, &header, go_float)?;
            histogram.zero_count = zero_count;
            histogram.count = count;
            return check_float_counts(histogram);
        }
        let histogram = &mut self.int_histogram;
        fill_histogram(histogram, fields, &header, go_int)?;
        // NOTE: Rust saturates out-of-range casts, Go's uint64() is platform-specific there.
        histogram.zero_count = zero_count as u64;
        histogram.count = count as u64;
        check_int_counts(histogram)?;
        absolute_to_deltas(&mut histogram.positive_buckets);
        absolute_to_deltas(&mut histogram.negative_buckets);
        Ok(())
    }
}

impl<'a> Parser<'a> for OpenMetrics2Parser<'a> {
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        if self.done {
            return Ok(None);
        }
        if self.pending.advance() {
            return Ok(Some(Entry::Series));
        }
        self.pending.clear();
        self.exemplars.clear();
        self.line_start = self.lexer.pos;
        self.name = None;
        self.labels.clear();
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
        match self.pending.current() {
            Some(entry) => (
                self.pending.series_bytes(entry),
                self.timestamp,
                entry.value,
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
        if let Some(entry) = self.pending.current() {
            self.pending.write_labels(entry, buf);
            return;
        }
        let name = std::str::from_utf8(self.metric_name()).unwrap_or_default();
        buf.push(Cow::Borrowed(METRIC_NAME_LABEL), unescape_label(name));
        let input = self.lexer.input;
        for span in &self.labels {
            let name = unescape_label(span.name(input));
            let value =
                normalize_float_label(self.metric_type, &name, unescape_label(span.value(input)));
            buf.push(name, value);
        }
        buf.sort();
    }

    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)> {
        buf.clear();
        let exemplar = self.exemplars.entries.get(self.exemplars.next)?;
        self.exemplars.next += 1;
        let input = self.lexer.input;
        // Go keeps exemplar label names escaped and unescapes only the values.
        for span in &self.exemplars.labels[exemplar.labels.clone()] {
            buf.push(
                Cow::Borrowed(span.name(input)),
                unescape_label(span.value(input)),
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

    /// The count and sum as `(key, series suffix, value)`. Gauge histograms use `gcount` and
    /// `gsum`, like Go.
    fn count_and_sum(&self, gauge: bool) -> [(&'static str, &'static str, Option<&'v str>); 2] {
        if gauge {
            [
                ("gcount", "_gcount", self.gcount),
                ("gsum", "_gsum", self.gsum),
            ]
        } else {
            [("count", "_count", self.count), ("sum", "_sum", self.sum)]
        }
    }
}

/// The scalar fields that int and float native histograms share.
struct NativeHeader {
    counter_reset_hint: CounterResetHint,
    schema: i32,
    zero_threshold: f64,
    sum: f64,
}

/// Fills the parts of a native histogram that do not depend on its count type, and checks
/// the spans against the buckets.
fn fill_histogram<C, B>(
    histogram: &mut Histogram<C, B>,
    fields: &CompositeFields<'_>,
    header: &NativeHeader,
    parse_bucket: impl Fn(&str) -> Result<B, String>,
) -> Result<(), String> {
    histogram.counter_reset_hint = header.counter_reset_hint;
    histogram.schema = header.schema;
    histogram.zero_threshold = header.zero_threshold;
    histogram.sum = header.sum;
    parse_spans(
        fields.positive_spans.unwrap_or_default(),
        &mut histogram.positive_spans,
    )?;
    parse_spans(
        fields.negative_spans.unwrap_or_default(),
        &mut histogram.negative_spans,
    )?;
    parse_buckets(
        fields.positive_buckets.unwrap_or_default(),
        &mut histogram.positive_buckets,
        &parse_bucket,
    )?;
    parse_buckets(
        fields.negative_buckets.unwrap_or_default(),
        &mut histogram.negative_buckets,
        &parse_bucket,
    )?;
    check_spans(&histogram.positive_spans, histogram.positive_buckets.len())?;
    check_spans(&histogram.negative_spans, histogram.negative_buckets.len())
}

/// Go's `FloatHistogram.Validate` count checks.
fn check_float_counts(histogram: &Histogram<f64, f64>) -> Result<(), String> {
    let negative_bucket = histogram
        .negative_buckets
        .iter()
        .chain(&histogram.positive_buckets)
        .any(|&bucket| bucket < 0.0);
    if negative_bucket || histogram.zero_count < 0.0 || histogram.count < 0.0 {
        return Err("histogram has a negative observation count".to_owned());
    }
    Ok(())
}

/// Go's `Histogram.Validate` count checks, on absolute bucket counts.
fn check_int_counts(histogram: &Histogram<u64, i64>) -> Result<(), String> {
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
    let count_too_small = if histogram.sum.is_nan() {
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
    Ok(())
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

fn required_float(field: Option<&str>, key: &str) -> Result<f64, String> {
    go_float(required(field, key)?)
}

/// Go's `strconv.ParseFloat`, with Go's NaN bit pattern.
// NOTE: Go also accepts hex floats here, like `0x1p3`; we reject them.
fn go_float(text: &str) -> Result<f64, String> {
    parse_go_float(text)
        .map(normalize_nan)
        .ok_or_else(|| format!("invalid float {text:?}"))
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
