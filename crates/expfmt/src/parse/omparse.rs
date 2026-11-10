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

//! OpenMetrics 1.0 text format parser, a port of
//! [`openmetricsparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/openmetricsparse.go).

use std::borrow::Cow;

use super::float::{FloatBuf, common_openmetrics_float, format_openmetrics_float, parse_go_float};
use super::omlex::{Lexer, LexerState, Token};
use super::{
    BUCKET_LABEL, ByteSpan, Entry, LabelSpan, LabelsBuffer, METRIC_NAME_LABEL, MetricType,
    ParseError, Parser, QUANTILE_LABEL,
};

/// Go's `value.NormalNaN`, the canonical NaN bit pattern Prometheus stores.
const NORMAL_NAN: u64 = 0x7ff8_0000_0000_0001;

const CREATED_SUFFIX: &[u8] = b"_created";

/// Reusable scratch buffers for [`OpenMetricsParser`] so callers can preserve capacity across
/// scrapes without lifetime coupling.
#[derive(Default)]
pub(crate) struct OmScratch {
    pub(crate) labels: Vec<LabelSpan>,
    pub(crate) exemplar_labels: Vec<LabelSpan>,
    pub(crate) peek_labels: Vec<LabelSpan>,
    pub(crate) start_timestamp_key: Vec<u8>,
}

impl OmScratch {
    pub(crate) fn with_capacity(label_cap: usize) -> Self {
        Self {
            labels: Vec::with_capacity(label_cap),
            exemplar_labels: Vec::with_capacity(4),
            peek_labels: Vec::with_capacity(label_cap),
            start_timestamp_key: Vec::with_capacity(64),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.labels.clear();
        self.exemplar_labels.clear();
        self.peek_labels.clear();
        self.start_timestamp_key.clear();
    }

    pub(crate) fn retained_memory_bytes(&self) -> usize {
        (self.labels.capacity() + self.exemplar_labels.capacity() + self.peek_labels.capacity())
            * size_of::<LabelSpan>()
            + self.start_timestamp_key.capacity()
    }
}

/// Lifetime-free state of [`OpenMetricsParser`] that can be stored across suspension points
/// alongside an owned input buffer without self-referential lifetimes.
#[derive(Default)]
pub(crate) struct OpenMetricsParserState {
    lexer: LexerState,
    done: bool,
    peeking: bool,
    line_start: usize,
    series: ByteSpan,
    text: ByteSpan,
    name: Option<ByteSpan>,
    family_name_len: usize,
    metric_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    labels: Vec<LabelSpan>,
    exemplar: Option<(f64, Option<i64>)>,
    exemplar_labels: Vec<LabelSpan>,
    peek_labels: Vec<LabelSpan>,
    start_timestamp_key: Vec<u8>,
    start_timestamp: Option<i64>,
}

impl OpenMetricsParserState {
    /// Resets cursor state for a new scrape while preserving internal scratch capacities in place.
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.lexer = LexerState::default();
        self.done = false;
        self.peeking = false;
        self.line_start = 0;
        self.series = ByteSpan::default();
        self.text = ByteSpan::default();
        self.name = None;
        self.family_name_len = 0;
        self.metric_type = MetricType::Unknown;
        self.value = 0.0;
        self.timestamp = None;
        self.labels.clear();
        self.exemplar = None;
        self.exemplar_labels.clear();
        self.peek_labels.clear();
        self.start_timestamp_key.clear();
        self.start_timestamp = None;
    }

    pub(crate) fn take_scratch(&mut self) -> OmScratch {
        self.labels.clear();
        self.exemplar_labels.clear();
        self.peek_labels.clear();
        self.start_timestamp_key.clear();
        OmScratch {
            labels: std::mem::take(&mut self.labels),
            exemplar_labels: std::mem::take(&mut self.exemplar_labels),
            peek_labels: std::mem::take(&mut self.peek_labels),
            start_timestamp_key: std::mem::take(&mut self.start_timestamp_key),
        }
    }

    pub(crate) fn put_scratch(&mut self, mut scratch: OmScratch) {
        scratch.clear();
        self.labels = scratch.labels;
        self.exemplar_labels = scratch.exemplar_labels;
        self.peek_labels = scratch.peek_labels;
        self.start_timestamp_key = scratch.start_timestamp_key;
    }

    pub(crate) fn retained_memory_bytes(&self) -> usize {
        (self.labels.capacity() + self.exemplar_labels.capacity() + self.peek_labels.capacity())
            * size_of::<LabelSpan>()
            + self.start_timestamp_key.capacity()
    }
}

/// Zero-copy parser for the OpenMetrics 1.0 text exposition format.
///
/// Mirrors Go's `textparse.NewOpenMetricsParser` with `WithOMParserSTSeriesSkipped`:
/// `_created` lines of counters, summaries, and histograms only feed
/// [`Parser::start_timestamp`].
pub struct OpenMetricsParser<'a> {
    lexer: Lexer<'a>,
    /// Set once `# EOF` is read, so later calls keep returning `Ok(None)`.
    done: bool,
    /// Set while peeking ahead for a `_created` line, where Go skips exemplars unparsed and
    /// returns `_created` lines.
    peeking: bool,
    line_start: usize,
    series: ByteSpan,
    text: ByteSpan,
    name: Option<ByteSpan>,
    /// Length of the name on the last metadata line, Go's `mfNameLen`.
    family_name_len: usize,
    /// The type from the last `# TYPE` line, which Go keeps across metric families.
    metric_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    /// Escaped label name and value byte spans in `lexer.input`, without quotes.
    labels: Vec<LabelSpan>,
    exemplar: Option<(f64, Option<i64>)>,
    exemplar_labels: Vec<LabelSpan>,
    /// Labels buffer lent to the start timestamp lookahead, so it does not allocate per call.
    peek_labels: Vec<LabelSpan>,
    /// Go's start timestamp cache: the series key and start timestamp of the last hit.
    start_timestamp_key: Vec<u8>,
    start_timestamp: Option<i64>,
}

impl<'a> OpenMetricsParser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self::with_scratch(input, OmScratch::default())
    }

    /// Creates a parser over `input` reusing pre-allocated scratch buffers.
    #[inline]
    pub(crate) fn with_scratch(input: &'a [u8], mut scratch: OmScratch) -> Self {
        scratch.clear();
        Self {
            lexer: Lexer::new(input),
            done: false,
            peeking: false,
            line_start: 0,
            series: ByteSpan::default(),
            text: ByteSpan::default(),
            name: None,
            family_name_len: 0,
            metric_type: MetricType::Unknown,
            value: 0.0,
            timestamp: None,
            labels: scratch.labels,
            exemplar: None,
            exemplar_labels: scratch.exemplar_labels,
            peek_labels: scratch.peek_labels,
            start_timestamp_key: scratch.start_timestamp_key,
            start_timestamp: None,
        }
    }

    /// Detaches the borrowed `input` slice and returns the lifetime-free parser state.
    #[inline]
    pub(crate) fn into_state(self) -> OpenMetricsParserState {
        OpenMetricsParserState {
            lexer: self.lexer.into_state(),
            done: self.done,
            peeking: self.peeking,
            line_start: self.line_start,
            series: self.series,
            text: self.text,
            name: self.name,
            family_name_len: self.family_name_len,
            metric_type: self.metric_type,
            value: self.value,
            timestamp: self.timestamp,
            labels: self.labels,
            exemplar: self.exemplar,
            exemplar_labels: self.exemplar_labels,
            peek_labels: self.peek_labels,
            start_timestamp_key: self.start_timestamp_key,
            start_timestamp: self.start_timestamp,
        }
    }

    /// Reconstructs a parser over `input` from a previously detached [`OpenMetricsParserState`].
    #[inline]
    pub(crate) fn from_state(input: &'a [u8], state: OpenMetricsParserState) -> Self {
        Self {
            lexer: Lexer::from_state(input, state.lexer),
            done: state.done,
            peeking: state.peeking,
            line_start: state.line_start,
            series: state.series,
            text: state.text,
            name: state.name,
            family_name_len: state.family_name_len,
            metric_type: state.metric_type,
            value: state.value,
            timestamp: state.timestamp,
            labels: state.labels,
            exemplar: state.exemplar,
            exemplar_labels: state.exemplar_labels,
            peek_labels: state.peek_labels,
            start_timestamp_key: state.start_timestamp_key,
            start_timestamp: state.start_timestamp,
        }
    }

    /// Returns the reusable scratch buffers so callers can preserve capacity across scrapes.
    pub(crate) fn into_scratch(mut self) -> OmScratch {
        self.take_scratch()
    }

    /// Takes the reusable scratch buffers in place for `Drop` handlers.
    #[inline]
    pub(crate) fn take_scratch(&mut self) -> OmScratch {
        self.labels.clear();
        self.exemplar_labels.clear();
        self.peek_labels.clear();
        self.start_timestamp_key.clear();
        OmScratch {
            labels: std::mem::take(&mut self.labels),
            exemplar_labels: std::mem::take(&mut self.exemplar_labels),
            peek_labels: std::mem::take(&mut self.peek_labels),
            start_timestamp_key: std::mem::take(&mut self.start_timestamp_key),
        }
    }

    /// Returns the current byte offset of the parser cursor in `input` (`0..=input.len()`).
    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.lexer.pos.min(self.lexer.input.len())
    }

    /// Returns the byte offset of the current entry's metric name in `input`.
    #[inline]
    pub(crate) fn name_offset(&self) -> usize {
        self.name.map_or(0, |span| span.start)
    }

    /// Returns the raw metric name and raw (escaped) help text for `Entry::Help`.
    #[inline]
    pub(crate) fn raw_help(&self) -> (&'a [u8], &'a [u8]) {
        (self.metric_name(), &self.lexer.input[self.text])
    }

    /// Returns the raw metric name, validated UTF-8 label spans, full input slice, optional
    /// timestamp in milliseconds, and sample value for `Entry::Series`.
    #[inline]
    pub(crate) fn raw_series_parts(&self) -> (&'a [u8], &[LabelSpan], &'a [u8], Option<i64>, f64) {
        (
            self.metric_name(),
            &self.labels,
            self.lexer.input,
            self.timestamp,
            self.value,
        )
    }

    /// Returns the exemplar value, optional timestamp in milliseconds, and label spans for the
    /// current `Entry::Series`, if present.
    #[inline]
    pub(crate) fn raw_exemplar_parts(&self) -> Option<(f64, Option<i64>, &[LabelSpan])> {
        self.exemplar
            .map(|(val, ts)| (val, ts, self.exemplar_labels.as_slice()))
    }

    fn unexpected(&self, expected: &'static str) -> ParseError {
        ParseError::UnexpectedToken {
            expected,
            offset: self.lexer.token_start,
        }
    }

    fn utf8_span(&self, start: usize, end: usize) -> Result<ByteSpan, ParseError> {
        let input = self.lexer.input;
        if std::str::from_utf8(&input[start..end]).is_err() {
            return Err(ParseError::InvalidUtf8 {
                offset: self.lexer.token_start,
            });
        }
        Ok(ByteSpan::new(start, end))
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
        self.family_name_len = end - start;
        self.name = Some(self.utf8_span(start, end)?);
        if self.lexer.lex() != Token::Text {
            return Err(self.unexpected("expected text"));
        }
        let text_span = self.lexer.token_span();
        let text = &self.lexer.input[text_span];
        // The text token starts with a blank and ends with a linebreak, which the lexer
        // can follow with NUL bytes.
        let end = text
            .iter()
            .position(|&byte| byte == b'\n')
            .unwrap_or(text.len());
        let text_end = text_span.start + end;
        self.text = ByteSpan::new((text_span.start + 1).min(text_end), text_end);
        let raw_text = &self.lexer.input[self.text];
        match kind {
            Token::Type => {
                self.metric_type = parse_metric_type(raw_text)?;
                self.start_timestamp = None;
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
            _ => {
                let metric = self.metric_name();
                let unit = raw_text;
                let is_suffix = metric.len() > unit.len()
                    && metric.ends_with(unit)
                    && metric[metric.len() - unit.len() - 1] == b'_';
                if !unit.is_empty() && !is_suffix {
                    return Err(ParseError::InvalidUnit {
                        metric: String::from_utf8_lossy(metric).into_owned(),
                        unit: String::from_utf8_lossy(unit).into_owned(),
                    });
                }
                Ok(Entry::Unit)
            }
        }
    }

    /// Parses a sample line that starts with a metric name or with `{`.
    fn parse_series(&mut self, first: Token) -> Result<Entry, ParseError> {
        let mut token = first;
        if first == Token::MName {
            self.name = Some(self.utf8_span(self.line_start, self.lexer.pos)?);
            token = self.lexer.lex();
        }
        if token == Token::BraceOpen {
            self.parse_label_values(false)?;
            token = self.lexer.lex();
        }
        self.series = ByteSpan::new(self.line_start, self.lexer.token_start);
        self.parse_series_end_of_line(token)?;
        Ok(Entry::Series)
    }

    /// Parses labels up to and including `}`, into the exemplar labels when `exemplar` is set.
    fn parse_label_values(&mut self, exemplar: bool) -> Result<(), ParseError> {
        let mut token = self.lexer.lex();
        loop {
            let (start, end) = match token {
                Token::BraceClose => return Ok(()),
                Token::LName => (self.lexer.token_start, self.lexer.pos),
                Token::QString => (self.lexer.token_start + 1, self.lexer.pos - 1),
                _ => return Err(self.unexpected("expected label name")),
            };
            let quoted = token == Token::QString;
            let name = self.utf8_span(start, end)?;
            token = self.lexer.lex();
            if quoted && matches!(token, Token::Comma | Token::BraceClose) {
                if exemplar {
                    return Err(self.unexpected("expected label name"));
                }
                if self.name.is_some() {
                    return Err(ParseError::InvalidMetricName {
                        offset: self.line_start,
                    });
                }
                self.name = Some(name);
                if token == Token::BraceClose {
                    return Ok(());
                }
                token = self.next_after_quoted_name();
                continue;
            }
            if token != Token::Equal {
                return Err(self.unexpected("expected equal"));
            }
            if self.lexer.lex() != Token::LValue {
                return Err(self.unexpected("expected label value"));
            }
            let val_token_start = self.lexer.token_start;
            let value =
                std::str::from_utf8(self.lexer.token()).map_err(|_| ParseError::InvalidUtf8 {
                    offset: val_token_start,
                })?;
            // The token can end in NUL bytes after the closing quote. Go drops only the last
            // byte, so it keeps the quote and all but the last NUL in the value. We cut at the
            // quote.
            let close = value.rfind('"').unwrap_or(0);
            let span = LabelSpan {
                name_start: start,
                name_end: end,
                val_start: val_token_start + 1,
                val_end: val_token_start + close.max(1),
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

    #[inline]
    fn next_after_quoted_name(&mut self) -> Token {
        self.lexer.lex()
    }

    fn parse_series_end_of_line(&mut self, token: Token) -> Result<(), ParseError> {
        if self.name.is_none() {
            return Err(ParseError::InvalidMetricName {
                offset: self.line_start,
            });
        }
        self.value = self.float_value(token, "expected value after metric")?;
        self.timestamp = None;
        match self.lexer.lex() {
            Token::Eof => return Err(ParseError::MissingEof),
            Token::Comment => self.parse_exemplar()?,
            Token::Timestamp => {
                self.timestamp = Some(self.timestamp_value()?);
                match self.lexer.lex() {
                    Token::Linebreak => {}
                    Token::Comment => self.parse_exemplar()?,
                    _ => return Err(self.unexpected("expected next entry after timestamp")),
                }
            }
            // Go has no default case here, so any other token ends the sample without error.
            _ => {}
        }
        Ok(())
    }

    /// Parses the exemplar after ` # {`, Go's `parseComment`.
    fn parse_exemplar(&mut self) -> Result<(), ParseError> {
        if self.peeking {
            loop {
                let before = self.lexer.pos;
                match self.lexer.lex() {
                    Token::Linebreak => return Ok(()),
                    Token::Eof => return Err(ParseError::MissingEof),
                    // Go loops forever here, so a scrape target could stall the scraper.
                    Token::Invalid if self.lexer.pos == before => {
                        return Err(self.unexpected("expected linebreak after exemplar"));
                    }
                    _ => {}
                }
            }
        }
        self.parse_label_values(true)?;
        let token = self.lexer.lex();
        let value = self.float_value(token, "expected value after exemplar labels")?;
        let mut timestamp = None;
        match self.lexer.lex() {
            Token::Eof => return Err(ParseError::MissingEof),
            Token::Linebreak => {}
            Token::Timestamp => {
                timestamp = Some(self.timestamp_value()?);
                if self.lexer.lex() != Token::Linebreak {
                    return Err(self.unexpected("expected next entry after exemplar timestamp"));
                }
            }
            _ => return Err(self.unexpected("expected timestamp or comment")),
        }
        self.exemplar = Some((value, timestamp));
        Ok(())
    }

    /// Parses the current value token, which starts with a blank.
    fn float_value(&self, token: Token, expected: &'static str) -> Result<f64, ParseError> {
        if token != Token::Value {
            return Err(self.unexpected(expected));
        }
        let raw = &self.lexer.token()[1..];
        let value = parse_sample_value(raw)
            .ok_or_else(|| ParseError::InvalidValue(String::from_utf8_lossy(raw).into_owned()))?;
        Ok(if value.is_nan() {
            f64::from_bits(NORMAL_NAN)
        } else {
            value
        })
    }

    /// Parses the current timestamp token, float seconds after a blank, into milliseconds.
    fn timestamp_value(&self) -> Result<i64, ParseError> {
        let raw = &self.lexer.token()[1..];
        let seconds = parse_sample_value(raw)
            .filter(|seconds| seconds.is_finite())
            .ok_or_else(|| {
                ParseError::InvalidTimestamp(String::from_utf8_lossy(raw).into_owned())
            })?;
        // NOTE: Rust saturates out-of-range casts, Go's int64() is platform-specific there.
        Ok((seconds * 1000.0) as i64)
    }

    #[inline]
    fn metric_name(&self) -> &'a [u8] {
        self.name.map_or(b"", |span| &self.lexer.input[span])
    }

    fn is_created_series(&self) -> bool {
        requires_start_timestamp(self.metric_type) && self.metric_name().ends_with(CREATED_SUFFIX)
    }

    /// Go's `seriesHash` input: label names and values, without `le` on histograms and
    /// `quantile` on summaries, followed by the metric family name. Each piece is
    /// length-prefixed so `{ab="c"}` and `{a="bc"}` differ.
    fn series_key<'k>(&'k self, family: &'k [u8]) -> impl Iterator<Item = u8> + 'k {
        let input = self.lexer.input;
        self.labels
            .iter()
            .filter(|span| {
                let name =
                    std::str::from_utf8(&input[span.name_start..span.name_end]).unwrap_or_default();
                !is_float_label(self.metric_type, name)
            })
            .flat_map(|span| {
                [
                    &input[span.name_start..span.name_end],
                    &input[span.val_start..span.val_end],
                ]
            })
            .chain([family])
            .flat_map(|piece| {
                piece
                    .len()
                    .to_le_bytes()
                    .into_iter()
                    .chain(piece.iter().copied())
            })
    }

    /// The metric family name, cut from the metric name to the length of the name on the
    /// last metadata line, `currName` in Go.
    fn family_name(&self) -> &'a [u8] {
        let name = self.metric_name();
        &name[..self.family_name_len.min(name.len())]
    }
}

impl<'a> Parser<'a> for OpenMetricsParser<'a> {
    #[inline]
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        if self.done {
            return Ok(None);
        }
        loop {
            self.line_start = self.lexer.pos;
            self.name = None;
            self.labels.clear();
            self.exemplar = None;
            self.exemplar_labels.clear();
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
            if entry == Entry::Series && !self.peeking && self.is_created_series() {
                continue;
            }
            return Ok(Some(entry));
        }
    }

    #[inline]
    fn pos(&self) -> usize {
        OpenMetricsParser::pos(self)
    }

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>) {
        // OpenMetrics help text uses label value escaping, unlike Prometheus text.
        (self.metric_name(), unescape(&self.lexer.input[self.text]))
    }

    #[inline]
    fn metric_type(&self) -> (&'a [u8], MetricType) {
        (self.metric_name(), self.metric_type)
    }

    #[inline]
    fn unit(&self) -> (&'a [u8], &'a [u8]) {
        (self.metric_name(), &self.lexer.input[self.text])
    }

    fn comment(&self) -> &'a [u8] {
        &self.lexer.input[self.text]
    }

    fn series(&self) -> (&'a [u8], Option<i64>, f64) {
        (&self.lexer.input[self.series], self.timestamp, self.value)
    }

    fn labels(&self, buf: &mut LabelsBuffer<'a>) {
        buf.clear();
        let name = std::str::from_utf8(self.metric_name()).unwrap_or_default();
        buf.push(Cow::Borrowed(METRIC_NAME_LABEL), unescape_label(name));
        let input = self.lexer.input;
        for span in &self.labels {
            let raw_name =
                std::str::from_utf8(&input[span.name_start..span.name_end]).unwrap_or_default();
            let raw_val =
                std::str::from_utf8(&input[span.val_start..span.val_end]).unwrap_or_default();
            let name = unescape_label(raw_name);
            let value = normalize_float_label(self.metric_type, &name, unescape_label(raw_val));
            buf.push(name, value);
        }
        buf.sort();
    }

    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)> {
        buf.clear();
        let exemplar = self.exemplar.take()?;
        // Go's OpenMetrics 1.0 parser keeps exemplar labels escaped. We unescape them like
        // series labels, as Go's OpenMetrics 2.0 parser does.
        let input = self.lexer.input;
        for span in &self.exemplar_labels {
            let raw_name =
                std::str::from_utf8(&input[span.name_start..span.name_end]).unwrap_or_default();
            let raw_val =
                std::str::from_utf8(&input[span.val_start..span.val_end]).unwrap_or_default();
            buf.push(unescape_label(raw_name), unescape_label(raw_val));
        }
        buf.sort();
        Some(exemplar)
    }

    /// Peeks ahead for the `_created` line of the current series, like Go's `StartTimestamp`,
    /// including its cache of the last hit.
    fn start_timestamp(&mut self) -> Option<i64> {
        if !requires_start_timestamp(self.metric_type) {
            self.start_timestamp = None;
            return None;
        }
        let family = self.family_name();
        if let Some(cached) = self.start_timestamp
            && self
                .series_key(family)
                .eq(self.start_timestamp_key.iter().copied())
        {
            return Some(cached);
        }
        let mut peek = OpenMetricsParser::new(self.lexer.input);
        peek.lexer = self.lexer.clone();
        peek.peeking = true;
        peek.metric_type = self.metric_type;
        peek.labels = std::mem::take(&mut self.peek_labels);
        let found = loop {
            if !matches!(peek.next_entry(), Ok(Some(Entry::Series))) {
                break None;
            }
            let Some(peeked_family) = peek.metric_name().strip_suffix(CREATED_SUFFIX) else {
                continue;
            };
            let same_series = peek.series_key(peeked_family).eq(self.series_key(family));
            let millis = peek.value * 1000.0;
            // Go converts NaN and Inf into a timestamp that looks valid; also ignore values
            // outside the representable i64 millisecond range instead of saturating to i64::MAX.
            break (same_series && (i64::MIN as f64..i64::MAX as f64).contains(&millis))
                .then_some(millis as i64);
        };
        self.peek_labels = std::mem::take(&mut peek.labels);
        if found.is_some() {
            let mut key = std::mem::take(&mut self.start_timestamp_key);
            key.clear();
            key.extend(self.series_key(family));
            self.start_timestamp_key = key;
        }
        self.start_timestamp = found;
        found
    }
}

/// Go's `typeRequiresST`.
fn requires_start_timestamp(metric_type: MetricType) -> bool {
    matches!(
        metric_type,
        MetricType::Counter | MetricType::Summary | MetricType::Histogram
    )
}

fn is_float_label(metric_type: MetricType, name: &str) -> bool {
    match metric_type {
        MetricType::Histogram => name == BUCKET_LABEL,
        MetricType::Summary => name == QUANTILE_LABEL,
        _ => false,
    }
}

/// Go's `normalizeFloatsInLabelValues`: `le` on histograms and `quantile` on summaries
/// use OpenMetrics float formatting. Keeps `value` borrowed when it is already canonical.
fn normalize_float_label<'v>(
    metric_type: MetricType,
    name: &str,
    value: Cow<'v, str>,
) -> Cow<'v, str> {
    // NOTE: Go's ParseFloat also accepts hex floats here (le="0x1p3"); we leave them as is.
    let Some(parsed) = is_float_label(metric_type, name)
        .then(|| parse_go_float(&value))
        .flatten()
    else {
        return value;
    };
    if let Some(common) = common_openmetrics_float(parsed) {
        return Cow::Borrowed(common);
    }
    let mut formatted = FloatBuf::default();
    if format_openmetrics_float(parsed, &mut formatted).is_err() || formatted.as_str() == value {
        return value;
    }
    Cow::Owned(formatted.as_str().to_owned())
}

/// Maps a `# TYPE` value to a [`MetricType`].
fn parse_metric_type(text: &[u8]) -> Result<MetricType, ParseError> {
    [
        MetricType::Counter,
        MetricType::Gauge,
        MetricType::Histogram,
        MetricType::GaugeHistogram,
        MetricType::Summary,
        MetricType::Info,
        MetricType::Stateset,
        MetricType::Unknown,
    ]
    .into_iter()
    .find(|metric_type| metric_type.as_str().as_bytes() == text)
    .ok_or_else(|| ParseError::InvalidMetricType(String::from_utf8_lossy(text).into_owned()))
}

/// Go's `lvalReplacer`, which replaces `\"`, `\\`, and `\n`.
fn unescape(raw: &[u8]) -> Cow<'_, [u8]> {
    if !raw.contains(&b'\\') {
        return Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        let replaced = match (byte, bytes.peek()) {
            (b'\\', Some(b'\\')) => b'\\',
            (b'\\', Some(b'n')) => b'\n',
            (b'\\', Some(b'"')) => b'"',
            _ => {
                out.push(byte);
                continue;
            }
        };
        bytes.next();
        out.push(replaced);
    }
    Cow::Owned(out)
}

fn unescape_label(raw: &str) -> Cow<'_, str> {
    match unescape(raw.as_bytes()) {
        Cow::Borrowed(_) => Cow::Borrowed(raw),
        // Replacing ASCII escapes keeps valid UTF-8 valid, so nothing is lost here.
        Cow::Owned(bytes) => Cow::Owned(
            String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
        ),
    }
}

/// Go's `parseFloat` in promparse.go, which rejects `pP_` before `strconv.ParseFloat`.
fn parse_sample_value(raw: &[u8]) -> Option<f64> {
    if raw.iter().any(|byte| matches!(byte, b'p' | b'P' | b'_')) {
        return None;
    }
    parse_go_float(std::str::from_utf8(raw).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(input: &[u8]) -> Result<(), ParseError> {
        let mut parser = OpenMetricsParser::new(input);
        while parser.next_entry()?.is_some() {}
        Ok(())
    }

    #[test]
    fn requires_eof() {
        assert_eq!(parse_all(b"a 1\n"), Err(ParseError::MissingEof));
        assert_eq!(parse_all(b"a 1"), Err(ParseError::MissingEof));
        assert_eq!(parse_all(b"a 1\n# EOF\n"), Ok(()));
        assert_eq!(parse_all(b"a 1\n# EOF"), Ok(()));
    }

    #[test]
    fn rejects_data_after_eof() {
        assert_eq!(
            parse_all(b"# EOF\na 1\n"),
            Err(ParseError::DataAfterEof { offset: 6 })
        );
        assert!(matches!(
            parse_all(b"a 1\n# EOF\n\n"),
            Err(ParseError::DataAfterEof { .. })
        ));
    }

    #[test]
    fn rejects_malformed_exemplars() {
        let inputs: &[&[u8]] = &[
            b"a_total 1 # {id=\"abc\" 1\n# EOF\n",
            b"a_total 1 # {\"id\"} 1\n# EOF\n",
            b"a_total 1 # {id=\"abc\"}\n# EOF\n",
            b"a_total 1 # {id=\"abc\"} 1 NaN\n# EOF\n",
        ];
        for input in inputs {
            assert!(
                matches!(
                    parse_all(input),
                    Err(ParseError::UnexpectedToken { .. } | ParseError::InvalidTimestamp(_))
                ),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn rejects_unit_that_is_not_a_suffix() {
        assert!(matches!(
            parse_all(b"# UNIT a_seconds bytes\n# EOF\n"),
            Err(ParseError::InvalidUnit { .. })
        ));
        assert!(matches!(
            parse_all(b"# UNIT seconds seconds\n# EOF\n"),
            Err(ParseError::InvalidUnit { .. })
        ));
        assert_eq!(parse_all(b"# UNIT a_seconds seconds\n# EOF\n"), Ok(()));
    }

    fn first_start_timestamp(input: &'static [u8]) -> Option<i64> {
        let mut parser = OpenMetricsParser::new(input);
        while parser.next_entry().unwrap() != Some(Entry::Series) {}
        parser.start_timestamp()
    }

    #[test]
    fn start_timestamp_stops_on_invalid_exemplar() {
        // Go's lookahead loops forever on this input.
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let input = b"# TYPE a counter\na_total 1\na_total{x=\"1\"} 2 # {id=\"x\"}x\n# EOF\n";
            done.send(first_start_timestamp(input)).unwrap();
        });
        let start = result.recv_timeout(std::time::Duration::from_secs(5));
        assert_eq!(start, Ok(None));
    }

    #[test]
    fn start_timestamp_ignores_non_finite_created() {
        for input in [
            &b"# TYPE a counter\na_total 1\na_created NaN\n# EOF\n"[..],
            b"# TYPE a counter\na_total 1\na_created +Inf\n# EOF\n",
            b"# TYPE a counter\na_total 1\na_created 1e300\n# EOF\n",
            b"# TYPE a counter\na_total 1\na_created -1e300\n# EOF\n",
        ] {
            assert_eq!(first_start_timestamp(input), None);
        }
    }

    /// Metric name and start timestamp of each series.
    fn start_timestamps(input: &[u8]) -> Vec<(String, Option<i64>)> {
        let mut parser = OpenMetricsParser::new(input);
        let mut out = Vec::new();
        while let Some(entry) = parser.next_entry().unwrap() {
            if entry == Entry::Series {
                let name = String::from_utf8_lossy(parser.metric_name()).into_owned();
                out.push((name, parser.start_timestamp()));
            }
        }
        out
    }

    #[test]
    fn skips_created_series() {
        assert_eq!(
            start_timestamps(b"# TYPE a counter\na_total 1\na_created 5\nb 1\n# EOF\n"),
            [("a_total".to_owned(), Some(5000)), ("b".to_owned(), None)]
        );
    }

    #[test]
    fn start_timestamp_keeps_zero_for_the_whole_series() {
        let input = b"# TYPE bar summary\nbar_count 1\nbar_created 0\nbar_sum 2\n# EOF\n";
        assert_eq!(
            start_timestamps(input),
            [
                ("bar_count".to_owned(), Some(0)),
                ("bar_sum".to_owned(), Some(0))
            ]
        );
    }

    #[test]
    fn start_timestamp_tells_label_splits_apart() {
        let input = b"# TYPE x counter\nx_total{a=\"bc\"} 1\nx_created{a=\"bc\"} 7\nx_total{ab=\"c\"} 1\n# EOF\n";
        assert_eq!(
            start_timestamps(input),
            [
                ("x_total".to_owned(), Some(7000)),
                ("x_total".to_owned(), None)
            ]
        );
    }

    #[test]
    fn start_timestamp_scans_past_other_series() {
        let input = b"# TYPE foo counter\nfoo_total{a=\"1\"} 1\nfoo_total{a=\"2\"} 2\nfoo_created{a=\"1\"} 100\n# EOF\n";
        assert_eq!(
            start_timestamps(input),
            [
                ("foo_total".to_owned(), Some(100_000)),
                ("foo_total".to_owned(), None)
            ]
        );
    }

    #[test]
    fn start_timestamp_cache_resets_on_type() {
        let input =
            b"# TYPE a counter\na_total 1\na_created 7\n# TYPE a counter\na_total 1\n# EOF\n";
        assert_eq!(
            start_timestamps(input),
            [
                ("a_total".to_owned(), Some(7000)),
                ("a_total".to_owned(), None)
            ]
        );
    }

    #[test]
    fn start_timestamp_finds_quoted_name_after_label() {
        let input = concat!(
            "# TYPE \"my.counter\" counter\n",
            "{q=\"0.9\",\"my.counter_total\"} 1\n",
            "{q=\"0.9\",\"my.counter_created\"} 7\n",
            "# EOF\n",
        );
        assert_eq!(
            start_timestamps(input.as_bytes()),
            [("my.counter_total".to_owned(), Some(7000))]
        );
    }

    #[test]
    fn keeps_returning_none_after_eof() {
        let mut parser = OpenMetricsParser::new(b"# EOF\n");
        assert_eq!(parser.next_entry(), Ok(None));
        assert_eq!(parser.next_entry(), Ok(None));
    }

    #[test]
    fn help_text_drops_nul_after_linebreak() {
        let mut parser = OpenMetricsParser::new(b"# HELP a foo\n\0\0# EOF\n");
        assert_eq!(parser.next_entry(), Ok(Some(Entry::Help)));
        assert_eq!(parser.help().1.as_ref(), b"foo");
    }

    #[test]
    fn rejects_invalid_utf8_in_quoted_names() {
        let inputs: &[&[u8]] = &[
            b"{\"\xff\"} 1\n# EOF\n",
            b"a{\"\xff\"=\"b\"} 1\n# EOF\n",
            b"# TYPE \"\xff\" counter\n# EOF\n",
            b"a_total 1 # {\"\xff\"=\"b\"} 1\n# EOF\n",
        ];
        for input in inputs {
            assert!(
                matches!(parse_all(input), Err(ParseError::InvalidUtf8 { .. })),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn unescapes_exemplar_labels() {
        let mut parser = OpenMetricsParser::new(b"a_total 1 # {id=\"a\\\"b\"} 2\n# EOF\n");
        let mut buf = LabelsBuffer::new();
        assert_eq!(parser.next_entry(), Ok(Some(Entry::Series)));
        assert!(parser.exemplar(&mut buf).is_some());
        assert_eq!(buf.get("id"), Some("a\"b"));
    }

    #[test]
    fn unexpected_eof_points_at_the_end() {
        for input in [&b"# TYPE m"[..], b"a{b=\"c\"}"] {
            assert_eq!(
                parse_all(input),
                Err(ParseError::UnexpectedToken {
                    expected: match input[0] {
                        b'#' => "expected text",
                        _ => "expected value after metric",
                    },
                    offset: input.len(),
                })
            );
        }
    }

    /// Error cases from Go's `TestOpenMetricsParseErrors` and `TestOMNullByteHandling`.
    #[test]
    fn rejects_upstream_error_cases() {
        let missing_eof: &[&[u8]] = &[
            b"",
            b"metric 1",
            b"metric 1\n",
            b"metric_total 1 # {aa=\"bb\"} 4",
        ];
        for input in missing_eof {
            assert_eq!(parse_all(input), Err(ParseError::MissingEof));
        }
        let inputs: &[&[u8]] = &[
            b"\n",
            b"metric",
            b"a\n#EOF\n",
            b"\n\n#EOF\n",
            b" a 1\n#EOF\n",
            b"9\n#EOF\n",
            b"# TYPE u untyped\n#EOF\n",
            b"# TYPE c counter \n#EOF\n",
            b"#  TYPE c counter\n#EOF\n",
            b"# TYPE \n#EOF\n",
            b"# TYPE m\n#EOF\n",
            b"# UNIT metric suffix\n#EOF\n",
            b"# UNIT metricsuffix suffix\n#EOF\n",
            b"# UNIT m suffix\n#EOF\n",
            b"# UNIT \n#EOF\n",
            b"# UNIT m\n#EOF\n",
            b"# HELP \n#EOF\n",
            b"# HELP m\n#EOF\n",
            b"a\t1\n#EOF\n",
            b"a 1\t2\n#EOF\n",
            b"a 1 2 \n#EOF\n",
            b"a 1 2 #\n#EOF\n",
            b"a 1 1z\n#EOF\n",
            b" # EOF\n",
            b"# EOF\na 1",
            b"# EOF\n\n",
            b"# EOFa 1",
            b"#\tTYPE c counter\n",
            b"# TYPE c  counter\n",
            b"a 1 1 1\n# EOF\n",
            b"a{b='c'} 1\n# EOF\n",
            b"a{,b=\"c\"} 1\n# EOF\n",
            b"a{b=\"c\"d=\"e\"} 1\n# EOF\n",
            b"a{b=\"c\",,d=\"e\"} 1\n# EOF\n",
            b"a{b=\n# EOF\n",
            b"a{\xff=\"foo\"} 1\n# EOF\n",
            b"a{b=\"\xff\"} 1\n# EOF\n",
            b"{\"a\",\"b = \"c\"}\n# EOF\n",
            b"{\"a\",b\\nc=\"d\"} 1\n# EOF\n",
            b"a true\n",
            b"something_weird{problem=\"\n# EOF\n",
            b"empty_label_name{=\"\"} 0\n# EOF\n",
            b"{A}0\n# EOF\n",
            b"foo 1_2\n\n# EOF\n",
            b"foo 0x1p-3\n\n# EOF\n",
            b"foo 0x1P-3\n\n# EOF\n",
            b"foo 0 1_2\n\n# EOF\n",
            b"custom_metric_total 1 # {aa=bb}\n# EOF\n",
            b"custom_metric_total 1 # {aa=\"bb\"}\n# EOF\n",
            b"custom_metric_total 1 # {aa=\"bb\"}",
            b"custom_metric_total 1 # {bb}",
            b"custom_metric_total 1 # {bb, a=\"dd\"}",
            b"custom_metric_total 1 # {aa=\"bb\",,cc=\"dd\"} 1",
            b"custom_metric_total 1 # {aa=\"bb\"} 1_2",
            b"custom_metric_total 1 # {aa=\"bb\"} 0x1p-3",
            b"custom_metric_total 1 # {aa=\"bb\"} true",
            b"custom_metric_total 1 # {aa=\"bb\",cc=}",
            br#"custom_metric_total 1 # {aa=\"\xff\"} 9.0"#,
            b"{b=\"c\",} 1",
            b"a 1 NaN",
            b"a 1 -Inf",
            b"a 1 Inf",
            b"# TYPE hhh histogram\nhhh_bucket{le=\"+Inf\"} 1 # {aa=\"bb\"} 4 NaN",
            b"# TYPE hhh histogram\nhhh_bucket{le=\"+Inf\"} 1 # {aa=\"bb\"} 4 -Inf",
            b"a{b=\0\"ssss\"} 1\n# EOF\n",
            b"a{b=\"\0",
            b"a{b\0=\"hiih\"}\t1",
            b"a\0{b=\"ddd\"} 1",
            b"#",
            b"# H",
            b"custom_metric_total 1 # {b=\0\"ssss\"} 1\n",
            b"custom_metric_total 1 # {b=\"\0ss\"} 1\n",
        ];
        for input in inputs {
            assert!(
                parse_all(input).is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    /// Valid cases from Go's `TestOpenMetricsParseErrors` and `TestOMNullByteHandling`.
    #[test]
    fn accepts_upstream_valid_cases() {
        let inputs: &[&[u8]] = &[
            b"# EOF",
            b"# EOF\n",
            b"null_byte_metric{a=\"abc\0\"} 1\n# EOF\n",
            b"a{b=\"\0ss\"} 1\n# EOF\n",
            b"a{b=\"\0\"} 1\n# EOF\n",
            b"a{b=\"\0\"} 1\n# EOF",
        ];
        for input in inputs {
            assert_eq!(
                parse_all(input),
                Ok(()),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn exemplar_is_returned_once() {
        let mut parser = OpenMetricsParser::new(b"a_total 1 # {id=\"x\"} 2\n# EOF\n");
        let mut buf = LabelsBuffer::new();
        assert_eq!(parser.next_entry(), Ok(Some(Entry::Series)));
        assert_eq!(parser.exemplar(&mut buf), Some((2.0, None)));
        assert_eq!(parser.exemplar(&mut buf), None);
    }

    #[test]
    fn label_value_drops_nul_after_closing_quote() {
        let mut parser = OpenMetricsParser::new(b"a{b=\"c\"\0} 1\n# EOF\n");
        let mut buf = LabelsBuffer::new();
        assert_eq!(parser.next_entry(), Ok(Some(Entry::Series)));
        parser.labels(&mut buf);
        assert_eq!(buf.get("b"), Some("c"));
    }

    #[test]
    fn pos_and_state_roundtrip_preserve_parse_results() {
        let input = concat!(
            "# HELP foo_seconds Counter help\n",
            "# UNIT foo_seconds seconds\n",
            "# TYPE foo_seconds counter\n",
            "foo_seconds_total{env=\"prod\"} 10 1.5 # {trace_id=\"abc\"} 1.0 2.0\n",
            "foo_seconds_created{env=\"prod\"} 1.0\n",
            "{\"my.gauge\",k=\"v\"} 3.25\n",
            "# EOF\n",
        );
        let bytes = input.as_bytes();

        type Snapshot = (
            Entry,
            String,
            Option<MetricType>,
            Option<(Option<i64>, u64, Option<i64>)>,
            Vec<(String, String)>,
            Option<(u64, Option<i64>, Vec<(String, String)>)>,
        );

        let collect_direct = |b: &[u8]| -> Vec<Snapshot> {
            let mut parser = OpenMetricsParser::new(b);
            let mut buf = LabelsBuffer::new();
            let mut ex_buf = LabelsBuffer::new();
            let mut out = Vec::new();
            let lossy = |s: &[u8]| String::from_utf8_lossy(s).into_owned();
            while let Some(entry) = parser.next_entry().unwrap() {
                let snap = match entry {
                    Entry::Help => {
                        let (n, t) = parser.help();
                        (
                            entry,
                            format!("{}:{}", lossy(n), lossy(&t)),
                            None,
                            None,
                            Vec::new(),
                            None,
                        )
                    }
                    Entry::Unit => {
                        let (n, u) = parser.unit();
                        (
                            entry,
                            format!("{}:{}", lossy(n), lossy(u)),
                            None,
                            None,
                            Vec::new(),
                            None,
                        )
                    }
                    Entry::Type => {
                        let (n, mt) = parser.metric_type();
                        (entry, lossy(n), Some(mt), None, Vec::new(), None)
                    }
                    Entry::Series => {
                        let (s, ts, val) = parser.series();
                        let s = lossy(s);
                        let st = parser.start_timestamp();
                        parser.labels(&mut buf);
                        let labels = buf
                            .iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect();
                        let ex = parser.exemplar(&mut ex_buf).map(|(ev, ets)| {
                            let elabels = ex_buf
                                .iter()
                                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                                .collect();
                            (ev.to_bits(), ets, elabels)
                        });
                        (entry, s, None, Some((ts, val.to_bits(), st)), labels, ex)
                    }
                    Entry::Comment => {
                        (entry, lossy(parser.comment()), None, None, Vec::new(), None)
                    }
                    Entry::Histogram => unreachable!("OpenMetrics 1.0 has no native histograms"),
                };
                out.push(snap);
            }
            out
        };

        let want = collect_direct(bytes);
        let mut state = OpenMetricsParser::new(bytes).into_state();
        let mut buf = LabelsBuffer::new();
        let mut ex_buf = LabelsBuffer::new();
        let mut got = Vec::new();
        let mut prev_pos = 0;
        let lossy = |s: &[u8]| String::from_utf8_lossy(s).into_owned();

        loop {
            let mut parser = OpenMetricsParser::from_state(bytes, state);
            assert_eq!(parser.pos(), prev_pos);
            let Some(entry) = parser.next_entry().unwrap() else {
                assert_eq!(parser.pos(), bytes.len());
                break;
            };
            let next_pos = parser.pos();
            assert!(next_pos > prev_pos, "{next_pos} <= {prev_pos}");
            prev_pos = next_pos;

            let mid_state = parser.into_state();
            let mut parser = OpenMetricsParser::from_state(bytes, mid_state);
            let snap = match entry {
                Entry::Help => {
                    let (n, t) = parser.help();
                    (
                        entry,
                        format!("{}:{}", lossy(n), lossy(&t)),
                        None,
                        None,
                        Vec::new(),
                        None,
                    )
                }
                Entry::Unit => {
                    let (n, u) = parser.unit();
                    (
                        entry,
                        format!("{}:{}", lossy(n), lossy(u)),
                        None,
                        None,
                        Vec::new(),
                        None,
                    )
                }
                Entry::Type => {
                    let (n, mt) = parser.metric_type();
                    (entry, lossy(n), Some(mt), None, Vec::new(), None)
                }
                Entry::Series => {
                    let (s, ts, val) = parser.series();
                    let s = lossy(s);
                    let st = parser.start_timestamp();
                    parser.labels(&mut buf);
                    let labels = buf
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect();
                    let ex = parser.exemplar(&mut ex_buf).map(|(ev, ets)| {
                        let elabels = ex_buf
                            .iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect();
                        (ev.to_bits(), ets, elabels)
                    });
                    (entry, s, None, Some((ts, val.to_bits(), st)), labels, ex)
                }
                Entry::Comment => (entry, lossy(parser.comment()), None, None, Vec::new(), None),
                Entry::Histogram => unreachable!("OpenMetrics 1.0 has no native histograms"),
            };
            got.push(snap);
            state = parser.into_state();
        }

        assert_eq!(got, want);
    }
}
