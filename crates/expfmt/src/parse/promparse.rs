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

//! Prometheus text format 0.0.4 parser, a port of
//! [`promparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promparse.go).

use std::borrow::Cow;
use std::ops::Index;

use super::float::{
    FloatBuf, common_openmetrics_float, format_openmetrics_float, parse_go_float,
    parse_go_float_no_underscore,
};
use super::promlex::{Lexer, LexerState, Token};
use super::{
    BUCKET_LABEL, Entry, LabelsBuffer, METRIC_NAME_LABEL, MetricType, ParseError, Parser,
    QUANTILE_LABEL,
};

/// Go's `value.NormalNaN`, the canonical NaN bit pattern Prometheus stores.
const NORMAL_NAN: u64 = 0x7ff8_0000_0000_0001;

/// Byte offsets `[start, end)` of a slice in the parser's input buffer.
///
/// Storing lifetime-free byte spans allows parser state to be held across suspension points
/// alongside an owned `Bytes` buffer without self-referential lifetimes under
/// `#![forbid(unsafe_code)]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ByteSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl ByteSpan {
    #[inline]
    pub(crate) const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

impl Index<ByteSpan> for [u8] {
    type Output = [u8];

    #[inline]
    fn index(&self, span: ByteSpan) -> &[u8] {
        &self[span.start..span.end]
    }
}

/// Byte offsets of a UTF-8 validated `(label_name, label_value)` pair in the input slice.
///
/// Storing lifetime-free byte spans allows `ArrowDecoder` to reuse the parser's label capacity
/// across scrapes with different input lifetimes under `#![forbid(unsafe_code)]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LabelSpan {
    pub(crate) name_start: usize,
    pub(crate) name_end: usize,
    pub(crate) val_start: usize,
    pub(crate) val_end: usize,
}

/// Lifetime-free state of [`PromParser`] that can be stored across suspension points alongside an
/// owned input buffer without self-referential lifetimes.
#[derive(Default)]
pub(crate) struct PromParserState {
    lexer: LexerState,
    series: ByteSpan,
    text: ByteSpan,
    last_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    line_start: usize,
    name: Option<ByteSpan>,
    pub(crate) labels: Vec<LabelSpan>,
}

impl PromParserState {
    pub(crate) fn with_capacity(label_cap: usize) -> Self {
        Self {
            labels: Vec::with_capacity(label_cap),
            ..Self::default()
        }
    }

    /// Resets cursor state for a new scrape while preserving `labels` capacity in place.
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.lexer = LexerState::default();
        self.series = ByteSpan::default();
        self.text = ByteSpan::default();
        self.last_type = MetricType::Unknown;
        self.value = 0.0;
        self.timestamp = None;
        self.line_start = 0;
        self.name = None;
        self.labels.clear();
    }

    pub(crate) fn retained_memory_bytes(&self) -> usize {
        self.labels.capacity() * size_of::<LabelSpan>()
    }
}

/// Zero-copy parser for the Prometheus text exposition format 0.0.4.
///
/// Mirrors Go's `textparse.NewPromParser` with type and unit labels disabled.
pub struct PromParser<'a> {
    lexer: Lexer<'a>,
    series: ByteSpan,
    text: ByteSpan,
    /// The type from the last `# TYPE` line, which Go keeps across metric families.
    last_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    line_start: usize,
    name: Option<ByteSpan>,
    /// Escaped label names and values, without quotes, already checked to be UTF-8.
    labels: Vec<LabelSpan>,
}

impl<'a> PromParser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self::with_scratch(input, Vec::new())
    }

    /// Creates a parser over `input` reusing a caller-owned `labels` span buffer.
    #[inline]
    pub(crate) fn with_scratch(input: &'a [u8], mut labels: Vec<LabelSpan>) -> Self {
        labels.clear();
        Self {
            lexer: Lexer::new(input),
            series: ByteSpan::default(),
            text: ByteSpan::default(),
            last_type: MetricType::Unknown,
            value: 0.0,
            timestamp: None,
            line_start: 0,
            name: None,
            labels,
        }
    }

    /// Detaches the borrowed `input` slice and returns the lifetime-free parser state.
    #[inline]
    pub(crate) fn into_state(self) -> PromParserState {
        PromParserState {
            lexer: self.lexer.into_state(),
            series: self.series,
            text: self.text,
            last_type: self.last_type,
            value: self.value,
            timestamp: self.timestamp,
            line_start: self.line_start,
            name: self.name,
            labels: self.labels,
        }
    }

    /// Reconstructs a parser over `input` from a previously detached [`PromParserState`].
    #[inline]
    pub(crate) fn from_state(input: &'a [u8], state: PromParserState) -> Self {
        Self {
            lexer: Lexer::from_state(input, state.lexer),
            series: state.series,
            text: state.text,
            last_type: state.last_type,
            value: state.value,
            timestamp: state.timestamp,
            line_start: state.line_start,
            name: state.name,
            labels: state.labels,
        }
    }

    /// Takes the reusable label span buffer in place for `Drop` handlers.
    #[inline]
    pub(crate) fn take_scratch(&mut self) -> Vec<LabelSpan> {
        self.labels.clear();
        std::mem::take(&mut self.labels)
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

    /// Returns the raw metric name and raw (escaped) help text for `Entry::Help` without
    /// allocating a `Cow::Owned` buffer.
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

    #[inline]
    fn next_token(&mut self) -> Token {
        loop {
            let token = self.lexer.lex();
            if token != Token::Whitespace {
                return token;
            }
        }
    }

    fn unexpected(&self, expected: &'static str) -> ParseError {
        ParseError::UnexpectedToken {
            expected,
            offset: self.lexer.token_start,
        }
    }

    fn parse_metadata(&mut self, kind: Token) -> Result<Entry, ParseError> {
        if self.next_token() != Token::MName {
            return Err(self.unexpected("expected metric name"));
        }
        let (mut start, mut end) = (self.lexer.token_start, self.lexer.pos);
        if self.lexer.input[start] == b'"' && self.lexer.input[end - 1] == b'"' {
            start += 1;
            end -= 1;
        }
        self.name = Some(ByteSpan::new(start, end));
        if self.next_token() != Token::Text {
            return Err(self.unexpected("expected text"));
        }
        let text_span = self.lexer.token_span();
        self.text = ByteSpan::new(
            text_span.start.saturating_add(1).min(text_span.end),
            text_span.end,
        );
        let text = &self.lexer.input[self.text];
        let entry = if kind == Token::Type {
            self.last_type = parse_metric_type(text)?;
            Entry::Type
        } else {
            if std::str::from_utf8(text).is_err() {
                return Err(ParseError::InvalidUtf8 {
                    offset: self.lexer.token_start,
                });
            }
            Entry::Help
        };
        if self.next_token() != Token::Linebreak {
            return Err(self.unexpected("expected linebreak after metadata"));
        }
        Ok(entry)
    }

    fn parse_comment(&mut self) -> Result<Entry, ParseError> {
        self.text = self.lexer.token_span();
        if self.next_token() != Token::Linebreak {
            return Err(self.unexpected("expected linebreak after comment"));
        }
        Ok(Entry::Comment)
    }

    /// Parses a sample line that starts with a metric name or with `{`.
    fn parse_series(&mut self, first: Token) -> Result<Entry, ParseError> {
        let mut token = first;
        if first == Token::MName {
            // Go uses the line start, so leading blanks become part of the name.
            self.series = self.consumed_line_span();
            self.name = Some(self.series);
            token = self.next_token();
        }
        if token == Token::BraceOpen {
            self.parse_label_values()?;
            self.series = self.consumed_line_span();
            token = self.next_token();
        }
        self.parse_metric_suffix(token)
    }

    /// Returns the byte span of the current line that the lexer has consumed so far.
    #[inline]
    fn consumed_line_span(&self) -> ByteSpan {
        ByteSpan::new(self.line_start, self.lexer.pos)
    }

    fn parse_label_values(&mut self) -> Result<(), ParseError> {
        let mut token = self.next_token();
        loop {
            let quoted = match token {
                Token::BraceClose => return Ok(()),
                Token::LName => false,
                Token::QString => true,
                _ => return Err(self.unexpected("expected label name")),
            };
            let (name_start, name_end) = self.validated_token_span(quoted)?;
            token = self.next_token();
            if quoted && matches!(token, Token::Comma | Token::BraceClose) {
                if self.name.is_some() {
                    return Err(ParseError::InvalidMetricName {
                        offset: self.line_start,
                    });
                }
                self.name = Some(ByteSpan::new(name_start, name_end));
                if token == Token::BraceClose {
                    return Ok(());
                }
                token = self.next_token();
                continue;
            }
            if token != Token::Equal {
                return Err(self.unexpected("expected equal"));
            }
            if self.next_token() != Token::LValue {
                return Err(self.unexpected("expected label value"));
            }
            let (val_start, val_end) = self.validated_token_span(true)?;
            self.labels.push(LabelSpan {
                name_start,
                name_end,
                val_start,
                val_end,
            });
            token = self.next_token();
            if token == Token::Comma {
                token = self.next_token();
            }
        }
    }

    /// Validates that the current token is UTF-8 and returns its unquoted `(start, end)` offsets.
    #[inline]
    fn validated_token_span(&self, quoted: bool) -> Result<(usize, usize), ParseError> {
        let end = self.lexer.input.len();
        let mut start = self.lexer.token_start.min(end);
        let mut stop = self.lexer.pos.min(end);
        if quoted {
            start += 1;
            stop -= 1;
            let raw = &self.lexer.input[start..stop];
            // Unquoted `LName` tokens only contain `[a-zA-Z0-9_]`, so only quoted strings can
            // carry non-ASCII bytes that require UTF-8 validation.
            if !raw.is_ascii() && std::str::from_utf8(raw).is_err() {
                return Err(ParseError::InvalidUtf8 {
                    offset: self.lexer.token_start,
                });
            }
        }
        Ok((start, stop))
    }

    fn parse_metric_suffix(&mut self, token: Token) -> Result<Entry, ParseError> {
        if self.name.is_none() {
            return Err(ParseError::InvalidMetricName {
                offset: self.line_start,
            });
        }
        if token != Token::Value {
            return Err(self.unexpected("expected value after metric"));
        }
        let raw = self.lexer.token();
        let value = parse_sample_value(raw)
            .ok_or_else(|| ParseError::InvalidValue(String::from_utf8_lossy(raw).into_owned()))?;
        self.value = if value.is_nan() {
            f64::from_bits(NORMAL_NAN)
        } else {
            value
        };
        self.timestamp = None;
        match self.next_token() {
            Token::Linebreak => {}
            Token::Timestamp => {
                let raw = self.lexer.token();
                let timestamp = parse_timestamp_i64(raw).ok_or_else(|| {
                    ParseError::InvalidTimestamp(String::from_utf8_lossy(raw).into_owned())
                })?;
                self.timestamp = Some(timestamp);
                if self.next_token() != Token::Linebreak {
                    return Err(self.unexpected("expected linebreak after timestamp"));
                }
            }
            _ => return Err(self.unexpected("expected timestamp or linebreak")),
        }
        Ok(Entry::Series)
    }

    #[inline]
    fn metric_name(&self) -> &'a [u8] {
        self.name.map_or(b"", |span| &self.lexer.input[span])
    }
}

impl<'a> Parser<'a> for PromParser<'a> {
    #[inline]
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        loop {
            self.line_start = self.lexer.pos;
            self.name = None;
            self.labels.clear();
            let entry = match self.next_token() {
                Token::Eof => return Ok(None),
                Token::Linebreak => continue,
                kind @ (Token::Help | Token::Type) => self.parse_metadata(kind),
                Token::Comment => self.parse_comment(),
                first @ (Token::BraceOpen | Token::MName) => self.parse_series(first),
                _ => Err(self.unexpected("expected a valid start token")),
            };
            return entry.map(Some);
        }
    }

    #[inline]
    fn pos(&self) -> usize {
        PromParser::pos(self)
    }

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>) {
        (
            self.metric_name(),
            unescape(&self.lexer.input[self.text], false),
        )
    }

    #[inline]
    fn metric_type(&self) -> (&'a [u8], MetricType) {
        (self.metric_name(), self.last_type)
    }

    fn comment(&self) -> &'a [u8] {
        &self.lexer.input[self.text]
    }

    fn series(&self) -> (&'a [u8], Option<i64>, f64) {
        (&self.lexer.input[self.series], self.timestamp, self.value)
    }

    fn labels(&self, buf: &mut LabelsBuffer<'a>) {
        buf.clear();
        // next_entry() already checked that a series name is UTF-8.
        let name = std::str::from_utf8(self.metric_name()).unwrap_or_default();
        buf.push(Cow::Borrowed(METRIC_NAME_LABEL), unescape_label(name));
        let input = self.lexer.input;
        for span in &self.labels {
            let raw_name =
                std::str::from_utf8(&input[span.name_start..span.name_end]).unwrap_or_default();
            let raw_val =
                std::str::from_utf8(&input[span.val_start..span.val_end]).unwrap_or_default();
            let name = unescape_label(raw_name);
            let value = normalize_float_label(self.last_type, &name, unescape_label(raw_val));
            buf.push(name, value);
        }
        buf.sort();
    }
}

/// Go's `normalizeFloatsInLabelValues`: `le` on histograms and `quantile` on summaries
/// use OpenMetrics float formatting. Keeps `value` borrowed when it is already canonical.
fn normalize_float_label<'v>(
    metric_type: MetricType,
    name: &str,
    value: Cow<'v, str>,
) -> Cow<'v, str> {
    let is_float_label = match metric_type {
        MetricType::Histogram => name == BUCKET_LABEL,
        MetricType::Summary => name == QUANTILE_LABEL,
        _ => false,
    };
    // NOTE: Go's ParseFloat also accepts hex floats here (le="0x1p3"); we leave them as is.
    let Some(parsed) = is_float_label.then(|| parse_go_float(&value)).flatten() else {
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

/// Maps a `# TYPE` value to a [`MetricType`]. Prometheus text spells the unknown type `untyped`.
fn parse_metric_type(text: &[u8]) -> Result<MetricType, ParseError> {
    match text {
        b"untyped" => Ok(MetricType::Unknown),
        b"counter" => Ok(MetricType::Counter),
        b"gauge" => Ok(MetricType::Gauge),
        b"histogram" => Ok(MetricType::Histogram),
        b"summary" => Ok(MetricType::Summary),
        _ => Err(ParseError::InvalidMetricType(
            String::from_utf8_lossy(text).into_owned(),
        )),
    }
}

/// Unescapes `\\`, `\n`, and, when `quote` is `true`, `\"` into `scratch` without allocating
/// once `scratch` has sufficient capacity. Returns `raw` directly when no backslash is present.
#[inline]
pub(crate) fn unescape_bytes_into<'c>(
    raw: &'c [u8],
    quote: bool,
    scratch: &'c mut Vec<u8>,
) -> &'c [u8] {
    let Some(first_slash) = raw.iter().position(|&b| b == b'\\') else {
        return raw;
    };
    scratch.clear();
    unescape_from_slash(raw, first_slash, quote, scratch);
    scratch.as_slice()
}

fn unescape_from_slash(raw: &[u8], first_slash: usize, quote: bool, out: &mut Vec<u8>) {
    out.reserve(raw.len());
    out.extend_from_slice(&raw[..first_slash]);

    let mut i = first_slash;
    let mut plain_start = first_slash;
    while i < raw.len() {
        if raw[i] == b'\\' {
            let replaced = match raw.get(i + 1) {
                Some(b'\\') => Some(b'\\'),
                Some(b'n') => Some(b'\n'),
                Some(b'"') if quote => Some(b'"'),
                _ => None,
            };
            if let Some(ch) = replaced {
                out.extend_from_slice(&raw[plain_start..i]);
                out.push(ch);
                i += 2;
                plain_start = i;
                continue;
            }
        }
        i += 1;
    }
    out.extend_from_slice(&raw[plain_start..]);
}

/// Go's `strings.Replacer` for `\\` and `\n`, plus `\"` when `quote` is set.
fn unescape(raw: &[u8], quote: bool) -> Cow<'_, [u8]> {
    let Some(first_slash) = raw.iter().position(|&b| b == b'\\') else {
        return Cow::Borrowed(raw);
    };
    let mut out = Vec::new();
    unescape_from_slash(raw, first_slash, quote, &mut out);
    Cow::Owned(out)
}

fn unescape_label(raw: &str) -> Cow<'_, str> {
    match unescape(raw.as_bytes(), true) {
        Cow::Borrowed(_) => Cow::Borrowed(raw),
        // Replacing ASCII escapes keeps valid UTF-8 valid, so nothing is lost here.
        Cow::Owned(bytes) => Cow::Owned(
            String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
        ),
    }
}

/// Go's `parseFloat` in promparse.go, which rejects `pP_` before `strconv.ParseFloat`.
#[inline]
fn parse_sample_value(raw: &[u8]) -> Option<f64> {
    if raw.is_empty() {
        return None;
    }
    // Fast path for exact integer counters and gauges up to 15 digits (< 2^53).
    let (neg, digits) = match raw[0] {
        b'-' => (true, &raw[1..]),
        b'+' => (false, &raw[1..]),
        _ => (false, raw),
    };
    if !digits.is_empty() && digits.len() <= 15 {
        let mut acc = 0u64;
        let mut all_digits = true;
        for &b in digits {
            if b.is_ascii_digit() {
                acc = acc * 10 + u64::from(b - b'0');
            } else {
                all_digits = false;
                break;
            }
        }
        if all_digits {
            let v = acc as f64;
            return Some(if neg { -v } else { v });
        }
    }

    for &b in raw {
        if !b.is_ascii() || matches!(b, b'p' | b'P' | b'_') {
            return None;
        }
    }
    let text = std::str::from_utf8(raw).ok()?;
    parse_go_float_no_underscore(text)
}

#[inline]
fn parse_timestamp_i64(raw: &[u8]) -> Option<i64> {
    if raw.is_empty() {
        return None;
    }
    let mut acc = 0i64;
    for &b in raw {
        acc = acc.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    Some(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Got {
        Help(String, String),
        Type(String, MetricType),
        Comment(String),
        Series(String, Option<i64>, u64, Vec<(String, String)>),
    }

    fn parse(input: &[u8]) -> Result<Vec<Got>, ParseError> {
        let mut parser = PromParser::new(input);
        let mut buf = LabelsBuffer::new();
        let mut out = Vec::new();
        let lossy = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        while let Some(entry) = parser.next_entry()? {
            out.push(match entry {
                Entry::Help => {
                    let (name, text) = parser.help();
                    Got::Help(lossy(name), lossy(&text))
                }
                Entry::Type => {
                    let (name, mtype) = parser.metric_type();
                    Got::Type(lossy(name), mtype)
                }
                Entry::Comment => Got::Comment(lossy(parser.comment())),
                _ => {
                    let (series, ts, val) = parser.series();
                    parser.labels(&mut buf);
                    let labels = buf
                        .iter()
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .collect();
                    Got::Series(lossy(series), ts, val.to_bits(), labels)
                }
            });
        }
        Ok(out)
    }

    fn series(raw: &str, ts: Option<i64>, val: f64, labels: &[(&str, &str)]) -> Got {
        let labels = labels
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        Got::Series(raw.to_owned(), ts, val.to_bits(), labels)
    }

    fn help(name: &str, text: &str) -> Got {
        Got::Help(name.to_owned(), text.to_owned())
    }

    #[test]
    fn parses_upstream_edge_cases() {
        let input = concat!(
            "# \tTYPE s summary\n",
            "s{quantile=\"0\"} 1\n",
            "s{ quantile = \"1\" a = \"b\", } 2 \t123\n",
            "# Hrandom\n",
            "#\n",
            "# HELP nohelp1\n",
            "# HELP nohelp2 \n",
            "# HELP h  two\\\\ \\n \\\" x\n",
            "# TYPE h histogram\n",
            "h{le=\"10\",l=\"a\\\"\\\\\\n\\x\"}\t-Inf\n",
            "h{le=\"1e6\"} NaN\n",
            "h{le=\"bogus\"} 1\n",
            "# TYPE u untyped\n",
            "u{quantile=\"0\"} +Inf",
        );
        let nan = f64::from_bits(NORMAL_NAN);
        let want = vec![
            Got::Type("s".into(), MetricType::Summary),
            series(
                "s{quantile=\"0\"}",
                None,
                1.0,
                &[("__name__", "s"), ("quantile", "0.0")],
            ),
            series(
                "s{ quantile = \"1\" a = \"b\", }",
                Some(123),
                2.0,
                &[("__name__", "s"), ("a", "b"), ("quantile", "1.0")],
            ),
            Got::Comment("# Hrandom".into()),
            Got::Comment("#".into()),
            help("nohelp1", ""),
            help("nohelp2", ""),
            help("h", " two\\ \n \\\" x"),
            Got::Type("h".into(), MetricType::Histogram),
            series(
                "h{le=\"10\",l=\"a\\\"\\\\\\n\\x\"}",
                None,
                f64::NEG_INFINITY,
                &[("__name__", "h"), ("l", "a\"\\\n\\x"), ("le", "10.0")],
            ),
            series(
                "h{le=\"1e6\"}",
                None,
                nan,
                &[("__name__", "h"), ("le", "1e+06")],
            ),
            series(
                "h{le=\"bogus\"}",
                None,
                1.0,
                &[("__name__", "h"), ("le", "bogus")],
            ),
            Got::Type("u".into(), MetricType::Unknown),
            series(
                "u{quantile=\"0\"}",
                None,
                f64::INFINITY,
                &[("__name__", "u"), ("quantile", "0")],
            ),
        ];
        assert_eq!(parse(input.as_bytes()).unwrap(), want);
    }

    #[test]
    fn parses_quoted_utf8_names_and_null_bytes() {
        let input = concat!(
            "# HELP \"go.gc\" doc\n",
            "{\"go.gc\",quantile=\"0.25\",} 7\n",
            "{\"go.gc\"} 8\n",
            "{ \"a\\\"b\\\\c\\nd\", \"strange©\\n\"=\"6\" } 10.0\n",
            "# HELP metric foo\0bar\n",
            "# c\0mment\n",
            "null_byte_metric{a=\"abc\0\"} 1\n",
            "\0this is EOF\n",
        );
        let want = vec![
            help("go.gc", "doc"),
            series(
                "{\"go.gc\",quantile=\"0.25\",}",
                None,
                7.0,
                &[("__name__", "go.gc"), ("quantile", "0.25")],
            ),
            series("{\"go.gc\"}", None, 8.0, &[("__name__", "go.gc")]),
            series(
                "{ \"a\\\"b\\\\c\\nd\", \"strange©\\n\"=\"6\" }",
                None,
                10.0,
                &[("__name__", "a\"b\\c\nd"), ("strange©\n", "6")],
            ),
            help("metric", "foo\0bar"),
            Got::Comment("# c\0mment".into()),
            series(
                "null_byte_metric{a=\"abc\0\"}",
                None,
                1.0,
                &[("__name__", "null_byte_metric"), ("a", "abc\0")],
            ),
        ];
        assert_eq!(parse(input.as_bytes()).unwrap(), want);
    }

    #[test]
    fn rejects_upstream_error_cases() {
        let inputs: &[&[u8]] = &[
            b"a",
            b"a{b='c'} 1\n",
            b"a{b=\n",
            b"a{\xff=\"foo\"} 1\n",
            b"a{b=\"\xff\"} 1\n",
            b"{\"a\", \"b = \"c\"}",
            b"{\"a\",b\\nc=\"d\"} 1",
            b"a true\n",
            b"something_weird{problem=\"",
            b"empty_label_name{=\"\"} 0",
            b"{A}0",
            b"foo 1_2\n",
            b"foo 0x1p-3\n",
            b"foo 0x1P-3\n",
            b"foo 0 1_2\n",
            b"{a=\"ok\"} 1",
            b"a{\"b\"} 1",
            b"{\"a\",\"b\"} 1",
            b"# TYPE #\n#EOF\n",
            b"# HELP #\n#EOF\n",
            b"# TYPE a bogus\n",
            b"# HELP a \xff\n",
            b"a 1 99999999999999999999\n",
            b"a 1e400\n",
            b"a{b=\0\"ssss\"} 1\n",
            b"a{b=\"\0",
            b"a{b\0=\"hiih\"}\t1",
            b"a\0{b=\"ddd\"} 1",
            b"a 0 1\0",
        ];
        assert!(PromParser::new(b"{\"\xff\"} 1\n").next_entry().is_err());
        for input in inputs {
            assert!(
                parse(input).is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn sample_value_rejects_underscores() {
        assert_eq!(parse_sample_value(b"1_000"), None);
    }

    #[test]
    fn borrowed_labels_outlive_clear() {
        let input = b"# TYPE h histogram\nh{le=\"2\"} 1\n";
        let mut parser = PromParser::new(input);
        let mut buf = LabelsBuffer::new();
        parser.next_entry().unwrap();
        parser.next_entry().unwrap();
        parser.labels(&mut buf);
        let mut kept = Vec::new();
        for (name, value) in buf.as_slice() {
            if let Cow::Borrowed(name) = name {
                kept.push(*name);
            }
            assert_eq!(matches!(value, Cow::Owned(_)), name == BUCKET_LABEL);
        }
        buf.clear();
        assert_eq!(kept, [METRIC_NAME_LABEL, BUCKET_LABEL]);
    }

    #[test]
    fn common_float_labels_do_not_allocate() {
        let cases = [
            (MetricType::Summary, QUANTILE_LABEL, "0", "0.0"),
            (MetricType::Summary, QUANTILE_LABEL, "1", "1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "1", "1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "-1", "-1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "+Inf", "+Inf"),
            (MetricType::Summary, QUANTILE_LABEL, "nan", "NaN"),
        ];
        for (metric_type, name, raw, want) in cases {
            let normalized = normalize_float_label(metric_type, name, Cow::Borrowed(raw));
            assert!(
                matches!(normalized, Cow::Borrowed(text) if text == want),
                "{raw}"
            );
        }
    }

    #[test]
    fn unescape_bytes_into_reuses_scratch() {
        let mut scratch = Vec::new();
        for (raw, want_q, want_noq) in [
            ("plain", "plain", "plain"),
            ("a\\\"\\\\\\n\\x", "a\"\\\n\\x", "a\\\"\\\n\\x"),
            ("\\\\n", "\\n", "\\n"),
            ("\\©", "\\©", "\\©"),
            ("two\\\\ \\n \\\" x", "two\\ \n \" x", "two\\ \n \\\" x"),
        ] {
            let got_q = unescape_bytes_into(raw.as_bytes(), true, &mut scratch).to_vec();
            assert_eq!(got_q, want_q.as_bytes(), "quote=true {raw:?}");
            let got_noq = unescape_bytes_into(raw.as_bytes(), false, &mut scratch).to_vec();
            assert_eq!(got_noq, want_noq.as_bytes(), "quote=false {raw:?}");
        }
    }

    #[test]
    fn pos_and_state_roundtrip_preserve_parse_results() {
        let input = concat!(
            "# HELP s A summary\n",
            "# TYPE s summary\n",
            "# comment line\n",
            "s{quantile=\"0.5\",l=\"a\\\"b\"} 42 1000\n",
            "{\"go.gc\",quantile=\"0.25\"} 7\n",
        );
        let bytes = input.as_bytes();
        let want = parse(bytes).unwrap();

        let mut state = PromParser::new(bytes).into_state();
        let mut buf = LabelsBuffer::new();
        let mut got = Vec::new();
        let mut prev_pos = 0;
        let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();

        loop {
            let mut parser = PromParser::from_state(bytes, state);
            assert_eq!(parser.pos(), prev_pos);
            let Some(entry) = parser.next_entry().unwrap() else {
                assert_eq!(parser.pos(), bytes.len());
                state = parser.into_state();
                break;
            };
            let next_pos = parser.pos();
            assert!(next_pos > prev_pos, "{next_pos} <= {prev_pos}");
            prev_pos = next_pos;

            // Round-trip state between `next_entry()` and entry inspection too.
            let mid_state = parser.into_state();
            let parser = PromParser::from_state(bytes, mid_state);
            got.push(match entry {
                Entry::Help => {
                    let (name, text) = parser.help();
                    Got::Help(lossy(name), lossy(&text))
                }
                Entry::Type => {
                    let (name, mtype) = parser.metric_type();
                    Got::Type(lossy(name), mtype)
                }
                Entry::Comment => Got::Comment(lossy(parser.comment())),
                _ => {
                    let (series, ts, val) = parser.series();
                    parser.labels(&mut buf);
                    let labels = buf
                        .iter()
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .collect();
                    Got::Series(lossy(series), ts, val.to_bits(), labels)
                }
            });
            state = parser.into_state();
        }

        assert_eq!(got, want);

        let retained = state.retained_memory_bytes();
        assert!(retained > 0);
        state.reset();
        assert_eq!(state.retained_memory_bytes(), retained);
        let mut reused = PromParser::from_state(bytes, state);
        assert_eq!(reused.pos(), 0);
        assert_eq!(reused.next_entry().unwrap(), Some(Entry::Help));
    }
}
