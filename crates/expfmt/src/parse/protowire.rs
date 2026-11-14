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

//! Zero-copy decoder for the `io.prometheus.client` messages, the Rust counterpart of Go's
//! [`MetricStreamingDecoder`](https://github.com/prometheus/prometheus/blob/v0.315.1/prompb/io/prometheus/client/decoder.go).
//!
//! [`MetricFamily::decode`] reads the family fields and records where each metric is, and
//! [`Metric::decode`] decodes one metric when the parser reaches it. Strings are UTF-8 checked
//! slices of the input, and every repeated field goes into a buffer that is cleared, not
//! freed, so a parser that reuses one [`Metric`] does not allocate per metric once the
//! buffers have grown.
//!
//! Decoding follows prost and Go's gogo-protobuf: known fields with the wrong wire type are
//! errors, unknown fields are skipped, a repeated scalar field may be packed or not, and a
//! message field that occurs more than once is merged.

use super::{ParseError, Span};

type Result<T> = std::result::Result<T, ParseError>;

/// prost's recursion limit, which bounds nested groups in skipped fields.
const RECURSION_LIMIT: u32 = 100;

fn invalid(message: impl Into<String>) -> ParseError {
    ParseError::InvalidProtobuf(message.into())
}

/// Decodes the varint length prefix at the start of `buf`. Returns the prefix length in
/// bytes and the decoded length.
pub(super) fn length_prefix(buf: &[u8]) -> Result<(usize, u64)> {
    let mut reader = Reader { buf };
    let length = reader.varint()?;
    Ok((buf.len() - reader.buf.len(), length))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireType {
    Varint,
    Fixed64,
    Len,
    StartGroup,
    EndGroup,
    Fixed32,
}

/// Cursor over the fields of one encoded message.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Returns the next field number and wire type, or `None` at the end of the message.
    fn field(&mut self) -> Result<Option<(u32, WireType)>> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let key = self.varint()?;
        let key = u32::try_from(key).map_err(|_| invalid(format!("invalid key value: {key}")))?;
        let wire_type = match key & 7 {
            0 => WireType::Varint,
            1 => WireType::Fixed64,
            2 => WireType::Len,
            3 => WireType::StartGroup,
            4 => WireType::EndGroup,
            5 => WireType::Fixed32,
            other => return Err(invalid(format!("invalid wire type value: {other}"))),
        };
        let field = key >> 3;
        if field == 0 {
            return Err(invalid("invalid tag value: 0"));
        }
        Ok(Some((field, wire_type)))
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for (index, &byte) in self.buf.iter().take(10).enumerate() {
            // The tenth byte holds the last bit of a u64.
            if index == 9 && byte > 1 {
                break;
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte < 0x80 {
                self.buf = &self.buf[index + 1..];
                return Ok(value);
            }
        }
        Err(invalid("invalid varint"))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if length > self.buf.len() {
            return Err(invalid("buffer underflow"));
        }
        let (head, tail) = self.buf.split_at(length);
        self.buf = tail;
        Ok(head)
    }

    fn fixed64(&mut self) -> Result<f64> {
        let bytes = self.take(8)?;
        Ok(f64::from_le_bytes(bytes.try_into().expect("took 8 bytes")))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = self.varint()?;
        let length = usize::try_from(length).map_err(|_| invalid("buffer underflow"))?;
        self.take(length)
    }

    fn skip(&mut self, field: u32, wire_type: WireType, depth: u32) -> Result<()> {
        match wire_type {
            WireType::Varint => {
                self.varint()?;
            }
            WireType::Fixed64 => {
                self.take(8)?;
            }
            WireType::Fixed32 => {
                self.take(4)?;
            }
            WireType::Len => {
                self.bytes()?;
            }
            WireType::StartGroup => {
                if depth >= RECURSION_LIMIT {
                    return Err(invalid("recursion limit reached"));
                }
                loop {
                    match self.field()? {
                        None => return Err(invalid("unexpected end of group")),
                        Some((end, WireType::EndGroup)) if end == field => return Ok(()),
                        Some((_, WireType::EndGroup)) => {
                            return Err(invalid("unexpected end group tag"));
                        }
                        Some((inner, wire_type)) => self.skip(inner, wire_type, depth + 1)?,
                    }
                }
            }
            WireType::EndGroup => return Err(invalid("unexpected end group tag")),
        }
        Ok(())
    }

    fn skip_field(&mut self, field: u32, wire_type: WireType) -> Result<()> {
        self.skip(field, wire_type, 0)
    }

    fn check(wire_type: WireType, expected: WireType) -> Result<()> {
        if wire_type == expected {
            return Ok(());
        }
        Err(invalid(format!(
            "invalid wire type: {wire_type:?} (expected {expected:?})"
        )))
    }

    fn read_varint(&mut self, wire_type: WireType) -> Result<u64> {
        Self::check(wire_type, WireType::Varint)?;
        self.varint()
    }

    fn read_double(&mut self, wire_type: WireType) -> Result<f64> {
        Self::check(wire_type, WireType::Fixed64)?;
        self.fixed64()
    }

    fn read_message(&mut self, wire_type: WireType) -> Result<&'a [u8]> {
        Self::check(wire_type, WireType::Len)?;
        self.bytes()
    }

    fn read_str(&mut self, wire_type: WireType) -> Result<&'a str> {
        let bytes = self.read_message(wire_type)?;
        std::str::from_utf8(bytes)
            .map_err(|_| invalid("invalid string value: data is not UTF-8 encoded"))
    }

    // Integer conversions truncate like prost and Go's generated code.
    fn read_i64(&mut self, wire_type: WireType) -> Result<i64> {
        Ok(self.read_varint(wire_type)? as i64)
    }

    fn read_i32(&mut self, wire_type: WireType) -> Result<i32> {
        Ok(self.read_varint(wire_type)? as i32)
    }

    fn read_u32(&mut self, wire_type: WireType) -> Result<u32> {
        Ok(self.read_varint(wire_type)? as u32)
    }

    fn read_sint32(&mut self, wire_type: WireType) -> Result<i32> {
        let value = self.read_varint(wire_type)? as u32;
        Ok((value >> 1) as i32 ^ -((value & 1) as i32))
    }

    /// Appends a packed or unpacked `repeated sint64` field to `out`.
    fn read_sint64s(&mut self, wire_type: WireType, out: &mut Vec<i64>) -> Result<()> {
        let zigzag = |value: u64| (value >> 1) as i64 ^ -((value & 1) as i64);
        if wire_type == WireType::Len {
            let mut packed = Reader::new(self.bytes()?);
            while !packed.buf.is_empty() {
                out.push(zigzag(packed.varint()?));
            }
            return Ok(());
        }
        out.push(zigzag(self.read_varint(wire_type)?));
        Ok(())
    }

    /// Appends a packed or unpacked `repeated double` field to `out`.
    fn read_doubles(&mut self, wire_type: WireType, out: &mut Vec<f64>) -> Result<()> {
        if wire_type == WireType::Len {
            let mut packed = Reader::new(self.bytes()?);
            while !packed.buf.is_empty() {
                out.push(packed.fixed64()?);
            }
            return Ok(());
        }
        out.push(self.read_double(wire_type)?);
        Ok(())
    }
}

/// `MetricFamily` without its metrics, which stay encoded until [`Metric::decode`].
#[derive(Debug, Default)]
pub(super) struct MetricFamily<'a> {
    pub(super) name: &'a str,
    pub(super) help: &'a str,
    pub(super) r#type: i32,
    pub(super) unit: &'a str,
    /// Encoded `Metric` messages, in input order.
    pub(super) metrics: Vec<&'a [u8]>,
}

impl<'a> MetricFamily<'a> {
    /// Replaces `self` with the family encoded in `buf`.
    pub(super) fn decode(&mut self, buf: &'a [u8]) -> Result<()> {
        self.name = "";
        self.help = "";
        self.r#type = 0;
        self.unit = "";
        self.metrics.clear();
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => self.name = reader.read_str(wire_type)?,
                2 => self.help = reader.read_str(wire_type)?,
                3 => self.r#type = reader.read_i32(wire_type)?,
                4 => self.metrics.push(reader.read_message(wire_type)?),
                5 => self.unit = reader.read_str(wire_type)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }
}

/// `google.protobuf.Timestamp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Timestamp {
    pub(super) seconds: i64,
    pub(super) nanos: i32,
}

impl Timestamp {
    /// Same as Go: seconds and nanoseconds to ms, without validation.
    pub(super) fn millis(self) -> i64 {
        self.seconds
            .wrapping_mul(1000)
            .wrapping_add(i64::from(self.nanos / 1_000_000))
    }

    fn merge(slot: &mut Option<Self>, buf: &[u8]) -> Result<()> {
        let timestamp = slot.get_or_insert_with(Self::default);
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => timestamp.seconds = reader.read_i64(wire_type)?,
                2 => timestamp.nanos = reader.read_i32(wire_type)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }
}

/// `Exemplar`, with its labels in `Metric::exemplar_labels[labels_start..labels_end]`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Exemplar {
    pub(super) labels_start: usize,
    pub(super) labels_end: usize,
    pub(super) value: f64,
    pub(super) timestamp: Option<Timestamp>,
}

impl Exemplar {
    fn merge<'a>(
        slot: &mut Option<Self>,
        labels: &mut Vec<(&'a str, &'a str)>,
        buf: &'a [u8],
    ) -> Result<()> {
        let exemplar = slot.get_or_insert_with(|| Self {
            labels_start: labels.len(),
            labels_end: labels.len(),
            ..Self::default()
        });
        if exemplar.labels_end != labels.len() {
            // A repeated exemplar field after other exemplars: move its labels to the end,
            // so the merged labels stay contiguous.
            let start = labels.len();
            labels.extend_from_within(exemplar.labels_start..exemplar.labels_end);
            exemplar.labels_start = start;
            exemplar.labels_end = labels.len();
        }
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => {
                    labels.push(label_pair(reader.read_message(wire_type)?)?);
                    exemplar.labels_end = labels.len();
                }
                2 => exemplar.value = reader.read_double(wire_type)?,
                3 => Timestamp::merge(&mut exemplar.timestamp, reader.read_message(wire_type)?)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }
}

fn label_pair(buf: &[u8]) -> Result<(&str, &str)> {
    let (mut name, mut value) = ("", "");
    let mut reader = Reader::new(buf);
    while let Some((field, wire_type)) = reader.field()? {
        match field {
            1 => name = reader.read_str(wire_type)?,
            2 => value = reader.read_str(wire_type)?,
            _ => reader.skip_field(field, wire_type)?,
        }
    }
    Ok((name, value))
}

/// Reads the single `double value = 1` field of `Gauge` and `Untyped` into `value`.
fn merge_value(value: &mut f64, buf: &[u8]) -> Result<()> {
    let mut reader = Reader::new(buf);
    while let Some((field, wire_type)) = reader.field()? {
        match field {
            1 => *value = reader.read_double(wire_type)?,
            _ => reader.skip_field(field, wire_type)?,
        }
    }
    Ok(())
}

/// `Counter`.
#[derive(Debug, Default)]
pub(super) struct Counter {
    pub(super) value: f64,
    pub(super) exemplar: Option<Exemplar>,
    pub(super) start_timestamp: Option<Timestamp>,
}

/// `Quantile`.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Quantile {
    pub(super) quantile: f64,
    pub(super) value: f64,
}

/// `Summary`.
#[derive(Debug, Default)]
pub(super) struct Summary {
    pub(super) sample_count: u64,
    pub(super) sample_sum: f64,
    pub(super) quantile: Vec<Quantile>,
    pub(super) start_timestamp: Option<Timestamp>,
}

impl Summary {
    fn merge(&mut self, buf: &[u8]) -> Result<()> {
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => self.sample_count = reader.read_varint(wire_type)?,
                2 => self.sample_sum = reader.read_double(wire_type)?,
                3 => {
                    let mut quantile = Quantile::default();
                    let mut inner = Reader::new(reader.read_message(wire_type)?);
                    while let Some((field, wire_type)) = inner.field()? {
                        match field {
                            1 => quantile.quantile = inner.read_double(wire_type)?,
                            2 => quantile.value = inner.read_double(wire_type)?,
                            _ => inner.skip_field(field, wire_type)?,
                        }
                    }
                    self.quantile.push(quantile);
                }
                4 => Timestamp::merge(&mut self.start_timestamp, reader.read_message(wire_type)?)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }
}

/// `Bucket` of a classic histogram.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct Bucket {
    pub(super) cumulative_count: u64,
    pub(super) cumulative_count_float: f64,
    pub(super) upper_bound: f64,
    pub(super) exemplar: Option<Exemplar>,
}

/// `Histogram`.
#[derive(Debug, Default)]
pub(super) struct Histogram {
    pub(super) sample_count: u64,
    pub(super) sample_count_float: f64,
    pub(super) sample_sum: f64,
    pub(super) bucket: Vec<Bucket>,
    pub(super) start_timestamp: Option<Timestamp>,
    pub(super) schema: i32,
    pub(super) zero_threshold: f64,
    pub(super) zero_count: u64,
    pub(super) zero_count_float: f64,
    pub(super) negative_span: Vec<Span>,
    pub(super) negative_delta: Vec<i64>,
    pub(super) negative_count: Vec<f64>,
    pub(super) positive_span: Vec<Span>,
    pub(super) positive_delta: Vec<i64>,
    pub(super) positive_count: Vec<f64>,
    pub(super) exemplars: Vec<Exemplar>,
}

impl Histogram {
    fn clear(&mut self) {
        let Self {
            sample_count,
            sample_count_float,
            sample_sum,
            bucket,
            start_timestamp,
            schema,
            zero_threshold,
            zero_count,
            zero_count_float,
            negative_span,
            negative_delta,
            negative_count,
            positive_span,
            positive_delta,
            positive_count,
            exemplars,
        } = self;
        *sample_count = 0;
        *sample_count_float = 0.0;
        *sample_sum = 0.0;
        bucket.clear();
        *start_timestamp = None;
        *schema = 0;
        *zero_threshold = 0.0;
        *zero_count = 0;
        *zero_count_float = 0.0;
        negative_span.clear();
        negative_delta.clear();
        negative_count.clear();
        positive_span.clear();
        positive_delta.clear();
        positive_count.clear();
        exemplars.clear();
    }

    fn merge<'a>(&mut self, labels: &mut Vec<(&'a str, &'a str)>, buf: &'a [u8]) -> Result<()> {
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => self.sample_count = reader.read_varint(wire_type)?,
                2 => self.sample_sum = reader.read_double(wire_type)?,
                3 => {
                    let bucket = Self::bucket(labels, reader.read_message(wire_type)?)?;
                    self.bucket.push(bucket);
                }
                4 => self.sample_count_float = reader.read_double(wire_type)?,
                5 => self.schema = reader.read_sint32(wire_type)?,
                6 => self.zero_threshold = reader.read_double(wire_type)?,
                7 => self.zero_count = reader.read_varint(wire_type)?,
                8 => self.zero_count_float = reader.read_double(wire_type)?,
                9 => self
                    .negative_span
                    .push(span(reader.read_message(wire_type)?)?),
                10 => reader.read_sint64s(wire_type, &mut self.negative_delta)?,
                11 => reader.read_doubles(wire_type, &mut self.negative_count)?,
                12 => self
                    .positive_span
                    .push(span(reader.read_message(wire_type)?)?),
                13 => reader.read_sint64s(wire_type, &mut self.positive_delta)?,
                14 => reader.read_doubles(wire_type, &mut self.positive_count)?,
                15 => Timestamp::merge(&mut self.start_timestamp, reader.read_message(wire_type)?)?,
                16 => {
                    let mut exemplar = None;
                    Exemplar::merge(&mut exemplar, labels, reader.read_message(wire_type)?)?;
                    self.exemplars.extend(exemplar);
                }
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }

    fn bucket<'a>(labels: &mut Vec<(&'a str, &'a str)>, buf: &'a [u8]) -> Result<Bucket> {
        let mut bucket = Bucket::default();
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => bucket.cumulative_count = reader.read_varint(wire_type)?,
                2 => bucket.upper_bound = reader.read_double(wire_type)?,
                3 => Exemplar::merge(
                    &mut bucket.exemplar,
                    labels,
                    reader.read_message(wire_type)?,
                )?,
                4 => bucket.cumulative_count_float = reader.read_double(wire_type)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(bucket)
    }
}

fn span(buf: &[u8]) -> Result<Span> {
    let mut span = Span::default();
    let mut reader = Reader::new(buf);
    while let Some((field, wire_type)) = reader.field()? {
        match field {
            1 => span.offset = reader.read_sint32(wire_type)?,
            2 => span.length = reader.read_u32(wire_type)?,
            _ => reader.skip_field(field, wire_type)?,
        }
    }
    Ok(span)
}

/// `Metric`. An absent `gauge`, `counter`, `summary`, `untyped` or `histogram` field decodes
/// to its default value, which the parser reads the same way as Go reads a nil message.
#[derive(Debug, Default)]
pub(super) struct Metric<'a> {
    pub(super) label: Vec<(&'a str, &'a str)>,
    pub(super) gauge: f64,
    pub(super) counter: Counter,
    pub(super) summary: Summary,
    pub(super) untyped: f64,
    pub(super) histogram: Histogram,
    pub(super) timestamp_ms: i64,
    /// Labels of every exemplar in the metric, indexed by [`Exemplar`].
    pub(super) exemplar_labels: Vec<(&'a str, &'a str)>,
}

impl<'a> Metric<'a> {
    /// Replaces `self` with the metric encoded in `buf`, keeping buffer capacity.
    pub(super) fn decode(&mut self, buf: &'a [u8]) -> Result<()> {
        self.label.clear();
        self.gauge = 0.0;
        self.counter = Counter::default();
        self.summary.sample_count = 0;
        self.summary.sample_sum = 0.0;
        self.summary.quantile.clear();
        self.summary.start_timestamp = None;
        self.untyped = 0.0;
        self.histogram.clear();
        self.timestamp_ms = 0;
        self.exemplar_labels.clear();

        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => self
                    .label
                    .push(label_pair(reader.read_message(wire_type)?)?),
                2 => merge_value(&mut self.gauge, reader.read_message(wire_type)?)?,
                3 => self.merge_counter(reader.read_message(wire_type)?)?,
                4 => self.summary.merge(reader.read_message(wire_type)?)?,
                5 => merge_value(&mut self.untyped, reader.read_message(wire_type)?)?,
                6 => self.timestamp_ms = reader.read_i64(wire_type)?,
                7 => self
                    .histogram
                    .merge(&mut self.exemplar_labels, reader.read_message(wire_type)?)?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }

    fn merge_counter(&mut self, buf: &'a [u8]) -> Result<()> {
        let counter = &mut self.counter;
        let mut reader = Reader::new(buf);
        while let Some((field, wire_type)) = reader.field()? {
            match field {
                1 => counter.value = reader.read_double(wire_type)?,
                2 => Exemplar::merge(
                    &mut counter.exemplar,
                    &mut self.exemplar_labels,
                    reader.read_message(wire_type)?,
                )?,
                3 => Timestamp::merge(
                    &mut counter.start_timestamp,
                    reader.read_message(wire_type)?,
                )?,
                _ => reader.skip_field(field, wire_type)?,
            }
        }
        Ok(())
    }

    /// Labels of `exemplar`.
    pub(super) fn exemplar_labels(&self, exemplar: &Exemplar) -> &[(&'a str, &'a str)] {
        &self.exemplar_labels[exemplar.labels_start..exemplar.labels_end]
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;
    use crate::dto;

    fn exemplar(id: &str, value: f64) -> dto::Exemplar {
        dto::Exemplar {
            label: vec![dto::LabelPair {
                name: "id".to_owned(),
                value: id.to_owned(),
            }],
            value,
            timestamp: Some(prost_types::Timestamp {
                seconds: 1,
                nanos: 2_000_000,
            }),
        }
    }

    fn assert_exemplar(metric: &Metric<'_>, got: Option<&Exemplar>, want: Option<&dto::Exemplar>) {
        let (Some(got), Some(want)) = (got, want) else {
            assert_eq!(got.is_some(), want.is_some());
            return;
        };
        let labels: Vec<_> = want
            .label
            .iter()
            .map(|label| (label.name.as_str(), label.value.as_str()))
            .collect();
        assert_eq!(metric.exemplar_labels(got), labels);
        assert_eq!(got.value.to_bits(), want.value.to_bits());
        assert_eq!(
            got.timestamp,
            want.timestamp.as_ref().map(|timestamp| Timestamp {
                seconds: timestamp.seconds,
                nanos: timestamp.nanos,
            })
        );
    }

    /// Checks every field `decode` returns against the prost-decoded `want`.
    fn assert_matches_prost(metric: &Metric<'_>, want: &dto::Metric) {
        let labels: Vec<_> = want
            .label
            .iter()
            .map(|label| (label.name.as_str(), label.value.as_str()))
            .collect();
        assert_eq!(metric.label, labels);
        assert_eq!(metric.timestamp_ms, want.timestamp_ms);
        assert_eq!(metric.gauge, want.gauge.as_ref().map_or(0.0, |g| g.value));
        assert_eq!(
            metric.untyped,
            want.untyped.as_ref().map_or(0.0, |u| u.value)
        );
        let counter = want.counter.clone().unwrap_or_default();
        assert_eq!(metric.counter.value, counter.value);
        assert_exemplar(
            metric,
            metric.counter.exemplar.as_ref(),
            counter.exemplar.as_ref(),
        );
        let summary = want.summary.clone().unwrap_or_default();
        assert_eq!(metric.summary.sample_count, summary.sample_count);
        assert_eq!(metric.summary.sample_sum, summary.sample_sum);
        let quantiles: Vec<_> = summary
            .quantile
            .iter()
            .map(|q| Quantile {
                quantile: q.quantile,
                value: q.value,
            })
            .collect();
        assert_eq!(metric.summary.quantile, quantiles);
        let histogram = want.histogram.clone().unwrap_or_default();
        let got = &metric.histogram;
        assert_eq!(got.sample_count, histogram.sample_count);
        assert_eq!(got.sample_count_float, histogram.sample_count_float);
        assert_eq!(got.schema, histogram.schema);
        assert_eq!(got.zero_count, histogram.zero_count);
        assert_eq!(got.positive_delta, histogram.positive_delta);
        assert_eq!(got.negative_delta, histogram.negative_delta);
        assert_eq!(got.positive_count, histogram.positive_count);
        assert_eq!(got.negative_count, histogram.negative_count);
        let spans = |spans: &[dto::BucketSpan]| -> Vec<Span> {
            spans
                .iter()
                .map(|s| Span {
                    offset: s.offset,
                    length: s.length,
                })
                .collect()
        };
        assert_eq!(got.positive_span, spans(&histogram.positive_span));
        assert_eq!(got.negative_span, spans(&histogram.negative_span));
        assert_eq!(got.bucket.len(), histogram.bucket.len());
        for (got_bucket, want_bucket) in got.bucket.iter().zip(&histogram.bucket) {
            assert_eq!(got_bucket.upper_bound, want_bucket.upper_bound);
            assert_eq!(got_bucket.cumulative_count, want_bucket.cumulative_count);
            assert_exemplar(
                metric,
                got_bucket.exemplar.as_ref(),
                want_bucket.exemplar.as_ref(),
            );
        }
        assert_eq!(got.exemplars.len(), histogram.exemplars.len());
        for (got_exemplar, want_exemplar) in got.exemplars.iter().zip(&histogram.exemplars) {
            assert_exemplar(metric, Some(got_exemplar), Some(want_exemplar));
        }
    }

    fn sample_metric() -> dto::Metric {
        dto::Metric {
            label: vec![
                dto::LabelPair {
                    name: "b".to_owned(),
                    value: "2".to_owned(),
                },
                dto::LabelPair {
                    name: "a".to_owned(),
                    value: "ü".to_owned(),
                },
            ],
            counter: Some(dto::Counter {
                value: 3.5,
                exemplar: Some(exemplar("c", 1.0)),
                start_timestamp: None,
            }),
            summary: Some(dto::Summary {
                sample_count: 4,
                sample_sum: 1.5,
                quantile: vec![dto::Quantile {
                    quantile: 0.5,
                    value: 7.0,
                }],
                start_timestamp: None,
            }),
            histogram: Some(dto::Histogram {
                sample_count: 9,
                schema: -3,
                zero_count: 1,
                positive_span: vec![dto::BucketSpan {
                    offset: -2,
                    length: 2,
                }],
                positive_delta: vec![-1, 4],
                negative_count: vec![1.0, 2.5],
                bucket: vec![dto::Bucket {
                    cumulative_count: 3,
                    upper_bound: 0.25,
                    exemplar: Some(exemplar("b", 0.1)),
                    ..Default::default()
                }],
                exemplars: vec![exemplar("h1", 2.0), exemplar("h2", 3.0)],
                ..Default::default()
            }),
            timestamp_ms: -7,
            ..Default::default()
        }
    }

    #[test]
    fn decodes_metric_like_prost() {
        let want = sample_metric();
        let encoded = want.encode_to_vec();
        let mut metric = Metric::default();
        metric.decode(&encoded).unwrap();
        assert_matches_prost(&metric, &want);

        // A reused metric must not keep anything from the previous one.
        let empty = dto::Metric::default().encode_to_vec();
        metric.decode(&empty).unwrap();
        assert_matches_prost(&metric, &dto::Metric::default());
    }

    #[test]
    fn merges_repeated_message_fields_like_prost() {
        // Concatenated encodings of the same message merge: scalars are replaced, repeated
        // fields appended, and message fields merged recursively.
        let first = sample_metric();
        let mut second = sample_metric();
        second.label.truncate(1);
        second.counter.as_mut().unwrap().value = 8.0;
        second.counter.as_mut().unwrap().exemplar = Some(exemplar("d", 5.0));
        let mut encoded = first.encode_to_vec();
        encoded.extend(second.encode_to_vec());

        let want = dto::Metric::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            want.counter
                .as_ref()
                .unwrap()
                .exemplar
                .as_ref()
                .unwrap()
                .label
                .len(),
            2
        );
        let mut metric = Metric::default();
        metric.decode(&encoded).unwrap();
        assert_matches_prost(&metric, &want);
    }

    #[test]
    fn reads_unpacked_repeated_fields_and_skips_unknown_fields() {
        let mut encoded = Vec::new();
        // Histogram (field 7) with unpacked positive_delta (13) and positive_count (14).
        let mut histogram = Vec::new();
        prost::encoding::sint64::encode(13, &-2, &mut histogram);
        prost::encoding::sint64::encode(13, &3, &mut histogram);
        prost::encoding::double::encode(14, &1.5, &mut histogram);
        // Unknown fields of every wire type, including a nested group.
        prost::encoding::uint64::encode(99, &1, &mut histogram);
        prost::encoding::fixed32::encode(98, &1, &mut histogram);
        prost::encoding::double::encode(97, &1.0, &mut histogram);
        prost::encoding::string::encode(96, &"x".to_owned(), &mut histogram);
        histogram.extend([0xab, 0x06, 0xb3, 0x06, 0x08, 0x01, 0xb4, 0x06, 0xac, 0x06]);
        prost::encoding::bytes::encode(7, &histogram, &mut encoded);

        let want = dto::Metric::decode(encoded.as_slice()).unwrap();
        let mut metric = Metric::default();
        metric.decode(&encoded).unwrap();
        assert_eq!(metric.histogram.positive_delta, [-2, 3]);
        assert_matches_prost(&metric, &want);
    }

    #[test]
    fn rejects_what_prost_rejects() {
        let mut bad_utf8 = Vec::new();
        prost::encoding::bytes::encode(1, &vec![0xff], &mut bad_utf8);
        let mut label = Vec::new();
        prost::encoding::bytes::encode(1, &bad_utf8, &mut label);

        let cases: [&[u8]; 7] = [
            // Truncated varint.
            &[0x30, 0x80],
            // Field number 0.
            &[0x00, 0x01],
            // Wire type 7.
            &[0x0f],
            // Length past the end.
            &[0x0a, 0x05, 0x00],
            // `timestamp_ms` with the fixed64 wire type.
            &[0x31, 0, 0, 0, 0, 0, 0, 0, 0],
            // Unmatched end group.
            &[0x0c],
            &label,
        ];
        for case in cases {
            assert!(
                dto::Metric::decode(case).is_err(),
                "prost accepts {case:x?}"
            );
            assert!(
                matches!(
                    Metric::default().decode(case),
                    Err(ParseError::InvalidProtobuf(_))
                ),
                "accepted {case:x?}"
            );
        }
    }

    #[test]
    fn decodes_family_without_metrics() {
        let family = dto::MetricFamily {
            name: "m".to_owned(),
            help: "h".to_owned(),
            r#type: dto::MetricType::Gauge as i32,
            unit: "seconds".to_owned(),
            metric: vec![sample_metric(), dto::Metric::default()],
        };
        let encoded = family.encode_to_vec();
        let mut decoded = MetricFamily::default();
        decoded.decode(&encoded).unwrap();
        assert_eq!(
            (decoded.name, decoded.help, decoded.r#type, decoded.unit),
            ("m", "h", 1, "seconds")
        );
        assert_eq!(decoded.metrics.len(), 2);
        assert_eq!(decoded.metrics[0], sample_metric().encode_to_vec());
        assert!(decoded.metrics[1].is_empty());
    }
}
