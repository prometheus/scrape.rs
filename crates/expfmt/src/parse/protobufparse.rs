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

//! Delimited protobuf parser, a port of
//! [`protobufparse.go`](https://github.com/prometheus/prometheus/blob/v0.315.1/model/textparse/protobufparse.go).

use std::borrow::Cow;
use std::sync::LazyLock;

use prost::Message;

use super::float::{FloatBuf, format_openmetrics_float};
use super::{
    CounterResetHint, Entry, Histogram, HistogramRef, LabelsBuffer, METRIC_NAME_LABEL, MetricType,
    ParseError, Parser, QUANTILE_LABEL, Span,
};
use crate::dto;

/// Go's `histogram.CustomBucketsSchema`.
const CUSTOM_BUCKETS_SCHEMA: i32 = -53;

/// Go's `binary.MaxVarintLen32`, the longest length prefix Go accepts.
const MAX_VARINT_LEN_32: usize = 5;

static EMPTY_METRIC: LazyLock<dto::Metric> = LazyLock::new(dto::Metric::default);
static EMPTY_DTO_HISTOGRAM: LazyLock<dto::Histogram> = LazyLock::new(dto::Histogram::default);

/// Parser for varint length-delimited `MetricFamily` messages (`FmtProtoDelim`).
///
/// Mirrors Go's `textparse.NewProtobufParser` with NHCB conversion on and type and unit labels
/// turned off. Histograms are only returned as native histograms: a histogram metric without
/// native buckets is converted to a native histogram with custom buckets (NHCB, schema -53),
/// and classic buckets are never returned as series.
pub struct ProtobufParser<'a> {
    input: &'a [u8],
    /// Offset of the next length prefix in `input`.
    pos: usize,
    family: dto::MetricFamily,
    metric_index: usize,
    next_metric_index: usize,
    /// `None` is Go's `EntryInvalid`: the next call decodes the next metric family.
    state: Option<Entry>,
    /// Go's `fieldPos`: -2 is `_count`, -1 is `_sum`, otherwise the quantile index, or the
    /// bucket index while reading native histogram exemplars from buckets.
    field_pos: isize,
    fields_done: bool,
    exemplar_pos: usize,
    exemplar_returned: bool,
    /// Metric name plus the `_count` or `_sum` suffix of the current summary series.
    series_name: String,
    /// The `quantile` label of the current summary series.
    magic_label: Option<(&'static str, FloatBuf)>,
    entry_bytes: Vec<u8>,
    /// Indexes into `label_at`, sorted by label name.
    label_order: Vec<usize>,
    int_histogram: Histogram<u64, i64>,
    float_histogram: Histogram<f64, f64>,
    is_float_histogram: bool,
    /// `(upper_bound, cumulative_count)` of the classic buckets during NHCB conversion.
    nhcb_buckets: Vec<(f64, f64)>,
}

impl<'a> ProtobufParser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            family: dto::MetricFamily::default(),
            metric_index: 0,
            next_metric_index: 0,
            state: None,
            field_pos: -2,
            fields_done: false,
            exemplar_pos: 0,
            exemplar_returned: false,
            series_name: String::new(),
            magic_label: None,
            entry_bytes: Vec::new(),
            label_order: Vec::new(),
            int_histogram: Histogram::default(),
            float_histogram: Histogram::default(),
            is_float_histogram: false,
            nhcb_buckets: Vec::new(),
        }
    }

    fn next_metric_family(&mut self) -> Result<bool, ParseError> {
        let rest = &self.input[self.pos..];
        if rest.is_empty() {
            return Ok(false);
        }
        let mut message = rest;
        let length = prost::decode_length_delimiter(&mut message)
            .map_err(|_| ParseError::InvalidProtobuf("invalid varint".to_owned()))?;
        let varint_len = rest.len() - message.len();
        if varint_len > MAX_VARINT_LEN_32 {
            return Err(ParseError::InvalidProtobuf("invalid varint".to_owned()));
        }
        let message = message.get(..length).ok_or_else(|| {
            ParseError::InvalidProtobuf(format!(
                "insufficient length of buffer, expected at least {} bytes, got {} bytes",
                length.saturating_add(varint_len),
                rest.len()
            ))
        })?;
        self.pos += varint_len + message.len();
        // TODO: decodes the whole family up front, so a malformed metric fails the family
        // before its earlier metrics are returned. A lazy decoder like Go's would fix that.
        self.family.clear();
        self.family
            .merge(message)
            .map_err(|err| ParseError::InvalidProtobuf(err.to_string()))?;
        self.next_metric_index = 0;
        Ok(true)
    }

    fn next_metric(&mut self) -> bool {
        if self.next_metric_index >= self.family.metric.len() {
            return false;
        }
        self.metric_index = self.next_metric_index;
        self.next_metric_index += 1;
        true
    }

    fn metric(&self) -> &dto::Metric {
        self.family
            .metric
            .get(self.metric_index)
            .unwrap_or(&EMPTY_METRIC)
    }

    fn dto_histogram(&self) -> &dto::Histogram {
        histogram_of(&self.family, self.metric_index).unwrap_or(&EMPTY_DTO_HISTOGRAM)
    }

    fn kind(&self) -> dto::MetricType {
        self.family.r#type()
    }

    fn is_histogram_kind(&self) -> bool {
        matches!(
            self.kind(),
            dto::MetricType::Histogram | dto::MetricType::GaugeHistogram
        )
    }

    fn timestamp(&self) -> Option<i64> {
        // Go treats 0 as unset, because gogo-protobuf has no optional fields.
        Some(self.metric().timestamp_ms).filter(|&millis| millis != 0)
    }

    /// Go's `getMagicName`.
    fn series_suffix(&self) -> &'static str {
        if self.kind() != dto::MetricType::Summary {
            return "";
        }
        match self.field_pos {
            -2 => "_count",
            -1 => "_sum",
            _ => "",
        }
    }

    /// Go's `getMagicLabel`, which also sets `fields_done`.
    fn update_magic_label(&mut self) {
        self.magic_label = self.magic_label_value().map(|(name, value)| {
            let mut formatted = FloatBuf::default();
            // A FloatBuf fits every f64.
            let _ = format_openmetrics_float(value, &mut formatted);
            (name, formatted)
        });
    }

    fn magic_label_value(&mut self) -> Option<(&'static str, f64)> {
        if self.kind() != dto::MetricType::Summary || self.field_pos < 0 {
            return None;
        }
        let pos = self.field_pos as usize;
        let quantiles = self
            .metric()
            .summary
            .as_ref()
            .map_or(&[][..], |summary| &summary.quantile);
        let (len, quantile) = (quantiles.len(), quantiles.get(pos).map(|q| q.quantile));
        self.fields_done = quantile.is_none() || pos == len - 1;
        quantile.map(|quantile| (QUANTILE_LABEL, quantile))
    }

    /// Go's `onSeriesOrHistogramUpdate`, plus the parts of Go's `Series` and `Histogram` that
    /// change parser state, so the accessors can take `&self`.
    fn update_series(&mut self) -> Result<(), ParseError> {
        if self
            .metric()
            .label
            .iter()
            .any(|label| label.name.is_empty())
        {
            return Err(ParseError::InvalidProtobuf(
                "invalid label name: empty".to_owned(),
            ));
        }
        let suffix = self.series_suffix();
        self.series_name.clear();
        self.series_name.push_str(&self.family.name);
        self.series_name.push_str(suffix);
        if self.kind() == dto::MetricType::Summary
            && self.field_pos == -1
            && self
                .metric()
                .summary
                .as_ref()
                .is_none_or(|summary| summary.quantile.is_empty())
        {
            self.fields_done = true;
        }
        self.update_magic_label();

        let mut entry_bytes = std::mem::take(&mut self.entry_bytes);
        entry_bytes.clear();
        let mut order = std::mem::take(&mut self.label_order);
        order.clear();
        order.extend(0..self.label_count());
        order.sort_by(|&left, &right| self.label_at(left).0.cmp(self.label_at(right).0));
        for (name, value) in order.iter().map(|&index| self.label_at(index)) {
            if name == METRIC_NAME_LABEL {
                entry_bytes.extend_from_slice(value.as_bytes());
                continue;
            }
            entry_bytes.push(0xff);
            entry_bytes.extend_from_slice(name.as_bytes());
            entry_bytes.push(0xff);
            entry_bytes.extend_from_slice(value.as_bytes());
        }
        self.entry_bytes = entry_bytes;
        self.label_order = order;

        if self.state == Some(Entry::Histogram) {
            self.load_histogram()?;
        }
        Ok(())
    }

    fn label_count(&self) -> usize {
        1 + self.metric().label.len() + usize::from(self.magic_label.is_some())
    }

    /// Label `index` of the current series in Go's insertion order: the metric name, the
    /// protobuf labels, then the `quantile` label.
    fn label_at(&self, index: usize) -> (&str, &str) {
        let labels = &self.metric().label;
        match index {
            0 => (METRIC_NAME_LABEL, self.series_name.as_str()),
            index if index <= labels.len() => {
                let label = &labels[index - 1];
                (label.name.as_str(), label.value.as_str())
            }
            _ => self
                .magic_label
                .as_ref()
                .map_or(("", ""), |(name, value)| (*name, value.as_str())),
        }
    }

    /// Go's `Histogram`, or Go's `convertToNHCB` for a histogram without native buckets, run
    /// when the parser reaches a histogram.
    fn load_histogram(&mut self) -> Result<(), ParseError> {
        let counter_reset_hint = if self.kind() == dto::MetricType::GaugeHistogram {
            CounterResetHint::Gauge
        } else {
            CounterResetHint::Unknown
        };
        // Not `dto_histogram()`, so the targets below can be borrowed mutably.
        let source = histogram_of(&self.family, self.metric_index).unwrap_or(&EMPTY_DTO_HISTOGRAM);
        if !is_native_histogram(source) {
            self.is_float_histogram = convert_to_nhcb(
                source,
                &mut self.nhcb_buckets,
                &mut self.int_histogram,
                &mut self.float_histogram,
                counter_reset_hint,
            )?;
            return Ok(());
        }
        let name = self.family.name.as_str();
        self.is_float_histogram = source.sample_count_float > 0.0 || source.zero_count_float > 0.0;
        if self.is_float_histogram {
            let target = &mut self.float_histogram;
            target.count = source.sample_count_float;
            target.zero_count = source.zero_count_float;
            fill_histogram(
                target,
                name,
                source,
                &source.positive_count,
                &source.negative_count,
                counter_reset_hint,
            )?;
        } else {
            let target = &mut self.int_histogram;
            target.count = source.sample_count;
            target.zero_count = source.zero_count;
            fill_histogram(
                target,
                name,
                source,
                &source.positive_delta,
                &source.negative_delta,
                counter_reset_hint,
            )?;
        }
        Ok(())
    }

    fn start_family(&mut self) -> Result<bool, ParseError> {
        self.exemplar_pos = 0;
        self.field_pos = -2;
        let family_offset = self.pos;
        if !self.next_metric_family()? {
            return Ok(false);
        }
        if self.family.metric.is_empty() {
            // Go skips empty metric families.
            return Ok(true);
        }
        if self.family.name.is_empty() {
            return Err(ParseError::InvalidMetricName {
                offset: family_offset,
            });
        }
        if dto::MetricType::try_from(self.family.r#type).is_err() {
            return Err(ParseError::InvalidMetricType(
                self.family.r#type.to_string(),
            ));
        }
        self.entry_bytes.clear();
        self.entry_bytes
            .extend_from_slice(self.family.name.as_bytes());
        self.state = Some(Entry::Help);
        Ok(true)
    }
}

impl<'a> Parser<'a> for ProtobufParser<'a> {
    fn pos(&self) -> usize {
        self.pos
    }

    /// Go's `Next`, with its recursive calls turned into loop iterations.
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        self.exemplar_returned = false;
        loop {
            match self.state {
                None => {
                    if !self.start_family()? {
                        return Ok(None);
                    }
                    if self.state.is_none() {
                        continue;
                    }
                }
                Some(Entry::Help) => {
                    self.state = Some(if self.family.unit.is_empty() {
                        Entry::Type
                    } else {
                        Entry::Unit
                    });
                }
                Some(Entry::Unit) => self.state = Some(Entry::Type),
                Some(Entry::Type) => {
                    if !self.next_metric() {
                        self.state = None;
                        continue;
                    }
                    self.state = Some(if self.is_histogram_kind() {
                        Entry::Histogram
                    } else {
                        Entry::Series
                    });
                    self.update_series()?;
                }
                Some(Entry::Series) => {
                    if self.kind() == dto::MetricType::Summary {
                        if !self.fields_done {
                            self.field_pos += 1;
                            self.update_series()?;
                            return Ok(self.state);
                        }
                        self.field_pos = -2;
                        self.fields_done = false;
                        self.exemplar_pos = 0;
                    }
                    if !self.next_metric() {
                        self.state = None;
                        continue;
                    }
                    self.update_series()?;
                }
                Some(Entry::Histogram) => {
                    // Go keeps both positions here and loses the next histogram's exemplars.
                    self.field_pos = -2;
                    self.exemplar_pos = 0;
                    if !self.next_metric() {
                        self.state = None;
                        continue;
                    }
                    self.update_series()?;
                }
                Some(Entry::Comment) => unreachable!("the protobuf parser never sets Comment"),
            }
            return Ok(self.state);
        }
    }

    fn help(&self) -> (&[u8], Cow<'_, [u8]>) {
        (
            &self.entry_bytes,
            Cow::Borrowed(self.family.help.as_bytes()),
        )
    }

    fn metric_type(&self) -> (&[u8], MetricType) {
        let metric_type = match self.kind() {
            dto::MetricType::Counter => MetricType::Counter,
            dto::MetricType::Gauge => MetricType::Gauge,
            dto::MetricType::Histogram => MetricType::Histogram,
            dto::MetricType::GaugeHistogram => MetricType::GaugeHistogram,
            dto::MetricType::Summary => MetricType::Summary,
            dto::MetricType::Untyped => MetricType::Unknown,
        };
        (&self.entry_bytes, metric_type)
    }

    fn unit(&self) -> (&[u8], &[u8]) {
        (&self.entry_bytes, self.family.unit.as_bytes())
    }

    fn comment(&self) -> &'a [u8] {
        b""
    }

    fn series(&self) -> (&[u8], Option<i64>, f64) {
        let metric = self.metric();
        let value = match self.kind() {
            dto::MetricType::Counter => {
                metric.counter.as_ref().map_or(0.0, |counter| counter.value)
            }
            dto::MetricType::Gauge => metric.gauge.as_ref().map_or(0.0, |gauge| gauge.value),
            dto::MetricType::Untyped => {
                metric.untyped.as_ref().map_or(0.0, |untyped| untyped.value)
            }
            dto::MetricType::Summary => {
                let summary = metric.summary.as_ref();
                match self.field_pos {
                    -2 => summary.map_or(0.0, |summary| summary.sample_count as f64),
                    -1 => summary.map_or(0.0, |summary| summary.sample_sum),
                    pos => summary
                        .and_then(|summary| summary.quantile.get(pos as usize))
                        .map_or(0.0, |quantile| quantile.value),
                }
            }
            // Histograms are only returned as `Entry::Histogram`.
            dto::MetricType::Histogram | dto::MetricType::GaugeHistogram => 0.0,
        };
        (&self.entry_bytes, self.timestamp(), value)
    }

    fn histogram(&self) -> (&[u8], Option<i64>, HistogramRef<'_>) {
        let histogram = if self.is_float_histogram {
            HistogramRef::Float(&self.float_histogram)
        } else {
            HistogramRef::Int(&self.int_histogram)
        };
        (&self.entry_bytes, self.timestamp(), histogram)
    }

    // TODO: copies label strings per call because they live in the decoded family, not
    // in the input. A borrowing decoder like Go's would make this zero-copy.
    fn labels(&self, buf: &mut LabelsBuffer<'a>) {
        buf.clear();
        for &index in &self.label_order {
            let (name, value) = self.label_at(index);
            buf.push(Cow::Owned(name.to_owned()), Cow::Owned(value.to_owned()));
        }
    }

    /// Go's `Exemplar`. A native histogram returns its exemplars with timestamps one per call,
    /// from the `exemplars` field or else from the classic buckets.
    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)> {
        buf.clear();
        if self.exemplar_returned && self.state == Some(Entry::Series) {
            return None;
        }
        let exemplar = match self.kind() {
            dto::MetricType::Counter => self.metric().counter.as_ref()?.exemplar.as_ref(),
            dto::MetricType::Histogram | dto::MetricType::GaugeHistogram => {
                self.histogram_exemplar()
            }
            _ => None,
        }?;
        let value = exemplar.value;
        let timestamp = exemplar.timestamp.as_ref().map(timestamp_millis);
        for label in &exemplar.label {
            buf.push(
                Cow::Owned(label.name.clone()),
                Cow::Owned(label.value.clone()),
            );
        }
        buf.sort();
        self.exemplar_returned = true;
        Some((value, timestamp))
    }

    fn start_timestamp(&mut self) -> Option<i64> {
        let metric = self.metric();
        let start = match self.kind() {
            dto::MetricType::Counter => metric.counter.as_ref()?.start_timestamp.as_ref(),
            dto::MetricType::Summary => metric.summary.as_ref()?.start_timestamp.as_ref(),
            dto::MetricType::Histogram | dto::MetricType::GaugeHistogram => {
                self.dto_histogram().start_timestamp.as_ref()
            }
            _ => None,
        };
        start.map(timestamp_millis)
    }
}

impl ProtobufParser<'_> {
    /// The native histogram branch of Go's `Exemplar`, which advances `exemplar_pos` or
    /// `field_pos`.
    fn histogram_exemplar(&mut self) -> Option<&dto::Exemplar> {
        let histogram = histogram_of(&self.family, self.metric_index)?;
        if !histogram.exemplars.is_empty() {
            // Native histograms drop exemplars without a timestamp.
            while let Some(exemplar) = histogram.exemplars.get(self.exemplar_pos) {
                self.exemplar_pos += 1;
                if exemplar.timestamp.is_some() {
                    return Some(exemplar);
                }
            }
            return None;
        }
        self.field_pos = self.field_pos.max(0);
        let mut found = None;
        while let Some(bucket) = histogram.bucket.get(self.field_pos as usize) {
            found = bucket.exemplar.as_ref();
            self.field_pos += 1;
            if found.is_some_and(|exemplar| exemplar.timestamp.is_some()) {
                break;
            }
        }
        found.filter(|exemplar| exemplar.timestamp.is_some())
    }
}

fn histogram_of(family: &dto::MetricFamily, metric_index: usize) -> Option<&dto::Histogram> {
    family.metric.get(metric_index)?.histogram.as_ref()
}

/// Go's `isNativeHistogram`.
fn is_native_histogram(histogram: &dto::Histogram) -> bool {
    !histogram.positive_span.is_empty()
        || !histogram.negative_span.is_empty()
        || histogram.zero_threshold > 0.0
        || histogram.zero_count > 0
}

/// Same as Go: seconds and nanoseconds to ms, without validation.
fn timestamp_millis(timestamp: &prost_types::Timestamp) -> i64 {
    timestamp
        .seconds
        .wrapping_mul(1000)
        .wrapping_add(i64::from(timestamp.nanos / 1_000_000))
}

/// Go's `checkProtoSpanBucketConsistency`, which keeps malformed spans out of compaction.
fn check_span_buckets(
    name: &str,
    side: &str,
    spans: &[dto::BucketSpan],
    buckets: usize,
) -> Result<(), ParseError> {
    let total: u64 = spans.iter().map(|span| u64::from(span.length)).sum();
    if total != buckets as u64 {
        return Err(ParseError::InvalidProtobuf(format!(
            "histogram {name:?}: {side} side: spans require {total} buckets, have {buckets}"
        )));
    }
    Ok(())
}

/// Checks the spans, copies the fields, then compacts like Go's `Compact(0)`.
fn fill_histogram<C, B: Bucket>(
    target: &mut Histogram<C, B>,
    name: &str,
    source: &dto::Histogram,
    positive_buckets: &[B],
    negative_buckets: &[B],
    counter_reset_hint: CounterResetHint,
) -> Result<(), ParseError> {
    check_span_buckets(
        name,
        "positive",
        &source.positive_span,
        positive_buckets.len(),
    )?;
    check_span_buckets(
        name,
        "negative",
        &source.negative_span,
        negative_buckets.len(),
    )?;
    positive_buckets.clone_into(&mut target.positive_buckets);
    negative_buckets.clone_into(&mut target.negative_buckets);
    target.custom_values.clear();
    target.counter_reset_hint = counter_reset_hint;
    target.schema = source.schema;
    target.zero_threshold = source.zero_threshold;
    target.sum = source.sample_sum;
    copy_spans(&mut target.positive_spans, &source.positive_span);
    copy_spans(&mut target.negative_spans, &source.negative_span);
    compact_buckets(&mut target.positive_buckets, &mut target.positive_spans, 0);
    compact_buckets(&mut target.negative_buckets, &mut target.negative_spans, 0);
    Ok(())
}

/// Go's `convertToNHCB` with `convertnhcb.TempHistogram`: turns the classic buckets into one
/// native histogram with custom buckets. Returns `true` for a float histogram.
fn convert_to_nhcb(
    source: &dto::Histogram,
    buckets: &mut Vec<(f64, f64)>,
    int_target: &mut Histogram<u64, i64>,
    float_target: &mut Histogram<f64, f64>,
    counter_reset_hint: CounterResetHint,
) -> Result<bool, ParseError> {
    let count = float_or_int(source.sample_count_float, source.sample_count);
    collect_nhcb_buckets(source, count, buckets)?;
    let cumulative_counts = buckets
        .iter()
        .map(|&(_, cumulative_count)| cumulative_count);
    if is_integer_histogram(count, buckets) {
        let deltas = differences(differences(cumulative_counts.map(|value| value as i64)));
        fill_nhcb(
            int_target,
            count as u64,
            source.sample_sum,
            buckets,
            deltas,
            counter_reset_hint,
            2,
        );
        return Ok(false);
    }
    let bucket_counts = differences(cumulative_counts);
    fill_nhcb(
        float_target,
        count,
        source.sample_sum,
        buckets,
        bucket_counts,
        counter_reset_hint,
        0,
    );
    Ok(true)
}

/// Go reads the float field of a count unless it is 0.
fn float_or_int(float: f64, int: u64) -> f64 {
    Some(float)
        .filter(|&float| float != 0.0)
        .unwrap_or(int as f64)
}

/// Fills `buckets` with the sorted `(upper_bound, cumulative_count)` pairs of `source`, ending
/// with a `+Inf` bucket, and checks them like Go's `TempHistogram`.
fn collect_nhcb_buckets(
    source: &dto::Histogram,
    count: f64,
    buckets: &mut Vec<(f64, f64)>,
) -> Result<(), ParseError> {
    ensure(count >= 0.0 || count.is_nan(), || {
        format!("count must be non-negative: count={count}")
    })?;
    buckets.clear();
    for bucket in &source.bucket {
        let cumulative_count = float_or_int(bucket.cumulative_count_float, bucket.cumulative_count);
        insert_nhcb_bucket(buckets, bucket.upper_bound, cumulative_count)?;
    }
    let has_infinity_bucket = buckets
        .last()
        .is_some_and(|&(upper_bound, _)| upper_bound == f64::INFINITY);
    if !has_infinity_bucket {
        buckets.push((f64::INFINITY, count));
    }
    let last_count = buckets[buckets.len() - 1].1;
    ensure(count == last_count, || {
        format!("count mismatch: count={count} != le=+Inf count={last_count}")
    })
}

/// Go's `TempHistogram.Convert` returns an integer histogram when every count is a whole number.
fn is_integer_histogram(count: f64, buckets: &[(f64, f64)]) -> bool {
    // Go's int64 conversion does not saturate on amd64, so 2^63 and above are not integers.
    let is_integer = |value: f64| value < i64::MAX as f64 && value == (value.round() as i64) as f64;
    count == (count.round() as u64) as f64
        && buckets
            .iter()
            .all(|&(_, cumulative_count)| is_integer(cumulative_count))
}

/// Each value minus the value before it, starting from zero.
fn differences<B: Bucket>(values: impl Iterator<Item = B>) -> impl Iterator<Item = B> {
    values.scan(B::ZERO, |previous, value| {
        let difference = value.sub(*previous);
        *previous = value;
        Some(difference)
    })
}

/// Fills `target` with an NHCB over `buckets`, then compacts it like Go's `Compact`.
fn fill_nhcb<C: Default, B: Bucket>(
    target: &mut Histogram<C, B>,
    count: C,
    sum: f64,
    buckets: &[(f64, f64)],
    bucket_counts: impl Iterator<Item = B>,
    counter_reset_hint: CounterResetHint,
    max_empty_buckets: usize,
) {
    target.counter_reset_hint = counter_reset_hint;
    target.schema = CUSTOM_BUCKETS_SCHEMA;
    target.zero_threshold = 0.0;
    target.zero_count = C::default();
    target.count = count;
    target.sum = sum;
    target.positive_spans.clear();
    target.positive_spans.push(Span {
        offset: 0,
        length: buckets.len() as u32,
    });
    target.positive_buckets.clear();
    target.positive_buckets.extend(bucket_counts);
    target.negative_spans.clear();
    target.negative_buckets.clear();
    // The last bucket is always +Inf, which Go does not store.
    target.custom_values.clear();
    target.custom_values.extend(
        buckets[..buckets.len() - 1]
            .iter()
            .map(|&(upper_bound, _)| upper_bound),
    );
    compact_buckets(
        &mut target.positive_buckets,
        &mut target.positive_spans,
        max_empty_buckets,
    );
}

/// Go's `TempHistogram.SetBucketCount`: keeps `buckets` sorted by upper bound and cumulative,
/// and ignores a repeated upper bound.
fn insert_nhcb_bucket(
    buckets: &mut Vec<(f64, f64)>,
    upper_bound: f64,
    cumulative_count: f64,
) -> Result<(), ParseError> {
    ensure(!upper_bound.is_nan(), || {
        "bucket boundary must not be NaN".to_owned()
    })?;
    ensure(cumulative_count >= 0.0 || cumulative_count.is_nan(), || {
        format!("bucket count must be non-negative: le={upper_bound}, count={cumulative_count}")
    })?;
    // Go's happy case: buckets usually arrive sorted, so append without a search.
    if buckets
        .last()
        .is_none_or(|&(bound, previous)| bound < upper_bound && previous <= cumulative_count)
    {
        buckets.push((upper_bound, cumulative_count));
        return Ok(());
    }
    let index = buckets.partition_point(|&(bound, _)| bound < upper_bound);
    let repeated = buckets
        .get(index)
        .is_some_and(|&(bound, _)| bound == upper_bound);
    if repeated {
        return Ok(());
    }
    check_cumulative(buckets, index, cumulative_count)?;
    buckets.insert(index, (upper_bound, cumulative_count));
    Ok(())
}

/// Checks that a bucket inserted at `index` keeps the counts cumulative.
fn check_cumulative(
    buckets: &[(f64, f64)],
    index: usize,
    cumulative_count: f64,
) -> Result<(), ParseError> {
    let previous = index
        .checked_sub(1)
        .map_or(f64::NEG_INFINITY, |previous| buckets[previous].1);
    let next = buckets.get(index).map_or(f64::INFINITY, |&(_, next)| next);
    ensure(
        !(cumulative_count < previous || cumulative_count > next),
        || {
            format!(
                "count is not cumulative: {cumulative_count} is not between {previous} and {next}"
            )
        },
    )
}

fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), ParseError> {
    condition
        .then_some(())
        .ok_or_else(|| ParseError::InvalidProtobuf(message()))
}

fn copy_spans(target: &mut Vec<Span>, source: &[dto::BucketSpan]) {
    target.clear();
    target.extend(source.iter().map(|span| Span {
        offset: span.offset,
        length: span.length,
    }));
}

/// Bucket count of a native histogram: delta-encoded `i64` or absolute `f64`.
trait Bucket: Copy + PartialEq {
    const ZERO: Self;
    const DELTA: bool;
    fn add(self, other: Self) -> Self;
    fn neg(self) -> Self;
    /// Plain subtraction: `add(other.neg())` flips the sign bit of a NaN `other`, Go's `-` does not.
    fn sub(self, other: Self) -> Self;
}

impl Bucket for i64 {
    const ZERO: Self = 0;
    const DELTA: bool = true;
    fn add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    fn neg(self) -> Self {
        self.wrapping_neg()
    }
    fn sub(self, other: Self) -> Self {
        self.wrapping_sub(other)
    }
}

impl Bucket for f64 {
    const ZERO: Self = 0.0;
    const DELTA: bool = false;
    fn add(self, other: Self) -> Self {
        self + other
    }
    fn neg(self) -> Self {
        -self
    }
    fn sub(self, other: Self) -> Self {
        self - other
    }
}

/// Go's `compactBuckets`: removes empty buckets, except runs of at most `max_empty_buckets`
/// inside a span, and merges spans. The caller has checked that the spans cover exactly
/// `buckets.len()` buckets.
///
/// Go's last step, which merges spans less than `max_empty_buckets` apart, is left out: it
/// only runs for NHCB, which starts with one span and only splits it at longer gaps.
fn compact_buckets<B: Bucket>(
    buckets: &mut Vec<B>,
    spans: &mut Vec<Span>,
    max_empty_buckets: usize,
) {
    debug_assert!(max_empty_buckets == 0 || spans.len() <= 1);
    let absolute = |current: B, bucket: B| {
        if B::DELTA {
            current.add(bucket)
        } else {
            bucket
        }
    };
    let mut current = B::ZERO;
    let has_empty_bucket = buckets.iter().any(|&bucket| {
        current = absolute(current, bucket);
        current == B::ZERO
    });
    // The first span's offset is a start index, not a gap, so it never needs compaction.
    if !has_empty_bucket
        && spans.first().is_none_or(|span| span.length != 0)
        && spans
            .iter()
            .skip(1)
            .all(|span| i64::from(span.offset) > max_empty_buckets as i64 && span.length != 0)
    {
        return;
    }

    if spans.len() > 1 {
        let mut kept = 0;
        for index in 1..spans.len() {
            let span = spans[index];
            if span.offset == 0 {
                spans[kept].length = spans[kept].length.wrapping_add(span.length);
                continue;
            }
            kept += 1;
            spans[kept] = span;
        }
        spans.truncate(kept + 1);
    }

    let mut kept = 0;
    for index in 0..spans.len() {
        let span = spans[index];
        if span.length == 0 {
            if let Some(next) = spans.get_mut(index + 1) {
                next.offset = next.offset.wrapping_add(span.offset);
            }
            continue;
        }
        spans[kept] = span;
        kept += 1;
    }
    spans.truncate(kept);
    if spans.is_empty() {
        buckets.clear();
        return;
    }

    let (mut bucket_index, mut span_index, mut pos_in_span) = (0, 0, 0u32);
    current = B::ZERO;
    while bucket_index < buckets.len() && span_index < spans.len() {
        current = absolute(current, buckets[bucket_index]);
        let empty = empty_buckets_here(
            buckets,
            spans[span_index].length,
            bucket_index,
            pos_in_span,
            current,
        );
        if empty == 0 {
            bucket_index += 1;
            pos_in_span += 1;
            if pos_in_span >= spans[span_index].length {
                pos_in_span = 0;
                span_index += 1;
            }
            continue;
        }
        if pos_in_span > 0
            && empty < (spans[span_index].length - pos_in_span) as usize
            && empty <= max_empty_buckets
        {
            bucket_index += empty;
            pos_in_span += empty as u32;
            continue;
        }
        if B::DELTA && bucket_index + empty < buckets.len() {
            current = buckets[bucket_index].neg();
            buckets[bucket_index + empty] =
                buckets[bucket_index + empty].add(buckets[bucket_index]);
        }
        buckets.drain(bucket_index..bucket_index + empty);
        let empty_u32 = empty as u32;
        if pos_in_span == 0 {
            if empty_u32 == spans[span_index].length {
                let offset = spans.remove(span_index).offset;
                if let Some(next) = spans.get_mut(span_index) {
                    next.offset = next
                        .offset
                        .wrapping_add(offset)
                        .wrapping_add(empty_u32 as i32);
                }
                continue;
            }
            spans[span_index].length -= empty_u32;
            spans[span_index].offset = spans[span_index].offset.wrapping_add(empty_u32 as i32);
            continue;
        }
        let split = Span {
            offset: empty_u32 as i32,
            length: spans[span_index].length - pos_in_span - empty_u32,
        };
        spans[span_index].length = pos_in_span;
        span_index += 1;
        pos_in_span = 0;
        if split.length == 0 {
            if let Some(next) = spans.get_mut(span_index) {
                next.offset = next.offset.wrapping_add(empty_u32 as i32);
            }
            continue;
        }
        spans.insert(span_index, split);
    }
}

/// Go's `emptyBucketsHere`: the number of empty buckets from `bucket_index` within the span.
fn empty_buckets_here<B: Bucket>(
    buckets: &[B],
    span_length: u32,
    bucket_index: usize,
    pos_in_span: u32,
    current: B,
) -> usize {
    let mut count = 0;
    let mut value = current;
    while (count as u32) + pos_in_span < span_length && value == B::ZERO {
        count += 1;
        match buckets.get(bucket_index + count) {
            Some(&bucket) => value = bucket,
            None => break,
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delimited(families: &[dto::MetricFamily]) -> Vec<u8> {
        let mut out = Vec::new();
        for family in families {
            family.encode_length_delimited(&mut out).unwrap();
        }
        out
    }

    fn parse_all(input: &[u8]) -> Result<(), ParseError> {
        let mut parser = ProtobufParser::new(input);
        while parser.next_entry()?.is_some() {
            if parser.state == Some(Entry::Histogram) {
                parser.histogram();
            }
        }
        Ok(())
    }

    fn histogram_family(name: &str, positive_delta: Vec<i64>) -> dto::MetricFamily {
        dto::MetricFamily {
            name: name.to_owned(),
            r#type: dto::MetricType::Histogram as i32,
            metric: vec![dto::Metric {
                histogram: Some(dto::Histogram {
                    positive_span: vec![dto::BucketSpan {
                        offset: 0,
                        length: 2,
                    }],
                    positive_delta,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        let valid = delimited(&[histogram_family("h", vec![1, 0])]);
        assert!(parse_all(&valid).is_ok());
        assert!(matches!(
            parse_all(&valid[..valid.len() - 1]),
            Err(ParseError::InvalidProtobuf(_))
        ));

        // Go skips the span check when a native histogram follows another one. Without it,
        // compaction here would index out of bounds.
        let second_bad = histogram_family("h", vec![1]);
        let mut family = histogram_family("h", vec![1, 0]);
        family.metric.extend(second_bad.metric);
        assert!(matches!(
            parse_all(&delimited(&[family])),
            Err(ParseError::InvalidProtobuf(message)) if message.starts_with("histogram \"h\": ")
        ));

        assert!(matches!(
            parse_all(&delimited(&[histogram_family("", vec![1, 0])])),
            Err(ParseError::InvalidMetricName { .. })
        ));
    }

    fn first_histogram(input: &[u8]) -> Histogram<u64, i64> {
        let mut parser = ProtobufParser::new(input);
        while let Some(entry) = parser.next_entry().unwrap() {
            if let (Entry::Histogram, (_, _, HistogramRef::Int(histogram))) =
                (entry, parser.histogram())
            {
                return histogram.clone();
            }
        }
        panic!("no native histogram");
    }

    fn assert_compacts(
        spans: &[(i32, u32)],
        deltas: &[i64],
        want_spans: &[(i32, u32)],
        want_buckets: &[i64],
    ) {
        let to_spans = |spans: &[(i32, u32)]| -> Vec<Span> {
            spans
                .iter()
                .map(|&(offset, length)| Span { offset, length })
                .collect()
        };
        let mut family = histogram_family("h", deltas.to_vec());
        family.metric[0].histogram.as_mut().unwrap().positive_span = spans
            .iter()
            .map(|&(offset, length)| dto::BucketSpan { offset, length })
            .collect();
        let histogram = first_histogram(&delimited(&[family]));
        assert_eq!(histogram.positive_spans, to_spans(want_spans));
        assert_eq!(histogram.positive_buckets, want_buckets);
    }

    #[test]
    fn compacts_empty_buckets_like_go() {
        // Expected values come from Go's NewProtobufParser at v0.315.1 on the same input.
        assert_compacts(
            &[(0, 2), (0, 2)],
            &[1, -1, 2, -2],
            &[(0, 1), (1, 1)],
            &[1, 1],
        );
        assert_compacts(
            &[(0, 2), (2, 2)],
            &[1, -1, 0, 2],
            &[(0, 1), (4, 1)],
            &[1, 1],
        );
        assert_compacts(&[(0, 1), (0, 1)], &[1, 0], &[(0, 2)], &[1, 0]);
    }

    #[test]
    fn returns_exemplars_of_each_native_histogram() {
        let exemplar = |id: &str| dto::Exemplar {
            label: vec![dto::LabelPair {
                name: "id".to_owned(),
                value: id.to_owned(),
            }],
            timestamp: Some(prost_types::Timestamp::default()),
            ..Default::default()
        };
        let mut family = histogram_family("h", vec![1, 0]);
        family.metric.push(family.metric[0].clone());
        for (metric, id) in family.metric.iter_mut().zip(["e1", "e2"]) {
            metric.histogram.as_mut().unwrap().exemplars = vec![exemplar(id)];
        }
        let input = delimited(&[family]);
        let mut parser = ProtobufParser::new(&input);
        let mut labels = LabelsBuffer::default();
        let mut ids = Vec::new();
        while let Some(entry) = parser.next_entry().unwrap() {
            if entry == Entry::Histogram {
                while parser.exemplar(&mut labels).is_some() {
                    ids.push(labels.iter().next().unwrap().1.to_owned());
                }
            }
        }
        assert_eq!(ids, ["e1", "e2"]);
    }
    #[test]
    fn converts_count_of_two_to_the_63_to_float_nhcb() {
        // Go's int64(2^63) on amd64 is not 2^63, so Go returns a FloatHistogram.
        let count = 1u64 << 63;
        let source = dto::Histogram {
            sample_count: count,
            bucket: vec![dto::Bucket {
                cumulative_count: count,
                upper_bound: 1.0,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut float_target = Histogram::default();
        let is_float = convert_to_nhcb(
            &source,
            &mut Vec::new(),
            &mut Histogram::default(),
            &mut float_target,
            CounterResetHint::Unknown,
        )
        .unwrap();
        assert!(is_float);
        assert_eq!(float_target.count, count as f64);
        assert_eq!(float_target.positive_buckets, [count as f64]);
    }
}
