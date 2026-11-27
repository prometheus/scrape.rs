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

//! Entry loop for delimited protobuf (`FmtProtoDelim`) input.
//!
//! The protobuf parser decodes one `MetricFamily` message at a time, so this loop reads the
//! decoded message directly instead of the byte spans the text loop uses: label strings are
//! interned as they are, without unescaping, and a summary becomes one data point from its
//! `dto::Summary` instead of being assembled from `_count`, `_sum`, and quantile series.
//!
//! Every message starts a new OTAP metric row, even when it repeats the name of the message
//! before it. Go accepts such split families, so unlike the text loop this one never returns
//! the duplicate or late metadata errors.

use std::time::Instant;

use crate::dto;
use crate::parse::{Entry, HistogramRef, MetricType, Parser, ProtobufParser, ProtobufParserState};
use crate::parse::{METRIC_NAME_LABEL, checked_timestamp_millis};

use super::columns::{ExemplarTable, ms_to_ns, parse_hex_array};
use super::family::CurrentFamily;
use super::intern::StringInterner;
use super::native::{
    CUSTOM_BUCKETS_SCHEMA, EXPONENTIAL_SCHEMAS, NativeView, check_float_histogram,
    invalid_histogram, push_custom_buckets, push_exponential,
};
use super::staleness::{DATA_POINT_FLAG_NO_RECORDED_VALUE, DpKind, StalenessTracker, is_stale_nan};
use super::{
    ArrowDecoder, DECODE_BUDGET_DURATION_CHECK_INTERVAL, DecodeBudget, DecodeError, DecodeOptions,
    DecodeStep, MAX_METRICS_PER_BATCH, UntypedPolicy,
};

/// Protobuf scratch the decoder keeps across scrapes.
#[derive(Default)]
pub(super) struct ProtoScratch {
    /// Parser state between scrapes, reused for its decoded `MetricFamily` and histogram buffers.
    pub(super) state: ProtobufParserState,
    /// `(quantile, value)` pairs of the current summary, sorted before they are appended.
    quantiles: Vec<(f64, f64)>,
    /// Indices of the labels being checked, sorted by name.
    label_order: Vec<usize>,
}

impl ProtoScratch {
    /// Keeps the scratch of a finished or abandoned parser if it holds more than the scratch
    /// already kept, like the text parsers' scratch. The last decoded message is dropped first,
    /// so `retained_memory_bytes` counts everything the decoder keeps.
    pub(super) fn keep_state(&mut self, mut state: ProtobufParserState) {
        state.release_decoded();
        if state.retained_memory_bytes() > self.state.retained_memory_bytes() {
            self.state = state;
        }
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.state.retained_memory_bytes()
            + self.quantiles.capacity() * size_of::<(f64, f64)>()
            + self.label_order.capacity() * size_of::<usize>()
    }
}

/// Whether the current histogram becomes an exponential point, so it needs the family's
/// exponential histogram row. Float histograms are dropped and need no row.
#[inline]
fn is_exponential(parser: &ProtobufParser<'_>) -> bool {
    match parser.histogram().2 {
        HistogramRef::Int(h) => EXPONENTIAL_SCHEMAS.contains(&h.schema),
        HistogramRef::Float(_) => false,
    }
}

/// Go reads a zero start timestamp as unset. A start timestamp out of the nanosecond range is
/// also unset, like an out-of-range created timestamp in the text loop.
#[inline]
fn start_timestamp_ns(parser: &ProtobufParser<'_>) -> Option<i64> {
    parser
        .start_timestamp_proto()
        .and_then(checked_timestamp_millis)
        .filter(|&ms| ms != 0)
        .and_then(|ms| ms.checked_mul(1_000_000))
}

#[inline]
fn sample_timestamp_ns(
    metric: &dto::Metric,
    default_ts_ns: Option<i64>,
) -> Result<Option<i64>, DecodeError> {
    // Go reads a zero timestamp as unset.
    match metric.timestamp_ms {
        0 => Ok(default_ts_ns),
        ms => ms_to_ns(ms).map(Some),
    }
}

/// The kind of the data point an append added and whether it is a stale marker, for the
/// staleness tracker. `None` when the point was dropped.
type AppendedPoint = Option<(DpKind, bool)>;

impl ArrowDecoder {
    /// The protobuf counterpart of `ingest_entries`, with the same chunking, budget, and
    /// staleness rules.
    ///
    /// Kept out of line so it does not change how the text loop in `ingest` is inlined.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub(super) fn ingest_proto_entries<
        const CHUNKED: bool,
        const BUDGETED: bool,
        const TRACKED: bool,
    >(
        &mut self,
        parser: &mut ProtobufParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
        max_data_points: usize,
        budget: Option<DecodeBudget>,
        pending_series: &mut bool,
        done: &mut bool,
        tracker: &mut Option<&mut StalenessTracker>,
    ) -> Result<DecodeStep, DecodeError> {
        let start_pos = if BUDGETED { parser.pos() } else { 0 };
        let budget = budget.filter(|_| BUDGETED);
        let max_entries = budget.map_or(usize::MAX, |b| b.max_entries.max(1));
        let max_bytes = budget.map_or(usize::MAX, |b| b.max_bytes.max(1));
        let started = if BUDGETED { Some(Instant::now()) } else { None };
        let mut entries = 0usize;

        loop {
            let entry = if CHUNKED && *pending_series {
                // Replays the series or histogram that did not fit the last batch.
                *pending_series = false;
                parser.current_entry().unwrap_or(Entry::Comment)
            } else {
                match parser.next_entry().map_err(DecodeError::from_parse)? {
                    Some(entry) => entry,
                    None => {
                        let step_budget = budget.and_then(|b| {
                            started
                                .map(|st| (max_entries.saturating_sub(entries), st, b.max_duration))
                        });
                        return self.finish_input::<CHUNKED, TRACKED>(
                            tracker,
                            opts,
                            default_ts_ns,
                            max_data_points,
                            step_budget,
                            done,
                        );
                    }
                }
            };

            match entry {
                Entry::Help => self.start_proto_family(parser),
                // `start_proto_family` already read the unit and type of the message.
                Entry::Unit | Entry::Type | Entry::Comment => {}
                Entry::Series | Entry::Histogram => {
                    // The parser returns one series per summary, its `_count` series, as the
                    // decoder resets it with `skip_entry_bytes`.
                    let row = if entry == Entry::Histogram && is_exponential(parser) {
                        self.current_family.exp_batch_id
                    } else {
                        self.current_family.batch_id
                    };
                    if CHUNKED && row.is_none() && self.metrics.len() >= MAX_METRICS_PER_BATCH {
                        *pending_series = true;
                        let batch = self.finish_batches(default_ts_ns.is_some())?;
                        self.reset_batch_for_mode::<TRACKED>(tracker);
                        return Ok(DecodeStep::Batch(batch));
                    }
                    let point = if entry == Entry::Histogram {
                        self.append_proto_histogram(parser, opts, default_ts_ns)?
                    } else if self.current_family.metric_type == MetricType::Summary {
                        self.append_proto_summary(parser, opts, default_ts_ns)?
                    } else {
                        self.append_proto_scalar(parser, opts, default_ts_ns)?
                    };
                    if TRACKED
                        && let Some(tr) = tracker.as_deref_mut()
                        && let Some((kind, is_stale)) = point
                    {
                        // Same rule as the text loop: a point with its own timestamp is
                        // tracked only with `track_timestamps_staleness`.
                        if parser.current_metric().timestamp_ms == 0
                            || opts.track_timestamps_staleness
                        {
                            tr.record_series(
                                &mut self.current_family,
                                kind,
                                &self.temp_attrs,
                                &self.key_interner,
                                &self.val_interner,
                                is_stale,
                            )?;
                        } else {
                            tr.sync_existing_family(&mut self.current_family)?;
                        }
                    }
                    if CHUNKED && self.total_data_points() >= max_data_points {
                        let batch = self.finish_batches(default_ts_ns.is_some())?;
                        self.reset_batch_for_mode::<TRACKED>(tracker);
                        return Ok(DecodeStep::Batch(batch));
                    }
                }
            }

            if let Some(budget) = budget {
                entries += 1;
                let bytes_consumed = parser.pos().saturating_sub(start_pos);
                let duration_exceeded = (budget.max_duration.is_zero()
                    || entries.is_multiple_of(DECODE_BUDGET_DURATION_CHECK_INTERVAL))
                    && started.is_some_and(|t| t.elapsed() >= budget.max_duration);
                if entries >= max_entries || bytes_consumed >= max_bytes || duration_exceeded {
                    return Ok(DecodeStep::Pending);
                }
            }
        }
    }

    /// Starts a new family for the message the parser just decoded, with all of its metadata.
    fn start_proto_family(&mut self, parser: &ProtobufParser<'_>) {
        let family = parser.family();
        let name = family.name.as_bytes();
        let current = &mut self.current_family;
        current.start_new(name, name);
        current.metric_type = parser.metric_type().1;
        current.has_type = true;
        if !family.help.is_empty() {
            current.help.extend_from_slice(family.help.as_bytes());
            current.has_help = true;
        }
        if !family.unit.is_empty() {
            current.unit.extend_from_slice(family.unit.as_bytes());
            current.has_unit = true;
        }
    }

    fn append_proto_scalar(
        &mut self,
        parser: &mut ProtobufParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<AppendedPoint, DecodeError> {
        let metric_type = self.current_family.metric_type;
        let start_ts_ns = if metric_type == MetricType::Counter {
            start_timestamp_ns(parser)
        } else {
            None
        };
        let value = parser.series().2;
        let metric = parser.current_metric();

        if metric_type == MetricType::Unknown && opts.untyped_policy == UntypedPolicy::Drop {
            // Labels are still checked, like the text loop does for dropped families.
            check_label_names(
                &metric.label,
                &mut self.proto.label_order,
                &self.current_family,
            )?;
            self.current_family.has_samples = true;
            return Ok(None);
        }

        let dp_index = self.num_dp.base.len();
        let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
            table: "NumberDataPoints",
            count: dp_index + 1,
        })?;
        self.proto_labels_into_temp(&metric.label)?;
        self.num_dp.attrs.extend_for_parent(dp_id, &self.temp_attrs);

        let is_stale = is_stale_nan(value);
        if let Some(exemplar) = metric
            .counter
            .as_ref()
            .and_then(|counter| counter.exemplar.as_ref())
            .filter(|_| metric_type == MetricType::Counter && !is_stale)
        {
            push_proto_exemplar(
                &mut self.num_dp.exemplars,
                "NumberDpExemplars",
                &mut self.key_interner,
                &mut self.val_interner,
                &self.current_family,
                dp_id,
                exemplar,
                default_ts_ns,
            )?;
        }

        let parent_id = self
            .current_family
            .emit_into_batch(&mut self.metrics, opts)?;
        let ts_ns = sample_timestamp_ns(metric, default_ts_ns)?;
        if is_stale {
            self.num_dp.base.push_with_flags(
                parent_id,
                start_ts_ns,
                ts_ns,
                DATA_POINT_FLAG_NO_RECORDED_VALUE,
            );
            self.num_dp.values.push_null(dp_index);
        } else {
            self.num_dp.base.push(parent_id, start_ts_ns, ts_ns);
            self.num_dp.values.push_value(value);
        }
        Ok(Some((DpKind::Number, is_stale)))
    }

    fn append_proto_summary(
        &mut self,
        parser: &mut ProtobufParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<AppendedPoint, DecodeError> {
        let start_ts_ns = start_timestamp_ns(parser);
        let metric = parser.current_metric();

        let dp_index = self.sum_dp.base.len();
        let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
            table: "SummaryDataPoints",
            count: dp_index + 1,
        })?;
        self.proto_labels_into_temp(&metric.label)?;
        self.sum_dp.attrs.extend_for_parent(dp_id, &self.temp_attrs);

        let parent_id = self
            .current_family
            .emit_into_batch(&mut self.metrics, opts)?;
        let ts_ns = sample_timestamp_ns(metric, default_ts_ns)?;
        let summary = metric.summary.as_ref();
        let sum_dp = &mut self.sum_dp;
        if sum_dp.quantile_offsets.is_empty() {
            sum_dp.quantile_offsets.push(0);
        }
        // Like the text loop, a stale marker in the sum or any quantile makes the point stale,
        // with zero count and sum and no quantiles.
        let is_stale = summary.is_some_and(|s| {
            is_stale_nan(s.sample_sum) || s.quantile.iter().any(|q| is_stale_nan(q.value))
        });
        if is_stale {
            sum_dp.base.push_with_flags(
                parent_id,
                start_ts_ns,
                ts_ns,
                DATA_POINT_FLAG_NO_RECORDED_VALUE,
            );
        } else {
            sum_dp.base.push(parent_id, start_ts_ns, ts_ns);
        }
        // Go reads a missing summary as zero count and sum.
        sum_dp.counts.push(
            dp_index,
            Some(summary.filter(|_| !is_stale).map_or(0, |s| s.sample_count)),
        );
        sum_dp.sums.push(
            dp_index,
            Some(summary.filter(|_| !is_stale).map_or(0.0, |s| s.sample_sum)),
        );

        // Same as the text loop: finite quantiles only, sorted by quantile.
        let quantiles = &mut self.proto.quantiles;
        quantiles.clear();
        quantiles.extend(
            summary
                .filter(|_| !is_stale)
                .map_or(&[][..], |s| &s.quantile)
                .iter()
                .filter(|q| q.quantile.is_finite())
                .map(|q| (q.quantile, q.value)),
        );
        if !quantiles.is_sorted_by(|a, b| a.0 <= b.0) {
            quantiles.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
        }
        for &(quantile, value) in quantiles.iter() {
            sum_dp.quantile_bounds.push(quantile);
            sum_dp.quantile_vals.push(value);
        }
        let q_off = i32::try_from(sum_dp.quantile_bounds.len()).map_err(|_| {
            DecodeError::CapacityOverflow {
                table: "SummaryDataPoints.quantile",
                count: sum_dp.quantile_bounds.len(),
            }
        })?;
        sum_dp.quantile_offsets.push(q_off);
        Ok(Some((DpKind::Summary, is_stale)))
    }

    /// Appends a native histogram: custom buckets (NHCB, which classic protobuf histograms are
    /// converted to) as an explicit-bucket point, exponential schemas as an exponential point.
    /// Float histograms are dropped, per the OpenTelemetry compatibility spec.
    fn append_proto_histogram(
        &mut self,
        parser: &mut ProtobufParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<AppendedPoint, DecodeError> {
        let start_ts_ns = start_timestamp_ns(parser);
        let (_, _, histogram) = parser.histogram();
        let metric = parser.current_metric();
        let view =
            NativeView::new(histogram).map_err(|r| invalid_histogram(&self.current_family, r))?;
        let exponential = match view.schema {
            CUSTOM_BUCKETS_SCHEMA => false,
            schema if EXPONENTIAL_SCHEMAS.contains(&schema) => true,
            schema => {
                return Err(invalid_histogram(
                    &self.current_family,
                    format!(
                        "histogram has an invalid schema, which must be between {} and {} or \
                         {CUSTOM_BUCKETS_SCHEMA}, got {schema}",
                        EXPONENTIAL_SCHEMAS.start(),
                        EXPONENTIAL_SCHEMAS.end(),
                    ),
                ));
            }
        };
        if view.is_float {
            check_float_histogram(&view).map_err(|r| invalid_histogram(&self.current_family, r))?;
            // Labels are still checked, like for points of dropped untyped families.
            check_label_names(
                &metric.label,
                &mut self.proto.label_order,
                &self.current_family,
            )?;
            self.current_family.has_samples = true;
            return Ok(None);
        }

        let (table, dp_index) = if exponential {
            ("ExpHistogramDataPoints", self.exp_hist_dp.base.len())
        } else {
            ("HistogramDataPoints", self.hist_dp.base.len())
        };
        let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
            table,
            count: dp_index + 1,
        })?;
        self.proto_labels_into_temp(&metric.label)?;
        let parent_id = if exponential {
            push_exponential(&mut self.exp_hist_dp, &view, &self.current_family)?;
            self.current_family
                .emit_exp_histogram_into_batch(&mut self.metrics, opts)?
        } else {
            push_custom_buckets(&mut self.hist_dp, dp_index, &view, &self.current_family)?;
            self.current_family
                .emit_into_batch(&mut self.metrics, opts)?
        };
        let ts_ns = sample_timestamp_ns(metric, default_ts_ns)?;

        let (base, attrs, exemplars, exemplar_table) = if exponential {
            let dp = &mut self.exp_hist_dp;
            (
                &mut dp.base,
                &mut dp.attrs,
                &mut dp.exemplars,
                "ExpHistogramDpExemplars",
            )
        } else {
            let dp = &mut self.hist_dp;
            (
                &mut dp.base,
                &mut dp.attrs,
                &mut dp.exemplars,
                "HistogramDpExemplars",
            )
        };
        attrs.extend_for_parent(dp_id, &self.temp_attrs);
        // Prometheus writes the stale NaN into the sum of a stale native histogram.
        let is_stale = is_stale_nan(view.sum);
        if is_stale {
            base.push_with_flags(
                parent_id,
                start_ts_ns,
                ts_ns,
                DATA_POINT_FLAG_NO_RECORDED_VALUE,
            );
        } else {
            base.push(parent_id, start_ts_ns, ts_ns);
        }
        while let Some(exemplar) = parser.next_histogram_exemplar().filter(|_| !is_stale) {
            push_proto_exemplar(
                exemplars,
                exemplar_table,
                &mut self.key_interner,
                &mut self.val_interner,
                &self.current_family,
                dp_id,
                exemplar,
                default_ts_ns,
            )?;
        }
        let kind = if exponential {
            DpKind::ExpHistogram
        } else {
            DpKind::Histogram
        };
        Ok(Some((kind, is_stale)))
    }

    /// Interns the labels of a protobuf metric into `temp_attrs`, sorted by key ID, with the
    /// same rules as the text loop: empty values are dropped, and `__name__` and duplicate
    /// names are rejected.
    fn proto_labels_into_temp(&mut self, labels: &[dto::LabelPair]) -> Result<(), DecodeError> {
        self.temp_attrs.clear();
        let mut prev_key_id = None;
        let mut sorted_by_key_id = true;
        let mut has_empty_value = false;
        for label in labels {
            if label.value.is_empty() {
                has_empty_value = true;
                continue;
            }
            let key_id = Self::intern_key(
                &mut self.key_interner,
                &self.current_family,
                label.name.as_bytes(),
                true,
                &mut prev_key_id,
                &mut sorted_by_key_id,
                "DpAttrs.key",
            )?;
            let val_id = Self::intern_val(
                &mut self.val_interner,
                label.value.as_bytes(),
                "DpAttrs.str",
            )?;
            self.temp_attrs.push((key_id, val_id));
        }
        if !sorted_by_key_id {
            Self::sort_and_check_duplicates(
                &mut self.temp_attrs,
                &self.key_interner,
                &self.current_family,
            )?;
        }
        if has_empty_value {
            // Labels with empty values are not interned, but their names still count.
            check_label_names(labels, &mut self.proto.label_order, &self.current_family)?;
        }
        Ok(())
    }
}

/// Saturates instead of wrapping like Go's `UnixMilli`, so the error keeps the overflow's sign.
#[cold]
fn exemplar_timestamp_overflow(timestamp: &prost_types::Timestamp) -> DecodeError {
    DecodeError::TimestampOverflow {
        timestamp_ms: timestamp
            .seconds
            .saturating_mul(1_000)
            .saturating_add(i64::from(timestamp.nanos / 1_000_000)),
    }
}

/// Rejects `__name__` and duplicate names among labels that are not interned. The labels are
/// sorted by name in `order`, so a long label list takes O(L log L), not O(L^2).
#[cold]
fn check_label_names(
    labels: &[dto::LabelPair],
    order: &mut Vec<usize>,
    family: &CurrentFamily,
) -> Result<(), DecodeError> {
    order.clear();
    order.extend(0..labels.len());
    order.sort_unstable_by_key(|&index| labels[index].name.as_str());
    let mut previous = None;
    for &index in order.iter() {
        let name = labels[index].name.as_str();
        if name == METRIC_NAME_LABEL || previous == Some(name) {
            return Err(DecodeError::DuplicateLabel {
                metric: family.name_string(),
                label: name.to_owned(),
            });
        }
        previous = Some(name);
    }
    Ok(())
}

/// Rejects label `index` if it is `__name__` (when `reject_metric_name` is set) or if another
/// label has the same name. Used for labels that are not interned.
#[cold]
fn check_label_name(
    index: usize,
    labels: &[dto::LabelPair],
    reject_metric_name: bool,
    family: &CurrentFamily,
) -> Result<(), DecodeError> {
    let name = labels[index].name.as_str();
    let duplicate = labels
        .iter()
        .enumerate()
        .any(|(other, label)| other != index && label.name == name);
    if (reject_metric_name && name == METRIC_NAME_LABEL) || duplicate {
        return Err(DecodeError::DuplicateLabel {
            metric: family.name_string(),
            label: name.to_owned(),
        });
    }
    Ok(())
}

/// Appends a protobuf exemplar to `exemplars`, with `span_id` and `trace_id` labels moved to
/// their columns like the text loop does.
#[allow(clippy::too_many_arguments)]
fn push_proto_exemplar(
    exemplars: &mut ExemplarTable,
    table: &'static str,
    key_interner: &mut StringInterner,
    val_interner: &mut StringInterner,
    family: &CurrentFamily,
    dp_id: u32,
    exemplar: &dto::Exemplar,
    default_ts_ns: Option<i64>,
) -> Result<(), DecodeError> {
    let ex_id = exemplars.next_id(table)?;
    let ts_ns = match exemplar.timestamp.as_ref() {
        // Go's `UnixMilli` wraps on overflow; the decoder rejects it like a sample timestamp.
        Some(timestamp) => match checked_timestamp_millis(timestamp) {
            Some(ms) => ms_to_ns(ms)?,
            None => return Err(exemplar_timestamp_overflow(timestamp)),
        },
        None => default_ts_ns.unwrap_or(0),
    };
    let mut span_id = None;
    let mut trace_id = None;
    let attr_start = exemplars.attrs.len();
    let mut prev_key_id = None;
    let mut sorted_by_key_id = true;
    for (index, label) in exemplar.label.iter().enumerate() {
        if label.value.is_empty() {
            // Exemplar labels may be named `__name__`, as the interned ones below.
            check_label_name(index, &exemplar.label, false, family)?;
            continue;
        }
        let parsed = match label.name.as_str() {
            "span_id" | "trace_id" => {
                // A repeated `span_id` or `trace_id` is a duplicate label.
                check_label_name(index, &exemplar.label, false, family)?;
                let value = label.value.as_bytes();
                if label.name == "span_id" {
                    span_id = parse_hex_array::<8>(value);
                    span_id.is_some()
                } else {
                    trace_id = parse_hex_array::<16>(value);
                    trace_id.is_some()
                }
            }
            _ => false,
        };
        if parsed {
            continue;
        }
        let key_id = ArrowDecoder::intern_key(
            key_interner,
            family,
            label.name.as_bytes(),
            false,
            &mut prev_key_id,
            &mut sorted_by_key_id,
            "ExemplarAttrs.key",
        )?;
        let val_id =
            ArrowDecoder::intern_val(val_interner, label.value.as_bytes(), "ExemplarAttrs.str")?;
        exemplars.attrs.push(ex_id, key_id, val_id);
    }
    if !sorted_by_key_id {
        ArrowDecoder::sort_and_check_duplicates(
            &mut exemplars.attrs.pairs[attr_start..],
            key_interner,
            family,
        )?;
    }
    exemplars.push_row(dp_id, ts_ns, exemplar.value, span_id, trace_id);
    Ok(())
}
