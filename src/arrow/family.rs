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

//! Contiguous metric-family state machine and multi-line histogram/summary assembly buffers.

use crate::parse::MetricType;

use super::columns::{HistogramDpTable, MetricTable, SummaryDpTable, f64_to_u64_count};
use super::options::{
    CounterSuffixPolicy, DecodeError, DecodeOptions, UnitSuffixPolicy, UntypedPolicy,
};
use super::schema::{
    OTAP_METRIC_TYPE_GAUGE, OTAP_METRIC_TYPE_HISTOGRAM, OTAP_METRIC_TYPE_SUM,
    OTAP_METRIC_TYPE_SUMMARY,
};

/// Role of a series line within the active [`CurrentFamily`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SeriesRole {
    Scalar,
    HistogramBucket,
    HistogramSum,
    HistogramCount,
    SummaryQuantile,
    SummarySum,
    SummaryCount,
}

/// Active contiguous metric-family cursor.
///
/// Tracking only the current contiguous family avoids maintaining a whole-scrape metric-name hash
/// table, lets `UnivariateMetrics` names, descriptions, and units append straight into Arrow
/// `(offsets, values)` buffers on first sample emission, and preserves active family metadata
/// across chunk flushes.
#[derive(Default)]
pub(super) struct CurrentFamily {
    pub(super) active: bool,
    pub(super) raw_name: Vec<u8>,
    pub(super) unescaped_name: Vec<u8>,
    pub(super) metric_type: MetricType,
    pub(super) has_type: bool,
    pub(super) has_help: bool,
    pub(super) has_unit: bool,
    pub(super) has_samples: bool,
    pub(super) saw_total_suffix: bool,
    pub(super) help: Vec<u8>,
    pub(super) unit: Vec<u8>,
    pub(super) batch_id: Option<u16>,
}

impl CurrentFamily {
    pub(super) fn with_capacity(name_cap: usize, help_cap: usize) -> Self {
        Self {
            raw_name: Vec::with_capacity(name_cap),
            unescaped_name: Vec::with_capacity(name_cap),
            help: Vec::with_capacity(help_cap),
            unit: Vec::with_capacity(16),
            ..Self::default()
        }
    }

    pub(super) fn clear(&mut self) {
        self.active = false;
        self.raw_name.clear();
        self.unescaped_name.clear();
        self.metric_type = MetricType::Unknown;
        self.has_type = false;
        self.has_help = false;
        self.has_unit = false;
        self.has_samples = false;
        self.saw_total_suffix = false;
        self.help.clear();
        self.unit.clear();
        self.batch_id = None;
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.raw_name.capacity()
            + self.unescaped_name.capacity()
            + self.help.capacity()
            + self.unit.capacity()
    }

    #[cold]
    pub(super) fn name_string(&self) -> String {
        String::from_utf8_lossy(&self.unescaped_name).into_owned()
    }

    pub(super) fn start_new(&mut self, raw_name: &[u8], unescaped: &[u8]) {
        self.active = true;
        self.raw_name.clear();
        self.raw_name.extend_from_slice(raw_name);
        self.unescaped_name.clear();
        self.unescaped_name.extend_from_slice(unescaped);
        self.metric_type = MetricType::Unknown;
        self.has_type = false;
        self.has_help = false;
        self.has_unit = false;
        self.has_samples = false;
        self.saw_total_suffix = unescaped.len() > 6 && unescaped.ends_with(b"_total");
        self.help.clear();
        self.unit.clear();
        self.batch_id = None;
    }

    #[inline]
    pub(super) fn classify_series(&mut self, series_name: &[u8]) -> Option<SeriesRole> {
        if !self.active {
            return None;
        }
        let fam = self.unescaped_name.as_slice();
        match self.metric_type {
            MetricType::Histogram => {
                series_name
                    .strip_prefix(fam)
                    .and_then(|suffix| match suffix {
                        b"_bucket" => Some(SeriesRole::HistogramBucket),
                        b"_sum" => Some(SeriesRole::HistogramSum),
                        b"_count" => Some(SeriesRole::HistogramCount),
                        _ => None,
                    })
            }
            MetricType::GaugeHistogram => {
                series_name
                    .strip_prefix(fam)
                    .and_then(|suffix| match suffix {
                        b"_bucket" => Some(SeriesRole::HistogramBucket),
                        b"_gsum" | b"_sum" => Some(SeriesRole::HistogramSum),
                        b"_gcount" | b"_count" => Some(SeriesRole::HistogramCount),
                        _ => None,
                    })
            }
            MetricType::Summary => {
                if series_name == fam {
                    return Some(SeriesRole::SummaryQuantile);
                }
                series_name
                    .strip_prefix(fam)
                    .and_then(|suffix| match suffix {
                        b"_sum" => Some(SeriesRole::SummarySum),
                        b"_count" => Some(SeriesRole::SummaryCount),
                        _ => None,
                    })
            }
            MetricType::Counter => {
                if series_name == fam {
                    if series_name.len() > 6 && series_name.ends_with(b"_total") {
                        self.saw_total_suffix = true;
                    }
                    return Some(SeriesRole::Scalar);
                }
                if series_name.strip_prefix(fam) == Some(b"_total") {
                    self.saw_total_suffix = true;
                    return Some(SeriesRole::Scalar);
                }
                None
            }
            MetricType::Info => (series_name == fam
                || series_name.strip_prefix(fam) == Some(b"_info"))
            .then_some(SeriesRole::Scalar),
            MetricType::Gauge | MetricType::Stateset | MetricType::Unknown => {
                (series_name == fam).then_some(SeriesRole::Scalar)
            }
        }
    }

    #[inline]
    pub(super) fn emit_into_batch(
        &mut self,
        metrics: &mut MetricTable,
        opts: &DecodeOptions,
        dp_start: u32,
    ) -> Result<u16, DecodeError> {
        if let Some(id) = self.batch_id {
            return Ok(id);
        }

        let m_idx = metrics.len();
        let id = u16::try_from(m_idx).map_err(|_| DecodeError::CapacityOverflow {
            table: "UnivariateMetrics",
            count: m_idx + 1,
        })?;

        let fam_name = self.unescaped_name.as_slice();
        let unit = self.unit.as_slice();
        let inferred_counter = self.metric_type == MetricType::Unknown
            && opts.untyped_policy == UntypedPolicy::InferFromSuffix
            && fam_name.len() > 6
            && fam_name.ends_with(b"_total");
        let is_counter = self.metric_type == MetricType::Counter || inferred_counter;

        let mut base_name = if is_counter && fam_name.len() > 6 && fam_name.ends_with(b"_total") {
            &fam_name[..fam_name.len() - 6]
        } else {
            fam_name
        };

        if opts.unit_suffix_policy == UnitSuffixPolicy::Strip
            && self.has_unit
            && !unit.is_empty()
            && base_name.len() > unit.len() + 1
            && base_name.ends_with(unit)
            && base_name[base_name.len() - unit.len() - 1] == b'_'
        {
            base_name = &base_name[..base_name.len() - unit.len() - 1];
        }

        let append_total = is_counter
            && opts.counter_suffix_policy == CounterSuffixPolicy::Keep
            && self.saw_total_suffix;
        let emitted_name_len = base_name.len() + if append_total { 6 } else { 0 };

        let next_name_len = metrics.name_bytes.len().saturating_add(emitted_name_len);
        let name_end_off =
            i32::try_from(next_name_len).map_err(|_| DecodeError::CapacityOverflow {
                table: "UnivariateMetrics.name",
                count: next_name_len,
            })?;

        let next_desc_len = metrics.desc.check_next_offset(
            self.has_help,
            &self.help,
            "UnivariateMetrics.description",
        )?;
        let next_unit_len =
            metrics
                .unit
                .check_next_offset(self.has_unit, &self.unit, "UnivariateMetrics.unit")?;

        metrics.name_bytes.extend_from_slice(base_name);
        if append_total {
            metrics.name_bytes.extend_from_slice(b"_total");
        }
        metrics.name_offsets.push(name_end_off);

        let (otap_type, attr_type_key, is_monotonic) = match self.metric_type {
            MetricType::Counter => (OTAP_METRIC_TYPE_SUM, 1u16, true),
            MetricType::Gauge => (OTAP_METRIC_TYPE_GAUGE, 2u16, false),
            MetricType::Histogram => (OTAP_METRIC_TYPE_HISTOGRAM, 3u16, false),
            MetricType::GaugeHistogram => (OTAP_METRIC_TYPE_HISTOGRAM, 4u16, false),
            MetricType::Summary => (OTAP_METRIC_TYPE_SUMMARY, 5u16, false),
            MetricType::Info => (OTAP_METRIC_TYPE_GAUGE, 6u16, false),
            MetricType::Stateset => (OTAP_METRIC_TYPE_GAUGE, 7u16, false),
            MetricType::Unknown => {
                if inferred_counter {
                    (OTAP_METRIC_TYPE_SUM, 0u16, true)
                } else {
                    (OTAP_METRIC_TYPE_GAUGE, 0u16, false)
                }
            }
        };

        let has_temporality =
            otap_type == OTAP_METRIC_TYPE_SUM || otap_type == OTAP_METRIC_TYPE_HISTOGRAM;
        let has_sum = otap_type == OTAP_METRIC_TYPE_SUM;

        metrics.metric_types.push(otap_type);
        metrics.is_monotonic.push(is_monotonic);
        metrics.attr_type_keys.push(attr_type_key);
        metrics.dp_ranges.push((dp_start, dp_start));
        metrics.any_temporality |= has_temporality;
        metrics.all_temporality &= has_temporality;
        metrics.any_sum |= has_sum;
        metrics.all_sum &= has_sum;

        metrics
            .desc
            .append_checked(m_idx, next_desc_len, &self.help);
        metrics
            .unit
            .append_checked(m_idx, next_unit_len, &self.unit);

        self.has_samples = true;
        self.batch_id = Some(id);
        Ok(id)
    }
}

/// Sentinel index (`u32::MAX`) marking an empty linked-list pointer or hash-table slot in
/// [`FamilyAssembly`].
const NONE_IDX: u32 = u32::MAX;

/// Multiplicative constant from `rustc-hash` (`FxHasher`) used to hash interned `(key_id, val_id)`
/// attribute slices when indexing [`FamilyAssembly`] groups.
const FX_SEED: u64 = 0x517c_c1b7_2722_0a95;

#[inline]
fn hash_attrs(attrs: &[(u32, u32)]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &(k, v) in attrs {
        let word = (u64::from(k) << 32) | u64::from(v);
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    hash ^ (hash >> 32)
}

#[derive(Clone, Copy)]
pub(super) struct GroupBucket {
    hash: u64,
    group_idx: u32,
}

impl GroupBucket {
    const EMPTY: Self = Self {
        hash: 0,
        group_idx: NONE_IDX,
    };
}

/// Assembled data-point group within the active `Histogram`, `GaugeHistogram`, or `Summary` family.
#[derive(Clone, Copy)]
pub(super) struct PendingDpGroup {
    pub(super) attr_start: u32,
    pub(super) attr_len: u32,
    pub(super) start_ts_ns: Option<i64>,
    pub(super) start_ts_checked: bool,
    pub(super) ts_ns: Option<i64>,
    pub(super) count: Option<u64>,
    pub(super) sum: Option<f64>,
    pub(super) point_head: u32,
    pub(super) point_tail: u32,
    pub(super) exemplar_head: u32,
    pub(super) exemplar_tail: u32,
}

impl PendingDpGroup {
    fn new(attr_start: u32, attr_len: u32) -> Self {
        Self {
            attr_start,
            attr_len,
            start_ts_ns: None,
            start_ts_checked: false,
            ts_ns: None,
            count: None,
            sum: None,
            point_head: NONE_IDX,
            point_tail: NONE_IDX,
            exemplar_head: NONE_IDX,
            exemplar_tail: NONE_IDX,
        }
    }
}

/// Staged bucket or quantile sample linked to a [`PendingDpGroup`].
#[derive(Clone, Copy)]
pub(super) struct PendingPoint {
    pub(super) bound: f64,
    pub(super) value: f64,
    pub(super) next: u32,
}

/// Staged exemplar linked to a [`PendingDpGroup`] within an active `Histogram` or
/// `GaugeHistogram` family.
#[derive(Clone, Copy)]
pub(super) struct PendingExemplar {
    pub(super) ts_ns: i64,
    pub(super) value: f64,
    pub(super) span_id: Option<[u8; 8]>,
    pub(super) trace_id: Option<[u8; 16]>,
    pub(super) attr_start: u32,
    pub(super) attr_len: u32,
    pub(super) next: u32,
}

/// Flat per-family staging buffers used to assemble multi-line `Histogram`, `GaugeHistogram`, and
/// `Summary` families before emitting them into columnar tables.
#[derive(Default)]
pub(super) struct FamilyAssembly {
    pub(super) groups: Vec<PendingDpGroup>,
    pub(super) group_buckets: Vec<GroupBucket>,
    pub(super) group_attrs: Vec<(u32, u32)>,
    pub(super) points: Vec<PendingPoint>,
    pub(super) exemplars: Vec<PendingExemplar>,
    pub(super) exemplar_attrs: Vec<(u32, u32)>,
    pub(super) group_points: Vec<(f64, f64)>,
    pub(super) last_group_idx: Option<usize>,
}

impl FamilyAssembly {
    pub(super) fn clear(&mut self) {
        if !self.groups.is_empty() {
            self.group_buckets.fill(GroupBucket::EMPTY);
        }
        self.groups.clear();
        self.group_attrs.clear();
        self.points.clear();
        self.exemplars.clear();
        self.exemplar_attrs.clear();
        self.group_points.clear();
        self.last_group_idx = None;
    }

    pub(super) fn retained_memory_bytes(&self) -> usize {
        self.groups.capacity() * size_of::<PendingDpGroup>()
            + self.group_buckets.capacity() * size_of::<GroupBucket>()
            + self.group_attrs.capacity() * size_of::<(u32, u32)>()
            + self.points.capacity() * size_of::<PendingPoint>()
            + self.exemplars.capacity() * size_of::<PendingExemplar>()
            + self.exemplar_attrs.capacity() * size_of::<(u32, u32)>()
            + self.group_points.capacity() * size_of::<(f64, f64)>()
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    #[inline]
    pub(super) fn contains_group(&mut self, attrs: &[(u32, u32)]) -> bool {
        if let Some(last_idx) = self.last_group_idx
            && last_idx < self.groups.len()
        {
            let g = self.groups[last_idx];
            let start = g.attr_start as usize;
            let end = start + g.attr_len as usize;
            if self.group_attrs[start..end] == attrs[..] {
                return true;
            }
        }
        if self.groups.is_empty() || self.group_buckets.is_empty() {
            return false;
        }

        let hash = hash_attrs(attrs);
        let mask = self.group_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;
        loop {
            let bucket = self.group_buckets[slot];
            if bucket.group_idx == NONE_IDX {
                return false;
            }
            if bucket.hash == hash {
                let idx = bucket.group_idx as usize;
                let g = self.groups[idx];
                let start = g.attr_start as usize;
                let end = start + g.attr_len as usize;
                if self.group_attrs[start..end] == attrs[..] {
                    self.last_group_idx = Some(idx);
                    return true;
                }
            }
            slot = (slot + 1) & mask;
        }
    }

    #[inline]
    pub(super) fn find_or_create_group(&mut self, attrs: &[(u32, u32)]) -> usize {
        if let Some(last_idx) = self.last_group_idx
            && last_idx < self.groups.len()
        {
            let g = self.groups[last_idx];
            let start = g.attr_start as usize;
            let end = start + g.attr_len as usize;
            if self.group_attrs[start..end] == attrs[..] {
                return last_idx;
            }
        }

        if self.group_buckets.is_empty() {
            self.group_buckets.resize(16, GroupBucket::EMPTY);
        }

        let hash = hash_attrs(attrs);
        let mask = self.group_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;
        loop {
            let bucket = self.group_buckets[slot];
            if bucket.group_idx == NONE_IDX {
                break;
            }
            if bucket.hash == hash {
                let idx = bucket.group_idx as usize;
                let g = self.groups[idx];
                let start = g.attr_start as usize;
                let end = start + g.attr_len as usize;
                if self.group_attrs[start..end] == attrs[..] {
                    self.last_group_idx = Some(idx);
                    return idx;
                }
            }
            slot = (slot + 1) & mask;
        }

        let attr_start = self.group_attrs.len() as u32;
        let attr_len = attrs.len() as u32;
        self.group_attrs.extend_from_slice(attrs);
        let idx = self.groups.len();
        self.groups.push(PendingDpGroup::new(attr_start, attr_len));
        self.group_buckets[slot] = GroupBucket {
            hash,
            group_idx: idx as u32,
        };
        if self.groups.len() * 10 >= self.group_buckets.len() * 7 {
            self.rehash_groups();
        }
        self.last_group_idx = Some(idx);
        idx
    }

    #[cold]
    fn rehash_groups(&mut self) {
        let new_cap = (self.group_buckets.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next_buckets = vec![GroupBucket::EMPTY; new_cap];
        for &bucket in &self.group_buckets {
            if bucket.group_idx == NONE_IDX {
                continue;
            }
            let mut slot = (bucket.hash as usize) & mask;
            while next_buckets[slot].group_idx != NONE_IDX {
                slot = (slot + 1) & mask;
            }
            next_buckets[slot] = bucket;
        }
        self.group_buckets = next_buckets;
    }

    #[inline]
    pub(super) fn push_point(&mut self, group_idx: usize, bound: f64, value: f64) {
        let pt_idx = self.points.len() as u32;
        self.points.push(PendingPoint {
            bound,
            value,
            next: NONE_IDX,
        });
        let group = &mut self.groups[group_idx];
        if group.point_tail == NONE_IDX {
            group.point_head = pt_idx;
        } else {
            self.points[group.point_tail as usize].next = pt_idx;
        }
        group.point_tail = pt_idx;
    }

    #[inline]
    pub(super) fn push_exemplar(
        &mut self,
        group_idx: usize,
        ts_ns: i64,
        value: f64,
        (span_id, trace_id): super::SpanAndTraceId,
        attr_start: u32,
        attr_len: u32,
    ) {
        let ex_idx = self.exemplars.len() as u32;
        self.exemplars.push(PendingExemplar {
            ts_ns,
            value,
            span_id,
            trace_id,
            attr_start,
            attr_len,
            next: NONE_IDX,
        });
        let group = &mut self.groups[group_idx];
        if group.exemplar_tail == NONE_IDX {
            group.exemplar_head = ex_idx;
        } else {
            self.exemplars[group.exemplar_tail as usize].next = ex_idx;
        }
        group.exemplar_tail = ex_idx;
    }

    #[inline]
    fn collect_sorted_group_points(&mut self, point_head: u32) {
        self.group_points.clear();
        let mut sorted = true;
        let mut prev_bound = f64::NEG_INFINITY;
        let mut cur = point_head;
        while cur != NONE_IDX {
            let pt = self.points[cur as usize];
            if pt.bound < prev_bound {
                sorted = false;
            }
            prev_bound = pt.bound;
            self.group_points.push((pt.bound, pt.value));
            cur = pt.next;
        }
        if !sorted {
            self.group_points
                .sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
        }
    }

    pub(super) fn flush(
        &mut self,
        current_family: &mut CurrentFamily,
        metrics: &mut MetricTable,
        sum_dp: &mut SummaryDpTable,
        hist_dp: &mut HistogramDpTable,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        if self.groups.is_empty() {
            return Ok(());
        }

        let dp_start = match current_family.metric_type {
            MetricType::Summary => sum_dp.base.len() as u32,
            _ => hist_dp.base.len() as u32,
        };
        let parent_id = current_family.emit_into_batch(metrics, opts, dp_start)?;
        let num_groups = self.groups.len();

        match current_family.metric_type {
            MetricType::Summary => {
                if sum_dp.quantile_offsets.is_empty() {
                    sum_dp.quantile_offsets.push(0);
                }
                for group_idx in 0..num_groups {
                    let group = self.groups[group_idx];
                    let dp_index = sum_dp.base.len();
                    let dp_id =
                        u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
                            table: "SummaryDataPoints",
                            count: dp_index + 1,
                        })?;

                    let attr_start = group.attr_start as usize;
                    let attr_end = attr_start + group.attr_len as usize;
                    sum_dp
                        .attrs
                        .extend_for_parent(dp_id, &self.group_attrs[attr_start..attr_end]);

                    sum_dp
                        .base
                        .push(parent_id, group.start_ts_ns, group.ts_ns.or(default_ts_ns));
                    sum_dp.counts.push(dp_index, group.count);
                    sum_dp.sums.push(dp_index, group.sum);

                    self.collect_sorted_group_points(group.point_head);
                    for &(q, val) in &self.group_points {
                        sum_dp.quantile_bounds.push(q);
                        sum_dp.quantile_vals.push(val);
                    }
                    let q_off = i32::try_from(sum_dp.quantile_bounds.len()).map_err(|_| {
                        DecodeError::CapacityOverflow {
                            table: "SummaryDataPoints.quantile",
                            count: sum_dp.quantile_bounds.len(),
                        }
                    })?;
                    sum_dp.quantile_offsets.push(q_off);
                }
                metrics.dp_ranges[parent_id as usize].1 = sum_dp.base.len() as u32;
            }
            MetricType::Histogram | MetricType::GaugeHistogram => {
                if hist_dp.bucket_offsets.is_empty() {
                    hist_dp.bucket_offsets.push(0);
                    hist_dp.bounds_offsets.push(0);
                }
                for group_idx in 0..num_groups {
                    let group = self.groups[group_idx];
                    let dp_index = hist_dp.base.len();
                    let dp_id =
                        u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
                            table: "HistogramDataPoints",
                            count: dp_index + 1,
                        })?;

                    let attr_start = group.attr_start as usize;
                    let attr_end = attr_start + group.attr_len as usize;
                    hist_dp
                        .attrs
                        .extend_for_parent(dp_id, &self.group_attrs[attr_start..attr_end]);

                    hist_dp
                        .base
                        .push(parent_id, group.start_ts_ns, group.ts_ns.or(default_ts_ns));

                    self.collect_sorted_group_points(group.point_head);

                    let mut prev_cum = 0u64;
                    let mut inf_cum: Option<u64> = None;
                    for &(bound, cum_f64) in &self.group_points {
                        let cum = f64_to_u64_count(cum_f64);
                        if bound == f64::INFINITY {
                            inf_cum = Some(cum);
                        } else if bound.is_finite() {
                            hist_dp.bounds_vals.push(bound);
                            hist_dp.bucket_counts.push(cum.saturating_sub(prev_cum));
                            prev_cum = cum;
                        }
                    }
                    let final_count = group.count.or(inf_cum);
                    if !self.group_points.is_empty() {
                        let total_for_inf = inf_cum.or(group.count).unwrap_or(prev_cum);
                        hist_dp
                            .bucket_counts
                            .push(total_for_inf.saturating_sub(prev_cum));
                    }

                    let bucket_off = i32::try_from(hist_dp.bucket_counts.len()).map_err(|_| {
                        DecodeError::CapacityOverflow {
                            table: "HistogramDataPoints.histogram_bucket_counts",
                            count: hist_dp.bucket_counts.len(),
                        }
                    })?;
                    let bounds_off = i32::try_from(hist_dp.bounds_vals.len()).map_err(|_| {
                        DecodeError::CapacityOverflow {
                            table: "HistogramDataPoints.histogram_explicit_bounds",
                            count: hist_dp.bounds_vals.len(),
                        }
                    })?;
                    hist_dp.bucket_offsets.push(bucket_off);
                    hist_dp.bounds_offsets.push(bounds_off);

                    hist_dp.counts.push(dp_index, final_count);
                    hist_dp.sums.push(dp_index, group.sum);

                    let mut ex_cur = group.exemplar_head;
                    while ex_cur != NONE_IDX {
                        let ex = self.exemplars[ex_cur as usize];
                        ex_cur = ex.next;
                        let hist_ex_id = hist_dp.exemplars.next_id("HistogramDpExemplars")?;
                        hist_dp.exemplars.push_row(
                            dp_id,
                            ex.ts_ns,
                            ex.value,
                            ex.span_id,
                            ex.trace_id,
                        );
                        let ex_attr_start = ex.attr_start as usize;
                        let ex_attr_end = ex_attr_start + ex.attr_len as usize;
                        hist_dp.exemplars.attrs.extend_for_parent(
                            hist_ex_id,
                            &self.exemplar_attrs[ex_attr_start..ex_attr_end],
                        );
                    }
                }
                metrics.dp_ranges[parent_id as usize].1 = hist_dp.base.len() as u32;
            }
            _ => {}
        }

        self.clear();
        Ok(())
    }
}
