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

//! Prometheus `StaleNaN` detection and cross-scrape per-target series staleness tracking.
//!
//! Prometheus marks disappeared time series with a distinguished quiet IEEE 754 `NaN` bit pattern
//! ([`STALE_NAN_BITS`] / [`STALE_NAN`], matching Go's `model/value.StaleNaN`). In OpenTelemetry
//! and OTAP, stale data points carry [`DATA_POINT_FLAG_NO_RECORDED_VALUE`] (`1`,
//! `DataPointFlags::FLAG_NO_RECORDED_VALUE`) in the optional `flags` (`UInt32`) column on
//! `NumberDataPoints`, `SummaryDataPoints`, and `HistogramDataPoints`.
//!
//! [`StalenessTracker`] maintains the active series set for a single scrape target across
//! consecutive scrapes in arena-backed tables so steady-state scrapes whose series set does not
//! change perform zero heap allocations.

use crate::parse::MetricType;

use super::columns::{HistogramDpTable, MetricTable, NumberDpTable, SummaryDpTable};
use super::family::{CurrentFamily, emit_family_row, hash_attrs};
use super::intern::StringInterner;
use super::options::{DecodeError, DecodeOptions, UntypedPolicy};

/// Raw IEEE 754 `u64` bit pattern of Prometheus's staleness marker (`0x7ff0_0000_0000_0002`),
/// matching `prometheus/prometheus/model/value.StaleNaN`.
///
/// Unlike normal quiet `NaN` (`0x7ff8_0000_0000_0001`), `StaleNaN` clears the MSB of the mantissa
/// (making it a signaling `NaN` bit pattern with payload `2`) to distinguish staleness markers
/// from arithmetic `NaN` results.
pub const STALE_NAN_BITS: u64 = 0x7ff0_0000_0000_0002;

/// IEEE 754 `f64` value with [`STALE_NAN_BITS`] bit representation.
pub const STALE_NAN: f64 = f64::from_bits(STALE_NAN_BITS);

/// OpenTelemetry `DataPointFlags::FLAG_NO_RECORDED_VALUE` bitmask (`1`) indicating a stale data
/// point with no recorded value.
pub const DATA_POINT_FLAG_NO_RECORDED_VALUE: u32 = 1;

/// Returns `true` if `v` has the exact IEEE 754 bit pattern of Prometheus's `StaleNaN` marker
/// ([`STALE_NAN_BITS`]).
#[inline]
#[must_use]
pub const fn is_stale_nan(v: f64) -> bool {
    v.to_bits() == STALE_NAN_BITS
}

/// Sentinel index (`u32::MAX`) marking an unoccupied hash-table slot.
const NONE_IDX: u32 = u32::MAX;

/// Multiplicative constant from `rustc-hash` (`FxHasher`).
const FX_SEED: u64 = 0x517c_c1b7_2722_0a95;

#[inline]
fn fx_hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_le_bytes(*chunk);
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
    for &b in remainder {
        hash = (hash.rotate_left(5) ^ u64::from(b)).wrapping_mul(FX_SEED);
    }
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    hash ^ (hash >> 32)
}

#[inline]
fn hash_series(family_idx: u32, kind: DpKind, attrs: &[(u32, u32)]) -> u64 {
    let mut hash = hash_attrs(attrs);
    let word = (u64::from(family_idx) << 8) | u64::from(kind as u8);
    hash = (hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    hash ^ (hash >> 32)
}

/// OTAP data-point table kind associated with a tracked time series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum DpKind {
    Number = 0,
    Summary = 1,
    Histogram = 2,
}

/// Per-scrape observation status of a [`TrackedSeries`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SeenState {
    Unseen = 0,
    SeenLive = 1,
    SeenStale = 2,
}

#[derive(Clone, Copy)]
struct FamilyBucket {
    hash: u64,
    family_idx: u32,
}

impl FamilyBucket {
    const EMPTY: Self = Self {
        hash: 0,
        family_idx: NONE_IDX,
    };
}

#[derive(Clone, Copy)]
struct SeriesBucket {
    hash: u64,
    series_idx: u32,
}

impl SeriesBucket {
    const EMPTY: Self = Self {
        hash: 0,
        series_idx: NONE_IDX,
    };
}

#[derive(Clone, Copy)]
struct TrackedFamily {
    name_start: u32,
    name_end: u32,
    help_start: u32,
    help_end: u32,
    unit_start: u32,
    unit_end: u32,
    metric_type: MetricType,
    saw_total_suffix: bool,
    has_help: bool,
    has_unit: bool,
    current_batch_id: Option<u16>,
}

#[derive(Clone, Copy)]
struct TrackedSeries {
    family_idx: u32,
    kind: DpKind,
    attr_start: u32,
    attr_len: u32,
    /// Committed active status from the end of the previous successful scrape.
    active: bool,
    /// Observation state during the current in-progress scrape.
    seen: SeenState,
}

/// Reusable per-target series staleness tracker for [`super::ArrowDecoder`].
///
/// `StalenessTracker` records the active time series observed for a single scrape target across
/// consecutive scrapes. When passed to [`super::ArrowDecoder::decode_with_staleness`] or
/// [`super::ArrowDecoder::decode_stream_with_staleness`], any series that was active at the end of
/// the previous scrape and is absent from the current scrape is emitted as a stale data point with
/// `flags = DATA_POINT_FLAG_NO_RECORDED_VALUE` (`1`) and [`STALE_NAN`], and then removed from the
/// active set so subsequent scrapes do not re-emit it.
///
/// All family metadata, label keys, label values, and sorted attribute slices are interned into
/// contiguous arena buffers so steady-state scrapes with a stable series set perform zero heap
/// allocations.
pub struct StalenessTracker {
    families: Vec<TrackedFamily>,
    family_bytes: Vec<u8>,
    family_buckets: Vec<FamilyBucket>,

    key_interner: StringInterner,
    val_interner: StringInterner,

    series: Vec<TrackedSeries>,
    series_attrs: Vec<(u32, u32)>,
    series_buckets: Vec<SeriesBucket>,

    batch_key_to_tracker: Vec<u32>,
    batch_val_to_tracker: Vec<u32>,
    temp_tracker_attrs: Vec<(u32, u32)>,

    active_count: usize,
    stale_cursor: usize,
    scrape_in_progress: bool,
}

impl Default for StalenessTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StalenessTracker {
    /// Creates a new [`StalenessTracker`] with default initial buffer capacities.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(64, 256, 512)
    }

    /// Creates a new [`StalenessTracker`] pre-sized for `families` metric families, `series`
    /// distinct time series, and `attrs` total label pairs.
    #[must_use]
    pub fn with_capacity(families: usize, series: usize, attrs: usize) -> Self {
        let fam_bucket_cap = (families.saturating_mul(2)).next_power_of_two().max(16);
        let ser_bucket_cap = (series.saturating_mul(2)).next_power_of_two().max(16);
        Self {
            families: Vec::with_capacity(families),
            family_bytes: Vec::with_capacity(families.saturating_mul(64)),
            family_buckets: vec![FamilyBucket::EMPTY; fam_bucket_cap],

            key_interner: StringInterner::with_capacity(64, 1024),
            val_interner: StringInterner::with_capacity(256, 4096),

            series: Vec::with_capacity(series),
            series_attrs: Vec::with_capacity(attrs),
            series_buckets: vec![SeriesBucket::EMPTY; ser_bucket_cap],

            batch_key_to_tracker: Vec::with_capacity(64),
            batch_val_to_tracker: Vec::with_capacity(256),
            temp_tracker_attrs: Vec::with_capacity(16),

            active_count: 0,
            stale_cursor: 0,
            scrape_in_progress: false,
        }
    }

    /// Returns the number of currently active (non-stale) time series tracked for the target.
    #[inline]
    #[must_use]
    pub fn active_series_len(&self) -> usize {
        self.active_count
    }

    /// Returns `true` if no active time series are currently tracked for the target.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }

    /// Resets the tracker, clearing all tracked series and family metadata while retaining
    /// allocated buffer capacities.
    pub fn clear(&mut self) {
        self.families.clear();
        self.family_bytes.clear();
        self.family_buckets.fill(FamilyBucket::EMPTY);
        self.key_interner.clear();
        self.val_interner.clear();
        self.series.clear();
        self.series_attrs.clear();
        self.series_buckets.fill(SeriesBucket::EMPTY);
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.temp_tracker_attrs.clear();
        self.active_count = 0;
        self.stale_cursor = 0;
        self.scrape_in_progress = false;
    }

    /// Returns the total heap buffer capacity in bytes currently retained by this tracker.
    #[must_use]
    pub fn retained_memory_bytes(&self) -> usize {
        self.families.capacity() * size_of::<TrackedFamily>()
            + self.family_bytes.capacity()
            + self.family_buckets.capacity() * size_of::<FamilyBucket>()
            + self.key_interner.retained_memory_bytes()
            + self.val_interner.retained_memory_bytes()
            + self.series.capacity() * size_of::<TrackedSeries>()
            + self.series_attrs.capacity() * size_of::<(u32, u32)>()
            + self.series_buckets.capacity() * size_of::<SeriesBucket>()
            + self.batch_key_to_tracker.capacity() * size_of::<u32>()
            + self.batch_val_to_tracker.capacity() * size_of::<u32>()
            + self.temp_tracker_attrs.capacity() * size_of::<(u32, u32)>()
    }

    /// Prepares the tracker for a new scrape.
    ///
    /// If a previous streaming scrape was dropped before completion, any uncommitted per-scrape
    /// observation flags are rolled back first.
    pub(super) fn begin_scrape(&mut self) {
        if self.scrape_in_progress {
            self.abort_scrape();
        }
        for fam in &mut self.families {
            fam.current_batch_id = None;
        }
        for s in &mut self.series {
            s.seen = SeenState::Unseen;
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.stale_cursor = 0;
        self.scrape_in_progress = true;
    }

    /// Clears per-batch metric IDs and interner translation caches across streaming chunk flushes.
    pub(super) fn reset_batch_ids(&mut self) {
        for fam in &mut self.families {
            fam.current_batch_id = None;
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
    }

    /// Rolls back uncommitted observation flags from a failed or early-dropped scrape so the
    /// committed active series set from the previous successful scrape remains intact.
    pub(super) fn abort_scrape(&mut self) {
        if !self.scrape_in_progress {
            return;
        }
        for fam in &mut self.families {
            fam.current_batch_id = None;
        }
        for s in &mut self.series {
            s.seen = SeenState::Unseen;
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.stale_cursor = 0;
        self.scrape_in_progress = false;
    }

    /// Records a data point observed during the current scrape.
    pub(super) fn record_series(
        &mut self,
        current_family: &mut CurrentFamily,
        kind: DpKind,
        batch_attrs: &[(u32, u32)],
        batch_keys: &StringInterner,
        batch_vals: &StringInterner,
        is_stale: bool,
    ) -> Result<(), DecodeError> {
        let fam_idx = self.find_or_insert_family(current_family)?;

        self.temp_tracker_attrs.clear();
        let mut prev_tk: Option<u32> = None;
        let mut sorted = true;

        for &(bk, bv) in batch_attrs {
            while self.batch_key_to_tracker.len() <= bk as usize {
                let next_k = self.batch_key_to_tracker.len() as u32;
                let tk = self
                    .key_interner
                    .intern(batch_keys.get_bytes(next_k))
                    .ok_or_else(|| DecodeError::CapacityOverflow {
                        table: "DpAttrs.key",
                        count: self.key_interner.len(),
                    })?;
                self.batch_key_to_tracker.push(tk);
            }
            while self.batch_val_to_tracker.len() <= bv as usize {
                let next_v = self.batch_val_to_tracker.len() as u32;
                let tv = self
                    .val_interner
                    .intern(batch_vals.get_bytes(next_v))
                    .ok_or_else(|| DecodeError::CapacityOverflow {
                        table: "DpAttrs.str",
                        count: self.val_interner.len(),
                    })?;
                self.batch_val_to_tracker.push(tv);
            }

            let tk = self.batch_key_to_tracker[bk as usize];
            let tv = self.batch_val_to_tracker[bv as usize];
            if let Some(prev) = prev_tk
                && tk < prev
            {
                sorted = false;
            }
            prev_tk = Some(tk);
            self.temp_tracker_attrs.push((tk, tv));
        }

        if !sorted {
            self.temp_tracker_attrs.sort_unstable_by_key(|&(k, _)| k);
        }

        let hash = hash_series(fam_idx, kind, &self.temp_tracker_attrs);
        let mask = self.series_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        let seen_state = if is_stale {
            SeenState::SeenStale
        } else {
            SeenState::SeenLive
        };

        loop {
            let bucket = self.series_buckets[slot];
            if bucket.series_idx == NONE_IDX {
                break;
            }
            if bucket.hash == hash {
                let idx = bucket.series_idx as usize;
                let s = &self.series[idx];
                if s.family_idx == fam_idx && s.kind == kind {
                    let start = s.attr_start as usize;
                    let end = start + s.attr_len as usize;
                    if self.series_attrs[start..end] == self.temp_tracker_attrs[..] {
                        self.series[idx].seen = seen_state;
                        return Ok(());
                    }
                }
            }
            slot = (slot + 1) & mask;
        }

        let attr_start =
            u32::try_from(self.series_attrs.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "StalenessTracker.series_attrs",
                count: self.series_attrs.len(),
            })?;
        let attr_len = u32::try_from(self.temp_tracker_attrs.len()).map_err(|_| {
            DecodeError::CapacityOverflow {
                table: "StalenessTracker.series_attrs",
                count: self.temp_tracker_attrs.len(),
            }
        })?;
        let series_idx =
            u32::try_from(self.series.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "StalenessTracker.series",
                count: self.series.len() + 1,
            })?;
        if series_idx == NONE_IDX {
            return Err(DecodeError::CapacityOverflow {
                table: "StalenessTracker.series",
                count: self.series.len() + 1,
            });
        }

        self.series_attrs
            .extend_from_slice(&self.temp_tracker_attrs);
        self.series.push(TrackedSeries {
            family_idx: fam_idx,
            kind,
            attr_start,
            attr_len,
            active: false,
            seen: seen_state,
        });
        self.series_buckets[slot] = SeriesBucket { hash, series_idx };

        if self.series.len() * 10 >= self.series_buckets.len() * 7 {
            self.rehash_series();
        }
        Ok(())
    }

    #[inline]
    fn find_or_insert_family(
        &mut self,
        current_family: &mut CurrentFamily,
    ) -> Result<u32, DecodeError> {
        if let Some(idx) = current_family.tracker_family_idx {
            let fam = &mut self.families[idx as usize];
            fam.current_batch_id = current_family.batch_id;
            fam.saw_total_suffix |= current_family.saw_total_suffix;
            return Ok(idx);
        }

        let name = current_family.unescaped_name.as_slice();
        let hash = fx_hash_bytes(name);
        let mask = self.family_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        loop {
            let bucket = self.family_buckets[slot];
            if bucket.family_idx == NONE_IDX {
                break;
            }
            if bucket.hash == hash {
                let idx = bucket.family_idx as usize;
                let fam = self.families[idx];
                if &self.family_bytes[fam.name_start as usize..fam.name_end as usize] == name {
                    self.update_existing_family(idx, current_family)?;
                    current_family.tracker_family_idx = Some(bucket.family_idx);
                    return Ok(bucket.family_idx);
                }
            }
            slot = (slot + 1) & mask;
        }

        let (name_start, name_end) = self.append_family_bytes(name)?;
        let (help_start, help_end) = if current_family.has_help {
            self.append_family_bytes(&current_family.help)?
        } else {
            (name_end, name_end)
        };
        let (unit_start, unit_end) = if current_family.has_unit {
            self.append_family_bytes(&current_family.unit)?
        } else {
            (help_end, help_end)
        };

        let family_idx =
            u32::try_from(self.families.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "StalenessTracker.families",
                count: self.families.len() + 1,
            })?;
        if family_idx == NONE_IDX {
            return Err(DecodeError::CapacityOverflow {
                table: "StalenessTracker.families",
                count: self.families.len() + 1,
            });
        }

        self.families.push(TrackedFamily {
            name_start,
            name_end,
            help_start,
            help_end,
            unit_start,
            unit_end,
            metric_type: current_family.metric_type,
            saw_total_suffix: current_family.saw_total_suffix,
            has_help: current_family.has_help,
            has_unit: current_family.has_unit,
            current_batch_id: current_family.batch_id,
        });
        self.family_buckets[slot] = FamilyBucket { hash, family_idx };

        if self.families.len() * 10 >= self.family_buckets.len() * 7 {
            self.rehash_families();
        }
        current_family.tracker_family_idx = Some(family_idx);
        Ok(family_idx)
    }

    #[inline]
    fn update_existing_family(
        &mut self,
        idx: usize,
        current_family: &CurrentFamily,
    ) -> Result<(), DecodeError> {
        let fam = self.families[idx];
        let (help_start, help_end) = if current_family.has_help {
            if fam.has_help
                && &self.family_bytes[fam.help_start as usize..fam.help_end as usize]
                    == current_family.help.as_slice()
            {
                (fam.help_start, fam.help_end)
            } else {
                self.append_family_bytes(&current_family.help)?
            }
        } else {
            (fam.help_start, fam.help_start)
        };

        let (unit_start, unit_end) = if current_family.has_unit {
            if fam.has_unit
                && &self.family_bytes[fam.unit_start as usize..fam.unit_end as usize]
                    == current_family.unit.as_slice()
            {
                (fam.unit_start, fam.unit_end)
            } else {
                self.append_family_bytes(&current_family.unit)?
            }
        } else {
            (fam.unit_start, fam.unit_start)
        };

        let entry = &mut self.families[idx];
        entry.help_start = help_start;
        entry.help_end = help_end;
        entry.unit_start = unit_start;
        entry.unit_end = unit_end;
        entry.metric_type = current_family.metric_type;
        entry.saw_total_suffix = current_family.saw_total_suffix;
        entry.has_help = current_family.has_help;
        entry.has_unit = current_family.has_unit;
        entry.current_batch_id = current_family.batch_id;
        Ok(())
    }

    #[inline]
    fn append_family_bytes(&mut self, slice: &[u8]) -> Result<(u32, u32), DecodeError> {
        let start =
            u32::try_from(self.family_bytes.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "StalenessTracker.family_bytes",
                count: self.family_bytes.len(),
            })?;
        let next_len = self.family_bytes.len().saturating_add(slice.len());
        let end = u32::try_from(next_len).map_err(|_| DecodeError::CapacityOverflow {
            table: "StalenessTracker.family_bytes",
            count: next_len,
        })?;
        self.family_bytes.extend_from_slice(slice);
        Ok((start, end))
    }

    #[cold]
    fn rehash_families(&mut self) {
        let new_cap = (self.family_buckets.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next_buckets = vec![FamilyBucket::EMPTY; new_cap];
        for &bucket in &self.family_buckets {
            if bucket.family_idx == NONE_IDX {
                continue;
            }
            let mut slot = (bucket.hash as usize) & mask;
            while next_buckets[slot].family_idx != NONE_IDX {
                slot = (slot + 1) & mask;
            }
            next_buckets[slot] = bucket;
        }
        self.family_buckets = next_buckets;
    }

    #[cold]
    fn rehash_series(&mut self) {
        let new_cap = (self.series_buckets.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next_buckets = vec![SeriesBucket::EMPTY; new_cap];
        for &bucket in &self.series_buckets {
            if bucket.series_idx == NONE_IDX {
                continue;
            }
            let mut slot = (bucket.hash as usize) & mask;
            while next_buckets[slot].series_idx != NONE_IDX {
                slot = (slot + 1) & mask;
            }
            next_buckets[slot] = bucket;
        }
        self.series_buckets = next_buckets;
    }

    /// Emits stale data points for all previously active series that were not observed during the
    /// current scrape, bounded by `max_data_points` when chunked streaming is active.
    ///
    /// Returns `Ok(true)` if additional stale series remain to be emitted in a subsequent chunk,
    /// or `Ok(false)` once all disappeared series have been emitted and the tracker's active set
    /// has been committed for the completed scrape.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_scrape_step(
        &mut self,
        metrics: &mut MetricTable,
        num_dp: &mut NumberDpTable,
        sum_dp: &mut SummaryDpTable,
        hist_dp: &mut HistogramDpTable,
        batch_keys: &mut StringInterner,
        batch_vals: &mut StringInterner,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
        max_data_points: Option<usize>,
        max_metrics: usize,
    ) -> Result<bool, DecodeError> {
        while self.stale_cursor < self.series.len() {
            let idx = self.stale_cursor;
            let s = self.series[idx];
            if !s.active || s.seen != SeenState::Unseen {
                self.stale_cursor += 1;
                continue;
            }

            let fam = self.families[s.family_idx as usize];
            if fam.metric_type == MetricType::Unknown && opts.untyped_policy == UntypedPolicy::Drop
            {
                self.series[idx].active = false;
                self.stale_cursor += 1;
                continue;
            }

            if let Some(max_dps) = max_data_points {
                let current_dps = num_dp.base.len() + sum_dp.base.len() + hist_dp.base.len();
                let need_new_metric = fam.current_batch_id.is_none();
                if current_dps >= max_dps || (need_new_metric && metrics.len() >= max_metrics) {
                    return Ok(true);
                }
            }

            self.emit_single_stale_series(
                s,
                metrics,
                num_dp,
                sum_dp,
                hist_dp,
                batch_keys,
                batch_vals,
                opts,
                default_ts_ns,
            )?;
            self.series[idx].active = false;
            self.stale_cursor += 1;
        }

        // All disappeared series have been emitted; commit the new active set for the next scrape.
        let mut active_count = 0usize;
        for s in &mut self.series {
            match s.seen {
                SeenState::SeenLive => {
                    s.active = true;
                    active_count += 1;
                }
                SeenState::SeenStale => {
                    s.active = false;
                }
                SeenState::Unseen => {}
            }
            s.seen = SeenState::Unseen;
        }
        for fam in &mut self.families {
            fam.current_batch_id = None;
        }
        self.active_count = active_count;
        self.stale_cursor = 0;
        self.scrape_in_progress = false;
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_single_stale_series(
        &mut self,
        s: TrackedSeries,
        metrics: &mut MetricTable,
        num_dp: &mut NumberDpTable,
        sum_dp: &mut SummaryDpTable,
        hist_dp: &mut HistogramDpTable,
        batch_keys: &mut StringInterner,
        batch_vals: &mut StringInterner,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let fam_idx = s.family_idx as usize;
        let parent_id = if let Some(id) = self.families[fam_idx].current_batch_id {
            id
        } else {
            let fam = self.families[fam_idx];
            let id = emit_family_row(
                &self.family_bytes[fam.name_start as usize..fam.name_end as usize],
                fam.metric_type,
                fam.saw_total_suffix,
                fam.has_help,
                &self.family_bytes[fam.help_start as usize..fam.help_end as usize],
                fam.has_unit,
                &self.family_bytes[fam.unit_start as usize..fam.unit_end as usize],
                metrics,
                opts,
            )?;
            self.families[fam_idx].current_batch_id = Some(id);
            id
        };

        let attr_start = s.attr_start as usize;
        let attr_end = attr_start + s.attr_len as usize;
        self.temp_tracker_attrs.clear();
        let mut prev_bk: Option<u32> = None;
        let mut sorted = true;

        for &(tk, tv) in &self.series_attrs[attr_start..attr_end] {
            let bk = batch_keys
                .intern(self.key_interner.get_bytes(tk))
                .ok_or_else(|| DecodeError::CapacityOverflow {
                    table: "DpAttrs.key",
                    count: batch_keys.len(),
                })?;
            let bv = batch_vals
                .intern(self.val_interner.get_bytes(tv))
                .ok_or_else(|| DecodeError::CapacityOverflow {
                    table: "DpAttrs.str",
                    count: batch_vals.len(),
                })?;
            if let Some(prev) = prev_bk
                && bk < prev
            {
                sorted = false;
            }
            prev_bk = Some(bk);
            self.temp_tracker_attrs.push((bk, bv));
        }

        if !sorted {
            self.temp_tracker_attrs.sort_unstable_by_key(|&(k, _)| k);
        }

        match s.kind {
            DpKind::Number => {
                let dp_index = num_dp.base.len();
                let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
                    table: "NumberDataPoints",
                    count: dp_index + 1,
                })?;
                num_dp
                    .attrs
                    .extend_for_parent(dp_id, &self.temp_tracker_attrs);
                num_dp.base.push_with_flags(
                    parent_id,
                    None,
                    default_ts_ns,
                    DATA_POINT_FLAG_NO_RECORDED_VALUE,
                );
                num_dp.values.push(STALE_NAN);
            }
            DpKind::Summary => {
                if sum_dp.quantile_offsets.is_empty() {
                    sum_dp.quantile_offsets.push(0);
                }
                let dp_index = sum_dp.base.len();
                let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
                    table: "SummaryDataPoints",
                    count: dp_index + 1,
                })?;
                sum_dp
                    .attrs
                    .extend_for_parent(dp_id, &self.temp_tracker_attrs);
                sum_dp.base.push_with_flags(
                    parent_id,
                    None,
                    default_ts_ns,
                    DATA_POINT_FLAG_NO_RECORDED_VALUE,
                );
                sum_dp.counts.push(dp_index, Some(0));
                sum_dp.sums.push(dp_index, Some(STALE_NAN));
                let q_off = i32::try_from(sum_dp.quantile_bounds.len()).map_err(|_| {
                    DecodeError::CapacityOverflow {
                        table: "SummaryDataPoints.quantile",
                        count: sum_dp.quantile_bounds.len(),
                    }
                })?;
                sum_dp.quantile_offsets.push(q_off);
            }
            DpKind::Histogram => {
                if hist_dp.bucket_offsets.is_empty() {
                    hist_dp.bucket_offsets.push(0);
                    hist_dp.bounds_offsets.push(0);
                }
                let dp_index = hist_dp.base.len();
                let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
                    table: "HistogramDataPoints",
                    count: dp_index + 1,
                })?;
                hist_dp
                    .attrs
                    .extend_for_parent(dp_id, &self.temp_tracker_attrs);
                hist_dp.base.push_with_flags(
                    parent_id,
                    None,
                    default_ts_ns,
                    DATA_POINT_FLAG_NO_RECORDED_VALUE,
                );
                hist_dp.counts.push(dp_index, Some(0));
                hist_dp.sums.push(dp_index, Some(STALE_NAN));
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
            }
        }
        Ok(())
    }
}
