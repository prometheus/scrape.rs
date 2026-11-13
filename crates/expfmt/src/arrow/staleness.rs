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
//! Prometheus marks disappeared time series with a distinguished signaling IEEE 754 `NaN` bit
//! pattern ([`STALE_NAN_BITS`] / [`STALE_NAN`], matching Go's `model/value.StaleNaN`). In
//! OpenTelemetry and OTAP, stale data points carry [`DATA_POINT_FLAG_NO_RECORDED_VALUE`] (`1`,
//! `DataPointFlags::FLAG_NO_RECORDED_VALUE`) in the optional `flags` (`UInt32`) column on
//! `NumberDataPoints`, `SummaryDataPoints`, and `HistogramDataPoints`.
//!
//! [`StalenessTracker`] maintains the active series set for a single scrape target across
//! consecutive scrapes in arena-backed tables so steady-state scrapes whose series set does not
//! change perform zero heap allocations.

use std::time::{Duration, Instant};

use crate::parse::MetricType;

use super::columns::{HistogramDpTable, MetricTable, NumberDpTable, SummaryDpTable};
use super::family::{CurrentFamily, emit_family_row, hash_attrs};
use super::intern::{StringInterner, bucket_capacity_for_len};
use super::options::{
    DECODE_BUDGET_DURATION_CHECK_INTERVAL, DecodeError, DecodeOptions, UntypedPolicy,
};

/// Raw IEEE 754 `u64` bit pattern of Prometheus's staleness marker (`0x7ff0_0000_0000_0002`),
/// matching `prometheus/prometheus/model/value.StaleNaN`.
///
/// Unlike normal quiet `NaN` (`0x7ff8_0000_0000_0001`), `StaleNaN` clears the MSB of the mantissa
/// (making it a signaling `NaN` bit pattern with payload `2`) to distinguish staleness markers
/// from arithmetic `NaN` results.
pub const STALE_NAN_BITS: u64 = 0x7ff0_0000_0000_0002;

/// IEEE 754 `f64` value with [`STALE_NAN_BITS`] bit representation.
///
/// NOTE: Because [`STALE_NAN_BITS`] clears the MSB of the mantissa (making it a signaling `NaN`),
/// floating-point arithmetic operations may quietize bit 51 under IEEE 754 / Rust float semantics.
/// Move this value bitwise (`from_bits` / `to_bits`) and inspect it with [`is_stale_nan`] rather
/// than passing it through arithmetic expressions.
pub const STALE_NAN: f64 = f64::from_bits(STALE_NAN_BITS);

/// OpenTelemetry `DataPointFlags::FLAG_NO_RECORDED_VALUE` bitmask (`1`) indicating a stale data
/// point with no recorded value.
pub const DATA_POINT_FLAG_NO_RECORDED_VALUE: u32 = 1;

/// Returns `true` if `v` has the exact IEEE 754 bit pattern of Prometheus's `StaleNaN` marker
/// ([`STALE_NAN_BITS`]).
///
/// Inspects raw bits via `f64::to_bits`; callers must avoid performing arithmetic on `v` prior to
/// calling this function because arithmetic on signaling `NaN`s may quietize the mantissa MSB.
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
const fn metric_type_tag(mt: MetricType) -> u8 {
    match mt {
        MetricType::Unknown => 0,
        MetricType::Counter => 1,
        MetricType::Gauge => 2,
        MetricType::Histogram => 3,
        MetricType::GaugeHistogram => 4,
        MetricType::Summary => 5,
        MetricType::Info => 6,
        MetricType::Stateset => 7,
    }
}

#[inline]
fn hash_family_key(name: &[u8], metric_type: MetricType, saw_total_suffix: bool) -> u32 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let (chunks, remainder) = name.as_chunks::<8>();
    for chunk in chunks {
        let word = u64::from_le_bytes(*chunk);
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
    for &b in remainder {
        hash = (hash.rotate_left(5) ^ u64::from(b)).wrapping_mul(FX_SEED);
    }
    let tag = (u64::from(metric_type_tag(metric_type)) << 1) | u64::from(saw_total_suffix);
    hash = (hash.rotate_left(5) ^ tag).wrapping_mul(FX_SEED);
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    (hash ^ (hash >> 32)) as u32
}

#[inline]
const fn hash_series_with_attr_hash(family_idx: u32, kind: DpKind, attr_hash: u64) -> u32 {
    let word = ((family_idx as u64) << 8) | (kind as u64);
    let mut hash = (attr_hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    hash ^= hash >> 32;
    hash = hash.wrapping_mul(FX_SEED);
    (hash ^ (hash >> 32)) as u32
}

#[inline]
const fn fold_u64_hash(hash: u64) -> u32 {
    (hash ^ (hash >> 32)) as u32
}

/// Outcome of a bounded EOF stale-series drain step in [`StalenessTracker::finish_scrape_step`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StaleDrainStep {
    /// The cooperative step budget expired while scanning/emitting disappeared series; yield
    /// [`super::DecodeStep::Pending`] and resume from `stale_cursor` on the next step.
    YieldPending,
    /// The active streaming chunk reached `max_data_points` or `max_metrics`; finalize this chunk
    /// and continue draining remaining stale series in the next chunk.
    ChunkFull,
    /// All disappeared series have been staged into the current batch.
    Complete,
}

/// OTAP data-point table kind associated with a tracked time series.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum DpKind {
    Number = 0,
    Summary = 1,
    Histogram = 2,
}

impl DpKind {
    #[inline]
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Number,
            1 => Self::Summary,
            _ => Self::Histogram,
        }
    }
}

/// Per-scrape observation status of a [`TrackedSeries`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SeenState {
    Unseen = 0,
    SeenLive = 1,
    SeenStale = 2,
}

impl SeenState {
    #[inline]
    const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Unseen,
            1 => Self::SeenLive,
            _ => Self::SeenStale,
        }
    }
}

#[derive(Clone, Copy)]
struct FamilyBucket {
    hash: u32,
    family_idx: u32,
}

const _: () = assert!(size_of::<FamilyBucket>() == 8);

impl FamilyBucket {
    const EMPTY: Self = Self {
        hash: 0,
        family_idx: NONE_IDX,
    };
}

/// Slice descriptor into [`StalenessTracker::series_attrs`] for a deduplicated label set.
///
/// Many metric families exposed by the same target share identical label sets (for example
/// container, pod, filesystem, or synthetic benchmark series labels). Interning sorted `(tk, tv)`
/// slices once per unique label set avoids repeating identical attribute pairs across every metric
/// family while keeping each [`TrackedSeries`] entry down to 8 bytes.
#[derive(Clone, Copy)]
struct AttrSetEntry {
    start: u32,
    len: u32,
}

const _: () = assert!(size_of::<AttrSetEntry>() == 8);

#[derive(Clone, Copy)]
struct AttrSetBucket {
    hash: u32,
    attr_set_id: u32,
}

const _: () = assert!(size_of::<AttrSetBucket>() == 8);

impl AttrSetBucket {
    const EMPTY: Self = Self {
        hash: 0,
        attr_set_id: NONE_IDX,
    };
}

#[derive(Clone, Copy)]
struct SeriesBucket {
    hash: u32,
    series_idx: u32,
}

const _: () = assert!(size_of::<SeriesBucket>() == 8);

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
    pending_help_start: u32,
    pending_help_end: u32,
    pending_unit_start: u32,
    pending_unit_end: u32,
    metric_type: MetricType,
    saw_total_suffix: bool,
    has_help: bool,
    has_unit: bool,
    pending_has_help: bool,
    pending_has_unit: bool,
    has_pending_meta: bool,
    current_batch_id: Option<u16>,
}

const MAX_FAMILY_IDX: u32 = (1 << 27) - 1;
const KIND_SHIFT: u32 = 27;
const KIND_MASK: u32 = 0b11;
const ACTIVE_BIT: u32 = 1 << 29;
const SEEN_SHIFT: u32 = 30;
const SEEN_MASK: u32 = 0b11;

/// Compact 8-byte descriptor for a tracked time series.
#[derive(Clone, Copy)]
struct TrackedSeries {
    /// Bit-packed metadata:
    /// - bits `0..27`: `family_idx` (`0..=MAX_FAMILY_IDX`)
    /// - bits `27..29`: [`DpKind`] (`0..=2`)
    /// - bit `29`: committed `active` status from the previous successful scrape
    /// - bits `30..32`: [`SeenState`] (`0..=2`) during the current in-progress scrape
    packed: u32,
    /// Index into [`StalenessTracker::attr_sets`].
    attr_set_id: u32,
}

const _: () = assert!(size_of::<TrackedSeries>() == 8);

impl TrackedSeries {
    #[inline]
    const fn new(
        family_idx: u32,
        kind: DpKind,
        attr_set_id: u32,
        active: bool,
        seen: SeenState,
    ) -> Self {
        let active_bits = if active { ACTIVE_BIT } else { 0 };
        let packed = (family_idx & MAX_FAMILY_IDX)
            | ((kind as u32) << KIND_SHIFT)
            | active_bits
            | ((seen as u32) << SEEN_SHIFT);
        Self {
            packed,
            attr_set_id,
        }
    }

    #[inline]
    const fn family_idx(self) -> u32 {
        self.packed & MAX_FAMILY_IDX
    }

    #[inline]
    const fn kind(self) -> DpKind {
        DpKind::from_u8(((self.packed >> KIND_SHIFT) & KIND_MASK) as u8)
    }

    #[inline]
    const fn active(self) -> bool {
        (self.packed & ACTIVE_BIT) != 0
    }

    #[inline]
    const fn seen(self) -> SeenState {
        SeenState::from_u8(((self.packed >> SEEN_SHIFT) & SEEN_MASK) as u8)
    }

    #[inline]
    fn set_seen(&mut self, seen: SeenState) {
        self.packed = (self.packed & !(SEEN_MASK << SEEN_SHIFT)) | ((seen as u32) << SEEN_SHIFT);
    }

    #[inline]
    fn clear_seen(&mut self) {
        self.packed &= !(SEEN_MASK << SEEN_SHIFT);
    }

    /// Sets `active = (seen == SeenLive)`, resets `seen = Unseen`, and returns the new `active`
    /// flag.
    #[inline]
    fn commit_seen(&mut self) -> bool {
        let live = self.seen() == SeenState::SeenLive;
        let active_mask = if live { ACTIVE_BIT } else { 0 };
        self.packed = (self.packed & !(ACTIVE_BIT | (SEEN_MASK << SEEN_SHIFT))) | active_mask;
        live
    }
}

/// Reusable per-target series staleness tracker for [`super::ArrowDecoder`].
///
/// `StalenessTracker` records the active time series observed for a single scrape target across
/// consecutive scrapes. When passed to [`super::ArrowDecoder::decode_with_staleness`] or
/// [`super::ArrowDecoder::decode_stream_with_staleness`], any series that was active at the end of
/// the previous scrape and is absent from the current scrape is emitted as a stale data point with
/// `flags = DATA_POINT_FLAG_NO_RECORDED_VALUE` (`1`), and then removed from the active set so
/// subsequent scrapes do not re-emit it.
///
/// # Memory model and optional usage
///
/// Emitting a stale OTAP data point when a series disappears from a target's exposition requires
/// retaining that target's active metric names and interned label sets across scrapes (mirroring
/// Go Prometheus's per-target `scrapeCache`). Because retaining per-target active series consumes
/// live heap proportional to the target's active series count, staleness tracking is strictly
/// opt-in: callers that do not need scrape-time staleness markers can call
/// [`super::ArrowDecoder::decode`] or [`super::ArrowDecoder::decode_stream`] with zero cross-scrape
/// series retention.
///
/// All family metadata, label keys, label values, and sorted attribute slices are interned into
/// contiguous arena buffers so steady-state scrapes with a stable series set perform zero heap
/// allocations. Under label churn, [`StalenessTracker`] automatically compacts deactivated series,
/// unreferenced families, and unreferenced interned strings (and clears arenas when active series
/// drop to zero) so retained live heap stays bounded by the currently active series set rather than
/// cumulative historical cardinality.
pub struct StalenessTracker {
    families: Vec<TrackedFamily>,
    family_bytes: Vec<u8>,
    family_buckets: Vec<FamilyBucket>,

    key_interner: StringInterner,
    val_interner: StringInterner,

    attr_sets: Vec<AttrSetEntry>,
    attr_set_buckets: Vec<AttrSetBucket>,
    series_attrs: Vec<(u32, u32)>,

    series: Vec<TrackedSeries>,
    series_buckets: Vec<SeriesBucket>,

    batch_key_to_tracker: Vec<u32>,
    batch_val_to_tracker: Vec<u32>,
    temp_tracker_attrs: Vec<(u32, u32)>,

    active_count: usize,
    stale_cursor: usize,
    active_scrape_id: u64,
}

impl Default for StalenessTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StalenessTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StalenessTracker")
            .field("active_series_len", &self.active_series_len())
            .field("retained_memory_bytes", &self.retained_memory_bytes())
            .finish_non_exhaustive()
    }
}

impl StalenessTracker {
    /// Creates an empty [`StalenessTracker`] that performs zero heap allocations until its first
    /// non-empty scrape.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            families: Vec::new(),
            family_bytes: Vec::new(),
            family_buckets: Vec::new(),

            key_interner: StringInterner::new(),
            val_interner: StringInterner::new(),

            attr_sets: Vec::new(),
            attr_set_buckets: Vec::new(),
            series_attrs: Vec::new(),

            series: Vec::new(),
            series_buckets: Vec::new(),

            batch_key_to_tracker: Vec::new(),
            batch_val_to_tracker: Vec::new(),
            temp_tracker_attrs: Vec::new(),

            active_count: 0,
            stale_cursor: 0,
            active_scrape_id: 0,
        }
    }

    /// Creates a new [`StalenessTracker`] pre-sized for `families` metric families, `series`
    /// distinct time series, and `attrs` total label pairs.
    #[must_use]
    pub fn with_capacity(families: usize, series: usize, attrs: usize) -> Self {
        if families == 0 && series == 0 && attrs == 0 {
            return Self::new();
        }
        let fam_bucket_cap = bucket_capacity_for_len(families).max(16);
        let ser_bucket_cap = bucket_capacity_for_len(series).max(16);
        let attr_set_cap = series.min(attrs.max(1));
        let attr_set_bucket_cap = bucket_capacity_for_len(attr_set_cap).max(16);
        Self {
            families: Vec::with_capacity(families),
            family_bytes: Vec::with_capacity(families.saturating_mul(32)),
            family_buckets: vec![FamilyBucket::EMPTY; fam_bucket_cap],

            key_interner: StringInterner::with_capacity(families.min(64), families * 8),
            val_interner: StringInterner::with_capacity(series.min(256), attrs * 8),

            attr_sets: Vec::with_capacity(attr_set_cap),
            attr_set_buckets: vec![AttrSetBucket::EMPTY; attr_set_bucket_cap],
            series_attrs: Vec::with_capacity(attrs),

            series: Vec::with_capacity(series),
            series_buckets: vec![SeriesBucket::EMPTY; ser_bucket_cap],

            batch_key_to_tracker: Vec::with_capacity(families.min(64)),
            batch_val_to_tracker: Vec::with_capacity(series.min(256)),
            temp_tracker_attrs: Vec::with_capacity(16),

            active_count: 0,
            stale_cursor: 0,
            active_scrape_id: 0,
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
        self.attr_sets.clear();
        self.attr_set_buckets.fill(AttrSetBucket::EMPTY);
        self.series_attrs.clear();
        self.series.clear();
        self.series_buckets.fill(SeriesBucket::EMPTY);
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.temp_tracker_attrs.clear();
        self.active_count = 0;
        self.stale_cursor = 0;
        self.active_scrape_id = 0;
    }

    /// Returns the total heap buffer capacity in bytes currently retained by this tracker.
    #[must_use]
    pub fn retained_memory_bytes(&self) -> usize {
        self.families.capacity() * size_of::<TrackedFamily>()
            + self.family_bytes.capacity()
            + self.family_buckets.capacity() * size_of::<FamilyBucket>()
            + self.key_interner.retained_memory_bytes()
            + self.val_interner.retained_memory_bytes()
            + self.attr_sets.capacity() * size_of::<AttrSetEntry>()
            + self.attr_set_buckets.capacity() * size_of::<AttrSetBucket>()
            + self.series_attrs.capacity() * size_of::<(u32, u32)>()
            + self.series.capacity() * size_of::<TrackedSeries>()
            + self.series_buckets.capacity() * size_of::<SeriesBucket>()
            + self.batch_key_to_tracker.capacity() * size_of::<u32>()
            + self.batch_val_to_tracker.capacity() * size_of::<u32>()
            + self.temp_tracker_attrs.capacity() * size_of::<(u32, u32)>()
    }

    #[inline]
    pub(super) const fn active_scrape_id(&self) -> u64 {
        self.active_scrape_id
    }

    /// Prepares the tracker for a new scrape identified by `scrape_id`.
    ///
    /// If a previous streaming scrape was dropped before completion, any uncommitted per-scrape
    /// observation flags are rolled back first.
    pub(super) fn begin_scrape(&mut self, scrape_id: u64) {
        if self.active_scrape_id != 0 {
            self.abort_scrape();
        }
        for fam in &mut self.families {
            fam.current_batch_id = None;
            fam.has_pending_meta = false;
        }
        for s in &mut self.series {
            s.clear_seen();
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.stale_cursor = 0;
        self.active_scrape_id = scrape_id;
    }

    /// Clears per-batch metric IDs and interner translation caches across streaming chunk flushes.
    pub(super) fn reset_batch_ids(&mut self) {
        for fam in &mut self.families {
            fam.current_batch_id = None;
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
    }

    /// Rolls back uncommitted observation flags and staged family metadata from a failed or
    /// early-dropped scrape so the committed active series set from the previous successful scrape
    /// remains intact.
    pub(super) fn abort_scrape(&mut self) {
        if self.active_scrape_id == 0 {
            return;
        }
        for fam in &mut self.families {
            fam.current_batch_id = None;
            fam.has_pending_meta = false;
        }
        for s in &mut self.series {
            s.clear_seen();
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.stale_cursor = 0;
        self.active_scrape_id = 0;
        self.reclaim_or_compact_inactive();
    }

    /// Commits staged family metadata and updates the active series set once all chunks and
    /// `RecordBatch` finalizations for the scrape have succeeded.
    pub(super) fn commit_scrape(&mut self) {
        let mut active_count = 0usize;
        for s in &mut self.series {
            if s.commit_seen() {
                active_count += 1;
            }
        }
        for fam in &mut self.families {
            if fam.has_pending_meta {
                fam.help_start = fam.pending_help_start;
                fam.help_end = fam.pending_help_end;
                fam.unit_start = fam.pending_unit_start;
                fam.unit_end = fam.pending_unit_end;
                fam.has_help = fam.pending_has_help;
                fam.has_unit = fam.pending_has_unit;
                fam.has_pending_meta = false;
            }
            fam.current_batch_id = None;
        }
        self.batch_key_to_tracker.clear();
        self.batch_val_to_tracker.clear();
        self.active_count = active_count;
        self.stale_cursor = 0;
        self.active_scrape_id = 0;
        self.reclaim_or_compact_inactive();
    }

    /// Releases excess capacity or compacts inactive entries when `self.series` or `self.families`
    /// have grown beyond the committed `self.active_count`.
    #[inline]
    fn reclaim_or_compact_inactive(&mut self) {
        let active_count = self.active_count;
        if active_count == 0 {
            if self.series.capacity() > 64 || self.families.capacity() > 64 {
                *self = Self::new();
            } else {
                self.clear();
            }
        } else {
            let inactive_series = self.series.len().saturating_sub(active_count);
            // Any deactivated series has already emitted its stale marker during
            // `finish_scrape_step` and is never needed again. Compact as soon as deactivated
            // series exceed 12.5% of active series (minimum 32), avoiding 2x dead-series retention
            // after label churn or hourly rotations while keeping steady-state scrapes free of
            // compaction work.
            let churn_threshold = (active_count >> 3).max(32);
            if inactive_series >= churn_threshold
                || self.families.len() > active_count.saturating_mul(2).max(64)
                || self.attr_sets.len() > active_count.saturating_add(churn_threshold)
            {
                self.compact();
            } else if self.series.capacity() > self.series.len() + (self.series.len() >> 3).max(32)
                || self.series_attrs.capacity()
                    > self.series_attrs.len() + (self.series_attrs.len() >> 3).max(64)
            {
                self.shrink_arenas_to_fit();
            }
        }
    }

    /// Trims unused `Vec` doubling tail capacity in place after the initial scrape population
    /// without rebuilding hash tables when no series were deactivated.
    #[cold]
    fn shrink_arenas_to_fit(&mut self) {
        self.families.shrink_to_fit();
        self.family_bytes.shrink_to_fit();
        self.key_interner.shrink_to_fit();
        self.val_interner.shrink_to_fit();
        self.attr_sets.shrink_to_fit();
        self.series_attrs.shrink_to_fit();
        self.series.shrink_to_fit();
    }

    /// Rebuilds the tracker's family, interner, label-set, and series arenas containing only
    /// currently `active` series so deactivated series under label churn do not accumulate
    /// unbounded memory or linear-scan overhead.
    #[cold]
    fn compact(&mut self) {
        let active_count = self.active_count;
        let mut fam_remap = vec![NONE_IDX; self.families.len()];
        let mut attr_set_remap = vec![NONE_IDX; self.attr_sets.len()];
        let mut key_remap = vec![NONE_IDX; self.key_interner.len()];
        let mut val_remap = vec![NONE_IDX; self.val_interner.len()];

        let mut next_families: Vec<TrackedFamily> =
            Vec::with_capacity(self.families.len().min(active_count));
        let mut next_family_bytes: Vec<u8> = Vec::new();
        let mut next_keys = StringInterner::with_capacity(
            self.key_interner.len().min(active_count.saturating_mul(4)),
            0,
        );
        let mut next_vals =
            StringInterner::with_capacity(active_count.min(self.val_interner.len()), 0);

        let mut next_attr_sets: Vec<AttrSetEntry> =
            Vec::with_capacity(self.attr_sets.len().min(active_count));
        let mut next_series_attrs: Vec<(u32, u32)> = Vec::new();

        let ser_bucket_cap = bucket_capacity_for_len(active_count).max(16);
        let mut next_series = Vec::with_capacity(active_count);
        let mut next_series_buckets = vec![SeriesBucket::EMPTY; ser_bucket_cap];
        let ser_mask = ser_bucket_cap - 1;

        for idx in 0..self.series.len() {
            let s = self.series[idx];
            if !s.active() {
                continue;
            }

            let old_fam_idx = s.family_idx() as usize;
            let new_fam_idx = if fam_remap[old_fam_idx] != NONE_IDX {
                fam_remap[old_fam_idx]
            } else {
                let fam = self.families[old_fam_idx];
                let name = &self.family_bytes[fam.name_start as usize..fam.name_end as usize];
                let name_start = next_family_bytes.len() as u32;
                next_family_bytes.extend_from_slice(name);
                let name_end = next_family_bytes.len() as u32;

                let (help_start, help_end) = if fam.has_help {
                    let h = &self.family_bytes[fam.help_start as usize..fam.help_end as usize];
                    let hs = next_family_bytes.len() as u32;
                    next_family_bytes.extend_from_slice(h);
                    (hs, next_family_bytes.len() as u32)
                } else {
                    (name_end, name_end)
                };

                let (unit_start, unit_end) = if fam.has_unit {
                    let u = &self.family_bytes[fam.unit_start as usize..fam.unit_end as usize];
                    let us = next_family_bytes.len() as u32;
                    next_family_bytes.extend_from_slice(u);
                    (us, next_family_bytes.len() as u32)
                } else {
                    (help_end, help_end)
                };

                let new_idx = next_families.len() as u32;
                next_families.push(TrackedFamily {
                    name_start,
                    name_end,
                    help_start,
                    help_end,
                    unit_start,
                    unit_end,
                    pending_help_start: help_start,
                    pending_help_end: help_end,
                    pending_unit_start: unit_start,
                    pending_unit_end: unit_end,
                    metric_type: fam.metric_type,
                    saw_total_suffix: fam.saw_total_suffix,
                    has_help: fam.has_help,
                    has_unit: fam.has_unit,
                    pending_has_help: fam.has_help,
                    pending_has_unit: fam.has_unit,
                    has_pending_meta: false,
                    current_batch_id: None,
                });
                fam_remap[old_fam_idx] = new_idx;
                new_idx
            };

            let old_attr_set_id = s.attr_set_id as usize;
            let new_attr_set_id = if attr_set_remap[old_attr_set_id] != NONE_IDX {
                attr_set_remap[old_attr_set_id]
            } else {
                let old_entry = self.attr_sets[old_attr_set_id];
                let attr_start = old_entry.start as usize;
                let attr_end = attr_start + old_entry.len as usize;
                self.temp_tracker_attrs.clear();
                let mut prev_nk: Option<u32> = None;
                let mut sorted = true;

                for &(tk, tv) in &self.series_attrs[attr_start..attr_end] {
                    let tk_idx = tk as usize;
                    let nk = if key_remap[tk_idx] != NONE_IDX {
                        key_remap[tk_idx]
                    } else {
                        let id = next_keys
                            .intern(self.key_interner.get_bytes(tk))
                            .expect("compacted key bytes <= existing interner bytes");
                        key_remap[tk_idx] = id;
                        id
                    };

                    let tv_idx = tv as usize;
                    let nv = if val_remap[tv_idx] != NONE_IDX {
                        val_remap[tv_idx]
                    } else {
                        let id = next_vals
                            .intern(self.val_interner.get_bytes(tv))
                            .expect("compacted val bytes <= existing interner bytes");
                        val_remap[tv_idx] = id;
                        id
                    };

                    if let Some(prev) = prev_nk
                        && nk < prev
                    {
                        sorted = false;
                    }
                    prev_nk = Some(nk);
                    self.temp_tracker_attrs.push((nk, nv));
                }

                if !sorted {
                    self.temp_tracker_attrs.sort_unstable_by_key(|&(k, _)| k);
                }

                let new_attr_start = next_series_attrs.len() as u32;
                let new_attr_len = self.temp_tracker_attrs.len() as u32;
                next_series_attrs.extend_from_slice(&self.temp_tracker_attrs);

                let id = next_attr_sets.len() as u32;
                next_attr_sets.push(AttrSetEntry {
                    start: new_attr_start,
                    len: new_attr_len,
                });
                attr_set_remap[old_attr_set_id] = id;
                id
            };

            let new_entry = next_attr_sets[new_attr_set_id as usize];
            let attr_slice = &next_series_attrs
                [new_entry.start as usize..(new_entry.start + new_entry.len) as usize];
            let attr_hash64 = hash_attrs(attr_slice);
            let kind = s.kind();

            let new_series_idx = next_series.len() as u32;
            next_series.push(TrackedSeries::new(
                new_fam_idx,
                kind,
                new_attr_set_id,
                true,
                SeenState::Unseen,
            ));

            let hash = hash_series_with_attr_hash(new_fam_idx, kind, attr_hash64);
            let mut slot = (hash as usize) & ser_mask;
            while next_series_buckets[slot].series_idx != NONE_IDX {
                slot = (slot + 1) & ser_mask;
            }
            next_series_buckets[slot] = SeriesBucket {
                hash,
                series_idx: new_series_idx,
            };
        }

        let attr_set_bucket_cap = bucket_capacity_for_len(next_attr_sets.len()).max(16);
        let attr_set_mask = attr_set_bucket_cap - 1;
        let mut next_attr_set_buckets = vec![AttrSetBucket::EMPTY; attr_set_bucket_cap];
        for (idx, entry) in next_attr_sets.iter().enumerate() {
            let slice =
                &next_series_attrs[entry.start as usize..(entry.start + entry.len) as usize];
            let hash = fold_u64_hash(hash_attrs(slice));
            let mut slot = (hash as usize) & attr_set_mask;
            while next_attr_set_buckets[slot].attr_set_id != NONE_IDX {
                slot = (slot + 1) & attr_set_mask;
            }
            next_attr_set_buckets[slot] = AttrSetBucket {
                hash,
                attr_set_id: idx as u32,
            };
        }

        let fam_bucket_cap = bucket_capacity_for_len(next_families.len()).max(16);
        let fam_mask = fam_bucket_cap - 1;
        let mut next_family_buckets = vec![FamilyBucket::EMPTY; fam_bucket_cap];
        for (idx, fam) in next_families.iter().enumerate() {
            let name = &next_family_bytes[fam.name_start as usize..fam.name_end as usize];
            let hash = hash_family_key(name, fam.metric_type, fam.saw_total_suffix);
            let mut slot = (hash as usize) & fam_mask;
            while next_family_buckets[slot].family_idx != NONE_IDX {
                slot = (slot + 1) & fam_mask;
            }
            next_family_buckets[slot] = FamilyBucket {
                hash,
                family_idx: idx as u32,
            };
        }

        next_families.shrink_to_fit();
        next_family_bytes.shrink_to_fit();
        next_keys.shrink_to_fit();
        next_vals.shrink_to_fit();
        next_attr_sets.shrink_to_fit();
        next_series_attrs.shrink_to_fit();
        next_series.shrink_to_fit();

        self.families = next_families;
        self.family_bytes = next_family_bytes;
        self.family_buckets = next_family_buckets;
        self.key_interner = next_keys;
        self.val_interner = next_vals;
        self.attr_sets = next_attr_sets;
        self.attr_set_buckets = next_attr_set_buckets;
        self.series_attrs = next_series_attrs;
        self.series = next_series;
        self.series_buckets = next_series_buckets;
        if self.batch_key_to_tracker.capacity() > self.key_interner.len().saturating_mul(4).max(64)
        {
            self.batch_key_to_tracker.shrink_to(64);
        }
        if self.batch_val_to_tracker.capacity() > self.val_interner.len().saturating_mul(4).max(256)
        {
            self.batch_val_to_tracker
                .shrink_to(self.val_interner.len().saturating_mul(2).max(64));
        }
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
            // Map only the batch IDs actually referenced by series attributes (`NONE_IDX` marks
            // unmapped slots) so ephemeral exemplar labels in `batch_keys`/`batch_vals` are never
            // copied into the tracker's persistent interners.
            let bk_idx = bk as usize;
            if bk_idx >= self.batch_key_to_tracker.len() {
                self.batch_key_to_tracker.resize(bk_idx + 1, NONE_IDX);
            }
            let mut tk = self.batch_key_to_tracker[bk_idx];
            if tk == NONE_IDX {
                tk = self
                    .key_interner
                    .intern(batch_keys.get_bytes(bk))
                    .ok_or_else(|| DecodeError::CapacityOverflow {
                        table: "DpAttrs.key",
                        count: self.key_interner.len(),
                    })?;
                self.batch_key_to_tracker[bk_idx] = tk;
            }

            let bv_idx = bv as usize;
            if bv_idx >= self.batch_val_to_tracker.len() {
                self.batch_val_to_tracker.resize(bv_idx + 1, NONE_IDX);
            }
            let mut tv = self.batch_val_to_tracker[bv_idx];
            if tv == NONE_IDX {
                tv = self
                    .val_interner
                    .intern(batch_vals.get_bytes(bv))
                    .ok_or_else(|| DecodeError::CapacityOverflow {
                        table: "DpAttrs.str",
                        count: self.val_interner.len(),
                    })?;
                self.batch_val_to_tracker[bv_idx] = tv;
            }

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

        if self.series_buckets.is_empty() {
            self.series_buckets.resize(16, SeriesBucket::EMPTY);
        }
        let attr_hash64 = hash_attrs(&self.temp_tracker_attrs);
        let hash = hash_series_with_attr_hash(fam_idx, kind, attr_hash64);
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
                let s = self.series[idx];
                if s.family_idx() == fam_idx && s.kind() == kind {
                    let entry = self.attr_sets[s.attr_set_id as usize];
                    let start = entry.start as usize;
                    let end = start + entry.len as usize;
                    if self.series_attrs[start..end] == self.temp_tracker_attrs[..] {
                        self.series[idx].set_seen(seen_state);
                        return Ok(());
                    }
                }
            }
            slot = (slot + 1) & mask;
        }

        let attr_set_id = self.find_or_insert_attr_set(fold_u64_hash(attr_hash64))?;

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

        self.series.push(TrackedSeries::new(
            fam_idx,
            kind,
            attr_set_id,
            false,
            seen_state,
        ));
        self.series_buckets[slot] = SeriesBucket { hash, series_idx };

        if self.series.len() * 10 >= self.series_buckets.len() * 7 {
            self.rehash_series();
        }
        Ok(())
    }

    #[inline]
    fn find_or_insert_attr_set(&mut self, hash: u32) -> Result<u32, DecodeError> {
        if self.attr_set_buckets.is_empty() {
            self.attr_set_buckets.resize(16, AttrSetBucket::EMPTY);
        }
        let mask = self.attr_set_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        loop {
            let bucket = self.attr_set_buckets[slot];
            if bucket.attr_set_id == NONE_IDX {
                break;
            }
            if bucket.hash == hash {
                let entry = self.attr_sets[bucket.attr_set_id as usize];
                let start = entry.start as usize;
                let end = start + entry.len as usize;
                if self.series_attrs[start..end] == self.temp_tracker_attrs[..] {
                    return Ok(bucket.attr_set_id);
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
        let attr_set_id =
            u32::try_from(self.attr_sets.len()).map_err(|_| DecodeError::CapacityOverflow {
                table: "StalenessTracker.series_attrs",
                count: self.attr_sets.len() + 1,
            })?;
        if attr_set_id == NONE_IDX {
            return Err(DecodeError::CapacityOverflow {
                table: "StalenessTracker.series_attrs",
                count: self.attr_sets.len() + 1,
            });
        }

        self.series_attrs
            .extend_from_slice(&self.temp_tracker_attrs);
        self.attr_sets.push(AttrSetEntry {
            start: attr_start,
            len: attr_len,
        });
        self.attr_set_buckets[slot] = AttrSetBucket { hash, attr_set_id };

        if self.attr_sets.len() * 10 >= self.attr_set_buckets.len() * 7 {
            self.rehash_attr_sets();
        }
        Ok(attr_set_id)
    }

    /// Synchronizes an existing tracked family's active batch row ID and pending `# HELP` /
    /// `# UNIT` metadata when a family emits a sample in the current batch that is not itself
    /// recorded in the tracker (e.g. an explicit-timestamp sample when
    /// `!opts.track_timestamps_staleness`). Does not insert a new family if it is not already
    /// tracked.
    #[inline]
    pub(super) fn sync_existing_family(
        &mut self,
        current_family: &mut CurrentFamily,
    ) -> Result<(), DecodeError> {
        let (name, metric_type, saw_total_suffix) = current_family.canonical_key();
        if let Some(idx) = current_family.tracker_family_idx
            && let Some(fam) = self.families.get_mut(idx as usize)
            && fam.metric_type == metric_type
            && fam.saw_total_suffix == saw_total_suffix
        {
            fam.current_batch_id = current_family.batch_id;
            return Ok(());
        }

        if self.family_buckets.is_empty() {
            return Ok(());
        }
        let hash = hash_family_key(name, metric_type, saw_total_suffix);
        let mask = self.family_buckets.len() - 1;
        let mut slot = (hash as usize) & mask;

        loop {
            let bucket = self.family_buckets[slot];
            if bucket.family_idx == NONE_IDX {
                return Ok(());
            }
            if bucket.hash == hash {
                let idx = bucket.family_idx as usize;
                let fam = self.families[idx];
                if fam.metric_type == metric_type
                    && fam.saw_total_suffix == saw_total_suffix
                    && &self.family_bytes[fam.name_start as usize..fam.name_end as usize] == name
                {
                    self.update_existing_family(idx, current_family)?;
                    current_family.tracker_family_idx = Some(bucket.family_idx);
                    return Ok(());
                }
            }
            slot = (slot + 1) & mask;
        }
    }

    #[inline]
    fn find_or_insert_family(
        &mut self,
        current_family: &mut CurrentFamily,
    ) -> Result<u32, DecodeError> {
        let (name, metric_type, saw_total_suffix) = current_family.canonical_key();
        if let Some(idx) = current_family.tracker_family_idx
            && let Some(fam) = self.families.get_mut(idx as usize)
            && fam.metric_type == metric_type
            && fam.saw_total_suffix == saw_total_suffix
        {
            fam.current_batch_id = current_family.batch_id;
            return Ok(idx);
        }

        if self.family_buckets.is_empty() {
            self.family_buckets.resize(16, FamilyBucket::EMPTY);
        }
        let hash = hash_family_key(name, metric_type, saw_total_suffix);
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
                if fam.metric_type == metric_type
                    && fam.saw_total_suffix == saw_total_suffix
                    && &self.family_bytes[fam.name_start as usize..fam.name_end as usize] == name
                {
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
        if family_idx > MAX_FAMILY_IDX {
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
            pending_help_start: help_start,
            pending_help_end: help_end,
            pending_unit_start: unit_start,
            pending_unit_end: unit_end,
            metric_type,
            saw_total_suffix,
            has_help: false,
            has_unit: false,
            pending_has_help: current_family.has_help,
            pending_has_unit: current_family.has_unit,
            has_pending_meta: true,
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
            if &self.family_bytes[fam.help_start as usize..fam.help_end as usize]
                == current_family.help.as_slice()
            {
                (fam.help_start, fam.help_end)
            } else {
                self.append_family_bytes(&current_family.help)?
            }
        } else {
            (fam.help_start, fam.help_end)
        };

        let (unit_start, unit_end) = if current_family.has_unit {
            if &self.family_bytes[fam.unit_start as usize..fam.unit_end as usize]
                == current_family.unit.as_slice()
            {
                (fam.unit_start, fam.unit_end)
            } else {
                self.append_family_bytes(&current_family.unit)?
            }
        } else {
            (fam.unit_start, fam.unit_end)
        };

        let entry = &mut self.families[idx];
        entry.pending_help_start = help_start;
        entry.pending_help_end = help_end;
        entry.pending_unit_start = unit_start;
        entry.pending_unit_end = unit_end;
        entry.pending_has_help = current_family.has_help;
        entry.pending_has_unit = current_family.has_unit;
        entry.has_pending_meta = true;
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
    fn rehash_attr_sets(&mut self) {
        let new_cap = (self.attr_set_buckets.len() * 2).max(16);
        let mask = new_cap - 1;
        let mut next_buckets = vec![AttrSetBucket::EMPTY; new_cap];
        for &bucket in &self.attr_set_buckets {
            if bucket.attr_set_id == NONE_IDX {
                continue;
            }
            let mut slot = (bucket.hash as usize) & mask;
            while next_buckets[slot].attr_set_id != NONE_IDX {
                slot = (slot + 1) & mask;
            }
            next_buckets[slot] = bucket;
        }
        self.attr_set_buckets = next_buckets;
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
    /// current scrape, bounded by `max_data_points` when chunked streaming is active and by
    /// `step_budget` (`(remaining_entries, started, max_duration)`) when cooperative budgeting is
    /// active.
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
        step_budget: Option<(usize, Instant, Duration)>,
    ) -> Result<StaleDrainStep, DecodeError> {
        let mut steps = 0usize;
        while self.stale_cursor < self.series.len() {
            if let Some((rem_entries, _, _)) = step_budget
                && rem_entries == 0
            {
                return Ok(StaleDrainStep::YieldPending);
            }

            let idx = self.stale_cursor;
            let s = self.series[idx];
            if !s.active() || s.seen() != SeenState::Unseen {
                self.stale_cursor += 1;
            } else {
                let fam = self.families[s.family_idx() as usize];
                if fam.metric_type == MetricType::Unknown
                    && opts.untyped_policy == UntypedPolicy::Drop
                {
                    self.stale_cursor += 1;
                } else {
                    if let Some(max_dps) = max_data_points {
                        let current_dps =
                            num_dp.base.len() + sum_dp.base.len() + hist_dp.base.len();
                        let need_new_metric = fam.current_batch_id.is_none();
                        if current_dps >= max_dps
                            || (need_new_metric && metrics.len() >= max_metrics)
                        {
                            return Ok(StaleDrainStep::ChunkFull);
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
                    self.stale_cursor += 1;
                }
            }

            if let Some((rem_entries, started, max_duration)) = step_budget {
                steps += 1;
                if self.stale_cursor < self.series.len() {
                    let duration_exceeded = (max_duration.is_zero()
                        || steps.is_multiple_of(DECODE_BUDGET_DURATION_CHECK_INTERVAL))
                        && started.elapsed() >= max_duration;
                    if steps >= rem_entries || duration_exceeded {
                        return Ok(StaleDrainStep::YieldPending);
                    }
                }
            }
        }

        Ok(StaleDrainStep::Complete)
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
        let fam_idx = s.family_idx() as usize;
        let parent_id = if let Some(id) = self.families[fam_idx].current_batch_id {
            id
        } else {
            let fam = self.families[fam_idx];
            let (has_help, help_start, help_end, has_unit, unit_start, unit_end) =
                if fam.has_pending_meta {
                    (
                        fam.pending_has_help,
                        fam.pending_help_start,
                        fam.pending_help_end,
                        fam.pending_has_unit,
                        fam.pending_unit_start,
                        fam.pending_unit_end,
                    )
                } else {
                    (
                        fam.has_help,
                        fam.help_start,
                        fam.help_end,
                        fam.has_unit,
                        fam.unit_start,
                        fam.unit_end,
                    )
                };
            let id = emit_family_row(
                &self.family_bytes[fam.name_start as usize..fam.name_end as usize],
                fam.metric_type,
                fam.saw_total_suffix,
                has_help,
                &self.family_bytes[help_start as usize..help_end as usize],
                has_unit,
                &self.family_bytes[unit_start as usize..unit_end as usize],
                metrics,
                opts,
            )?;
            self.families[fam_idx].current_batch_id = Some(id);
            id
        };

        let attr_entry = self.attr_sets[s.attr_set_id as usize];
        let attr_start = attr_entry.start as usize;
        let attr_end = attr_start + attr_entry.len as usize;
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

        match s.kind() {
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
                num_dp.values.push(dp_index, None);
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
                sum_dp.sums.push(dp_index, Some(0.0));
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
                hist_dp.sums.push(dp_index, None);
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
