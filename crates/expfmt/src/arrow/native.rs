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

//! Conversion of parsed native histograms into OTAP histogram columns.
//!
//! Each conversion makes one pass over the sparse buckets, writes straight into the reused
//! column buffers, and applies the checks of Go's
//! [`Histogram.Validate`](https://github.com/prometheus/prometheus/blob/v0.315.1/model/histogram/histogram.go#L426)
//! and `FloatHistogram.Validate` on the way. Prometheus runs `Validate` when it appends a
//! scraped histogram, and an invalid histogram fails the whole scrape, so a check failure here
//! is a [`DecodeError::InvalidHistogram`].

use crate::parse::{Histogram, HistogramRef, Span};

use super::columns::{ExpBucketsCol, ExpHistogramDpTable, HistogramDpTable, f64_to_u64_count};
use super::family::CurrentFamily;
use super::options::DecodeError;
use super::staleness::is_stale_nan;

/// Go's `histogram.CustomBucketsSchema`, the schema of a native histogram with custom buckets
/// (NHCB).
pub(super) const CUSTOM_BUCKETS_SCHEMA: i32 = -53;

/// Go's `histogram.ExponentialSchemaMin` and `histogram.ExponentialSchemaMax`.
pub(super) const EXPONENTIAL_SCHEMAS: std::ops::RangeInclusive<i32> = -4..=8;

/// Dense buckets one side of an exponential histogram may always use, the default `MaxSize` of
/// the OpenTelemetry SDK's exponential histogram.
const MIN_DENSE_BUCKET_LIMIT: u64 = 160;

/// Dense buckets one side may use per sparse bucket on top of [`MIN_DENSE_BUCKET_LIMIT`], so the
/// dense lists grow at most linearly with the input.
const DENSE_BUCKETS_PER_SPARSE_BUCKET: u64 = 8;

const EXPONENTIAL_CUSTOM_BOUNDS: &str =
    "histogram with exponential schema must not have custom bounds";

/// Bucket counts of one side of a native histogram.
#[derive(Clone, Copy)]
pub(super) enum Buckets<'h> {
    /// Delta-encoded integer counts, Go's `Histogram`.
    Delta(&'h [i64]),
    /// Absolute float counts, Go's `FloatHistogram`.
    Absolute(&'h [f64]),
}

impl Buckets<'_> {
    fn len(self) -> usize {
        match self {
            Self::Delta(buckets) => buckets.len(),
            Self::Absolute(buckets) => buckets.len(),
        }
    }
}

/// Integer and float native histograms behind one shape, with counts as `u64`.
pub(super) struct NativeView<'h> {
    pub(super) schema: i32,
    pub(super) zero_threshold: f64,
    pub(super) sum: f64,
    pub(super) count: u64,
    pub(super) zero_count: u64,
    /// `true` if the zero count as sent is not 0. A float zero count below 1 or NaN converts
    /// to a `zero_count` of 0, but Go still rejects it on custom buckets.
    pub(super) has_zero_count: bool,
    /// `true` for a float histogram, which is only validated and then dropped.
    pub(super) is_float: bool,
    pub(super) positive_spans: &'h [Span],
    pub(super) positive: Buckets<'h>,
    pub(super) negative_spans: &'h [Span],
    pub(super) negative: Buckets<'h>,
    pub(super) custom_values: &'h [f64],
}

impl<'h> NativeView<'h> {
    /// Returns the view of `histogram`, or the reason Go's `FloatHistogram.Validate` rejects a
    /// negative float count.
    pub(super) fn new(histogram: HistogramRef<'h>) -> Result<Self, String> {
        match histogram {
            HistogramRef::Int(h) => Ok(Self::with_counts(
                h,
                h.count,
                h.zero_count,
                h.zero_count != 0,
                false,
                Buckets::Delta(&h.positive_buckets),
                Buckets::Delta(&h.negative_buckets),
            )),
            HistogramRef::Float(h) => {
                if h.count < 0.0 {
                    return Err(format!("histogram has negative count: {}", h.count));
                }
                if h.zero_count < 0.0 {
                    return Err(format!(
                        "histogram has negative zero count: {}",
                        h.zero_count
                    ));
                }
                Ok(Self::with_counts(
                    h,
                    f64_to_u64_count(h.count),
                    f64_to_u64_count(h.zero_count),
                    h.zero_count != 0.0,
                    true,
                    Buckets::Absolute(&h.positive_buckets),
                    Buckets::Absolute(&h.negative_buckets),
                ))
            }
        }
    }

    fn with_counts<C, B>(
        h: &'h Histogram<C, B>,
        count: u64,
        zero_count: u64,
        has_zero_count: bool,
        is_float: bool,
        positive: Buckets<'h>,
        negative: Buckets<'h>,
    ) -> Self {
        Self {
            schema: h.schema,
            zero_threshold: h.zero_threshold,
            sum: h.sum,
            count,
            zero_count,
            has_zero_count,
            is_float,
            positive_spans: &h.positive_spans,
            positive,
            negative_spans: &h.negative_spans,
            negative,
            custom_values: &h.custom_values,
        }
    }

    /// Go's count check for integer histograms: the buckets must add up to `count`, or to at
    /// most `count` when the sum is NaN.
    fn check_count(&self, bucket_total: u64) -> Result<(), String> {
        if self.sum.is_nan() {
            if bucket_total > self.count {
                return Err(format!(
                    "{} observations found in buckets, but the Count field is {}: histogram's \
                     observation count should be at least the number of observations found in \
                     the buckets",
                    bucket_total, self.count
                ));
            }
        } else if bucket_total != self.count {
            return Err(format!(
                "{} observations found in buckets, but the Count field is {}: histogram's \
                 observation count should equal the number of observations found in the \
                 buckets (in absence of NaN)",
                bucket_total, self.count
            ));
        }
        Ok(())
    }
}

/// Walks the buckets of one side in index order and calls `visit(index, count)` with absolute
/// counts. Indexes follow Go: the first span's offset is the index of its first bucket, later
/// offsets are gaps.
///
/// Applies Go's `checkHistogramSpans` and `checkHistogramBuckets`, and returns the total count
/// of the side, wrapping like Go's `uint64`.
pub(super) fn walk_buckets(
    side: &str,
    spans: &[Span],
    buckets: Buckets<'_>,
    mut visit: impl FnMut(i64, u64),
) -> Result<u64, String> {
    let mut span_buckets = 0u64;
    for (n, span) in spans.iter().enumerate() {
        if n > 0 && span.offset < 0 {
            return Err(format!(
                "{side} side: span number {} with offset {}: histogram has a span whose offset \
                 is negative",
                n + 1,
                span.offset
            ));
        }
        span_buckets += u64::from(span.length);
    }
    if span_buckets != buckets.len() as u64 {
        return Err(format!(
            "{side} side: spans need {span_buckets} buckets, have {} buckets: histogram spans \
             specify different number of buckets than provided",
            buckets.len()
        ));
    }

    let mut total = 0u64;
    let mut index = 0i64;
    let mut bucket = 0usize;
    let mut current = 0i64;
    for span in spans {
        index += i64::from(span.offset);
        for _ in 0..span.length {
            let count = match buckets {
                Buckets::Delta(deltas) => {
                    current = current.wrapping_add(deltas[bucket]);
                    if current < 0 {
                        return Err(negative_bucket(side, bucket, current as f64));
                    }
                    current as u64
                }
                Buckets::Absolute(counts) => {
                    let count = counts[bucket];
                    if count < 0.0 {
                        return Err(negative_bucket(side, bucket, count));
                    }
                    f64_to_u64_count(count)
                }
            };
            visit(index, count);
            total = total.wrapping_add(count);
            index += 1;
            bucket += 1;
        }
    }
    Ok(total)
}

#[cold]
fn negative_bucket(side: &str, bucket: usize, count: f64) -> String {
    format!(
        "{side} side: bucket number {} has observation count of {count}: histogram has a bucket \
         whose observation count is negative",
        bucket + 1
    )
}

#[cold]
pub(super) fn invalid_histogram(family: &CurrentFamily, reason: String) -> DecodeError {
    DecodeError::InvalidHistogram {
        metric: family.name_string(),
        reason,
    }
}

/// Appends a native histogram with custom buckets (NHCB) to `dp` as an explicit-bucket
/// histogram data point: the custom values become the explicit bounds, followed by one dense
/// count per bucket including `+Inf`. A stale NaN sum leaves the count zero, the sum null, and
/// the buckets and bounds empty, like a stale classic histogram from the text loop.
///
/// `dp_index` is the row of the data point, whose base columns the caller appends. The caller
/// drops float histograms.
pub(super) fn push_custom_buckets(
    dp: &mut HistogramDpTable,
    dp_index: usize,
    histogram: &NativeView<'_>,
    family: &CurrentFamily,
) -> Result<(), DecodeError> {
    debug_assert!(!histogram.is_float);
    check_custom_buckets(histogram).map_err(|reason| invalid_histogram(family, reason))?;

    if dp.bucket_offsets.is_empty() {
        dp.bucket_offsets.push(0);
        dp.bounds_offsets.push(0);
    }
    let bounds = histogram.custom_values;
    let (spans, buckets) = (histogram.positive_spans, histogram.positive);
    let stale = is_stale_nan(histogram.sum);
    // A stale point is only checked and writes no buckets.
    let total = if stale {
        walk_buckets("positive", spans, buckets, |_, _| {})
    } else {
        let start = dp.bucket_counts.len();
        dp.bucket_counts.resize(start + bounds.len() + 1, 0);
        let counts = &mut dp.bucket_counts[start..];
        // `check_custom_buckets` keeps every index within `0..=bounds.len()`.
        walk_buckets("positive", spans, buckets, |index, count| {
            counts[index as usize] = count;
        })
    };
    total
        .and_then(|total| histogram.check_count(total))
        .map_err(|reason| invalid_histogram(family, reason))?;

    if !stale {
        dp.bounds_vals.extend_from_slice(bounds);
    }
    let bucket_off =
        i32::try_from(dp.bucket_counts.len()).map_err(|_| DecodeError::CapacityOverflow {
            table: "HistogramDataPoints.histogram_bucket_counts",
            count: dp.bucket_counts.len(),
        })?;
    let bounds_off =
        i32::try_from(dp.bounds_vals.len()).map_err(|_| DecodeError::CapacityOverflow {
            table: "HistogramDataPoints.histogram_explicit_bounds",
            count: dp.bounds_vals.len(),
        })?;
    dp.bucket_offsets.push(bucket_off);
    dp.bounds_offsets.push(bounds_off);
    if stale {
        dp.counts.push(dp_index, Some(0));
        dp.sums.push(dp_index, None);
    } else {
        dp.counts.push(dp_index, Some(histogram.count));
        dp.sums.push(dp_index, Some(histogram.sum));
    }
    Ok(())
}

/// The custom-bucket checks of Go's `Validate`, except the per-bucket checks that
/// [`walk_buckets`] does.
fn check_custom_buckets(histogram: &NativeView<'_>) -> Result<(), String> {
    check_custom_bounds(histogram.custom_values, histogram.positive_spans)?;
    if histogram.has_zero_count {
        return Err("custom buckets: must have zero count of 0".to_owned());
    }
    if histogram.zero_threshold != 0.0 {
        return Err("custom buckets: must have zero threshold of 0".to_owned());
    }
    if !histogram.negative_spans.is_empty() {
        return Err("custom buckets: must not have negative spans".to_owned());
    }
    if histogram.negative.len() != 0 {
        return Err("custom buckets: must not have negative buckets".to_owned());
    }
    Ok(())
}

/// Range of bucket indexes at `schema` whose buckets hold float64 values, per Go's
/// `getBoundExponential`.
///
/// The highest index is the bucket that ends at `math.MaxFloat64`; the next one is the
/// overflow bucket for `±Inf`. The lowest index is the bucket of the smallest subnormal,
/// `2^-1074`. The bounds of buckets outside the range are outside the float64 range.
fn exponential_index_range(schema: i32) -> (i64, i64) {
    debug_assert!(EXPONENTIAL_SCHEMAS.contains(&schema));
    if schema >= 0 {
        (-1074 << schema, 1024 << schema)
    } else {
        (-(1074 >> -schema), 1024 >> -schema)
    }
}

/// Go's `FloatHistogram.Validate` for a float histogram, which the caller then drops: the
/// custom-bucket checks for NHCB or no custom bounds for an exponential schema, then valid
/// spans and no negative buckets. Like Go, it does not check the count against the buckets.
pub(super) fn check_float_histogram(histogram: &NativeView<'_>) -> Result<(), String> {
    debug_assert!(histogram.is_float);
    if histogram.schema == CUSTOM_BUCKETS_SCHEMA {
        check_custom_buckets(histogram)?;
    } else if !histogram.custom_values.is_empty() {
        return Err(EXPONENTIAL_CUSTOM_BOUNDS.to_owned());
    }
    walk_buckets(
        "positive",
        histogram.positive_spans,
        histogram.positive,
        |_, _| {},
    )?;
    walk_buckets(
        "negative",
        histogram.negative_spans,
        histogram.negative,
        |_, _| {},
    )?;
    Ok(())
}

/// Appends an exponential native histogram (schema -4 to 8) to `dp` as an OTAP exponential
/// histogram data point, per the OpenTelemetry Prometheus compatibility spec: `scale` is the
/// schema, the sparse spans become one dense list per side whose offset is the first index
/// minus one, and buckets outside the float64 range are dropped and not counted. A stale NaN
/// sum leaves the counts, scale and zero threshold zero, the sum null, and the buckets empty.
///
/// A side whose dense list would be wider than [`dense_bucket_limit`] lowers the scale and
/// merges adjacent buckets until it fits, like Prometheus's `native_histogram_bucket_limit`,
/// so a few sparse buckets far apart cannot make the decoder allocate a huge list.
///
/// The caller drops float histograms, which the spec does not map, and appends the base
/// columns, with the no-recorded-value flag for a stale point.
pub(super) fn push_exponential(
    dp: &mut ExpHistogramDpTable,
    histogram: &NativeView<'_>,
    family: &CurrentFamily,
) -> Result<(), DecodeError> {
    debug_assert!(!histogram.is_float);
    if !histogram.custom_values.is_empty() {
        return Err(invalid_histogram(
            family,
            EXPONENTIAL_CUSTOM_BOUNDS.to_owned(),
        ));
    }
    // Prometheus writes the stale NaN into the sum of a stale native histogram.
    let stale = is_stale_nan(histogram.sum);
    let range = exponential_index_range(histogram.schema);
    let shift = downscale_shift(
        histogram.schema,
        [
            (
                kept_index_bounds(histogram.positive_spans, range),
                histogram.positive.len(),
            ),
            (
                kept_index_bounds(histogram.negative_spans, range),
                histogram.negative.len(),
            ),
        ],
    );
    let (positive_total, positive_kept) = push_dense_side(
        &mut dp.positive,
        "positive",
        histogram.positive_spans,
        histogram.positive,
        range,
        shift,
        stale,
        family,
    )?;
    let (negative_total, negative_kept) = push_dense_side(
        &mut dp.negative,
        "negative",
        histogram.negative_spans,
        histogram.negative,
        range,
        shift,
        stale,
        family,
    )?;
    histogram
        .check_count(
            positive_total
                .wrapping_add(negative_total)
                .wrapping_add(histogram.zero_count),
        )
        .map_err(|reason| invalid_histogram(family, reason))?;

    if stale {
        // Same values as the stale points the tracker appends; the buckets are already empty.
        dp.sums.push_null(dp.counts.len());
        dp.counts.push(0);
        dp.scales.push(0);
        dp.zero_counts.push(0);
        dp.zero_thresholds.push(0.0);
    } else {
        dp.sums.push_value(histogram.sum);
        dp.counts.push(
            histogram
                .zero_count
                .wrapping_add(positive_kept)
                .wrapping_add(negative_kept),
        );
        dp.scales.push(histogram.schema - shift as i32);
        dp.zero_counts.push(histogram.zero_count);
        dp.zero_thresholds.push(histogram.zero_threshold);
    }
    Ok(())
}

/// Dense buckets a side with `sparse_buckets` buckets may use before it is downscaled.
fn dense_bucket_limit(sparse_buckets: usize) -> u64 {
    MIN_DENSE_BUCKET_LIMIT
        .max(DENSE_BUCKETS_PER_SPARSE_BUCKET.saturating_mul(sparse_buckets as u64))
}

/// Lowest and highest index within `range` that `spans` cover, or `None` if they cover none.
///
/// It only reads the spans, before [`walk_buckets`] checks them, so it takes the extremes of
/// every span instead of relying on their order.
fn kept_index_bounds(spans: &[Span], (min_index, max_index): (i64, i64)) -> Option<(i64, i64)> {
    let mut bounds: Option<(i64, i64)> = None;
    let mut index = 0i64;
    for span in spans {
        index = index.saturating_add(i64::from(span.offset));
        if span.length > 0 {
            let first = index.max(min_index);
            let last = index
                .saturating_add(i64::from(span.length) - 1)
                .min(max_index);
            if first <= last {
                bounds =
                    Some(bounds.map_or((first, last), |(lo, hi)| (lo.min(first), hi.max(last))));
            }
        }
        index = index.saturating_add(i64::from(span.length));
    }
    bounds
}

/// OTel index of the bucket that holds Prometheus bucket `index` after lowering the scale by
/// `shift`. Prometheus bucket `index` is OTel bucket `index - 1`, and lowering the scale by one
/// merges OTel buckets `2i` and `2i + 1` into bucket `i`.
fn otel_index(index: i64, shift: u32) -> i64 {
    (index - 1) >> shift
}

/// How far to lower `schema` so that every side fits its [`dense_bucket_limit`]. Each side is
/// the `kept_index_bounds` of its spans and its sparse bucket count.
fn downscale_shift(schema: i32, sides: [(Option<(i64, i64)>, usize); 2]) -> u32 {
    let too_wide = |shift: u32| {
        sides.iter().any(|&(bounds, sparse_buckets)| {
            bounds.is_some_and(|(first, last)| {
                let width = otel_index(last, shift) - otel_index(first, shift) + 1;
                width as u64 > dense_bucket_limit(sparse_buckets)
            })
        })
    };
    let mut shift = 0;
    // At schema -4 the whole float range is 132 buckets, below the limit.
    while too_wide(shift) && schema - (shift as i32) > *EXPONENTIAL_SCHEMAS.start() {
        shift += 1;
    }
    debug_assert!(!too_wide(shift));
    shift
}

/// Appends one side of an exponential histogram to `col` as a dense list at the scale lowered
/// by `shift`, keeping only the buckets within `range`, and returns the total count of all
/// buckets, for Go's count check, and of the kept buckets. A stale point gets an empty list.
///
/// Invalid spans and buckets are [`DecodeError::InvalidHistogram`]; a column that outgrows
/// the OTAP i32 list offsets is [`DecodeError::CapacityOverflow`].
#[allow(clippy::too_many_arguments)]
fn push_dense_side(
    col: &mut ExpBucketsCol,
    side: &'static str,
    spans: &[Span],
    buckets: Buckets<'_>,
    (min_index, max_index): (i64, i64),
    shift: u32,
    stale: bool,
    family: &CurrentFamily,
) -> Result<(u64, u64), DecodeError> {
    if col.list_offsets.is_empty() {
        col.list_offsets.push(0);
    }
    let start = col.counts.len();
    let counts = &mut col.counts;
    let mut first_index = None;
    let mut kept = 0u64;
    // `walk_buckets` checks the spans before it visits any bucket, so indexes only grow and
    // stay within the `kept_index_bounds` that `downscale_shift` limited to the dense limit.
    // A stale point is only checked and writes no buckets.
    let total = if stale {
        walk_buckets(side, spans, buckets, |_, _| {})
    } else {
        walk_buckets(side, spans, buckets, |index, count| {
            if index < min_index || index > max_index {
                return;
            }
            let otel = otel_index(index, shift);
            let first = *first_index.get_or_insert(otel);
            let pos = start + (otel - first) as usize;
            if pos < counts.len() {
                counts[pos] = counts[pos].wrapping_add(count);
            } else {
                counts.resize(pos, 0);
                counts.push(count);
            }
            kept = kept.wrapping_add(count);
        })
    }
    .map_err(|reason| invalid_histogram(family, reason))?;
    // Both bounds of the index range fit in i32.
    col.offsets.push(first_index.unwrap_or(0) as i32);
    let end = i32::try_from(col.counts.len()).map_err(|_| DecodeError::CapacityOverflow {
        table: if side == "positive" {
            "ExpHistogramDataPoints.positive"
        } else {
            "ExpHistogramDataPoints.negative"
        },
        count: col.counts.len(),
    })?;
    col.list_offsets.push(end);
    Ok((total, kept))
}

/// Go's `checkHistogramCustomBounds`, without the span and bucket count check that
/// [`walk_buckets`] does.
fn check_custom_bounds(bounds: &[f64], spans: &[Span]) -> Result<(), String> {
    let mut previous = f64::NEG_INFINITY;
    for (i, &bound) in bounds.iter().enumerate() {
        if bound.is_nan() {
            return Err("custom buckets: must not have NaN bounds".to_owned());
        }
        // The first bound may be -Inf.
        if i > 0 && bound <= previous {
            return Err(format!(
                "previous bound is {previous} and current is {bound}: custom buckets: must be \
                 in strictly increasing order"
            ));
        }
        previous = bound;
    }
    if previous == f64::INFINITY {
        return Err("custom buckets: last +Inf bound must not be explicitly defined".to_owned());
    }
    let mut total_span_length = 0i64;
    for (n, span) in spans.iter().enumerate() {
        if span.offset < 0 {
            return Err(format!(
                "span number {} with offset {}: histogram has a span whose offset is negative",
                n + 1,
                span.offset
            ));
        }
        total_span_length += i64::from(span.offset) + i64::from(span.length);
    }
    if total_span_length > bounds.len() as i64 + 1 {
        return Err(format!(
            "spans need at least {total_span_length} custom bounds, have {}: custom buckets: \
             must have enough bounds for the spans",
            bounds.len() + 1
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow::staleness::STALE_NAN;

    fn span(offset: i32, length: u32) -> Span {
        Span { offset, length }
    }

    fn walk(spans: &[Span], buckets: Buckets<'_>) -> Result<(Vec<(i64, u64)>, u64), String> {
        let mut seen = Vec::new();
        let total = walk_buckets("positive", spans, buckets, |index, count| {
            seen.push((index, count));
        })?;
        Ok((seen, total))
    }

    #[test]
    fn walk_buckets_decodes_deltas_and_gaps() {
        let spans = [span(-2, 2), span(3, 1)];
        let (seen, total) = walk(&spans, Buckets::Delta(&[1, 2, -1])).unwrap();
        assert_eq!(seen, [(-2, 1), (-1, 3), (3, 2)]);
        assert_eq!(total, 6);
    }

    #[test]
    fn walk_buckets_applies_go_checks() {
        let err = walk(&[span(0, 1), span(-1, 1)], Buckets::Delta(&[1, 1])).unwrap_err();
        assert!(err.contains("offset is negative"), "{err}");
        let err = walk(&[span(0, 2)], Buckets::Delta(&[1])).unwrap_err();
        assert!(err.contains("different number of buckets"), "{err}");
        let err = walk(&[span(0, 2)], Buckets::Delta(&[1, -2])).unwrap_err();
        assert!(err.contains("count is negative"), "{err}");
        let err = walk(&[span(0, 1)], Buckets::Absolute(&[-0.5])).unwrap_err();
        assert!(err.contains("count is negative"), "{err}");
    }

    #[test]
    fn check_custom_bounds_matches_go() {
        assert!(check_custom_bounds(&[1.0, 2.0], &[span(0, 3)]).is_ok());
        assert!(check_custom_bounds(&[1.0, 1.0], &[]).is_err());
        assert!(check_custom_bounds(&[f64::NAN], &[]).is_err());
        // Go only compares a bound with the one before it, so the first may be -Inf.
        assert!(check_custom_bounds(&[f64::NEG_INFINITY], &[]).is_ok());
        assert!(check_custom_bounds(&[f64::NEG_INFINITY, 1.0], &[span(0, 3)]).is_ok());
        assert!(check_custom_bounds(&[f64::NEG_INFINITY, f64::NEG_INFINITY], &[]).is_err());
        assert!(check_custom_bounds(&[1.0, f64::INFINITY], &[]).is_err());
        assert!(check_custom_bounds(&[1.0], &[span(-1, 1)]).is_err());
        assert!(check_custom_bounds(&[1.0], &[span(1, 2)]).is_err());
    }

    fn nhcb(count: u64, sum: f64, spans: Vec<Span>, deltas: Vec<i64>) -> Histogram<u64, i64> {
        Histogram {
            schema: CUSTOM_BUCKETS_SCHEMA,
            count,
            sum,
            positive_spans: spans,
            positive_buckets: deltas,
            custom_values: vec![1.0, 2.0, 5.0],
            ..Histogram::default()
        }
    }

    fn family() -> CurrentFamily {
        let mut family = CurrentFamily::default();
        family.start_new(b"h", b"h");
        family
    }

    fn push(dp: &mut HistogramDpTable, h: &Histogram<u64, i64>) -> Result<(), DecodeError> {
        let view = NativeView::new(HistogramRef::Int(h)).unwrap();
        push_custom_buckets(
            dp,
            dp.bucket_offsets.len().saturating_sub(1),
            &view,
            &family(),
        )
    }

    #[test]
    fn push_custom_buckets_writes_dense_counts() {
        let mut dp = HistogramDpTable::default();
        // Buckets 0 and 3 (+Inf) only, compacted with a gap like the protobuf parser does.
        let h = nhcb(5, 7.5, vec![span(0, 1), span(2, 1)], vec![2, 1]);
        push(&mut dp, &h).unwrap();
        assert_eq!(dp.bucket_counts, [2, 0, 0, 3]);
        assert_eq!(dp.bounds_vals, [1.0, 2.0, 5.0]);
        assert_eq!(dp.bucket_offsets, [0, 4]);
        assert_eq!(dp.bounds_offsets, [0, 3]);
    }

    #[test]
    fn push_custom_buckets_empties_stale_points() {
        let stale = nhcb(2, STALE_NAN, vec![span(0, 1)], vec![2]);
        let mut dp = HistogramDpTable::default();
        push(&mut dp, &nhcb(2, 1.0, vec![span(0, 1)], vec![2])).unwrap();
        push(&mut dp, &stale).unwrap();
        assert_eq!(dp.bucket_counts, [2, 0, 0, 0]);
        assert_eq!(dp.bounds_vals, [1.0, 2.0, 5.0]);
        assert_eq!(dp.bucket_offsets, [0, 4, 4]);
        assert_eq!(dp.bounds_offsets, [0, 3, 3]);
        assert!(!dp.counts.is_nullable());
        let sums = dp.sums.to_f64_array();
        assert_eq!(
            (sums.len(), sums.is_valid(0), sums.is_null(1)),
            (2, true, true)
        );

        // A stale point does not grow the bucket buffer.
        let mut dp = HistogramDpTable::default();
        push(&mut dp, &stale).unwrap();
        assert_eq!(dp.bucket_counts.capacity(), 0);
    }

    #[test]
    fn push_custom_buckets_checks_count() {
        let mut dp = HistogramDpTable::default();
        let h = nhcb(4, 1.0, vec![span(0, 1)], vec![5]);
        let err = push(&mut dp, &h).unwrap_err().to_string();
        assert!(err.contains("should equal"), "{err}");

        let h = nhcb(6, f64::NAN, vec![span(0, 1)], vec![5]);
        push(&mut HistogramDpTable::default(), &h).unwrap();
    }

    #[test]
    fn push_custom_buckets_rejects_zero_and_negative_buckets() {
        let mut h = nhcb(1, 1.0, vec![span(0, 1)], vec![1]);
        h.zero_count = 1;
        h.count = 2;
        assert!(push(&mut HistogramDpTable::default(), &h).is_err());

        let mut h = nhcb(2, 1.0, vec![span(0, 1)], vec![1]);
        h.negative_spans = vec![span(0, 1)];
        h.negative_buckets = vec![1];
        assert!(push(&mut HistogramDpTable::default(), &h).is_err());
    }

    #[test]
    fn float_custom_buckets_reject_fractional_and_nan_zero_count() {
        // Go checks the float zero count as sent, before any conversion to an integer count.
        for zero_count in [0.5, f64::NAN] {
            let h = Histogram::<f64, f64> {
                schema: CUSTOM_BUCKETS_SCHEMA,
                count: 1.0,
                sum: 1.0,
                zero_count,
                positive_spans: vec![span(0, 1)],
                positive_buckets: vec![1.0],
                custom_values: vec![1.0],
                ..Histogram::default()
            };
            let err = check_float_histogram(&NativeView::new(HistogramRef::Float(&h)).unwrap())
                .unwrap_err();
            assert!(err.contains("zero count of 0"), "{err}");
        }
    }

    fn exponential(schema: i32, spans: Vec<Span>, deltas: Vec<i64>) -> Histogram<u64, i64> {
        let count = deltas
            .iter()
            .scan(0i64, |current, delta| {
                *current += delta;
                Some(*current as u64)
            })
            .sum::<u64>()
            + 2;
        Histogram {
            schema,
            zero_threshold: 1e-128,
            zero_count: 2,
            count,
            sum: 10.0,
            positive_spans: spans,
            positive_buckets: deltas,
            ..Histogram::default()
        }
    }

    fn push_exp(dp: &mut ExpHistogramDpTable, h: &Histogram<u64, i64>) -> Result<(), DecodeError> {
        let view = NativeView::new(HistogramRef::Int(h)).unwrap();
        push_exponential(dp, &view, &family())
    }

    #[test]
    fn index_range_matches_go_bounds() {
        assert_eq!(exponential_index_range(0), (-1074, 1024));
        assert_eq!(exponential_index_range(8), (-1074 << 8, 1024 << 8));
        // 2^(16 * -67) = 2^-1072 still holds 2^-1074, the bucket below does not.
        assert_eq!(exponential_index_range(-4), (-67, 64));
        assert_eq!(exponential_index_range(-1), (-537, 512));
    }

    #[test]
    fn push_exponential_densifies_with_otel_offsets() {
        let mut dp = ExpHistogramDpTable::default();
        let mut h = exponential(3, vec![span(-2, 2), span(3, 1)], vec![1, 2, -1]);
        h.negative_spans = vec![span(5, 1)];
        h.negative_buckets = vec![4];
        h.count += 4;
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.scales, [3]);
        assert_eq!(dp.counts, [h.count]);
        assert_eq!(dp.zero_counts, [2]);
        // Prometheus index -2 is the bucket above OTel index -3.
        assert_eq!(dp.positive.offsets, [-3]);
        assert_eq!(dp.positive.counts, [1, 3, 0, 0, 0, 2]);
        assert_eq!(dp.positive.list_offsets, [0, 6]);
        assert_eq!(dp.negative.offsets, [4]);
        assert_eq!(dp.negative.counts, [4]);

        // No spans: offset 0 and an empty list.
        push_exp(&mut dp, &exponential(0, vec![], vec![])).unwrap();
        assert_eq!(dp.positive.offsets, [-3, 0]);
        assert_eq!(dp.positive.list_offsets, [0, 6, 6]);
        assert_eq!(dp.counts[1], 2);
    }

    #[test]
    fn push_exponential_drops_buckets_outside_the_float_range() {
        let mut dp = ExpHistogramDpTable::default();
        // At schema 0 index 1024 ends at math.MaxFloat64 and 1025 is the ±Inf bucket;
        // index -1075 is below the smallest subnormal.
        let h = exponential(0, vec![span(-1075, 1), span(2098, 2)], vec![7, -6, 2]);
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.positive.offsets, [1023]);
        assert_eq!(dp.positive.counts, [1]);
        // Zero count plus the one kept bucket.
        assert_eq!(dp.counts, [3]);
    }

    #[test]
    fn push_exponential_empties_stale_points() {
        let mut dp = ExpHistogramDpTable::default();
        let mut h = exponential(1, vec![span(0, 1)], vec![3]);
        h.sum = STALE_NAN;
        h.zero_threshold = 0.5;
        push_exp(&mut dp, &h).unwrap();
        assert_eq!((dp.counts[0], dp.zero_counts[0]), (0, 0));
        assert_eq!((dp.scales[0], dp.zero_thresholds[0]), (0, 0.0));
        assert!(dp.sums.is_nullable());
        assert_eq!(dp.positive.counts.capacity(), 0);
        assert_eq!(dp.positive.offsets, [0]);
    }

    #[test]
    fn push_exponential_applies_go_checks() {
        let mut h = exponential(0, vec![span(0, 1)], vec![3]);
        h.count = 4;
        let err = push_exp(&mut ExpHistogramDpTable::default(), &h).unwrap_err();
        assert!(err.to_string().contains("should equal"), "{err}");

        let mut h = exponential(0, vec![span(0, 1)], vec![3]);
        h.custom_values = vec![1.0];
        let err = push_exp(&mut ExpHistogramDpTable::default(), &h).unwrap_err();
        assert!(err.to_string().contains("custom bounds"), "{err}");

        let h = exponential(0, vec![span(0, 1), span(-2, 1)], vec![3, 0]);
        assert!(push_exp(&mut ExpHistogramDpTable::default(), &h).is_err());
    }

    #[test]
    fn push_exponential_downscales_wide_sides() {
        // Indexes 1 and 2 are OTel buckets 0 and 1, which merge at scale 1, and index 301 is
        // OTel bucket 300. At scale 2 the list would need 301 buckets, more than 160.
        let mut dp = ExpHistogramDpTable::default();
        let h = exponential(2, vec![span(1, 2), span(298, 1)], vec![2, 1, -1]);
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.scales, [1]);
        assert_eq!(dp.positive.offsets, [0]);
        assert_eq!(dp.positive.counts.len(), 151);
        assert_eq!(dp.positive.counts[0], 5);
        assert_eq!(dp.positive.counts[150], 2);
        assert_eq!(dp.counts, [9]);

        // Two buckets at the ends of the schema 8 range would need 537,088 dense buckets.
        let mut dp = ExpHistogramDpTable::default();
        let h = exponential(8, vec![span(-274_944, 1), span(537_087, 1)], vec![1, 0]);
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.scales, [-4]);
        assert_eq!(dp.positive.offsets, [-68]);
        assert_eq!(dp.positive.counts.len(), 132);
        assert_eq!(dp.positive.counts[0], 1);
        assert_eq!(dp.positive.counts[131], 1);

        // Many sparse buckets raise the limit, so a dense histogram keeps its scale.
        let mut dp = ExpHistogramDpTable::default();
        let h = exponential(8, vec![span(0, 200)], vec![1; 200]);
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.scales, [8]);
        assert_eq!(dp.positive.counts.len(), 200);
    }

    /// `exponential` with its buckets on the negative side instead.
    fn negative(schema: i32, spans: Vec<Span>, deltas: Vec<i64>) -> Histogram<u64, i64> {
        let mut h = exponential(schema, spans, deltas);
        h.negative_spans = std::mem::take(&mut h.positive_spans);
        h.negative_buckets = std::mem::take(&mut h.positive_buckets);
        h
    }

    #[test]
    fn push_exponential_negative_side_only() {
        let mut dp = ExpHistogramDpTable::default();
        push_exp(
            &mut dp,
            &negative(3, vec![span(-2, 2), span(3, 1)], vec![1, 2, -1]),
        )
        .unwrap();
        assert_eq!(dp.counts, [8]);
        assert_eq!(dp.negative.offsets, [-3]);
        assert_eq!(dp.negative.counts, [1, 3, 0, 0, 0, 2]);
        assert!(dp.positive.counts.is_empty());
        assert_eq!(dp.positive.offsets, [0]);
        assert_eq!(dp.positive.list_offsets, [0, 0]);

        // Buckets outside the float range are dropped on the negative side too.
        let mut dp = ExpHistogramDpTable::default();
        let h = negative(0, vec![span(-1075, 1), span(2098, 2)], vec![7, -6, 2]);
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.negative.offsets, [1023]);
        assert_eq!(dp.negative.counts, [1]);
        assert_eq!(dp.counts, [3]);

        // A negative side alone can overflow the count check.
        let mut h = negative(0, vec![span(0, 1)], vec![3]);
        h.count = 4;
        let err = push_exp(&mut ExpHistogramDpTable::default(), &h).unwrap_err();
        assert!(err.to_string().contains("should equal"), "{err}");
    }

    #[test]
    fn push_exponential_writes_no_stale_negative_buckets_after_the_first_row() {
        let mut dp = ExpHistogramDpTable::default();
        push_exp(&mut dp, &negative(0, vec![span(0, 2)], vec![1, 1])).unwrap();
        let mut stale = negative(0, vec![span(4, 3)], vec![1, 1, 1]);
        stale.sum = STALE_NAN;
        push_exp(&mut dp, &stale).unwrap();
        // The stale row writes none of its buckets after row 0's.
        assert_eq!(dp.negative.counts, [1, 2]);
        assert_eq!(dp.negative.offsets, [-1, 0]);
        assert_eq!(dp.negative.list_offsets, [0, 2, 2]);
        assert_eq!(dp.counts, [5, 0]);
    }

    #[test]
    fn push_exponential_downscales_both_sides_for_a_wide_negative_side() {
        // Same wide side as `push_exponential_downscales_wide_sides`, on the negative side,
        // with a narrow positive side that is downscaled with it.
        let mut dp = ExpHistogramDpTable::default();
        let mut h = negative(2, vec![span(1, 2), span(298, 1)], vec![2, 1, -1]);
        h.positive_spans = vec![span(1, 2)];
        h.positive_buckets = vec![4, 0];
        h.count += 8;
        push_exp(&mut dp, &h).unwrap();
        assert_eq!(dp.scales, [1]);
        assert_eq!(dp.negative.offsets, [0]);
        assert_eq!(dp.negative.counts.len(), 151);
        assert_eq!(dp.negative.counts[0], 5);
        assert_eq!(dp.negative.counts[150], 2);
        assert_eq!(dp.positive.offsets, [0]);
        assert_eq!(dp.positive.counts, [8]);
        assert_eq!(dp.counts, [17]);
    }

    #[test]
    fn downscale_shift_uses_both_sides() {
        assert_eq!(downscale_shift(3, [(Some((0, 159)), 2), (None, 0)]), 0);
        assert_eq!(
            downscale_shift(3, [(Some((0, 159)), 2), (Some((0, 160)), 2)]),
            1
        );
        assert_eq!(dense_bucket_limit(0), 160);
        assert_eq!(dense_bucket_limit(100), 800);
    }

    #[test]
    fn check_float_histogram_applies_go_checks() {
        let float = |spans: Vec<Span>, buckets: Vec<f64>| Histogram::<f64, f64> {
            schema: 0,
            count: 1.0,
            positive_spans: spans,
            positive_buckets: buckets,
            ..Histogram::default()
        };
        let check = |h: &Histogram<f64, f64>| {
            check_float_histogram(&NativeView::new(HistogramRef::Float(h)).unwrap())
        };
        // Go does not check the count of a float histogram.
        assert!(check(&float(vec![span(0, 1)], vec![5.0])).is_ok());
        let err = check(&float(vec![span(0, 1), span(-1, 1)], vec![1.0, 1.0])).unwrap_err();
        assert!(err.contains("offset is negative"), "{err}");
        let err = check(&float(vec![span(0, 1)], vec![-1.0])).unwrap_err();
        assert!(err.contains("count is negative"), "{err}");
        let mut h = float(vec![], vec![]);
        h.custom_values = vec![1.0];
        assert!(check(&h).unwrap_err().contains("custom bounds"));

        // Float NHCB get the custom-bucket checks.
        h.schema = CUSTOM_BUCKETS_SCHEMA;
        h.positive_spans = vec![span(0, 2)];
        h.positive_buckets = vec![1.0, 1.0];
        assert!(check(&h).is_ok());
        h.custom_values = vec![1.0, 1.0];
        assert!(check(&h).unwrap_err().contains("strictly increasing"));
    }

    #[test]
    fn float_view_rejects_negative_counts() {
        let h = Histogram::<f64, f64> {
            count: -1.0,
            ..Histogram::default()
        };
        assert!(NativeView::new(HistogramRef::Float(&h)).is_err());
    }
}
