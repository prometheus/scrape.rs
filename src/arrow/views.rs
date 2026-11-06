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

//! Zero-copy [`otel_arrow_dfe_pdata_views`] trait implementations over [`ArrowDecoder`] staging
//! buffers.
//!
//! [`DecodedMetricsView`] borrows [`ArrowDecoder`]'s columnar staging tables and string interners
//! directly after parsing and family assembly without materializing intermediate Arrow
//! [`arrow_array::RecordBatch`]es or per-sample heap allocations. Downstream callers such as
//! `otel-arrow-dfe-pdata`'s `encode_metrics_otap_batch` can traverse the view hierarchy in $O(1)$
//! per family, data point, exemplar, and attribute.

use std::iter::{Copied, Empty, FusedIterator, Once};
use std::ops::Range;
use std::slice;

use otel_arrow_dfe_pdata_views::views::common::{
    AnyValueView, AttributeView, InstrumentationScopeView, Str, ValueType,
};
use otel_arrow_dfe_pdata_views::views::metrics::{
    AggregationTemporality, BucketsView, DataPointFlags, DataType, DataView, ExemplarView,
    ExponentialHistogramDataPointView, ExponentialHistogramView, GaugeView, HistogramDataPointView,
    HistogramView, MetricView, MetricsView, NumberDataPointView, ResourceMetricsView,
    ScopeMetricsView, SumView, SummaryDataPointView, SummaryView, Value, ValueAtQuantileView,
};
use otel_arrow_dfe_pdata_views::views::resource::ResourceView;
use otel_arrow_dfe_pdata_views::{SpanId, TraceId};

use super::ArrowDecoder;
use super::columns::{AttrTable, ExemplarTable};
use super::intern::StringInterner;
use super::schema::{
    OTAP_METRIC_TYPE_GAUGE, OTAP_METRIC_TYPE_HISTOGRAM, OTAP_METRIC_TYPE_SUM,
    OTAP_METRIC_TYPE_SUMMARY, PROMETHEUS_TYPE_METADATA_KEY,
};

/// Static string values for the `prometheus.type` metric metadata attribute, indexed by
/// `MetricTable::attr_type_keys` (`0..=7`).
const PROMETHEUS_TYPE_VALUES: [&[u8]; 8] = [
    b"unknown",
    b"counter",
    b"gauge",
    b"histogram",
    b"gaugehistogram",
    b"summary",
    b"info",
    b"stateset",
];

/// Zero-copy [`MetricsView`] borrowing the active batch staged inside an [`ArrowDecoder`].
#[derive(Clone, Copy)]
pub struct DecodedMetricsView<'a> {
    decoder: &'a ArrowDecoder,
}

impl std::fmt::Debug for DecodedMetricsView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedMetricsView")
            .field("num_metrics", &self.num_metrics())
            .field("num_data_points", &self.num_data_points())
            .finish()
    }
}

impl<'a> DecodedMetricsView<'a> {
    #[inline]
    pub(super) const fn new(decoder: &'a ArrowDecoder) -> Self {
        Self { decoder }
    }

    /// Returns `true` when the staged batch contains zero metric families.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decoder.metrics.is_empty()
    }

    /// Returns the number of metric families staged in the batch.
    #[inline]
    #[must_use]
    pub fn num_metrics(&self) -> usize {
        self.decoder.metrics.len()
    }

    /// Returns the total number of data points staged across number, summary, and histogram tables.
    #[inline]
    #[must_use]
    pub fn num_data_points(&self) -> usize {
        self.decoder.total_data_points()
    }
}

impl<'a> MetricsView for DecodedMetricsView<'a> {
    type ResourceMetrics<'res>
        = DecodedResourceMetricsView<'res>
    where
        Self: 'res;

    type ResourceMetricsIter<'res>
        = std::option::IntoIter<DecodedResourceMetricsView<'res>>
    where
        Self: 'res;

    #[inline]
    fn resources(&self) -> Self::ResourceMetricsIter<'_> {
        (!self.decoder.metrics.is_empty())
            .then_some(DecodedResourceMetricsView {
                decoder: self.decoder,
            })
            .into_iter()
    }
}

/// Zero-copy [`ResourceMetricsView`] for a decoded Prometheus/OpenMetrics scrape batch.
#[derive(Clone, Copy)]
pub struct DecodedResourceMetricsView<'a> {
    decoder: &'a ArrowDecoder,
}

impl<'a> ResourceMetricsView for DecodedResourceMetricsView<'a> {
    type Resource<'res>
        = DecodedEmptyResourceView
    where
        Self: 'res;

    type ScopeMetrics<'scp>
        = DecodedScopeMetricsView<'scp>
    where
        Self: 'scp;

    type ScopesIter<'scp>
        = Once<DecodedScopeMetricsView<'scp>>
    where
        Self: 'scp;

    #[inline]
    fn resource(&self) -> Option<Self::Resource<'_>> {
        None
    }

    #[inline]
    fn scopes(&self) -> Self::ScopesIter<'_> {
        std::iter::once(DecodedScopeMetricsView {
            decoder: self.decoder,
        })
    }

    #[inline]
    fn schema_url(&self) -> Option<Str<'_>> {
        None
    }
}

/// Uninhabited/empty [`ResourceView`] and [`InstrumentationScopeView`] placeholder for scrape
/// batches, which carry no embedded OTLP resource or scope descriptors in exposition wire format.
#[derive(Clone, Copy, Debug)]
pub struct DecodedEmptyResourceView;

impl ResourceView for DecodedEmptyResourceView {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributesIter<'att>
        = Empty<DecodedAttributeView<'att>>
    where
        Self: 'att;

    #[inline]
    fn attributes(&self) -> Self::AttributesIter<'_> {
        std::iter::empty()
    }

    #[inline]
    fn dropped_attributes_count(&self) -> u32 {
        0
    }
}

impl InstrumentationScopeView for DecodedEmptyResourceView {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = Empty<DecodedAttributeView<'att>>
    where
        Self: 'att;

    #[inline]
    fn name(&self) -> Option<Str<'_>> {
        None
    }

    #[inline]
    fn version(&self) -> Option<Str<'_>> {
        None
    }

    #[inline]
    fn attributes(&self) -> Self::AttributeIter<'_> {
        std::iter::empty()
    }

    #[inline]
    fn dropped_attributes_count(&self) -> u32 {
        0
    }
}

/// Zero-copy [`ScopeMetricsView`] yielding all metric families staged in [`ArrowDecoder`].
#[derive(Clone, Copy)]
pub struct DecodedScopeMetricsView<'a> {
    decoder: &'a ArrowDecoder,
}

impl<'a> ScopeMetricsView for DecodedScopeMetricsView<'a> {
    type Scope<'scp>
        = DecodedEmptyResourceView
    where
        Self: 'scp;

    type Metric<'met>
        = DecodedMetricView<'met>
    where
        Self: 'met;

    type MetricIter<'met>
        = DecodedMetricIter<'met>
    where
        Self: 'met;

    #[inline]
    fn scope(&self) -> Option<Self::Scope<'_>> {
        None
    }

    #[inline]
    fn metrics(&self) -> Self::MetricIter<'_> {
        DecodedMetricIter {
            decoder: self.decoder,
            range: 0..self.decoder.metrics.len(),
        }
    }

    #[inline]
    fn schema_url(&self) -> Str<'_> {
        b""
    }
}

/// Iterator over [`DecodedMetricView`] entries in a [`DecodedScopeMetricsView`].
#[derive(Clone)]
pub struct DecodedMetricIter<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> Iterator for DecodedMetricIter<'a> {
    type Item = DecodedMetricView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let row = self.range.next()?;
        Some(DecodedMetricView {
            decoder: self.decoder,
            row,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl ExactSizeIterator for DecodedMetricIter<'_> {}
impl FusedIterator for DecodedMetricIter<'_> {}

/// Zero-copy [`MetricView`] over a single metric family row in [`ArrowDecoder`].
#[derive(Clone, Copy)]
pub struct DecodedMetricView<'a> {
    decoder: &'a ArrowDecoder,
    row: usize,
}

impl<'a> MetricView for DecodedMetricView<'a> {
    type Data<'dat>
        = DecodedDataView<'dat>
    where
        Self: 'dat;

    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = Once<DecodedAttributeView<'att>>
    where
        Self: 'att;

    #[inline]
    fn name(&self) -> Str<'_> {
        self.decoder.metrics.name_at(self.row)
    }

    #[inline]
    fn description(&self) -> Str<'_> {
        self.decoder.metrics.desc.get_bytes(self.row)
    }

    #[inline]
    fn unit(&self) -> Str<'_> {
        self.decoder.metrics.unit.get_bytes(self.row)
    }

    #[inline]
    fn data(&self) -> Option<Self::Data<'_>> {
        let (start, end) = self.decoder.metrics.dp_ranges[self.row];
        let range = (start as usize)..(end as usize);
        match self.decoder.metrics.metric_types[self.row] {
            OTAP_METRIC_TYPE_GAUGE => Some(DecodedDataView::Gauge(DecodedGaugeView {
                decoder: self.decoder,
                range,
            })),
            OTAP_METRIC_TYPE_SUM => Some(DecodedDataView::Sum(DecodedSumView {
                decoder: self.decoder,
                range,
                is_monotonic: self.decoder.metrics.is_monotonic[self.row],
            })),
            OTAP_METRIC_TYPE_HISTOGRAM => Some(DecodedDataView::Histogram(DecodedHistogramView {
                decoder: self.decoder,
                range,
            })),
            OTAP_METRIC_TYPE_SUMMARY => Some(DecodedDataView::Summary(DecodedSummaryView {
                decoder: self.decoder,
                range,
            })),
            _ => None,
        }
    }

    #[inline]
    fn metadata(&self) -> Self::AttributeIter<'_> {
        let type_idx = usize::from(self.decoder.metrics.attr_type_keys[self.row]);
        let type_val = PROMETHEUS_TYPE_VALUES
            .get(type_idx)
            .copied()
            .unwrap_or(b"unknown");
        std::iter::once(DecodedAttributeView {
            key: PROMETHEUS_TYPE_METADATA_KEY.as_bytes(),
            val: type_val,
        })
    }
}

/// Zero-copy [`DataView`] enum dispatching across Gauge, Sum, Histogram, and Summary metric data.
#[derive(Clone)]
pub enum DecodedDataView<'a> {
    /// Gauge data points.
    Gauge(DecodedGaugeView<'a>),
    /// Sum data points.
    Sum(DecodedSumView<'a>),
    /// Explicit-bucket Histogram data points.
    Histogram(DecodedHistogramView<'a>),
    /// Summary data points.
    Summary(DecodedSummaryView<'a>),
}

impl<'a> DataView<'a> for DecodedDataView<'a> {
    type Gauge<'g>
        = DecodedGaugeView<'g>
    where
        Self: 'g;

    type Sum<'s>
        = DecodedSumView<'s>
    where
        Self: 's;

    type Histogram<'h>
        = DecodedHistogramView<'h>
    where
        Self: 'h;

    type ExponentialHistogram<'e>
        = DecodedExpHistogramView
    where
        Self: 'e;

    type Summary<'su>
        = DecodedSummaryView<'su>
    where
        Self: 'su;

    #[inline]
    fn value_type(&self) -> DataType {
        match self {
            Self::Gauge(_) => DataType::Gauge,
            Self::Sum(_) => DataType::Sum,
            Self::Histogram(_) => DataType::Histogram,
            Self::Summary(_) => DataType::Summary,
        }
    }

    #[inline]
    fn as_gauge(&self) -> Option<<Self as DataView<'a>>::Gauge<'_>> {
        match self {
            Self::Gauge(g) => Some(g.clone()),
            _ => None,
        }
    }

    #[inline]
    fn as_sum(&self) -> Option<<Self as DataView<'a>>::Sum<'_>> {
        match self {
            Self::Sum(s) => Some(s.clone()),
            _ => None,
        }
    }

    #[inline]
    fn as_histogram(&self) -> Option<<Self as DataView<'a>>::Histogram<'_>> {
        match self {
            Self::Histogram(h) => Some(h.clone()),
            _ => None,
        }
    }

    #[inline]
    fn as_exponential_histogram(&self) -> Option<<Self as DataView<'a>>::ExponentialHistogram<'_>> {
        None
    }

    #[inline]
    fn as_summary(&self) -> Option<<Self as DataView<'a>>::Summary<'_>> {
        match self {
            Self::Summary(s) => Some(s.clone()),
            _ => None,
        }
    }
}

/// Zero-copy [`GaugeView`] over a contiguous range of `NumberDataPoints` rows.
#[derive(Clone)]
pub struct DecodedGaugeView<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> GaugeView for DecodedGaugeView<'a> {
    type NumberDataPoint<'dp>
        = DecodedNumberDataPointView<'dp>
    where
        Self: 'dp;

    type NumberDataPointIter<'dp>
        = DecodedNumberDpIter<'dp>
    where
        Self: 'dp;

    #[inline]
    fn data_points(&self) -> Self::NumberDataPointIter<'_> {
        DecodedNumberDpIter {
            decoder: self.decoder,
            range: self.range.clone(),
        }
    }
}

/// Zero-copy [`SumView`] over a contiguous range of `NumberDataPoints` rows.
#[derive(Clone)]
pub struct DecodedSumView<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
    is_monotonic: bool,
}

impl<'a> SumView for DecodedSumView<'a> {
    type NumberDataPoint<'dp>
        = DecodedNumberDataPointView<'dp>
    where
        Self: 'dp;

    type NumberDataPointIter<'dp>
        = DecodedNumberDpIter<'dp>
    where
        Self: 'dp;

    #[inline]
    fn data_points(&self) -> Self::NumberDataPointIter<'_> {
        DecodedNumberDpIter {
            decoder: self.decoder,
            range: self.range.clone(),
        }
    }

    #[inline]
    fn aggregation_temporality(&self) -> AggregationTemporality {
        AggregationTemporality::Cumulative
    }

    #[inline]
    fn is_monotonic(&self) -> bool {
        self.is_monotonic
    }
}

/// Iterator over [`DecodedNumberDataPointView`] rows for a Gauge or Sum metric family.
#[derive(Clone)]
pub struct DecodedNumberDpIter<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> Iterator for DecodedNumberDpIter<'a> {
    type Item = DecodedNumberDataPointView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let row = self.range.next()?;
        Some(DecodedNumberDataPointView {
            decoder: self.decoder,
            row,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl ExactSizeIterator for DecodedNumberDpIter<'_> {}
impl FusedIterator for DecodedNumberDpIter<'_> {}

/// Zero-copy [`NumberDataPointView`] over a single row in `NumberDpTable`.
#[derive(Clone, Copy)]
pub struct DecodedNumberDataPointView<'a> {
    decoder: &'a ArrowDecoder,
    row: usize,
}

impl<'a> NumberDataPointView for DecodedNumberDataPointView<'a> {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = DecodedAttrIter<'att>
    where
        Self: 'att;

    type Exemplar<'ex>
        = DecodedExemplarView<'ex>
    where
        Self: 'ex;

    type ExemplarIter<'ex>
        = DecodedExemplarIter<'ex>
    where
        Self: 'ex;

    #[inline]
    fn start_time_unix_nano(&self) -> u64 {
        self.decoder.num_dp.base.start_time.get_u64(self.row)
    }

    #[inline]
    fn time_unix_nano(&self) -> u64 {
        self.decoder.num_dp.base.time.get_u64(self.row)
    }

    #[inline]
    fn value(&self) -> Option<Value> {
        Some(Value::Double(self.decoder.num_dp.values[self.row]))
    }

    #[inline]
    fn attributes(&self) -> Self::AttributeIter<'_> {
        DecodedAttrIter::new(
            &self.decoder.num_dp.attrs,
            &self.decoder.key_interner,
            &self.decoder.val_interner,
            self.row,
        )
    }

    #[inline]
    fn exemplars(&self) -> Self::ExemplarIter<'_> {
        DecodedExemplarIter::new(
            &self.decoder.num_dp.exemplars,
            &self.decoder.key_interner,
            &self.decoder.val_interner,
            self.row,
        )
    }

    #[inline]
    fn flags(&self) -> DataPointFlags {
        DataPointFlags::new(0)
    }
}

/// Zero-copy [`HistogramView`] over a contiguous range of `HistogramDataPoints` rows.
#[derive(Clone)]
pub struct DecodedHistogramView<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> HistogramView for DecodedHistogramView<'a> {
    type HistogramDataPoint<'dp>
        = DecodedHistogramDataPointView<'dp>
    where
        Self: 'dp;

    type HistogramDataPointIter<'dp>
        = DecodedHistogramDpIter<'dp>
    where
        Self: 'dp;

    #[inline]
    fn data_points(&self) -> Self::HistogramDataPointIter<'_> {
        DecodedHistogramDpIter {
            decoder: self.decoder,
            range: self.range.clone(),
        }
    }

    #[inline]
    fn aggregation_temporality(&self) -> AggregationTemporality {
        AggregationTemporality::Cumulative
    }
}

/// Iterator over [`DecodedHistogramDataPointView`] rows for a Histogram metric family.
#[derive(Clone)]
pub struct DecodedHistogramDpIter<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> Iterator for DecodedHistogramDpIter<'a> {
    type Item = DecodedHistogramDataPointView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let row = self.range.next()?;
        Some(DecodedHistogramDataPointView {
            decoder: self.decoder,
            row,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl ExactSizeIterator for DecodedHistogramDpIter<'_> {}
impl FusedIterator for DecodedHistogramDpIter<'_> {}

/// Zero-copy [`HistogramDataPointView`] over a single row in `HistogramDpTable`.
#[derive(Clone, Copy)]
pub struct DecodedHistogramDataPointView<'a> {
    decoder: &'a ArrowDecoder,
    row: usize,
}

impl<'a> HistogramDataPointView for DecodedHistogramDataPointView<'a> {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = DecodedAttrIter<'att>
    where
        Self: 'att;

    type BucketCountIter<'bc>
        = Copied<slice::Iter<'bc, u64>>
    where
        Self: 'bc;

    type ExplicitBoundsIter<'eb>
        = Copied<slice::Iter<'eb, f64>>
    where
        Self: 'eb;

    type Exemplar<'ex>
        = DecodedExemplarView<'ex>
    where
        Self: 'ex;

    type ExemplarIter<'ex>
        = DecodedExemplarIter<'ex>
    where
        Self: 'ex;

    #[inline]
    fn attributes(&self) -> Self::AttributeIter<'_> {
        DecodedAttrIter::new(
            &self.decoder.hist_dp.attrs,
            &self.decoder.key_interner,
            &self.decoder.val_interner,
            self.row,
        )
    }

    #[inline]
    fn start_time_unix_nano(&self) -> u64 {
        self.decoder.hist_dp.base.start_time.get_u64(self.row)
    }

    #[inline]
    fn time_unix_nano(&self) -> u64 {
        self.decoder.hist_dp.base.time.get_u64(self.row)
    }

    #[inline]
    fn count(&self) -> u64 {
        self.decoder.hist_dp.counts.get(self.row).unwrap_or(0)
    }

    #[inline]
    fn sum(&self) -> Option<f64> {
        self.decoder.hist_dp.sums.get(self.row)
    }

    #[inline]
    fn bucket_counts(&self) -> Self::BucketCountIter<'_> {
        let start = self.decoder.hist_dp.bucket_offsets[self.row] as usize;
        let end = self.decoder.hist_dp.bucket_offsets[self.row + 1] as usize;
        self.decoder.hist_dp.bucket_counts[start..end]
            .iter()
            .copied()
    }

    #[inline]
    fn explicit_bounds(&self) -> Self::ExplicitBoundsIter<'_> {
        let start = self.decoder.hist_dp.bounds_offsets[self.row] as usize;
        let end = self.decoder.hist_dp.bounds_offsets[self.row + 1] as usize;
        self.decoder.hist_dp.bounds_vals[start..end].iter().copied()
    }

    #[inline]
    fn exemplars(&self) -> Self::ExemplarIter<'_> {
        DecodedExemplarIter::new(
            &self.decoder.hist_dp.exemplars,
            &self.decoder.key_interner,
            &self.decoder.val_interner,
            self.row,
        )
    }

    #[inline]
    fn flags(&self) -> DataPointFlags {
        DataPointFlags::new(0)
    }

    #[inline]
    fn min(&self) -> Option<f64> {
        None
    }

    #[inline]
    fn max(&self) -> Option<f64> {
        None
    }
}

/// Placeholder [`ExponentialHistogramView`] (native histograms will be populated in Phase 3).
#[derive(Clone, Copy, Debug)]
pub struct DecodedExpHistogramView;

impl ExponentialHistogramView for DecodedExpHistogramView {
    type ExponentialHistogramDataPoint<'edp>
        = DecodedExpHistogramDataPointView
    where
        Self: 'edp;

    type ExponentialHistogramDataPointIter<'edp>
        = Empty<DecodedExpHistogramDataPointView>
    where
        Self: 'edp;

    #[inline]
    fn data_points(&self) -> Self::ExponentialHistogramDataPointIter<'_> {
        std::iter::empty()
    }

    #[inline]
    fn aggregation_temporality(&self) -> AggregationTemporality {
        AggregationTemporality::Cumulative
    }
}

/// Placeholder [`ExponentialHistogramDataPointView`].
#[derive(Clone, Copy, Debug)]
pub struct DecodedExpHistogramDataPointView;

impl ExponentialHistogramDataPointView for DecodedExpHistogramDataPointView {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = Empty<DecodedAttributeView<'att>>
    where
        Self: 'att;

    type Buckets<'b>
        = DecodedBucketsView
    where
        Self: 'b;

    type Exemplar<'ex>
        = DecodedExemplarView<'ex>
    where
        Self: 'ex;

    type ExemplarIter<'ex>
        = Empty<DecodedExemplarView<'ex>>
    where
        Self: 'ex;

    #[inline]
    fn attributes(&self) -> Self::AttributeIter<'_> {
        std::iter::empty()
    }

    #[inline]
    fn start_time_unix_nano(&self) -> u64 {
        0
    }

    #[inline]
    fn time_unix_nano(&self) -> u64 {
        0
    }

    #[inline]
    fn count(&self) -> u64 {
        0
    }

    #[inline]
    fn sum(&self) -> Option<f64> {
        None
    }

    #[inline]
    fn scale(&self) -> i32 {
        0
    }

    #[inline]
    fn zero_count(&self) -> u64 {
        0
    }

    #[inline]
    fn positive(&self) -> Option<Self::Buckets<'_>> {
        None
    }

    #[inline]
    fn negative(&self) -> Option<Self::Buckets<'_>> {
        None
    }

    #[inline]
    fn flags(&self) -> DataPointFlags {
        DataPointFlags::new(0)
    }

    #[inline]
    fn exemplars(&self) -> Self::ExemplarIter<'_> {
        std::iter::empty()
    }

    #[inline]
    fn min(&self) -> Option<f64> {
        None
    }

    #[inline]
    fn max(&self) -> Option<f64> {
        None
    }

    #[inline]
    fn zero_threshold(&self) -> f64 {
        0.0
    }
}

/// Placeholder [`BucketsView`].
#[derive(Clone, Copy, Debug)]
pub struct DecodedBucketsView;

impl BucketsView for DecodedBucketsView {
    type BucketCountIter<'bc>
        = Empty<u64>
    where
        Self: 'bc;

    #[inline]
    fn offset(&self) -> i32 {
        0
    }

    #[inline]
    fn bucket_counts(&self) -> Self::BucketCountIter<'_> {
        std::iter::empty()
    }
}

/// Zero-copy [`SummaryView`] over a contiguous range of `SummaryDataPoints` rows.
#[derive(Clone)]
pub struct DecodedSummaryView<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> SummaryView for DecodedSummaryView<'a> {
    type SummaryDataPoint<'dp>
        = DecodedSummaryDataPointView<'dp>
    where
        Self: 'dp;

    type SummaryDataPointIter<'dp>
        = DecodedSummaryDpIter<'dp>
    where
        Self: 'dp;

    #[inline]
    fn data_points(&self) -> Self::SummaryDataPointIter<'_> {
        DecodedSummaryDpIter {
            decoder: self.decoder,
            range: self.range.clone(),
        }
    }
}

/// Iterator over [`DecodedSummaryDataPointView`] rows for a Summary metric family.
#[derive(Clone)]
pub struct DecodedSummaryDpIter<'a> {
    decoder: &'a ArrowDecoder,
    range: Range<usize>,
}

impl<'a> Iterator for DecodedSummaryDpIter<'a> {
    type Item = DecodedSummaryDataPointView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let row = self.range.next()?;
        Some(DecodedSummaryDataPointView {
            decoder: self.decoder,
            row,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl ExactSizeIterator for DecodedSummaryDpIter<'_> {}
impl FusedIterator for DecodedSummaryDpIter<'_> {}

/// Zero-copy [`SummaryDataPointView`] over a single row in `SummaryDpTable`.
#[derive(Clone, Copy)]
pub struct DecodedSummaryDataPointView<'a> {
    decoder: &'a ArrowDecoder,
    row: usize,
}

impl<'a> SummaryDataPointView for DecodedSummaryDataPointView<'a> {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = DecodedAttrIter<'att>
    where
        Self: 'att;

    type ValueAtQuantile<'vaq>
        = DecodedValueAtQuantileView
    where
        Self: 'vaq;

    type ValueAtQuantileIter<'vaq>
        = DecodedQuantileIter<'vaq>
    where
        Self: 'vaq;

    #[inline]
    fn attributes(&self) -> Self::AttributeIter<'_> {
        DecodedAttrIter::new(
            &self.decoder.sum_dp.attrs,
            &self.decoder.key_interner,
            &self.decoder.val_interner,
            self.row,
        )
    }

    #[inline]
    fn start_time_unix_nano(&self) -> u64 {
        self.decoder.sum_dp.base.start_time.get_u64(self.row)
    }

    #[inline]
    fn time_unix_nano(&self) -> u64 {
        self.decoder.sum_dp.base.time.get_u64(self.row)
    }

    #[inline]
    fn count(&self) -> u64 {
        self.decoder.sum_dp.counts.get(self.row).unwrap_or(0)
    }

    #[inline]
    fn sum(&self) -> f64 {
        self.decoder.sum_dp.sums.get(self.row).unwrap_or(0.0)
    }

    #[inline]
    fn quantile_values(&self) -> Self::ValueAtQuantileIter<'_> {
        let start = self.decoder.sum_dp.quantile_offsets[self.row] as usize;
        let end = self.decoder.sum_dp.quantile_offsets[self.row + 1] as usize;
        DecodedQuantileIter {
            bounds: &self.decoder.sum_dp.quantile_bounds[start..end],
            vals: &self.decoder.sum_dp.quantile_vals[start..end],
            pos: 0,
        }
    }

    #[inline]
    fn flags(&self) -> DataPointFlags {
        DataPointFlags::new(0)
    }
}

/// Iterator over [`DecodedValueAtQuantileView`] entries for a Summary data point.
#[derive(Clone)]
pub struct DecodedQuantileIter<'a> {
    bounds: &'a [f64],
    vals: &'a [f64],
    pos: usize,
}

impl Iterator for DecodedQuantileIter<'_> {
    type Item = DecodedValueAtQuantileView;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.bounds.len() {
            return None;
        }
        let item = DecodedValueAtQuantileView {
            quantile: self.bounds[self.pos],
            value: self.vals[self.pos],
        };
        self.pos += 1;
        Some(item)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.bounds.len() - self.pos;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for DecodedQuantileIter<'_> {}
impl FusedIterator for DecodedQuantileIter<'_> {}

/// Zero-copy [`ValueAtQuantileView`] pair `(quantile, value)`.
#[derive(Clone, Copy, Debug)]
pub struct DecodedValueAtQuantileView {
    quantile: f64,
    value: f64,
}

impl ValueAtQuantileView for DecodedValueAtQuantileView {
    #[inline]
    fn quantile(&self) -> f64 {
        self.quantile
    }

    #[inline]
    fn value(&self) -> f64 {
        self.value
    }
}

/// Iterator over [`DecodedExemplarView`] entries attached to a data point.
#[derive(Clone)]
pub struct DecodedExemplarIter<'a> {
    table: &'a ExemplarTable,
    key_interner: &'a StringInterner,
    val_interner: &'a StringInterner,
    range: Range<usize>,
}

impl<'a> DecodedExemplarIter<'a> {
    #[inline]
    fn new(
        table: &'a ExemplarTable,
        key_interner: &'a StringInterner,
        val_interner: &'a StringInterner,
        dp_row: usize,
    ) -> Self {
        Self {
            table,
            key_interner,
            val_interner,
            range: table.range_for_dp(dp_row),
        }
    }
}

impl<'a> Iterator for DecodedExemplarIter<'a> {
    type Item = DecodedExemplarView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let row = self.range.next()?;
        Some(DecodedExemplarView {
            table: self.table,
            key_interner: self.key_interner,
            val_interner: self.val_interner,
            row,
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.range.size_hint()
    }
}

impl ExactSizeIterator for DecodedExemplarIter<'_> {}
impl FusedIterator for DecodedExemplarIter<'_> {}

/// Zero-copy [`ExemplarView`] over a single row in `ExemplarTable`.
#[derive(Clone, Copy)]
pub struct DecodedExemplarView<'a> {
    table: &'a ExemplarTable,
    key_interner: &'a StringInterner,
    val_interner: &'a StringInterner,
    row: usize,
}

impl<'a> ExemplarView for DecodedExemplarView<'a> {
    type Attribute<'att>
        = DecodedAttributeView<'att>
    where
        Self: 'att;

    type AttributeIter<'att>
        = DecodedAttrIter<'att>
    where
        Self: 'att;

    #[inline]
    fn filtered_attributes(&self) -> Self::AttributeIter<'_> {
        DecodedAttrIter::new(
            &self.table.attrs,
            self.key_interner,
            self.val_interner,
            self.row,
        )
    }

    #[inline]
    fn time_unix_nano(&self) -> u64 {
        self.table.timestamps[self.row] as u64
    }

    #[inline]
    fn value(&self) -> Option<Value> {
        Some(Value::Double(self.table.values[self.row]))
    }

    #[inline]
    fn span_id(&self) -> Option<&SpanId> {
        self.table
            .span_ids
            .get(self.row)
            .filter(|id| **id != [0u8; 8])
    }

    #[inline]
    fn trace_id(&self) -> Option<&TraceId> {
        self.table
            .trace_ids
            .get(self.row)
            .filter(|id| **id != [0u8; 16])
    }
}

/// Iterator over [`DecodedAttributeView`] key-value pairs for a single parent row.
#[derive(Clone)]
pub struct DecodedAttrIter<'a> {
    pairs: &'a [(u32, u32)],
    key_interner: &'a StringInterner,
    val_interner: &'a StringInterner,
    pos: usize,
}

impl<'a> DecodedAttrIter<'a> {
    #[inline]
    fn new(
        table: &'a AttrTable,
        key_interner: &'a StringInterner,
        val_interner: &'a StringInterner,
        parent_row: usize,
    ) -> Self {
        let range = table.range_for_parent(parent_row);
        Self {
            pairs: &table.pairs[range],
            key_interner,
            val_interner,
            pos: 0,
        }
    }
}

impl<'a> Iterator for DecodedAttrIter<'a> {
    type Item = DecodedAttributeView<'a>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.pairs.len() {
            return None;
        }
        let (key_id, val_id) = self.pairs[self.pos];
        self.pos += 1;
        Some(DecodedAttributeView {
            key: self.key_interner.get_bytes(key_id),
            val: self.val_interner.get_bytes(val_id),
        })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.pairs.len() - self.pos;
        (rem, Some(rem))
    }
}

impl ExactSizeIterator for DecodedAttrIter<'_> {}
impl FusedIterator for DecodedAttrIter<'_> {}

/// Zero-copy [`AttributeView`] borrowing an interned `(key, value)` byte slice pair.
#[derive(Clone, Copy, Debug)]
pub struct DecodedAttributeView<'a> {
    key: &'a [u8],
    val: &'a [u8],
}

impl<'a> AttributeView for DecodedAttributeView<'a> {
    type Val<'val>
        = DecodedStringValueView<'val>
    where
        Self: 'val;

    #[inline]
    fn key(&self) -> Str<'_> {
        self.key
    }

    #[inline]
    fn value(&self) -> Option<Self::Val<'_>> {
        Some(DecodedStringValueView(self.val))
    }
}

/// Zero-copy [`AnyValueView`] wrapping a borrowed string attribute value.
#[derive(Clone, Copy, Debug)]
pub struct DecodedStringValueView<'a>(&'a [u8]);

impl<'a> AnyValueView<'a> for DecodedStringValueView<'a> {
    type KeyValue
        = DecodedAttributeView<'a>
    where
        Self: 'a;

    type ArrayIter<'arr>
        = Empty<Self>
    where
        Self: 'arr;

    type KeyValueIter<'kv>
        = Empty<Self::KeyValue>
    where
        Self: 'kv;

    #[inline]
    fn value_type(&self) -> ValueType {
        ValueType::String
    }

    #[inline]
    fn as_string(&self) -> Option<Str<'_>> {
        Some(self.0)
    }

    #[inline]
    fn as_bool(&self) -> Option<bool> {
        None
    }

    #[inline]
    fn as_int64(&self) -> Option<i64> {
        None
    }

    #[inline]
    fn as_double(&self) -> Option<f64> {
        None
    }

    #[inline]
    fn as_bytes(&self) -> Option<&[u8]> {
        None
    }

    #[inline]
    fn as_array(&self) -> Option<Self::ArrayIter<'_>> {
        None
    }

    #[inline]
    fn as_kvlist(&self) -> Option<Self::KeyValueIter<'_>> {
        None
    }
}
