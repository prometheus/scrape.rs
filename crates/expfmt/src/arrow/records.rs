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

//! Output container and payload discriminants for OTAP metric `RecordBatch` sets.

use arrow_array::RecordBatch;

/// Metric subset of OTAP `ArrowPayloadType` wire discriminants produced by [`super::ArrowDecoder`].
///
/// Discriminant values match `opentelemetry.proto.experimental.arrow.v1.ArrowPayloadType` in
/// [`open-telemetry/otel-arrow`](https://github.com/open-telemetry/otel-arrow), and the
/// `tests/otap-compat` suite asserts exact wire parity against `otel-arrow-dfe-pdata`.
///
/// `expfmt` defines this metric-only enum locally rather than importing `ArrowPayloadType` from
/// `otel-arrow-dfe-pdata` for three reasons:
/// 1. Upstream `otel-arrow` has not split a standalone schema or proto crate out of
///    `otel-arrow-dfe-pdata`, which unconditionally pulls in `datafusion`, `tonic`, and `tokio`
///    and requires MSRV 1.94, exceeding `expfmt`'s MSRV 1.88.
/// 2. `otel-arrow`'s planned Prometheus scrape receiver (`open-telemetry/otel-arrow#3277`) intends
///    to depend on `expfmt`, so a reverse runtime dependency from `expfmt` would create a cycle.
/// 3. `ArrowPayloadType` includes trace and log tables (`Spans`, `Logs`, `SpanEvents`, etc.) that
///    `ArrowDecoder` never emits, whereas `MetricPayloadType` narrows `get` and `iter` to metric
///    tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
#[non_exhaustive]
pub enum MetricPayloadType {
    /// Metric descriptor table (`ArrowPayloadType::UnivariateMetrics = 10`).
    UnivariateMetrics = 10,
    /// Scalar gauge, counter, and untyped data points (`ArrowPayloadType::NumberDataPoints = 11`).
    NumberDataPoints = 11,
    /// Summary data points with quantile values (`ArrowPayloadType::SummaryDataPoints = 12`).
    SummaryDataPoints = 12,
    /// Classic explicit-bucket histogram data points
    /// (`ArrowPayloadType::HistogramDataPoints = 13`).
    HistogramDataPoints = 13,
    /// Key-value label attributes attached to [`Self::NumberDataPoints`]
    /// (`ArrowPayloadType::NumberDpAttrs = 15`).
    NumberDpAttrs = 15,
    /// Key-value label attributes attached to [`Self::SummaryDataPoints`]
    /// (`ArrowPayloadType::SummaryDpAttrs = 16`).
    SummaryDpAttrs = 16,
    /// Key-value label attributes attached to [`Self::HistogramDataPoints`]
    /// (`ArrowPayloadType::HistogramDpAttrs = 17`).
    HistogramDpAttrs = 17,
    /// Exemplars attached to [`Self::NumberDataPoints`]
    /// (`ArrowPayloadType::NumberDpExemplars = 19`).
    NumberDpExemplars = 19,
    /// Exemplars attached to [`Self::HistogramDataPoints`]
    /// (`ArrowPayloadType::HistogramDpExemplars = 20`).
    HistogramDpExemplars = 20,
    /// Filtered attributes attached to [`Self::NumberDpExemplars`]
    /// (`ArrowPayloadType::NumberDpExemplarAttrs = 22`).
    NumberDpExemplarAttrs = 22,
    /// Filtered attributes attached to [`Self::HistogramDpExemplars`]
    /// (`ArrowPayloadType::HistogramDpExemplarAttrs = 23`).
    HistogramDpExemplarAttrs = 23,
    /// Metric-level metadata attributes (`ArrowPayloadType::MetricAttrs = 26`).
    MetricAttrs = 26,
}

impl MetricPayloadType {
    /// Returns the protobuf `ArrowPayloadType` `i32` wire value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Collection of non-empty OTAP metric [`RecordBatch`] tables decoded from a single exposition
/// payload.
///
/// Tables with zero rows are omitted (`None`) to match OTAP batch store invariants.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OtapMetricRecords {
    pub(super) univariate_metrics: Option<RecordBatch>,
    pub(super) metric_attrs: Option<RecordBatch>,
    pub(super) number_data_points: Option<RecordBatch>,
    pub(super) summary_data_points: Option<RecordBatch>,
    pub(super) histogram_data_points: Option<RecordBatch>,
    pub(super) number_dp_attrs: Option<RecordBatch>,
    pub(super) summary_dp_attrs: Option<RecordBatch>,
    pub(super) histogram_dp_attrs: Option<RecordBatch>,
    pub(super) number_dp_exemplars: Option<RecordBatch>,
    pub(super) histogram_dp_exemplars: Option<RecordBatch>,
    pub(super) number_dp_exemplar_attrs: Option<RecordBatch>,
    pub(super) histogram_dp_exemplar_attrs: Option<RecordBatch>,
}

impl OtapMetricRecords {
    /// Returns the `UnivariateMetrics` table (`ArrowPayloadType = 10`), if non-empty.
    #[must_use]
    pub fn univariate_metrics(&self) -> Option<&RecordBatch> {
        self.univariate_metrics.as_ref()
    }

    /// Returns the `MetricAttrs` table (`ArrowPayloadType = 26`), if non-empty.
    #[must_use]
    pub fn metric_attrs(&self) -> Option<&RecordBatch> {
        self.metric_attrs.as_ref()
    }

    /// Returns the `NumberDataPoints` table (`ArrowPayloadType = 11`), if non-empty.
    #[must_use]
    pub fn number_data_points(&self) -> Option<&RecordBatch> {
        self.number_data_points.as_ref()
    }

    /// Returns the `SummaryDataPoints` table (`ArrowPayloadType = 12`), if non-empty.
    #[must_use]
    pub fn summary_data_points(&self) -> Option<&RecordBatch> {
        self.summary_data_points.as_ref()
    }

    /// Returns the `HistogramDataPoints` table (`ArrowPayloadType = 13`), if non-empty.
    #[must_use]
    pub fn histogram_data_points(&self) -> Option<&RecordBatch> {
        self.histogram_data_points.as_ref()
    }

    /// Returns the `NumberDpAttrs` table (`ArrowPayloadType = 15`), if non-empty.
    #[must_use]
    pub fn number_dp_attrs(&self) -> Option<&RecordBatch> {
        self.number_dp_attrs.as_ref()
    }

    /// Returns the `SummaryDpAttrs` table (`ArrowPayloadType = 16`), if non-empty.
    #[must_use]
    pub fn summary_dp_attrs(&self) -> Option<&RecordBatch> {
        self.summary_dp_attrs.as_ref()
    }

    /// Returns the `HistogramDpAttrs` table (`ArrowPayloadType = 17`), if non-empty.
    #[must_use]
    pub fn histogram_dp_attrs(&self) -> Option<&RecordBatch> {
        self.histogram_dp_attrs.as_ref()
    }

    /// Returns the `NumberDpExemplars` table (`ArrowPayloadType = 19`), if non-empty.
    #[must_use]
    pub fn number_dp_exemplars(&self) -> Option<&RecordBatch> {
        self.number_dp_exemplars.as_ref()
    }

    /// Returns the `HistogramDpExemplars` table (`ArrowPayloadType = 20`), if non-empty.
    #[must_use]
    pub fn histogram_dp_exemplars(&self) -> Option<&RecordBatch> {
        self.histogram_dp_exemplars.as_ref()
    }

    /// Returns the `NumberDpExemplarAttrs` table (`ArrowPayloadType = 22`), if non-empty.
    #[must_use]
    pub fn number_dp_exemplar_attrs(&self) -> Option<&RecordBatch> {
        self.number_dp_exemplar_attrs.as_ref()
    }

    /// Returns the `HistogramDpExemplarAttrs` table (`ArrowPayloadType = 23`), if non-empty.
    #[must_use]
    pub fn histogram_dp_exemplar_attrs(&self) -> Option<&RecordBatch> {
        self.histogram_dp_exemplar_attrs.as_ref()
    }

    /// Looks up a decoded [`RecordBatch`] by its [`MetricPayloadType`].
    #[must_use]
    pub fn get(&self, payload_type: MetricPayloadType) -> Option<&RecordBatch> {
        match payload_type {
            MetricPayloadType::UnivariateMetrics => self.univariate_metrics.as_ref(),
            MetricPayloadType::NumberDataPoints => self.number_data_points.as_ref(),
            MetricPayloadType::SummaryDataPoints => self.summary_data_points.as_ref(),
            MetricPayloadType::HistogramDataPoints => self.histogram_data_points.as_ref(),
            MetricPayloadType::NumberDpAttrs => self.number_dp_attrs.as_ref(),
            MetricPayloadType::SummaryDpAttrs => self.summary_dp_attrs.as_ref(),
            MetricPayloadType::HistogramDpAttrs => self.histogram_dp_attrs.as_ref(),
            MetricPayloadType::NumberDpExemplars => self.number_dp_exemplars.as_ref(),
            MetricPayloadType::HistogramDpExemplars => self.histogram_dp_exemplars.as_ref(),
            MetricPayloadType::NumberDpExemplarAttrs => self.number_dp_exemplar_attrs.as_ref(),
            MetricPayloadType::HistogramDpExemplarAttrs => {
                self.histogram_dp_exemplar_attrs.as_ref()
            }
            MetricPayloadType::MetricAttrs => self.metric_attrs.as_ref(),
        }
    }

    /// Replaces or clears the [`RecordBatch`] stored under `payload_type`.
    ///
    /// Batches with `num_rows() == 0` are normalized to `None` to preserve OTAP's non-empty table
    /// invariant.
    pub fn set(&mut self, payload_type: MetricPayloadType, batch: Option<RecordBatch>) {
        let normalized = batch.filter(|b| b.num_rows() > 0);
        let slot = match payload_type {
            MetricPayloadType::UnivariateMetrics => &mut self.univariate_metrics,
            MetricPayloadType::NumberDataPoints => &mut self.number_data_points,
            MetricPayloadType::SummaryDataPoints => &mut self.summary_data_points,
            MetricPayloadType::HistogramDataPoints => &mut self.histogram_data_points,
            MetricPayloadType::NumberDpAttrs => &mut self.number_dp_attrs,
            MetricPayloadType::SummaryDpAttrs => &mut self.summary_dp_attrs,
            MetricPayloadType::HistogramDpAttrs => &mut self.histogram_dp_attrs,
            MetricPayloadType::NumberDpExemplars => &mut self.number_dp_exemplars,
            MetricPayloadType::HistogramDpExemplars => &mut self.histogram_dp_exemplars,
            MetricPayloadType::NumberDpExemplarAttrs => &mut self.number_dp_exemplar_attrs,
            MetricPayloadType::HistogramDpExemplarAttrs => &mut self.histogram_dp_exemplar_attrs,
            MetricPayloadType::MetricAttrs => &mut self.metric_attrs,
        };
        *slot = normalized;
    }

    /// Iterates over all non-empty `(MetricPayloadType, &RecordBatch)` pairs in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (MetricPayloadType, &RecordBatch)> {
        [
            (
                MetricPayloadType::UnivariateMetrics,
                self.univariate_metrics.as_ref(),
            ),
            (
                MetricPayloadType::NumberDataPoints,
                self.number_data_points.as_ref(),
            ),
            (
                MetricPayloadType::SummaryDataPoints,
                self.summary_data_points.as_ref(),
            ),
            (
                MetricPayloadType::HistogramDataPoints,
                self.histogram_data_points.as_ref(),
            ),
            (
                MetricPayloadType::NumberDpAttrs,
                self.number_dp_attrs.as_ref(),
            ),
            (
                MetricPayloadType::SummaryDpAttrs,
                self.summary_dp_attrs.as_ref(),
            ),
            (
                MetricPayloadType::HistogramDpAttrs,
                self.histogram_dp_attrs.as_ref(),
            ),
            (
                MetricPayloadType::NumberDpExemplars,
                self.number_dp_exemplars.as_ref(),
            ),
            (
                MetricPayloadType::HistogramDpExemplars,
                self.histogram_dp_exemplars.as_ref(),
            ),
            (
                MetricPayloadType::NumberDpExemplarAttrs,
                self.number_dp_exemplar_attrs.as_ref(),
            ),
            (
                MetricPayloadType::HistogramDpExemplarAttrs,
                self.histogram_dp_exemplar_attrs.as_ref(),
            ),
            (MetricPayloadType::MetricAttrs, self.metric_attrs.as_ref()),
        ]
        .into_iter()
        .filter_map(|(kind, batch)| batch.map(|b| (kind, b)))
    }

    /// Consumes `self` and yields all non-empty `(MetricPayloadType, RecordBatch)` pairs.
    pub fn into_batches(self) -> impl Iterator<Item = (MetricPayloadType, RecordBatch)> {
        [
            (
                MetricPayloadType::UnivariateMetrics,
                self.univariate_metrics,
            ),
            (MetricPayloadType::NumberDataPoints, self.number_data_points),
            (
                MetricPayloadType::SummaryDataPoints,
                self.summary_data_points,
            ),
            (
                MetricPayloadType::HistogramDataPoints,
                self.histogram_data_points,
            ),
            (MetricPayloadType::NumberDpAttrs, self.number_dp_attrs),
            (MetricPayloadType::SummaryDpAttrs, self.summary_dp_attrs),
            (MetricPayloadType::HistogramDpAttrs, self.histogram_dp_attrs),
            (
                MetricPayloadType::NumberDpExemplars,
                self.number_dp_exemplars,
            ),
            (
                MetricPayloadType::HistogramDpExemplars,
                self.histogram_dp_exemplars,
            ),
            (
                MetricPayloadType::NumberDpExemplarAttrs,
                self.number_dp_exemplar_attrs,
            ),
            (
                MetricPayloadType::HistogramDpExemplarAttrs,
                self.histogram_dp_exemplar_attrs,
            ),
            (MetricPayloadType::MetricAttrs, self.metric_attrs),
        ]
        .into_iter()
        .filter_map(|(kind, batch)| batch.map(|b| (kind, b)))
    }

    /// Returns `true` when the payload produced zero metric families.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.univariate_metrics.is_none()
    }

    /// Returns the number of emitted metric families in `UnivariateMetrics`.
    #[must_use]
    pub fn num_metrics(&self) -> usize {
        self.univariate_metrics
            .as_ref()
            .map_or(0, RecordBatch::num_rows)
    }

    /// Returns the total number of data points across `NumberDataPoints`, `SummaryDataPoints`,
    /// and `HistogramDataPoints`.
    #[must_use]
    pub fn num_data_points(&self) -> usize {
        self.number_data_points
            .as_ref()
            .map_or(0, RecordBatch::num_rows)
            + self
                .summary_data_points
                .as_ref()
                .map_or(0, RecordBatch::num_rows)
            + self
                .histogram_data_points
                .as_ref()
                .map_or(0, RecordBatch::num_rows)
    }
}
