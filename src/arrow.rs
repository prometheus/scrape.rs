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

//! Layer 1 columnar Apache Arrow decoder producing OpenTelemetry Arrow Protocol metric batches.
//!
//! [`ArrowDecoder`] ingests entries from Layer 0 parsers one by one into reusable columnar buffers
//! and arena-backed string interners without per-sample heap allocations, locks, or shared
//! thread-synchronized state. Callers can materialize a full scrape with [`ArrowDecoder::decode`]
//! or pull bounded chunks with [`ArrowDecoder::decode_stream`] so single-threaded `!Send` scrape
//! loops keep scratch memory bounded and stay within OTAP's `u16` per-batch metric ID limit.

mod columns;
mod family;
mod intern;
mod options;
mod records;
mod schema;
#[cfg(test)]
mod tests;
pub mod views;

use std::iter::FusedIterator;

pub use otel_arrow_dfe_pdata_views as pdata_views;

use crate::format::{Format, FormatType};
use crate::parse::{
    Entry, LabelSpan, METRIC_NAME_LABEL, MetricType, OmScratch, OpenMetricsParser, ParseError,
    Parser, PromParser, parse_go_float, unescape_bytes_into,
};

use self::columns::{
    AttrEncoding, HistogramDpTable, MetricTable, NumberDpTable, ScratchBuffers, SummaryDpTable,
    f64_to_u64_count, ms_to_ns, parse_hex_array,
};
use self::family::{CurrentFamily, FamilyAssembly, SeriesRole};
use self::intern::StringInterner;
pub use self::options::{
    CounterSuffixPolicy, DEFAULT_MAX_DATA_POINTS_PER_BATCH, DecodeError, DecodeOptions,
    UnitSuffixPolicy, UntypedPolicy,
};
pub use self::records::{MetricPayloadType, OtapMetricRecords};
pub use self::schema::PROMETHEUS_TYPE_METADATA_KEY;
pub use self::views::DecodedMetricsView;

/// Maximum distinct `UnivariateMetrics` rows representable in a single OTAP batch (`u16` IDs).
const MAX_METRICS_PER_BATCH: usize = (u16::MAX as usize) + 1;

type SpanAndTraceId = (Option<[u8; 8]>, Option<[u8; 16]>);

enum ActiveParser<'input> {
    Prom(PromParser<'input>),
    OpenMetrics(OpenMetricsParser<'input>),
    Invalid,
}

impl<'input> ActiveParser<'input> {
    #[inline]
    fn is_openmetrics(&self) -> bool {
        matches!(self, Self::OpenMetrics(_))
    }

    #[inline]
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        match self {
            Self::Prom(p) => p.next_entry(),
            Self::OpenMetrics(p) => p.next_entry(),
            Self::Invalid => Ok(None),
        }
    }

    #[inline]
    fn name_offset(&self) -> usize {
        match self {
            Self::Prom(p) => p.name_offset(),
            Self::OpenMetrics(p) => p.name_offset(),
            Self::Invalid => 0,
        }
    }

    #[inline]
    fn raw_help(&self) -> (&'input [u8], &'input [u8]) {
        match self {
            Self::Prom(p) => p.raw_help(),
            Self::OpenMetrics(p) => p.raw_help(),
            Self::Invalid => (b"", b""),
        }
    }

    #[inline]
    fn metric_type(&self) -> (&[u8], MetricType) {
        match self {
            Self::Prom(p) => p.metric_type(),
            Self::OpenMetrics(p) => p.metric_type(),
            Self::Invalid => (b"", MetricType::Unknown),
        }
    }

    #[inline]
    fn unit(&self) -> (&[u8], &[u8]) {
        match self {
            Self::Prom(p) => p.unit(),
            Self::OpenMetrics(p) => p.unit(),
            Self::Invalid => (b"", b""),
        }
    }

    #[inline]
    fn raw_series_parts(&self) -> (&'input [u8], &[LabelSpan], &'input [u8], Option<i64>, f64) {
        match self {
            Self::Prom(p) => p.raw_series_parts(),
            Self::OpenMetrics(p) => p.raw_series_parts(),
            Self::Invalid => (b"", &[], b"", None, 0.0),
        }
    }

    #[inline]
    fn raw_exemplar_parts(&self) -> Option<(f64, Option<i64>, &[LabelSpan])> {
        match self {
            Self::Prom(_) | Self::Invalid => None,
            Self::OpenMetrics(p) => p.raw_exemplar_parts(),
        }
    }

    #[inline]
    fn start_timestamp(&mut self) -> Option<i64> {
        match self {
            Self::Prom(_) | Self::Invalid => None,
            Self::OpenMetrics(p) => p.start_timestamp(),
        }
    }

    fn take_scratch_into(&mut self, decoder: &mut ArrowDecoder) {
        match self {
            Self::Prom(p) => decoder.prom_spans = p.take_scratch(),
            Self::OpenMetrics(p) => decoder.om_scratch = p.take_scratch(),
            Self::Invalid => {}
        }
    }
}

/// Stateful, lock-free decoder translating Prometheus and OpenMetrics exposition payloads into OTAP
/// Arrow metric [`arrow_array::RecordBatch`]es.
///
/// Reusing a single `ArrowDecoder` across scrapes preserves internal parser scratch spans, label
/// string interners, and column staging buffers so steady-state scrapes allocate only the output
/// Arrow `Buffer`s returned inside [`OtapMetricRecords`].
pub struct ArrowDecoder {
    prom_spans: Vec<LabelSpan>,
    om_scratch: OmScratch,
    unescape_buf: Vec<u8>,
    series_name_buf: Vec<u8>,
    current_family: CurrentFamily,
    assembly: FamilyAssembly,

    metrics: MetricTable,
    key_interner: StringInterner,
    val_interner: StringInterner,
    num_dp: NumberDpTable,
    sum_dp: SummaryDpTable,
    hist_dp: HistogramDpTable,
    temp_attrs: Vec<(u32, u32)>,
    scratch: ScratchBuffers,
}

impl Default for ArrowDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArrowDecoder {
    /// Creates a new [`ArrowDecoder`] with default initial buffer capacities.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(64, 256, 512)
    }

    /// Creates a new [`ArrowDecoder`] pre-sized for `metrics` families, `data_points` series, and
    /// `attrs` label pairs.
    #[must_use]
    pub fn with_capacity(metrics: usize, data_points: usize, attrs: usize) -> Self {
        Self {
            prom_spans: Vec::with_capacity(16),
            om_scratch: OmScratch::default(),
            unescape_buf: Vec::new(),
            series_name_buf: Vec::with_capacity(64),
            current_family: CurrentFamily::with_capacity(64, 128),
            assembly: FamilyAssembly::default(),

            metrics: MetricTable::with_capacity(metrics),
            key_interner: StringInterner::with_capacity(64, 1024),
            val_interner: StringInterner::with_capacity(256, 4096),
            num_dp: NumberDpTable::with_capacity(data_points, attrs),
            sum_dp: SummaryDpTable::default(),
            hist_dp: HistogramDpTable::default(),
            temp_attrs: Vec::new(),
            scratch: ScratchBuffers::with_capacity(metrics, data_points, attrs),
        }
    }

    /// Returns the total heap buffer capacity in bytes currently retained by this decoder's
    /// reusable scratch structures.
    #[must_use]
    pub fn retained_memory_bytes(&self) -> usize {
        self.prom_spans.capacity() * size_of::<LabelSpan>()
            + self.om_scratch.retained_memory_bytes()
            + self.unescape_buf.capacity()
            + self.series_name_buf.capacity()
            + self.current_family.retained_memory_bytes()
            + self.assembly.retained_memory_bytes()
            + self.metrics.retained_memory_bytes()
            + self.key_interner.retained_memory_bytes()
            + self.val_interner.retained_memory_bytes()
            + self.num_dp.retained_memory_bytes()
            + self.sum_dp.retained_memory_bytes()
            + self.hist_dp.retained_memory_bytes()
            + self.temp_attrs.capacity() * size_of::<(u32, u32)>()
            + self.scratch.retained_memory_bytes()
    }

    /// Decodes a single exposition scrape buffer of `format` into OTAP metric
    /// [`arrow_array::RecordBatch`]es.
    ///
    /// # Contiguous families and batching
    ///
    /// Input parsing streams `Entry` items one by one from [`PromParser`] or
    /// [`OpenMetricsParser`] directly into reusable columnar staging vectors and label string
    /// interners without materializing intermediate per-sample structs or per-string allocations.
    /// Metric families are decoded as contiguous runs, with `# HELP`, `# TYPE`, and `# UNIT`
    /// lines appearing before that family's samples. Non-contiguous repetitions of an earlier
    /// metric name are not reassembled or rejected; each run starts with fresh `untyped` metadata
    /// unless preceded by its own metadata lines.
    ///
    /// Single-batch `decode` returns [`DecodeError::CapacityOverflow`] if a scrape contains more
    /// than 65,536 distinct metric families (OTAP's `u16` `UnivariateMetrics.id` limit). Use
    /// [`ArrowDecoder::decode_stream`] for unbounded or chunked scrapes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `format` is unsupported, the exposition payload fails syntax or
    /// UTF-8 validation, duplicate or late metadata lines are encountered within a contiguous
    /// family, duplicate label names appear on a sample, or an OTAP table exceeds its integer ID
    /// width.
    pub fn decode(
        &mut self,
        input: &[u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<OtapMetricRecords, DecodeError> {
        let has_default_ts = self.stage_scrape(input, format, opts)?;
        self.finish_batches(has_default_ts)
    }

    /// Decodes a single exposition scrape buffer of `format` into [`ArrowDecoder`]'s reusable
    /// staging buffers and returns a zero-copy [`DecodedMetricsView`] implementing
    /// [`otel_arrow_dfe_pdata_views::views::metrics::MetricsView`].
    ///
    /// Unlike [`ArrowDecoder::decode`], `decode_view` skips materializing Arrow
    /// [`arrow_array::RecordBatch`]es, allowing downstream [`MetricsView`] consumers to traverse
    /// the staged metric families, data points, exemplars, and interned attributes directly.
    /// Callers that need OTAP Arrow [`arrow_array::RecordBatch`]es should prefer
    /// [`ArrowDecoder::decode`] (or [`DecodeStream::next`]), which builds dictionary-encoded
    /// Arrow columns directly from the decoder's interners and is faster and lower-allocation
    /// than passing [`DecodedMetricsView`] through
    /// `otel_arrow_dfe_pdata::encode::encode_metrics_otap_batch`.
    ///
    /// Note that [`views::DecodedHistogramDataPointView::sum`] preserves explicit `Some(0.0)`
    /// histogram sums (matching [`ArrowDecoder::decode`]), whereas passing the view into
    /// `otel_arrow_dfe_pdata::encode::encode_metrics_otap_batch` elides the
    /// `HistogramDataPoints.sum` column when every histogram in the batch has `sum == 0.0`
    /// because upstream configures that column with `default_values_optional: true`.
    ///
    /// [`MetricsView`]: otel_arrow_dfe_pdata_views::views::metrics::MetricsView
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] under the same conditions as [`ArrowDecoder::decode`].
    pub fn decode_view(
        &mut self,
        input: &[u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<DecodedMetricsView<'_>, DecodeError> {
        self.stage_scrape(input, format, opts)?;
        Ok(self.view())
    }

    /// Returns a zero-copy [`DecodedMetricsView`] over the metric batch currently staged in `self`.
    #[inline]
    #[must_use]
    pub fn view(&self) -> DecodedMetricsView<'_> {
        DecodedMetricsView::new(self)
    }

    fn stage_scrape(
        &mut self,
        input: &[u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<bool, DecodeError> {
        self.reset_scrape();
        let (mut parser, default_ts_ns) = self.init_scrape_parser(input, format, opts)?;

        let mut pending_series = false;
        let mut done = false;
        let res = self.stage_entries::<false>(
            &mut parser,
            opts,
            default_ts_ns,
            0,
            &mut pending_series,
            &mut done,
        );
        parser.take_scratch_into(self);
        if let Err(err) = res {
            self.reset_scrape();
            return Err(err);
        }
        Ok(default_ts_ns.is_some())
    }

    /// Streams `input` as a sequence of non-empty [`OtapMetricRecords`] chunks bounded by
    /// [`DecodeOptions::max_data_points_per_batch`] and OTAP's 65,536-metric per-batch `u16` ID
    /// limit.
    ///
    /// Empty or metadata-only scrapes yield zero items. When a contiguous metric family spans a
    /// chunk boundary, [`ArrowDecoder`] retains its `# HELP`, `# TYPE`, and `# UNIT` metadata
    /// across the flush and re-emits the family row in the next chunk only if further samples
    /// follow. Dropping [`DecodeStream`] early returns the internal parser scratch buffer to
    /// `self`.
    pub fn decode_stream<'dec, 'input>(
        &'dec mut self,
        input: &'input [u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> DecodeStream<'dec, 'input> {
        self.reset_scrape();
        let max_data_points = opts
            .max_data_points_per_batch
            .clamp(1, (u32::MAX as usize).saturating_add(1));

        match self.init_scrape_parser(input, format, opts) {
            Ok((parser, default_ts_ns)) => DecodeStream {
                decoder: self,
                parser,
                opts: *opts,
                default_ts_ns,
                max_data_points,
                pending_series: false,
                init_err: None,
                done: false,
            },
            Err(err) => DecodeStream {
                decoder: self,
                parser: ActiveParser::Invalid,
                opts: *opts,
                default_ts_ns: None,
                max_data_points,
                pending_series: false,
                init_err: Some(err),
                done: false,
            },
        }
    }

    fn init_scrape_parser<'input>(
        &mut self,
        input: &'input [u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<(ActiveParser<'input>, Option<i64>), DecodeError> {
        let default_ts_ns = match opts.timestamp_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => None,
        };
        let parser = match format.format_type() {
            FormatType::TextPlain => {
                let spans = std::mem::take(&mut self.prom_spans);
                ActiveParser::Prom(PromParser::with_scratch(input, spans))
            }
            FormatType::OpenMetrics if !format.version().starts_with("2.") => {
                // TODO(bwplotka): Dispatch OpenMetrics 2.0 in Phase 3.
                let scratch = std::mem::take(&mut self.om_scratch);
                ActiveParser::OpenMetrics(OpenMetricsParser::with_scratch(input, scratch))
            }
            _ => {
                // TODO(bwplotka): Dispatch Proto* in Phase 3.
                return Err(DecodeError::UnsupportedFormat(format.as_str().to_owned()));
            }
        };
        Ok((parser, default_ts_ns))
    }

    fn reset_scrape(&mut self) {
        self.current_family.clear();
        self.assembly.clear();
        self.reset_batch();
    }

    fn reset_batch(&mut self) {
        self.current_family.batch_id = None;
        self.metrics.clear();
        self.key_interner.clear();
        self.val_interner.clear();
        self.num_dp.clear();
        self.sum_dp.clear();
        self.hist_dp.clear();
    }

    #[inline]
    fn total_data_points(&self) -> usize {
        self.num_dp.base.len() + self.sum_dp.base.len() + self.hist_dp.base.len()
    }

    #[inline]
    fn batch_data_points(&self) -> usize {
        self.total_data_points() + self.assembly.groups.len()
    }

    #[inline]
    fn flush_pending_family(
        &mut self,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        self.assembly.flush(
            &mut self.current_family,
            &mut self.metrics,
            &mut self.sum_dp,
            &mut self.hist_dp,
            opts,
            default_ts_ns,
        )
    }

    #[inline]
    fn transition_family_for_metadata(
        &mut self,
        raw_name: &[u8],
        name_offset: usize,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        if self.current_family.active && self.current_family.raw_name.as_slice() == raw_name {
            return Ok(());
        }
        if !raw_name.is_ascii() && std::str::from_utf8(raw_name).is_err() {
            return Err(DecodeError::InvalidUtf8 {
                offset: name_offset,
            });
        }
        let unescaped = unescape_bytes_into(raw_name, true, &mut self.unescape_buf);
        if self.current_family.active && self.current_family.unescaped_name.as_slice() == unescaped
        {
            self.current_family.raw_name.clear();
            self.current_family.raw_name.extend_from_slice(raw_name);
            return Ok(());
        }

        self.series_name_buf.clear();
        self.series_name_buf.extend_from_slice(unescaped);
        self.flush_pending_family(opts, default_ts_ns)?;
        self.current_family
            .start_new(raw_name, &self.series_name_buf);
        Ok(())
    }

    // Monomorphizing on `CHUNKED` shares one entry dispatch loop between single-batch (`false`)
    // and streaming (`true`) decoding while compiling out chunk-boundary checks on single-batch
    // calls. Returns `Ok(true)` when a non-empty chunk (or single batch) is staged.
    fn stage_entries<const CHUNKED: bool>(
        &mut self,
        parser: &mut ActiveParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
        max_data_points: usize,
        pending_series: &mut bool,
        done: &mut bool,
    ) -> Result<bool, DecodeError> {
        loop {
            let entry = if CHUNKED && *pending_series {
                *pending_series = false;
                Entry::Series
            } else {
                match parser.next_entry().map_err(DecodeError::from_parse)? {
                    Some(entry) => entry,
                    None => {
                        self.flush_pending_family(opts, default_ts_ns)?;
                        *done = true;
                        if CHUNKED {
                            return Ok(!self.metrics.is_empty());
                        }
                        return Ok(true);
                    }
                }
            };

            match entry {
                // `Entry::Histogram` arrives with #22.
                Entry::Comment | Entry::Histogram => {}
                Entry::Help => self.ingest_help_entry(parser, opts, default_ts_ns)?,
                Entry::Type => self.ingest_type_entry(parser, opts, default_ts_ns)?,
                Entry::Unit => self.ingest_unit_entry(parser, opts, default_ts_ns)?,
                Entry::Series => {
                    let (raw_name, name_offset) = {
                        let (rn, _, _, _, _) = parser.raw_series_parts();
                        (rn, parser.name_offset())
                    };
                    if !raw_name.is_ascii() && std::str::from_utf8(raw_name).is_err() {
                        return Err(DecodeError::InvalidUtf8 {
                            offset: name_offset,
                        });
                    }
                    let role = if self.current_family.active
                        && self.current_family.raw_name.as_slice() == raw_name
                        && !matches!(
                            self.current_family.metric_type,
                            MetricType::Histogram | MetricType::GaugeHistogram
                        ) {
                        if self.current_family.metric_type == MetricType::Summary {
                            SeriesRole::SummaryQuantile
                        } else {
                            SeriesRole::Scalar
                        }
                    } else {
                        let unescaped = unescape_bytes_into(raw_name, true, &mut self.unescape_buf);
                        if let Some(r) = self.current_family.classify_series(unescaped) {
                            r
                        } else {
                            self.series_name_buf.clear();
                            self.series_name_buf.extend_from_slice(unescaped);
                            self.flush_pending_family(opts, default_ts_ns)?;
                            if CHUNKED && self.total_data_points() >= max_data_points {
                                self.current_family
                                    .start_new(raw_name, &self.series_name_buf);
                                *pending_series = true;
                                return Ok(true);
                            }
                            self.current_family
                                .start_new(raw_name, &self.series_name_buf);
                            SeriesRole::Scalar
                        }
                    };

                    if CHUNKED {
                        let split_assembled = !self.assembly.is_empty()
                            && self.batch_data_points() >= max_data_points
                            && !self.series_matches_staged_group(parser, role);
                        let split_scalar = self.assembly.is_empty()
                            && (self.total_data_points() >= max_data_points
                                || (self.current_family.batch_id.is_none()
                                    && self.metrics.len() >= MAX_METRICS_PER_BATCH));
                        if split_assembled || split_scalar {
                            if split_assembled {
                                self.flush_pending_family(opts, default_ts_ns)?;
                            }
                            *pending_series = true;
                            return Ok(true);
                        }
                    }

                    self.ingest_series_entry(parser, role, opts, default_ts_ns)?;

                    if CHUNKED
                        && self.assembly.is_empty()
                        && self.total_data_points() >= max_data_points
                    {
                        return Ok(true);
                    }
                }
            }
        }
    }

    #[inline]
    fn ingest_help_entry(
        &mut self,
        parser: &ActiveParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let (raw_name, raw_help) = parser.raw_help();
        let name_offset = parser.name_offset();
        // Match `prometheus/common/expfmt/text_parse.go`: a bare `# HELP name` line without
        // docstring text is a no-op and does not count as setting HELP or transitioning families.
        if raw_help.is_empty() {
            if !raw_name.is_ascii() && std::str::from_utf8(raw_name).is_err() {
                return Err(DecodeError::InvalidUtf8 {
                    offset: name_offset,
                });
            }
            return Ok(());
        }
        self.transition_family_for_metadata(raw_name, name_offset, opts, default_ts_ns)?;
        if self.current_family.has_help
            || self.current_family.has_samples
            || !self.assembly.is_empty()
        {
            return Err(DecodeError::DuplicateOrLateHelp {
                metric: self.current_family.name_string(),
            });
        }
        let unescaped =
            unescape_bytes_into(raw_help, parser.is_openmetrics(), &mut self.unescape_buf);
        self.current_family.help.clear();
        self.current_family.help.extend_from_slice(unescaped);
        self.current_family.has_help = true;
        Ok(())
    }

    #[inline]
    fn ingest_type_entry(
        &mut self,
        parser: &ActiveParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let (raw_name, metric_type) = parser.metric_type();
        let name_offset = parser.name_offset();
        self.transition_family_for_metadata(raw_name, name_offset, opts, default_ts_ns)?;
        if self.current_family.has_type
            || self.current_family.has_samples
            || !self.assembly.is_empty()
        {
            return Err(DecodeError::DuplicateOrLateType {
                metric: self.current_family.name_string(),
            });
        }
        self.current_family.metric_type = metric_type;
        self.current_family.has_type = true;
        Ok(())
    }

    #[inline]
    fn ingest_unit_entry(
        &mut self,
        parser: &ActiveParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let (raw_name, raw_unit) = parser.unit();
        let name_offset = parser.name_offset();
        if raw_unit.is_empty() {
            return Ok(());
        }
        self.transition_family_for_metadata(raw_name, name_offset, opts, default_ts_ns)?;
        if self.current_family.has_unit
            || self.current_family.has_samples
            || !self.assembly.is_empty()
        {
            return Err(DecodeError::DuplicateOrLateUnit {
                metric: self.current_family.name_string(),
            });
        }
        let unescaped = unescape_bytes_into(raw_unit, true, &mut self.unescape_buf);
        self.current_family.unit.clear();
        self.current_family.unit.extend_from_slice(unescaped);
        self.current_family.has_unit = true;
        Ok(())
    }

    #[inline]
    fn ingest_series_entry(
        &mut self,
        parser: &mut ActiveParser<'_>,
        role: SeriesRole,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        match role {
            SeriesRole::Scalar => self.append_scalar_series(parser, opts, default_ts_ns),
            SeriesRole::HistogramBucket
            | SeriesRole::HistogramSum
            | SeriesRole::HistogramCount
            | SeriesRole::SummaryQuantile
            | SeriesRole::SummarySum
            | SeriesRole::SummaryCount => self.append_assembled_series(parser, role, default_ts_ns),
        }
    }

    #[inline]
    fn append_scalar_series(
        &mut self,
        parser: &mut ActiveParser<'_>,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let start_ts_ms = if self.current_family.metric_type == MetricType::Counter {
            parser.start_timestamp()
        } else {
            None
        };
        let (_, label_spans, full_input, sample_ts_ms, value) = parser.raw_series_parts();
        let exemplar_parts = parser.raw_exemplar_parts();

        // Always validate series labels first so duplicate/reserved labels are caught even when a
        // translation policy drops the metric family.
        let is_dropped = self.current_family.metric_type == MetricType::Unknown
            && opts.untyped_policy == UntypedPolicy::Drop;
        if is_dropped {
            for span_idx in 0..label_spans.len() {
                self.validate_empty_label(span_idx, &label_spans[..=span_idx], full_input)?;
            }
            self.current_family.has_samples = true;
            return Ok(());
        }

        let dp_index = self.num_dp.base.len();
        let dp_id = u32::try_from(dp_index).map_err(|_| DecodeError::CapacityOverflow {
            table: "NumberDataPoints",
            count: dp_index + 1,
        })?;

        self.extract_series_labels_into_temp(label_spans, full_input, None)?;
        self.num_dp.attrs.extend_for_parent(dp_id, &self.temp_attrs);

        if let Some((ex_val, ex_ts_ms, ex_spans)) = exemplar_parts {
            self.append_number_exemplar(
                dp_id,
                ex_val,
                ex_ts_ms,
                ex_spans,
                full_input,
                default_ts_ns,
            )?;
        }

        let parent_id = self
            .current_family
            .emit_into_batch(&mut self.metrics, opts, dp_id)?;
        let start_ts_ns = start_ts_ms.and_then(|ms| ms.checked_mul(1_000_000));
        let resolved_ts_ns = match sample_ts_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => default_ts_ns,
        };
        self.num_dp
            .base
            .push(parent_id, start_ts_ns, resolved_ts_ns);
        self.num_dp.values.push(value);
        self.metrics.set_dp_end(parent_id, dp_id + 1);
        Ok(())
    }

    fn append_assembled_series(
        &mut self,
        parser: &mut ActiveParser<'_>,
        role: SeriesRole,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let special_label = match role {
            SeriesRole::HistogramBucket => Some(b"le" as &[u8]),
            SeriesRole::SummaryQuantile => Some(b"quantile" as &[u8]),
            _ => None,
        };
        let (sample_ts_ms, value, special_bound) = {
            let (_, label_spans, full_input, sample_ts_ms, value) = parser.raw_series_parts();
            let bound =
                self.extract_series_labels_into_temp(label_spans, full_input, special_label)?;
            (sample_ts_ms, value, bound)
        };

        let group_idx = self.assembly.find_or_create_group(&self.temp_attrs);
        let sample_ts_ns = match sample_ts_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => None,
        };
        let om_start_ts_ns = if !self.assembly.groups[group_idx].start_ts_checked {
            self.assembly.groups[group_idx].start_ts_checked = true;
            if parser.is_openmetrics() {
                parser
                    .start_timestamp()
                    .and_then(|ms| ms.checked_mul(1_000_000))
            } else {
                None
            }
        } else {
            None
        };

        let group = &mut self.assembly.groups[group_idx];
        if group.ts_ns.is_none() && sample_ts_ns.is_some() {
            group.ts_ns = sample_ts_ns;
        }
        if group.start_ts_ns.is_none() && om_start_ts_ns.is_some() {
            group.start_ts_ns = om_start_ts_ns;
        }

        match role {
            SeriesRole::HistogramBucket | SeriesRole::SummaryQuantile => {
                if let Some(bound) = special_bound
                    && (bound.is_finite()
                        || (role == SeriesRole::HistogramBucket && bound == f64::INFINITY))
                {
                    self.assembly.push_point(group_idx, bound, value);
                }
            }
            SeriesRole::HistogramSum | SeriesRole::SummarySum => {
                group.sum = Some(value);
            }
            SeriesRole::HistogramCount | SeriesRole::SummaryCount => {
                group.count = Some(f64_to_u64_count(value));
            }
            SeriesRole::Scalar => {}
        }

        if matches!(
            self.current_family.metric_type,
            MetricType::Histogram | MetricType::GaugeHistogram
        ) && let Some((ex_val, ex_ts_ms, ex_spans)) = parser.raw_exemplar_parts()
        {
            let full_input = parser.raw_series_parts().2;
            self.stage_pending_histogram_exemplar(
                group_idx,
                ex_val,
                ex_ts_ms,
                ex_spans,
                full_input,
                default_ts_ns,
            )?;
        }

        Ok(())
    }

    /// Checks whether the current assembled series line belongs to a data-point group already
    /// staged in `self.assembly` without interning new keys or values into the active batch.
    fn series_matches_staged_group(&mut self, parser: &ActiveParser<'_>, role: SeriesRole) -> bool {
        let special_label = match role {
            SeriesRole::HistogramBucket => Some(b"le" as &[u8]),
            SeriesRole::SummaryQuantile => Some(b"quantile" as &[u8]),
            _ => None,
        };
        let (_, label_spans, full_input, _, _) = parser.raw_series_parts();
        self.temp_attrs.clear();

        let mut prev_key_id: Option<u32> = None;
        let mut sorted_by_key_id = true;

        for span in label_spans {
            let raw_key = &full_input[span.name_start..span.name_end];
            let raw_val = &full_input[span.val_start..span.val_end];

            if let Some(target_key) = special_label {
                let key = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
                if key == target_key {
                    continue;
                }
            }
            if raw_val.is_empty() {
                continue;
            }

            let key_bytes = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
            let Some(key_id) = self.key_interner.lookup(key_bytes) else {
                return false;
            };
            let val_bytes = unescape_bytes_into(raw_val, true, &mut self.unescape_buf);
            let Some(val_id) = self.val_interner.lookup(val_bytes) else {
                return false;
            };

            if let Some(prev) = prev_key_id
                && key_id <= prev
            {
                sorted_by_key_id = false;
            }
            prev_key_id = Some(key_id);
            self.temp_attrs.push((key_id, val_id));
        }

        if !sorted_by_key_id {
            self.temp_attrs.sort_unstable_by_key(|&(k, _)| k);
        }
        self.assembly.contains_group(&self.temp_attrs)
    }

    #[inline]
    fn extract_series_labels_into_temp(
        &mut self,
        label_spans: &[LabelSpan],
        full_input: &[u8],
        special_label: Option<&[u8]>,
    ) -> Result<Option<f64>, DecodeError> {
        self.temp_attrs.clear();
        if label_spans.is_empty() {
            return Ok(None);
        }

        let mut prev_key_id: Option<u32> = None;
        let mut sorted_by_key_id = true;
        let mut seen_special = false;
        let mut special_val: Option<f64> = None;

        for (span_idx, span) in label_spans.iter().enumerate() {
            let raw_key = &full_input[span.name_start..span.name_end];
            let raw_val = &full_input[span.val_start..span.val_end];

            if let Some(target_key) = special_label {
                let key = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
                if key == target_key {
                    if seen_special {
                        return Err(DecodeError::DuplicateLabel {
                            metric: self.current_family.name_string(),
                            label: String::from_utf8_lossy(target_key).into_owned(),
                        });
                    }
                    seen_special = true;
                    if !raw_val.is_empty() {
                        let val = unescape_bytes_into(raw_val, true, &mut self.unescape_buf);
                        special_val = std::str::from_utf8(val).ok().and_then(parse_go_float);
                    }
                    continue;
                }
            }

            // Prometheus treats `label=""` as an absent label (`labels.Builder` deletes empty
            // values). Validate reserved and duplicate label names before skipping so unused keys
            // and `""` never enter the OTAP attribute dictionaries.
            if raw_val.is_empty() {
                self.validate_empty_label(span_idx, label_spans, full_input)?;
                continue;
            }

            let (key_id, val_id) = self.intern_attr_pair(
                raw_key,
                raw_val,
                true,
                &mut prev_key_id,
                &mut sorted_by_key_id,
                "DpAttrs.key",
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

        Ok(special_val)
    }

    fn append_number_exemplar(
        &mut self,
        dp_id: u32,
        ex_val: f64,
        ex_ts_ms: Option<i64>,
        ex_spans: &[LabelSpan],
        full_input: &[u8],
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let ex_id = self.num_dp.exemplars.next_id("NumberDpExemplars")?;
        let ts_ns = match ex_ts_ms {
            Some(ms) => ms_to_ns(ms)?,
            None => default_ts_ns.unwrap_or(0),
        };
        let (span_id, trace_id) =
            self.extract_exemplar_labels(ex_id, ex_spans, full_input, true)?;
        self.num_dp
            .exemplars
            .push_row(dp_id, ts_ns, ex_val, span_id, trace_id);
        Ok(())
    }

    fn stage_pending_histogram_exemplar(
        &mut self,
        group_idx: usize,
        ex_val: f64,
        ex_ts_ms: Option<i64>,
        ex_spans: &[LabelSpan],
        full_input: &[u8],
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let ts_ns = match ex_ts_ms {
            Some(ms) => ms_to_ns(ms)?,
            None => default_ts_ns.unwrap_or(0),
        };
        let attr_start = self.assembly.exemplar_attrs.len() as u32;
        let ids = self.extract_exemplar_labels(0, ex_spans, full_input, false)?;
        let attr_len = (self.assembly.exemplar_attrs.len() as u32) - attr_start;
        self.assembly
            .push_exemplar(group_idx, ts_ns, ex_val, ids, attr_start, attr_len);
        Ok(())
    }

    fn extract_exemplar_labels(
        &mut self,
        ex_id: u32,
        ex_spans: &[LabelSpan],
        full_input: &[u8],
        into_number_exemplar_attrs: bool,
    ) -> Result<SpanAndTraceId, DecodeError> {
        let mut span_id: Option<[u8; 8]> = None;
        let mut trace_id: Option<[u8; 16]> = None;
        let mut seen_span_id = false;
        let mut seen_trace_id = false;

        let attr_start = if into_number_exemplar_attrs {
            self.num_dp.exemplars.attrs.len()
        } else {
            self.assembly.exemplar_attrs.len()
        };
        let mut prev_key_id: Option<u32> = None;
        let mut sorted_by_key_id = true;

        for (span_idx, span) in ex_spans.iter().enumerate() {
            let raw_key = &full_input[span.name_start..span.name_end];
            let raw_val = &full_input[span.val_start..span.val_end];

            if raw_val.is_empty() {
                self.validate_empty_label(span_idx, ex_spans, full_input)?;
                continue;
            }

            let key = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
            if key == b"span_id" {
                if seen_span_id {
                    return Err(DecodeError::DuplicateLabel {
                        metric: self.current_family.name_string(),
                        label: "span_id".to_owned(),
                    });
                }
                seen_span_id = true;
                let val = unescape_bytes_into(raw_val, true, &mut self.unescape_buf);
                if let Some(parsed) = parse_hex_array::<8>(val) {
                    if parsed != [0u8; 8] {
                        span_id = Some(parsed);
                    }
                    continue;
                }
            } else if key == b"trace_id" {
                if seen_trace_id {
                    return Err(DecodeError::DuplicateLabel {
                        metric: self.current_family.name_string(),
                        label: "trace_id".to_owned(),
                    });
                }
                seen_trace_id = true;
                let val = unescape_bytes_into(raw_val, true, &mut self.unescape_buf);
                if let Some(parsed) = parse_hex_array::<16>(val) {
                    if parsed != [0u8; 16] {
                        trace_id = Some(parsed);
                    }
                    continue;
                }
            }

            let (key_id, val_id) = self.intern_attr_pair(
                raw_key,
                raw_val,
                false,
                &mut prev_key_id,
                &mut sorted_by_key_id,
                "ExemplarAttrs.key",
                "ExemplarAttrs.str",
            )?;

            if into_number_exemplar_attrs {
                self.num_dp.exemplars.attrs.push(ex_id, key_id, val_id);
            } else {
                self.assembly.exemplar_attrs.push((key_id, val_id));
            }
        }

        if !sorted_by_key_id {
            let slice = if into_number_exemplar_attrs {
                &mut self.num_dp.exemplars.attrs.pairs[attr_start..]
            } else {
                &mut self.assembly.exemplar_attrs[attr_start..]
            };
            Self::sort_and_check_duplicates(slice, &self.key_interner, &self.current_family)?;
        }

        Ok((span_id, trace_id))
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn intern_attr_pair(
        &mut self,
        raw_key: &[u8],
        raw_val: &[u8],
        reject_metric_name: bool,
        prev_key_id: &mut Option<u32>,
        sorted_by_key_id: &mut bool,
        key_table: &'static str,
        val_table: &'static str,
    ) -> Result<(u32, u32), DecodeError> {
        let key = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
        if reject_metric_name && key == METRIC_NAME_LABEL.as_bytes() {
            return Err(DecodeError::DuplicateLabel {
                metric: self.current_family.name_string(),
                label: METRIC_NAME_LABEL.to_owned(),
            });
        }
        let key_id =
            self.key_interner
                .intern(key)
                .ok_or_else(|| DecodeError::CapacityOverflow {
                    table: key_table,
                    count: self.key_interner.len(),
                })?;

        if let Some(prev) = *prev_key_id
            && key_id <= prev
        {
            if key_id == prev {
                return Err(DecodeError::DuplicateLabel {
                    metric: self.current_family.name_string(),
                    label: self.key_interner.get(key_id).to_owned(),
                });
            }
            *sorted_by_key_id = false;
        }
        *prev_key_id = Some(key_id);

        let val = unescape_bytes_into(raw_val, true, &mut self.unescape_buf);
        let val_id =
            self.val_interner
                .intern(val)
                .ok_or_else(|| DecodeError::CapacityOverflow {
                    table: val_table,
                    count: self.val_interner.len(),
                })?;
        Ok((key_id, val_id))
    }

    #[cold]
    fn sort_and_check_duplicates(
        slice: &mut [(u32, u32)],
        key_interner: &StringInterner,
        current_family: &CurrentFamily,
    ) -> Result<(), DecodeError> {
        slice.sort_unstable_by_key(|&(k, _)| k);
        for window in slice.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(DecodeError::DuplicateLabel {
                    metric: current_family.name_string(),
                    label: key_interner.get(window[0].0).to_owned(),
                });
            }
        }
        Ok(())
    }

    #[cold]
    fn validate_empty_label(
        &mut self,
        span_idx: usize,
        label_spans: &[LabelSpan],
        full_input: &[u8],
    ) -> Result<(), DecodeError> {
        let span = &label_spans[span_idx];
        let raw_key = &full_input[span.name_start..span.name_end];
        let key = unescape_bytes_into(raw_key, true, &mut self.unescape_buf);
        if key == METRIC_NAME_LABEL.as_bytes() {
            return Err(DecodeError::DuplicateLabel {
                metric: self.current_family.name_string(),
                label: METRIC_NAME_LABEL.to_owned(),
            });
        }
        for (other_idx, other) in label_spans.iter().enumerate() {
            if other_idx == span_idx {
                continue;
            }
            let other_raw_key = &full_input[other.name_start..other.name_end];
            let other_key = unescape_bytes_into(other_raw_key, true, &mut self.scratch.bytes);
            if key == other_key {
                return Err(DecodeError::DuplicateLabel {
                    metric: self.current_family.name_string(),
                    label: String::from_utf8_lossy(key).into_owned(),
                });
            }
        }
        Ok(())
    }

    fn finish_batches(&mut self, has_default_ts: bool) -> Result<OtapMetricRecords, DecodeError> {
        if self.metrics.is_empty() {
            return Ok(OtapMetricRecords::default());
        }

        let univariate_metrics = Some(self.metrics.build_univariate_metrics(&mut self.scratch)?);
        let number_data_points = self.num_dp.build_batch(has_default_ts, &mut self.scratch)?;
        let summary_data_points = self.sum_dp.build_batch(has_default_ts, &mut self.scratch)?;
        let histogram_data_points = self
            .hist_dp
            .build_batch(has_default_ts, &mut self.scratch)?;

        let any_dp_attrs = !self.num_dp.attrs.is_empty()
            || !self.sum_dp.attrs.is_empty()
            || !self.hist_dp.attrs.is_empty()
            || !self.num_dp.exemplars.attrs.is_empty()
            || !self.hist_dp.exemplars.attrs.is_empty();

        let enc = AttrEncoding::new(&self.key_interner, &self.val_interner, any_dp_attrs);
        let number_dp_attrs = self.num_dp.attrs.build_batch(&enc, &mut self.scratch)?;
        let summary_dp_attrs = self.sum_dp.attrs.build_batch(&enc, &mut self.scratch)?;
        let histogram_dp_attrs = self.hist_dp.attrs.build_batch(&enc, &mut self.scratch)?;

        let number_dp_exemplars = self.num_dp.exemplars.build_batch(&mut self.scratch)?;
        let histogram_dp_exemplars = self.hist_dp.exemplars.build_batch(&mut self.scratch)?;

        let number_dp_exemplar_attrs = self
            .num_dp
            .exemplars
            .attrs
            .build_batch(&enc, &mut self.scratch)?;
        let histogram_dp_exemplar_attrs = self
            .hist_dp
            .exemplars
            .attrs
            .build_batch(&enc, &mut self.scratch)?;

        let metric_attrs = Some(self.metrics.build_metric_attrs(&mut self.scratch)?);

        Ok(OtapMetricRecords {
            univariate_metrics,
            metric_attrs,
            number_data_points,
            summary_data_points,
            histogram_data_points,
            number_dp_attrs,
            summary_dp_attrs,
            histogram_dp_attrs,
            number_dp_exemplars,
            histogram_dp_exemplars,
            number_dp_exemplar_attrs,
            histogram_dp_exemplar_attrs,
        })
    }
}

/// Lending-style streaming iterator yielding bounded, non-empty [`OtapMetricRecords`] chunks from
/// a single exposition scrape.
///
/// Created by [`ArrowDecoder::decode_stream`]. Each `next()` call advances the underlying parser
/// until [`DecodeOptions::max_data_points_per_batch`], OTAP's 65,536-metric `u16` batch limit, or
/// end-of-input is reached, then finalizes a batch and clears per-batch staging buffers so peak
/// decoder scratch memory stays proportional to one chunk.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct DecodeStream<'dec, 'input> {
    decoder: &'dec mut ArrowDecoder,
    parser: ActiveParser<'input>,
    opts: DecodeOptions,
    default_ts_ns: Option<i64>,
    max_data_points: usize,
    pending_series: bool,
    init_err: Option<DecodeError>,
    done: bool,
}

impl DecodeStream<'_, '_> {
    /// Advances the stream to the next bounded chunk and returns a zero-copy
    /// [`DecodedMetricsView`] borrowing the staged batch without materializing Arrow
    /// [`arrow_array::RecordBatch`]es.
    ///
    /// See [`ArrowDecoder::decode_view`] for notes on `HistogramDataPoints.sum` elision when
    /// encoding chunks where every histogram has `sum == 0.0` via
    /// `otel_arrow_dfe_pdata::encode::encode_metrics_otap_batch`.
    pub fn next_view(&mut self) -> Option<Result<DecodedMetricsView<'_>, DecodeError>> {
        match self.step_chunk() {
            Some(Ok(())) => Some(Ok(self.decoder.view())),
            Some(Err(err)) => Some(Err(err)),
            None => None,
        }
    }

    fn step_chunk(&mut self) -> Option<Result<(), DecodeError>> {
        if self.done {
            return None;
        }
        if let Some(err) = self.init_err.take() {
            self.done = true;
            return Some(Err(err));
        }
        if !self.decoder.metrics.is_empty() {
            self.decoder.reset_batch();
        }
        match self.decoder.stage_entries::<true>(
            &mut self.parser,
            &self.opts,
            self.default_ts_ns,
            self.max_data_points,
            &mut self.pending_series,
            &mut self.done,
        ) {
            Ok(true) => Some(Ok(())),
            Ok(false) => None,
            Err(err) => {
                self.fail();
                Some(Err(err))
            }
        }
    }

    #[cold]
    fn fail(&mut self) {
        self.done = true;
        self.decoder.reset_scrape();
    }
}

impl Iterator for DecodeStream<'_, '_> {
    type Item = Result<OtapMetricRecords, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.step_chunk()? {
            Ok(()) => {
                let res = self.decoder.finish_batches(self.default_ts_ns.is_some());
                if res.is_err() {
                    self.fail();
                }
                Some(res)
            }
            Err(err) => Some(Err(err)),
        }
    }
}

impl FusedIterator for DecodeStream<'_, '_> {}

impl Drop for DecodeStream<'_, '_> {
    fn drop(&mut self) {
        self.parser.take_scratch_into(self.decoder);
    }
}
