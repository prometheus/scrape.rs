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

use std::future::Future;
use std::iter::FusedIterator;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::format::{Format, FormatType};
use crate::parse::{
    Entry, LabelSpan, METRIC_NAME_LABEL, MetricType, OpenMetricsParser, OpenMetricsParserState,
    Parser, PromParser, PromParserState, parse_go_float, unescape_bytes_into,
};

use self::columns::{
    AttrEncoding, HistogramDpTable, MetricTable, NumberDpTable, ScratchBuffers, SummaryDpTable,
    f64_to_u64_count, ms_to_ns, parse_hex_array,
};
use self::family::{CurrentFamily, FamilyAssembly, SeriesRole};
use self::intern::StringInterner;
pub use self::options::{
    CounterSuffixPolicy, DECODE_BUDGET_DURATION_CHECK_INTERVAL, DEFAULT_DECODE_BUDGET_MAX_BYTES,
    DEFAULT_DECODE_BUDGET_MAX_DURATION, DEFAULT_DECODE_BUDGET_MAX_ENTRIES,
    DEFAULT_MAX_DATA_POINTS_PER_BATCH, DecodeBudget, DecodeError, DecodeOptions, UnitSuffixPolicy,
    UntypedPolicy,
};
pub use self::records::{MetricPayloadType, OtapMetricRecords};
pub use self::schema::PROMETHEUS_TYPE_METADATA_KEY;

/// Maximum distinct `UnivariateMetrics` rows representable in a single OTAP batch (`u16` IDs).
const MAX_METRICS_PER_BATCH: usize = (u16::MAX as usize) + 1;

/// Process-wide counter assigning each decoder scrape a unique ID so a [`DecodeCursor`] from one
/// [`ArrowDecoder`] cannot pass the active-scrape check on another [`ArrowDecoder`].
static NEXT_SCRAPE_ID: AtomicU64 = AtomicU64::new(1);

#[inline]
fn next_scrape_id() -> u64 {
    NEXT_SCRAPE_ID.fetch_add(1, Ordering::Relaxed)
}

type SpanAndTraceId = (Option<[u8; 8]>, Option<[u8; 16]>);

/// Outcome of a single bounded decode step in [`DecodeStream::step`] or
/// [`ArrowDecoder::step_decode`].
#[derive(Clone, Debug, PartialEq)]
// Keep `OtapMetricRecords` unboxed on the stack just like `Option<Result<OtapMetricRecords, _>>`
// in `DecodeStream::next` so finalizing a batch does not add an extra heap allocation.
#[allow(clippy::large_enum_variant)]
pub enum DecodeStep {
    /// The [`DecodeBudget`] was reached at an `Entry` boundary before a batch boundary or
    /// end-of-input; yield to the runtime and call `step` again.
    Pending,
    /// A [`OtapMetricRecords`] batch was finalized. Call `step` again until [`DecodeStep::Done`]
    /// is returned.
    Batch(OtapMetricRecords),
    /// End of input was reached with no remaining data points.
    Done,
}

#[derive(Clone, Copy)]
enum ParserKind {
    Prom,
    OpenMetrics,
    Invalid,
}

/// Lifetime-free incremental decode cursor for driving [`ArrowDecoder::step_decode`] across
/// async suspension points without borrowing the input slice.
///
/// Created by [`ArrowDecoder::start_decode`] (single-batch mode) or
/// [`ArrowDecoder::start_decode_stream`] (chunked streaming mode). Because `DecodeCursor` stores
/// only scalar byte offsets and options while [`ArrowDecoder`] retains the reusable parser scratch
/// buffers in place, an owned task or `otel-arrow` `PdataDecodeJob` struct can hold an owned
/// buffer (`Bytes`, `Vec<u8>`, or `Rc<[u8]>`), an [`ArrowDecoder`], and a compact `DecodeCursor`
/// side by side under `#![forbid(unsafe_code)]`.
pub struct DecodeCursor {
    parser_kind: ParserKind,
    opts: DecodeOptions,
    default_ts_ns: Option<i64>,
    max_data_points: usize,
    scrape_id: u64,
    input_len: Option<usize>,
    pos: usize,
    chunked: bool,
    pending_series: bool,
    done: bool,
}

impl std::fmt::Debug for DecodeCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeCursor")
            .field("opts", &self.opts)
            .field("pos", &self.pos)
            .field("chunked", &self.chunked)
            .field("pending_series", &self.pending_series)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl DecodeCursor {
    /// Returns the current byte offset of the parser cursor in `input` (`0..=input.len()`).
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// Returns `true` once the cursor has reached end-of-input or encountered an error.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }
}

// Internal parser specialization trait so `ingest_entries` monomorphizes directly over
// `PromParser` and `OpenMetricsParser` without per-entry enum dispatch or unused stack state.
trait ScrapeParser<'input>: Parser<'input> {
    const IS_OPENMETRICS: bool;

    fn name_offset(&self) -> usize;
    fn raw_help(&self) -> (&'input [u8], &'input [u8]);
    fn raw_series_parts(&self) -> (&'input [u8], &[LabelSpan], &'input [u8], Option<i64>, f64);
    fn raw_exemplar_parts(&self) -> Option<(f64, Option<i64>, &[LabelSpan])>;
}

impl<'input> ScrapeParser<'input> for PromParser<'input> {
    const IS_OPENMETRICS: bool = false;

    #[inline]
    fn name_offset(&self) -> usize {
        PromParser::name_offset(self)
    }

    #[inline]
    fn raw_help(&self) -> (&'input [u8], &'input [u8]) {
        PromParser::raw_help(self)
    }

    #[inline]
    fn raw_series_parts(&self) -> (&'input [u8], &[LabelSpan], &'input [u8], Option<i64>, f64) {
        PromParser::raw_series_parts(self)
    }

    #[inline]
    fn raw_exemplar_parts(&self) -> Option<(f64, Option<i64>, &[LabelSpan])> {
        None
    }
}

impl<'input> ScrapeParser<'input> for OpenMetricsParser<'input> {
    const IS_OPENMETRICS: bool = true;

    #[inline]
    fn name_offset(&self) -> usize {
        OpenMetricsParser::name_offset(self)
    }

    #[inline]
    fn raw_help(&self) -> (&'input [u8], &'input [u8]) {
        OpenMetricsParser::raw_help(self)
    }

    #[inline]
    fn raw_series_parts(&self) -> (&'input [u8], &[LabelSpan], &'input [u8], Option<i64>, f64) {
        OpenMetricsParser::raw_series_parts(self)
    }

    #[inline]
    fn raw_exemplar_parts(&self) -> Option<(f64, Option<i64>, &[LabelSpan])> {
        OpenMetricsParser::raw_exemplar_parts(self)
    }
}

/// Stateful, lock-free decoder translating Prometheus and OpenMetrics exposition payloads into OTAP
/// Arrow metric [`arrow_array::RecordBatch`]es.
///
/// Reusing a single `ArrowDecoder` across scrapes preserves internal parser scratch spans, label
/// string interners, and column staging buffers so steady-state scrapes allocate only the output
/// Arrow `Buffer`s returned inside [`OtapMetricRecords`].
pub struct ArrowDecoder {
    scrape_id: u64,
    prom_state: PromParserState,
    om_state: OpenMetricsParserState,
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

impl std::fmt::Debug for ArrowDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArrowDecoder")
            .field("retained_memory_bytes", &self.retained_memory_bytes())
            .finish_non_exhaustive()
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
            scrape_id: 0,
            prom_state: PromParserState::with_capacity(16),
            om_state: OpenMetricsParserState::default(),
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
        self.prom_state.retained_memory_bytes()
            + self.om_state.retained_memory_bytes()
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
    /// Input parsing streams `Entry` items one by one from `PromParser` or
    /// `OpenMetricsParser` directly into reusable columnar staging vectors and label string
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
        self.reset_scrape();
        let default_ts_ns = match opts.timestamp_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => None,
        };
        let mut pending_series = false;
        let mut done = false;
        let res = match format.format_type() {
            FormatType::TextPlain => {
                let spans = std::mem::take(&mut self.prom_state.labels);
                let mut parser = PromParser::with_scratch(input, spans);
                let res = self.ingest_entries::<_, false, false>(
                    &mut parser,
                    input.len(),
                    opts,
                    default_ts_ns,
                    0,
                    None,
                    &mut pending_series,
                    &mut done,
                );
                self.prom_state.labels = parser.take_scratch();
                res
            }
            FormatType::OpenMetrics if !format.version().starts_with("2.") => {
                // TODO(bwplotka): Dispatch OpenMetrics 2.0 in Phase 3.
                let scratch = self.om_state.take_scratch();
                let mut parser = OpenMetricsParser::with_scratch(input, scratch);
                let res = self.ingest_entries::<_, false, false>(
                    &mut parser,
                    input.len(),
                    opts,
                    default_ts_ns,
                    0,
                    None,
                    &mut pending_series,
                    &mut done,
                );
                self.om_state.put_scratch(parser.take_scratch());
                res
            }
            _ => {
                // TODO(bwplotka): Dispatch Proto* in Phase 3.
                return Err(DecodeError::UnsupportedFormat(format.as_str().to_owned()));
            }
        };
        match res? {
            DecodeStep::Batch(records) => Ok(records),
            DecodeStep::Done => Ok(OtapMetricRecords::default()),
            DecodeStep::Pending => {
                unreachable!("unbudgeted decode never returns DecodeStep::Pending")
            }
        }
    }

    /// Cooperatively decodes a single exposition scrape buffer of `format` into OTAP metric
    /// [`arrow_array::RecordBatch`]es, yielding via `yield_to_runtime` whenever `budget` is
    /// exhausted at an `Entry` boundary.
    ///
    /// When the entire scrape fits within the first `budget` step, this method completes on the
    /// first poll without invoking `yield_to_runtime`. Because single-batch mode materializes all
    /// Arrow `RecordBatch`es for the scrape in the final step once end-of-input is reached, use
    /// [`ArrowDecoder::decode_stream`] with [`DecodeStream::next_cooperative`] or
    /// [`ArrowDecoder::start_decode_stream`] on large scrapes to bound per-batch finalization by
    /// [`DecodeOptions::max_data_points_per_batch`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] under the same conditions as [`ArrowDecoder::decode`].
    pub async fn decode_cooperative<Y: Future<Output = ()>>(
        &mut self,
        input: &[u8],
        format: &Format,
        opts: &DecodeOptions,
        budget: DecodeBudget,
        mut yield_to_runtime: impl FnMut() -> Y,
    ) -> Result<OtapMetricRecords, DecodeError> {
        struct CursorDropGuard<'dec> {
            decoder: &'dec mut ArrowDecoder,
            cursor: DecodeCursor,
        }
        impl Drop for CursorDropGuard<'_> {
            fn drop(&mut self) {
                self.decoder.finish_decode(&mut self.cursor);
            }
        }

        let cursor = self.start_decode(format, opts)?;
        let mut guard = CursorDropGuard {
            decoder: self,
            cursor,
        };
        loop {
            match guard
                .decoder
                .step_decode(&mut guard.cursor, input, budget)?
            {
                DecodeStep::Pending => yield_to_runtime().await,
                DecodeStep::Batch(records) => return Ok(records),
                DecodeStep::Done => return Ok(OtapMetricRecords::default()),
            }
        }
    }

    /// Initializes a lifetime-free [`DecodeCursor`] for single-batch cooperative decoding with
    /// [`ArrowDecoder::step_decode`].
    ///
    /// Single-batch mode stages the entire scrape and materializes all Arrow `RecordBatch`es in
    /// the final step when end-of-input is reached. For large scrapes, prefer
    /// [`ArrowDecoder::start_decode_stream`] so batch finalization stays bounded by
    /// [`DecodeOptions::max_data_points_per_batch`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `format` is unsupported or `opts.timestamp_ms` overflows `i64`
    /// nanoseconds.
    pub fn start_decode(
        &mut self,
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<DecodeCursor, DecodeError> {
        self.init_cursor(format, opts, false)
    }

    /// Initializes a lifetime-free [`DecodeCursor`] for chunked streaming cooperative decoding
    /// with [`ArrowDecoder::step_decode`], bounded by [`DecodeOptions::max_data_points_per_batch`]
    /// and OTAP's 65,536-metric per-batch `u16` ID limit.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `format` is unsupported or `opts.timestamp_ms` overflows `i64`
    /// nanoseconds.
    pub fn start_decode_stream(
        &mut self,
        format: &Format,
        opts: &DecodeOptions,
    ) -> Result<DecodeCursor, DecodeError> {
        self.init_cursor(format, opts, true)
    }

    /// Advances `cursor` over `input` by at most `budget` entries, bytes, or duration, pausing at
    /// `Entry` boundaries.
    ///
    /// Callers must pass the exact same `input` byte slice (both contents and length) to every
    /// `step_decode` call for a given `cursor`, because the cursor and staged parser state store
    /// byte offsets into `input`.
    ///
    /// If `cursor` is abandoned early before completion, call [`ArrowDecoder::finish_decode`] to
    /// reset partial scrape state in `self` while preserving internal scratch capacities.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the exposition payload fails validation or an OTAP table exceeds
    /// its integer ID width.
    #[inline]
    pub fn step_decode(
        &mut self,
        cursor: &mut DecodeCursor,
        input: &[u8],
        budget: DecodeBudget,
    ) -> Result<DecodeStep, DecodeError> {
        self.step_cursor::<true>(cursor, input, Some(budget))
    }

    fn step_cursor<const BUDGETED: bool>(
        &mut self,
        cursor: &mut DecodeCursor,
        input: &[u8],
        budget: Option<DecodeBudget>,
    ) -> Result<DecodeStep, DecodeError> {
        if cursor.done {
            return Ok(DecodeStep::Done);
        }
        if cursor.scrape_id != self.scrape_id {
            cursor.done = true;
            cursor.parser_kind = ParserKind::Invalid;
            return Err(DecodeError::InvalidCursor(
                "cursor does not belong to current decoder scrape",
            ));
        }
        let expected_len = *cursor.input_len.get_or_insert(input.len());
        if input.len() != expected_len {
            self.finish_decode(cursor);
            return Err(DecodeError::InvalidCursor(
                "scrape input buffer length changed across decode steps",
            ));
        }
        match cursor.parser_kind {
            ParserKind::Prom => {
                let state = std::mem::take(&mut self.prom_state);
                let mut parser = PromParser::from_state(input, state);
                let res =
                    self.run_cursor_step::<_, BUDGETED>(&mut parser, input.len(), cursor, budget);
                cursor.pos = parser.pos();
                self.prom_state = parser.into_state();
                match res {
                    Ok(step) => {
                        if cursor.done {
                            cursor.parser_kind = ParserKind::Invalid;
                            self.prom_state.reset();
                        }
                        Ok(step)
                    }
                    Err(err) => {
                        cursor.done = true;
                        cursor.parser_kind = ParserKind::Invalid;
                        self.prom_state.reset();
                        self.reset_scrape();
                        Err(err)
                    }
                }
            }
            ParserKind::OpenMetrics => {
                let state = std::mem::take(&mut self.om_state);
                let mut parser = OpenMetricsParser::from_state(input, state);
                let res =
                    self.run_cursor_step::<_, BUDGETED>(&mut parser, input.len(), cursor, budget);
                cursor.pos = parser.pos();
                self.om_state = parser.into_state();
                match res {
                    Ok(step) => {
                        if cursor.done {
                            cursor.parser_kind = ParserKind::Invalid;
                            self.om_state.reset();
                        }
                        Ok(step)
                    }
                    Err(err) => {
                        cursor.done = true;
                        cursor.parser_kind = ParserKind::Invalid;
                        self.om_state.reset();
                        self.reset_scrape();
                        Err(err)
                    }
                }
            }
            ParserKind::Invalid => {
                cursor.done = true;
                Ok(DecodeStep::Done)
            }
        }
    }

    #[inline]
    fn run_cursor_step<'input, P: ScrapeParser<'input>, const BUDGETED: bool>(
        &mut self,
        parser: &mut P,
        input_len: usize,
        cursor: &mut DecodeCursor,
        budget: Option<DecodeBudget>,
    ) -> Result<DecodeStep, DecodeError> {
        if cursor.chunked {
            self.ingest_entries::<P, true, BUDGETED>(
                parser,
                input_len,
                &cursor.opts,
                cursor.default_ts_ns,
                cursor.max_data_points,
                budget,
                &mut cursor.pending_series,
                &mut cursor.done,
            )
        } else {
            self.ingest_entries::<P, false, BUDGETED>(
                parser,
                input_len,
                &cursor.opts,
                cursor.default_ts_ns,
                0,
                budget,
                &mut cursor.pending_series,
                &mut cursor.done,
            )
        }
    }

    /// Ends an active [`DecodeCursor`] and resets partial scrape state in `self` while preserving
    /// internal parser scratch capacities.
    pub fn finish_decode(&mut self, cursor: &mut DecodeCursor) {
        cursor.parser_kind = ParserKind::Invalid;
        if !cursor.done {
            cursor.done = true;
            if cursor.scrape_id == self.scrape_id {
                self.prom_state.reset();
                self.om_state.reset();
                self.reset_scrape();
            }
        }
    }

    /// Streams `input` as a sequence of non-empty [`OtapMetricRecords`] chunks bounded by
    /// [`DecodeOptions::max_data_points_per_batch`] and OTAP's 65,536-metric per-batch `u16` ID
    /// limit.
    ///
    /// Empty or metadata-only scrapes yield zero items. When a contiguous metric family spans a
    /// chunk boundary, [`ArrowDecoder`] retains its `# HELP`, `# TYPE`, and `# UNIT` metadata
    /// across the flush and re-emits the family row in the next chunk only if further samples
    /// follow. Dropping [`DecodeStream`] early resets partial scrape state in `self` while
    /// preserving internal scratch capacities.
    pub fn decode_stream<'dec, 'input>(
        &'dec mut self,
        input: &'input [u8],
        format: &Format,
        opts: &DecodeOptions,
    ) -> DecodeStream<'dec, 'input> {
        match self.start_decode_stream(format, opts) {
            Ok(mut cursor) => {
                cursor.input_len = Some(input.len());
                DecodeStream {
                    decoder: self,
                    input,
                    cursor,
                    init_err: None,
                }
            }
            Err(err) => {
                let max_data_points = opts
                    .max_data_points_per_batch
                    .clamp(1, (u32::MAX as usize).saturating_add(1));
                let scrape_id = self.scrape_id;
                DecodeStream {
                    decoder: self,
                    input,
                    cursor: DecodeCursor {
                        parser_kind: ParserKind::Invalid,
                        opts: *opts,
                        default_ts_ns: None,
                        max_data_points,
                        scrape_id,
                        input_len: Some(input.len()),
                        pos: 0,
                        chunked: true,
                        pending_series: false,
                        done: false,
                    },
                    init_err: Some(err),
                }
            }
        }
    }

    fn init_cursor(
        &mut self,
        format: &Format,
        opts: &DecodeOptions,
        chunked: bool,
    ) -> Result<DecodeCursor, DecodeError> {
        self.reset_scrape();
        let max_data_points = if chunked {
            opts.max_data_points_per_batch
                .clamp(1, (u32::MAX as usize).saturating_add(1))
        } else {
            0
        };
        let default_ts_ns = match opts.timestamp_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => None,
        };
        let parser_kind = match format.format_type() {
            FormatType::TextPlain => {
                self.prom_state.reset();
                ParserKind::Prom
            }
            FormatType::OpenMetrics if !format.version().starts_with("2.") => {
                // TODO(bwplotka): Dispatch OpenMetrics 2.0 in Phase 3.
                self.om_state.reset();
                ParserKind::OpenMetrics
            }
            _ => {
                // TODO(bwplotka): Dispatch Proto* in Phase 3.
                return Err(DecodeError::UnsupportedFormat(format.as_str().to_owned()));
            }
        };
        Ok(DecodeCursor {
            parser_kind,
            opts: *opts,
            default_ts_ns,
            max_data_points,
            scrape_id: self.scrape_id,
            input_len: None,
            pos: 0,
            chunked,
            pending_series: false,
            done: false,
        })
    }

    fn reset_scrape(&mut self) {
        self.scrape_id = next_scrape_id();
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

    // Monomorphizing on `P`, `CHUNKED`, and `BUDGETED` shares one entry dispatch loop across
    // synchronous single-batch `decode` (`false, false`), synchronous `decode_stream`
    // (`true, false`), cooperative single-batch `decode_cooperative` (`false, true`), and
    // cooperative streaming `DecodeStream::step` (`true, true`), compiling out per-entry parser
    // enum dispatch and unused budget/chunk checks on each path.
    #[allow(clippy::too_many_arguments)]
    fn ingest_entries<
        'input,
        P: ScrapeParser<'input>,
        const CHUNKED: bool,
        const BUDGETED: bool,
    >(
        &mut self,
        parser: &mut P,
        input_len: usize,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
        max_data_points: usize,
        budget: Option<DecodeBudget>,
        pending_series: &mut bool,
        done: &mut bool,
    ) -> Result<DecodeStep, DecodeError> {
        let start_pos = if BUDGETED { parser.pos() } else { 0 };
        let (max_entries, byte_limit, max_duration, check_every_entry, started) = if let Some(b) =
            budget.filter(|_| BUDGETED)
        {
            let max_entries = b.max_entries.max(1);
            let byte_limit = start_pos.saturating_add(b.max_bytes.max(1));
            let check_every = b.max_duration.is_zero();
            // Skip `Instant::now()` when the step is guaranteed to finish or hit `max_entries`
            // before the first periodic duration check at `DECODE_BUDGET_DURATION_CHECK_INTERVAL`.
            let need_clock = check_every
                || (max_entries > DECODE_BUDGET_DURATION_CHECK_INTERVAL
                    && b.max_bytes.max(1) > DECODE_BUDGET_DURATION_CHECK_INTERVAL
                    && input_len.saturating_sub(start_pos) > DECODE_BUDGET_DURATION_CHECK_INTERVAL);
            (
                max_entries,
                byte_limit,
                b.max_duration,
                check_every,
                need_clock.then(Instant::now),
            )
        } else {
            (
                usize::MAX,
                usize::MAX,
                std::time::Duration::ZERO,
                false,
                None,
            )
        };
        let mut entries = 0usize;

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
                        if self.metrics.is_empty() {
                            return Ok(DecodeStep::Done);
                        }
                        let batch = self.finish_batches(default_ts_ns.is_some())?;
                        if CHUNKED {
                            self.reset_batch();
                        }
                        return Ok(DecodeStep::Batch(batch));
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
                                let batch = self.finish_batches(default_ts_ns.is_some())?;
                                self.reset_batch();
                                return Ok(DecodeStep::Batch(batch));
                            }
                            self.current_family
                                .start_new(raw_name, &self.series_name_buf);
                            SeriesRole::Scalar
                        }
                    };

                    if CHUNKED {
                        if self.assembly.is_empty() {
                            if self.total_data_points() >= max_data_points
                                || (self.current_family.batch_id.is_none()
                                    && self.metrics.len() >= MAX_METRICS_PER_BATCH)
                            {
                                *pending_series = true;
                                let batch = self.finish_batches(default_ts_ns.is_some())?;
                                self.reset_batch();
                                return Ok(DecodeStep::Batch(batch));
                            }
                        } else if self.batch_data_points() >= max_data_points
                            && !self.series_matches_staged_group(parser, role)
                        {
                            self.flush_pending_family(opts, default_ts_ns)?;
                            *pending_series = true;
                            let batch = self.finish_batches(default_ts_ns.is_some())?;
                            self.reset_batch();
                            return Ok(DecodeStep::Batch(batch));
                        }
                    }

                    self.ingest_series_entry(parser, role, opts, default_ts_ns)?;

                    if CHUNKED
                        && self.assembly.is_empty()
                        && self.total_data_points() >= max_data_points
                    {
                        let batch = self.finish_batches(default_ts_ns.is_some())?;
                        self.reset_batch();
                        return Ok(DecodeStep::Batch(batch));
                    }
                }
            }

            if BUDGETED {
                entries += 1;
                if entries >= max_entries || parser.pos() >= byte_limit {
                    return Ok(DecodeStep::Pending);
                }
                if (check_every_entry
                    || entries.is_multiple_of(DECODE_BUDGET_DURATION_CHECK_INTERVAL))
                    && started.is_some_and(|t| t.elapsed() >= max_duration)
                {
                    return Ok(DecodeStep::Pending);
                }
            }
        }
    }

    #[inline]
    fn ingest_help_entry<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &P,
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
        let unescaped = unescape_bytes_into(raw_help, P::IS_OPENMETRICS, &mut self.unescape_buf);
        self.current_family.help.clear();
        self.current_family.help.extend_from_slice(unescaped);
        self.current_family.has_help = true;
        Ok(())
    }

    #[inline]
    fn ingest_type_entry<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &P,
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
    fn ingest_unit_entry<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &P,
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
    fn ingest_series_entry<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &mut P,
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
    fn append_scalar_series<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &mut P,
        opts: &DecodeOptions,
        default_ts_ns: Option<i64>,
    ) -> Result<(), DecodeError> {
        let start_ts_ms =
            if P::IS_OPENMETRICS && self.current_family.metric_type == MetricType::Counter {
                parser.start_timestamp()
            } else {
                None
            };
        let (_, label_spans, full_input, sample_ts_ms, value) = parser.raw_series_parts();
        let exemplar_parts = if P::IS_OPENMETRICS {
            parser.raw_exemplar_parts()
        } else {
            None
        };

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

        if P::IS_OPENMETRICS
            && let Some((ex_val, ex_ts_ms, ex_spans)) = exemplar_parts
        {
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
            .emit_into_batch(&mut self.metrics, opts)?;
        let start_ts_ns = start_ts_ms.and_then(|ms| ms.checked_mul(1_000_000));
        let resolved_ts_ns = match sample_ts_ms {
            Some(ms) => Some(ms_to_ns(ms)?),
            None => default_ts_ns,
        };
        self.num_dp
            .base
            .push(parent_id, start_ts_ns, resolved_ts_ns);
        self.num_dp.values.push(value);
        Ok(())
    }

    fn append_assembled_series<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &mut P,
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
            if P::IS_OPENMETRICS {
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

        if P::IS_OPENMETRICS
            && matches!(
                self.current_family.metric_type,
                MetricType::Histogram | MetricType::GaugeHistogram
            )
            && let Some((ex_val, ex_ts_ms, ex_spans)) = parser.raw_exemplar_parts()
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
    fn series_matches_staged_group<'input, P: ScrapeParser<'input>>(
        &mut self,
        parser: &P,
        role: SeriesRole,
    ) -> bool {
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
                    span_id = Some(parsed);
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
                    trace_id = Some(parsed);
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
    input: &'input [u8],
    cursor: DecodeCursor,
    init_err: Option<DecodeError>,
}

impl std::fmt::Debug for DecodeStream<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodeStream")
            .field("opts", &self.cursor.opts)
            .field("pos", &self.pos())
            .field("pending_series", &self.cursor.pending_series)
            .field("done", &self.cursor.done)
            .finish_non_exhaustive()
    }
}

impl DecodeStream<'_, '_> {
    /// Returns the current byte offset of the parser cursor in `input` (`0..=input.len()`).
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.cursor.pos()
    }

    /// Advances parsing and metric family assembly until a chunk is ready
    /// ([`DecodeStep::Batch`]), end-of-input is reached ([`DecodeStep::Done`]), or `budget` is
    /// exhausted at an `Entry` boundary ([`DecodeStep::Pending`]).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if `format` is unsupported, the exposition payload fails syntax or
    /// UTF-8 validation, duplicate or late metadata lines are encountered within a contiguous
    /// family, duplicate label names appear on a sample, or an OTAP table exceeds its integer ID
    /// width.
    #[inline]
    pub fn step(&mut self, budget: DecodeBudget) -> Result<DecodeStep, DecodeError> {
        if self.cursor.done {
            return Ok(DecodeStep::Done);
        }
        if let Some(err) = self.init_err.take() {
            self.cursor.done = true;
            return Err(err);
        }
        self.decoder
            .step_decode(&mut self.cursor, self.input, budget)
    }

    /// Cooperatively pulls the next non-empty [`OtapMetricRecords`] chunk from the stream,
    /// awaiting `yield_to_runtime()` each time `budget` is exhausted at an `Entry` boundary.
    pub async fn next_cooperative<Y: Future<Output = ()>>(
        &mut self,
        budget: DecodeBudget,
        mut yield_to_runtime: impl FnMut() -> Y,
    ) -> Option<Result<OtapMetricRecords, DecodeError>> {
        loop {
            match self.step(budget) {
                Ok(DecodeStep::Pending) => yield_to_runtime().await,
                Ok(DecodeStep::Batch(batch)) => return Some(Ok(batch)),
                Ok(DecodeStep::Done) => return None,
                Err(err) => return Some(Err(err)),
            }
        }
    }
}

impl Iterator for DecodeStream<'_, '_> {
    type Item = Result<OtapMetricRecords, DecodeError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.done {
            return None;
        }
        if let Some(err) = self.init_err.take() {
            self.cursor.done = true;
            return Some(Err(err));
        }
        match self
            .decoder
            .step_cursor::<false>(&mut self.cursor, self.input, None)
        {
            Ok(DecodeStep::Batch(batch)) => Some(Ok(batch)),
            Ok(DecodeStep::Done) => None,
            Ok(DecodeStep::Pending) => {
                unreachable!("unbudgeted stream never returns DecodeStep::Pending")
            }
            Err(err) => Some(Err(err)),
        }
    }
}

impl FusedIterator for DecodeStream<'_, '_> {}

impl Drop for DecodeStream<'_, '_> {
    fn drop(&mut self) {
        self.decoder.finish_decode(&mut self.cursor);
    }
}
