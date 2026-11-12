# `scrape.rs` specification and implementation plan

`scrape.rs` provides official Rust decoders for Prometheus and OpenMetrics wire exposition formats (`prometheus-expfmt`), Prometheus target and metric relabeling (`prometheus-relabel`), and service discovery and scrape management (`prometheus-scrape-manager`).

## Background and goals

Rust metric pipelines and tools currently lack an official, spec-compliant parser for the full set of Prometheus and OpenMetrics wire formats. Existing community crates cover only basic Prometheus 0.0.4 text and allocate on the heap for every sample.

This repository targets two use cases:

1. High-throughput columnar ingestion for OpenTelemetry Arrow. [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) defines an OTAP-native `prometheus_scrape` receiver in Rust. Its steady-state path streams scrape bytes through early `__name__` series filtering, metric family assembly, and dictionary-vectorized relabeling directly into Apache Arrow metric records. That avoids intermediate Go-style `pmetric` or SDK `metricdata` object graphs and fits thread-per-core `!Send` runtimes with bounded memory.
2. Programmatic inspection and ecosystem tooling. Validation tools like OpenTelemetry Weaver live-checking `/metrics` endpoints against semantic conventions, test harnesses, and Rust CLIs need an ergonomic API that decodes any Prometheus or OpenMetrics payload into standard [`io.prometheus.client.MetricFamily`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto) protobuf structs, matching Go's [`prometheus/common/expfmt`](https://github.com/prometheus/common/tree/main/expfmt).

## Supported formats and content negotiation

The `format` module mirrors [`prometheus/common/expfmt/expfmt.go`](https://github.com/prometheus/common/blob/main/expfmt/expfmt.go), parsing `Content-Type` and `Accept` headers into format descriptors and UTF-8 escaping schemes: `allow-utf-8`, `underscores`, `dots`, and `values`.

| Format | Baseline `Content-Type` | Scope |
| :--- | :--- | :--- |
| Prometheus Text 0.0.4 | `text/plain; version=0.0.4; charset=utf-8` | Classic text exposition, `# HELP` and `# TYPE`, classic histograms and summaries, optional timestamps, UTF-8 quoted metric and label names. |
| OpenMetrics 1.0 | `application/openmetrics-text; version=1.0.0; charset=utf-8` and `0.0.1` | Strict grammar per the [OpenMetrics 1.0 ABNF specification](https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md#abnf) in RFC 5234, `# UNIT`, `_created` lines, exemplars, `info`, `stateset`, `gaugehistogram`, and mandatory `# EOF`. |
| OpenMetrics 2.0 | `application/openmetrics-text; version=2.0.0; charset=utf-8` and `2.0.0-rc` | Native histograms in text format, inline start timestamps `st@...`, UTF-8 names, and composite values matching [`model/textparse/openmetrics2parse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/openmetrics2parse.go). |
| Prometheus Protobuf | `application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited` plus `text` and `compact-text` | Varint length-delimited `MetricFamily` messages from [`prompb/io/prometheus/client/metrics.proto`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto), native sparse exponential histograms, and custom-bucket native histograms. |

### ABNF-driven OpenMetrics parsing

OpenMetrics 1.0 defines a normative [ABNF grammar](https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md#abnf) that takes precedence over the prose specification.
- We will store machine-readable ABNF grammar files in the repository under `specs/expfmt/openmetrics_1_0.abnf` and `specs/expfmt/openmetrics_2_0.abnf`.
- We will either generate the OpenMetrics parser state tables directly from the ABNF or validate a hand-written zero-copy lexer against an ABNF reference parser in tests and fuzzers.

## Decoding architecture and APIs

Decoding is split into three chained layers so streaming callers pay zero per-sample heap allocations while test and CLI callers still get a simple struct API derived from the primary Arrow output:

```text
                       Scrape payload (&[u8] / Bytes)
                                     │
                                     ▼
        ┌─────────────────────────────────────────────────────────┐
        │  Layer 0: Streaming event parser (text / proto)         │
        │  - Zero-copy borrowed slices (&[u8] / &str)             │
        │  - Yields Entry::{Help, Type, Unit, Series, Histogram}  │
        └────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼  Primary API
        ┌─────────────────────────────────────────────────────────┐
        │  Layer 1: Arrow / OTAP decoder                          │
        │  - Stage 1 pushdown: series `__name__` keep/drop filter │
        │  - Metric family assembly & arena string interners      │
        │  - Stage 2: dictionary-vectorized relabeling &          │
        │    `honor_labels` key resolution                        │
        │  - Direct Arrow RecordBatches (fits otel-arrow#3277     │
        │    and DataFusion SIMD execution)                       │
        └────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼  Ergonomic API
        ┌─────────────────────────────────────────────────────────┐
        │  Layer 2: Proto DTO decoder                             │
        │  - Converts Arrow / OTAP records into MetricFamily      │
        │    structs from metrics.proto                           │
        │  - Built for tests, Weaver, and CLI inspection          │
        └─────────────────────────────────────────────────────────┘
```

### Layer 0: Zero-copy streaming parser

Modeled on Prometheus's [`model/textparse.Parser`](https://github.com/prometheus/prometheus/blob/main/model/textparse/interface.go), the low-level parser advances entry-by-entry over a byte slice without allocating per sample. It is internal to the crate; the Arrow and `dto` decoders are the public API:

```rust
pub enum Entry {
    Type,
    Help,
    Unit,
    Comment,
    Series,
    Histogram,
}

pub trait Parser<'a> {
    /// Advances to the next entry in the exposition stream, returning `Ok(None)` at EOF.
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError>;

    // These slices borrow from the parser, because the protobuf parser builds them.
    fn help(&self) -> (&[u8], Cow<'_, [u8]>);
    fn metric_type(&self) -> (&[u8], MetricType);
    fn unit(&self) -> (&[u8], &[u8]);
    fn comment(&self) -> &'a [u8];

    /// Returns the raw series bytes, optional sample timestamp in ms, and float64 value.
    fn series(&self) -> (&[u8], Option<i64>, f64);

    /// Returns the raw series bytes, optional timestamp in ms, and parsed native histogram.
    fn histogram(&self) -> (&[u8], Option<i64>, HistogramRef<'_>);

    /// Returns the start timestamp in ms if present via `st@...`, `_created`, or the protobuf
    /// `start_timestamp` field.
    fn start_timestamp(&mut self) -> Option<i64>;

    /// Returns the current byte offset of the parser cursor in `input` (`0..=input.len()`).
    fn pos(&self) -> usize;

    /// Populates the caller's reusable label buffer for the current sample.
    fn labels(&self, buf: &mut LabelsBuffer<'a>);

    /// Fills `buf` with the labels of the next exemplar of the current sample and returns its
    /// value and optional timestamp in ms. A native histogram can have several exemplars, so
    /// call it until it returns `None`.
    fn exemplar(&mut self, buf: &mut LabelsBuffer<'a>) -> Option<(f64, Option<i64>)>;
}
```

### Layer 1: Columnar Apache Arrow decoder

This is the primary API, designed for the [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) scrape pipeline:

```text
scrape bytes
  -> streaming parser
  -> Stage 1: series `__name__` keep/drop filter pushdown
  -> metric family assembler & arena string interners (`key_interner`, `val_interner`)
  -> Stage 2: dictionary-vectorized relabeling & `honor_labels`
  -> direct OTAP metric records (ready for DataFusion / Arrow SIMD execution)
```

- `ArrowDecoder` appends parsed metrics, attributes, number data points, summary data points, classic and exponential histogram data points, and exemplars directly into Arrow array builders (`arrow-array` and `arrow-schema`), matching the relational `id` and `parent_id` tables in [`rust/otap-dataflow/crates/pdata`](https://github.com/open-telemetry/otel-arrow/tree/main/rust/otap-dataflow/crates/pdata). Callers can materialize one batch set per scrape with `ArrowDecoder::decode`, pull bounded chunks on demand with `ArrowDecoder::decode_stream` to cap scratch memory and stay within OTAP's `u16` per-batch metric ID limit, or yield cooperatively between bounded steps with `DecodeBudget`, `DecodeStep`, `DecodeStream::step`, `DecodeCursor` (`ArrowDecoder::start_decode` / `start_decode_stream` / `step_decode`), `ArrowDecoder::decode_cooperative`, and `DecodeStream::next_cooperative` so multi-megabyte scrapes do not starve timers or peer tasks on single-threaded `!Send` `LocalSet` runtimes.
- Metric families in text exposition are decoded as contiguous runs, with `# HELP`, `# TYPE`, and `# UNIT` metadata lines preceding that family's samples. Like OpenMetrics 1.0/2.0 and Prometheus's scrape loop, `ArrowDecoder` tracks only the active family cursor instead of maintaining a whole-scrape hash table to reassemble or reject previously seen names, so a non-contiguous repetition of an earlier metric name starts a fresh untyped run unless preceded by its own metadata.
- Rather than materializing a per-sample `BTreeMap` or running regular expressions on every scraped text line, `metric_relabel_configs` and `honor_labels` will wire into `ArrowDecoder` (Phase 4, `#35`) as a two-stage pipeline (see [Target and metric relabeling architecture](#target-and-metric-relabeling-architecture)):
  1. **Stage 1 (`__name__` series filter pushdown)**: Leading `keep`, `drop`, `keepequal`, and `dropequal` rules that inspect only `__name__` will run once per contiguous wire series-name transition (e.g. `foo_bucket`, `foo_sum`, `foo_count`, matching Prometheus `scrape/scrape.go`) so dropped series runs skip float parsing, label unescaping, string interning, and family assembly.
  2. **Stage 2 (dictionary-vectorized relabeling and `honor_labels`)**: Once kept series have been assembled into metric families (collapsing classic histogram `_bucket`, `_sum`, and `_count` lines into a single `HistogramDataPoints` row) and their label keys and values have been deduplicated in `key_interner` and `val_interner`, attribute-level `honor_labels` collision resolution, `labeldrop` / `labelkeep`, and single-label `keep` / `drop` / value transformations (`replace`, `lowercase`, `uppercase`, `hashmod`) will execute across unique dictionary entries (memoized per `source_labels[0]` value ID) instead of $O(N_{\text{samples}})$.
- The metric family assembler groups classic histogram `_bucket`, `_sum`, and `_count` lines and summary `quantile`, `_sum`, and `_count` lines (plus OpenMetrics `_created` start timestamps) into complete metric families.
- Configurable translation policies control counter `_total` and unit suffix handling and untyped series handling.
- `ArrowDecoder` owns its scratch buffers and Arrow builders without internal locks or global state, so a per-core `!Send` receiver can reuse allocations across scrapes with bounded memory.

### Target and metric relabeling architecture

The `relabel` module implements Prometheus `relabel_configs`, `metric_relabel_configs`, and `honor_labels` across three execution tiers matched to data cardinality:

1. **Pre-scrape target discovery relabeling (`relabel_configs`)**:
   - Runs once per discovered target endpoint (cold path) over `relabel::LabelSet` (`BTreeMap<String, String>`) via `populate_discovered_labels` and `populate_labels`.
   - Populates reserved discovery labels (`__address__`, `__scheme__`, `__metrics_path__`, `__scrape_interval__`, `__scrape_timeout__`, `__param_*`, `job`), executes all 11 Prometheus relabel actions, strips `__meta_*` labels, and defaults `instance` to `__address__`.
   - Non-reserved target labels (`PopulatedTarget::public_labels()`) attach once per scrape to the batch's `ResourceAttrs` (`job` -> `service.name`, `instance` -> `service.instance.id`) rather than duplicating unchanged target labels onto every data-point attribute row. When a `metric_relabel_configs` rule reads or mutates a public target label key (such as `source_labels: ["job"]`, `target_label: "job"`, `labeldrop`, `labelkeep`, or `labelmap`), Stage 2 resolves that key against the post-`honor_labels` target label value (using the target label when `honor_labels = false` or when the series omits that key under `honor_labels = true`) and materializes per-point attribute overrides only if a rule mutates or drops the target label.
2. **Stage 1 pre-staging `__name__` filter pushdown (Layer 1 ingestion, wired in Phase 4 / `#35`)**:
   - `relabel::split_metric_name_pushdown` extracts the leading prefix of `metric_relabel_configs` rules (`keep`, `drop`, `keepequal`, `dropequal`) that depend exclusively on `__name__`.
   - `ArrowDecoder` will evaluate `relabel::keep_metric_name` against the wire series `__name__` (such as `foo_bucket` or `foo_count`, not the stripped family base name `foo`) once when transitioning to a new contiguous series-name run, discarding dropped series runs before parsing sample floats, unescaping labels, interning strings, or staging histogram buckets.
3. **Stage 2 dictionary-vectorized relabeling and Layer 3 DataFusion SIMD execution (`ArrowDecoder` wiring in Phase 4 / `#35`)**:
   - After `ArrowDecoder` interns label keys into `key_interner` ($U_{\text{keys}}$ unique keys, typically ~32) and label values into `val_interner` ($U_{\text{vals}}$ unique values across all keys), dictionary-level primitives in `relabel` avoid per-sample regex and string allocations:
     - **`honor_labels = false` (`relabel::resolve_conflicting_exposed_keys`)**: Checks `key_interner` against public target labels in $O(U_{\text{keys}})$. When no sample label key collides with a target label key (the common case), `honor_labels` is a zero-copy no-op. When a collision occurs, only the colliding dictionary entries are renamed to `exported_<name>` in ascending key-length order. Note that whereas Go [`resolveConflictingExposedLabels`](https://github.com/prometheus/prometheus/blob/236a2b1fe8e0471586ff29cb8fd8929372643650/scrape/scrape.go#L682-L697) checks `exported_<name>` occupancy per series (like scalar `merge_target_and_metric_labels`), `resolve_conflicting_exposed_keys` intentionally resolves collisions once across the batch-wide `key_interner` dictionary so key indices do not have to be rewritten per series; if another series in the same batch already exposes `exported_<name>`, `<name>` is renamed to `exported_exported_<name>` across the batch dictionary.
     - **`labeldrop` / `labelkeep` (`relabel::eval_key_keep_mask`)**: Evaluates the key regex once per unique entry in `key_interner` ($O(U_{\text{keys}})$) to build a boolean key-ID mask used to filter `(key_id, val_id)` attribute rows.
     - **Single-label `keep` / `drop` (`relabel::SingleLabelKeepCache`, `relabel::eval_single_label_keep_mask`) and value transformations (`relabel::SingleLabelTransformCache`, `relabel::eval_single_label_value_transform`)**: Memoizes single-source-label predicates and transformations (`replace`, `lowercase`, `uppercase`, `hashmod`) lazily across only the `val_id`s seen under `source_labels[0]` on surviving series ($\le \min(U_{\text{source\_key}}, N_{\text{kept\_series}})$), avoiding touching unrelated high-cardinality values in `val_interner`.
     - **Layer 3 DataFusion / Arrow compute in `otel-arrow`**: Downstream cross-series aggregations, SQL projections, and vectorized SIMD filtering execute directly on the dictionary-encoded `OtapArrowRecords` (`RecordBatch`es) inside `open-telemetry/otel-arrow`'s DataFusion engine without pulling `datafusion` into `expfmt`.

### Layer 2: Proto DTO decoder

For tests, CLIs, and validation tools such as OpenTelemetry Weaver live-check, the `dto` module is chained on top of Layer 1 (`ArrowDecoder`). It decodes any supported wire format via `ArrowDecoder` and converts the resulting Arrow / OTAP metric records into [`io.prometheus.client.MetricFamily`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto) structs generated with `prost`. Keeping metric family assembly in Layer 1 avoids duplicating histogram and summary reconstruction logic and means every `dto` caller exercises the primary Arrow pipeline. The API matches [`expfmt.NewDecoder`](https://github.com/prometheus/common/blob/main/expfmt/decode.go) and [`expfmt.TextParser`](https://github.com/prometheus/common/blob/main/expfmt/text_parse.go) in Go:

```rust
/// Decodes an exposition payload of the given `Format` into a list of `MetricFamily` DTOs.
pub fn decode_to_metric_families(
    input: &[u8],
    format: Format,
    opts: &DecodeOptions,
) -> Result<Vec<dto::MetricFamily>, DecodeError>;

/// Converts Arrow / OTAP metric records decoded by `ArrowDecoder` into `MetricFamily` DTOs.
pub fn arrow_to_metric_families(
    records: &OtapMetricRecords,
) -> Result<Vec<dto::MetricFamily>, DecodeError>;
```

### Bounded scrape scheduling and memory pools

`prometheus-scrape-manager` (`crates/scrape-manager`) schedules periodic HTTP scrapes and feeds wire payloads into `ArrowDecoder` with bounded scratch memory. Go Prometheus spawns one goroutine, `scrapeCache`, and `gzip.Reader` per target in [`scrape/scrape.go`](https://github.com/prometheus/prometheus/blob/v0.315.1/scrape/scrape.go#L510-L584) and pulls from an unbounded `sync.Pool` buffer allocator in [`scrapeAndReport`](https://github.com/prometheus/prometheus/blob/v0.315.1/scrape/scrape.go#L1568-L1575), so working-set memory grows when many targets return responses at the same time. `ScrapeManager` decouples schedule concurrency from buffer and decoder residency:

- `TargetSchedule` stores all active targets in a single `BinaryHeap` rather than one task per target. Each target receives a deterministic phase offset `fnv1a_64(jitter_seed, url, sorted_labels) % scrape_interval`, mirroring [`Target.offset`](https://github.com/prometheus/prometheus/blob/v0.315.1/scrape/target.go#L170-L184). Popping a due target advances its next grid tick, `due + k * scrape_interval`, right away so scrape latency does not shift future intervals. If a previous scrape of the same target is still in flight when its next tick arrives, the scheduler skips that tick and increments `scrapes_overrun`. Updating targets preserves existing phase offsets for unchanged targets.
- `SchedulingMode::Concurrent` separates three limits: `max_in_flight` bounds simultaneous HTTP requests waiting on TCP connect and response headers, `max_buffered_bodies` bounds reusable `Vec<u8>` response buffers in `BodyBufferPool`, and `max_decoders` bounds reusable `ArrowDecoder` instances in `DecoderPool`. A slow target waiting on server-side `/metrics` generation holds zero payload buffers and zero decoders until HTTP `200 OK` headers pass `Content-Length <= max_body_bytes`. Any buffer that grows past `max_retained_body_bytes` on an outlier target shrinks back to `max_retained_body_bytes` when returned to `BodyBufferPool`, and any `ArrowDecoder` whose scratch capacity exceeds `max_retained_decoder_bytes` resets on return to `DecoderPool`.
- `SchedulingMode::Sequential` remains available as a first-class option for callers that want strict one-at-a-time scraping with `1` body buffer and `1` decoder, using either a job-wide cycle tick via `SequentialSchedule::CycleTick` or per-target FNV-1a offsets via `SequentialSchedule::Jittered`.
- `ReqwestFetcher` sends `Accept`, `Accept-Encoding: gzip`, `User-Agent`, and `X-Prometheus-Scrape-Timeout-Seconds` headers matching [`targetScraper.scrape`](https://github.com/prometheus/prometheus/blob/v0.315.1/scrape/scrape.go#L824-L836), and streams compressed or plain chunks with a hard `max_body_bytes` cap on uncompressed output so oversized responses abort mid-stream.
- `ScrapeManager` drives concurrent scrapes via `FuturesUnordered` without `tokio::spawn`, keeping `ArrowScrapeSink` and `RawScrapeSink` free of `Send` bounds for thread-per-core `LocalSet` receivers in `open-telemetry/otel-arrow`. Chunks delivered to `ArrowScrapeSink::on_batch` are tentative until `ArrowScrapeSink::on_scrape_complete` observes `report.up == true`; if decoding fails mid-stream, `ScrapeReport` records `up == false` alongside the partial `batches_emitted` count so transactional sinks can discard staged chunks like Go `app.Rollback()`.

## Testing and verification

### Test corpus from `prometheus/prometheus` and `prometheus/common`

We will test against fixtures from the upstream Go implementations:
- [`prometheus/prometheus/model/textparse`](https://github.com/prometheus/prometheus/tree/main/model/textparse) test cases covering Prometheus text, OpenMetrics 1.0, OpenMetrics 2.0, protobuf, custom-bucket native histograms, UTF-8 names, exemplars, start timestamps, and malformed input errors.
- [`prometheus/common/expfmt`](https://github.com/prometheus/common/tree/main/expfmt) testdata files and parser edge cases from `text_parse_test.go`, `decode_test.go`, and `encode_test.go`.
- To keep fixtures in sync with upstream without requiring a Go toolchain for normal `cargo test` runs, `tests/go-harness/go.mod` pins `github.com/prometheus/prometheus` and `github.com/prometheus/common` (updated via Renovate/Dependabot). A `go generate` sync tool in `tests/go-harness` resolves the module directories from the Go module cache (`go list -m -f '{{.Dir}}'`), copies `expfmt/testdata/*`, and extracts table-driven test cases from `model/textparse/*_test.go` and `expfmt/*_test.go` into checked-in `testdata/` fixtures. CI runs `go generate` and verifies `git diff --exit-code` so dependency bumps keep checked-in fixtures up to date.

### Differential testing with Go `prometheus/common/expfmt` encoders

A Go test harness under `tests/go-harness/` will verify wire compatibility against the reference Go implementation:
- The harness calls Go's [`prometheus/common/expfmt`](https://github.com/prometheus/common/tree/main/expfmt) encoders in [`text_create.go`](https://github.com/prometheus/common/blob/main/expfmt/text_create.go), [`openmetrics_create.go`](https://github.com/prometheus/common/blob/main/expfmt/openmetrics_create.go), [`openmetrics_2_0_create.go`](https://github.com/prometheus/common/blob/main/expfmt/openmetrics_2_0_create.go), and [`encode.go`](https://github.com/prometheus/common/blob/main/expfmt/encode.go) to serialize canonical `MetricFamily` inputs across all `Format` and `EscapingScheme` combinations (`AllowUTF8`, `EscapeUnderscores`, `EscapeDots`, `EscapeValues`).
- Rust tests decode the Go-generated bytes through both `dto::decode_to_metric_families` and `arrow::ArrowDecoder` and assert semantic equivalence with the input `MetricFamily` messages.
- Differential tests also run Go's `model/textparse` parsers (`NewPromParser`, `NewOpenMetricsParser`, `NewOpenMetrics2Parser`, `NewProtobufParser`) and Rust's Layer 0 `Parser` side by side on identical inputs.

### OTAP compatibility verification against `open-telemetry/otel-arrow#3277`

To verify that `ArrowDecoder` meets the [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) data model and runtime constraints before the receiver itself lands, integration tests pull [`otel-arrow-dfe-pdata`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/Cargo.toml) with `features = ["testing"]` as a `dev-dependency`:
- Inserting every `RecordBatch` produced by `ArrowDecoder` into [`OtapArrowRecords::Metrics`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/src/otap.rs#L40-L55) via `set(payload_type, batch)` validates column names, data types, dictionary encodings, and nullability rules against the OTAP schema specification.
- Running [`encode_transport_optimized()`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/src/otap.rs#L112-L146) followed by `decode_transport_optimized_ids()` verifies relational `id` and `parent_id` invariants across metrics, attributes, data points, and exemplars.
- Calling [`otap_to_otlp`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/src/testing/round_trip.rs#L65-L83) and [`assert_equivalent`](https://github.com/open-telemetry/otel-arrow/tree/main/rust/otap-dataflow/crates/pdata/src/testing/equiv) transcodes the decoded `OtapArrowRecords` into OTLP `MetricsData` and checks Prometheus-to-OTLP translation semantics.
- Driving `ArrowDecoder` inside a single-threaded `tokio::task::LocalSet` across repeated scrapes asserts `!Send` compatibility and verifies via [`retained_memory_bytes()`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/src/otap.rs#L92-L100) and `dhat` that memory stays bounded after warmup.

## Implementation plan

### Phase 1: Workspace layout, format negotiation, proto DTOs, and test fixtures
- Set up the Cargo workspace with `arrow` and optional `dto` feature flags, plus `tests/go-harness`.
- Implement `Format`, `FormatType`, `EscapingScheme`, and `Content-Type` / `Accept` header parsing matching [`prometheus/common/expfmt/expfmt.go`](https://github.com/prometheus/common/blob/main/expfmt/expfmt.go).
- Compile the proto3 [`prompb/io/prometheus/client/metrics.proto`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto) schema ([`buf.build/prometheus/prometheus`](https://buf.build/prometheus/prometheus/docs/main%3Aio.prometheus.client)) with `prost-build` for the `dto` module.
- Add the `go generate` fixture sync tool in `tests/go-harness` and generate initial `testdata/` fixtures from [`prometheus/prometheus/model/textparse`](https://github.com/prometheus/prometheus/tree/main/model/textparse) and [`prometheus/common/expfmt`](https://github.com/prometheus/common/tree/main/expfmt), verified in CI with `git diff --exit-code`.

### Phase 2: Prometheus Text 0.0.4 and OpenMetrics 1.0 across Layer 0, Layer 1, and Layer 2
- Add `specs/expfmt/openmetrics_1_0.abnf` from the [OpenMetrics 1.0 specification](https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md#abnf).
- Implement Layer 0 `Parser` for Prometheus Text 0.0.4 and OpenMetrics 1.0, including UTF-8 quoting and unescaping, exemplars, `_created` timestamps, `# UNIT`, and `# EOF` validation.
- Implement Layer 1 `arrow::ArrowDecoder` targeting [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277), assembling classic histograms, summaries, counters, gauges, untyped, info, and stateset metrics into OTAP Arrow `RecordBatch` tables.
- Implement Layer 2 `dto::decode_to_metric_families` and `dto::arrow_to_metric_families` on top of `ArrowDecoder`.
- Wire up the Go `prometheus/common/expfmt` encoder harness and [`otel-arrow-dfe-pdata`](https://github.com/open-telemetry/otel-arrow/blob/main/rust/otap-dataflow/crates/pdata/Cargo.toml) validation in CI for round-trip differential and OTAP schema testing across Prometheus Text and OpenMetrics 1.0.

### Phase 3: OpenMetrics 2.0 and Prometheus protobuf decoding
- Implement Layer 0, Layer 1, and Layer 2 support for OpenMetrics 2.0 matching [`openmetrics2parse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/openmetrics2parse.go) (native histograms in text format, `st@` start timestamps, composite values) and add `specs/expfmt/openmetrics_2_0.abnf`.
- Implement delimited protobuf decoding (`FmtProtoDelim`), including native sparse histograms, start timestamps, and exemplars, matching [`protobufparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/protobufparse.go).
- Histograms are only returned as native histograms, converting explicit-bucket histograms to NHCB (#37). Classic `_bucket`, `_sum`, and `_count` histogram series are left out on purpose; we can add classic support later if users need it ([discussion](https://github.com/prometheus/scrape.rs/pull/25#discussion_r4476081239)).
- Out of scope: `FmtProtoText` and `FmtProtoCompact`, because Prometheus only scrapes `encoding=delimited` ([config.go#L584](https://github.com/prometheus/prometheus/blob/v0.315.1/config/config.go#L584)).
- Extend the Go `expfmt` encoder harness to cover `FmtOpenMetrics_2_0_0` and `FmtProtoDelim`.

### Phase 4: Relabeling hooks, pooling, benchmarks, fuzzing, and initial release
- Add Stage 1 family `__name__` filter pushdown and Stage 2 dictionary-vectorized `honor_labels` and attribute relabeling on `ArrowDecoder` interners, plus dictionary/buffer reuse across scrapes.
- Add `cargo-fuzz` targets comparing Rust decoding against Go `expfmt` and `textparse`.
- Add `criterion` benchmarks measuring throughput in MB/s and allocations per sample across Layer 0 `Parser`, Layer 1 `ArrowDecoder`, and Layer 2 `dto`.
- Publish the `0.1.0` crate release and integrate with `open-telemetry/otel-arrow`.
