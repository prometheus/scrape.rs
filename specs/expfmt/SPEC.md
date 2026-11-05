# `expfmt` specification and implementation plan

The `expfmt` crate in `scrape.rs` provides official Rust decoders for Prometheus and OpenMetrics wire exposition formats.

## Background and goals

Rust metric pipelines and tools currently lack an official, spec-compliant parser for the full set of Prometheus and OpenMetrics wire formats. Existing community crates cover only basic Prometheus 0.0.4 text and allocate on the heap for every sample.

This repository targets two use cases:

1. High-throughput columnar ingestion for OpenTelemetry Arrow. [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) defines an OTAP-native `prometheus_scrape` receiver in Rust. Its steady-state path streams scrape bytes through pre-allocation relabeling and metric family assembly directly into Apache Arrow metric records. That avoids intermediate Go-style `pmetric` or SDK `metricdata` object graphs and fits thread-per-core `!Send` runtimes with bounded memory.
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
        │  - Pre-allocation metric relabel and drop hook          │
        └────────────────────────────┬────────────────────────────┘
                                     │
                                     ▼  Primary API
        ┌─────────────────────────────────────────────────────────┐
        │  Layer 1: Arrow / OTAP decoder                          │
        │  - Metric family assembly                               │
        │  - Direct Arrow RecordBatches                           │
        │  - Reusable builders/interners                          │
        │  - Fits otel-arrow#3277                                 │
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

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>);
    fn metric_type(&self) -> (&'a [u8], MetricType);
    fn unit(&self) -> (&'a [u8], &'a [u8]);
    fn comment(&self) -> &'a [u8];

    /// Returns the raw series bytes, optional sample timestamp in ms, and float64 value.
    fn series(&self) -> (&'a [u8], Option<i64>, f64);

    /// Returns the raw series bytes, optional timestamp in ms, and parsed native histogram.
    fn histogram(&self) -> (&'a [u8], Option<i64>, HistogramRef<'a>);

    /// Returns the start timestamp in ms if present via `st@...` or `_created`.
    fn start_timestamp(&self) -> Option<i64>;

    /// Populates the caller's reusable label buffer for the current sample.
    fn labels(&self, buf: &mut LabelsBuffer<'a>);

    /// Iterates over exemplars attached to the current sample.
    fn exemplars(&self, buf: &mut ExemplarsBuffer<'a>) -> Result<(), ParseError>;
}
```

### Layer 1: Columnar Apache Arrow decoder

This is the primary API, designed for the [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) scrape pipeline:

```text
scrape bytes
  -> streaming parser
  -> metric relabel/drop
  -> metric family assembler
  -> direct OTAP metric records
```

- `ArrowDecoder` appends parsed metrics, attributes, number data points, summary data points, classic and exponential histogram data points, and exemplars directly into Arrow array builders (`arrow-array` and `arrow-schema`), matching the relational `id` and `parent_id` tables in [`rust/otap-dataflow/crates/pdata`](https://github.com/open-telemetry/otel-arrow/tree/main/rust/otap-dataflow/crates/pdata). Callers can materialize one batch set per scrape with `ArrowDecoder::decode`, pull bounded chunks on demand with `ArrowDecoder::decode_stream` to cap scratch memory and stay within OTAP's `u16` per-batch metric ID limit, or traverse zero-copy [`otel-arrow-dfe-pdata-views`](https://crates.io/crates/otel-arrow-dfe-pdata-views) `MetricsView` wrappers over the staged buffers with `ArrowDecoder::decode_view` and `DecodeStream::next_view`.
- Metric families in text exposition are decoded as contiguous runs, with `# HELP`, `# TYPE`, and `# UNIT` metadata lines preceding that family's samples. Like OpenMetrics 1.0/2.0 and Prometheus's scrape loop, `ArrowDecoder` tracks only the active family cursor instead of maintaining a whole-scrape hash table to reassemble or reject previously seen names, so a non-contiguous repetition of an earlier metric name starts a fresh untyped run unless preceded by its own metadata.
- A `LabelFilter` / `Relabeler` hook runs on the borrowed `LabelsBuffer` from Layer 0 so dropped series never allocate in Arrow builders or metric family state.
- The metric family assembler groups classic histogram `_bucket`, `_sum`, and `_count` lines and summary `quantile`, `_sum`, and `_count` lines (plus OpenMetrics `_created` start timestamps) into complete metric families.
- Configurable translation policies control counter `_total` and unit suffix handling and untyped series handling.
- `ArrowDecoder` owns its scratch buffers and Arrow builders without internal locks or global state, so a per-core `!Send` receiver can reuse allocations across scrapes with bounded memory.

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
- Implement delimited and text protobuf decoding (`FmtProtoDelim`, `FmtProtoText`, `FmtProtoCompact`), including native sparse histograms and NHCB conversion matching [`protobufparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/protobufparse.go) and [`nhcbparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/nhcbparse.go).
- Extend the Go `expfmt` encoder harness to cover `FmtOpenMetrics_2_0_0` and `FmtProtoDelim`.

### Phase 4: Relabeling hooks, pooling, benchmarks, fuzzing, and initial release
- Add the pre-allocation `LabelFilter` and relabeling hook on Layer 0 `LabelsBuffer` and dictionary/buffer reuse across scrapes in `ArrowDecoder`.
- Add `cargo-fuzz` targets comparing Rust decoding against Go `expfmt` and `textparse`.
- Add `criterion` benchmarks measuring throughput in MB/s and allocations per sample across Layer 0 `Parser`, Layer 1 `ArrowDecoder`, and Layer 2 `dto`.
- Publish the `0.1.0` crate release and integrate with `open-telemetry/otel-arrow`.
