# scrape.rs

> **Status: Experimental (Work in Progress)**

Official Rust libraries for Prometheus and OpenMetrics metric collection pipelines: wire exposition format decoding (`prometheus-expfmt`), target and metric relabeling (`prometheus-relabel`), and service discovery and scrape management (`prometheus-scrape-manager`).

## Overview

`scrape.rs` provides the building blocks required to discover targets, relabel labels, scrape HTTP endpoints, and decode Prometheus and OpenMetrics payloads in Rust:

```text
Service discoveries
  -> Target relabeling
  -> Scrape manager / HTTP fetch
  -> Streaming expfmt parser
  -> Stage 1: family `__name__` filter pushdown
  -> Metric family assembly & string interning
  -> Stage 2: dictionary-vectorized relabeling & `honor_labels`
  -> Columnar Apache Arrow (OTAP) batches or Protobuf DTOs
```

The project serves two main use cases:

1. Columnar scraping for OpenTelemetry Arrow. [`open-telemetry/otel-arrow#3277`](https://github.com/open-telemetry/otel-arrow/issues/3277) defines an OTAP-native `prometheus_scrape` receiver in Rust. `scrape.rs` streams scrape bytes through early `__name__` family filtering, metric family assembly, and dictionary-vectorized relabeling directly into Apache Arrow (`OtapArrowRecords`) tables on thread-per-core `!Send` runtimes with bounded memory.
2. Standalone Rust Prometheus tooling. Validation harnesses such as OpenTelemetry Weaver live-checking `/metrics` endpoints against semantic conventions, CLIs, and custom collectors can depend on individual pure-CPU crates (`prometheus-expfmt` or `prometheus-relabel`) without pulling in async HTTP or service discovery dependencies.

## Workspace crates

| Crate | Path | Status | Specification | Scope |
| :--- | :--- | :--- | :--- | :--- |
| `prometheus-expfmt` | [`crates/expfmt`](./crates/expfmt) | In progress | [specs/SPEC.md](./specs/SPEC.md) | `Content-Type` and `Accept` negotiation, zero-copy streaming parsers for Prometheus Text 0.0.4, OpenMetrics 1.0, OpenMetrics 2.0, and Prometheus Protobuf, primary Apache Arrow / OTAP decoder (`ArrowDecoder`), and [`MetricFamily`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto) protobuf DTO decoder. |
| `prometheus-relabel` | [`crates/relabel`](./crates/relabel) | In progress | [specs/SPEC.md](./specs/SPEC.md#target-and-metric-relabeling-architecture) | Prometheus-compatible target and metric relabeling (`replace`, `keep`, `drop`, `hashmod`, `labelmap`, `labeldrop`, `labelkeep`, `lowercase`, `uppercase`, `keepequal`, `dropequal`), Stage 1 `__name__` filter pushdown, and Stage 2 dictionary-vectorized relabeling and `honor_labels` resolution. |
| `prometheus-scrape-manager` | [`crates/scrape-manager`](./crates/scrape-manager) | In progress | [specs/SPEC.md](./specs/SPEC.md#bounded-scrape-scheduling-and-memory-pools) | Bounded concurrent and sequential target scrape scheduling (`scrape`), Prometheus HTTP/TLS client configuration (`http_config`), and service discovery mechanisms (`discovery`: static, file, HTTP, DNS, Kubernetes). |

## Development and testing

Run the workspace unit and fixture test suite:

```sh
cargo test --workspace --all-features
```

Run the [`otel-arrow-dfe-pdata`](https://github.com/open-telemetry/otel-arrow/tree/main/rust/otap-dataflow/crates/pdata) compatibility test suite:

```sh
cargo test --manifest-path tests/otap-compat/Cargo.toml
```

Run the Go differential fixture extractor and tests (requires Go):

```sh
cd tests/go-harness && go test ./...
```

Run the decoding, relabeling, and scrape scheduling benchmarks in Go `benchfmt` format for [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat):

```sh
cargo bench -p prometheus-expfmt --bench decode -- -bench '^BenchmarkDecode' -benchtime 1s -count 6 -cpu 2 -benchmem | tee decode.txt
cargo bench -p prometheus-relabel --bench relabel -- -bench '^BenchmarkRelabel' -benchtime 1s -count 6 -cpu 2 -benchmem | tee relabel.txt
cargo bench -p prometheus-scrape-manager --bench scrape -- -bench '^BenchmarkScrape' -benchtime 500ms -count 6 -cpu 2 -benchmem | tee scrape.txt
```
