# prometheus-scrape-manager

Prometheus target scrape pool management (`scrape`), HTTP/TLS client configuration (`http_config`), and service discovery (`discovery`) in Rust, built on [`prometheus-expfmt`](../expfmt) and [`prometheus-relabel`](../relabel).

## Scrape scheduling modes

`scrape::ScrapeManager` supports two scheduling strategies configured via `SchedulingMode`:

- `SchedulingMode::Concurrent` schedules every target on its own deterministic 64-bit FNV-1a phase offset modulo `scrape_interval` inside a single min-heap. Up to `max_in_flight` HTTP requests wait for response headers in parallel while holding zero payload memory. Only after an HTTP `200 OK` header arrives does the fetcher lease one of `max_buffered_bodies` reusable `Vec<u8>` buffers from `BodyBufferPool`, and decoding leases one of `max_decoders` reusable `ArrowDecoder` instances from `DecoderPool`.
- `SchedulingMode::Sequential` scrapes one target at a time using a single reusable body buffer and a single decoder, either on a job-wide tick via `SequentialSchedule::CycleTick` or across per-target FNV-1a phase offsets via `SequentialSchedule::Jittered`.

The scrape loop drives concurrent futures with `FuturesUnordered` rather than `tokio::spawn`, so thread-per-core `!Send` `LocalSet` runtimes can pass non-`Send` sinks directly.

Part of the [`prometheus/scrape.rs`](https://github.com/prometheus/scrape.rs) workspace.
