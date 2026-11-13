# prometheus-expfmt

Official Rust decoders and content negotiation for Prometheus and OpenMetrics wire exposition formats, part of the [`prometheus/scrape.rs`](https://github.com/prometheus/scrape.rs) workspace:

- `format`: `Content-Type` and `Accept` negotiation matching [`prometheus/common/expfmt`](https://github.com/prometheus/common/tree/main/expfmt), plus scraper-side `ScrapeProtocol`, `accept_header`, and `resolve_scrape_format` fallback resolution matching [`prometheus/prometheus`](https://github.com/prometheus/prometheus).
- `arrow` *(default feature)*: Zero-copy streaming decoder (`ArrowDecoder`) producing columnar Apache Arrow / OpenTelemetry Arrow (`OtapArrowRecords`) metric tables with bounded memory.
- `dto` *(default feature)*: `io.prometheus.client.MetricFamily` protobuf DTO decoding for CLIs, live-checkers, and test harnesses.
