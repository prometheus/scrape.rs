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

//! Throughput and allocation benchmarks for `prometheus_scrape_manager::scrape::ScrapeManager`
//! comparing sequential and bounded concurrent scrape modes over the upstream Prometheus
//! `model/textparse` fixture corpus.
//!
//! Recommended CLI invocation:
//! ```sh
//! cargo bench -p prometheus-scrape-manager --bench scrape -- -bench '^BenchmarkScrape' -benchtime 500ms -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use benchfmt::{CountingAlloc, Suite};
use prometheus_expfmt::arrow::OtapMetricRecords;
use prometheus_expfmt::format::Format;
use prometheus_scrape_manager::scrape::{
    ArrowScrapeSink, BodyBufferPool, FetchedScrape, SchedulingMode, ScrapeConfig, ScrapeError,
    ScrapeManager, ScrapeReport, ScrapeTarget, TargetFetcher,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

#[derive(Clone)]
struct BenchFetcher {
    payload: Arc<[u8]>,
    header_wait: Duration,
}

impl TargetFetcher for BenchFetcher {
    async fn fetch(
        &self,
        _target: &ScrapeTarget,
        body_pool: &BodyBufferPool,
    ) -> Result<FetchedScrape, ScrapeError> {
        // Simulate waiting on target TCP connect and server-side `/metrics` generation before
        // HTTP 200 headers arrive. No body buffer or decoder is leased during this wait.
        if self.header_wait.is_zero() {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(self.header_wait).await;
        }

        let mut body = body_pool.acquire(self.payload.len()).await;
        body.extend_from_slice(&self.payload);

        Ok(FetchedScrape {
            body,
            format: Format::TEXT,
            scrape_timestamp_ms: 1_700_000_000_000,
            wire_bytes: self.payload.len(),
            fetch_duration: self.header_wait,
        })
    }
}

struct BlackBoxSink;

impl ArrowScrapeSink for BlackBoxSink {
    async fn on_batch(
        &self,
        target: &ScrapeTarget,
        scrape_timestamp_ms: i64,
        records: OtapMetricRecords,
    ) -> ControlFlow<()> {
        black_box((target, scrape_timestamp_ms, records));
        ControlFlow::Continue(())
    }

    async fn on_scrape_complete(
        &self,
        target: &ScrapeTarget,
        report: ScrapeReport,
    ) -> ControlFlow<()> {
        black_box((target, report));
        ControlFlow::Continue(())
    }
}

fn build_targets(count: usize) -> Vec<ScrapeTarget> {
    (0..count)
        .map(|i| {
            ScrapeTarget::parse(&format!("http://10.0.{}.{}:9100/metrics", i / 256, i % 256))
                .expect("valid target url")
                .with_label("job", "node")
                .with_label("instance", format!("node-{i}"))
        })
        .collect()
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let full = fs::read(root.join("alltypes.237mfs.prom.txt")).expect("read fixture");
    let payload: Arc<[u8]> = Arc::from(full.into_boxed_slice());

    let targets = Arc::new(build_targets(16));
    let total_bytes = (payload.len() * targets.len()) as u64;

    let modes: [(&str, SchedulingMode, usize, usize); 3] = [
        ("sequential_tick", SchedulingMode::sequential(), 1, 1),
        (
            "concurrent_k8_b2_d1",
            SchedulingMode::concurrent_with_pools(
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(2).unwrap(),
                NonZeroUsize::new(1).unwrap(),
            ),
            2,
            1,
        ),
        (
            "concurrent_k8_b8_d4",
            SchedulingMode::concurrent_with_pools(
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(8).unwrap(),
                NonZeroUsize::new(4).unwrap(),
            ),
            8,
            4,
        ),
    ];

    let mut suite = Suite::from_env("prometheus-scrape-manager").with_alloc(&ALLOC);

    // Tokio's 1ms timer-wheel rounding plus OS timer slack makes `Duration::from_millis(1)`
    // wait ~2.2ms per fetch in practice, so label the dimension `2ms` to reflect actual wait time.
    for (wait_label, header_wait) in [("none", Duration::ZERO), ("2ms", Duration::from_millis(1))] {
        for (mode_label, scheduling, max_bodies, max_decoders) in modes {
            let payload = Arc::clone(&payload);
            let targets = Arc::clone(&targets);

            suite = suite.bench(
                format!("ScrapeCycle/targets=16/header_wait={wait_label}/mode={mode_label}"),
                move |b| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .expect("current_thread runtime");

                    let fetcher = BenchFetcher {
                        payload: Arc::clone(&payload),
                        header_wait,
                    };
                    let cfg = ScrapeConfig::new("bench")
                        .with_scheduling(scheduling)
                        .with_max_data_points_per_batch(256);
                    let manager = ScrapeManager::new(cfg, fetcher).expect("manager");
                    let sink = BlackBoxSink;

                    // Warm pool buffers and decoder interner arenas once so B/op and allocs/op
                    // reflect steady-state scrape reuse rather than first-pass capacity growth.
                    rt.block_on(async {
                        let _ = manager.run_once_arrow(&targets, &sink).await;
                    });
                    let warm_stats = manager.stats();
                    assert!(warm_stats.total_body_buffers_created <= max_bodies);
                    assert!(warm_stats.total_decoders_created <= max_decoders);

                    b.set_bytes(total_bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        rt.block_on(async {
                            let out = manager
                                .run_once_arrow(black_box(targets.as_slice()), &sink)
                                .await;
                            let _ = black_box(out);
                        });
                    }
                },
            );
        }
    }

    suite.run();
}
