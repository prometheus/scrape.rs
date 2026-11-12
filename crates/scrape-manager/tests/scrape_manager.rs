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

//! Integration tests for `prometheus_scrape_manager::scrape::ScrapeManager`.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Mutex;
use std::time::{Duration, Instant as StdInstant};

use prometheus_expfmt::format::{FMT_TEXT, Format};
use prometheus_scrape_manager::scrape::{
    BodyBufferPool, FetchedScrape, RawScrapeSink, SchedulingMode, ScrapeConfig, ScrapeError,
    ScrapeManager, ScrapeTarget, TargetFetcher,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;

struct SimulatedLatencyFetcher {
    slow_url: String,
    slow_delay: Duration,
    fast_delay: Duration,
    payload: Vec<u8>,
}

impl TargetFetcher for SimulatedLatencyFetcher {
    async fn fetch(
        &self,
        target: &ScrapeTarget,
        pool: &BodyBufferPool,
    ) -> Result<FetchedScrape, ScrapeError> {
        let delay = if target.url().as_str() == self.slow_url {
            self.slow_delay
        } else {
            self.fast_delay
        };
        // Simulate server computation / network RTT before HTTP 200 headers arrive (zero buffer held).
        tokio::time::sleep(delay).await;

        let mut body = pool.acquire(self.payload.len()).await;
        body.extend_from_slice(&self.payload);
        // Simulate brief body transfer while holding the pooled buffer.
        tokio::time::sleep(Duration::from_millis(5)).await;

        Ok(FetchedScrape {
            body,
            format: Format::from(FMT_TEXT),
            scrape_timestamp_ms: 1_700_000_000_000,
            fetch_duration: delay + Duration::from_millis(5),
            wire_bytes: self.payload.len(),
        })
    }
}

struct RecordingRawSink {
    seen: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RecordingRawSink {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }
}

impl RawScrapeSink for RecordingRawSink {
    async fn on_raw_scrape(
        &self,
        target: &ScrapeTarget,
        result: Result<FetchedScrape, ScrapeError>,
    ) -> ControlFlow<()> {
        assert!(result.is_ok(), "unexpected scrape error: {result:?}");
        self.seen
            .lock()
            .expect("lock")
            .entry(target.url().as_str().to_owned())
            .or_default()
            .push(Instant::now());
        ControlFlow::Continue(())
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_mode_preserves_equal_intervals_despite_stalled_target_and_bounds_buffers() {
    let interval = Duration::from_secs(10);
    let targets: Vec<ScrapeTarget> = (0..8)
        .map(|i| {
            ScrapeTarget::parse(&format!("http://10.0.0.{}:9100/metrics", i + 1))
                .expect("url")
                .with_label("instance", format!("target-{i}"))
        })
        .collect();
    let slow_url = targets[0].url().as_str().to_owned();

    let fetcher = SimulatedLatencyFetcher {
        slow_url: slow_url.clone(),
        slow_delay: Duration::from_secs(8),
        fast_delay: Duration::from_millis(40),
        payload: b"# TYPE up_metric gauge\nup_metric 1\n".repeat(64),
    };

    let cfg = ScrapeConfig::new("node")
        .with_scrape_interval(interval)
        .with_scrape_timeout(Duration::from_secs(9))
        .with_scheduling(SchedulingMode::concurrent_with_pools(
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        ));

    let manager = ScrapeManager::new(cfg, fetcher).expect("manager");
    let (ctrl, ctrl_rx) = ScrapeManager::control_channel();
    let sink = RecordingRawSink::new();

    let shutdown_ctrl = ctrl.clone();
    let driver = async move {
        tokio::time::sleep(Duration::from_secs(45)).await;
        let _ = shutdown_ctrl.shutdown();
    };

    tokio::join!(manager.run_raw(targets.clone(), ctrl_rx, &sink), driver);

    let stats = manager.stats();
    assert_eq!(stats.scrapes_failed, 0);
    assert_eq!(stats.scrapes_overrun, 0);
    // Even with 8 targets and an 8-second stall on target-0, at most 2 body buffers are ever created.
    assert!(
        stats.total_body_buffers_created <= 2,
        "expected <= 2 pooled buffers, got {}",
        stats.total_body_buffers_created
    );
    assert!(stats.peak_buffered_bodies <= 2);

    let recorded = sink.seen.lock().expect("lock");
    for t in &targets[1..] {
        let stamps = recorded.get(t.url().as_str()).expect("fast target scraped");
        assert!(
            stamps.len() >= 4,
            "expected >= 4 scrapes in 45s at 10s interval, got {}",
            stamps.len()
        );
        for pair in stamps.windows(2) {
            let delta = pair[1].duration_since(pair[0]);
            let diff_ms = delta.as_millis().abs_diff(interval.as_millis());
            assert!(
                diff_ms <= 25,
                "expected exact 10s interval on fast target {}, got {delta:?}",
                t.url()
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sequential_modes_use_single_buffer_and_count_overruns() {
    for mode in [
        SchedulingMode::sequential(),
        SchedulingMode::sequential_jittered(),
    ] {
        let targets: Vec<ScrapeTarget> = (0..3)
            .map(|i| ScrapeTarget::parse(&format!("http://10.1.0.{}:9100/metrics", i + 1)).unwrap())
            .collect();

        let fetcher = SimulatedLatencyFetcher {
            slow_url: targets[0].url().as_str().to_owned(),
            slow_delay: Duration::from_secs(7),
            fast_delay: Duration::from_secs(7),
            payload: b"metric_a 1\n".to_vec(),
        };

        // 3 targets * 7s = 21s per full pass, overrunning a 10s scrape_interval in both sequential modes.
        let cfg = ScrapeConfig::new("seq")
            .with_scrape_interval(Duration::from_secs(10))
            .with_scrape_timeout(Duration::from_secs(10))
            .with_scheduling(mode);

        let manager = ScrapeManager::new(cfg, fetcher).expect("manager");
        let (ctrl, ctrl_rx) = ScrapeManager::control_channel();
        let sink = RecordingRawSink::new();

        let driver = async move {
            tokio::time::sleep(Duration::from_secs(35)).await;
            let _ = ctrl.shutdown();
        };

        tokio::join!(manager.run_raw(targets, ctrl_rx, &sink), driver);

        let stats = manager.stats();
        assert_eq!(stats.total_body_buffers_created, 1);
        assert_eq!(stats.peak_buffered_bodies, 1);
        assert!(
            stats.scrapes_overrun >= 1,
            "expected overrun count >= 1 in mode {mode:?}, got {stats:?}"
        );
    }
}

#[tokio::test]
async fn real_http_concurrent_header_stalls_complete_in_parallel_with_bounded_buffers() {
    let mut targets = Vec::new();
    let mut server_handles = Vec::new();

    for idx in 0..6 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        targets.push(ScrapeTarget::parse(&format!("http://{addr}/metrics")).expect("target"));

        server_handles.push(tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut req = [0u8; 1024];
            let _ = sock.read(&mut req).await.expect("read req");

            // Stall 120ms before sending HTTP 200 headers.
            tokio::time::sleep(Duration::from_millis(120)).await;

            let body = format!(
                "# TYPE http_test_total counter\nhttp_test_total{{shard=\"{idx}\"}} {}\n",
                idx + 1
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.expect("write resp");
        }));
    }

    let cfg = ScrapeConfig::new("http-parallel")
        .with_scrape_interval(Duration::from_secs(10))
        .with_scrape_timeout(Duration::from_secs(5))
        .with_scheduling(SchedulingMode::concurrent_with_pools(
            NonZeroUsize::new(6).unwrap(),
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        ));

    let manager = ScrapeManager::with_reqwest(cfg).expect("reqwest manager");

    let wall_start = StdInstant::now();
    #[cfg(feature = "arrow")]
    {
        use prometheus_expfmt::arrow::OtapMetricRecords;
        use prometheus_scrape_manager::scrape::{ArrowScrapeSink, ScrapeReport};

        struct CountSink(Mutex<Vec<ScrapeReport>>);
        impl ArrowScrapeSink for CountSink {
            async fn on_batch(
                &self,
                _target: &ScrapeTarget,
                _ts_ms: i64,
                _records: OtapMetricRecords,
            ) -> ControlFlow<()> {
                ControlFlow::Continue(())
            }
            async fn on_scrape_complete(
                &self,
                _target: &ScrapeTarget,
                report: ScrapeReport,
            ) -> ControlFlow<()> {
                self.0.lock().expect("lock").push(report);
                ControlFlow::Continue(())
            }
        }

        let sink = CountSink(Mutex::new(Vec::new()));
        let _ = manager.run_once_arrow(&targets, &sink).await;
        let reports = sink.0.lock().expect("lock");
        assert_eq!(reports.len(), 6);
        assert!(reports.iter().all(|r| r.up && r.data_points_decoded == 1));
    }
    #[cfg(not(feature = "arrow"))]
    {
        let sink = RecordingRawSink::new();
        let _ = manager.run_once_raw(&targets, &sink).await;
        let seen = sink.seen.lock().expect("lock");
        assert_eq!(seen.len(), 6);
    }

    let elapsed = wall_start.elapsed();
    // Sequential execution of six 120ms stalls would take >= 720ms; 6-way concurrent headers finish well under 550ms.
    assert!(
        elapsed < Duration::from_millis(550),
        "expected concurrent header wait (<550ms), took {elapsed:?}"
    );

    let stats = manager.stats();
    assert_eq!(stats.scrapes_succeeded, 6);
    assert!(stats.total_body_buffers_created <= 2);
    #[cfg(feature = "arrow")]
    assert_eq!(stats.total_decoders_created, 1);

    for h in server_handles {
        h.await.expect("server task");
    }
}

#[cfg(feature = "arrow")]
#[test]
fn non_send_local_set_compatibility_for_thread_per_core_runtimes() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use prometheus_expfmt::arrow::OtapMetricRecords;
    use prometheus_scrape_manager::scrape::{ArrowScrapeSink, ScrapeReport};

    // Rc<RefCell<...>> is !Send and !Sync, matching otel-arrow per-core LocalSet receivers.
    struct LocalOnlySink {
        points: Rc<RefCell<u64>>,
        batches: Rc<RefCell<usize>>,
    }

    impl ArrowScrapeSink for LocalOnlySink {
        async fn on_batch(
            &self,
            _target: &ScrapeTarget,
            _scrape_timestamp_ms: i64,
            records: OtapMetricRecords,
        ) -> ControlFlow<()> {
            *self.points.borrow_mut() += records.num_data_points() as u64;
            *self.batches.borrow_mut() += 1;
            ControlFlow::Continue(())
        }

        async fn on_scrape_complete(
            &self,
            _target: &ScrapeTarget,
            report: ScrapeReport,
        ) -> ControlFlow<()> {
            assert!(report.up);
            ControlFlow::Continue(())
        }
    }

    struct LocalOnlyFetcher {
        payload: Rc<Vec<u8>>,
    }

    impl TargetFetcher for LocalOnlyFetcher {
        async fn fetch(
            &self,
            _target: &ScrapeTarget,
            pool: &BodyBufferPool,
        ) -> Result<FetchedScrape, ScrapeError> {
            let mut body = pool.acquire(self.payload.len()).await;
            body.extend_from_slice(&self.payload);
            Ok(FetchedScrape {
                body,
                format: Format::from(FMT_TEXT),
                scrape_timestamp_ms: 1_700_000_000_000,
                fetch_duration: Duration::from_micros(50),
                wire_bytes: self.payload.len(),
            })
        }
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime");
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let mut text = String::from("# TYPE local_counter_total counter\n");
        for i in 0..500 {
            text.push_str(&format!("local_counter_total{{id=\"{i}\"}} {i}\n"));
        }
        let fetcher = LocalOnlyFetcher {
            payload: Rc::new(text.into_bytes()),
        };
        let cfg = ScrapeConfig::new("local-core")
            .with_max_data_points_per_batch(200)
            .with_scheduling(SchedulingMode::concurrent(NonZeroUsize::new(4).unwrap()));
        let manager = ScrapeManager::new(cfg, fetcher).expect("manager");

        let targets: Vec<ScrapeTarget> = (0..4)
            .map(|i| ScrapeTarget::parse(&format!("http://127.0.0.1:900{i}/metrics")).unwrap())
            .collect();

        let sink = LocalOnlySink {
            points: Rc::new(RefCell::new(0)),
            batches: Rc::new(RefCell::new(0)),
        };

        let _ = manager.run_once_arrow(&targets, &sink).await;
        assert_eq!(*sink.points.borrow(), 4 * 500);
        // 500 points chunked at 200 points/batch -> 3 chunks per target * 4 targets = 12 chunks.
        assert_eq!(*sink.batches.borrow(), 12);

        let stats = manager.stats();
        assert_eq!(stats.total_decoders_created, 1);
        assert!(stats.total_body_buffers_created <= 2);
    });
}
