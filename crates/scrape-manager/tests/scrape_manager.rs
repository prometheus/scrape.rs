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
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

#[tokio::test(start_paused = true)]
async fn cycle_tick_finishes_current_pass_across_target_updates() {
    let t0 = ScrapeTarget::parse("http://10.2.0.1:9100/metrics").unwrap();
    let t1 = ScrapeTarget::parse("http://10.2.0.2:9100/metrics").unwrap();
    let t2 = ScrapeTarget::parse("http://10.2.0.3:9100/metrics").unwrap();
    let t3 = ScrapeTarget::parse("http://10.2.0.4:9100/metrics").unwrap();

    let fetcher = SimulatedLatencyFetcher {
        slow_url: t0.url().as_str().to_owned(),
        slow_delay: Duration::from_secs(2),
        fast_delay: Duration::from_secs(2),
        payload: b"metric_a 1\n".to_vec(),
    };

    let cfg = ScrapeConfig::new("seq-update")
        .with_scrape_interval(Duration::from_secs(10))
        .with_scrape_timeout(Duration::from_secs(5))
        .with_scheduling(SchedulingMode::sequential());

    let manager = ScrapeManager::new(cfg, fetcher).expect("manager");
    let (ctrl, ctrl_rx) = ScrapeManager::control_channel();
    let sink = RecordingRawSink::new();

    let t3_for_driver = t3.clone();
    let driver = async move {
        // Send `UpdateTargets` at t = 1s while `t0` is mid-scrape; `t0`, `t1`, and `t2` must all
        // complete pass 1, and `t3` must take effect on pass 2 (t = 10s).
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(ctrl.update_targets(vec![t3_for_driver]));
        tokio::time::sleep(Duration::from_secs(14)).await;
        let _ = ctrl.shutdown();
    };

    tokio::join!(
        manager.run_raw(vec![t0.clone(), t1.clone(), t2.clone()], ctrl_rx, &sink),
        driver
    );

    let stats = manager.stats();
    assert_eq!(
        stats.scrapes_started,
        stats.scrapes_succeeded + stats.scrapes_failed
    );
    assert_eq!(stats.scrapes_succeeded, 4);

    let seen = sink.seen.lock().expect("lock");
    assert_eq!(seen.get(t0.url().as_str()).map(Vec::len), Some(1));
    assert_eq!(seen.get(t1.url().as_str()).map(Vec::len), Some(1));
    assert_eq!(seen.get(t2.url().as_str()).map(Vec::len), Some(1));
    assert_eq!(seen.get(t3.url().as_str()).map(Vec::len), Some(1));
}

#[tokio::test(start_paused = true)]
async fn empty_startup_honors_initial_delay_on_update_targets_and_stops_on_channel_drop() {
    let t1 = ScrapeTarget::parse("http://10.3.0.1:9100/metrics").unwrap();
    let fetcher = SimulatedLatencyFetcher {
        slow_url: String::new(),
        slow_delay: Duration::from_millis(10),
        fast_delay: Duration::from_millis(10),
        payload: b"metric_a 1\n".to_vec(),
    };

    let cfg = ScrapeConfig::new("dynamic-sd")
        .with_scrape_interval(Duration::from_secs(10))
        .with_scrape_timeout(Duration::from_secs(5))
        .with_initial_delay(Duration::from_secs(6))
        .with_scheduling(SchedulingMode::concurrent(NonZeroUsize::new(4).unwrap()));

    let start = Instant::now();
    let manager = ScrapeManager::new(cfg, fetcher).expect("manager");
    let (ctrl, ctrl_rx) = ScrapeManager::control_channel();
    let sink = RecordingRawSink::new();
    let observer = ctrl.clone();

    let t1_for_driver = t1.clone();
    let driver = async move {
        // Start with 0 targets; push `t1` at t = 1s while still inside the 6s `initial_delay`.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(ctrl.update_targets(vec![t1_for_driver]));

        // Wait past `initial_delay + scrape_interval` so `t1` scrapes at least once after t >= 6s.
        tokio::time::sleep(Duration::from_secs(16)).await;
        assert!(ctrl.update_targets(Vec::new()));
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Drop the last active sender (`ctrl`) after dropping `observer` below -> clean exit.
        drop(ctrl);
    };

    // Drop `observer` inside the driver check after run_raw exits to verify `false` return value.
    let check_closed = async move {
        driver.await;
    };
    drop(observer);
    let (probe_ctrl, probe_rx) = ScrapeManager::control_channel();
    drop(probe_rx);
    assert!(!probe_ctrl.update_targets(Vec::new()));
    assert!(!probe_ctrl.shutdown());

    tokio::join!(manager.run_raw(Vec::new(), ctrl_rx, &sink), check_closed);

    let seen = sink.seen.lock().expect("lock");
    let stamps = seen.get(t1.url().as_str()).expect("t1 scraped");
    assert!(
        stamps[0].duration_since(start) >= Duration::from_secs(6),
        "expected first scrape after 6s initial_delay, got {:?}",
        stamps[0].duration_since(start)
    );
}

#[tokio::test]
async fn real_http_concurrent_header_stalls_complete_in_parallel_with_bounded_buffers() {
    let mut targets = Vec::new();
    let mut server_handles = Vec::new();
    #[cfg(feature = "arrow")]
    let expected_passes = 2usize;
    #[cfg(not(feature = "arrow"))]
    let expected_passes = 1usize;

    let header_barrier = Arc::new(tokio::sync::Barrier::new(6));

    for idx in 0..6 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        targets.push(ScrapeTarget::parse(&format!("http://{addr}/metrics")).expect("target"));
        let barrier = Arc::clone(&header_barrier);

        server_handles.push(tokio::spawn(async move {
            for _ in 0..expected_passes {
                let (mut sock, _) = listener.accept().await.expect("accept");
                let mut req = [0u8; 1024];
                let _ = sock.read(&mut req).await.expect("read req");

                // All 6 requests must be in flight concurrently before any handler sends headers.
                barrier.wait().await;

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
            }
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

    let raw_sink = RecordingRawSink::new();
    let raw_cf = tokio::time::timeout(
        Duration::from_secs(5),
        manager.run_once_raw(&targets, &raw_sink),
    )
    .await
    .expect("6-way barrier must release under concurrent header scheduling");
    assert!(raw_cf.is_continue());
    assert_eq!(raw_sink.seen.lock().expect("lock").len(), 6);

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
        let arrow_cf = tokio::time::timeout(
            Duration::from_secs(5),
            manager.run_once_arrow(&targets, &sink),
        )
        .await
        .expect("6-way barrier must release under concurrent arrow scheduling");
        assert!(arrow_cf.is_continue());
        let reports = sink.0.lock().expect("lock");
        assert_eq!(reports.len(), 6);
        assert!(reports.iter().all(|r| r.up && r.data_points_decoded == 1));
    }

    let stats = manager.stats();
    assert_eq!(stats.scrapes_succeeded, (6 * expected_passes) as u64);
    assert!(stats.total_body_buffers_created <= 2);
    #[cfg(feature = "arrow")]
    assert_eq!(stats.total_decoders_created, 1);

    for h in server_handles {
        h.await.expect("server task");
    }
}

#[test]
fn non_send_local_set_compatibility_for_thread_per_core_runtimes() {
    use std::cell::RefCell;
    use std::rc::Rc;

    struct LocalRawSink {
        seen: Rc<RefCell<usize>>,
        stop_at: usize,
    }

    impl RawScrapeSink for LocalRawSink {
        async fn on_raw_scrape(
            &self,
            _target: &ScrapeTarget,
            result: Result<FetchedScrape, ScrapeError>,
        ) -> ControlFlow<()> {
            assert!(result.is_ok());
            let mut count = self.seen.borrow_mut();
            *count += 1;
            if *count >= self.stop_at {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
    }

    #[cfg(feature = "arrow")]
    use prometheus_expfmt::arrow::OtapMetricRecords;
    #[cfg(feature = "arrow")]
    use prometheus_scrape_manager::scrape::{ArrowScrapeSink, ScrapeReport};

    // Rc<RefCell<...>> is !Send and !Sync, matching otel-arrow per-core LocalSet receivers.
    #[cfg(feature = "arrow")]
    struct LocalOnlySink {
        points: Rc<RefCell<u64>>,
        batches: Rc<RefCell<usize>>,
        completed: Rc<RefCell<usize>>,
        stop_after: usize,
    }

    #[cfg(feature = "arrow")]
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
            let mut done = self.completed.borrow_mut();
            *done += 1;
            if *done >= self.stop_after {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
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
        .start_paused(true)
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
            .with_scrape_interval(Duration::from_secs(5))
            .with_scrape_timeout(Duration::from_secs(2))
            .with_max_data_points_per_batch(200)
            .with_scheduling(SchedulingMode::concurrent(NonZeroUsize::new(4).unwrap()));
        let manager = ScrapeManager::new(cfg, fetcher).expect("manager");

        let targets: Vec<ScrapeTarget> = (0..4)
            .map(|i| ScrapeTarget::parse(&format!("http://127.0.0.1:900{i}/metrics")).unwrap())
            .collect();

        // Exercise `!Send` `RawScrapeSink` on both `run_once_raw` and continuous `run_raw`.
        let raw_sink = LocalRawSink {
            seen: Rc::new(RefCell::new(0)),
            stop_at: 8,
        };
        let _ = manager.run_once_raw(&targets, &raw_sink).await;
        assert_eq!(*raw_sink.seen.borrow(), 4);
        let (_raw_ctrl, raw_rx) = ScrapeManager::control_channel();
        manager.run_raw(targets.clone(), raw_rx, &raw_sink).await;
        assert!(*raw_sink.seen.borrow() >= 8);

        #[cfg(feature = "arrow")]
        {
            let sink = LocalOnlySink {
                points: Rc::new(RefCell::new(0)),
                batches: Rc::new(RefCell::new(0)),
                completed: Rc::new(RefCell::new(0)),
                stop_after: 8,
            };

            let _ = manager.run_once_arrow(&targets, &sink).await;
            assert_eq!(*sink.points.borrow(), 4 * 500);
            // 500 points chunked at 200 points/batch -> 3 chunks per target * 4 targets = 12 chunks.
            assert_eq!(*sink.batches.borrow(), 12);

            let (_arrow_ctrl, arrow_rx) = ScrapeManager::control_channel();
            manager.run_arrow(targets, arrow_rx, &sink).await;
            assert!(*sink.completed.borrow() >= 8);

            let stats = manager.stats();
            assert!(stats.total_decoders_created <= 2);
            assert!(stats.total_body_buffers_created <= 2);
        }
    });
}

#[cfg(feature = "arrow")]
#[tokio::test(start_paused = true)]
async fn cooperative_arrow_decode_reports_partial_errors_reclaims_pools_on_break_and_runs_loop() {
    use prometheus_expfmt::arrow::{DecodeBudget, OtapMetricRecords};
    use prometheus_scrape_manager::scrape::{ArrowScrapeSink, ScrapeReport};

    enum StubMode {
        OkText(Vec<u8>),
        MissingEofOpenMetrics(Vec<u8>),
        Http503,
    }

    struct StubFetcher {
        by_url: HashMap<String, StubMode>,
    }

    impl TargetFetcher for StubFetcher {
        async fn fetch(
            &self,
            target: &ScrapeTarget,
            pool: &BodyBufferPool,
        ) -> Result<FetchedScrape, ScrapeError> {
            match self.by_url.get(target.url().as_str()).expect("stub url") {
                StubMode::OkText(bytes) => {
                    let mut body = pool.acquire(bytes.len()).await;
                    body.extend_from_slice(bytes);
                    Ok(FetchedScrape {
                        body,
                        format: Format::TEXT,
                        scrape_timestamp_ms: 1_700_000_000_000,
                        fetch_duration: Duration::from_millis(1),
                        wire_bytes: bytes.len(),
                    })
                }
                StubMode::MissingEofOpenMetrics(bytes) => {
                    let mut body = pool.acquire(bytes.len()).await;
                    body.extend_from_slice(bytes);
                    Ok(FetchedScrape {
                        body,
                        format: Format::OPEN_METRICS_1_0_0,
                        scrape_timestamp_ms: 1_700_000_000_000,
                        fetch_duration: Duration::from_millis(1),
                        wire_bytes: bytes.len(),
                    })
                }
                StubMode::Http503 => Err(ScrapeError::UnexpectedStatus { status: 503 }),
            }
        }
    }

    struct InspectSink {
        break_on_first_batch: bool,
        batches: Mutex<usize>,
        reports: Mutex<Vec<ScrapeReport>>,
    }

    impl ArrowScrapeSink for InspectSink {
        async fn on_batch(
            &self,
            _target: &ScrapeTarget,
            _ts_ms: i64,
            _records: OtapMetricRecords,
        ) -> ControlFlow<()> {
            *self.batches.lock().unwrap() += 1;
            if self.break_on_first_batch {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }

        async fn on_scrape_complete(
            &self,
            _target: &ScrapeTarget,
            report: ScrapeReport,
        ) -> ControlFlow<()> {
            self.reports.lock().unwrap().push(report);
            ControlFlow::Continue(())
        }
    }

    let ok_target = ScrapeTarget::parse("http://10.9.0.1:9100/metrics").unwrap();
    let bad_om_target = ScrapeTarget::parse("http://10.9.0.2:9100/metrics").unwrap();
    let down_target = ScrapeTarget::parse("http://10.9.0.3:9100/metrics").unwrap();

    let mut ok_payload = String::from("# TYPE coop_metric gauge\n");
    for i in 0..25 {
        ok_payload.push_str(&format!("coop_metric{{idx=\"{i}\"}} {i}\n"));
    }
    let mut missing_eof = String::from("# TYPE om_metric gauge\n");
    for i in 0..8 {
        missing_eof.push_str(&format!("om_metric{{idx=\"{i}\"}} {i}\n"));
    }

    let mut by_url = HashMap::new();
    by_url.insert(
        ok_target.url().as_str().to_owned(),
        StubMode::OkText(ok_payload.into_bytes()),
    );
    by_url.insert(
        bad_om_target.url().as_str().to_owned(),
        StubMode::MissingEofOpenMetrics(missing_eof.into_bytes()),
    );
    by_url.insert(down_target.url().as_str().to_owned(), StubMode::Http503);

    // Tight `DecodeBudget` (2 entries / 32 bytes) forces `DecodeStep::Pending` cooperative yields
    // and sub-slice budget clamping on a single-buffer, single-decoder sequential manager.
    let cfg = ScrapeConfig::new("coop-arrow")
        .with_scrape_interval(Duration::from_secs(10))
        .with_scrape_timeout(Duration::from_secs(5))
        .with_max_data_points_per_batch(4)
        .with_decode_budget(DecodeBudget::new(2, 32, Duration::from_millis(1)))
        .with_scheduling(SchedulingMode::sequential());
    let manager = ScrapeManager::new(cfg, StubFetcher { by_url }).expect("manager");

    // 1. Break on chunk 1 of a multi-chunk scrape must reclaim both single-slot pools cleanly.
    let break_sink = InspectSink {
        break_on_first_batch: true,
        batches: Mutex::new(0),
        reports: Mutex::new(Vec::new()),
    };
    let brk = manager.scrape_once_arrow(&ok_target, &break_sink).await;
    assert!(brk.is_break());

    // 2. Subsequent scrapes succeed without deadlocking on the 1-slot body/decoder pools, and
    // mid-stream OpenMetrics decode failure reports the 2 tentative chunks emitted before EOF.
    let sink = InspectSink {
        break_on_first_batch: false,
        batches: Mutex::new(0),
        reports: Mutex::new(Vec::new()),
    };
    let ok_rep = match manager.scrape_once_arrow(&ok_target, &sink).await {
        ControlFlow::Continue(r) => r,
        ControlFlow::Break(()) => panic!("unexpected break"),
    };
    assert!(ok_rep.up);
    assert_eq!(ok_rep.data_points_decoded, 25);
    assert_eq!(ok_rep.batches_emitted, 7);

    let om_rep = match manager.scrape_once_arrow(&bad_om_target, &sink).await {
        ControlFlow::Continue(r) => r,
        ControlFlow::Break(()) => panic!("unexpected break"),
    };
    assert!(!om_rep.up);
    assert_eq!(om_rep.data_points_decoded, 8);
    assert_eq!(om_rep.batches_emitted, 2);
    assert!(om_rep.error.is_some());

    let down_rep = match manager.scrape_once_arrow(&down_target, &sink).await {
        ControlFlow::Continue(r) => r,
        ControlFlow::Break(()) => panic!("unexpected break"),
    };
    assert!(!down_rep.up);
    assert_eq!(down_rep.batches_emitted, 0);

    // 3. Drive continuous `run_arrow` across one interval tick and shut down cleanly.
    let (ctrl, ctrl_rx) = ScrapeManager::control_channel();
    let driver = async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = ctrl.shutdown();
    };
    tokio::join!(manager.run_arrow(vec![ok_target], ctrl_rx, &sink), driver);

    let stats = manager.stats();
    assert_eq!(stats.total_body_buffers_created, 1);
    assert_eq!(stats.total_decoders_created, 1);
    assert_eq!(stats.scrapes_succeeded, 2);
    assert_eq!(stats.scrapes_failed, 2);
}
