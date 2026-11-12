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

use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
#[cfg(feature = "arrow")]
use std::time::Instant as StdInstant;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
#[cfg(feature = "arrow")]
use prometheus_expfmt::arrow::{DecodeBudget, DecodeCursor, DecodeStep, OtapMetricRecords};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

#[cfg(feature = "arrow")]
use crate::scrape::DecoderPool;
#[cfg(feature = "arrow")]
use crate::scrape::http::current_timestamp_ms;
use crate::scrape::schedule::{TargetSchedule, advance_grid_deadline};
use crate::scrape::{
    BodyBufferPool, FetchedScrape, ReqwestFetcher, SchedulingMode, ScrapeConfig, ScrapeError,
    ScrapeTarget, SequentialSchedule, TargetFetcher,
};

/// Control-plane messages accepted by a running [`ScrapeManager`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ScrapeCommand {
    /// Replaces the active target set while preserving the interval phase of unchanged targets.
    UpdateTargets(Vec<ScrapeTarget>),
    /// Stops scheduling new scrapes and exits the run loop cleanly.
    Shutdown,
}

/// Handle used to push target discovery updates or request shutdown on a [`ScrapeManager`].
#[derive(Clone, Debug)]
pub struct ScrapeControl {
    tx: mpsc::UnboundedSender<ScrapeCommand>,
}

impl ScrapeControl {
    /// Creates an unbounded control channel pair `(`[`ScrapeControl`]`, Receiver)` for live target
    /// updates and graceful shutdown.
    #[must_use]
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<ScrapeCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    /// Sends a new target snapshot to the running [`ScrapeManager`].
    ///
    /// Returns `false` if the manager loop has already exited.
    #[must_use]
    pub fn update_targets(&self, targets: Vec<ScrapeTarget>) -> bool {
        self.tx.send(ScrapeCommand::UpdateTargets(targets)).is_ok()
    }

    /// Signals the running [`ScrapeManager`] to stop and return.
    ///
    /// Returns `false` if the manager loop has already exited.
    #[must_use]
    pub fn shutdown(&self) -> bool {
        self.tx.send(ScrapeCommand::Shutdown).is_ok()
    }
}

/// Per-target outcome summary emitted at the end of every scrape attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScrapeReport {
    /// `true` when HTTP fetch and payload decoding succeeded (`up == 1`).
    pub up: bool,
    /// Unix epoch timestamp in milliseconds recorded for the scrape.
    pub scrape_timestamp_ms: i64,
    /// End-to-end fetch + decode wall-clock duration.
    pub duration: Duration,
    /// Compressed (wire) bytes read from the target socket.
    pub wire_bytes: usize,
    /// Uncompressed exposition payload bytes.
    pub uncompressed_bytes: usize,
    /// Total metric data points delivered to [`ArrowScrapeSink::on_batch`] during this scrape
    /// (`0` on raw scrapes or when failing before the first batch).
    pub data_points_decoded: u64,
    /// Number of Arrow chunks delivered to [`ArrowScrapeSink::on_batch`] during this scrape
    /// (`0` on empty/raw scrapes or when failing before the first batch).
    pub batches_emitted: usize,
    /// Error description when `up == false`.
    pub error: Option<String>,
}

/// Point-in-time counter and pool memory snapshot from [`ScrapeManager::stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ManagerStats {
    /// Total target scrape attempts started.
    pub scrapes_started: u64,
    /// Total target scrapes that completed HTTP fetch and decode without error.
    pub scrapes_succeeded: u64,
    /// Total target scrapes that failed HTTP fetch, size limits, or decoding.
    pub scrapes_failed: u64,
    /// Missed interval ticks caused by slow cycles or targets still in flight at their next tick.
    pub scrapes_overrun: u64,
    /// Total metric data points decoded across all succeeded Arrow scrapes.
    pub data_points_decoded: u64,
    /// Maximum number of response body buffers leased simultaneously.
    pub peak_buffered_bodies: usize,
    /// Total distinct `Vec<u8>` body buffers ever allocated by the pool.
    pub total_body_buffers_created: usize,
    /// Idle `Vec<u8>` buffer capacity currently retained in bytes.
    pub retained_body_buffer_bytes: usize,
    /// Maximum number of `ArrowDecoder` instances leased simultaneously.
    #[cfg(feature = "arrow")]
    pub peak_active_decoders: usize,
    /// Total distinct `ArrowDecoder` instances ever allocated by the pool.
    #[cfg(feature = "arrow")]
    pub total_decoders_created: usize,
    /// Idle `ArrowDecoder` scratch capacity currently retained in bytes.
    #[cfg(feature = "arrow")]
    pub retained_decoder_bytes: usize,
}

#[derive(Debug, Default)]
struct AtomicCounters {
    started: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
    overrun: AtomicU64,
    points_decoded: AtomicU64,
}

/// Consumer receiving raw uncompressed target payloads without Arrow decoding.
pub trait RawScrapeSink {
    /// Handles a completed or failed target fetch, returning [`ControlFlow::Break`] to stop the
    /// manager loop early.
    ///
    /// Note that `Ok(fetched)` owns a [`crate::scrape::PooledBodyBuffer`] permit from
    /// [`crate::scrape::BodyBufferPool`] until `fetched` is dropped; drop `fetched` before
    /// awaiting slow downstream I/O to avoid stalling concurrent scrapes.
    fn on_raw_scrape(
        &self,
        target: &ScrapeTarget,
        result: Result<FetchedScrape, ScrapeError>,
    ) -> impl Future<Output = ControlFlow<()>>;
}

/// Consumer receiving streaming [`OtapMetricRecords`] chunks and per-scrape completion reports.
///
/// Intentionally omits `Send` bounds so single-threaded `!Send` runtimes (such as Tokio
/// `LocalSet` workers) can pass local channels or `Rc`/`RefCell` state directly.
///
/// # Transactional scrape atomicity and pool permits
///
/// Because [`ArrowScrapeSink::on_batch`] streams decoded chunks incrementally to bound scratch
/// memory, a multi-chunk scrape can fail on a later chunk (for example, on malformed trailing
/// syntax or a missing OpenMetrics `# EOF`). Chunks delivered to `on_batch` are therefore
/// tentative until [`ArrowScrapeSink::on_scrape_complete`] observes `report.up == true`. Sinks
/// that require transactional Prometheus scrape semantics (matching Go `app.Commit()` /
/// `app.Rollback()`) should stage per-scrape batches and discard the `report.batches_emitted`
/// tentative chunks whenever `report.up == false`.
#[cfg(feature = "arrow")]
pub trait ArrowScrapeSink {
    /// Receives one bounded [`OtapMetricRecords`] chunk decoded from `target`.
    ///
    /// On single-chunk scrapes (and on the final chunk of multi-chunk scrapes), both the
    /// [`crate::scrape::PooledBodyBuffer`] and [`crate::scrape::PooledDecoder`] permits are
    /// released back to their pools before `on_batch` is awaited. On intermediate chunks of a
    /// multi-chunk scrape, awaiting inside `on_batch` holds both permits until decoding resumes;
    /// size `max_buffered_bodies` and `max_decoders` via
    /// [`SchedulingMode::concurrent_with_pools`] when sinks apply async backpressure on large
    /// multi-chunk targets. Returning [`ControlFlow::Break`] aborts the active scrape, drops
    /// pooled buffers back into their freelists, and stops the manager loop.
    fn on_batch(
        &self,
        target: &ScrapeTarget,
        scrape_timestamp_ms: i64,
        records: OtapMetricRecords,
    ) -> impl Future<Output = ControlFlow<()>>;

    /// Receives final outcome telemetry for `target` after all chunks have been delivered and both
    /// the body buffer and [`prometheus_expfmt::arrow::ArrowDecoder`] have been returned to their
    /// pools.
    ///
    /// When `report.up == false` and `report.batches_emitted > 0`, decoding failed after earlier
    /// chunks were streamed to [`ArrowScrapeSink::on_batch`]; transactional sinks must roll back
    /// those tentative batches.
    fn on_scrape_complete(
        &self,
        target: &ScrapeTarget,
        report: ScrapeReport,
    ) -> impl Future<Output = ControlFlow<()>> {
        let _ = (target, report);
        async { ControlFlow::Continue(()) }
    }
}

/// Target scrape coordinator supporting both [`SchedulingMode::Sequential`] and bounded
/// [`SchedulingMode::Concurrent`] execution on `Send` or `!Send` Tokio runtimes.
#[derive(Debug)]
pub struct ScrapeManager<F = ReqwestFetcher> {
    config: ScrapeConfig,
    fetcher: F,
    body_pool: BodyBufferPool,
    #[cfg(feature = "arrow")]
    decoder_pool: DecoderPool,
    counters: AtomicCounters,
}

impl ScrapeManager<ReqwestFetcher> {
    /// Constructs a [`ScrapeManager`] backed by a default [`ReqwestFetcher`].
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError`] if `config` fails validation or the HTTP client cannot be built.
    pub fn with_reqwest(config: ScrapeConfig) -> Result<Self, ScrapeError> {
        let fetcher = ReqwestFetcher::new(&config)?;
        Self::new(config, fetcher)
    }

    /// Creates an unbounded control channel pair `(`[`ScrapeControl`]`, Receiver)` for live target
    /// updates and graceful shutdown.
    #[must_use]
    pub fn control_channel() -> (ScrapeControl, mpsc::UnboundedReceiver<ScrapeCommand>) {
        ScrapeControl::channel()
    }
}

impl<F> ScrapeManager<F> {
    /// Constructs a [`ScrapeManager`] with a caller-supplied [`TargetFetcher`].
    ///
    /// # Errors
    ///
    /// Returns [`ScrapeError::InvalidConfig`] if `config` fails validation.
    pub fn new(config: ScrapeConfig, fetcher: F) -> Result<Self, ScrapeError> {
        config.validate()?;
        let body_pool = BodyBufferPool::new(
            config.scheduling.max_buffered_bodies(),
            config.max_retained_body_bytes,
        );
        #[cfg(feature = "arrow")]
        let decoder_pool = DecoderPool::new(
            config.scheduling.max_decoders(),
            config.max_retained_decoder_bytes,
        );
        Ok(Self {
            config,
            fetcher,
            body_pool,
            #[cfg(feature = "arrow")]
            decoder_pool,
            counters: AtomicCounters::default(),
        })
    }

    /// Returns the active [`ScrapeConfig`].
    #[must_use]
    pub const fn config(&self) -> &ScrapeConfig {
        &self.config
    }

    /// Returns a snapshot of cumulative scrape counters and scratch pool memory usage.
    #[must_use]
    pub fn stats(&self) -> ManagerStats {
        ManagerStats {
            scrapes_started: self.counters.started.load(Ordering::Relaxed),
            scrapes_succeeded: self.counters.succeeded.load(Ordering::Relaxed),
            scrapes_failed: self.counters.failed.load(Ordering::Relaxed),
            scrapes_overrun: self.counters.overrun.load(Ordering::Relaxed),
            data_points_decoded: self.counters.points_decoded.load(Ordering::Relaxed),
            peak_buffered_bodies: self.body_pool.peak_leases(),
            total_body_buffers_created: self.body_pool.total_buffers_created(),
            retained_body_buffer_bytes: self.body_pool.retained_memory_bytes(),
            #[cfg(feature = "arrow")]
            peak_active_decoders: self.decoder_pool.peak_leases(),
            #[cfg(feature = "arrow")]
            total_decoders_created: self.decoder_pool.total_decoders_created(),
            #[cfg(feature = "arrow")]
            retained_decoder_bytes: self.decoder_pool.retained_memory_bytes(),
        }
    }
}

impl<F: TargetFetcher> ScrapeManager<F> {
    /// Executes a single HTTP fetch of `target` using the bounded [`BodyBufferPool`].
    pub async fn scrape_once_raw(
        &self,
        target: &ScrapeTarget,
    ) -> Result<FetchedScrape, ScrapeError> {
        self.counters.started.fetch_add(1, Ordering::Relaxed);
        match self.fetcher.fetch(target, &self.body_pool).await {
            Ok(fetched) => {
                self.counters.succeeded.fetch_add(1, Ordering::Relaxed);
                Ok(fetched)
            }
            Err(err) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    /// Executes a single immediate raw scrape pass across `targets` respecting the concurrency and
    /// pool limits in [`ScrapeConfig::scheduling`] without sleeping between interval ticks.
    pub async fn run_once_raw<S: RawScrapeSink>(
        &self,
        targets: &[ScrapeTarget],
        sink: &S,
    ) -> ControlFlow<()> {
        self.run_once_with(targets, |target| async move {
            let res = self.scrape_once_raw(target).await;
            sink.on_raw_scrape(target, res).await
        })
        .await
    }

    /// Runs continuous raw target scraping according to [`ScrapeConfig::scheduling`] until
    /// [`ScrapeCommand::Shutdown`], control channel closure, or [`ControlFlow::Break`] from `sink`.
    pub async fn run_raw<S: RawScrapeSink>(
        &self,
        initial_targets: Vec<ScrapeTarget>,
        ctrl_rx: mpsc::UnboundedReceiver<ScrapeCommand>,
        sink: &S,
    ) {
        self.run_loop(initial_targets, ctrl_rx, |target| async move {
            let res = self.scrape_once_raw(&target).await;
            sink.on_raw_scrape(&target, res).await
        })
        .await;
    }

    /// Fetches `target` once, streams cooperatives chunks through a pooled [`ArrowDecoder`], and
    /// emits a final [`ScrapeReport`] to `sink`.
    #[cfg(feature = "arrow")]
    pub async fn scrape_once_arrow<S: ArrowScrapeSink>(
        &self,
        target: &ScrapeTarget,
        sink: &S,
    ) -> ControlFlow<(), ScrapeReport> {
        let started = StdInstant::now();
        self.counters.started.fetch_add(1, Ordering::Relaxed);

        let fetched = match self.fetcher.fetch(target, &self.body_pool).await {
            Ok(ok) => ok,
            Err(err) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                let report = ScrapeReport {
                    up: false,
                    scrape_timestamp_ms: current_timestamp_ms(),
                    duration: started.elapsed(),
                    wire_bytes: 0,
                    uncompressed_bytes: 0,
                    data_points_decoded: 0,
                    batches_emitted: 0,
                    error: Some(err.to_string()),
                };
                if sink
                    .on_scrape_complete(target, report.clone())
                    .await
                    .is_break()
                {
                    return ControlFlow::Break(());
                }
                return ControlFlow::Continue(report);
            }
        };

        let wire_bytes = fetched.wire_bytes;
        let uncompressed_bytes = fetched.uncompressed_bytes();
        let scrape_timestamp_ms = fetched.scrape_timestamp_ms;

        let decode_outcome = self
            .decode_fetched_cooperatively(target, fetched, sink)
            .await;

        let report = match decode_outcome {
            ControlFlow::Break(()) => return ControlFlow::Break(()),
            ControlFlow::Continue((points, batches, Ok(()))) => {
                self.counters.succeeded.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .points_decoded
                    .fetch_add(points, Ordering::Relaxed);
                ScrapeReport {
                    up: true,
                    scrape_timestamp_ms,
                    duration: started.elapsed(),
                    wire_bytes,
                    uncompressed_bytes,
                    data_points_decoded: points,
                    batches_emitted: batches,
                    error: None,
                }
            }
            ControlFlow::Continue((points, batches, Err(err))) => {
                self.counters.failed.fetch_add(1, Ordering::Relaxed);
                ScrapeReport {
                    up: false,
                    scrape_timestamp_ms,
                    duration: started.elapsed(),
                    wire_bytes,
                    uncompressed_bytes,
                    data_points_decoded: points,
                    batches_emitted: batches,
                    error: Some(err.to_string()),
                }
            }
        };

        if sink
            .on_scrape_complete(target, report.clone())
            .await
            .is_break()
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(report)
    }

    /// Executes a single immediate scrape pass across `targets` respecting the concurrency and
    /// pool limits in [`ScrapeConfig::scheduling`] without sleeping between interval ticks.
    #[cfg(feature = "arrow")]
    pub async fn run_once_arrow<S: ArrowScrapeSink>(
        &self,
        targets: &[ScrapeTarget],
        sink: &S,
    ) -> ControlFlow<()> {
        self.run_once_with(targets, |target| async move {
            match self.scrape_once_arrow(target, sink).await {
                ControlFlow::Continue(_) => ControlFlow::Continue(()),
                ControlFlow::Break(()) => ControlFlow::Break(()),
            }
        })
        .await
    }

    /// Runs continuous Arrow target scraping according to [`ScrapeConfig::scheduling`] until
    /// [`ScrapeCommand::Shutdown`], control channel closure, or [`ControlFlow::Break`] from `sink`.
    #[cfg(feature = "arrow")]
    pub async fn run_arrow<S: ArrowScrapeSink>(
        &self,
        initial_targets: Vec<ScrapeTarget>,
        ctrl_rx: mpsc::UnboundedReceiver<ScrapeCommand>,
        sink: &S,
    ) {
        self.run_loop(initial_targets, ctrl_rx, |target| async move {
            match self.scrape_once_arrow(&target, sink).await {
                ControlFlow::Continue(_) => ControlFlow::Continue(()),
                ControlFlow::Break(()) => ControlFlow::Break(()),
            }
        })
        .await;
    }

    #[cfg(feature = "arrow")]
    async fn decode_fetched_cooperatively<S: ArrowScrapeSink>(
        &self,
        target: &ScrapeTarget,
        fetched: FetchedScrape,
        sink: &S,
    ) -> ControlFlow<(), (u64, usize, Result<(), ScrapeError>)> {
        struct ActiveDecodeGuard {
            decoder: Option<crate::scrape::PooledDecoder>,
            cursor: DecodeCursor,
        }

        impl ActiveDecodeGuard {
            fn release(&mut self) {
                if let Some(mut dec) = self.decoder.take() {
                    dec.finish_decode(&mut self.cursor);
                }
            }
        }

        impl Drop for ActiveDecodeGuard {
            fn drop(&mut self) {
                self.release();
            }
        }

        let scrape_timestamp_ms = fetched.scrape_timestamp_ms;
        let format = fetched.format;
        let mut body_lease = Some(fetched.body);
        let mut decoder = self.decoder_pool.acquire().await;

        let chunk_limit = if self.config.max_data_points_per_batch == 0 {
            usize::MAX
        } else {
            self.config.max_data_points_per_batch
        };

        // TODO(bwplotka): Add and wire `ScrapeConfig::honor_timestamps` once
        // `DecodeOptions::with_honor_timestamps` lands in
        // https://github.com/prometheus/scrape.rs/issues/33.
        let decode_opts = self
            .config
            .decode_options
            .with_timestamp_ms(scrape_timestamp_ms)
            .with_max_data_points_per_batch(chunk_limit);

        let cursor = match decoder.start_decode_stream(&format, &decode_opts) {
            Ok(c) => c,
            Err(err) => {
                drop(decoder);
                drop(body_lease);
                return ControlFlow::Continue((0, 0, Err(ScrapeError::Decode(err))));
            }
        };
        let mut guard = ActiveDecodeGuard {
            decoder: Some(decoder),
            cursor,
        };

        let base_budget = self.config.decode_budget;
        let max_entries = base_budget.max_entries.max(1);
        let max_bytes = base_budget.max_bytes.max(1);
        let max_duration = base_budget.max_duration;

        let mut decoded_points = 0_u64;
        let mut batches_emitted = 0_usize;
        let mut slice_start_pos = 0_usize;
        let mut slice_entries = 0_usize;
        let mut slice_started = StdInstant::now();

        loop {
            if guard.cursor.is_done() {
                break;
            }

            let step_budget = if slice_entries == 0 && guard.cursor.pos() == slice_start_pos {
                base_budget
            } else {
                let remaining_duration = if max_duration.is_zero() {
                    Duration::ZERO
                } else {
                    max_duration
                        .saturating_sub(slice_started.elapsed())
                        .max(Duration::from_nanos(1))
                };
                DecodeBudget::new(
                    max_entries.saturating_sub(slice_entries).max(1),
                    max_bytes
                        .saturating_sub(guard.cursor.pos().saturating_sub(slice_start_pos))
                        .max(1),
                    remaining_duration,
                )
            };

            let step = {
                let body = body_lease
                    .as_ref()
                    .expect("body_lease stays Some until cursor is_done")
                    .as_slice();
                let dec = guard
                    .decoder
                    .as_mut()
                    .expect("decoder stays Some until cursor is_done");
                dec.step_decode(&mut guard.cursor, body, step_budget)
            };

            let records = match step {
                Ok(DecodeStep::Pending) => {
                    tokio::task::yield_now().await;
                    slice_start_pos = guard.cursor.pos();
                    slice_entries = 0;
                    slice_started = StdInstant::now();
                    continue;
                }
                Ok(DecodeStep::Batch(records)) => records,
                Ok(DecodeStep::Done) => {
                    guard.release();
                    let _ = body_lease.take();
                    break;
                }
                Err(err) => {
                    guard.release();
                    let _ = body_lease.take();
                    return ControlFlow::Continue((
                        decoded_points,
                        batches_emitted,
                        Err(ScrapeError::Decode(err)),
                    ));
                }
            };

            // Release both pooled permits before awaiting `on_batch` once the final chunk of the
            // scrape has been materialized so downstream sink awaits do not block peer scrapes.
            if guard.cursor.is_done() {
                guard.release();
                let _ = body_lease.take();
            }

            let pts = records.num_data_points();
            decoded_points = decoded_points.saturating_add(pts as u64);
            slice_entries = slice_entries.saturating_add(pts.max(1));

            if !records.is_empty() {
                batches_emitted += 1;
                if sink
                    .on_batch(target, scrape_timestamp_ms, records)
                    .await
                    .is_break()
                {
                    return ControlFlow::Break(());
                }
            }

            if let Some(body) = body_lease.as_ref()
                && guard.cursor.pos() < body.len()
                && (slice_entries >= max_entries
                    || guard.cursor.pos().saturating_sub(slice_start_pos) >= max_bytes
                    || slice_started.elapsed() >= max_duration)
            {
                tokio::task::yield_now().await;
                slice_start_pos = guard.cursor.pos();
                slice_entries = 0;
                slice_started = StdInstant::now();
            }
        }

        guard.release();
        drop(body_lease);
        ControlFlow::Continue((decoded_points, batches_emitted, Ok(())))
    }

    async fn run_once_with<'a, Exec, Fut>(
        &'a self,
        targets: &'a [ScrapeTarget],
        exec_one: Exec,
    ) -> ControlFlow<()>
    where
        Exec: Fn(&'a ScrapeTarget) -> Fut,
        Fut: Future<Output = ControlFlow<()>>,
    {
        match self.config.scheduling {
            SchedulingMode::Sequential { .. } => {
                for target in targets {
                    if exec_one(target).await.is_break() {
                        return ControlFlow::Break(());
                    }
                    tokio::task::yield_now().await;
                }
                ControlFlow::Continue(())
            }
            SchedulingMode::Concurrent { max_in_flight, .. } => {
                let cap = max_in_flight.get();
                let mut iter = targets.iter();
                let mut active = FuturesUnordered::new();

                while active.len() < cap
                    && let Some(target) = iter.next()
                {
                    active.push(exec_one(target));
                }

                while let Some(res) = active.next().await {
                    if res.is_break() {
                        return ControlFlow::Break(());
                    }
                    if let Some(target) = iter.next() {
                        active.push(exec_one(target));
                    }
                }
                ControlFlow::Continue(())
            }
        }
    }

    async fn run_loop<Exec, Fut>(
        &self,
        initial_targets: Vec<ScrapeTarget>,
        ctrl_rx: mpsc::UnboundedReceiver<ScrapeCommand>,
        exec_one: Exec,
    ) where
        Exec: Fn(Arc<ScrapeTarget>) -> Fut,
        Fut: Future<Output = ControlFlow<()>>,
    {
        match self.config.scheduling {
            SchedulingMode::Sequential {
                schedule: SequentialSchedule::CycleTick,
            } => {
                self.run_sequential_cycle_tick(initial_targets, ctrl_rx, exec_one)
                    .await;
            }
            SchedulingMode::Sequential {
                schedule: SequentialSchedule::Jittered,
            } => {
                self.run_jittered(initial_targets, ctrl_rx, 1, exec_one)
                    .await;
            }
            SchedulingMode::Concurrent { max_in_flight, .. } => {
                self.run_jittered(initial_targets, ctrl_rx, max_in_flight.get(), exec_one)
                    .await;
            }
        }
    }

    async fn run_sequential_cycle_tick<Exec, Fut>(
        &self,
        initial_targets: Vec<ScrapeTarget>,
        mut ctrl_rx: mpsc::UnboundedReceiver<ScrapeCommand>,
        exec_one: Exec,
    ) where
        Exec: Fn(Arc<ScrapeTarget>) -> Fut,
        Fut: Future<Output = ControlFlow<()>>,
    {
        let mut targets: Vec<Arc<ScrapeTarget>> =
            initial_targets.into_iter().map(Arc::new).collect();
        let interval = self.config.scrape_interval;
        let start_now = Instant::now();
        let mut next_due = start_now
            .checked_add(self.config.initial_delay)
            .unwrap_or(start_now);

        loop {
            tokio::select! {
                biased;

                cmd = ctrl_rx.recv() => {
                    match cmd {
                        Some(ScrapeCommand::UpdateTargets(new_targets)) => {
                            targets = new_targets.into_iter().map(Arc::new).collect();
                        }
                        Some(ScrapeCommand::Shutdown) | None => return,
                    }
                }

                () = sleep_until(next_due) => {
                    let now = Instant::now();
                    let (advanced_due, missed_ticks) =
                        advance_grid_deadline(next_due, now, interval);
                    if missed_ticks > 1 {
                        self.counters
                            .overrun
                            .fetch_add(missed_ticks - 1, Ordering::Relaxed);
                    }
                    next_due = advanced_due;

                    let snapshot = targets.clone();
                    for target in snapshot {
                        let fut = exec_one(target);
                        tokio::pin!(fut);
                        loop {
                            tokio::select! {
                                biased;

                                cmd = ctrl_rx.recv() => {
                                    match cmd {
                                        Some(ScrapeCommand::UpdateTargets(new_targets)) => {
                                            // Stage the updated target list for the next cycle
                                            // tick without cancelling the in-flight scrape or
                                            // skipping remaining targets in the current pass.
                                            targets = new_targets.into_iter().map(Arc::new).collect();
                                        }
                                        Some(ScrapeCommand::Shutdown) | None => return,
                                    }
                                }

                                out = &mut fut => {
                                    if out.is_break() {
                                        return;
                                    }
                                    break;
                                }
                            }
                        }
                        tokio::task::yield_now().await;
                    }

                    // If the sequential pass ran past one or more scheduled grid ticks, skip those
                    // missed ticks and advance to the next future grid point (matching Go time.Ticker).
                    let finish_now = Instant::now();
                    if finish_now >= next_due {
                        let (skipped_due, skipped_ticks) =
                            advance_grid_deadline(next_due, finish_now, interval);
                        self.counters
                            .overrun
                            .fetch_add(skipped_ticks, Ordering::Relaxed);
                        next_due = skipped_due;
                    }
                }
            }
        }
    }

    async fn run_jittered<Exec, Fut>(
        &self,
        initial_targets: Vec<ScrapeTarget>,
        mut ctrl_rx: mpsc::UnboundedReceiver<ScrapeCommand>,
        max_in_flight: usize,
        exec_one: Exec,
    ) where
        Exec: Fn(Arc<ScrapeTarget>) -> Fut,
        Fut: Future<Output = ControlFlow<()>>,
    {
        let start_now = Instant::now();
        let start_base = start_now
            .checked_add(self.config.initial_delay)
            .unwrap_or(start_now);
        let mut schedule =
            TargetSchedule::new(self.config.scrape_interval, self.config.jitter_seed);
        schedule.sync_targets(initial_targets, start_base);

        let mut in_flight = FuturesUnordered::new();

        loop {
            if in_flight.len() < max_in_flight {
                let now = Instant::now();
                while in_flight.len() < max_in_flight
                    && let Some(due) = schedule.pop_due(now)
                {
                    let fut = exec_one(due.target);
                    in_flight.push(async move {
                        let out = fut.await;
                        (due.slot_id, due.generation, out)
                    });
                }
                let overruns = schedule.take_overruns();
                if overruns > 0 {
                    self.counters.overrun.fetch_add(overruns, Ordering::Relaxed);
                }
            }

            let next_wake = if in_flight.len() < max_in_flight && !schedule.is_empty() {
                schedule.peek_next_due()
            } else {
                None
            };

            tokio::select! {
                biased;

                cmd = ctrl_rx.recv() => {
                    match cmd {
                        Some(ScrapeCommand::UpdateTargets(new_targets)) => {
                            schedule.sync_targets(new_targets, Instant::now().max(start_base));
                        }
                        Some(ScrapeCommand::Shutdown) | None => return,
                    }
                }

                Some((slot_id, generation, out)) = in_flight.next(), if !in_flight.is_empty() => {
                    schedule.complete(slot_id, generation, Instant::now());
                    let overruns = schedule.take_overruns();
                    if overruns > 0 {
                        self.counters.overrun.fetch_add(overruns, Ordering::Relaxed);
                    }
                    if out.is_break() {
                        return;
                    }
                }

                () = async {
                    match next_wake {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                }, if next_wake.is_some() => {}
            }
        }
    }
}
