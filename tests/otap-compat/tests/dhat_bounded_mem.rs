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

//! Bounded-memory verification for `!Send` single-threaded `tokio::task::LocalSet` scrape loops
//! using both `retained_memory_bytes()` and `dhat` live heap tracking.

use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::rc::Rc;

use otel_arrow_dfe_pdata::otap::{Metrics, OtapArrowRecords, OtapBatchStore};
use otel_arrow_dfe_pdata::proto::opentelemetry::arrow::v1::ArrowPayloadType;
use prometheus_expfmt::arrow::{
    ArrowDecoder, DecodeBudget, DecodeOptions, DecodeStep, OtapMetricRecords, StalenessTracker,
};
use prometheus_expfmt::format::Format;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn to_otap_arrow_records(records: &OtapMetricRecords) -> OtapArrowRecords {
    let mut store = Metrics::new();
    for (payload_type, batch) in records.iter() {
        let wire_type = ArrowPayloadType::try_from(payload_type.as_i32())
            .expect("MetricPayloadType matches ArrowPayloadType wire discriminant");
        store
            .set(wire_type, batch.clone())
            .unwrap_or_else(|err| panic!("OTAP schema rejected {payload_type:?}: {err}"));
    }
    OtapArrowRecords::Metrics(store)
}

#[test]
fn local_set_non_send_repeated_scrapes_keep_bounded_memory() {
    let _profiler = dhat::Profiler::builder().testing().build();

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let full_237: Rc<[u8]> = fs::read(root.join("alltypes.237mfs.prom.txt"))
        .unwrap()
        .into();
    let om_bench: Rc<[u8]> = fs::read(root.join("alltypes.bench.om.txt")).unwrap().into();

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("single-threaded runtime builds");
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async move {
        // Wrap `ArrowDecoder` in `!Send` `Rc<RefCell<_>>` to mirror thread-per-core OTAP receivers.
        let shared_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let opts = DecodeOptions::new().with_timestamp_ms(1_700_000_000_000);
        let full_237_clone = Rc::clone(&full_237);

        let handle = tokio::task::spawn_local(async move {
            let mut warmup_decoder_mem = 0usize;
            let mut warmup_batch_mem = 0usize;
            let mut warmup_live_heap = 0usize;

            for i in 0..32 {
                let records = shared_decoder
                    .borrow_mut()
                    .decode(&full_237_clone, &Format::TEXT, &opts)
                    .expect("scrape succeeds");
                let otap = to_otap_arrow_records(&records);
                let dec_mem = shared_decoder.borrow().retained_memory_bytes();
                let batch_mem = otap.retained_memory_bytes();
                drop(otap);
                drop(records);

                let live_heap = dhat::HeapStats::get().curr_bytes;

                // Record baseline at `i == 1` so both `ArrowDecoder` scratch buffers and Tokio's
                // `LocalSet` `yield_now` queue have completed their one-time initial allocation.
                if i == 1 {
                    warmup_decoder_mem = dec_mem;
                    warmup_batch_mem = batch_mem;
                    warmup_live_heap = live_heap;
                    assert!(warmup_decoder_mem > 0);
                    assert!(warmup_batch_mem > 0);
                    assert!(warmup_live_heap > 0);
                } else if i > 1 {
                    assert_eq!(
                        dec_mem, warmup_decoder_mem,
                        "decoder scratch memory grew after warmup at iteration {i}"
                    );
                    assert_eq!(
                        batch_mem, warmup_batch_mem,
                        "output OTAP batch memory changed across identical scrapes at iteration {i}"
                    );
                    assert_eq!(
                        live_heap, warmup_live_heap,
                        "live heap bytes leaked after dropping scrape batch at iteration {i}"
                    );
                }
                tokio::task::yield_now().await;
            }
            warmup_decoder_mem
        });

        let full_decoder_mem = handle.await.expect("local task succeeds");

        // Verify `decode_stream` caps retained decoder scratch memory to a single 128-point chunk
        // and keeps both decoder capacity and live heap constant across repeated scrapes.
        let stream_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let stream_opts = opts.with_max_data_points_per_batch(128);
        let full_237_coop = Rc::clone(&full_237);
        let full_237_stale = Rc::clone(&full_237);
        let stream_handle = tokio::task::spawn_local(async move {
            let mut warmup_stream_dec_mem = 0usize;
            let mut warmup_stream_live_heap = 0usize;

            for i in 0..32 {
                {
                    let mut dec = stream_decoder.borrow_mut();
                    for chunk_res in dec.decode_stream(&full_237, &Format::TEXT, &stream_opts) {
                        let chunk = chunk_res.expect("stream chunk succeeds");
                        let otap = to_otap_arrow_records(&chunk);
                        drop(otap);
                        drop(chunk);
                    }
                }

                let dec_mem = stream_decoder.borrow().retained_memory_bytes();
                let live_heap = dhat::HeapStats::get().curr_bytes;

                if i == 1 {
                    warmup_stream_dec_mem = dec_mem;
                    warmup_stream_live_heap = live_heap;
                    assert!(warmup_stream_dec_mem > 0);
                    assert!(
                        warmup_stream_dec_mem * 3 < full_decoder_mem * 2,
                        "expected 128-row streaming decoder ({warmup_stream_dec_mem} B) to retain \
                         significantly less than full-scrape decoder ({full_decoder_mem} B)"
                    );
                } else if i > 1 {
                    assert_eq!(
                        dec_mem, warmup_stream_dec_mem,
                        "streaming decoder scratch memory grew after warmup at iteration {i}"
                    );
                    assert_eq!(
                        live_heap, warmup_stream_live_heap,
                        "live heap bytes leaked after streaming scrape at iteration {i}"
                    );
                }
                tokio::task::yield_now().await;
            }
            warmup_stream_dec_mem
        });

        let warmup_stream_dec_mem = stream_handle.await.expect("streaming local task succeeds");

        // Verify cooperative incremental streaming (`start_decode_stream` + `step_decode` across
        // `Rc<RefCell<ArrowDecoder>>` without holding a `RefMut` across `.await`, plus owned
        // `next_cooperative`) keeps retained decoder scratch memory and live heap strictly
        // constant across repeated scrapes.
        let coop_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let mut owned_coop_decoder = ArrowDecoder::new();
        let coop_budget = DecodeBudget::default().with_max_entries(64);
        let coop_handle = tokio::task::spawn_local(async move {
            let mut warmup_coop_dec_mem = 0usize;
            let mut warmup_owned_dec_mem = 0usize;
            let mut warmup_coop_live_heap = 0usize;

            for i in 0..32 {
                let mut cursor = coop_decoder
                    .borrow_mut()
                    .start_decode_stream(&Format::TEXT, &stream_opts)
                    .expect("cursor starts");
                loop {
                    let step = coop_decoder
                        .borrow_mut()
                        .step_decode(&mut cursor, &full_237_coop, coop_budget)
                        .expect("cooperative step succeeds");
                    match step {
                        DecodeStep::Pending => tokio::task::yield_now().await,
                        DecodeStep::Batch(chunk) => {
                            let otap = to_otap_arrow_records(&chunk);
                            drop(otap);
                            drop(chunk);
                        }
                        DecodeStep::Done => break,
                    }
                }

                {
                    let mut stream = owned_coop_decoder.decode_stream(
                        &full_237_coop,
                        &Format::TEXT,
                        &stream_opts,
                    );
                    while let Some(chunk_res) = stream
                        .next_cooperative(coop_budget, tokio::task::yield_now)
                        .await
                    {
                        let chunk = chunk_res.expect("next_cooperative chunk succeeds");
                        let otap = to_otap_arrow_records(&chunk);
                        drop(otap);
                        drop(chunk);
                    }
                }

                let dec_mem = coop_decoder.borrow().retained_memory_bytes();
                let owned_dec_mem = owned_coop_decoder.retained_memory_bytes();
                let live_heap = dhat::HeapStats::get().curr_bytes;

                if i == 1 {
                    warmup_coop_dec_mem = dec_mem;
                    warmup_owned_dec_mem = owned_dec_mem;
                    warmup_coop_live_heap = live_heap;
                    assert_eq!(warmup_coop_dec_mem, warmup_stream_dec_mem);
                    assert_eq!(warmup_owned_dec_mem, warmup_stream_dec_mem);
                } else if i > 1 {
                    assert_eq!(
                        dec_mem, warmup_coop_dec_mem,
                        "cooperative streaming decoder scratch memory grew at iteration {i}"
                    );
                    assert_eq!(
                        owned_dec_mem, warmup_owned_dec_mem,
                        "next_cooperative decoder scratch memory grew at iteration {i}"
                    );
                    assert_eq!(
                        live_heap, warmup_coop_live_heap,
                        "live heap bytes leaked after cooperative streaming scrape at iteration {i}"
                    );
                }
                tokio::task::yield_now().await;
            }
        });

        coop_handle
            .await
            .expect("cooperative streaming local task succeeds");

        // Verify stateless OpenMetrics 1.0 `decode` (without `StalenessTracker`) keeps retained
        // scratch memory and live heap strictly constant after warmup.
        let om_bench_stale = Rc::clone(&om_bench);
        let om_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let om_opts = opts;
        let om_handle = tokio::task::spawn_local(async move {
            let mut warmup_om_dec_mem = 0usize;
            let mut warmup_om_live_heap = 0usize;

            for i in 0..32 {
                let records = om_decoder
                    .borrow_mut()
                    .decode(&om_bench, &Format::OPEN_METRICS_1_0_0, &om_opts)
                    .expect("OpenMetrics stateless decode succeeds");
                let otap = to_otap_arrow_records(&records);
                let dec_mem = om_decoder.borrow().retained_memory_bytes();
                drop(otap);
                drop(records);

                let live_heap = dhat::HeapStats::get().curr_bytes;
                if i == 1 {
                    warmup_om_dec_mem = dec_mem;
                    warmup_om_live_heap = live_heap;
                    assert!(warmup_om_dec_mem > 0);
                } else if i > 1 {
                    assert_eq!(dec_mem, warmup_om_dec_mem);
                    assert_eq!(live_heap, warmup_om_live_heap);
                }
                tokio::task::yield_now().await;
            }
            warmup_om_dec_mem
        });

        let stateless_om_dec_mem = om_handle
            .await
            .expect("OpenMetrics stateless task succeeds");

        // Verify optional `StalenessTracker` starts with zero heap allocation, keeps steady-state
        // OpenMetrics scrapes strictly zero-allocation, and stays bounded across alternating
        // full/subset scrapes (exercising `SparseFlagsCol`, stale series emission, and compaction)
        // in both `decode_with_staleness` and `decode_stream_with_staleness`.
        assert_eq!(StalenessTracker::new().retained_memory_bytes(), 0);
        let stale_om_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let stale_om_tracker = Rc::new(RefCell::new(StalenessTracker::new()));
        let stale_om_opts = opts.with_track_timestamps_staleness(true);
        let stale_om_handle = tokio::task::spawn_local(async move {
            let mut warmup_dec_mem = 0usize;
            let mut warmup_tracker_mem = 0usize;
            let mut warmup_live_heap = 0usize;

            for i in 0..16 {
                let records = stale_om_decoder
                    .borrow_mut()
                    .decode_with_staleness(
                        &om_bench_stale,
                        &Format::OPEN_METRICS_1_0_0,
                        &stale_om_opts,
                        &mut stale_om_tracker.borrow_mut(),
                    )
                    .expect("OpenMetrics tracked decode succeeds");
                let otap = to_otap_arrow_records(&records);
                let dec_mem = stale_om_decoder.borrow().retained_memory_bytes();
                let tracker_mem = stale_om_tracker.borrow().retained_memory_bytes();
                drop(otap);
                drop(records);

                let live_heap = dhat::HeapStats::get().curr_bytes;
                if i == 1 {
                    warmup_dec_mem = dec_mem;
                    warmup_tracker_mem = tracker_mem;
                    warmup_live_heap = live_heap;
                    assert!(warmup_tracker_mem > 0);
                    assert_eq!(warmup_dec_mem, stateless_om_dec_mem);
                } else if i > 1 {
                    assert_eq!(dec_mem, warmup_dec_mem);
                    assert_eq!(tracker_mem, warmup_tracker_mem);
                    assert_eq!(live_heap, warmup_live_heap);
                }
                tokio::task::yield_now().await;
            }
        });
        stale_om_handle
            .await
            .expect("OpenMetrics tracked local task succeeds");

        let churn_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let churn_stream_decoder = Rc::new(RefCell::new(ArrowDecoder::new()));
        let churn_tracker = Rc::new(RefCell::new(StalenessTracker::new()));
        let churn_stream_tracker = Rc::new(RefCell::new(StalenessTracker::new()));
        let subset_prom: &[u8] = b"# TYPE go_gc_gogc_percent gauge\ngo_gc_gogc_percent 75\n";
        let churn_handle = tokio::task::spawn_local(async move {
            let mut max_dec_mem = 0usize;
            let mut max_stream_dec_mem = 0usize;
            let mut max_tracker_mem = 0usize;
            let mut max_live_heap = 0usize;

            for cycle in 0..16 {
                let step_opts = opts.with_timestamp_ms(1_700_000_000_000 + (cycle * 1_000));
                let step_stream_opts = step_opts.with_max_data_points_per_batch(128);
                let payload: &[u8] = if cycle % 2 == 0 {
                    &full_237_stale
                } else {
                    subset_prom
                };

                let records = churn_decoder
                    .borrow_mut()
                    .decode_with_staleness(
                        payload,
                        &Format::TEXT,
                        &step_opts,
                        &mut churn_tracker.borrow_mut(),
                    )
                    .expect("alternating decode_with_staleness succeeds");
                let otap = to_otap_arrow_records(&records);
                drop(otap);
                drop(records);

                {
                    let mut dec = churn_stream_decoder.borrow_mut();
                    let mut tr = churn_stream_tracker.borrow_mut();
                    for chunk_res in dec.decode_stream_with_staleness(
                        payload,
                        &Format::TEXT,
                        &step_stream_opts,
                        &mut tr,
                    ) {
                        let chunk = chunk_res.expect("alternating stream chunk succeeds");
                        let otap = to_otap_arrow_records(&chunk);
                        drop(otap);
                        drop(chunk);
                    }
                }

                let dec_mem = churn_decoder.borrow().retained_memory_bytes();
                let stream_dec_mem = churn_stream_decoder.borrow().retained_memory_bytes();
                let tracker_mem = churn_tracker.borrow().retained_memory_bytes();
                let live_heap = dhat::HeapStats::get().curr_bytes;

                if cycle == 2 {
                    max_dec_mem = dec_mem;
                    max_stream_dec_mem = stream_dec_mem;
                    max_tracker_mem = tracker_mem;
                    max_live_heap = live_heap;
                } else if cycle > 2 && cycle % 2 == 0 {
                    assert_eq!(
                        dec_mem, max_dec_mem,
                        "alternating staleness decoder scratch grew at cycle {cycle}"
                    );
                    assert_eq!(
                        stream_dec_mem, max_stream_dec_mem,
                        "alternating streaming staleness decoder scratch grew at cycle {cycle}"
                    );
                    assert_eq!(
                        tracker_mem, max_tracker_mem,
                        "compacted StalenessTracker capacity grew across cycles at {cycle}"
                    );
                    assert_eq!(
                        live_heap, max_live_heap,
                        "live heap bytes grew across alternating staleness cycles at {cycle}"
                    );
                }
                tokio::task::yield_now().await;
            }
        });
        churn_handle
            .await
            .expect("alternating staleness churn task succeeds");
    });
}
