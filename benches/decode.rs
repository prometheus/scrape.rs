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

//! Throughput and allocation benchmarks for `expfmt::arrow::ArrowDecoder` over the upstream
//! Prometheus `model/textparse` fixture corpus.
//!
//! Recommended CLI invocation:
//! ```sh
//! cargo bench --bench decode -- -bench '^BenchmarkDecode' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::hint::black_box;
use std::path::Path;

use benchfmt::{CountingAlloc, Suite};
use expfmt::arrow::{ArrowDecoder, DecodeOptions};
use expfmt::format::Format;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

/// Filters `alltypes.237mfs.prom.txt` down to its 209 counter, gauge, and untyped metric families
/// to isolate simple scalar family decoding from histogram and summary assembly.
fn filter_counter_gauge_families(raw: &str) -> Vec<u8> {
    let mut out = String::with_capacity(raw.len());
    let mut skip_family: Option<String> = None;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or_default();
            if matches!(kind, "histogram" | "summary") {
                skip_family = Some(name.to_owned());
                continue;
            }
            skip_family = None;
        } else if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split_whitespace().next().unwrap_or_default();
            let type_decl_hist = raw.lines().any(|l| {
                l == format!("# TYPE {name} histogram") || l == format!("# TYPE {name} summary")
            });
            if type_decl_hist {
                skip_family = Some(name.to_owned());
                continue;
            }
            skip_family = None;
        } else if let Some(skipped) = &skip_family {
            let sample_name = line.split(['{', ' ', '\t']).next().unwrap_or_default();
            if sample_name == skipped
                || sample_name == format!("{skipped}_bucket")
                || sample_name == format!("{skipped}_sum")
                || sample_name == format!("{skipped}_count")
            {
                continue;
            }
            skip_family = None;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.into_bytes()
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/textparse");
    let nometa = fs::read(root.join("alltypes.237mfs.nometa.prom.txt")).unwrap();
    let full = fs::read_to_string(root.join("alltypes.237mfs.prom.txt")).unwrap();
    let typed_simple = filter_counter_gauge_families(&full);
    let full_bytes = full.as_bytes();

    let opts = DecodeOptions::new().with_timestamp_ms(0);
    let stream_256_opts = opts.with_max_data_points_per_batch(256);

    let mut suite = Suite::from_env("expfmt").with_alloc(&ALLOC);

    for (case, payload) in [
        ("alltypes.237mfs.nometa", nometa.as_slice()),
        ("alltypes.209mfs.counter_gauge", typed_simple.as_slice()),
        ("alltypes.237mfs", full_bytes),
    ] {
        let bytes = payload.len() as u64;

        suite = suite
            .bench(format!("Decode/case={case}/mode=decode"), move |b| {
                // Warm internal staging and interner capacities once so B/op and allocs/op
                // measure steady-state scrape reuse rather than cold capacity growth divided by N.
                let mut decoder = ArrowDecoder::new();
                black_box(decoder.decode(payload, &Format::TEXT, &opts).unwrap());

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    let records = decoder
                        .decode(black_box(payload), &Format::TEXT, &opts)
                        .unwrap();
                    black_box(records);
                }
            })
            .bench(format!("Decode/case={case}/mode=decode_view"), move |b| {
                let mut decoder = ArrowDecoder::new();
                black_box(decoder.decode_view(payload, &Format::TEXT, &opts).unwrap());

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    let view = decoder
                        .decode_view(black_box(payload), &Format::TEXT, &opts)
                        .unwrap();
                    black_box(view);
                }
            })
            .bench(format!("Decode/case={case}/mode=stream_16k"), move |b| {
                let mut decoder = ArrowDecoder::new();
                for chunk in decoder.decode_stream(payload, &Format::TEXT, &opts) {
                    black_box(chunk.unwrap());
                }

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    for chunk in decoder.decode_stream(black_box(payload), &Format::TEXT, &opts) {
                        black_box(chunk.unwrap());
                    }
                }
            })
            .bench(format!("Decode/case={case}/mode=stream_256"), move |b| {
                let mut decoder = ArrowDecoder::new();
                for chunk in decoder.decode_stream(payload, &Format::TEXT, &stream_256_opts) {
                    black_box(chunk.unwrap());
                }

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    for chunk in
                        decoder.decode_stream(black_box(payload), &Format::TEXT, &stream_256_opts)
                    {
                        black_box(chunk.unwrap());
                    }
                }
            });
    }

    suite.run();
}
