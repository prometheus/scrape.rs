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

//! Throughput and allocation comparison between direct `ArrowDecoder::decode`
//! (`OtapMetricRecords` column builders), `ArrowDecoder::decode_view` (staging only), and
//! `otel_arrow_dfe_pdata::encode::encode_metrics_otap_batch` over `DecodedMetricsView`.
//!
//! Recommended CLI invocation:
//! ```sh
//! cargo bench --manifest-path tests/otap-compat/Cargo.toml --bench otap_encode -- -bench '^BenchmarkOtapEncode' -benchtime 500ms -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::hint::black_box;
use std::path::Path;

use benchfmt::{CountingAlloc, Suite};
use expfmt::arrow::{ArrowDecoder, DecodeOptions};
use expfmt::format::Format;
use otel_arrow_dfe_pdata::encode::encode_metrics_otap_batch;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let nometa = fs::read(root.join("alltypes.237mfs.nometa.prom.txt")).unwrap();
    let full = fs::read(root.join("alltypes.237mfs.prom.txt")).unwrap();
    let om_bench = fs::read(root.join("alltypes.bench.om.txt")).unwrap();

    let opts = DecodeOptions::new().with_timestamp_ms(0);

    let mut suite = Suite::from_env("expfmt_otap_compat").with_alloc(&ALLOC);

    for (case, payload, format) in [
        ("alltypes.237mfs.nometa", nometa.as_slice(), &Format::TEXT),
        ("alltypes.237mfs", full.as_slice(), &Format::TEXT),
        (
            "alltypes.bench.om",
            om_bench.as_slice(),
            &Format::OPEN_METRICS_1_0_0,
        ),
    ] {
        let bytes = payload.len() as u64;

        suite = suite
            .bench(
                format!("OtapEncode/case={case}/mode=direct_decode"),
                move |b| {
                    // Warm internal staging and interner capacities once so B/op and allocs/op
                    // measure steady-state scrape reuse rather than cold capacity growth.
                    let mut decoder = ArrowDecoder::new();
                    black_box(decoder.decode(payload, format, &opts).unwrap());

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let records = decoder.decode(black_box(payload), format, &opts).unwrap();
                        black_box(records);
                    }
                },
            )
            .bench(
                format!("OtapEncode/case={case}/mode=decode_view"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    black_box(decoder.decode_view(payload, format, &opts).unwrap());

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let view = decoder
                            .decode_view(black_box(payload), format, &opts)
                            .unwrap();
                        black_box(view);
                    }
                },
            )
            .bench(
                format!("OtapEncode/case={case}/mode=encode_metrics_otap_batch"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    {
                        let view = decoder.decode_view(payload, format, &opts).unwrap();
                        black_box(encode_metrics_otap_batch(&view).unwrap());
                    }

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let view = decoder
                            .decode_view(black_box(payload), format, &opts)
                            .unwrap();
                        let otap = encode_metrics_otap_batch(&view).unwrap();
                        black_box(otap);
                    }
                },
            );
    }

    suite.run();
}
