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

//! Throughput and allocation benchmarks for `prometheus_expfmt::arrow::ArrowDecoder` over the
//! upstream Prometheus `model/textparse` fixture corpus, plus delimited protobuf payloads with
//! classic and native histograms.
//!
//! Recommended CLI invocation:
//! ```sh
//! cargo bench -p prometheus-expfmt --bench decode -- -bench '^BenchmarkDecode' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::future::Future;
use std::hint::black_box;
use std::path::Path;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use benchfmt::{CountingAlloc, Suite};
use prometheus_expfmt::arrow::{
    ArrowDecoder, DecodeBudget, DecodeOptions, DecodeStep, StalenessTracker,
};
use prometheus_expfmt::format::Format;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

#[inline]
fn poll_cooperative<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
    }
}

/// Filters `alltypes.237mfs.prom.txt` down to its 209 counter, gauge, and untyped metric families
/// until `#8` adds classic histogram and summary assembly.
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

/// Delimited protobuf payloads: the `prometheus/common` `expfmt` fixture, and 200 histogram
/// families of 10 series each, either classic (converted to NHCB) or exponential native
/// histograms at schema 3 with two sparse spans per side.
#[cfg(feature = "dto")]
fn protobuf_cases(root: &Path) -> Vec<(&'static str, Vec<u8>)> {
    use prometheus_expfmt::dto;
    use prost::Message;

    let histogram_families = |native: bool| {
        let mut out = Vec::new();
        for family in 0..200 {
            let metric = (0..10)
                .map(|series| {
                    let histogram = if native {
                        let spans = vec![
                            dto::BucketSpan {
                                offset: -5 + series,
                                length: 12,
                            },
                            dto::BucketSpan {
                                offset: 6,
                                length: 8,
                            },
                        ];
                        let deltas: Vec<i64> =
                            (0..20).map(|i| if i % 3 == 0 { 2 } else { -1 }).collect();
                        let mut current = 0i64;
                        let buckets: u64 = deltas
                            .iter()
                            .map(|delta| {
                                current += delta;
                                current as u64
                            })
                            .sum();
                        dto::Histogram {
                            sample_count: 2 * buckets + 3,
                            sample_sum: 1234.5,
                            schema: 3,
                            zero_threshold: 1e-128,
                            zero_count: 3,
                            negative_span: spans.clone(),
                            negative_delta: deltas.clone(),
                            positive_span: spans,
                            positive_delta: deltas,
                            ..dto::Histogram::default()
                        }
                    } else {
                        let bucket = [
                            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                        ]
                        .iter()
                        .enumerate()
                        .map(|(i, &upper_bound)| dto::Bucket {
                            upper_bound,
                            cumulative_count: (i as u64 / 2) * 7,
                            ..dto::Bucket::default()
                        })
                        .collect();
                        dto::Histogram {
                            sample_count: 40,
                            sample_sum: 1234.5,
                            bucket,
                            ..dto::Histogram::default()
                        }
                    };
                    dto::Metric {
                        label: vec![
                            dto::LabelPair {
                                name: "handler".to_owned(),
                                value: format!("/api/v{series}"),
                            },
                            dto::LabelPair {
                                name: "method".to_owned(),
                                value: "GET".to_owned(),
                            },
                        ],
                        histogram: Some(histogram),
                        // No explicit timestamp, so `decode_staleness` tracks every series.
                        ..dto::Metric::default()
                    }
                })
                .collect();
            dto::MetricFamily {
                name: format!("http_request_duration_seconds_{family}"),
                help: "Request latency.".to_owned(),
                r#type: dto::MetricType::Histogram as i32,
                metric,
                unit: String::new(),
            }
            .encode_length_delimited(&mut out)
            .unwrap();
        }
        out
    };

    vec![
        (
            "expfmt.protobuf",
            fs::read(root.join("../expfmt/protobuf")).unwrap(),
        ),
        ("histograms.200mfs.classic", histogram_families(false)),
        ("histograms.200mfs.native", histogram_families(true)),
    ]
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let nometa = fs::read(root.join("alltypes.237mfs.nometa.prom.txt")).unwrap();
    let full = fs::read_to_string(root.join("alltypes.237mfs.prom.txt")).unwrap();
    let typed_simple = filter_counter_gauge_families(&full);
    let full_bytes = full.as_bytes();

    let opts = DecodeOptions::new().with_timestamp_ms(0);
    let stream_256_opts = opts.with_max_data_points_per_batch(256);
    let budget = DecodeBudget::default();
    // Declared before `suite`, which borrows the payloads.
    #[cfg(feature = "dto")]
    let protobuf = protobuf_cases(&root);

    let mut suite = Suite::from_env("prometheus-expfmt").with_alloc(&ALLOC);

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
            .bench(
                format!("Decode/case={case}/mode=decode_cooperative"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    black_box(decoder.decode(payload, &Format::TEXT, &opts).unwrap());

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let records = poll_cooperative(decoder.decode_cooperative(
                            black_box(payload),
                            &Format::TEXT,
                            &opts,
                            budget,
                            || YieldOnce(false),
                        ))
                        .unwrap();
                        black_box(records);
                    }
                },
            )
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
            })
            .bench(
                format!("Decode/case={case}/mode=stream_256_cooperative"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    for chunk in decoder.decode_stream(payload, &Format::TEXT, &stream_256_opts) {
                        black_box(chunk.unwrap());
                    }

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let mut stream = decoder.decode_stream(
                            black_box(payload),
                            &Format::TEXT,
                            &stream_256_opts,
                        );
                        loop {
                            match stream.step(budget).unwrap() {
                                DecodeStep::Pending => {}
                                DecodeStep::Batch(chunk) => {
                                    black_box(chunk);
                                }
                                DecodeStep::Done => break,
                            }
                        }
                    }
                },
            )
            .bench(
                format!("Decode/case={case}/mode=decode_staleness"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    let mut tracker = StalenessTracker::new();
                    black_box(
                        decoder
                            .decode_with_staleness(payload, &Format::TEXT, &opts, &mut tracker)
                            .unwrap(),
                    );

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        let records = decoder
                            .decode_with_staleness(
                                black_box(payload),
                                &Format::TEXT,
                                &opts,
                                &mut tracker,
                            )
                            .unwrap();
                        black_box(records);
                    }
                },
            );
    }

    #[cfg(feature = "dto")]
    for (case, payload) in &protobuf {
        let payload = payload.as_slice();
        let bytes = payload.len() as u64;
        let format = &Format::PROTO_DELIM;
        suite = suite
            .bench(format!("Decode/case={case}/mode=decode"), move |b| {
                let mut decoder = ArrowDecoder::new();
                black_box(decoder.decode(payload, format, &opts).unwrap());

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    black_box(decoder.decode(black_box(payload), format, &opts).unwrap());
                }
            })
            .bench(format!("Decode/case={case}/mode=stream_256"), move |b| {
                let mut decoder = ArrowDecoder::new();
                for chunk in decoder.decode_stream(payload, format, &stream_256_opts) {
                    black_box(chunk.unwrap());
                }

                b.set_bytes(bytes);
                b.report_allocs();
                while b.keep_running() {
                    for chunk in decoder.decode_stream(black_box(payload), format, &stream_256_opts)
                    {
                        black_box(chunk.unwrap());
                    }
                }
            })
            .bench(
                format!("Decode/case={case}/mode=decode_staleness"),
                move |b| {
                    let mut decoder = ArrowDecoder::new();
                    let mut tracker = StalenessTracker::new();
                    black_box(
                        decoder
                            .decode_with_staleness(payload, format, &opts, &mut tracker)
                            .unwrap(),
                    );

                    b.set_bytes(bytes);
                    b.report_allocs();
                    while b.keep_running() {
                        black_box(
                            decoder
                                .decode_with_staleness(
                                    black_box(payload),
                                    format,
                                    &opts,
                                    &mut tracker,
                                )
                                .unwrap(),
                        );
                    }
                },
            );
    }

    suite.run();
}
