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

//! Throughput and allocation benchmarks for the Layer 0 protobuf parser, mirroring Go's
//! `BenchmarkParsePromProto` in `model/textparse/benchmark_test.go`: every entry is read with
//! its accessor, then labels, start timestamp, and all exemplars.
//!
//! Recommended CLI invocation:
//! ```sh
//! cargo bench -p prometheus-expfmt --features bench-internals --bench parse -- -bench '^BenchmarkParsePromProto' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::hint::black_box;
use std::path::Path;

use benchfmt::{CountingAlloc, Suite};
use prometheus_expfmt::parse::{Entry, LabelsBuffer, Parser, ProtobufParser};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

fn parse_all<'a>(input: &'a [u8], labels: &mut LabelsBuffer<'a>, exemplar: &mut LabelsBuffer<'a>) {
    let mut parser = ProtobufParser::new(input);
    while let Some(entry) = parser.next_entry().unwrap() {
        match entry {
            Entry::Help => {
                black_box(parser.help());
                continue;
            }
            Entry::Type => {
                black_box(parser.metric_type());
                continue;
            }
            Entry::Unit => {
                black_box(parser.unit());
                continue;
            }
            Entry::Series => {
                black_box(parser.series());
            }
            Entry::Histogram => {
                black_box(parser.histogram());
            }
            _ => continue,
        }
        parser.labels(labels);
        black_box(&*labels);
        black_box(parser.start_timestamp());
        while let Some(value) = parser.exemplar(exemplar) {
            black_box((value, &*exemplar));
        }
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    // `textparse/TestProtobufParse.pb` is the payload of Go's `createTestProtoBuf`, which
    // `BenchmarkParsePromProto` parses.
    let textparse = fs::read(root.join("textparse/TestProtobufParse.pb")).unwrap();
    let expfmt = fs::read(root.join("expfmt/protobuf")).unwrap();

    let mut suite = Suite::from_env("prometheus-expfmt").with_alloc(&ALLOC);

    for (case, payload) in [
        ("textparse.TestProtobufParse", textparse.as_slice()),
        ("expfmt.protobuf", expfmt.as_slice()),
    ] {
        let bytes = payload.len() as u64;
        suite = suite.bench(format!("ParsePromProto/case={case}"), move |b| {
            // Like Go's reused `labels.Labels` and `exemplar.Exemplar`, the label buffers keep
            // their capacity across iterations.
            let mut labels = LabelsBuffer::new();
            let mut exemplar = LabelsBuffer::new();
            parse_all(payload, &mut labels, &mut exemplar);

            b.set_bytes(bytes);
            b.report_allocs();
            while b.keep_running() {
                parse_all(black_box(payload), &mut labels, &mut exemplar);
            }
        });
    }

    suite.run();
}
