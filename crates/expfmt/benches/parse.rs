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

//! OpenMetrics 1.0 and 2.0 parser benchmarks; each op reads every sample like Go's scrape loop.
//! Recommended CLI invocation:
//! ```sh
//! cargo bench -p prometheus-expfmt --bench parse -- -bench '^BenchmarkParse' -benchtime 1s -count 6 -cpu 2 -benchmem | tee ${bench}.txt
//! ```

use std::fs;
use std::hint::black_box;
use std::path::Path;

use benchfmt::{CountingAlloc, Suite};
use prometheus_expfmt::__bench::{
    Entry, LabelsBuffer, OpenMetrics2Parser, OpenMetricsParser, Parser,
};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

fn read_all<'a>(mut parser: impl Parser<'a>, labels: &mut LabelsBuffer<'a>) {
    while let Some(entry) = parser.next_entry().unwrap() {
        match entry {
            Entry::Series => {
                black_box(parser.series());
            }
            Entry::Histogram => {
                black_box(parser.histogram());
            }
            _ => continue,
        }
        parser.labels(labels);
        while parser.exemplar(labels).is_some() {}
        black_box(parser.start_timestamp());
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let mut suite = Suite::from_env("prometheus-expfmt").with_alloc(&ALLOC);

    for case in ["alltypes", "ct", "histograms"] {
        for format in ["om", "om2"] {
            let input: &'static [u8] = fs::read(root.join(format!("{case}.bench.{format}.txt")))
                .unwrap()
                .leak();
            suite = suite.bench(format!("Parse/case={case}/format={format}"), move |b| {
                let mut labels = LabelsBuffer::new();
                b.set_bytes(input.len() as u64);
                b.report_allocs();
                while b.keep_running() {
                    let input = black_box(input);
                    if format == "om2" {
                        read_all(OpenMetrics2Parser::new(input), &mut labels);
                    } else {
                        read_all(OpenMetricsParser::new(input), &mut labels);
                    }
                }
            });
        }
    }

    suite.run();
}
