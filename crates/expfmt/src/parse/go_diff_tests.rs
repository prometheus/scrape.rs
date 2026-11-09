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

//! Compares Layer 0 parser output with Go's `textparse` output stored in `testdata/promparse`,
//! `testdata/omparse`, and `testdata/protobufparse`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{Entry, HistogramRef, LabelsBuffer, OpenMetricsParser, Parser, PromParser, Span};

fn quote(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'"');
    for &byte in bytes {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0..0x20 | 0x7f => out.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

fn quote_labels(out: &mut Vec<u8>, labels: &LabelsBuffer<'_>) {
    for (name, value) in labels.iter() {
        out.push(b' ');
        quote(out, name.as_bytes());
        out.push(b'=');
        quote(out, value.as_bytes());
    }
}

fn spans_text(spans: &[Span]) -> String {
    let spans: Vec<String> = spans
        .iter()
        .map(|span| format!("{}:{}", span.offset, span.length))
        .collect();
    format!("[{}]", spans.join(","))
}

fn ints_text(buckets: &[i64]) -> String {
    let buckets: Vec<String> = buckets.iter().map(i64::to_string).collect();
    format!("[{}]", buckets.join(","))
}

fn floats_text(buckets: &[f64]) -> String {
    let buckets: Vec<String> = buckets
        .iter()
        .map(|bucket| format!("{:016x}", bucket.to_bits()))
        .collect();
    format!("[{}]", buckets.join(","))
}

fn exemplar_text(out: &mut Vec<u8>, value: f64, timestamp: Option<i64>, labels: &LabelsBuffer<'_>) {
    let timestamp = timestamp_text(timestamp);
    write!(out, "\nexemplar {:016x} {timestamp}", value.to_bits()).unwrap();
    quote_labels(out, labels);
}

fn timestamp_text(timestamp: Option<i64>) -> String {
    timestamp.map_or("-".to_owned(), |millis| millis.to_string())
}

/// Writes one line per entry in the format of `tests/go-harness/*_expected.go`, with a
/// `st` line after each series when `start_timestamps` is set.
fn render<'a>(mut parser: impl Parser<'a>, start_timestamps: bool) -> Vec<u8> {
    let mut labels = LabelsBuffer::new();
    let mut out = Vec::new();
    loop {
        let entry = match parser.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => return out,
            Err(_) => {
                out.extend_from_slice(b"error\n");
                return out;
            }
        };
        match entry {
            Entry::Help => {
                let (name, text) = parser.help();
                out.extend_from_slice(b"help ");
                quote(&mut out, name);
                out.push(b' ');
                quote(&mut out, &text);
            }
            Entry::Type => {
                let (name, metric_type) = parser.metric_type();
                out.extend_from_slice(b"type ");
                quote(&mut out, name);
                write!(out, " {}", metric_type.as_str()).unwrap();
            }
            Entry::Unit => {
                let (name, unit) = parser.unit();
                out.extend_from_slice(b"unit ");
                quote(&mut out, name);
                out.push(b' ');
                quote(&mut out, unit);
            }
            Entry::Comment => {
                out.extend_from_slice(b"comment ");
                quote(&mut out, parser.comment());
            }
            Entry::Series => {
                let (series, timestamp, value) = parser.series();
                out.extend_from_slice(b"series ");
                quote(&mut out, series);
                let timestamp = timestamp_text(timestamp);
                write!(out, " {:016x} {timestamp}", value.to_bits()).unwrap();
                parser.labels(&mut labels);
                quote_labels(&mut out, &labels);
                if let Some((value, timestamp)) = parser.exemplar(&mut labels) {
                    exemplar_text(&mut out, value, timestamp, &labels);
                }
                start_timestamp_text(&mut out, &mut parser, start_timestamps);
            }
            Entry::Histogram => {
                let (series, timestamp, histogram) = parser.histogram();
                out.extend_from_slice(b"histogram ");
                quote(&mut out, series);
                write!(out, " {}", timestamp_text(timestamp)).unwrap();
                match histogram {
                    HistogramRef::Int(histogram) => write!(
                        out,
                        " int schema={} count={} sum={:016x} zero_threshold={:016x} zero_count={} hint={} pos_spans={} pos={} neg_spans={} neg={} custom={}",
                        histogram.schema,
                        histogram.count,
                        histogram.sum.to_bits(),
                        histogram.zero_threshold.to_bits(),
                        histogram.zero_count,
                        histogram.counter_reset_hint as u8,
                        spans_text(&histogram.positive_spans),
                        ints_text(&histogram.positive_buckets),
                        spans_text(&histogram.negative_spans),
                        ints_text(&histogram.negative_buckets),
                        floats_text(&histogram.custom_values),
                    ),
                    HistogramRef::Float(histogram) => write!(
                        out,
                        " float schema={} count={:016x} sum={:016x} zero_threshold={:016x} zero_count={:016x} hint={} pos_spans={} pos={} neg_spans={} neg={} custom={}",
                        histogram.schema,
                        histogram.count.to_bits(),
                        histogram.sum.to_bits(),
                        histogram.zero_threshold.to_bits(),
                        histogram.zero_count.to_bits(),
                        histogram.counter_reset_hint as u8,
                        spans_text(&histogram.positive_spans),
                        floats_text(&histogram.positive_buckets),
                        spans_text(&histogram.negative_spans),
                        floats_text(&histogram.negative_buckets),
                        floats_text(&histogram.custom_values),
                    ),
                }
                .unwrap();
                parser.labels(&mut labels);
                quote_labels(&mut out, &labels);
                while let Some((value, timestamp)) = parser.exemplar(&mut labels) {
                    exemplar_text(&mut out, value, timestamp, &labels);
                }
                start_timestamp_text(&mut out, &mut parser, start_timestamps);
            }
        }
        out.push(b'\n');
    }
}

fn start_timestamp_text<'a>(out: &mut Vec<u8>, parser: &mut impl Parser<'a>, enabled: bool) {
    if enabled {
        // Go returns 0 when there is no start timestamp.
        let start = parser.start_timestamp().unwrap_or(0);
        write!(out, "\nst {start}").unwrap();
    }
}

/// Expected files sit under `testdata/<dir>/` at the same relative path as their input.
fn expected_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            expected_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Compares every expected file under `testdata/<dir>/` with `render` of its input.
fn assert_matches_go(dir: &str, render: impl Fn(&[u8]) -> Vec<u8>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let mut expected = Vec::new();
    expected_files(&root.join(dir), &mut expected);
    assert!(
        !expected.is_empty(),
        "no Go expected files in testdata/{dir}"
    );
    for path in expected {
        let input = path.strip_prefix(root.join(dir)).unwrap();
        let want = fs::read(&path).unwrap();
        let got = render(&fs::read(root.join(input)).unwrap());
        // Compare as text first for a readable diff, then as bytes for non-UTF-8 input.
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want),
            "{dir} fixture {}",
            input.display()
        );
        assert_eq!(got, want, "{dir} fixture {}", input.display());
    }
}

#[test]
fn matches_go_promparse_output() {
    assert_matches_go("promparse", |input| render(PromParser::new(input), false));
}

#[test]
fn matches_go_openmetricsparse_output() {
    assert_matches_go("omparse", |input| {
        render(OpenMetricsParser::new(input), true)
    });
}

#[cfg(feature = "dto")]
#[test]
fn matches_go_protobufparse_output() {
    use super::ProtobufParser;

    assert_matches_go("protobufparse", |input| {
        render(ProtobufParser::new(input), true)
    });
}
