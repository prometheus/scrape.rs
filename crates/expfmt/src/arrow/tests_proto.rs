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

//! Decoding delimited protobuf input with [`ArrowDecoder`].

use arrow_array::cast::AsArray;
use arrow_array::types::{
    Float64Type, TimestampNanosecondType, UInt16Type, UInt32Type, UInt64Type,
};
use arrow_array::{Array, RecordBatch, StringArray};
use prost::Message;

use super::*;
use crate::dto;

fn encode(families: &[dto::MetricFamily]) -> Vec<u8> {
    let mut buf = Vec::new();
    for family in families {
        family.encode_length_delimited(&mut buf).unwrap();
    }
    buf
}

fn family(
    name: &str,
    help: &str,
    metric_type: dto::MetricType,
    metric: Vec<dto::Metric>,
) -> dto::MetricFamily {
    dto::MetricFamily {
        name: name.to_owned(),
        help: help.to_owned(),
        r#type: metric_type as i32,
        metric,
        unit: String::new(),
    }
}

fn labels(pairs: &[(&str, &str)]) -> Vec<dto::LabelPair> {
    pairs
        .iter()
        .map(|&(name, value)| dto::LabelPair {
            name: name.to_owned(),
            value: value.to_owned(),
        })
        .collect()
}

fn timestamp(millis: i64) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: millis.div_euclid(1000),
        nanos: (millis.rem_euclid(1000) * 1_000_000) as i32,
    }
}

fn counter(pairs: &[(&str, &str)], value: f64, timestamp_ms: i64) -> dto::Metric {
    dto::Metric {
        label: labels(pairs),
        counter: Some(dto::Counter {
            value,
            ..dto::Counter::default()
        }),
        timestamp_ms,
        ..dto::Metric::default()
    }
}

fn gauge(pairs: &[(&str, &str)], value: f64) -> dto::Metric {
    dto::Metric {
        label: labels(pairs),
        gauge: Some(dto::Gauge { value }),
        ..dto::Metric::default()
    }
}

/// Classic histogram with `(upper_bound, cumulative_count)` buckets, which the protobuf parser
/// converts to NHCB.
fn classic_histogram(
    pairs: &[(&str, &str)],
    buckets: &[(f64, u64)],
    count: u64,
    sum: f64,
) -> dto::Metric {
    dto::Metric {
        label: labels(pairs),
        histogram: Some(dto::Histogram {
            sample_count: count,
            sample_sum: sum,
            bucket: buckets
                .iter()
                .map(|&(upper_bound, cumulative_count)| dto::Bucket {
                    upper_bound,
                    cumulative_count,
                    ..dto::Bucket::default()
                })
                .collect(),
            ..dto::Histogram::default()
        }),
        timestamp_ms: 1_700_000_000_000,
        ..dto::Metric::default()
    }
}

fn decode(input: &[u8], opts: &DecodeOptions) -> Result<OtapMetricRecords, DecodeError> {
    ArrowDecoder::new().decode(input, &Format::PROTO_DELIM, opts)
}

/// Values of a plain or dictionary-encoded string column.
fn strings(batch: &RecordBatch, column: &str) -> Vec<String> {
    let array = batch.column_by_name(column).unwrap();
    if let Some(array) = array.as_any().downcast_ref::<StringArray>() {
        return (0..array.len())
            .map(|i| array.value(i).to_owned())
            .collect();
    }
    let dictionary = array.as_any_dictionary();
    let values = dictionary
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    dictionary
        .normalized_keys()
        .into_iter()
        .map(|key| values.value(key).to_owned())
        .collect()
}

fn u64s(batch: &RecordBatch, column: &str) -> Vec<u64> {
    let array = batch.column_by_name(column).unwrap();
    array.as_primitive::<UInt64Type>().values().to_vec()
}

fn f64s(batch: &RecordBatch, column: &str) -> Vec<f64> {
    let array = batch.column_by_name(column).unwrap();
    array.as_primitive::<Float64Type>().values().to_vec()
}

fn timestamps(batch: &RecordBatch, column: &str) -> Vec<Option<i64>> {
    let array = batch.column_by_name(column).unwrap();
    let array = array.as_primitive::<TimestampNanosecondType>();
    (0..array.len())
        .map(|i| array.is_valid(i).then(|| array.value(i)))
        .collect()
}

#[test]
fn scalars_labels_exemplars_and_timestamps() {
    let mut requests = counter(&[("path", "/a"), ("code", "200")], 5.0, 1_700_000_000_123);
    let requests_counter = requests.counter.as_mut().unwrap();
    requests_counter.start_timestamp = Some(timestamp(1_600_000_000_000));
    requests_counter.exemplar = Some(dto::Exemplar {
        label: labels(&[
            ("trace_id", "0102030405060708090a0b0c0d0e0f10"),
            ("span_id", "0102030405060708"),
            ("user", "x"),
        ]),
        value: 0.25,
        timestamp: Some(timestamp(1_700_000_000_100)),
    });
    // A zero start timestamp is unset, like in Go. An empty label value drops the label.
    let mut other = counter(&[("path", "/b"), ("code", "")], 7.0, 0);
    other.counter.as_mut().unwrap().start_timestamp = Some(timestamp(0));

    let input = encode(&[
        family(
            "requests_total",
            "Requests.",
            dto::MetricType::Counter,
            vec![requests, other],
        ),
        family(
            "temperature",
            "",
            dto::MetricType::Gauge,
            vec![gauge(&[("room", "a\\b\"c")], -1.5)],
        ),
        family(
            "mystery",
            "",
            dto::MetricType::Untyped,
            vec![dto::Metric {
                untyped: Some(dto::Untyped { value: 3.0 }),
                ..dto::Metric::default()
            }],
        ),
    ]);
    let opts = DecodeOptions::default().with_timestamp_ms(1_800_000_000_000);
    let records = decode(&input, &opts).unwrap();

    let metrics = records.univariate_metrics().unwrap();
    assert_eq!(
        strings(metrics, "name"),
        ["requests_total", "temperature", "mystery"]
    );
    let points = records.number_data_points().unwrap();
    assert_eq!(f64s(points, "double_value"), [5.0, 7.0, -1.5, 3.0]);
    assert_eq!(
        timestamps(points, "time_unix_nano"),
        [
            Some(1_700_000_000_123_000_000),
            Some(1_800_000_000_000_000_000),
            Some(1_800_000_000_000_000_000),
            Some(1_800_000_000_000_000_000),
        ]
    );
    assert_eq!(
        timestamps(points, "start_time_unix_nano"),
        [Some(1_600_000_000_000_000_000), None, None, None]
    );

    // Protobuf label values are taken as they are, without text unescaping. Attributes are
    // sorted by interned key ID, like the text decoder does.
    let attrs = records.number_dp_attrs().unwrap();
    assert_eq!(strings(attrs, "key"), ["path", "code", "path", "room"]);
    assert_eq!(strings(attrs, "str"), ["/a", "200", "/b", "a\\b\"c"]);

    let exemplars = records.number_dp_exemplars().unwrap();
    assert_eq!(f64s(exemplars, "double_value"), [0.25]);
    assert_eq!(
        timestamps(exemplars, "time_unix_nano"),
        [Some(1_700_000_000_100_000_000)]
    );
    let span_ids = exemplars
        .column_by_name("span_id")
        .unwrap()
        .as_fixed_size_binary();
    assert_eq!(span_ids.value(0), [1, 2, 3, 4, 5, 6, 7, 8]);
    let exemplar_attrs = records.number_dp_exemplar_attrs().unwrap();
    assert_eq!(strings(exemplar_attrs, "key"), ["user"]);
}

#[test]
fn summaries_become_one_data_point_per_metric() {
    let summary = dto::Metric {
        label: labels(&[("job", "a")]),
        summary: Some(dto::Summary {
            sample_count: 10,
            sample_sum: 4.5,
            quantile: vec![
                dto::Quantile {
                    quantile: 0.9,
                    value: 2.0,
                },
                dto::Quantile {
                    quantile: 0.5,
                    value: 1.0,
                },
                dto::Quantile {
                    quantile: f64::NAN,
                    value: 9.0,
                },
            ],
            start_timestamp: Some(timestamp(1_000)),
        }),
        ..dto::Metric::default()
    };
    let empty = dto::Metric::default();
    let input = encode(&[family(
        "latency",
        "Latency.",
        dto::MetricType::Summary,
        vec![summary, empty],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();

    assert!(records.number_data_points().is_none());
    let points = records.summary_data_points().unwrap();
    assert_eq!(points.num_rows(), 2);
    assert_eq!(u64s(points, "count"), [10, 0]);
    assert_eq!(f64s(points, "sum"), [4.5, 0.0]);
    assert_eq!(
        timestamps(points, "start_time_unix_nano"),
        [Some(1_000_000_000), None]
    );
    let quantiles = points.column_by_name("quantile").unwrap().as_list::<i32>();
    assert_eq!(quantiles.value_offsets(), [0, 2, 2]);
    let quantile_values = quantiles.values().as_struct();
    assert_eq!(
        quantile_values
            .column_by_name("quantile")
            .unwrap()
            .as_primitive::<Float64Type>()
            .values(),
        &[0.5, 0.9]
    );
    let summary_attrs = records.summary_dp_attrs().unwrap();
    assert_eq!(
        summary_attrs
            .column_by_name("parent_id")
            .unwrap()
            .as_primitive::<UInt32Type>()
            .values(),
        &[0]
    );
}

#[test]
fn classic_histograms_become_explicit_bucket_points() {
    let input = encode(&[family(
        "rpc_seconds",
        "RPC latency.",
        dto::MetricType::Histogram,
        vec![
            // Empty buckets in the middle are compacted away by the NHCB conversion and come
            // back as zero counts.
            classic_histogram(
                &[("method", "get")],
                &[(0.1, 1), (0.5, 1), (1.0, 1), (2.0, 1), (5.0, 3)],
                4,
                9.0,
            ),
            classic_histogram(&[("method", "put")], &[], 0, 0.0),
        ],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    let points = records.histogram_data_points().unwrap();
    assert_eq!(u64s(points, "count"), [4, 0]);
    assert_eq!(f64s(points, "sum"), [9.0, 0.0]);
    let buckets = points
        .column_by_name("bucket_counts")
        .unwrap()
        .as_list::<i32>();
    assert_eq!(buckets.value_offsets(), [0, 6, 7]);
    assert_eq!(
        buckets.values().as_primitive::<UInt64Type>().values(),
        &[1, 0, 0, 0, 2, 1, 0]
    );
    let bounds = points
        .column_by_name("explicit_bounds")
        .unwrap()
        .as_list::<i32>();
    assert_eq!(bounds.value_offsets(), [0, 5, 5]);
    assert_eq!(
        bounds.values().as_primitive::<Float64Type>().values(),
        &[0.1, 0.5, 1.0, 2.0, 5.0]
    );
}

#[test]
fn text_and_protobuf_decode_to_the_same_records() {
    let text = "\
# HELP requests_total Requests.
# TYPE requests_total counter
requests_total{code=\"200\",path=\"/a\"} 5 1700000000000
requests_total{code=\"500\",path=\"/a\"} 1 1700000000000
# TYPE temperature gauge
temperature{room=\"a\"} 21.5 1700000000000
# HELP latency Latency.
# TYPE latency summary
latency{job=\"a\",quantile=\"0.5\"} 1 1700000000000
latency{job=\"a\",quantile=\"0.9\"} 2 1700000000000
latency_sum{job=\"a\"} 4.5 1700000000000
latency_count{job=\"a\"} 10 1700000000000
# HELP rpc_seconds RPC latency.
# TYPE rpc_seconds histogram
rpc_seconds_bucket{method=\"get\",le=\"0.1\"} 1 1700000000000
rpc_seconds_bucket{method=\"get\",le=\"0.5\"} 1 1700000000000
rpc_seconds_bucket{method=\"get\",le=\"1\"} 3 1700000000000
rpc_seconds_bucket{method=\"get\",le=\"+Inf\"} 4 1700000000000
rpc_seconds_sum{method=\"get\"} 9 1700000000000
rpc_seconds_count{method=\"get\"} 4 1700000000000
";
    let at = |mut metric: dto::Metric| {
        metric.timestamp_ms = 1_700_000_000_000;
        metric
    };
    let summary = dto::Metric {
        label: labels(&[("job", "a")]),
        summary: Some(dto::Summary {
            sample_count: 10,
            sample_sum: 4.5,
            quantile: vec![
                dto::Quantile {
                    quantile: 0.5,
                    value: 1.0,
                },
                dto::Quantile {
                    quantile: 0.9,
                    value: 2.0,
                },
            ],
            start_timestamp: None,
        }),
        ..dto::Metric::default()
    };
    let proto = encode(&[
        family(
            "requests_total",
            "Requests.",
            dto::MetricType::Counter,
            vec![
                counter(&[("code", "200"), ("path", "/a")], 5.0, 1_700_000_000_000),
                counter(&[("code", "500"), ("path", "/a")], 1.0, 1_700_000_000_000),
            ],
        ),
        family(
            "temperature",
            "",
            dto::MetricType::Gauge,
            vec![at(gauge(&[("room", "a")], 21.5))],
        ),
        family(
            "latency",
            "Latency.",
            dto::MetricType::Summary,
            vec![at(summary)],
        ),
        family(
            "rpc_seconds",
            "RPC latency.",
            dto::MetricType::Histogram,
            vec![classic_histogram(
                &[("method", "get")],
                &[(0.1, 1), (0.5, 1), (1.0, 3)],
                4,
                9.0,
            )],
        ),
    ]);
    for policy in [CounterSuffixPolicy::Keep, CounterSuffixPolicy::Strip] {
        let opts = DecodeOptions::default().with_counter_suffix_policy(policy);
        let from_text = ArrowDecoder::new()
            .decode(text.as_bytes(), &Format::TEXT, &opts)
            .unwrap();
        let from_proto = decode(&proto, &opts).unwrap();
        for (payload_type, batch) in from_text.iter() {
            assert_eq!(
                Some(batch),
                from_proto.get(payload_type),
                "{payload_type:?} differs with {policy:?}"
            );
        }
        assert_eq!(from_text, from_proto);
    }
}

#[test]
fn repeated_family_names_start_new_metric_rows() {
    let input = encode(&[
        family(
            "up",
            "Up.",
            dto::MetricType::Gauge,
            vec![gauge(&[("job", "a")], 1.0)],
        ),
        family(
            "up",
            "Up.",
            dto::MetricType::Gauge,
            vec![gauge(&[("job", "b")], 0.0)],
        ),
        // Go skips families without metrics.
        family("nothing", "", dto::MetricType::Counter, vec![]),
    ]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    assert_eq!(
        strings(records.univariate_metrics().unwrap(), "name"),
        ["up", "up"]
    );
    let points = records.number_data_points().unwrap();
    assert_eq!(
        points
            .column_by_name("parent_id")
            .unwrap()
            .as_primitive::<UInt16Type>()
            .values(),
        &[0, 1]
    );
}

#[test]
fn label_errors_match_the_text_decoder() {
    for pairs in [
        &[("__name__", "x")][..],
        &[("__name__", "")][..],
        &[("a", "1"), ("a", "2")][..],
        &[("a", ""), ("a", "2")][..],
        &[("a", ""), ("b", "1"), ("a", "2")][..],
    ] {
        let input = encode(&[family(
            "g",
            "",
            dto::MetricType::Gauge,
            vec![gauge(pairs, 1.0)],
        )]);
        let err = decode(&input, &DecodeOptions::default()).unwrap_err();
        assert!(
            matches!(err, DecodeError::DuplicateLabel { .. }),
            "{pairs:?}: {err:?}"
        );
    }

    let untyped = |pairs| dto::Metric {
        label: labels(pairs),
        untyped: Some(dto::Untyped { value: 1.0 }),
        ..dto::Metric::default()
    };
    let opts = DecodeOptions::default().with_untyped_policy(UntypedPolicy::Drop);
    let input = encode(&[family(
        "u",
        "",
        dto::MetricType::Untyped,
        vec![untyped(&[("a", "1")])],
    )]);
    assert!(decode(&input, &opts).unwrap().is_empty());
    let input = encode(&[family(
        "u",
        "",
        dto::MetricType::Untyped,
        vec![untyped(&[("a", "1"), ("b", "1"), ("a", "2")])],
    )]);
    assert!(matches!(
        decode(&input, &opts),
        Err(DecodeError::DuplicateLabel { .. })
    ));
}

fn span(offset: i32, length: u32) -> dto::BucketSpan {
    dto::BucketSpan { offset, length }
}

/// Integer exponential native histogram with positive buckets only.
fn native(schema: i32, spans: Vec<dto::BucketSpan>, deltas: Vec<i64>) -> dto::Histogram {
    let mut current = 0i64;
    let buckets: u64 = deltas
        .iter()
        .map(|delta| {
            current += delta;
            // Negative counts are for the Validate tests, which never get to the count check.
            current.max(0) as u64
        })
        .sum();
    dto::Histogram {
        sample_count: buckets + 1,
        sample_sum: 12.5,
        schema,
        zero_threshold: 1e-128,
        zero_count: 1,
        positive_span: spans,
        positive_delta: deltas,
        ..dto::Histogram::default()
    }
}

fn histogram_metric(pairs: &[(&str, &str)], histogram: dto::Histogram) -> dto::Metric {
    dto::Metric {
        label: labels(pairs),
        histogram: Some(histogram),
        timestamp_ms: 1_700_000_000_000,
        ..dto::Metric::default()
    }
}

fn metric_types(records: &OtapMetricRecords) -> Vec<u8> {
    records
        .univariate_metrics()
        .unwrap()
        .column_by_name("metric_type")
        .unwrap()
        .as_primitive::<arrow_array::types::UInt8Type>()
        .values()
        .to_vec()
}

#[test]
fn exponential_histograms_become_exponential_points() {
    let mut first = native(3, vec![span(-1, 2), span(2, 1)], vec![2, 1, -2]);
    first.start_timestamp = Some(timestamp(1_600_000_000_000));
    first.negative_span = vec![span(0, 1)];
    first.negative_delta = vec![4];
    first.sample_count += 4;
    first.exemplars = vec![
        dto::Exemplar {
            label: labels(&[("trace_id", "0102030405060708090a0b0c0d0e0f10")]),
            value: 0.3,
            timestamp: Some(timestamp(1_700_000_000_001)),
        },
        // Go drops native histogram exemplars without a timestamp.
        dto::Exemplar {
            label: labels(&[("user", "x")]),
            value: 0.4,
            timestamp: None,
        },
        dto::Exemplar {
            label: labels(&[("user", "y")]),
            value: 0.5,
            timestamp: Some(timestamp(1_700_000_000_002)),
        },
    ];
    let second = native(0, vec![], vec![]);
    let input = encode(&[family(
        "rpc_seconds",
        "RPC latency.",
        dto::MetricType::Histogram,
        vec![
            histogram_metric(&[("method", "get")], first),
            histogram_metric(&[("method", "put")], second),
        ],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();

    assert_eq!(metric_types(&records), [4]);
    assert!(records.histogram_data_points().is_none());
    let points = records.exp_histogram_data_points().unwrap();
    assert_eq!(u64s(points, "count"), [11, 1]);
    assert_eq!(f64s(points, "sum"), [12.5, 12.5]);
    assert_eq!(u64s(points, "zero_count"), [1, 1]);
    assert_eq!(
        points
            .column_by_name("scale")
            .unwrap()
            .as_primitive::<arrow_array::types::Int32Type>()
            .values(),
        &[3, 0]
    );
    assert_eq!(
        timestamps(points, "start_time_unix_nano"),
        [Some(1_600_000_000_000_000_000), None]
    );
    let positive = points.column_by_name("positive").unwrap().as_struct();
    assert_eq!(
        positive
            .column_by_name("offset")
            .unwrap()
            .as_primitive::<arrow_array::types::Int32Type>()
            .values(),
        &[-2, 0]
    );
    let counts = positive
        .column_by_name("bucket_counts")
        .unwrap()
        .as_list::<i32>();
    assert_eq!(counts.value_offsets(), [0, 5, 5]);
    assert_eq!(
        counts.values().as_primitive::<UInt64Type>().values(),
        &[2, 3, 0, 0, 1]
    );
    assert!(points.column_by_name("negative").is_some());
    assert!(points.column_by_name("flags").is_none());

    let exemplars = records.exp_histogram_dp_exemplars().unwrap();
    assert_eq!(f64s(exemplars, "double_value"), [0.3, 0.5]);
    let exemplar_attrs = records.exp_histogram_dp_exemplar_attrs().unwrap();
    assert_eq!(strings(exemplar_attrs, "str"), ["y"]);
    let attrs = records.exp_histogram_dp_attrs().unwrap();
    assert_eq!(strings(attrs, "str"), ["get", "put"]);
}

#[test]
fn mixed_native_and_custom_bucket_histograms_use_two_rows() {
    let input = encode(&[family(
        "mixed",
        "Mixed.",
        dto::MetricType::Histogram,
        vec![
            histogram_metric(&[("a", "1")], native(1, vec![span(0, 1)], vec![3])),
            classic_histogram(&[("a", "2")], &[(1.0, 2)], 2, 1.0),
            histogram_metric(&[("a", "3")], native(1, vec![span(0, 1)], vec![1])),
        ],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    assert_eq!(metric_types(&records), [4, 3]);
    let metrics = records.univariate_metrics().unwrap();
    assert_eq!(strings(metrics, "name"), ["mixed", "mixed"]);
    assert_eq!(strings(metrics, "description"), ["Mixed.", "Mixed."]);
    assert_eq!(records.exp_histogram_data_points().unwrap().num_rows(), 2);
    assert_eq!(records.histogram_data_points().unwrap().num_rows(), 1);
}

#[test]
fn float_histograms_are_dropped_and_gauge_ones_kept() {
    let float_exponential = dto::Histogram {
        sample_count_float: 2.0,
        sample_sum: 1.0,
        schema: 0,
        zero_count_float: 2.0,
        zero_threshold: 1e-128,
        ..dto::Histogram::default()
    };
    // A classic histogram with float counts converts to a float NHCB.
    let float_classic = dto::Histogram {
        sample_count_float: 1.8,
        sample_sum: 1.0,
        bucket: [(1.0, 0.6), (2.0, 1.2)]
            .map(|(upper_bound, cumulative_count_float)| dto::Bucket {
                upper_bound,
                cumulative_count_float,
                ..dto::Bucket::default()
            })
            .to_vec(),
        ..dto::Histogram::default()
    };
    let input = encode(&[
        family(
            "float",
            "",
            dto::MetricType::Histogram,
            vec![
                histogram_metric(&[("kind", "exponential")], float_exponential),
                histogram_metric(&[("kind", "classic")], float_classic),
            ],
        ),
        family(
            "gauge",
            "",
            dto::MetricType::GaugeHistogram,
            vec![histogram_metric(&[], native(0, vec![span(1, 1)], vec![2]))],
        ),
    ]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    assert_eq!(
        strings(records.univariate_metrics().unwrap(), "name"),
        ["gauge"]
    );
    assert_eq!(metric_types(&records), [4]);
    assert_eq!(records.exp_histogram_data_points().unwrap().num_rows(), 1);
}

/// The `flags` column of a data point batch, zero for every point when it is left out.
fn parent_ids(batch: &RecordBatch) -> Vec<u16> {
    let parents = batch.column_by_name("parent_id").unwrap();
    parents.as_primitive::<UInt16Type>().values().to_vec()
}

fn flags(batch: &RecordBatch) -> Vec<u32> {
    batch.column_by_name("flags").map_or_else(
        || vec![0; batch.num_rows()],
        |array| array.as_primitive::<UInt32Type>().values().to_vec(),
    )
}

fn summary_metric(pairs: &[(&str, &str)], sum: f64, quantile_value: f64) -> dto::Metric {
    dto::Metric {
        label: labels(pairs),
        summary: Some(dto::Summary {
            sample_count: 3,
            sample_sum: sum,
            quantile: vec![dto::Quantile {
                quantile: 0.5,
                value: quantile_value,
            }],
            start_timestamp: None,
        }),
        ..dto::Metric::default()
    }
}

#[test]
fn stale_markers_set_the_no_recorded_value_flag() {
    let mut stale_native = native(0, vec![span(0, 1)], vec![2]);
    stale_native.sample_sum = STALE_NAN;
    let input = encode(&[
        family(
            "g",
            "",
            dto::MetricType::Gauge,
            vec![gauge(&[("s", "1")], STALE_NAN), gauge(&[("s", "2")], 1.0)],
        ),
        family(
            "s",
            "",
            dto::MetricType::Summary,
            vec![
                summary_metric(&[("s", "1")], STALE_NAN, 1.0),
                summary_metric(&[("s", "2")], 1.0, STALE_NAN),
                summary_metric(&[("s", "3")], 1.0, 1.0),
            ],
        ),
        family(
            "h",
            "",
            dto::MetricType::Histogram,
            vec![
                histogram_metric(&[("s", "1")], stale_native),
                histogram_metric(&[("s", "2")], native(0, vec![span(0, 1)], vec![2])),
                classic_histogram(&[("s", "3")], &[(1.0, 2)], 2, STALE_NAN),
                classic_histogram(&[("s", "4")], &[(1.0, 2)], 2, 1.0),
            ],
        ),
    ]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();

    let numbers = records.number_data_points().unwrap();
    assert_eq!(flags(numbers), [1, 0]);
    let values = numbers.column_by_name("double_value").unwrap();
    assert!(values.is_null(0) && values.is_valid(1));

    // Like the text loop: zero count and sum and no quantiles.
    let summaries = records.summary_data_points().unwrap();
    assert_eq!(flags(summaries), [1, 1, 0]);
    assert_eq!(u64s(summaries, "count"), [0, 0, 3]);
    assert_eq!(f64s(summaries, "sum"), [0.0, 0.0, 1.0]);

    let exponential = records.exp_histogram_data_points().unwrap();
    assert_eq!(flags(exponential), [1, 0]);
    assert_eq!(u64s(exponential, "count"), [0, 3]);

    // Like a stale classic histogram from the text loop: zero count, no sum, no buckets.
    let custom = records.histogram_data_points().unwrap();
    assert_eq!(flags(custom), [1, 0]);
    assert_eq!(u64s(custom, "count"), [0, 2]);
    let sums = custom.column_by_name("sum").unwrap();
    assert!(sums.is_null(0) && sums.is_valid(1));
    let buckets = custom
        .column_by_name("bucket_counts")
        .unwrap()
        .as_list::<i32>();
    assert_eq!(buckets.value_length(0), 0);
    assert_eq!(buckets.value_length(1), 2);
}

/// One family of every kind the tracker records, with all points at the scrape timestamp.
fn tracked_families(series: &[&str]) -> Vec<u8> {
    let stamped = |mut metric: dto::Metric| {
        metric.timestamp_ms = 0;
        metric
    };
    let mut gauges = Vec::new();
    let mut summaries = Vec::new();
    let mut histograms = Vec::new();
    for &value in series {
        let pairs = [("s", value)];
        gauges.push(stamped(gauge(&pairs, 1.0)));
        summaries.push(stamped(summary_metric(&pairs, 1.0, 1.0)));
        histograms.push(stamped(histogram_metric(
            &pairs,
            native(0, vec![span(0, 1)], vec![2]),
        )));
        histograms.push(stamped(classic_histogram(&pairs, &[(1.0, 2)], 2, 1.0)));
    }
    encode(&[
        family("g", "", dto::MetricType::Gauge, gauges),
        family("s", "", dto::MetricType::Summary, summaries),
        family("h", "", dto::MetricType::Histogram, histograms),
    ])
}

#[test]
fn disappeared_series_get_stale_points() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    let mut scrape = |input: &[u8], tracker: &mut StalenessTracker| {
        decoder
            .decode_with_staleness(input, &Format::PROTO_DELIM, &opts, tracker)
            .unwrap()
    };

    let first = scrape(&tracked_families(&["1", "2"]), &mut tracker);
    assert_eq!(metric_types(&first), [1, 5, 4, 3]);

    // Series 2 disappears: each kind gets one stale point in the row of its kind, after the
    // live point of series 1.
    let second = scrape(&tracked_families(&["1"]), &mut tracker);
    assert_eq!(metric_types(&second), [1, 5, 4, 3]);
    for points in [
        second.number_data_points(),
        second.summary_data_points(),
        second.exp_histogram_data_points(),
        second.histogram_data_points(),
    ] {
        assert_eq!(flags(points.unwrap()), [0, 1]);
    }
    let exponential = second.exp_histogram_data_points().unwrap();
    assert_eq!(u64s(exponential, "count"), [3, 0]);

    // A family that disappears entirely gets its rows back for its stale points, an
    // `ExpHistogram` row for the exponential ones.
    let third = scrape(&encode(&[]), &mut tracker);
    assert_eq!(metric_types(&third), [1, 5, 4, 3]);
    assert_eq!(flags(third.exp_histogram_data_points().unwrap()), [1]);
    assert_eq!(flags(third.histogram_data_points().unwrap()), [1]);

    // Stale points are only written once.
    let fourth = scrape(&encode(&[]), &mut tracker);
    assert!(fourth.univariate_metrics().is_none());
}

#[test]
fn input_stale_markers_end_tracked_series() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    let mut stale_native = native(0, vec![span(0, 1)], vec![2]);
    stale_native.sample_sum = STALE_NAN;
    let mut stale = histogram_metric(&[("s", "1")], stale_native);
    stale.timestamp_ms = 0;

    let mut scrape = |input: &[u8]| {
        decoder
            .decode_with_staleness(input, &Format::PROTO_DELIM, &opts, &mut tracker)
            .unwrap()
    };
    scrape(&tracked_families(&["1"]));

    // The exponential series is stale in the input, the other kinds disappeared.
    let second = scrape(&encode(&[family(
        "h",
        "",
        dto::MetricType::Histogram,
        vec![stale],
    )]));
    assert_eq!(metric_types(&second), [4, 1, 5, 3]);
    for points in [
        second.exp_histogram_data_points(),
        second.number_data_points(),
        second.summary_data_points(),
        second.histogram_data_points(),
    ] {
        assert_eq!(flags(points.unwrap()), [1]);
    }

    // None of them is marked stale again.
    assert!(scrape(&encode(&[])).univariate_metrics().is_none());
}

#[test]
fn explicit_timestamps_are_tracked_only_when_enabled() {
    let input = encode(&[family(
        "c_total",
        "",
        dto::MetricType::Counter,
        vec![counter(&[], 1.0, 1_700_000_000_000)],
    )]);
    for (track, stale_points) in [(false, 0), (true, 1)] {
        let opts = DecodeOptions::default()
            .with_timestamp_ms(1_700_000_000_000)
            .with_track_timestamps_staleness(track);
        let mut decoder = ArrowDecoder::new();
        let mut tracker = StalenessTracker::new();
        decoder
            .decode_with_staleness(&input, &Format::PROTO_DELIM, &opts, &mut tracker)
            .unwrap();
        let records = decoder
            .decode_with_staleness(&encode(&[]), &Format::PROTO_DELIM, &opts, &mut tracker)
            .unwrap();
        let points = records.number_data_points().map_or(0, |b| b.num_rows());
        assert_eq!(points, stale_points, "track_timestamps_staleness = {track}");
    }
}

/// Stale points per table: number, summary, explicit-bucket, and exponential histogram.
fn stale_counts(records: &OtapMetricRecords) -> [usize; 4] {
    [
        records.number_data_points(),
        records.summary_data_points(),
        records.histogram_data_points(),
        records.exp_histogram_data_points(),
    ]
    .map(|points| points.map_or(0, |b| flags(b).iter().filter(|&&f| f == 1).count()))
}

#[test]
fn chunked_and_budgeted_stale_points_match_single_batch() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let full = tracked_families(&["1", "2", "3"]);
    let partial = tracked_families(&["2"]);

    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    let mut single = |input: &[u8]| {
        decoder
            .decode_with_staleness(input, &Format::PROTO_DELIM, &opts, &mut tracker)
            .unwrap()
    };
    single(&full);
    assert_eq!(stale_counts(&single(&partial)), [2; 4]);

    let chunked_opts = opts.with_max_data_points_per_batch(1);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    for input in [&full, &partial] {
        let mut stale = [0; 4];
        let mut chunks = 0;
        for chunk in decoder.decode_stream_with_staleness(
            input,
            &Format::PROTO_DELIM,
            &chunked_opts,
            &mut tracker,
        ) {
            chunks += 1;
            let counts = stale_counts(&chunk.unwrap());
            stale.iter_mut().zip(counts).for_each(|(s, c)| *s += c);
        }
        if input == &partial {
            // One live and two stale points of each kind, one per chunk.
            assert_eq!(chunks, 12);
            assert_eq!(stale, [2; 4]);
        }
    }

    let budget = DecodeBudget::default().with_max_entries(1);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    for input in [&full, &partial] {
        let mut stale = [0; 4];
        let mut cursor = decoder
            .start_decode_stream(&Format::PROTO_DELIM, &chunked_opts)
            .unwrap();
        loop {
            match decoder
                .step_decode_with_staleness(&mut cursor, input, budget, &mut tracker)
                .unwrap()
            {
                DecodeStep::Pending => {}
                DecodeStep::Batch(chunk) => {
                    let counts = stale_counts(&chunk);
                    stale.iter_mut().zip(counts).for_each(|(s, c)| *s += c);
                }
                DecodeStep::Done => break,
            }
        }
        if input == &partial {
            assert_eq!(stale, [2; 4]);
        }
    }
}

#[test]
fn invalid_histograms_fail_the_scrape() {
    let cases = [
        (native(9, vec![], vec![]), "invalid schema"),
        (native(-5, vec![], vec![]), "invalid schema"),
        (
            native(0, vec![span(0, 1), span(-1, 1)], vec![1, 1]),
            "offset is negative",
        ),
        (
            native(0, vec![span(0, 2)], vec![1, -2]),
            "count is negative",
        ),
        (
            dto::Histogram {
                sample_count: 99,
                ..native(0, vec![span(0, 1)], vec![1])
            },
            "should equal",
        ),
        // Float exponential histograms are dropped, but only after Go's checks.
        (
            dto::Histogram {
                sample_count_float: 2.0,
                schema: 0,
                positive_span: vec![span(0, 1), span(-1, 1)],
                positive_count: vec![1.0, 1.0],
                ..dto::Histogram::default()
            },
            "offset is negative",
        ),
    ];
    for (histogram, expected) in cases {
        let input = encode(&[family(
            "h",
            "",
            dto::MetricType::Histogram,
            vec![histogram_metric(&[], histogram)],
        )]);
        let err = decode(&input, &DecodeOptions::default()).unwrap_err();
        assert!(
            matches!(&err, DecodeError::InvalidHistogram { metric, reason }
                if metric == "h" && reason.contains(expected)),
            "{expected}: {err:?}"
        );
    }
}

#[test]
fn chunked_and_budgeted_decoding_matches_single_batch() {
    let mut metrics = Vec::new();
    for i in 0..5 {
        metrics.push(classic_histogram(
            &[("i", &i.to_string())],
            &[(1.0, i)],
            i,
            0.5,
        ));
    }
    let input = encode(&[
        family(
            "a",
            "A.",
            dto::MetricType::Gauge,
            (0..5).map(|i| gauge(&[], f64::from(i))).collect(),
        ),
        family("h", "H.", dto::MetricType::Histogram, metrics),
        family(
            "e",
            "E.",
            dto::MetricType::Histogram,
            (0..4)
                .map(|i| histogram_metric(&[], native(i, vec![span(0, 1)], vec![1])))
                .collect(),
        ),
    ]);
    let opts = DecodeOptions::default().with_max_data_points_per_batch(2);
    let mut dec = ArrowDecoder::new();
    let chunks: Vec<_> = dec
        .decode_stream(&input, &Format::PROTO_DELIM, &opts)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        chunks
            .iter()
            .map(OtapMetricRecords::num_data_points)
            .collect::<Vec<_>>(),
        [2, 2, 2, 2, 2, 2, 2]
    );
    // The family row is repeated in every chunk its points land in.
    assert_eq!(
        strings(chunks[2].univariate_metrics().unwrap(), "name"),
        ["a", "h"]
    );
    assert_eq!(
        strings(chunks[3].univariate_metrics().unwrap(), "description"),
        ["H."]
    );

    // A budget of one entry per step pauses at every entry, which round-trips the parser
    // state through the cursor, and still yields the same chunks.
    let mut cursor = dec
        .start_decode_stream(&Format::PROTO_DELIM, &opts)
        .unwrap();
    let mut stepped = Vec::new();
    let mut pending = 0;
    loop {
        match dec
            .step_decode(
                &mut cursor,
                &input,
                DecodeBudget::default().with_max_entries(1),
            )
            .unwrap()
        {
            DecodeStep::Pending => pending += 1,
            DecodeStep::Batch(batch) => stepped.push(batch),
            DecodeStep::Done => break,
        }
    }
    assert!(pending >= 5, "{pending}");
    assert_eq!(stepped, chunks);

    let whole = dec
        .decode(&input, &Format::PROTO_DELIM, &DecodeOptions::default())
        .unwrap();
    assert_eq!(whole.num_data_points(), 14);
    assert_eq!(
        strings(chunks[6].univariate_metrics().unwrap(), "name"),
        ["e"]
    );
}

#[test]
fn protobuf_scratch_is_reused_across_scrapes() {
    let input = encode(&[family(
        "h",
        "",
        dto::MetricType::Histogram,
        vec![classic_histogram(&[], &[(1.0, 1), (2.0, 2)], 2, 1.0)],
    )]);
    let mut dec = ArrowDecoder::new();
    dec.decode(&input, &Format::PROTO_DELIM, &DecodeOptions::default())
        .unwrap();
    let retained = dec.retained_memory_bytes();
    assert!(dec.proto.retained_memory_bytes() > 0);
    for _ in 0..3 {
        dec.decode(&input, &Format::PROTO_DELIM, &DecodeOptions::default())
            .unwrap();
    }
    assert_eq!(dec.retained_memory_bytes(), retained);
}

/// Exponential histograms with labels `s` = `{prefix}{i}` for `i` in `0..series`, at the scrape
/// timestamp.
fn exponential_series(prefix: &str, series: usize) -> Vec<u8> {
    let metric = (0..series)
        .map(|i| {
            let value = format!("{prefix}{i}");
            let mut metric =
                histogram_metric(&[("s", &value)], native(0, vec![span(0, 1)], vec![2]));
            metric.timestamp_ms = 0;
            metric
        })
        .collect();
    encode(&[family("h", "", dto::MetricType::Histogram, metric)])
}

#[test]
fn target_flushes_write_exponential_stale_points() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    decoder
        .decode_with_staleness(
            &tracked_families(&["1", "2"]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();
    assert_eq!(tracker.active_series_len(), 8);

    // A dropped stream rolls back, so the flush below still sees every series.
    let chunk_opts = opts.with_max_data_points_per_batch(1);
    {
        let mut partial = decoder.flush_target_stale_stream(&mut tracker, &chunk_opts);
        assert_eq!(partial.next().unwrap().unwrap().num_data_points(), 1);
    }
    assert_eq!(tracker.active_series_len(), 8);

    let mut stale = [0; 4];
    for chunk in decoder.flush_target_stale_stream(&mut tracker, &chunk_opts) {
        let counts = stale_counts(&chunk.unwrap());
        stale.iter_mut().zip(counts).for_each(|(s, c)| *s += c);
    }
    assert_eq!(stale, [2; 4]);
    assert!(tracker.is_empty());

    decoder
        .decode_with_staleness(
            &tracked_families(&["1", "2"]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();
    let flushed = decoder.flush_target_stale(&mut tracker, &opts).unwrap();
    assert_eq!(stale_counts(&flushed), [2; 4]);
    assert_eq!(metric_types(&flushed), [1, 5, 4, 3]);
    let exponential = flushed.exp_histogram_data_points().unwrap();
    assert_eq!(u64s(exponential, "count"), [0, 0]);
    let sums = exponential.column_by_name("sum").unwrap();
    assert_eq!(sums.null_count(), 2);
    assert!(tracker.is_empty());
}

#[test]
fn failed_and_dropped_scrapes_roll_back_the_tracker() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    decoder
        .decode_with_staleness(
            &tracked_families(&["1"]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();

    // Series 2 of every kind is recorded before the invalid histogram fails the scrape.
    let mut failing = tracked_families(&["2"]);
    failing.extend(encode(&[family(
        "bad",
        "",
        dto::MetricType::Histogram,
        vec![histogram_metric(&[], native(9, vec![], vec![]))],
    )]));
    let err = decoder
        .decode_with_staleness(&failing, &Format::PROTO_DELIM, &opts, &mut tracker)
        .unwrap_err();
    assert!(
        matches!(err, DecodeError::InvalidHistogram { .. }),
        "{err:?}"
    );
    assert_eq!(tracker.active_series_len(), 4);

    // A stream dropped after its first chunk rolls back too.
    let chunk_opts = opts.with_max_data_points_per_batch(1);
    let third = tracked_families(&["3"]);
    {
        let mut partial = decoder.decode_stream_with_staleness(
            &third,
            &Format::PROTO_DELIM,
            &chunk_opts,
            &mut tracker,
        );
        partial.next().unwrap().unwrap();
    }
    assert_eq!(tracker.active_series_len(), 4);

    // Neither series 2 nor series 3 was committed, so only series 1 is live and none is stale.
    let records = decoder
        .decode_with_staleness(
            &tracked_families(&["1"]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();
    assert_eq!(stale_counts(&records), [0; 4]);
    assert_eq!(records.num_data_points(), 4);
}

#[test]
fn churned_exponential_series_are_compacted() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    let mut scrape = |input: &[u8], tracker: &mut StalenessTracker| {
        decoder
            .decode_with_staleness(input, &Format::PROTO_DELIM, &opts, tracker)
            .unwrap()
    };

    scrape(&exponential_series("a", 40), &mut tracker);
    let retained = tracker.retained_memory_bytes();
    // 40 deactivated series pass the compaction threshold of 32.
    let rotated = scrape(&exponential_series("b", 40), &mut tracker);
    assert_eq!(stale_counts(&rotated), [0, 0, 0, 40]);
    assert_eq!(tracker.active_series_len(), 40);
    // Without compaction the tracker would hold 80 series.
    assert!(tracker.retained_memory_bytes() <= retained);

    // The compacted series keep their kind: they come back as exponential stale points.
    assert_eq!(
        stale_counts(&scrape(&exponential_series("b", 40), &mut tracker)),
        [0; 4]
    );
    let flushed = decoder.flush_target_stale(&mut tracker, &opts).unwrap();
    assert_eq!(stale_counts(&flushed), [0, 0, 0, 40]);
    assert_eq!(metric_types(&flushed), [4]);
}

#[test]
fn split_families_keep_one_row_per_kind_for_stale_points() {
    let opts = DecodeOptions::default().with_timestamp_ms(1_700_000_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    let stamped = |mut metric: dto::Metric| {
        metric.timestamp_ms = 0;
        metric
    };
    let exponential = |value: &str| {
        stamped(histogram_metric(
            &[("s", value)],
            native(0, vec![span(0, 1)], vec![2]),
        ))
    };
    let classic = |value: &str| stamped(classic_histogram(&[("s", value)], &[(1.0, 2)], 2, 1.0));

    decoder
        .decode_with_staleness(
            &encode(&[family(
                "h",
                "",
                dto::MetricType::Histogram,
                vec![exponential("1"), classic("2")],
            )]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();

    // `h` comes in two messages. The second one has no exponential row, which must not make
    // the stale point of series 1 open a second exponential row.
    let records = decoder
        .decode_with_staleness(
            &encode(&[
                family("h", "", dto::MetricType::Histogram, vec![exponential("3")]),
                family("h", "", dto::MetricType::Histogram, vec![classic("2")]),
            ]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();
    assert_eq!(metric_types(&records), [4, 3]);
    let points = records.exp_histogram_data_points().unwrap();
    assert_eq!(flags(points), [0, 1]);
    assert_eq!(parent_ids(points), [0, 0]);

    // The other way around: the classic row comes first, and the stale point of series 2 must
    // not open a second classic row after the exponential-only message.
    let records = decoder
        .decode_with_staleness(
            &encode(&[
                family("h", "", dto::MetricType::Histogram, vec![classic("4")]),
                family("h", "", dto::MetricType::Histogram, vec![exponential("3")]),
            ]),
            &Format::PROTO_DELIM,
            &opts,
            &mut tracker,
        )
        .unwrap();
    assert_eq!(metric_types(&records), [3, 4]);
    let points = records.histogram_data_points().unwrap();
    assert_eq!(flags(points), [0, 1]);
    assert_eq!(parent_ids(points), [0, 0]);
}

#[test]
fn chunked_stream_splits_rows_past_the_u16_metric_limit() {
    // A gauge row, then an explicit-bucket and an exponential row per family: 65,537 rows, so
    // the batch fills after the explicit-bucket row of the last family and its exponential row
    // starts the next batch, in the input and in the stale pass.
    let families = MAX_METRICS_PER_BATCH / 2;
    let mut messages = vec![family(
        "g",
        "",
        dto::MetricType::Gauge,
        vec![gauge(&[], 1.0)],
    )];
    messages.extend((0..families).map(|i| {
        let mut metrics = Vec::with_capacity(2);
        for metric in [
            classic_histogram(&[], &[(1.0, 2)], 2, 1.0),
            histogram_metric(&[], native(0, vec![span(0, 1)], vec![2])),
        ] {
            let mut metric = metric;
            metric.timestamp_ms = 0;
            metrics.push(metric);
        }
        family(&format!("h_{i}"), "", dto::MetricType::Histogram, metrics)
    }));
    let input = encode(&messages);
    let opts = DecodeOptions::default()
        .with_timestamp_ms(1_700_000_000_000)
        .with_max_data_points_per_batch(1_000_000);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();

    let chunks: Vec<_> = decoder
        .decode_stream_with_staleness(&input, &Format::PROTO_DELIM, &opts, &mut tracker)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].num_metrics(), MAX_METRICS_PER_BATCH);
    // The point that did not fit is replayed into the next batch, not lost.
    assert_eq!(chunks[1].num_metrics(), 1);
    assert_eq!(metric_types(&chunks[1]), [4]);
    assert_eq!(
        chunks.iter().map(|c| c.num_data_points()).sum::<usize>(),
        2 * families + 1
    );
    assert_eq!(tracker.active_series_len(), 2 * families + 1);

    let stale: Vec<_> = decoder
        .decode_stream_with_staleness(&encode(&[]), &Format::PROTO_DELIM, &opts, &mut tracker)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(stale.len(), 2);
    assert_eq!(metric_types(&stale[1]), [4]);
    let mut counts = [0; 4];
    for chunk in &stale {
        counts
            .iter_mut()
            .zip(stale_counts(chunk))
            .for_each(|(s, c)| *s += c);
    }
    assert_eq!(counts, [1, 0, families, families]);
    assert!(tracker.is_empty());
}

#[test]
fn exemplar_and_start_timestamps_out_of_range() {
    let mut metric = counter(&[], 1.0, 0);
    metric.counter.as_mut().unwrap().exemplar = Some(dto::Exemplar {
        label: vec![],
        value: 1.0,
        timestamp: Some(prost_types::Timestamp {
            seconds: i64::MAX / 100,
            nanos: 0,
        }),
    });
    let input = encode(&[family(
        "c_total",
        "",
        dto::MetricType::Counter,
        vec![metric],
    )]);
    let err = decode(&input, &DecodeOptions::default()).unwrap_err();
    // The error saturates, where Go's `UnixMilli` would wrap to a small negative value.
    assert!(
        matches!(err, DecodeError::TimestampOverflow { timestamp_ms } if timestamp_ms == i64::MAX),
        "{err:?}"
    );

    // A start timestamp out of range is unset, like an out-of-range created timestamp.
    let mut metric = counter(&[], 1.0, 0);
    metric.counter.as_mut().unwrap().start_timestamp = Some(prost_types::Timestamp {
        seconds: i64::MAX / 100,
        nanos: 0,
    });
    let input = encode(&[family(
        "c_total",
        "",
        dto::MetricType::Counter,
        vec![metric],
    )]);
    let records = decode(&input, &DecodeOptions::default().with_timestamp_ms(1_000)).unwrap();
    let numbers = records.number_data_points().unwrap();
    assert!(
        numbers
            .column_by_name("start_time_unix_nano")
            .is_none_or(|column| column.is_null(0))
    );
}

#[test]
fn exemplar_label_named_metric_name_with_empty_value_is_dropped() {
    let mut metric = counter(&[], 1.0, 0);
    metric.counter.as_mut().unwrap().exemplar = Some(dto::Exemplar {
        label: labels(&[("__name__", ""), ("user", "a")]),
        value: 1.0,
        timestamp: Some(timestamp(1_000)),
    });
    let input = encode(&[family(
        "c_total",
        "",
        dto::MetricType::Counter,
        vec![metric],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    assert_eq!(
        strings(records.number_dp_exemplar_attrs().unwrap(), "key"),
        ["user"]
    );
}

#[test]
fn dropped_float_exponential_histograms_check_labels() {
    let mut metric = histogram_metric(
        &[("a", "1"), ("a", "2")],
        dto::Histogram {
            sample_count_float: 1.0,
            schema: 0,
            positive_span: vec![span(0, 1)],
            positive_count: vec![1.0],
            ..dto::Histogram::default()
        },
    );
    metric.timestamp_ms = 0;
    let input = encode(&[family("h", "", dto::MetricType::Histogram, vec![metric])]);
    let err = decode(&input, &DecodeOptions::default()).unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateLabel { .. }), "{err:?}");
}

#[test]
fn a_smaller_scrape_keeps_the_larger_scratch() {
    let large = tracked_families(&["1", "2", "3", "4", "5", "6", "7", "8"]);
    let opts = DecodeOptions::default();
    let mut decoder = ArrowDecoder::new();
    // A cursor started before the large scrape holds the empty scratch.
    let mut stale_cursor = decoder.start_decode(&Format::PROTO_DELIM, &opts).unwrap();
    decoder.decode(&large, &Format::PROTO_DELIM, &opts).unwrap();
    let retained = decoder.proto.retained_memory_bytes();
    assert!(retained > 0);
    decoder.finish_decode(&mut stale_cursor);
    assert_eq!(decoder.proto.retained_memory_bytes(), retained);
    // The decoded metrics of the last message are not kept between scrapes.
    assert!(decoder.proto.state.family_is_empty());
}

#[test]
fn units_are_kept_and_stripped_like_text() {
    let mut rpc = family(
        "rpc_seconds",
        "",
        dto::MetricType::Gauge,
        vec![gauge(&[], 1.0)],
    );
    rpc.unit = "seconds".to_owned();
    let input = encode(&[rpc]);
    for (policy, name) in [
        (UnitSuffixPolicy::Keep, "rpc_seconds"),
        (UnitSuffixPolicy::Strip, "rpc"),
    ] {
        let opts = DecodeOptions::default().with_unit_suffix_policy(policy);
        let records = decode(&input, &opts).unwrap();
        let metrics = records.univariate_metrics().unwrap();
        assert_eq!(strings(metrics, "name"), [name]);
        assert_eq!(strings(metrics, "unit"), ["seconds"]);
    }
}

#[test]
fn empty_families_count_against_the_decode_budget() {
    let mut messages = vec![family("empty", "", dto::MetricType::Gauge, vec![]); 3];
    messages.push(family(
        "g",
        "",
        dto::MetricType::Gauge,
        vec![gauge(&[], 1.0)],
    ));
    let input = encode(&messages);
    let mut decoder = ArrowDecoder::new();
    let mut cursor = decoder
        .start_decode(&Format::PROTO_DELIM, &DecodeOptions::default())
        .unwrap();
    let budget = DecodeBudget::default().with_max_entries(1);
    let mut pending = 0;
    let records = loop {
        match decoder.step_decode(&mut cursor, &input, budget).unwrap() {
            DecodeStep::Pending => pending += 1,
            DecodeStep::Batch(batch) => break batch,
            DecodeStep::Done => panic!("no batch"),
        }
    };
    // One step per empty message, then the gauge family's help, type, and series entries.
    assert_eq!(pending, 3 + 3);
    assert_eq!(records.num_data_points(), 1);
}

#[test]
fn classic_histograms_may_have_a_negative_infinity_bucket() {
    // Go's NHCB conversion keeps a `-Inf` bucket as the first custom bound, and its
    // `checkHistogramCustomBounds` accepts it.
    let input = encode(&[family(
        "h",
        "",
        dto::MetricType::Histogram,
        vec![classic_histogram(
            &[],
            &[(f64::NEG_INFINITY, 0), (1.0, 2)],
            2,
            1.0,
        )],
    )]);
    let records = decode(&input, &DecodeOptions::default()).unwrap();
    let points = records.histogram_data_points().unwrap();
    let bounds = points
        .column_by_name("explicit_bounds")
        .unwrap()
        .as_list::<i32>()
        .value(0);
    assert_eq!(
        bounds.as_primitive::<Float64Type>().values().to_vec(),
        [f64::NEG_INFINITY, 1.0]
    );
}
