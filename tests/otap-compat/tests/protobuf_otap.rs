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

//! Integration tests verifying protobuf decoding with native histograms in
//! `prometheus_expfmt::arrow::ArrowDecoder` against `otel-arrow-dfe-pdata` schema checks and OTLP
//! semantic equivalence.

use std::fs;
use std::path::Path;

use otel_arrow_dfe_pdata::otap::{Metrics, OtapArrowRecords, OtapBatchStore};
use otel_arrow_dfe_pdata::proto::OtlpProtoMessage;
use otel_arrow_dfe_pdata::proto::opentelemetry::arrow::v1::ArrowPayloadType;
use otel_arrow_dfe_pdata::proto::opentelemetry::common::v1::{AnyValue, KeyValue, any_value};
use otel_arrow_dfe_pdata::proto::opentelemetry::metrics::v1::{
    AggregationTemporality, Exemplar, ExponentialHistogram, ExponentialHistogramDataPoint,
    Histogram, HistogramDataPoint, Metric, NumberDataPoint, Sum, Summary, SummaryDataPoint,
    exemplar, exponential_histogram_data_point::Buckets, metric, number_data_point,
    summary_data_point::ValueAtQuantile,
};
use otel_arrow_dfe_pdata::schema::payloads;
use otel_arrow_dfe_pdata::testing::equiv::assert_equivalent;
use otel_arrow_dfe_pdata::testing::round_trip::{otap_to_otlp, to_metrics_data};
use prometheus_expfmt::arrow::{
    ArrowDecoder, DATA_POINT_FLAG_NO_RECORDED_VALUE, DecodeError, DecodeOptions, MetricPayloadType,
    OtapMetricRecords, PROMETHEUS_TYPE_METADATA_KEY, StalenessTracker,
};
use prometheus_expfmt::dto;
use prometheus_expfmt::format::Format;
use prost::Message;

fn to_otap_arrow_records(records: &OtapMetricRecords) -> OtapArrowRecords {
    let mut store = Metrics::new();
    for (payload_type, batch) in records.iter() {
        let wire_type = ArrowPayloadType::try_from(payload_type.as_i32())
            .expect("MetricPayloadType matches ArrowPayloadType wire discriminant");
        payloads::get(wire_type)
            .check_match(batch)
            .unwrap_or_else(|err| panic!("upstream OTAP schema rejected {payload_type:?}: {err}"));
        store
            .set(wire_type, batch.clone())
            .unwrap_or_else(|err| panic!("OTAP batch store rejected {payload_type:?}: {err}"));
    }
    OtapArrowRecords::Metrics(store)
}

/// Plain OTLP and OTLP after a transport-optimized ID encoding round trip.
fn to_otlp(records: &OtapMetricRecords) -> (OtlpProtoMessage, OtlpProtoMessage) {
    let mut otap = to_otap_arrow_records(records);
    let plain = otap_to_otlp(&otap);
    otap.encode_transport_optimized()
        .expect("transport optimize succeeds");
    otap.decode_transport_optimized_ids()
        .expect("transport decode IDs succeeds");
    (plain, otap_to_otlp(&otap))
}

fn kv_str(key: &str, val: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(val.to_owned())),
        }),
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

fn family(name: &str, help: &str, metric_type: dto::MetricType) -> dto::MetricFamily {
    dto::MetricFamily {
        name: name.to_owned(),
        help: help.to_owned(),
        r#type: metric_type as i32,
        metric: Vec::new(),
        unit: String::new(),
    }
}

fn span(offset: i32, length: u32) -> dto::BucketSpan {
    dto::BucketSpan { offset, length }
}

fn encode(families: &[dto::MetricFamily]) -> Vec<u8> {
    let mut buf = Vec::new();
    for family in families {
        family.encode_length_delimited(&mut buf).unwrap();
    }
    buf
}

const TS_MS: i64 = 1_710_000_000_000;
const TS_NS: u64 = 1_710_000_000_000_000_000;
const START_MS: i64 = 1_709_000_000_000;
const START_NS: u64 = 1_709_000_000_000_000_000;

fn trace_exemplar(value: f64, millis: i64) -> dto::Exemplar {
    dto::Exemplar {
        label: labels(&[
            ("trace_id", "0102030405060708090a0b0c0d0e0f10"),
            ("span_id", "1112131415161718"),
            ("user", "u1"),
        ]),
        value,
        timestamp: Some(timestamp(millis)),
    }
}

fn expected_exemplar(value: f64, millis: u64) -> Exemplar {
    Exemplar {
        filtered_attributes: vec![kv_str("user", "u1")],
        time_unix_nano: millis * 1_000_000,
        span_id: vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
        trace_id: (1..=16).collect(),
        value: Some(exemplar::Value::AsDouble(value)),
    }
}

/// Payload covering every protobuf metric type, native histograms with both sides, gaps,
/// overflow and stale points, a classic histogram (converted to NHCB), and a family mixing both
/// histogram kinds.
fn payload() -> Vec<u8> {
    let mut counter = family("calls_total", "Total calls.", dto::MetricType::Counter);
    counter.metric.push(dto::Metric {
        label: labels(&[("env", "prod")]),
        counter: Some(dto::Counter {
            value: 15.0,
            exemplar: Some(trace_exemplar(1.0, TS_MS - 1_000)),
            start_timestamp: Some(timestamp(START_MS)),
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });

    let mut summary = family("rpc_seconds", "RPC quantiles.", dto::MetricType::Summary);
    summary.unit = "seconds".to_owned();
    summary.metric.push(dto::Metric {
        label: labels(&[("service", "auth")]),
        summary: Some(dto::Summary {
            sample_count: 100,
            sample_sum: 4.5,
            quantile: vec![
                dto::Quantile {
                    quantile: 0.5,
                    value: 0.02,
                },
                dto::Quantile {
                    quantile: 0.99,
                    value: 0.15,
                },
            ],
            start_timestamp: Some(timestamp(START_MS)),
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });

    let mut native = family(
        "req_seconds",
        "Request latency.",
        dto::MetricType::Histogram,
    );
    native.metric.push(dto::Metric {
        label: labels(&[("route", "/a")]),
        histogram: Some(dto::Histogram {
            // 1 zero, 2 + 3 + 1 positive, 4 negative, plus 5 in the +Inf overflow bucket at
            // schema 0 index 1025, which is dropped.
            sample_count: 16,
            sample_sum: 12.5,
            schema: 0,
            zero_threshold: 1e-128,
            zero_count: 1,
            positive_span: vec![span(-1, 2), span(2, 1), span(1023, 1)],
            positive_delta: vec![2, 1, -2, 4],
            negative_span: vec![span(3, 1)],
            negative_delta: vec![4],
            exemplars: vec![trace_exemplar(0.5, TS_MS - 500)],
            start_timestamp: Some(timestamp(START_MS)),
            ..dto::Histogram::default()
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });
    native.metric.push(dto::Metric {
        label: labels(&[("route", "/stale")]),
        histogram: Some(dto::Histogram {
            sample_count: 1,
            sample_sum: f64::from_bits(0x7ff0_0000_0000_0002),
            schema: 2,
            zero_threshold: 1e-128,
            zero_count: 1,
            ..dto::Histogram::default()
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });

    let mut mixed = family("mixed_seconds", "Mixed.", dto::MetricType::Histogram);
    mixed.metric.push(dto::Metric {
        label: labels(&[("kind", "classic")]),
        histogram: Some(dto::Histogram {
            sample_count: 3,
            sample_sum: 1.5,
            bucket: vec![
                dto::Bucket {
                    upper_bound: 0.1,
                    cumulative_count: 1,
                    exemplar: Some(trace_exemplar(0.05, TS_MS - 200)),
                    ..dto::Bucket::default()
                },
                dto::Bucket {
                    upper_bound: 1.0,
                    cumulative_count: 1,
                    ..dto::Bucket::default()
                },
                dto::Bucket {
                    upper_bound: 10.0,
                    cumulative_count: 2,
                    // Skipped, like every protobuf histogram exemplar without a timestamp.
                    exemplar: Some(dto::Exemplar {
                        timestamp: None,
                        ..trace_exemplar(5.0, 0)
                    }),
                    ..dto::Bucket::default()
                },
            ],
            ..dto::Histogram::default()
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });
    mixed.metric.push(dto::Metric {
        label: labels(&[("kind", "native")]),
        histogram: Some(dto::Histogram {
            sample_count: 2,
            sample_sum: 0.5,
            schema: 8,
            zero_threshold: 1e-128,
            positive_span: vec![span(0, 1)],
            positive_delta: vec![2],
            ..dto::Histogram::default()
        }),
        timestamp_ms: TS_MS,
        ..dto::Metric::default()
    });

    encode(&[counter, summary, native, mixed])
}

fn histogram_metadata() -> Vec<KeyValue> {
    vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "histogram")]
}

fn expected() -> OtlpProtoMessage {
    let cumulative = AggregationTemporality::Cumulative as i32;
    OtlpProtoMessage::Metrics(to_metrics_data(vec![
        Metric {
            name: "calls_total".to_owned(),
            description: "Total calls.".to_owned(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: cumulative,
                is_monotonic: true,
                data_points: vec![NumberDataPoint {
                    attributes: vec![kv_str("env", "prod")],
                    start_time_unix_nano: START_NS,
                    time_unix_nano: TS_NS,
                    exemplars: vec![expected_exemplar(1.0, TS_MS as u64 - 1_000)],
                    flags: 0,
                    value: Some(number_data_point::Value::AsDouble(15.0)),
                }],
            })),
        },
        Metric {
            name: "rpc_seconds".to_owned(),
            description: "RPC quantiles.".to_owned(),
            unit: "seconds".to_owned(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "summary")],
            data: Some(metric::Data::Summary(Summary {
                data_points: vec![SummaryDataPoint {
                    attributes: vec![kv_str("service", "auth")],
                    start_time_unix_nano: START_NS,
                    time_unix_nano: TS_NS,
                    count: 100,
                    sum: 4.5,
                    quantile_values: vec![
                        ValueAtQuantile {
                            quantile: 0.5,
                            value: 0.02,
                        },
                        ValueAtQuantile {
                            quantile: 0.99,
                            value: 0.15,
                        },
                    ],
                    flags: 0,
                }],
            })),
        },
        Metric {
            name: "req_seconds".to_owned(),
            description: "Request latency.".to_owned(),
            unit: String::new(),
            metadata: histogram_metadata(),
            data: Some(metric::Data::ExponentialHistogram(ExponentialHistogram {
                aggregation_temporality: cumulative,
                data_points: vec![
                    ExponentialHistogramDataPoint {
                        attributes: vec![kv_str("route", "/a")],
                        start_time_unix_nano: START_NS,
                        time_unix_nano: TS_NS,
                        count: 11,
                        sum: Some(12.5),
                        scale: 0,
                        zero_count: 1,
                        zero_threshold: 1e-128,
                        // Prometheus indexes -1, 0, and 3, as OTel offset -2.
                        positive: Some(Buckets {
                            offset: -2,
                            bucket_counts: vec![2, 3, 0, 0, 1],
                        }),
                        negative: Some(Buckets {
                            offset: 2,
                            bucket_counts: vec![4],
                        }),
                        flags: 0,
                        exemplars: vec![expected_exemplar(0.5, TS_MS as u64 - 500)],
                        min: None,
                        max: None,
                    },
                    ExponentialHistogramDataPoint {
                        attributes: vec![kv_str("route", "/stale")],
                        start_time_unix_nano: 0,
                        time_unix_nano: TS_NS,
                        // Like the stale points the tracker writes: no sum, and zero scale
                        // and zero threshold.
                        count: 0,
                        sum: None,
                        scale: 0,
                        zero_count: 0,
                        zero_threshold: 0.0,
                        positive: Some(Buckets {
                            offset: 0,
                            bucket_counts: Vec::new(),
                        }),
                        negative: Some(Buckets {
                            offset: 0,
                            bucket_counts: Vec::new(),
                        }),
                        flags: 1,
                        exemplars: Vec::new(),
                        min: None,
                        max: None,
                    },
                ],
            })),
        },
        Metric {
            name: "mixed_seconds".to_owned(),
            description: "Mixed.".to_owned(),
            unit: String::new(),
            metadata: histogram_metadata(),
            data: Some(metric::Data::Histogram(Histogram {
                aggregation_temporality: cumulative,
                data_points: vec![HistogramDataPoint {
                    attributes: vec![kv_str("kind", "classic")],
                    start_time_unix_nano: 0,
                    time_unix_nano: TS_NS,
                    count: 3,
                    sum: Some(1.5),
                    bucket_counts: vec![1, 0, 1, 1],
                    explicit_bounds: vec![0.1, 1.0, 10.0],
                    exemplars: vec![expected_exemplar(0.05, TS_MS as u64 - 200)],
                    flags: 0,
                    min: None,
                    max: None,
                }],
            })),
        },
        Metric {
            name: "mixed_seconds".to_owned(),
            description: "Mixed.".to_owned(),
            unit: String::new(),
            metadata: histogram_metadata(),
            data: Some(metric::Data::ExponentialHistogram(ExponentialHistogram {
                aggregation_temporality: cumulative,
                data_points: vec![ExponentialHistogramDataPoint {
                    attributes: vec![kv_str("kind", "native")],
                    start_time_unix_nano: 0,
                    time_unix_nano: TS_NS,
                    count: 2,
                    sum: Some(0.5),
                    scale: 8,
                    zero_count: 0,
                    zero_threshold: 1e-128,
                    positive: Some(Buckets {
                        offset: -1,
                        bucket_counts: vec![2],
                    }),
                    negative: Some(Buckets {
                        offset: 0,
                        bucket_counts: Vec::new(),
                    }),
                    flags: 0,
                    exemplars: Vec::new(),
                    min: None,
                    max: None,
                }],
            })),
        },
    ]))
}

#[test]
fn protobuf_native_histograms_round_trip_through_otap_and_otlp() {
    let decoded = ArrowDecoder::new()
        .decode(&payload(), &Format::PROTO_DELIM, &DecodeOptions::new())
        .expect("protobuf payload decodes");
    assert_eq!(decoded.num_metrics(), 5);
    for payload_type in [
        MetricPayloadType::ExpHistogramDataPoints,
        MetricPayloadType::ExpHistogramDpAttrs,
        MetricPayloadType::ExpHistogramDpExemplars,
        MetricPayloadType::ExpHistogramDpExemplarAttrs,
    ] {
        assert!(decoded.get(payload_type).is_some(), "{payload_type:?}");
    }

    let (plain, round_tripped) = to_otlp(&decoded);
    let expected = expected();
    assert_equivalent(std::slice::from_ref(&expected), &[plain]);
    assert_equivalent(&[expected], &[round_tripped]);
}

#[test]
fn protobuf_decode_stream_chunks_validate_in_otap() {
    let payload = payload();
    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new().with_max_data_points_per_batch(1);
    let mut streamed = Vec::new();
    for chunk in decoder.decode_stream(&payload, &Format::PROTO_DELIM, &opts) {
        let chunk = chunk.expect("streamed chunk decodes");
        assert_eq!(chunk.num_data_points(), 1);
        streamed.push(to_otlp(&chunk).1);
    }
    assert_eq!(streamed.len(), 6);
    assert_equivalent(&[expected()], &streamed);
}

#[test]
fn protobuf_stale_points_validate_in_otap_and_otlp() {
    // The payload's points have explicit timestamps.
    let opts = DecodeOptions::new()
        .with_timestamp_ms(TS_MS + 15_000)
        .with_track_timestamps_staleness(true);
    let mut decoder = ArrowDecoder::new();
    let mut tracker = StalenessTracker::new();
    decoder
        .decode_with_staleness(&payload(), &Format::PROTO_DELIM, &opts, &mut tracker)
        .expect("protobuf payload decodes");
    let stale = decoder
        .decode_with_staleness(&[], &Format::PROTO_DELIM, &opts, &mut tracker)
        .expect("empty scrape decodes");
    assert!(
        stale
            .get(MetricPayloadType::ExpHistogramDataPoints)
            .is_some()
    );

    let (plain, round_tripped) = to_otlp(&stale);
    for message in [plain, round_tripped] {
        let OtlpProtoMessage::Metrics(data) = message else {
            panic!("expected OTLP MetricsData");
        };
        let metrics = &data.resource_metrics[0].scope_metrics[0].metrics;
        let mut exponential = 0;
        for m in metrics {
            let flags: Vec<u32> = match &m.data {
                Some(metric::Data::Sum(s)) => s.data_points.iter().map(|p| p.flags).collect(),
                Some(metric::Data::Summary(s)) => s.data_points.iter().map(|p| p.flags).collect(),
                Some(metric::Data::Histogram(h)) => h.data_points.iter().map(|p| p.flags).collect(),
                Some(metric::Data::ExponentialHistogram(h)) => {
                    exponential += h.data_points.len();
                    for p in &h.data_points {
                        assert_eq!(
                            (p.count, p.zero_count, p.scale, p.zero_threshold, p.sum),
                            (0, 0, 0, 0.0, None)
                        );
                        for side in [&p.positive, &p.negative] {
                            assert!(
                                side.as_ref()
                                    .is_none_or(|b| b.offset == 0 && b.bucket_counts.is_empty())
                            );
                        }
                    }
                    h.data_points.iter().map(|p| p.flags).collect()
                }
                other => panic!("unexpected metric data: {other:?}"),
            };
            assert!(!flags.is_empty(), "{}", m.name);
            for flag in flags {
                assert_eq!(flag, DATA_POINT_FLAG_NO_RECORDED_VALUE, "{}", m.name);
            }
        }
        // `/a` and `kind="native"`. `/stale` already ended with its input stale marker.
        assert_eq!(exponential, 2);
    }
}

#[test]
fn decodes_go_protobuf_fixtures_into_valid_otap() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");

    // Go's parser fixture has native histograms whose buckets do not add up to their count.
    // Go's parser tests never run `Validate`, but a Prometheus scrape fails on them when the
    // TSDB appends them, so the decoder fails the scrape too.
    let input = fs::read(root.join("textparse/TestProtobufParse.pb")).unwrap();
    let err = ArrowDecoder::new()
        .decode(&input, &Format::PROTO_DELIM, &DecodeOptions::new())
        .unwrap_err();
    assert!(
        matches!(&err, DecodeError::InvalidHistogram { metric, .. } if metric == "test_histogram"),
        "{err:?}"
    );

    for fixture in [
        "textparse/TestProtobufParseWithNHCB.pb",
        "nhcb/conversion.pb",
        "expfmt/protobuf",
        "expfmt/protobuf-multimessage",
    ] {
        let input = fs::read(root.join(fixture)).unwrap();
        let mut decoder = ArrowDecoder::new();
        let opts = DecodeOptions::new().with_timestamp_ms(1_700_000_000_000);
        let decoded = decoder
            .decode(&input, &Format::PROTO_DELIM, &opts)
            .unwrap_or_else(|err| panic!("{fixture}: {err}"));
        assert!(!decoded.is_empty(), "{fixture}");
        let single = otap_to_otlp(&to_otap_arrow_records(&decoded));

        let stream_opts = opts.with_max_data_points_per_batch(3);
        let streamed: Vec<_> = decoder
            .decode_stream(&input, &Format::PROTO_DELIM, &stream_opts)
            .map(|chunk| to_otlp(&chunk.unwrap()).1)
            .collect();
        assert_equivalent(&[single], &streamed);
    }
}

#[test]
fn go_nhcb_fixture_drops_float_histograms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let input = fs::read(root.join("nhcb/conversion.pb")).unwrap();
    let decoded = ArrowDecoder::new()
        .decode(&input, &Format::PROTO_DELIM, &DecodeOptions::new())
        .unwrap();
    let OtlpProtoMessage::Metrics(data) = to_otlp(&decoded).0 else {
        panic!("expected OTLP MetricsData");
    };
    let names: Vec<_> = data.resource_metrics[0].scope_metrics[0]
        .metrics
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    // `mixed` keeps its 3 integer points, in an NHCB row and an exponential row, and drops its
    // 3 float points.
    assert_eq!(names, ["int_empty_runs", "mixed", "mixed"]);
    assert_eq!(decoded.num_data_points(), 6);
}
