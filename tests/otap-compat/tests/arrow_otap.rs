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

//! Integration tests verifying `expfmt::arrow::ArrowDecoder` against `otel-arrow-dfe-pdata`
//! schema checks, transport-optimized ID encoding and decoding, and OTLP semantic equivalence.

use std::fs;
use std::path::Path;

use expfmt::arrow::{
    ArrowDecoder, CounterSuffixPolicy, DecodeError, DecodeOptions, MetricPayloadType,
    OtapMetricRecords, PROMETHEUS_TYPE_METADATA_KEY, UnitSuffixPolicy, UntypedPolicy,
};
use expfmt::format::Format;
use otel_arrow_dfe_pdata::otap::{Metrics, OtapArrowRecords, OtapBatchStore};
use otel_arrow_dfe_pdata::proto::OtlpProtoMessage;
use otel_arrow_dfe_pdata::proto::opentelemetry::arrow::v1::ArrowPayloadType;
use otel_arrow_dfe_pdata::proto::opentelemetry::common::v1::{AnyValue, KeyValue, any_value};
use otel_arrow_dfe_pdata::proto::opentelemetry::metrics::v1::{
    AggregationTemporality, Exemplar, Gauge, Histogram, HistogramDataPoint, Metric,
    NumberDataPoint, Sum, Summary, SummaryDataPoint, exemplar, metric, number_data_point,
    summary_data_point::ValueAtQuantile,
};
use otel_arrow_dfe_pdata::schema::{
    consts, is_id_plain_encoded, is_parent_id_plain_encoded, payloads,
};
use otel_arrow_dfe_pdata::testing::equiv::assert_equivalent;
use otel_arrow_dfe_pdata::testing::round_trip::{otap_to_otlp, to_metrics_data};

fn assert_matches_otap_schema(records: &OtapMetricRecords) {
    for (payload_type, batch) in records.iter() {
        let wire_type = ArrowPayloadType::try_from(payload_type.as_i32())
            .expect("MetricPayloadType matches ArrowPayloadType wire discriminant");
        payloads::get(wire_type)
            .check_match(batch)
            .unwrap_or_else(|err| panic!("upstream OTAP schema rejected {payload_type:?}: {err}"));

        let schema = batch.schema();
        if schema.index_of(consts::ID).is_ok() {
            assert!(
                is_id_plain_encoded(batch),
                "{payload_type:?} id column must carry plain encoding metadata"
            );
        }
        if schema.index_of(consts::PARENT_ID).is_ok() {
            assert!(
                is_parent_id_plain_encoded(batch),
                "{payload_type:?} parent_id column must carry plain encoding metadata"
            );
        }
    }
}

fn to_otap_arrow_records(records: &OtapMetricRecords) -> OtapArrowRecords {
    assert_matches_otap_schema(records);
    let mut store = Metrics::new();
    for (payload_type, batch) in records.iter() {
        let wire_type = ArrowPayloadType::try_from(payload_type.as_i32())
            .expect("MetricPayloadType matches ArrowPayloadType wire discriminant");
        store
            .set(wire_type, batch.clone())
            .unwrap_or_else(|err| panic!("OTAP batch store rejected {payload_type:?}: {err}"));
    }
    OtapArrowRecords::Metrics(store)
}

fn kv_str(key: &str, val: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(val.to_owned())),
        }),
    }
}

fn number_dp(attrs: &[(&str, &str)], time_unix_nano: u64, val: f64) -> NumberDataPoint {
    NumberDataPoint {
        attributes: attrs.iter().map(|&(k, v)| kv_str(k, v)).collect(),
        start_time_unix_nano: 0,
        time_unix_nano,
        exemplars: Vec::new(),
        flags: 0,
        value: Some(number_data_point::Value::AsDouble(val)),
    }
}

#[test]
fn metric_payload_type_discriminants_match_otap_proto() {
    let cases = [
        (
            MetricPayloadType::UnivariateMetrics,
            ArrowPayloadType::UnivariateMetrics,
        ),
        (
            MetricPayloadType::NumberDataPoints,
            ArrowPayloadType::NumberDataPoints,
        ),
        (
            MetricPayloadType::SummaryDataPoints,
            ArrowPayloadType::SummaryDataPoints,
        ),
        (
            MetricPayloadType::HistogramDataPoints,
            ArrowPayloadType::HistogramDataPoints,
        ),
        (
            MetricPayloadType::NumberDpAttrs,
            ArrowPayloadType::NumberDpAttrs,
        ),
        (
            MetricPayloadType::SummaryDpAttrs,
            ArrowPayloadType::SummaryDpAttrs,
        ),
        (
            MetricPayloadType::HistogramDpAttrs,
            ArrowPayloadType::HistogramDpAttrs,
        ),
        (
            MetricPayloadType::NumberDpExemplars,
            ArrowPayloadType::NumberDpExemplars,
        ),
        (
            MetricPayloadType::HistogramDpExemplars,
            ArrowPayloadType::HistogramDpExemplars,
        ),
        (
            MetricPayloadType::NumberDpExemplarAttrs,
            ArrowPayloadType::NumberDpExemplarAttrs,
        ),
        (
            MetricPayloadType::HistogramDpExemplarAttrs,
            ArrowPayloadType::HistogramDpExemplarAttrs,
        ),
        (
            MetricPayloadType::MetricAttrs,
            ArrowPayloadType::MetricAttrs,
        ),
    ];
    for (local, upstream) in cases {
        assert_eq!(local.as_i32(), upstream as i32);
        assert_eq!(ArrowPayloadType::try_from(local.as_i32()), Ok(upstream));
    }
}

#[test]
fn adaptive_schema_variants_match_upstream_otap_schema_definitions() {
    let mut decoder = ArrowDecoder::new();

    // Minimal schema: no description, no counter columns, no dp id, no timestamps.
    let minimal = decoder
        .decode(b"bare_gauge 1\n", &Format::TEXT, &DecodeOptions::new())
        .expect("minimal payload decodes");
    assert_matches_otap_schema(&minimal);

    // Mixed explicit and omitted timestamps (nullable `time_unix_nano` when fallback is `None`).
    let mixed_ts = decoder
        .decode(
            b"m_ts{a=\"1\"} 1 1700000000000\nm_ts{a=\"2\"} 2\n",
            &Format::TEXT,
            &DecodeOptions::new(),
        )
        .expect("mixed timestamp payload decodes");
    assert_matches_otap_schema(&mixed_ts);

    // >256 distinct label keys upgrades `NumberDpAttrs.key` from `Dict(UInt8)` to `Dict(UInt16)`.
    let mut wide_keys = String::from("# TYPE wide_total counter\n");
    for i in 0..260 {
        wide_keys.push_str(&format!("wide_total{{k_{i}=\"v\"}} {i}\n"));
    }
    let wide = decoder
        .decode(wide_keys.as_bytes(), &Format::TEXT, &DecodeOptions::new())
        .expect("wide key payload decodes");
    assert_matches_otap_schema(&wide);
}

#[test]
fn counter_gauge_and_untyped_round_trip_through_otap_and_otlp() {
    let payload = concat!(
        "# HELP http_requests_total Total HTTP requests.\\nLine two\\\\end.\n",
        "# TYPE http_requests_total counter\n",
        "http_requests_total{status=\"200\",method=\"GET\"} 42 1700000000123\n",
        "http_requests_total{method=\"POST\",status=\"500\",empty=\"\"} 3\n",
        "http_requests_total{method=\"DELETE\",status=\"204\"} 1 1700000000999\n",
        "# HELP memory_bytes Resident memory in bytes.\n",
        "# TYPE memory_bytes gauge\n",
        "memory_bytes{empty=\"\"} 1048576\n",
        "# HELP bare_empty_help\n",
        "# HELP bare_empty_help \n",
        "# TYPE explicit_untyped untyped\n",
        "explicit_untyped{env=\"prod\"} -12.5 0\n",
        "implicit_untyped +Inf\n",
        "# HELP \"utf8.metric\\\"name\\\\\\n\" Quoted UTF-8 metric with escapes.\n",
        "# TYPE \"utf8.metric\\\"name\\\\\\n\" counter\n",
        "{ \"utf8.metric\\\"name\\\\\\n\", \"k.1©\\\"\"=\"v\\\"\\\\\\n1\" } 7.5\n",
        // Metadata-only family with zero samples must be omitted.
        "# HELP zero_samples_total Unused family.\n",
        "# TYPE zero_samples_total counter\n",
    );

    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new().with_timestamp_ms(1_700_000_000_000);
    let decoded = decoder
        .decode(payload.as_bytes(), &Format::TEXT, &opts)
        .expect("decode succeeds");

    assert_eq!(decoded.num_metrics(), 5);
    assert_eq!(decoded.num_data_points(), 7);
    assert!(decoded.get(MetricPayloadType::UnivariateMetrics).is_some());
    assert!(decoded.get(MetricPayloadType::MetricAttrs).is_some());
    assert!(decoded.get(MetricPayloadType::NumberDataPoints).is_some());
    assert!(decoded.get(MetricPayloadType::NumberDpAttrs).is_some());

    let mut otap = to_otap_arrow_records(&decoded);
    let plain_otlp = otap_to_otlp(&otap);

    // Verify transport-optimized delta and quasi-delta ID encoding and decoding round-trip.
    otap.encode_transport_optimized()
        .expect("transport optimize succeeds");
    otap.decode_transport_optimized_ids()
        .expect("transport decode IDs succeeds");
    let round_tripped_otlp = otap_to_otlp(&otap);

    let default_ns = 1_700_000_000_000_000_000_u64;
    let expected = OtlpProtoMessage::Metrics(to_metrics_data(vec![
        Metric {
            name: "http_requests_total".to_owned(),
            description: "Total HTTP requests.\nLine two\\end.".to_owned(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![
                    number_dp(
                        &[("method", "GET"), ("status", "200")],
                        1_700_000_000_123_000_000,
                        42.0,
                    ),
                    number_dp(&[("method", "POST"), ("status", "500")], default_ns, 3.0),
                    number_dp(
                        &[("method", "DELETE"), ("status", "204")],
                        1_700_000_000_999_000_000,
                        1.0,
                    ),
                ],
            })),
        },
        Metric {
            name: "memory_bytes".to_owned(),
            description: "Resident memory in bytes.".to_owned(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "gauge")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[], default_ns, 1_048_576.0)],
            })),
        },
        Metric {
            name: "explicit_untyped".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "unknown")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[("env", "prod")], 0, -12.5)],
            })),
        },
        Metric {
            name: "implicit_untyped".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "unknown")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[], default_ns, f64::INFINITY)],
            })),
        },
        Metric {
            name: "utf8.metric\"name\\\n".to_owned(),
            description: "Quoted UTF-8 metric with escapes.".to_owned(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![number_dp(&[("k.1©\"", "v\"\\\n1")], default_ns, 7.5)],
            })),
        },
    ]));

    assert_equivalent(std::slice::from_ref(&expected), &[plain_otlp]);
    assert_equivalent(&[expected], &[round_tripped_otlp]);
}

#[test]
fn histograms_summaries_exemplars_and_openmetrics_types_round_trip_through_otlp() {
    let payload = concat!(
        "# HELP req_seconds Request latency.\n",
        "# TYPE req_seconds histogram\n",
        "# UNIT req_seconds seconds\n",
        "req_seconds_bucket{route=\"/a\",le=\"0.1\"} 2 1710000000.0 # {trace_id=\"0102030405060708090a0b0c0d0e0f10\",span_id=\"1112131415161718\",user=\"u1\"} 0.05 1709999999.5\n",
        "req_seconds_bucket{route=\"/a\",le=\"0.5\"} 5 1710000000.0\n",
        "req_seconds_bucket{route=\"/a\",le=\"+Inf\"} 6 1710000000.0\n",
        "req_seconds_sum{route=\"/a\"} 1.25 1710000000.0\n",
        "req_seconds_count{route=\"/a\"} 6 1710000000.0\n",
        "req_seconds_created{route=\"/a\"} 1709000000.0\n",
        "# HELP rpc_seconds RPC duration quantiles.\n",
        "# TYPE rpc_seconds summary\n",
        "# UNIT rpc_seconds seconds\n",
        "rpc_seconds{service=\"auth\",quantile=\"0.5\"} 0.02 1710000000.0\n",
        "rpc_seconds{service=\"auth\",quantile=\"0.99\"} 0.15 1710000000.0\n",
        "rpc_seconds_sum{service=\"auth\"} 4.5 1710000000.0\n",
        "rpc_seconds_count{service=\"auth\"} 100 1710000000.0\n",
        "rpc_seconds_created{service=\"auth\"} 1709000000.0\n",
        "# HELP calls_total Total calls.\n",
        "# TYPE calls counter\n",
        "calls_total{env=\"prod\"} 15 1710000000.0 # {trace_id=\"non-hex-id\"} 1.0 1709999999.0\n",
        "calls_created{env=\"prod\"} 1709000000.0\n",
        "# HELP target_info Target metadata.\n",
        "# TYPE target info\n",
        "target_info{version=\"1.2.3\"} 1 1710000000.0\n",
        "# HELP modeFeature Feature state.\n",
        "# TYPE modeFeature stateset\n",
        "modeFeature{modeFeature=\"enabled\"} 1 1710000000.0\n",
        "# EOF\n",
    );

    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new();
    let decoded = decoder
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .expect("OpenMetrics payload decodes");

    assert_eq!(decoded.num_metrics(), 5);
    assert_eq!(decoded.num_data_points(), 5);
    assert!(decoded.summary_data_points().is_some());
    assert!(decoded.histogram_data_points().is_some());
    assert!(decoded.summary_dp_attrs().is_some());
    assert!(decoded.histogram_dp_attrs().is_some());
    assert!(decoded.number_dp_exemplars().is_some());
    assert!(decoded.histogram_dp_exemplars().is_some());
    assert!(decoded.number_dp_exemplar_attrs().is_some());
    assert!(decoded.histogram_dp_exemplar_attrs().is_some());

    let mut otap = to_otap_arrow_records(&decoded);
    let plain_otlp = otap_to_otlp(&otap);

    otap.encode_transport_optimized()
        .expect("transport optimize succeeds");
    otap.decode_transport_optimized_ids()
        .expect("transport decode IDs succeeds");
    let round_tripped_otlp = otap_to_otlp(&otap);

    let ts_ns = 1_710_000_000_000_000_000_u64;
    let start_ns = 1_709_000_000_000_000_000_u64;
    let expected = OtlpProtoMessage::Metrics(to_metrics_data(vec![
        Metric {
            name: "req_seconds".to_owned(),
            description: "Request latency.".to_owned(),
            unit: "seconds".to_owned(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "histogram")],
            data: Some(metric::Data::Histogram(Histogram {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                data_points: vec![HistogramDataPoint {
                    attributes: vec![kv_str("route", "/a")],
                    start_time_unix_nano: start_ns,
                    time_unix_nano: ts_ns,
                    count: 6,
                    sum: Some(1.25),
                    bucket_counts: vec![2, 3, 1],
                    explicit_bounds: vec![0.1, 0.5],
                    exemplars: vec![Exemplar {
                        filtered_attributes: vec![kv_str("user", "u1")],
                        time_unix_nano: 1_709_999_999_500_000_000,
                        span_id: vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
                        trace_id: vec![
                            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                            0x0d, 0x0e, 0x0f, 0x10,
                        ],
                        value: Some(exemplar::Value::AsDouble(0.05)),
                    }],
                    flags: 0,
                    min: None,
                    max: None,
                }],
            })),
        },
        Metric {
            name: "rpc_seconds".to_owned(),
            description: "RPC duration quantiles.".to_owned(),
            unit: "seconds".to_owned(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "summary")],
            data: Some(metric::Data::Summary(Summary {
                data_points: vec![SummaryDataPoint {
                    attributes: vec![kv_str("service", "auth")],
                    start_time_unix_nano: start_ns,
                    time_unix_nano: ts_ns,
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
            name: "calls_total".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![NumberDataPoint {
                    attributes: vec![kv_str("env", "prod")],
                    start_time_unix_nano: start_ns,
                    time_unix_nano: ts_ns,
                    exemplars: vec![Exemplar {
                        filtered_attributes: vec![kv_str("trace_id", "non-hex-id")],
                        time_unix_nano: 1_709_999_999_000_000_000,
                        span_id: Vec::new(),
                        trace_id: Vec::new(),
                        value: Some(exemplar::Value::AsDouble(1.0)),
                    }],
                    flags: 0,
                    value: Some(number_data_point::Value::AsDouble(15.0)),
                }],
            })),
        },
        Metric {
            name: "target".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "info")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[("version", "1.2.3")], ts_ns, 1.0)],
            })),
        },
        Metric {
            name: "modeFeature".to_owned(),
            description: "Feature state.".to_owned(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "stateset")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[("modeFeature", "enabled")], ts_ns, 1.0)],
            })),
        },
    ]));

    assert_equivalent(std::slice::from_ref(&expected), &[plain_otlp]);
    assert_equivalent(&[expected], &[round_tripped_otlp]);
}

#[test]
fn gaugehistogram_unsorted_bounds_nullable_sums_and_exemplar_nulls_validate_in_otap() {
    // 1. OpenMetrics `gaugehistogram` with `_bucket`, `_gsum`, `_gcount`, unsorted
    //    `le` buckets, ignored `le="-Inf"`, multiple exemplars with mixed `span_id`/`trace_id`
    //    presence and uppercase hex digits, plus a second series omitting `_gsum` so
    //    `histogram_sum` is nullable.
    let om_payload = concat!(
        "# TYPE queue_bytes gaugehistogram\n",
        "queue_bytes_bucket{shard=\"0\",le=\"10\"} 5 1710000000.0 # {trace_id=\"0102030405060708090A0B0C0D0E0F10\",k=\"v1\"} 8.0 1709999999.0\n",
        "queue_bytes_bucket{shard=\"0\",le=\"1\"} 2 1710000000.0 # {span_id=\"ABCDEF0123456789\",k=\"v2\"} 0.5 1709999998.0\n",
        "queue_bytes_bucket{shard=\"0\",le=\"-Inf\"} 99 1710000000.0\n",
        "queue_bytes_bucket{shard=\"0\",le=\"+Inf\"} 6 1710000000.0\n",
        "queue_bytes_gsum{shard=\"0\"} 42.0 1710000000.0\n",
        "queue_bytes_gcount{shard=\"0\"} 6 1710000000.0\n",
        "queue_bytes_bucket{shard=\"1\",le=\"+Inf\"} 3 1710000000.0\n",
        "# EOF\n",
    );

    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new();
    let om_records = decoder
        .decode(om_payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .expect("gaugehistogram OpenMetrics payload decodes");

    assert_eq!(om_records.num_metrics(), 1);
    assert_eq!(om_records.num_data_points(), 2);

    let mut om_otap = to_otap_arrow_records(&om_records);
    let om_plain = otap_to_otlp(&om_otap);
    om_otap
        .encode_transport_optimized()
        .expect("gaugehistogram transport optimize succeeds");
    om_otap
        .decode_transport_optimized_ids()
        .expect("gaugehistogram transport decode succeeds");
    let om_round_tripped = otap_to_otlp(&om_otap);

    let ts_ns = 1_710_000_000_000_000_000_u64;
    let om_expected = OtlpProtoMessage::Metrics(to_metrics_data(vec![Metric {
        name: "queue_bytes".to_owned(),
        description: String::new(),
        unit: String::new(),
        metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "gaugehistogram")],
        data: Some(metric::Data::Histogram(Histogram {
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            data_points: vec![
                HistogramDataPoint {
                    attributes: vec![kv_str("shard", "0")],
                    start_time_unix_nano: 0,
                    time_unix_nano: ts_ns,
                    count: 6,
                    sum: Some(42.0),
                    bucket_counts: vec![2, 3, 1],
                    explicit_bounds: vec![1.0, 10.0],
                    exemplars: vec![
                        Exemplar {
                            filtered_attributes: vec![kv_str("k", "v1")],
                            time_unix_nano: 1_709_999_999_000_000_000,
                            span_id: Vec::new(),
                            trace_id: vec![
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                            ],
                            value: Some(exemplar::Value::AsDouble(8.0)),
                        },
                        Exemplar {
                            filtered_attributes: vec![kv_str("k", "v2")],
                            time_unix_nano: 1_709_999_998_000_000_000,
                            span_id: vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89],
                            trace_id: Vec::new(),
                            value: Some(exemplar::Value::AsDouble(0.5)),
                        },
                    ],
                    flags: 0,
                    min: None,
                    max: None,
                },
                HistogramDataPoint {
                    attributes: vec![kv_str("shard", "1")],
                    start_time_unix_nano: 0,
                    time_unix_nano: ts_ns,
                    count: 3,
                    sum: None,
                    bucket_counts: vec![3],
                    explicit_bounds: Vec::new(),
                    exemplars: Vec::new(),
                    flags: 0,
                    min: None,
                    max: None,
                },
            ],
        })),
    }]));
    assert_equivalent(std::slice::from_ref(&om_expected), &[om_plain]);
    assert_equivalent(&[om_expected], &[om_round_tripped]);

    // 2. Prometheus text format (`Format::TEXT`) with unsorted histogram bounds, unsorted summary
    //    quantiles, ignored non-finite quantile bounds (`+Inf`, `-Inf`, `NaN`), and `*_created`
    //    lines treated as regular metrics rather than OpenMetrics start timestamps.
    let text_payload = concat!(
        "# TYPE c counter\n",
        "c_total{id=\"a\"} 10 1710000000000\n",
        "c_total{id=\"b\"} 20 1710000000000\n",
        "c_created{id=\"a\"} 1709000000.0 1710000000000\n",
        "# TYPE h histogram\n",
        "h_bucket{id=\"a\",le=\"5\"} 4 1710000000000\n",
        "h_bucket{id=\"a\",le=\"1\"} 1 1710000000000\n",
        "h_bucket{id=\"a\",le=\"+Inf\"} 4 1710000000000\n",
        "h_sum{id=\"a\"} 9.5 1710000000000\n",
        "h_count{id=\"a\"} 4 1710000000000\n",
        "# TYPE s summary\n",
        "s{id=\"a\",quantile=\"0.9\"} 9.0 1710000000000\n",
        "s{id=\"a\",quantile=\"0.5\"} 5.0 1710000000000\n",
        "s{id=\"a\",quantile=\"+Inf\"} 99.0 1710000000000\n",
        "s{id=\"a\",quantile=\"-Inf\"} 0.0 1710000000000\n",
        "s{id=\"a\",quantile=\"NaN\"} 0.0 1710000000000\n",
        "s_sum{id=\"a\"} 50.0 1710000000000\n",
        "s_count{id=\"a\"} 10 1710000000000\n",
    );
    let text_records = decoder
        .decode(text_payload.as_bytes(), &Format::TEXT, &opts)
        .expect("Prometheus text payload decodes");
    let mut text_otap = to_otap_arrow_records(&text_records);
    text_otap
        .encode_transport_optimized()
        .expect("text transport optimize succeeds");
    text_otap
        .decode_transport_optimized_ids()
        .expect("text transport decode succeeds");
    let text_otlp = otap_to_otlp(&text_otap);

    let text_expected = OtlpProtoMessage::Metrics(to_metrics_data(vec![
        Metric {
            name: "c_total".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![
                    number_dp(&[("id", "a")], ts_ns, 10.0),
                    number_dp(&[("id", "b")], ts_ns, 20.0),
                ],
            })),
        },
        Metric {
            name: "c_created".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "unknown")],
            data: Some(metric::Data::Gauge(Gauge {
                data_points: vec![number_dp(&[("id", "a")], ts_ns, 1_709_000_000.0)],
            })),
        },
        Metric {
            name: "h".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "histogram")],
            data: Some(metric::Data::Histogram(Histogram {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                data_points: vec![HistogramDataPoint {
                    attributes: vec![kv_str("id", "a")],
                    start_time_unix_nano: 0,
                    time_unix_nano: ts_ns,
                    count: 4,
                    sum: Some(9.5),
                    bucket_counts: vec![1, 3, 0],
                    explicit_bounds: vec![1.0, 5.0],
                    exemplars: Vec::new(),
                    flags: 0,
                    min: None,
                    max: None,
                }],
            })),
        },
        Metric {
            name: "s".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "summary")],
            data: Some(metric::Data::Summary(Summary {
                data_points: vec![SummaryDataPoint {
                    attributes: vec![kv_str("id", "a")],
                    start_time_unix_nano: 0,
                    time_unix_nano: ts_ns,
                    count: 10,
                    sum: 50.0,
                    quantile_values: vec![
                        ValueAtQuantile {
                            quantile: 0.5,
                            value: 5.0,
                        },
                        ValueAtQuantile {
                            quantile: 0.9,
                            value: 9.0,
                        },
                    ],
                    flags: 0,
                }],
            })),
        },
    ]));
    assert_equivalent(&[text_expected], &[text_otlp]);

    // 3. Attribute-free exemplars (only `span_id`/`trace_id`, so `ExemplarAttrs` is omitted and
    //    `Exemplars.id` is omitted).
    let attr_free_ex = concat!(
        "# TYPE c counter\n",
        "c_total 1 1710000000.0 # {span_id=\"0102030405060708\"} 1.0 1710000000.0\n",
        "# EOF\n",
    );
    let ex_records = decoder
        .decode(attr_free_ex.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .expect("attribute-free exemplar decodes");
    assert!(ex_records.number_dp_exemplars().is_some());
    assert!(ex_records.number_dp_exemplar_attrs().is_none());
    let mut ex_otap = to_otap_arrow_records(&ex_records);
    ex_otap
        .encode_transport_optimized()
        .expect("attribute-free exemplar transport optimize succeeds");
    ex_otap
        .decode_transport_optimized_ids()
        .expect("attribute-free exemplar transport decode succeeds");
}

#[test]
fn translation_policies_control_suffix_stripping_and_untyped_projections() {
    let payload = concat!(
        "# TYPE net_bytes counter\n",
        "# UNIT net_bytes bytes\n",
        "net_bytes_total 100 1710000000.0\n",
        "# TYPE raw_total unknown\n",
        "raw_total 7 1710000000.0\n",
        "# EOF\n",
    );

    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new()
        .with_counter_suffix_policy(CounterSuffixPolicy::Strip)
        .with_unit_suffix_policy(UnitSuffixPolicy::Strip)
        .with_untyped_policy(UntypedPolicy::InferFromSuffix);

    let decoded = decoder
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .expect("policy decode succeeds");

    let mut otap = to_otap_arrow_records(&decoded);
    otap.encode_transport_optimized()
        .expect("transport optimize succeeds");
    otap.decode_transport_optimized_ids()
        .expect("transport decode succeeds");
    let actual_otlp = otap_to_otlp(&otap);

    let ts_ns = 1_710_000_000_000_000_000_u64;
    let expected = OtlpProtoMessage::Metrics(to_metrics_data(vec![
        Metric {
            name: "net".to_owned(),
            description: String::new(),
            unit: "bytes".to_owned(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "counter")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![number_dp(&[], ts_ns, 100.0)],
            })),
        },
        Metric {
            name: "raw".to_owned(),
            description: String::new(),
            unit: String::new(),
            metadata: vec![kv_str(PROMETHEUS_TYPE_METADATA_KEY, "unknown")],
            data: Some(metric::Data::Sum(Sum {
                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
                data_points: vec![number_dp(&[], ts_ns, 7.0)],
            })),
        },
    ]));
    assert_equivalent(&[expected], &[actual_otlp]);

    // Verify `UntypedPolicy::Drop` omits `unknown` families cleanly.
    let drop_opts = DecodeOptions::new().with_untyped_policy(UntypedPolicy::Drop);
    let dropped = decoder
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &drop_opts)
        .expect("drop policy decode succeeds");
    assert_eq!(dropped.num_metrics(), 1);
    assert_eq!(dropped.num_data_points(), 1);
}

#[test]
fn special_floats_and_label_free_batches_validate_in_otap() {
    let payload = "g_inf +Inf\ng_neginf -Inf\ng_nan NaN\n";
    let mut decoder = ArrowDecoder::new();
    let decoded = decoder
        .decode(payload.as_bytes(), &Format::TEXT, &DecodeOptions::default())
        .expect("decode succeeds");

    assert_eq!(decoded.num_metrics(), 3);
    assert_eq!(decoded.num_data_points(), 3);
    // Label-free scrapes omit `NumberDpAttrs` rather than emitting an empty 0-row batch.
    assert!(decoded.number_dp_attrs().is_none());

    let mut otap = to_otap_arrow_records(&decoded);
    otap.encode_transport_optimized()
        .expect("transport optimize succeeds without NumberDpAttrs");
    otap.decode_transport_optimized_ids()
        .expect("transport decode succeeds");

    let OtlpProtoMessage::Metrics(metrics_data) = otap_to_otlp(&otap) else {
        panic!("expected OTLP MetricsData");
    };
    let metrics = &metrics_data.resource_metrics[0].scope_metrics[0].metrics;
    assert_eq!(metrics.len(), 3);
    // `encode_transport_optimized` reorders rows by metric name, so inspect values by name.
    for m in metrics {
        let Some(metric::Data::Gauge(g)) = &m.data else {
            panic!("expected Gauge for {}", m.name);
        };
        let Some(number_data_point::Value::AsDouble(v)) = g.data_points[0].value else {
            panic!("expected double value for {}", m.name);
        };
        match m.name.as_str() {
            "g_inf" => assert_eq!(v, f64::INFINITY),
            "g_neginf" => assert_eq!(v, f64::NEG_INFINITY),
            "g_nan" => assert!(v.is_nan()),
            other => panic!("unexpected metric {other}"),
        }
    }
}

#[test]
fn decodes_full_upstream_prom_and_openmetrics_fixtures_into_valid_otap() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new().with_timestamp_ms(0);

    // 1. Full unmodified `alltypes.237mfs.nometa.prom.txt` (1,857 untyped samples).
    let nometa = fs::read(root.join("alltypes.237mfs.nometa.prom.txt")).unwrap();
    let nometa_records = decoder
        .decode(&nometa, &Format::TEXT, &opts)
        .expect("nometa fixture decodes");
    assert_eq!(nometa_records.num_data_points(), 1857);
    let mut nometa_otap = to_otap_arrow_records(&nometa_records);
    nometa_otap
        .encode_transport_optimized()
        .expect("nometa transport optimize succeeds");
    nometa_otap
        .decode_transport_optimized_ids()
        .expect("nometa transport decode IDs succeeds");
    let _ = otap_to_otlp(&nometa_otap);

    // 2. Full unmodified `alltypes.237mfs.prom.txt` (all 237 families including 28 classic
    //    histograms and summaries).
    let full_237 = fs::read(root.join("alltypes.237mfs.prom.txt")).unwrap();
    let full_records = decoder
        .decode(&full_237, &Format::TEXT, &opts)
        .expect("full 237mfs fixture decodes");
    assert_eq!(full_records.num_metrics(), 237);
    assert!(full_records.histogram_data_points().is_some());
    assert!(full_records.summary_data_points().is_some());
    let mut full_otap = to_otap_arrow_records(&full_records);
    full_otap
        .encode_transport_optimized()
        .expect("full 237mfs transport optimize succeeds");
    full_otap
        .decode_transport_optimized_ids()
        .expect("full 237mfs transport decode IDs succeeds");
    let _ = otap_to_otlp(&full_otap);

    // 3. Upstream OpenMetrics 1.0 fixtures (`alltypes.5mfs.om.txt`, `alltypes.bench.om.txt`,
    //    `histograms.bench.om.txt`, `ct.bench.om.txt`, `1histogram.om.txt`,
    //    `TestOpenMetricsParse_UTF8.om.txt`).
    for fixture in [
        "alltypes.5mfs.om.txt",
        "alltypes.bench.om.txt",
        "histograms.bench.om.txt",
        "ct.bench.om.txt",
        "1histogram.om.txt",
        "TestOpenMetricsParse_UTF8.om.txt",
    ] {
        let bytes = fs::read(root.join(fixture)).unwrap();
        let records = decoder
            .decode(&bytes, &Format::OPEN_METRICS_1_0_0, &opts)
            .unwrap_or_else(|err| panic!("{fixture} failed to decode: {err}"));
        assert!(!records.is_empty(), "{fixture} produced empty records");
        let mut otap = to_otap_arrow_records(&records);
        otap.encode_transport_optimized()
            .unwrap_or_else(|err| panic!("{fixture} transport optimize failed: {err}"));
        otap.decode_transport_optimized_ids()
            .unwrap_or_else(|err| panic!("{fixture} transport decode failed: {err}"));
        let _ = otap_to_otlp(&otap);
    }
}

#[test]
fn decode_stream_chunks_validate_in_otap_and_handle_more_than_u16_max_metrics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/textparse");
    let full_237 = fs::read(root.join("alltypes.237mfs.prom.txt")).unwrap();

    let mut decoder = ArrowDecoder::new();
    let single_opts = DecodeOptions::new().with_timestamp_ms(1_700_000_000_000);
    let single = decoder
        .decode(&full_237, &Format::TEXT, &single_opts)
        .expect("single-batch decode succeeds");
    let single_otlp = otap_to_otlp(&to_otap_arrow_records(&single));

    // Stream the full 237-family payload in 64-point chunks and verify semantic equivalence with
    // single-batch decoding.
    let stream_opts = single_opts.with_max_data_points_per_batch(64);
    let mut chunk_count = 0usize;
    let mut streamed_dps = 0usize;
    let mut streamed_otlp = Vec::new();
    for chunk_res in decoder.decode_stream(&full_237, &Format::TEXT, &stream_opts) {
        let chunk = chunk_res.expect("streamed chunk decodes");
        assert!(!chunk.is_empty());
        chunk_count += 1;
        streamed_dps += chunk.num_data_points();

        let mut otap = to_otap_arrow_records(&chunk);
        otap.encode_transport_optimized()
            .expect("chunk transport optimize succeeds");
        otap.decode_transport_optimized_ids()
            .expect("chunk transport decode IDs succeeds");
        streamed_otlp.push(otap_to_otlp(&otap));
    }
    assert!(chunk_count > 5);
    assert_eq!(streamed_dps, single.num_data_points());
    assert_equivalent(&[single_otlp], &streamed_otlp);

    // Also stream `alltypes.bench.om.txt` in 16-point chunks and verify equivalence.
    let om_bench = fs::read(root.join("alltypes.bench.om.txt")).unwrap();
    let om_single = decoder
        .decode(&om_bench, &Format::OPEN_METRICS_1_0_0, &single_opts)
        .expect("single-batch OpenMetrics decode succeeds");
    let om_single_otlp = otap_to_otlp(&to_otap_arrow_records(&om_single));
    let om_stream_opts = single_opts.with_max_data_points_per_batch(16);
    let mut om_streamed_otlp = Vec::new();
    for chunk_res in decoder.decode_stream(&om_bench, &Format::OPEN_METRICS_1_0_0, &om_stream_opts)
    {
        let chunk = chunk_res.expect("OpenMetrics chunk decodes");
        let otap = to_otap_arrow_records(&chunk);
        om_streamed_otlp.push(otap_to_otlp(&otap));
    }
    assert_equivalent(&[om_single_otlp], &om_streamed_otlp);

    // 70,000 metric families exceed OTAP's `u16` per-batch metric ID limit in single-batch
    // `decode`, whereas `decode_stream` splits cleanly at 65,536 metrics while preserving metadata
    // declared right across the flush boundary.
    let mut huge = String::with_capacity(70_000 * 16);
    for i in 0..70_000usize {
        if i == 65_536 {
            huge.push_str("# HELP m_65536 Boundary counter across u16 batch split.\n");
            huge.push_str("# TYPE m_65536 counter\n");
        }
        huge.push_str(&format!("m_{i} {i}\n"));
    }

    let err = decoder
        .decode(huge.as_bytes(), &Format::TEXT, &single_opts)
        .expect_err("single-batch decode must reject >65,536 metrics");
    assert!(matches!(err, DecodeError::CapacityOverflow { .. }));

    let large_batch_opts = single_opts.with_max_data_points_per_batch(100_000);
    let chunks: Vec<OtapMetricRecords> = decoder
        .decode_stream(huge.as_bytes(), &Format::TEXT, &large_batch_opts)
        .collect::<Result<Vec<_>, _>>()
        .expect("decode_stream splits >65,536 metrics across OTAP batches");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].num_metrics(), 65_536);
    assert_eq!(chunks[0].num_data_points(), 65_536);
    assert_eq!(chunks[1].num_metrics(), 70_000 - 65_536);
    assert_eq!(chunks[1].num_data_points(), 70_000 - 65_536);
    assert_matches_otap_schema(&chunks[0]);
    assert_matches_otap_schema(&chunks[1]);

    let second_otap = to_otap_arrow_records(&chunks[1]);
    let OtlpProtoMessage::Metrics(second_otlp) = otap_to_otlp(&second_otap) else {
        panic!("expected OTLP MetricsData");
    };
    let boundary_metric = &second_otlp.resource_metrics[0].scope_metrics[0].metrics[0];
    assert_eq!(boundary_metric.name, "m_65536");
    assert_eq!(
        boundary_metric.description,
        "Boundary counter across u16 batch split."
    );
    assert!(matches!(boundary_metric.data, Some(metric::Data::Sum(_))));
}

#[test]
fn univariate_metrics_resource_id_enables_otap_resource_attribute_upserts() {
    use otel_arrow_dfe_pdata::otap::transform::{
        AttributesTransform, LiteralValue, UpsertTransform, apply_attribute_transform,
    };
    use std::collections::BTreeMap;

    let mut decoder = ArrowDecoder::new();
    let decoded = decoder
        .decode(
            b"# TYPE up gauge\nup 1\n# TYPE requests_total counter\nrequests_total 5\n",
            &Format::TEXT,
            &DecodeOptions::new().with_timestamp_ms(1_700_000_000_000),
        )
        .expect("decode succeeds");

    let mut otap = to_otap_arrow_records(&decoded);
    let transform = AttributesTransform {
        upsert: Some(UpsertTransform::new(BTreeMap::from([
            (
                "gcp.project_id".into(),
                LiteralValue::Str("gpe-test-1".into()),
            ),
            ("service.name".into(), LiteralValue::Str("avalanche".into())),
            (
                "service.instance.id".into(),
                LiteralValue::Str("10.0.0.1:9001".into()),
            ),
        ]))),
        ..Default::default()
    };

    apply_attribute_transform(
        &mut otap,
        ArrowPayloadType::ResourceAttrs,
        &transform,
        false,
    )
    .expect("resource attribute upsert succeeds");

    assert!(otap.get(ArrowPayloadType::ResourceAttrs).is_some());

    otap.encode_transport_optimized()
        .expect("transport optimize succeeds");
    otap.decode_transport_optimized_ids()
        .expect("transport decode IDs succeeds");

    let OtlpProtoMessage::Metrics(otlp) = otap_to_otlp(&otap) else {
        panic!("expected OTLP MetricsData");
    };
    assert_eq!(otlp.resource_metrics.len(), 1);
    let res_attrs = &otlp.resource_metrics[0]
        .resource
        .as_ref()
        .expect("resource present")
        .attributes;
    assert!(res_attrs.contains(&kv_str("gcp.project_id", "gpe-test-1")));
    assert!(res_attrs.contains(&kv_str("service.name", "avalanche")));
    assert!(res_attrs.contains(&kv_str("service.instance.id", "10.0.0.1:9001")));
}
