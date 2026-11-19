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

use arrow_array::types::{UInt8Type, UInt16Type};
use arrow_array::{
    Array, BooleanArray, DictionaryArray, StringArray, TimestampNanosecondArray, UInt8Array,
};
use arrow_schema::{DataType, TimeUnit};

use super::schema::{OTAP_METRIC_TYPE_GAUGE, OTAP_METRIC_TYPE_SUM};
use super::*;

fn assert_timestamp_column(
    batch: &arrow_array::RecordBatch,
    column_name: &str,
    expected: Option<i64>,
) {
    let column = batch.column_by_name(column_name);
    let Some(expected) = expected else {
        assert!(column.is_none(), "{column_name} should be omitted");
        return;
    };
    let timestamps = column
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampNanosecondArray>()
        .unwrap();
    assert_eq!(timestamps.len(), batch.num_rows());
    assert_eq!(timestamps.null_count(), 0);
    assert!(timestamps.values().iter().all(|&value| value == expected));
}

#[test]
fn sample_timestamp_policy_applies_to_single_and_streamed_data_points() {
    assert!(DecodeOptions::new().honor_timestamps);
    assert_eq!(DecodeOptions::new(), DecodeOptions::default());

    let mut decoder = ArrowDecoder::new();
    for (format, wire_timestamp, expected_wire_ns) in [
        (Format::TEXT, "10000", Some(10_000_000_000)),
        (Format::TEXT, "0", Some(0)),
        (Format::TEXT, "9223372036855", None),
        (Format::OPEN_METRICS_1_0_0, "10.0", Some(10_000_000_000)),
        (Format::OPEN_METRICS_1_0_0, "0.0", Some(0)),
        (Format::OPEN_METRICS_1_0_0, "-10.0", Some(-10_000_000_000)),
        (Format::OPEN_METRICS_1_0_0, "1000000000000.0", None),
        (Format::OPEN_METRICS_1_0_0, "-1000000000000.0", None),
    ] {
        // Scalars and every component of assembled families carry a wire timestamp.
        let mut payload = concat!(
            "# TYPE c counter\nc_total 2 TS\n",
            "# TYPE g gauge\ng 3 TS\nu 4 TS\n",
            "# TYPE h histogram\n",
            "h_bucket{le=\"1\"} 1 TS\nh_bucket{le=\"+Inf\"} 2 TS\n",
            "h_sum 1.5 TS\nh_count 2 TS\n",
            "# TYPE s summary\ns{quantile=\"0.5\"} 0.2 TS\n",
            "s_sum 0.2 TS\ns_count 1 TS\n",
        )
        .replace("TS", wire_timestamp);
        if format == Format::OPEN_METRICS_1_0_0 {
            payload.push_str("# EOF\n");
        }

        for honor_timestamps in [true, false] {
            for timestamp_ms in [Some(20_000), None] {
                let mut opts = DecodeOptions::new()
                    .with_honor_timestamps(honor_timestamps)
                    .with_max_data_points_per_batch(1);
                opts.timestamp_ms = timestamp_ms;

                for streaming in [false, true] {
                    let result = if streaming {
                        decoder
                            .decode_stream(payload.as_bytes(), &format, &opts)
                            .collect::<Result<Vec<_>, _>>()
                    } else {
                        decoder
                            .decode(payload.as_bytes(), &format, &opts)
                            .map(|records| vec![records])
                    };
                    if honor_timestamps && expected_wire_ns.is_none() {
                        assert!(matches!(result, Err(DecodeError::TimestampOverflow { .. })));
                        continue;
                    }
                    let chunks = result.unwrap_or_else(|err| {
                        panic!(
                            "format={format:?}, timestamp={wire_timestamp}, honor_timestamps={honor_timestamps}, fallback={timestamp_ms:?}, streaming={streaming}: {err:?}"
                        )
                    });
                    assert_eq!(
                        chunks
                            .iter()
                            .map(OtapMetricRecords::num_data_points)
                            .sum::<usize>(),
                        5
                    );
                    let expected = if honor_timestamps {
                        expected_wire_ns
                    } else {
                        timestamp_ms.map(|ms| ms * 1_000_000)
                    };
                    for records in chunks {
                        for batch in [
                            records.number_data_points(),
                            records.histogram_data_points(),
                            records.summary_data_points(),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            assert_timestamp_column(batch, "time_unix_nano", expected);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ignoring_sample_timestamps_preserves_exemplar_and_start_timestamps() {
    let payload = concat!(
        "# TYPE c counter\n",
        "c_total 2 10.0 # {trace_id=\"0123456789abcdef0123456789abcdef\"} 1 7.0\n",
        "c_created 1.0\n",
        "# TYPE h histogram\n",
        "h_bucket{le=\"+Inf\"} 2 10.0 # {trace_id=\"0123456789abcdef0123456789abcdef\"} 1 7.0\n",
        "h_sum 1.5 10.0\nh_count 2 10.0\nh_created 1.0\n",
        "# TYPE s summary\ns{quantile=\"0.5\"} 0.2 10.0\n",
        "s_sum 0.2 10.0\ns_count 1 10.0\ns_created 1.0\n# EOF\n",
    );
    let mut decoder = ArrowDecoder::new();
    for honor_timestamps in [true, false] {
        let opts = DecodeOptions::new()
            .with_timestamp_ms(20_000)
            .with_honor_timestamps(honor_timestamps)
            .with_max_data_points_per_batch(1);
        for streaming in [false, true] {
            let chunks = if streaming {
                decoder
                    .decode_stream(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            } else {
                vec![
                    decoder
                        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
                        .unwrap(),
                ]
            };
            let mut exemplar_count = 0;
            for records in chunks {
                for batch in [
                    records.number_data_points(),
                    records.histogram_data_points(),
                    records.summary_data_points(),
                ]
                .into_iter()
                .flatten()
                {
                    let expected = if honor_timestamps {
                        10_000_000_000
                    } else {
                        20_000_000_000
                    };
                    assert_timestamp_column(batch, "time_unix_nano", Some(expected));
                    assert_timestamp_column(batch, "start_time_unix_nano", Some(1_000_000_000));
                }
                for batch in [
                    records.number_dp_exemplars(),
                    records.histogram_dp_exemplars(),
                ]
                .into_iter()
                .flatten()
                {
                    assert_timestamp_column(batch, "time_unix_nano", Some(7_000_000_000));
                    exemplar_count += batch.num_rows();
                }
            }
            assert_eq!(exemplar_count, 2);
        }
    }
}

#[test]
fn ignoring_sample_timestamps_still_validates_syntax_defaults_and_exemplars() {
    let mut decoder = ArrowDecoder::new();
    let opts = DecodeOptions::new().with_honor_timestamps(false);
    // Like Go's Prometheus text lexer, signed wire timestamps are invalid syntax even when
    // sample timestamps are ignored. OpenMetrics signed timestamps are covered above.
    for payload in ["m 1 invalid\n", "m 1 -10000\n", "m 1 -9223372036855\n"] {
        assert!(
            decoder
                .decode(payload.as_bytes(), &Format::TEXT, &opts)
                .is_err()
        );
    }
    let opts = opts.with_timestamp_ms(9_223_372_036_855);
    assert!(matches!(
        decoder.decode(b"m 1 10000\n", &Format::TEXT, &opts),
        Err(DecodeError::TimestampOverflow { .. })
    ));

    let opts = DecodeOptions::new().with_honor_timestamps(false);
    for payload in [
        "# TYPE c counter\nc_total 2 10.0 # {id=\"a\"} 1 1000000000000.0\n# EOF\n",
        "# TYPE h histogram\nh_bucket{le=\"+Inf\"} 2 10.0 # {id=\"a\"} 1 1000000000000.0\n# EOF\n",
    ] {
        assert!(matches!(
            decoder.decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts),
            Err(DecodeError::TimestampOverflow { .. })
        ));
    }
}

#[test]
fn empty_and_metadata_only_inputs_produce_empty_records() {
    let mut dec = ArrowDecoder::new();
    for input in [
        b"" as &[u8],
        b"\n\n# just a comment\n",
        b"# HELP orphan_metric A metric with zero samples.\n# TYPE orphan_metric counter\n",
    ] {
        let records = dec
            .decode(input, &Format::TEXT, &DecodeOptions::default())
            .unwrap();
        assert!(records.is_empty());
        assert_eq!(records.num_metrics(), 0);
        assert_eq!(records.num_data_points(), 0);
        assert_eq!(records.iter().count(), 0);
        assert_eq!(records.into_batches().count(), 0);
    }
}

#[test]
fn schema_metadata_mixed_timestamps_and_widened_key_dictionaries() {
    let mut payload = String::from(
        "# HELP req_total Total requests.\n\
         # TYPE req_total counter\n\
         req_total 10\n\
         req_total 12 1700000000500\n",
    );
    // Emit 260 distinct label keys so `NumberDpAttrs.key` widens from UInt8 to UInt16.
    payload.push_str("# TYPE wide_gauge gauge\nwide_gauge{");
    for i in 0..260 {
        if i > 0 {
            payload.push(',');
        }
        payload.push_str(&format!("k_{i}=\"v\""));
    }
    payload.push_str("} 3.5\n");

    let mut dec = ArrowDecoder::new();
    let records = dec
        .decode(payload.as_bytes(), &Format::TEXT, &DecodeOptions::new())
        .unwrap();

    let metrics = records.univariate_metrics().unwrap();
    assert_eq!(
        metrics
            .schema()
            .field_with_name("id")
            .unwrap()
            .metadata()
            .get("encoding")
            .map(String::as_str),
        Some("plain")
    );

    let dps = records.number_data_points().unwrap();
    let dps_schema = dps.schema();
    let ts_field = dps_schema.field_with_name("time_unix_nano").unwrap();
    assert!(ts_field.is_nullable());
    assert_eq!(
        ts_field.data_type(),
        &DataType::Timestamp(TimeUnit::Nanosecond, Some("UTC".into()))
    );
    let ts_col = dps
        .column_by_name("time_unix_nano")
        .unwrap()
        .as_any()
        .downcast_ref::<TimestampNanosecondArray>()
        .unwrap();
    assert!(ts_col.is_null(0));
    assert!(!ts_col.is_null(1));
    assert_eq!(ts_col.value(1), 1_700_000_000_500_000_000);
    assert!(ts_col.is_null(2));

    let dp_attrs = records.number_dp_attrs().unwrap();
    assert_eq!(
        dp_attrs
            .schema()
            .field_with_name("key")
            .unwrap()
            .data_type(),
        &DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8))
    );
}

#[test]
fn description_column_handles_mixed_and_uniform_help_presence() {
    let mut dec = ArrowDecoder::new();
    let opts = DecodeOptions::default();

    // Case 1: first metric has no HELP, second has HELP, third has no HELP.
    let records = dec
        .decode(
            b"m0 1\n# HELP m1 With help.\nm1 2\nm2 3\n",
            &Format::TEXT,
            &opts,
        )
        .unwrap();
    let metrics = records.univariate_metrics().unwrap();
    let desc = metrics
        .column_by_name("description")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert!(desc.is_null(0));
    assert!(!desc.is_null(1));
    assert_eq!(desc.value(1), "With help.");
    assert!(desc.is_null(2));

    // Case 2: all metrics have HELP, so no null bitmap is materialized on `description`.
    let records = dec
        .decode(
            b"# HELP a First.\na 1\n# HELP b Second.\nb 2\n",
            &Format::TEXT,
            &opts,
        )
        .unwrap();
    let metrics = records.univariate_metrics().unwrap();
    let desc = metrics
        .column_by_name("description")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(desc.null_count(), 0);
    assert_eq!(desc.value(0), "First.");
    assert_eq!(desc.value(1), "Second.");

    // Case 3: no metric has HELP, so the optional `description` column is omitted.
    let records = dec.decode(b"a 1\nb 2\n", &Format::TEXT, &opts).unwrap();
    let metrics = records.univariate_metrics().unwrap();
    assert!(metrics.column_by_name("description").is_none());
}

#[test]
fn rejects_invalid_metadata_and_duplicate_labels() {
    let mut dec = ArrowDecoder::new();
    let opts = DecodeOptions::default();

    // Duplicate non-empty `# HELP`.
    let err = dec
        .decode(
            b"# HELP m first\n# HELP m second\nm 1\n",
            &Format::TEXT,
            &opts,
        )
        .unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateOrLateHelp { ref metric } if metric == "m"));

    // `# HELP` appearing after a sample has already been emitted.
    let err = dec
        .decode(b"m 1\n# HELP m late\n", &Format::TEXT, &opts)
        .unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateOrLateHelp { ref metric } if metric == "m"));

    // Duplicate `# TYPE`.
    let err = dec
        .decode(
            b"# TYPE m counter\n# TYPE m gauge\nm 1\n",
            &Format::TEXT,
            &opts,
        )
        .unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateOrLateType { ref metric } if metric == "m"));

    // `# TYPE` appearing after a sample has already been emitted.
    let err = dec
        .decode(b"m 1\n# TYPE m counter\n", &Format::TEXT, &opts)
        .unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateOrLateType { ref metric } if metric == "m"));

    // Duplicate `# UNIT` in OpenMetrics.
    let err = dec
        .decode(
            b"# UNIT m_seconds seconds\n# UNIT m_seconds seconds\nm_seconds 1\n# EOF\n",
            &Format::OPEN_METRICS_1_0_0,
            &opts,
        )
        .unwrap_err();
    assert!(
        matches!(err, DecodeError::DuplicateOrLateUnit { ref metric } if metric == "m_seconds")
    );

    // Duplicate label names (adjacent, non-adjacent, or empty-valued) and reserved `__name__`.
    for payload in [
        b"m{a=\"1\",a=\"2\"} 1\n" as &[u8],
        b"m{b=\"1\",a=\"2\",b=\"3\"} 1\n",
        b"m{a=\"\",a=\"\"} 1\n",
        b"m{a=\"1\",a=\"\"} 1\n",
        b"m{a=\"\",a=\"1\"} 1\n",
        b"m{\"a\\nb\"=\"\",\"a\nb\"=\"1\"} 1\n",
        b"m{__name__=\"override\"} 1\n",
        b"m{__name__=\"\"} 1\n",
        b"# TYPE h histogram\nh_bucket{le=\"1\",le=\"2\"} 1\n",
        b"# TYPE s summary\ns{quantile=\"0.5\",quantile=\"0.9\"} 1\n",
    ] {
        let err = dec.decode(payload, &Format::TEXT, &opts).unwrap_err();
        assert!(
            matches!(err, DecodeError::DuplicateLabel { .. }),
            "expected DuplicateLabel, got {err:?}"
        );
    }

    // Unsupported formats.
    let err = dec.decode(b"m 1\n", &Format::UNKNOWN, &opts).unwrap_err();
    assert!(matches!(err, DecodeError::UnsupportedFormat(_)));

    // Timestamp overflow.
    let err = dec
        .decode(b"m 1 9223372036855\n", &Format::TEXT, &opts)
        .unwrap_err();
    assert!(matches!(
        err,
        DecodeError::TimestampOverflow {
            timestamp_ms: 9_223_372_036_855
        }
    ));

    // Out-of-range OpenMetrics `_created` values are ignored rather than failing the scrape.
    let huge_created = dec
        .decode(
            b"# TYPE foo counter\nfoo_total 1\nfoo_created 1e300\n# TYPE h histogram\nh_bucket{le=\"+Inf\"} 1\nh_created 1e12\n# EOF\n",
            &Format::OPEN_METRICS_1_0_0,
            &opts,
        )
        .unwrap();
    assert_eq!(huge_created.num_metrics(), 2);
    assert_eq!(huge_created.num_data_points(), 2);
    assert!(
        huge_created
            .number_data_points()
            .unwrap()
            .column_by_name("start_time_unix_nano")
            .is_none()
    );
    assert!(
        huge_created
            .histogram_data_points()
            .unwrap()
            .column_by_name("start_time_unix_nano")
            .is_none()
    );
}

#[test]
fn empty_label_values_match_missing_labels() {
    let mut dec = ArrowDecoder::new();
    let opts = DecodeOptions::default();

    let bare = dec.decode(b"m 1\n", &Format::TEXT, &opts).unwrap();
    let with_empty = dec
        .decode(b"m{a=\"\",b=\"\"} 1\n", &Format::TEXT, &opts)
        .unwrap();
    assert_eq!(with_empty, bare);
    assert!(with_empty.number_dp_attrs().is_none());

    let mixed = dec
        .decode(b"m{a=\"\",b=\"x\"} 1\n", &Format::TEXT, &opts)
        .unwrap();
    let dp_attrs = mixed.number_dp_attrs().unwrap();
    assert_eq!(dp_attrs.num_rows(), 1);
    let key_dict = dp_attrs
        .column_by_name("key")
        .unwrap()
        .as_any()
        .downcast_ref::<DictionaryArray<UInt8Type>>()
        .unwrap();
    let key_vals = key_dict
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(key_vals.len(), 1);
    assert_eq!(key_vals.value(0), "b");

    let val_dict = dp_attrs
        .column_by_name("str")
        .unwrap()
        .as_any()
        .downcast_ref::<DictionaryArray<UInt16Type>>()
        .unwrap();
    let str_vals = val_dict
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(str_vals.len(), 1);
    assert_eq!(str_vals.value(0), "x");

    // Dropped families (`UntypedPolicy::Drop`) validate duplicate/reserved labels without
    // interning their keys or values into `NumberDpAttrs` dictionaries.
    let drop_opts = DecodeOptions::new().with_untyped_policy(UntypedPolicy::Drop);
    let with_dropped = dec
        .decode(
            b"dropped_metric{dropped_k=\"dropped_v\"} 1\n# TYPE kept gauge\nkept{b=\"x\"} 2\n",
            &Format::TEXT,
            &drop_opts,
        )
        .unwrap();
    let kept_attrs = with_dropped.number_dp_attrs().unwrap();
    let kept_keys = kept_attrs
        .column_by_name("key")
        .unwrap()
        .as_any()
        .downcast_ref::<DictionaryArray<UInt8Type>>()
        .unwrap()
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(kept_keys.len(), 1);
    assert_eq!(kept_keys.value(0), "b");

    let dup_dropped = dec
        .decode(
            b"dropped_metric{a=\"1\",a=\"2\"} 1\n",
            &Format::TEXT,
            &drop_opts,
        )
        .unwrap_err();
    assert!(matches!(dup_dropped, DecodeError::DuplicateLabel { .. }));
}

#[test]
fn decode_stream_splits_mid_family_preserves_metadata_and_handles_edges() {
    let mut dec = ArrowDecoder::new();

    // Empty and metadata-only scrapes yield zero chunks.
    for empty in [
        b"" as &[u8],
        b"# comment\n",
        b"# HELP unused Help.\n# TYPE unused counter\n",
    ] {
        assert_eq!(
            dec.decode_stream(empty, &Format::TEXT, &DecodeOptions::new())
                .count(),
            0
        );
    }

    // Split a 4-sample counter family into chunks of 2, followed by a 1-sample gauge family
    // and a trailing metadata-only family. Also verify `max_data_points_per_batch = 0` clamps.
    let zero_opts = DecodeOptions::new().with_max_data_points_per_batch(0);
    let one_by_one: Vec<_> = dec
        .decode_stream(b"a 1\na 2\n", &Format::TEXT, &zero_opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(one_by_one.len(), 2);
    assert_eq!(one_by_one[0].num_data_points(), 1);
    assert_eq!(one_by_one[1].num_data_points(), 1);

    let payload = concat!(
        "# HELP req_total Total HTTP requests.\n",
        "# TYPE req_total counter\n",
        "req_total{shard=\"0\"} 10\n",
        "req_total{shard=\"1\"} 20\n",
        "req_total{shard=\"2\"} 30\n",
        "req_total{shard=\"3\"} 40\n",
        "# TYPE mem_bytes gauge\n",
        "mem_bytes 512\n",
        "# HELP trailing_empty Unused.\n",
        "# TYPE trailing_empty gauge\n",
    );
    let opts = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_max_data_points_per_batch(2);

    let chunks: Vec<OtapMetricRecords> = dec
        .decode_stream(payload.as_bytes(), &Format::TEXT, &opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(chunks.len(), 3);

    // Chunks 0 and 1 both carry `req_total` with its original `# HELP` and counter semantics.
    for chunk in &chunks[..2] {
        assert_eq!(chunk.num_metrics(), 1);
        assert_eq!(chunk.num_data_points(), 2);
        let um = chunk.univariate_metrics().unwrap();
        let names = um
            .column_by_name("name")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let descs = um
            .column_by_name("description")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(names.value(0), "req_total");
        assert_eq!(descs.value(0), "Total HTTP requests.");
        assert!(um.column_by_name("is_monotonic").is_some());
    }

    // Chunk 2 contains only `mem_bytes`; `req_total` was not re-emitted with zero samples.
    assert_eq!(chunks[2].num_metrics(), 1);
    assert_eq!(chunks[2].num_data_points(), 1);
    let um2 = chunks[2].univariate_metrics().unwrap();
    let names2 = um2
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(names2.value(0), "mem_bytes");
    assert!(um2.column_by_name("description").is_none());
    assert!(um2.column_by_name("is_monotonic").is_none());

    // Late `# HELP` or `# TYPE` immediately after a chunk boundary is still rejected.
    let late_help = b"m{a=\"1\"} 1\nm{a=\"2\"} 2\n# HELP m too late\nm{a=\"3\"} 3\n";
    let mut stream = dec.decode_stream(late_help, &Format::TEXT, &opts);
    assert!(stream.next().unwrap().is_ok());
    let err = stream.next().unwrap().unwrap_err();
    assert!(matches!(err, DecodeError::DuplicateOrLateHelp { ref metric } if metric == "m"));
    assert!(stream.next().is_none());
    drop(stream);

    // Dropping a stream early returns the scratch label span vector to the decoder.
    let labeled = b"m{k1=\"1\",k2=\"2\",k3=\"3\",k4=\"4\"} 1\nm{k1=\"5\"} 2\n";
    {
        let mut stream = dec.decode_stream(labeled, &Format::TEXT, &zero_opts);
        assert!(stream.next().unwrap().is_ok());
    }
    assert!(dec.prom_spans.capacity() >= 4);

    // Consecutive assembled families (histograms/summaries) preceded by `# TYPE` flush at
    // `max_data_points_per_batch` when the next family begins, and a single assembled family
    // with multiple series splits across chunks at `max_data_points_per_batch`.
    let assembled_stream = concat!(
        "# HELP h1 Request latency.\n",
        "# TYPE h1 histogram\n",
        "h1_bucket{id=\"1\",le=\"1\"} 1\n",
        "h1_bucket{id=\"1\",le=\"+Inf\"} 2\n",
        "h1_sum{id=\"1\"} 1.5\n",
        "h1_count{id=\"1\"} 2\n",
        "h1_bucket{id=\"2\",le=\"1\"} 3\n",
        "h1_bucket{id=\"2\",le=\"+Inf\"} 4\n",
        "h1_sum{id=\"2\"} 3.5\n",
        "h1_count{id=\"2\"} 4\n",
        "# TYPE s1 summary\n",
        "s1{quantile=\"0.5\"} 2\n",
        "s1_sum 2\n",
        "s1_count 1\n",
    );
    let assembled_chunks: Vec<_> = dec
        .decode_stream(assembled_stream.as_bytes(), &Format::TEXT, &zero_opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(assembled_chunks.len(), 3);
    assert_eq!(assembled_chunks[0].num_data_points(), 1);
    assert!(assembled_chunks[0].histogram_data_points().is_some());
    assert_eq!(assembled_chunks[1].num_data_points(), 1);
    assert!(assembled_chunks[1].histogram_data_points().is_some());
    assert_eq!(assembled_chunks[2].num_data_points(), 1);
    assert!(assembled_chunks[2].summary_data_points().is_some());

    // In Prometheus text format (`Format::TEXT`), `*_created` lines are regular metrics rather
    // than OpenMetrics start timestamps, so non-adjacent `foo_created` lines are preserved as
    // their own metric family instead of being dropped or attached to `foo_total`.
    let text_created_payload = concat!(
        "# TYPE foo counter\n",
        "foo_total{a=\"1\"} 1\n",
        "foo_total{a=\"2\"} 2\n",
        "foo_created{a=\"1\"} 100\n",
    );
    let text_created = dec
        .decode(text_created_payload.as_bytes(), &Format::TEXT, &opts)
        .unwrap();
    assert_eq!(text_created.num_metrics(), 2);
    assert_eq!(text_created.num_data_points(), 3);
    let text_created_um = text_created.univariate_metrics().unwrap();
    let text_created_names = text_created_um
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(text_created_names.value(0), "foo_total");
    assert_eq!(text_created_names.value(1), "foo_created");

    // Init errors surface on the first `next()` and fuse the iterator.
    let mut bad_fmt = dec.decode_stream(b"m 1\n", &Format::UNKNOWN, &opts);
    assert!(matches!(
        bad_fmt.next(),
        Some(Err(DecodeError::UnsupportedFormat(_)))
    ));
    assert!(bad_fmt.next().is_none());
}

#[test]
fn interleaved_family_starts_fresh_untyped_run() {
    let mut dec = ArrowDecoder::new();
    let opts = DecodeOptions::default();
    let payload = b"# TYPE a counter\na{x=\"1\"} 1\nb 2\na{x=\"2\"} 3\n";

    let records = dec.decode(payload, &Format::TEXT, &opts).unwrap();
    assert_eq!(records.num_metrics(), 3);
    assert_eq!(records.num_data_points(), 3);

    let um = records.univariate_metrics().unwrap();
    let names = um
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let metric_types = um
        .column_by_name("metric_type")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt8Array>()
        .unwrap();
    let is_monotonic = um
        .column_by_name("is_monotonic")
        .unwrap()
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();

    assert_eq!(names.value(0), "a");
    assert_eq!(metric_types.value(0), OTAP_METRIC_TYPE_SUM);
    assert!(!is_monotonic.is_null(0));
    assert!(is_monotonic.value(0));

    assert_eq!(names.value(1), "b");
    assert_eq!(metric_types.value(1), OTAP_METRIC_TYPE_GAUGE);
    assert!(is_monotonic.is_null(1));

    // The second run of `a` is non-contiguous and has no `# TYPE` of its own, so it decodes as
    // a separate untyped (`Gauge`) metric rather than failing the scrape.
    assert_eq!(names.value(2), "a");
    assert_eq!(metric_types.value(2), OTAP_METRIC_TYPE_GAUGE);
    assert!(is_monotonic.is_null(2));

    let streamed: Vec<_> = dec
        .decode_stream(payload, &Format::TEXT, &opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(streamed, vec![records]);
}

#[test]
fn interleaved_histogram_lines_and_group_rehashing_assemble_correctly() {
    let mut payload = String::from("# TYPE h histogram\n");
    for i in 0..32_u64 {
        payload.push_str(&format!("h_bucket{{id=\"{i}\",le=\"1\"}} {i}\n"));
        payload.push_str(&format!(
            "h_bucket{{id=\"{i}\",le=\"+Inf\"}} {}\n",
            i * 2 + 1
        ));
    }
    for i in 0..32_u64 {
        payload.push_str(&format!("h_sum{{id=\"{i}\"}} {}.5\n", i * 10));
    }
    for i in 0..32_u64 {
        payload.push_str(&format!("h_count{{id=\"{i}\"}} {}\n", i * 2 + 1));
    }

    let mut dec = ArrowDecoder::new();
    let records = dec
        .decode(payload.as_bytes(), &Format::TEXT, &DecodeOptions::default())
        .unwrap();
    assert_eq!(records.num_metrics(), 1);
    assert_eq!(records.num_data_points(), 32);

    let hdp = records.histogram_data_points().unwrap();
    let counts = hdp
        .column_by_name("count")
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::UInt64Array>()
        .unwrap();
    let sums = hdp
        .column_by_name("sum")
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::Float64Array>()
        .unwrap();
    for i in 0..32_usize {
        assert_eq!(counts.value(i), (i as u64) * 2 + 1);
        assert_eq!(sums.value(i), (i as f64) * 10.0 + 0.5);
    }
}

#[test]
fn decode_budget_defaults_and_builders() {
    let default_budget = DecodeBudget::default();
    assert_eq!(
        default_budget.max_entries,
        DEFAULT_DECODE_BUDGET_MAX_ENTRIES
    );
    assert_eq!(default_budget.max_bytes, DEFAULT_DECODE_BUDGET_MAX_BYTES);
    assert_eq!(
        default_budget.max_duration,
        DEFAULT_DECODE_BUDGET_MAX_DURATION
    );

    let custom = DecodeBudget::new(32, 4096, std::time::Duration::from_micros(500))
        .with_max_entries(16)
        .with_max_bytes(2048)
        .with_max_duration(std::time::Duration::from_millis(2));
    assert_eq!(custom.max_entries, 16);
    assert_eq!(custom.max_bytes, 2048);
    assert_eq!(custom.max_duration, std::time::Duration::from_millis(2));
}

#[test]
fn decode_stream_step_respects_entry_byte_and_duration_budgets() {
    let payload = concat!(
        "# HELP req_total Total HTTP requests.\n",
        "# TYPE req_total counter\n",
        "req_total{shard=\"0\"} 10\n",
        "req_total{shard=\"1\"} 20\n",
        "# TYPE lat histogram\n",
        "lat_bucket{le=\"1\"} 2\n",
        "lat_bucket{le=\"+Inf\"} 5\n",
        "lat_sum 3.5\n",
        "lat_count 5\n",
    );
    let bytes = payload.as_bytes();
    let opts = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_max_data_points_per_batch(2);

    let mut dec = ArrowDecoder::new();
    let expected: Vec<OtapMetricRecords> = dec
        .decode_stream(bytes, &Format::TEXT, &opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(expected.len(), 2);

    // 1. Entry budget (`max_entries = 1`, `max_bytes = 0` clamped to 1).
    for budget in [
        DecodeBudget::default().with_max_entries(1),
        DecodeBudget::new(0, 0, std::time::Duration::from_secs(60)),
        DecodeBudget::default().with_max_duration(std::time::Duration::ZERO),
        DecodeBudget::default().with_max_bytes(16),
    ] {
        let mut stream = dec.decode_stream(bytes, &Format::TEXT, &opts);
        let mut pending_count = 0usize;
        let mut got_batches = Vec::new();
        let mut prev_pos = 0usize;

        loop {
            match stream.step(budget).unwrap() {
                DecodeStep::Pending => {
                    pending_count += 1;
                    assert!(stream.pos() >= prev_pos);
                    prev_pos = stream.pos();
                }
                DecodeStep::Batch(batch) => {
                    assert!(stream.pos() >= prev_pos);
                    prev_pos = stream.pos();
                    got_batches.push(batch);
                }
                DecodeStep::Done => {
                    assert_eq!(stream.pos(), bytes.len());
                    break;
                }
            }
        }
        assert!(pending_count > 0, "expected Pending steps for {budget:?}");
        assert_eq!(got_batches, expected, "mismatch for {budget:?}");
        assert_eq!(stream.step(budget).unwrap(), DecodeStep::Done);
    }

    // Init errors and mid-scrape syntax errors fuse `step()`.
    let mut bad_stream = dec.decode_stream(b"m 1\n", &Format::UNKNOWN, &opts);
    assert!(matches!(
        bad_stream.step(DecodeBudget::default()),
        Err(DecodeError::UnsupportedFormat(_))
    ));
    assert_eq!(
        bad_stream.step(DecodeBudget::default()).unwrap(),
        DecodeStep::Done
    );
    drop(bad_stream);

    let mut mid_err_stream =
        dec.decode_stream(b"m{a=\"1\",b=\"2\"} 1\nbad_line\n", &Format::TEXT, &opts);
    let step1 = DecodeBudget::default().with_max_entries(1);
    assert_eq!(mid_err_stream.step(step1).unwrap(), DecodeStep::Pending);
    assert!(matches!(
        mid_err_stream.step(step1),
        Err(DecodeError::Syntax { .. })
    ));
    assert_eq!(mid_err_stream.step(step1).unwrap(), DecodeStep::Done);
    drop(mid_err_stream);

    // Non-zero `max_duration` checks elapsed time every 16 entries (`entries.is_multiple_of(16)`).
    let mut heavy_lines = String::new();
    for i in 0..20 {
        heavy_lines.push_str("m{");
        for k in 0..32 {
            if k > 0 {
                heavy_lines.push(',');
            }
            heavy_lines.push_str(&format!("k_{k}=\"v\\\\n_{i}_{k}\""));
        }
        heavy_lines.push_str(&format!("}} {i}\n"));
    }
    let dur_budget = DecodeBudget::new(usize::MAX, usize::MAX, std::time::Duration::from_nanos(1));
    let mut dur_stream = dec.decode_stream(
        heavy_lines.as_bytes(),
        &Format::TEXT,
        &DecodeOptions::new().with_max_data_points_per_batch(64),
    );
    assert_eq!(dur_stream.step(dur_budget).unwrap(), DecodeStep::Pending);
    let consumed_lines = heavy_lines.as_bytes()[..dur_stream.pos()]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    assert_eq!(consumed_lines, DECODE_BUDGET_DURATION_CHECK_INTERVAL);
    match dur_stream.step(dur_budget).unwrap() {
        DecodeStep::Batch(batch) => assert_eq!(batch.num_data_points(), 20),
        other => panic!("expected DecodeStep::Batch, got {other:?}"),
    }
    assert_eq!(dur_stream.step(dur_budget).unwrap(), DecodeStep::Done);
}

#[test]
fn lifetime_free_decode_cursor_supports_owned_job_across_steps() {
    #[derive(Debug)]
    struct OwnedDecodeJob {
        payload: Vec<u8>,
        decoder: ArrowDecoder,
        cursor: DecodeCursor,
    }

    let om_payload = concat!(
        "# HELP rpc_seconds RPC latency.\n",
        "# UNIT rpc_seconds seconds\n",
        "# TYPE rpc_seconds histogram\n",
        "rpc_seconds_bucket{service=\"auth\",le=\"0.1\"} 3 1710000000.0 # {trace_id=\"0102030405060708090a0b0c0d0e0f10\"} 0.05 1709999999.0\n",
        "rpc_seconds_bucket{service=\"auth\",le=\"+Inf\"} 4 1710000000.0\n",
        "rpc_seconds_sum{service=\"auth\"} 0.42 1710000000.0\n",
        "rpc_seconds_count{service=\"auth\"} 4 1710000000.0\n",
        "rpc_seconds_created{service=\"auth\"} 1709000000.0\n",
        "# TYPE calls counter\n",
        "calls_total{service=\"auth\"} 9 1710000000.0\n",
        "calls_created{service=\"auth\"} 1709000000.0\n",
        "# EOF\n",
    );

    let opts = DecodeOptions::new();
    let mut ref_dec = ArrowDecoder::new();
    let expected_single = ref_dec
        .decode(om_payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();

    // 1. Single-batch `start_decode` driven 1 entry at a time on an owned struct.
    let mut decoder = ArrowDecoder::new();
    let cursor = decoder
        .start_decode(&Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();
    let mut job = OwnedDecodeJob {
        payload: om_payload.as_bytes().to_vec(),
        decoder,
        cursor,
    };
    let budget = DecodeBudget::default().with_max_entries(1);
    let mut pending_steps = 0usize;
    let mut single_out = None;
    while !job.cursor.is_done() {
        match job
            .decoder
            .step_decode(&mut job.cursor, &job.payload, budget)
            .unwrap()
        {
            DecodeStep::Pending => pending_steps += 1,
            DecodeStep::Batch(records) => {
                assert!(single_out.replace(records).is_none());
            }
            DecodeStep::Done => break,
        }
    }
    assert!(pending_steps >= 6);
    assert_eq!(job.cursor.pos(), job.payload.len());
    assert!(job.cursor.is_done());
    assert_eq!(single_out.unwrap(), expected_single);
    assert_eq!(
        job.decoder
            .step_decode(&mut job.cursor, &job.payload, budget)
            .unwrap(),
        DecodeStep::Done
    );

    // 2. Chunked `start_decode_stream` driven 1 entry at a time.
    let stream_opts = opts.with_max_data_points_per_batch(1);
    let expected_chunks: Vec<_> = ref_dec
        .decode_stream(
            om_payload.as_bytes(),
            &Format::OPEN_METRICS_1_0_0,
            &stream_opts,
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut stream_cursor = job
        .decoder
        .start_decode_stream(&Format::OPEN_METRICS_1_0_0, &stream_opts)
        .unwrap();
    let mut got_chunks = Vec::new();
    loop {
        match job
            .decoder
            .step_decode(&mut stream_cursor, &job.payload, budget)
            .unwrap()
        {
            DecodeStep::Pending => {}
            DecodeStep::Batch(chunk) => got_chunks.push(chunk),
            DecodeStep::Done => break,
        }
    }
    assert_eq!(got_chunks, expected_chunks);

    // 3. Aborting a cursor early via `finish_decode` is idempotent and reclaims parser scratch
    //    capacity, and `DecodeCursor` implements `Debug`.
    let mut aborted = job
        .decoder
        .start_decode(&Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();
    assert!(format!("{aborted:?}").contains("DecodeCursor"));
    assert_eq!(
        job.decoder
            .step_decode(&mut aborted, &job.payload, budget)
            .unwrap(),
        DecodeStep::Pending
    );
    job.decoder.finish_decode(&mut aborted);
    let retained_after_first = job.decoder.om_scratch.retained_memory_bytes();
    assert!(aborted.is_done());
    assert!(retained_after_first > 0);
    job.decoder.finish_decode(&mut aborted);
    assert_eq!(
        job.decoder.om_scratch.retained_memory_bytes(),
        retained_after_first
    );

    // 4. Empty or comment-only scrapes return `DecodeStep::Done` in single-batch `start_decode`.
    let mut empty_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    assert_eq!(
        job.decoder
            .step_decode(&mut empty_cursor, b"# only comment\n", budget)
            .unwrap(),
        DecodeStep::Pending
    );
    assert_eq!(
        job.decoder
            .step_decode(&mut empty_cursor, b"# only comment\n", budget)
            .unwrap(),
        DecodeStep::Done
    );
    assert!(empty_cursor.is_done());

    // 5. `split_assembled` and assembled-to-untyped `pending_series` transitions under `budget`.
    let hist_and_untyped = concat!(
        "# TYPE h histogram\n",
        "h_bucket{id=\"1\",le=\"1\"} 1\n",
        "h_bucket{id=\"1\",le=\"+Inf\"} 2\n",
        "h_sum{id=\"1\"} 1.5\n",
        "h_count{id=\"1\"} 2\n",
        "h_bucket{id=\"2\",le=\"1\"} 3\n",
        "h_bucket{id=\"2\",le=\"+Inf\"} 4\n",
        "h_sum{id=\"2\"} 3.5\n",
        "h_count{id=\"2\"} 4\n",
        "untyped_after_hist 7\n",
    );
    let expected_hist_chunks: Vec<_> = ref_dec
        .decode_stream(hist_and_untyped.as_bytes(), &Format::TEXT, &stream_opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(expected_hist_chunks.len(), 3);
    let mut hist_cursor = job
        .decoder
        .start_decode_stream(&Format::TEXT, &stream_opts)
        .unwrap();
    let mut got_hist_chunks = Vec::new();
    loop {
        match job
            .decoder
            .step_decode(&mut hist_cursor, hist_and_untyped.as_bytes(), budget)
            .unwrap()
        {
            DecodeStep::Pending => {}
            DecodeStep::Batch(chunk) => got_hist_chunks.push(chunk),
            DecodeStep::Done => break,
        }
    }
    assert_eq!(got_hist_chunks, expected_hist_chunks);

    // 6. Init errors, mid-scrape syntax errors, truncated input slices, and stale cursors in
    //    `start_decode` / `step_decode`.
    assert!(matches!(
        job.decoder.start_decode(&Format::UNKNOWN, &opts),
        Err(DecodeError::UnsupportedFormat(_))
    ));
    assert!(matches!(
        job.decoder
            .start_decode_stream(&Format::TEXT, &opts.with_timestamp_ms(i64::MAX)),
        Err(DecodeError::TimestampOverflow { .. })
    ));

    let bad_bytes = b"m{a=\"1\",b=\"2\"} 1\nbad_line\n";
    let mut err_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    assert_eq!(
        job.decoder
            .step_decode(&mut err_cursor, bad_bytes, budget)
            .unwrap(),
        DecodeStep::Pending
    );
    assert!(matches!(
        job.decoder.step_decode(&mut err_cursor, bad_bytes, budget),
        Err(DecodeError::Syntax { .. })
    ));
    assert!(err_cursor.is_done());
    assert_eq!(
        job.decoder
            .step_decode(&mut err_cursor, bad_bytes, budget)
            .unwrap(),
        DecodeStep::Done
    );

    let mut trunc_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    assert_eq!(
        job.decoder
            .step_decode(&mut trunc_cursor, bad_bytes, budget)
            .unwrap(),
        DecodeStep::Pending
    );
    let trunc_pos = trunc_cursor.pos();
    assert!(matches!(
        job.decoder
            .step_decode(&mut trunc_cursor, &bad_bytes[trunc_pos..], budget),
        Err(DecodeError::InvalidCursor(
            "scrape input buffer length changed across decode steps"
        ))
    ));
    assert!(trunc_cursor.is_done());

    let mut longer_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    assert_eq!(
        job.decoder
            .step_decode(&mut longer_cursor, b"m 1\nn 2\n", budget)
            .unwrap(),
        DecodeStep::Pending
    );
    assert!(matches!(
        job.decoder
            .step_decode(&mut longer_cursor, b"m 1\nn 2\no 3\n", budget),
        Err(DecodeError::InvalidCursor(
            "scrape input buffer length changed across decode steps"
        ))
    ));
    assert!(longer_cursor.is_done());

    let mut stale_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    let mut stale_finish_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    let mut stale_after_active = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    let active_input =
        b"m{k0=\"0\",k1=\"1\",k2=\"2\",k3=\"3\",k4=\"4\",k5=\"5\",k6=\"6\",k7=\"7\",k8=\"8\",k9=\"9\",k10=\"10\",k11=\"11\",k12=\"12\",k13=\"13\",k14=\"14\",k15=\"15\",k16=\"16\",k17=\"17\"} 1\nm2 2\n";
    let mut active_cursor = job.decoder.start_decode(&Format::TEXT, &opts).unwrap();
    assert_eq!(
        job.decoder
            .step_decode(&mut active_cursor, active_input, budget)
            .unwrap(),
        DecodeStep::Pending
    );
    assert!(matches!(
        job.decoder.step_decode(&mut stale_cursor, b"m 1\n", budget),
        Err(DecodeError::InvalidCursor(
            "cursor does not belong to current decoder scrape"
        ))
    ));
    assert!(stale_cursor.is_done());
    job.decoder.finish_decode(&mut stale_finish_cursor);
    assert!(stale_finish_cursor.is_done());
    match job
        .decoder
        .step_decode(&mut active_cursor, active_input, DecodeBudget::default())
        .unwrap()
    {
        DecodeStep::Batch(records) => assert_eq!(records.num_data_points(), 2),
        other => panic!("expected active cursor to finish cleanly, got {other:?}"),
    }
    let grown_prom_cap = job.decoder.prom_spans.capacity();
    assert!(grown_prom_cap >= 18);
    job.decoder.finish_decode(&mut stale_after_active);
    assert!(stale_after_active.is_done());
    assert_eq!(job.decoder.prom_spans.capacity(), grown_prom_cap);

    let mut om_holder = job
        .decoder
        .start_decode(&Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();
    let mut stale_om_cursor = job
        .decoder
        .start_decode(&Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();
    job.decoder.finish_decode(&mut om_holder);
    assert_eq!(
        job.decoder.om_scratch.retained_memory_bytes(),
        retained_after_first
    );
    job.decoder.finish_decode(&mut stale_om_cursor);
    assert_eq!(
        job.decoder.om_scratch.retained_memory_bytes(),
        retained_after_first
    );

    let mut dec_a = ArrowDecoder::new();
    let mut dec_b = ArrowDecoder::new();
    let mut cursor_from_a = dec_a.start_decode(&Format::TEXT, &opts).unwrap();
    let _ = dec_b.start_decode(&Format::TEXT, &opts).unwrap();
    assert!(matches!(
        dec_b.step_decode(&mut cursor_from_a, b"y 3\n", budget),
        Err(DecodeError::InvalidCursor(
            "cursor does not belong to current decoder scrape"
        ))
    ));
    assert!(cursor_from_a.is_done());
}

#[test]
fn cooperative_async_helpers_respect_fast_path_and_yield_budgets() {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    struct YieldOnce(bool);
    impl Future for YieldOnce {
        type Output = ();
        fn poll(mut self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }

    fn drive_future<F: Future>(fut: F) -> (F::Output, usize) {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        let mut polls_after_first = 0usize;
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return (out, polls_after_first),
                Poll::Pending => polls_after_first += 1,
            }
        }
    }

    let mut payload = String::from("# TYPE c counter\n");
    for i in 0..40 {
        payload.push_str(&format!("c{{id=\"{i}\"}} {i}\n"));
    }
    let bytes = payload.as_bytes();
    let opts = DecodeOptions::new().with_timestamp_ms(1_700_000_000_000);

    let mut dec = ArrowDecoder::new();
    let expected = dec.decode(bytes, &Format::TEXT, &opts).unwrap();

    // 1. Single-poll path: when the scrape fits within `budget`, `decode_cooperative` completes
    //    in a single poll with zero yields.
    let mut fast_yields = 0usize;
    let fast_budget = DecodeBudget::default();
    assert!(bytes.len() <= fast_budget.max_bytes);
    let (fast_res, fast_polls) =
        drive_future(
            dec.decode_cooperative(bytes, &Format::TEXT, &opts, fast_budget, || {
                fast_yields += 1;
                YieldOnce(false)
            }),
        );
    assert_eq!(fast_res.unwrap(), expected);
    assert_eq!(fast_yields, 0);
    assert_eq!(fast_polls, 0);

    // 2. Cooperative path: when `budget` is exceeded (even if `max_bytes` is raised above
    //    `bytes.len()`), `decode_cooperative` yields between bounded steps and produces the exact
    //    same `OtapMetricRecords`.
    let mut coop_yields = 0usize;
    let coop_budget = DecodeBudget::new(5, 8 << 20, std::time::Duration::from_secs(60));
    assert!(bytes.len() <= coop_budget.max_bytes);
    let (coop_res, coop_polls) =
        drive_future(
            dec.decode_cooperative(bytes, &Format::TEXT, &opts, coop_budget, || {
                coop_yields += 1;
                YieldOnce(false)
            }),
        );
    assert_eq!(coop_res.unwrap(), expected);
    assert!(coop_yields >= 5);
    assert_eq!(coop_polls, coop_yields);

    // 3. `DecodeStream::next_cooperative` yields between steps while streaming chunks.
    let stream_opts = opts.with_max_data_points_per_batch(15);
    let expected_chunks: Vec<_> = dec
        .decode_stream(bytes, &Format::TEXT, &stream_opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut stream_yields = 0usize;
    let (got_chunks, stream_polls) = drive_future(async {
        let mut stream = dec.decode_stream(bytes, &Format::TEXT, &stream_opts);
        let mut out = Vec::new();
        while let Some(res) = stream
            .next_cooperative(coop_budget, || {
                stream_yields += 1;
                YieldOnce(false)
            })
            .await
        {
            out.push(res.unwrap());
        }
        out
    });
    assert_eq!(got_chunks, expected_chunks);
    assert!(stream_yields >= 5);
    assert_eq!(stream_polls, stream_yields);

    // 4. Dropping a suspended `decode_cooperative` future at `Poll::Pending` reclaims parser
    //    scratch capacity and resets partial scrape state, and mid-scrape errors propagate after
    //    yielding.
    {
        let fut = dec.decode_cooperative(bytes, &Format::TEXT, &opts, coop_budget, || {
            YieldOnce(false)
        });
        let mut pinned = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(pinned.as_mut().poll(&mut cx), Poll::Pending));
    }
    assert!(dec.prom_spans.capacity() > 0);
    assert!(dec.metrics.is_empty());

    let bad_coop = b"m{a=\"1\",b=\"2\",c=\"3\",d=\"4\"} 1\nbad_line\n";
    let err_budget = DecodeBudget::new(1, 8, std::time::Duration::from_secs(60));
    let (coop_err, err_polls) =
        drive_future(
            dec.decode_cooperative(bad_coop, &Format::TEXT, &opts, err_budget, || {
                YieldOnce(false)
            }),
        );
    assert!(matches!(coop_err, Err(DecodeError::Syntax { .. })));
    assert_eq!(err_polls, 1);

    let (empty_coop, empty_polls) = drive_future(dec.decode_cooperative(
        b"# comment exceeding max_bytes threshold\n",
        &Format::TEXT,
        &opts,
        err_budget,
        || YieldOnce(false),
    ));
    assert!(empty_coop.unwrap().is_empty());
    assert_eq!(empty_polls, 1);

    let (stream_err_res, stream_err_polls) = drive_future(async {
        let mut stream = dec.decode_stream(bad_coop, &Format::TEXT, &stream_opts);
        let first = stream
            .next_cooperative(err_budget, || YieldOnce(false))
            .await;
        let second = stream
            .next_cooperative(err_budget, || YieldOnce(false))
            .await;
        (first, second)
    });
    assert!(matches!(
        stream_err_res.0,
        Some(Err(DecodeError::Syntax { .. }))
    ));
    assert!(stream_err_res.1.is_none());
    assert_eq!(stream_err_polls, 1);
}
