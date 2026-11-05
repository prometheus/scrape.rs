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
fn staging_ranges_and_column_accessors_match_emitted_rows() {
    let payload = br#"# TYPE c_seconds counter
# HELP c_seconds counter help
# UNIT c_seconds seconds
c_seconds_total 1 1.0
c_seconds_total{k="v1",k2="v2"} 2 2.0 # {trace_id="0102030405060708090a0b0c0d0e0f10",span_id="0102030405060708",user="u1"} 1.5 2.5
c_seconds_created 0.5
# TYPE g gauge
g{a="1"} 10
# TYPE h histogram
h_bucket{le="1.0"} 3 # {span_id="1112131415161718",route="/a"} 0.5 3.0
h_bucket{le="+Inf"} 5
h_sum 12.5
h_count 5
# TYPE s summary
s{q="x",quantile="0.5"} 4.0
# EOF
"#;

    let mut dec = ArrowDecoder::new();
    let _records = dec
        .decode(
            payload,
            &Format::OPEN_METRICS_1_0_0,
            &DecodeOptions::default(),
        )
        .unwrap();

    assert_eq!(dec.metrics.len(), 4);
    assert_eq!(dec.metrics.name_at(0), b"c_seconds_total");
    assert_eq!(dec.metrics.desc.get_bytes(0), b"counter help");
    assert_eq!(dec.metrics.unit.get_bytes(0), b"seconds");
    assert_eq!(dec.metrics.dp_ranges[0], (0, 2));

    assert_eq!(dec.metrics.name_at(1), b"g");
    assert_eq!(dec.metrics.desc.get_bytes(1), b"");
    assert_eq!(dec.metrics.unit.get_bytes(1), b"");
    assert_eq!(dec.metrics.dp_ranges[1], (2, 3));

    assert_eq!(dec.metrics.name_at(2), b"h");
    assert_eq!(dec.metrics.dp_ranges[2], (0, 1));

    assert_eq!(dec.metrics.name_at(3), b"s");
    assert_eq!(dec.metrics.dp_ranges[3], (0, 1));

    // DP 0 has no attributes or exemplars; DP 1 has 2 attributes and 1 exemplar; DP 2 has 1 attribute.
    assert_eq!(dec.num_dp.attrs.range_for_parent(0), 0..0);
    assert_eq!(dec.num_dp.attrs.range_for_parent(1), 0..2);
    assert_eq!(dec.num_dp.attrs.range_for_parent(2), 2..3);
    assert_eq!(dec.num_dp.attrs.range_for_parent(3), 0..0);

    assert_eq!(dec.num_dp.exemplars.range_for_dp(0), 0..0);
    assert_eq!(dec.num_dp.exemplars.range_for_dp(1), 0..1);
    assert_eq!(dec.num_dp.exemplars.range_for_dp(2), 0..0);
    assert_eq!(dec.num_dp.exemplars.attrs.range_for_parent(0), 0..1);
    assert_eq!(
        dec.num_dp.exemplars.span_ids.get(0),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert_eq!(
        dec.num_dp.exemplars.trace_ids.get(0),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    );

    assert_eq!(dec.num_dp.base.start_time.get_u64(0), 500_000_000);
    assert_eq!(dec.num_dp.base.time.get_u64(0), 1_000_000_000);
    assert_eq!(dec.num_dp.base.start_time.get_u64(2), 0);
    assert_eq!(dec.num_dp.base.time.get_u64(2), 0);

    assert_eq!(dec.hist_dp.counts.get(0), Some(5));
    assert_eq!(dec.hist_dp.sums.get(0), Some(12.5));
    assert_eq!(dec.hist_dp.exemplars.range_for_dp(0), 0..1);
    assert_eq!(dec.hist_dp.exemplars.trace_ids.get(0), None);

    assert_eq!(dec.sum_dp.counts.get(0), None);
    assert_eq!(dec.sum_dp.sums.get(0), None);
    assert_eq!(dec.sum_dp.attrs.range_for_parent(0), 0..1);
}

#[test]
fn decode_view_and_stream_next_view_traverse_all_metric_types() {
    use otel_arrow_dfe_pdata_views::views::common::{AnyValueView, AttributeView, ValueType};
    use otel_arrow_dfe_pdata_views::views::metrics::{
        AggregationTemporality, DataType, DataView, ExemplarView, GaugeView,
        HistogramDataPointView, HistogramView, MetricView, MetricsView, NumberDataPointView,
        ResourceMetricsView, ScopeMetricsView, SumView, SummaryDataPointView, SummaryView, Value,
        ValueAtQuantileView,
    };

    let payload = br#"# TYPE c_seconds counter
# HELP c_seconds counter help
# UNIT c_seconds seconds
c_seconds_total{method="GET"} 42 2.0 # {trace_id="0102030405060708090a0b0c0d0e0f10",span_id="0102030405060708",user="u1"} 1.0 2.5
c_seconds_created{method="GET"} 1.0
# TYPE g gauge
g{host="a"} 3.5 4.0 # {trace_id="00000000000000000000000000000000",span_id="0000000000000000"} 3.5 4.0
# TYPE h histogram
h_bucket{le="1.0",svc="api"} 2 # {span_id="1112131415161718",route="/v1"} 0.5 3.0
h_bucket{le="+Inf",svc="api"} 5
h_sum{svc="api"} 9.25
h_count{svc="api"} 5
# TYPE s summary
s{q="p",quantile="0.5"} 1.25
s{q="p",quantile="0.99"} 4.75
s_sum{q="p"} 15.0
s_count{q="p"} 10
# EOF
"#;

    let mut dec = ArrowDecoder::new();
    let empty_view = dec
        .decode_view(
            b"# EOF\n",
            &Format::OPEN_METRICS_1_0_0,
            &DecodeOptions::default(),
        )
        .unwrap();
    assert!(empty_view.is_empty());
    assert_eq!(empty_view.num_metrics(), 0);
    assert_eq!(empty_view.num_data_points(), 0);
    assert_eq!(empty_view.resources().count(), 0);

    let view = dec
        .decode_view(
            payload,
            &Format::OPEN_METRICS_1_0_0,
            &DecodeOptions::default(),
        )
        .unwrap();
    assert!(!view.is_empty());
    assert_eq!(view.num_metrics(), 4);
    assert_eq!(view.num_data_points(), 4);

    let res = view.resources().next().unwrap();
    assert!(res.resource().is_none());
    assert!(res.schema_url().is_none());
    let scope = res.scopes().next().unwrap();
    assert!(scope.scope().is_none());
    assert_eq!(scope.schema_url(), b"");

    let metrics: Vec<_> = scope.metrics().collect();
    assert_eq!(metrics.len(), 4);

    // 0: Counter (`Sum`)
    assert_eq!(metrics[0].name(), b"c_seconds_total");
    assert_eq!(metrics[0].description(), b"counter help");
    assert_eq!(metrics[0].unit(), b"seconds");
    let m0_meta = metrics[0].metadata().next().unwrap();
    assert_eq!(m0_meta.key(), b"prometheus.type");
    assert_eq!(m0_meta.value().unwrap().value_type(), ValueType::String);
    assert_eq!(m0_meta.value().unwrap().as_string(), Some(&b"counter"[..]));
    let d0 = metrics[0].data().unwrap();
    assert_eq!(d0.value_type(), DataType::Sum);
    let sum0 = d0.as_sum().unwrap();
    assert_eq!(
        sum0.aggregation_temporality(),
        AggregationTemporality::Cumulative
    );
    assert!(sum0.is_monotonic());
    let dp0 = sum0.data_points().next().unwrap();
    assert_eq!(dp0.start_time_unix_nano(), 1_000_000_000);
    assert_eq!(dp0.time_unix_nano(), 2_000_000_000);
    assert_eq!(dp0.value(), Some(Value::Double(42.0)));
    let dp0_attr = dp0.attributes().next().unwrap();
    assert_eq!(dp0_attr.key(), b"method");
    assert_eq!(dp0_attr.value().unwrap().as_string(), Some(&b"GET"[..]));
    let ex0 = dp0.exemplars().next().unwrap();
    assert_eq!(ex0.value(), Some(Value::Double(1.0)));
    assert_eq!(ex0.time_unix_nano(), 2_500_000_000);
    assert_eq!(ex0.span_id(), Some(&[1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(
        ex0.trace_id(),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    );
    let ex0_attr = ex0.filtered_attributes().next().unwrap();
    assert_eq!(ex0_attr.key(), b"user");
    assert_eq!(ex0_attr.value().unwrap().as_string(), Some(&b"u1"[..]));

    // 1: Gauge with all-zero exemplar span_id/trace_id filtered to `None`
    let d1 = metrics[1].data().unwrap();
    let g1 = d1.as_gauge().unwrap();
    let dp1 = g1.data_points().next().unwrap();
    assert_eq!(dp1.value(), Some(Value::Double(3.5)));
    let ex1 = dp1.exemplars().next().unwrap();
    assert_eq!(ex1.span_id(), None);
    assert_eq!(ex1.trace_id(), None);

    // 2: Histogram
    let d2 = metrics[2].data().unwrap();
    let h2 = d2.as_histogram().unwrap();
    assert_eq!(
        h2.aggregation_temporality(),
        AggregationTemporality::Cumulative
    );
    let hdp = h2.data_points().next().unwrap();
    assert_eq!(hdp.count(), 5);
    assert_eq!(hdp.sum(), Some(9.25));
    assert_eq!(hdp.explicit_bounds().collect::<Vec<_>>(), vec![1.0]);
    assert_eq!(hdp.bucket_counts().collect::<Vec<_>>(), vec![2, 3]);
    assert_eq!(hdp.exemplars().count(), 1);

    // 3: Summary
    let d3 = metrics[3].data().unwrap();
    let s3 = d3.as_summary().unwrap();
    let sdp = s3.data_points().next().unwrap();
    assert_eq!(sdp.count(), 10);
    assert_eq!(sdp.sum(), 15.0);
    let qvs: Vec<_> = sdp
        .quantile_values()
        .map(|qv| (qv.quantile(), qv.value()))
        .collect();
    assert_eq!(qvs, vec![(0.5, 1.25), (0.99, 4.75)]);

    // Verify `DecodeStream::next_view` chunking.
    let opts = DecodeOptions {
        max_data_points_per_batch: 2,
        ..DecodeOptions::default()
    };
    let mut stream = dec.decode_stream(payload, &Format::OPEN_METRICS_1_0_0, &opts);
    let mut chunk_counts = Vec::new();
    while let Some(res) = stream.next_view() {
        let v = res.unwrap();
        chunk_counts.push((v.num_metrics(), v.num_data_points()));
    }
    assert_eq!(chunk_counts, vec![(2, 2), (2, 2)]);
}
