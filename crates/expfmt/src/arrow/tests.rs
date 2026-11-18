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
    let stream_opts = opts.clone().with_max_data_points_per_batch(1);
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
            .start_decode_stream(&Format::TEXT, &opts.clone().with_timestamp_ms(i64::MAX)),
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
    let stream_opts = opts.clone().with_max_data_points_per_batch(15);
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

#[test]
fn target_attributes_emit_resource_attrs_and_map_job_and_instance() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use arrow_array::UInt16Array;

    let target = Arc::new(
        TargetAttributes::from_target_labels([
            ("__address__", "10.0.0.1:9100"),
            ("__meta_kubernetes_pod_name", "api-0"),
            ("job", "api-server"),
            ("instance", "10.0.0.1:9100"),
            ("env", "prod"),
            ("empty_label", ""),
        ])
        .with_resource_attribute("cloud.region", "us-central1"),
    );

    assert_eq!(
        target.target_labels(),
        &BTreeMap::from([
            ("env".to_owned(), "prod".to_owned()),
            ("instance".to_owned(), "10.0.0.1:9100".to_owned()),
            ("job".to_owned(), "api-server".to_owned()),
        ])
    );
    assert_eq!(
        target.resource_attributes(),
        &BTreeMap::from([
            ("cloud.region".to_owned(), "us-central1".to_owned()),
            ("env".to_owned(), "prod".to_owned()),
            (
                SERVICE_INSTANCE_ID_ATTR.to_owned(),
                "10.0.0.1:9100".to_owned()
            ),
            (SERVICE_NAME_ATTR.to_owned(), "api-server".to_owned()),
        ])
    );

    let opts = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_target_attributes(Arc::clone(&target));

    let payload =
        b"# TYPE reqs_total counter\nreqs_total{method=\"GET\"} 1\nreqs_total{method=\"POST\"} 2\n";
    let mut dec = ArrowDecoder::new();
    let records = dec.decode(payload, &Format::TEXT, &opts).unwrap();

    let res_batch = records
        .resource_attrs()
        .expect("ResourceAttrs emitted on non-empty scrape");
    assert_eq!(
        records.get(MetricPayloadType::ResourceAttrs),
        Some(res_batch)
    );
    assert_eq!(res_batch.num_rows(), 4);
    assert_eq!(
        res_batch
            .schema()
            .field_with_name("parent_id")
            .unwrap()
            .metadata()
            .get("encoding")
            .map(String::as_str),
        Some("plain")
    );

    let parent_ids = res_batch
        .column_by_name("parent_id")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt16Array>()
        .unwrap();
    let keys = res_batch
        .column_by_name("key")
        .unwrap()
        .as_any()
        .downcast_ref::<DictionaryArray<UInt8Type>>()
        .unwrap();
    let key_vals = keys
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let types = res_batch
        .column_by_name("type")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt8Array>()
        .unwrap();
    let vals = res_batch
        .column_by_name("str")
        .unwrap()
        .as_any()
        .downcast_ref::<DictionaryArray<UInt16Type>>()
        .unwrap();
    let str_vals = vals
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();

    let mut extracted = BTreeMap::new();
    for row in 0..res_batch.num_rows() {
        assert_eq!(parent_ids.value(row), 0);
        assert_eq!(types.value(row), 1);
        let k = key_vals.value(usize::from(keys.keys().value(row)));
        let v = str_vals.value(usize::from(vals.keys().value(row)));
        extracted.insert(k.to_owned(), v.to_owned());
    }
    assert_eq!(&extracted, target.resource_attributes());

    // Multi-chunk streaming attaches `ResourceAttrs` to every emitted chunk.
    let stream_opts = opts.clone().with_max_data_points_per_batch(1);
    let chunks: Vec<_> = dec
        .decode_stream(payload, &Format::TEXT, &stream_opts)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(chunks.len(), 2);
    for chunk in &chunks {
        assert_eq!(chunk.resource_attrs(), Some(res_batch));
    }

    // Empty and all-dropped scrapes omit `ResourceAttrs`.
    let empty = dec.decode(b"", &Format::TEXT, &opts).unwrap();
    assert!(empty.is_empty());
    assert!(empty.resource_attrs().is_none());

    let dropped_opts = opts.clone().with_untyped_policy(UntypedPolicy::Drop);
    let dropped = dec
        .decode(b"untyped_only 1\n", &Format::TEXT, &dropped_opts)
        .unwrap();
    assert!(dropped.is_empty());
    assert!(dropped.resource_attrs().is_none());

    // Explicit resource attributes override `job` -> `service.name` while keeping `job` in
    // `target_labels`.
    let overridden = TargetAttributes::new()
        .with_job("prom-job")
        .with_instance("host:9090")
        .with_resource_attribute(SERVICE_NAME_ATTR, "explicit-service");
    assert_eq!(
        overridden.target_labels().get("job").map(String::as_str),
        Some("prom-job")
    );
    assert_eq!(
        overridden
            .resource_attributes()
            .get(SERVICE_NAME_ATTR)
            .map(String::as_str),
        Some("explicit-service")
    );
    assert_eq!(
        overridden
            .resource_attributes()
            .get(SERVICE_INSTANCE_ID_ATTR)
            .map(String::as_str),
        Some("host:9090")
    );

    // Reserved-only and cleared target labels stay empty and omit `ResourceAttrs`.
    let reserved_only = TargetAttributes::from_target_labels([
        ("__address__", "10.0.0.1:9100"),
        ("__meta_foo", "bar"),
    ])
    .with_job("temp")
    .with_job("");
    assert!(reserved_only.is_empty());
    let reserved_opts = DecodeOptions::new().with_target_attributes(Arc::new(reserved_only));
    let reserved_records = dec.decode(b"m 1\n", &Format::TEXT, &reserved_opts).unwrap();
    assert!(reserved_records.resource_attrs().is_none());

    // `Clone` and `Eq` treat cached vs uncached `TargetAttributes` identically.
    let uncached = TargetAttributes::new()
        .with_job("api-server")
        .with_instance("10.0.0.1:9100")
        .with_target_label("env", "prod")
        .with_resource_attribute("cloud.region", "us-central1");
    assert_eq!(*target, uncached);
    assert_eq!(target.as_ref().clone(), uncached);

    // >256 resource attributes widen `ResourceAttrs.key` from UInt8 to UInt16 dictionary.
    let mut wide_target = TargetAttributes::new();
    for i in 0..260 {
        wide_target = wide_target.with_target_label(format!("res_k_{i}"), "v");
    }
    let wide_opts = DecodeOptions::new().with_target_attributes(Arc::new(wide_target));
    let wide_records = dec.decode(b"m 1\n", &Format::TEXT, &wide_opts).unwrap();
    let wide_res = wide_records.resource_attrs().unwrap();
    assert_eq!(wide_res.num_rows(), 260);
    assert_eq!(
        wide_res
            .schema()
            .field_with_name("key")
            .unwrap()
            .data_type(),
        &DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8))
    );
}

fn extract_attrs_by_parent_u32(
    batch: Option<&arrow_array::RecordBatch>,
) -> std::collections::BTreeMap<u32, std::collections::BTreeMap<String, String>> {
    use std::collections::BTreeMap;

    use arrow_array::UInt32Array;

    let mut out: BTreeMap<u32, BTreeMap<String, String>> = BTreeMap::new();
    let Some(batch) = batch else {
        return out;
    };
    let parents = batch
        .column_by_name("parent_id")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    let key_col = batch.column_by_name("key").unwrap();
    let val_col = batch.column_by_name("str").unwrap();

    let read_str = |col: &arrow_array::ArrayRef, row: usize| -> String {
        if let Some(d) = col.as_any().downcast_ref::<DictionaryArray<UInt8Type>>() {
            let vals = d.values().as_any().downcast_ref::<StringArray>().unwrap();
            vals.value(usize::from(d.keys().value(row))).to_owned()
        } else if let Some(d) = col.as_any().downcast_ref::<DictionaryArray<UInt16Type>>() {
            let vals = d.values().as_any().downcast_ref::<StringArray>().unwrap();
            vals.value(usize::from(d.keys().value(row))).to_owned()
        } else {
            col.as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(row)
                .to_owned()
        }
    };

    for row in 0..batch.num_rows() {
        out.entry(parents.value(row))
            .or_default()
            .insert(read_str(key_col, row), read_str(val_col, row));
    }
    out
}

fn extract_resource_attrs(
    batch: Option<&arrow_array::RecordBatch>,
) -> std::collections::BTreeMap<String, String> {
    use std::collections::BTreeMap;

    let mut out = BTreeMap::new();
    let Some(batch) = batch else {
        return out;
    };
    let key_col = batch.column_by_name("key").unwrap();
    let val_col = batch.column_by_name("str").unwrap();
    let read_str = |col: &arrow_array::ArrayRef, row: usize| -> String {
        if let Some(d) = col.as_any().downcast_ref::<DictionaryArray<UInt8Type>>() {
            let vals = d.values().as_any().downcast_ref::<StringArray>().unwrap();
            vals.value(usize::from(d.keys().value(row))).to_owned()
        } else if let Some(d) = col.as_any().downcast_ref::<DictionaryArray<UInt16Type>>() {
            let vals = d.values().as_any().downcast_ref::<StringArray>().unwrap();
            vals.value(usize::from(d.keys().value(row))).to_owned()
        } else {
            col.as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(row)
                .to_owned()
        }
    };
    for row in 0..batch.num_rows() {
        out.insert(read_str(key_col, row), read_str(val_col, row));
    }
    out
}

#[test]
fn honor_labels_collision_resolution_and_exemplar_preservation() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let target = Arc::new(TargetAttributes::from_target_labels([
        ("job", "prom-job"),
        ("instance", "10.0.0.1:9090"),
        ("foo", "target-foo"),
        ("exported_foo", "target-exported-foo"),
    ]));

    let payload = concat!(
        "# TYPE req_total counter\n",
        "req_total{job=\"sample-job\",foo=\"1\",exported_foo=\"2\",method=\"GET\"} 7 # {job=\"ex-job\",trace_id=\"00112233445566778899aabbccddeeff\"} 1 1700000000\n",
        "# EOF\n",
    );

    let mut dec = ArrowDecoder::new();

    // `honor_labels = false` (default): colliding series keys get `exported_` prefixing in
    // ascending key-length order, while exemplar attributes stay untouched.
    let opts_false = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_target_attributes(Arc::clone(&target));
    let rec_false = dec
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts_false)
        .unwrap();
    let dp_attrs = extract_attrs_by_parent_u32(rec_false.number_dp_attrs());
    assert_eq!(
        dp_attrs.get(&0),
        Some(&BTreeMap::from([
            ("exported_exported_exported_foo".to_owned(), "2".to_owned()),
            ("exported_exported_foo".to_owned(), "1".to_owned()),
            ("exported_job".to_owned(), "sample-job".to_owned()),
            ("method".to_owned(), "GET".to_owned()),
        ]))
    );
    let ex_attrs = extract_attrs_by_parent_u32(rec_false.number_dp_exemplar_attrs());
    assert_eq!(
        ex_attrs.get(&0),
        Some(&BTreeMap::from([("job".to_owned(), "ex-job".to_owned())]))
    );

    // `honor_labels = true`: exposed metric labels stay unprefixed.
    let opts_true = opts_false.with_honor_labels(true);
    let rec_true = dec
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts_true)
        .unwrap();
    let dp_attrs_true = extract_attrs_by_parent_u32(rec_true.number_dp_attrs());
    assert_eq!(
        dp_attrs_true.get(&0),
        Some(&BTreeMap::from([
            ("exported_foo".to_owned(), "2".to_owned()),
            ("foo".to_owned(), "1".to_owned()),
            ("job".to_owned(), "sample-job".to_owned()),
            ("method".to_owned(), "GET".to_owned()),
        ]))
    );
}

#[test]
fn stage1_pushdown_filters_wire_series_across_scalar_histogram_and_cooperative_streaming() {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use prometheus_relabel::{Action, Config, METRIC_NAME_LABEL, Regexp};

    let payload = concat!(
        "# TYPE http_requests_total counter\n",
        "http_requests_total{method=\"GET\"} 10\n",
        "http_requests_total{method=\"POST\"} 20\n",
        "# TYPE go_goroutines gauge\n",
        "go_goroutines 42\n",
        "# TYPE http_latency_seconds histogram\n",
        "http_latency_seconds_bucket{le=\"0.5\"} 3\n",
        "http_latency_seconds_bucket{le=\"+Inf\"} 5\n",
        "http_latency_seconds_sum 2.5\n",
        "http_latency_seconds_count 5\n",
        "# TYPE rpc_latency_seconds summary\n",
        "rpc_latency_seconds{quantile=\"0.5\"} 0.1\n",
        "rpc_latency_seconds_sum 1.0\n",
        "rpc_latency_seconds_count 10\n",
    );

    // Keep only `http_*` wire series and drop histogram `*_bucket` series at Stage 1.
    let plan = MetricRelabelPlan::new(vec![
        Config {
            source_labels: vec![METRIC_NAME_LABEL.to_owned()],
            regex: Regexp::must_new("http_.*"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            source_labels: vec![METRIC_NAME_LABEL.to_owned()],
            regex: Regexp::must_new(".*_bucket"),
            action: Action::Drop,
            ..Config::default()
        },
    ]);
    assert_eq!(plan.stage1_configs().len(), 2);
    assert!(plan.stage2_configs().is_empty());

    let opts = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_metric_relabel_plan(std::sync::Arc::new(plan));

    let mut dec = ArrowDecoder::new();
    let rec = dec
        .decode(payload.as_bytes(), &Format::TEXT, &opts)
        .unwrap();
    let metrics = rec.univariate_metrics().unwrap();
    let names = metrics
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let emitted_names: Vec<&str> = (0..names.len()).map(|i| names.value(i)).collect();
    assert_eq!(
        emitted_names,
        vec!["http_requests_total", "http_latency_seconds"]
    );
    assert!(rec.summary_data_points().is_none());
    let hist = rec.histogram_data_points().unwrap();
    assert_eq!(hist.num_rows(), 1);
    let bounds = hist
        .column_by_name("explicit_bounds")
        .unwrap()
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    assert_eq!(bounds.value(0).len(), 0);

    // Cooperative decoding still respects budgets even when Stage 1 drops 100% of series.
    let drop_all_opts = DecodeOptions::new().with_metric_relabel_configs(vec![Config {
        source_labels: vec![METRIC_NAME_LABEL.to_owned()],
        regex: Regexp::must_new(".*"),
        action: Action::Drop,
        ..Config::default()
    }]);
    let mut yields = 0usize;
    let budget = DecodeBudget::new(2, 8 << 20, std::time::Duration::from_secs(60));
    let dropped_res = {
        let mut fut = pin!(dec.decode_cooperative(
            payload.as_bytes(),
            &Format::TEXT,
            &drop_all_opts,
            budget,
            || {
                yields += 1;
                std::future::ready(())
            },
        ));
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(res) = fut.as_mut().poll(&mut cx) {
                break res.unwrap();
            }
        }
    };
    assert!(dropped_res.is_empty());
    assert!(yields > 0);
}

#[test]
fn stage2_dictionary_relabeling_covers_labeldrop_filters_transforms_targets_and_empty_chunks() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use prometheus_relabel::{Action, Config, Regexp, ValidationScheme};

    let target = Arc::new(
        TargetAttributes::from_target_labels([
            ("job", "api"),
            ("instance", "10.0.0.1:9090"),
            ("env", "prod"),
            ("drop_target", "bye"),
        ])
        .with_resource_attribute("cloud.region", "us-east1"),
    );

    let payload = concat!(
        "# TYPE drop_me_gauge gauge\n",
        "drop_me_gauge{env_tag=\"DEV\",pod=\"worker-1111\",ephemeral_a=\"x\"} 1\n",
        "# TYPE keep_me_total counter\n",
        "keep_me_total{env_tag=\"DEV\",pod=\"api-dead\",ephemeral_a=\"x\"} 2 # {trace_id=\"00112233445566778899aabbccddeeff\",ex_k=\"dropped\"} 2 1700000000\n",
        "keep_me_total{env_tag=\"PROD\",pod=\"api-7f8b\",ephemeral_a=\"x\"} 5 # {trace_id=\"ffeeddccbbaa99887766554433221100\",ex_k=\"kept\"} 5 1700000000\n",
        "# EOF\n",
    );

    let plan = Arc::new(
        MetricRelabelPlan::try_new(
            vec![
                Config {
                    regex: Regexp::must_new("ephemeral_.*|drop_target"),
                    action: Action::LabelDrop,
                    ..Config::default()
                },
                Config {
                    source_labels: vec!["env".to_owned()],
                    regex: Regexp::must_new("prod"),
                    action: Action::Keep,
                    ..Config::default()
                },
                Config {
                    source_labels: vec!["env_tag".to_owned()],
                    regex: Regexp::must_new("PROD"),
                    action: Action::Keep,
                    ..Config::default()
                },
                Config {
                    source_labels: vec!["env_tag".to_owned()],
                    target_label: "env_tag".to_owned(),
                    action: Action::Lowercase,
                    ..Config::default()
                },
                Config {
                    source_labels: vec!["pod".to_owned()],
                    regex: Regexp::must_new("([a-z0-9-]+)-[0-9a-f]+"),
                    target_label: "app".to_owned(),
                    replacement: "$1".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
                Config {
                    source_labels: vec!["job".to_owned()],
                    target_label: "job".to_owned(),
                    action: Action::Uppercase,
                    ..Config::default()
                },
            ],
            ValidationScheme::Utf8,
        )
        .unwrap(),
    );

    let opts = DecodeOptions::new()
        .with_timestamp_ms(1_700_000_000_000)
        .with_target_attributes(target)
        .with_metric_relabel_plan(plan);

    let mut dec = ArrowDecoder::new();
    let rec = dec
        .decode(payload.as_bytes(), &Format::OPEN_METRICS_1_0_0, &opts)
        .unwrap();

    // `drop_me_gauge` was completely pruned; only `keep_me_total` with `env_tag="prod"` survives.
    let metrics = rec.univariate_metrics().unwrap();
    assert_eq!(metrics.num_rows(), 1);
    let names = metrics
        .column_by_name("name")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(names.value(0), "keep_me_total");

    let dps = rec.number_data_points().unwrap();
    assert_eq!(dps.num_rows(), 1);
    let dp_attrs = extract_attrs_by_parent_u32(rec.number_dp_attrs());
    assert_eq!(
        dp_attrs.get(&0),
        Some(&BTreeMap::from([
            ("app".to_owned(), "api".to_owned()),
            ("env_tag".to_owned(), "prod".to_owned()),
            ("pod".to_owned(), "api-7f8b".to_owned()),
        ]))
    );

    // Only the surviving data point's exemplar remains, re-indexed to `parent_id = 0`.
    let exemplars = rec.number_dp_exemplars().unwrap();
    assert_eq!(exemplars.num_rows(), 1);
    let ex_attrs = extract_attrs_by_parent_u32(rec.number_dp_exemplar_attrs());
    assert_eq!(
        ex_attrs.get(&0),
        Some(&BTreeMap::from([("ex_k".to_owned(), "kept".to_owned())]))
    );

    // `drop_target` was removed and `job` was uppercased to `"API"` -> `service.name = "API"`.
    let res_attrs = extract_resource_attrs(rec.resource_attrs());
    assert_eq!(
        res_attrs,
        BTreeMap::from([
            ("cloud.region".to_owned(), "us-east1".to_owned()),
            ("env".to_owned(), "prod".to_owned()),
            (
                SERVICE_INSTANCE_ID_ATTR.to_owned(),
                "10.0.0.1:9090".to_owned()
            ),
            (SERVICE_NAME_ATTR.to_owned(), "API".to_owned()),
        ])
    );

    // Streaming with `max_data_points_per_batch = 1` skips chunks whose points are all dropped.
    let stream_opts = opts.with_max_data_points_per_batch(1);
    let chunks: Vec<_> = dec
        .decode_stream(
            payload.as_bytes(),
            &Format::OPEN_METRICS_1_0_0,
            &stream_opts,
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].num_data_points(), 1);
}

#[test]
fn stage2_general_fallback_and_end_to_end_oracle_match_prometheus() {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use prometheus_relabel::{
        Action, Config, LabelSet, METRIC_NAME_LABEL, Regexp, merge_target_and_metric_labels,
        process_in_place,
    };

    // 1. General rules: metric rename splitting one family into two, `labelmap`, and multi-label `replace`.
    let target_labels = LabelSet::from([
        ("job".to_owned(), "checkout".to_owned()),
        ("instance".to_owned(), "10.0.0.2:8080".to_owned()),
        ("region".to_owned(), "eu".to_owned()),
    ]);
    let target = Arc::new(TargetAttributes::from_target_labels(&target_labels));

    let cfgs = vec![
        Config {
            source_labels: vec![METRIC_NAME_LABEL.to_owned()],
            regex: Regexp::must_new("(http|app)_.*"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            regex: Regexp::must_new("tmp_.*"),
            action: Action::LabelDrop,
            ..Config::default()
        },
        Config {
            source_labels: vec!["region".to_owned(), "method".to_owned()],
            separator: ":".to_owned(),
            regex: Regexp::must_new("(.+):(.+)"),
            target_label: "route".to_owned(),
            replacement: "$1/$2".to_owned(),
            action: Action::Replace,
            ..Config::default()
        },
        Config {
            regex: Regexp::must_new("meta_(.+)"),
            replacement: "m_$1".to_owned(),
            action: Action::LabelMap,
            ..Config::default()
        },
        Config {
            source_labels: vec![METRIC_NAME_LABEL.to_owned(), "v".to_owned()],
            separator: "_".to_owned(),
            regex: Regexp::must_new("app_events_(v[12])"),
            target_label: METRIC_NAME_LABEL.to_owned(),
            replacement: "app_events_$1".to_owned(),
            action: Action::Replace,
            ..Config::default()
        },
    ];

    type OracleSample<'a> = (&'a str, &'a [(&'a str, &'a str)], f64);

    let samples: &[OracleSample<'_>] = &[
        (
            "http_reqs_total",
            &[
                ("job", "inner"),
                ("method", "GET"),
                ("tmp_x", "1"),
                ("meta_a", "z"),
            ],
            10.0,
        ),
        ("go_gc_seconds", &[("method", "GET")], 1.0),
        ("app_events", &[("v", "v1"), ("method", "POST")], 3.0),
        ("app_events", &[("v", "v2"), ("method", "PUT")], 4.0),
    ];

    let mut payload = String::new();
    for (name, labels, val) in samples {
        payload.push_str(name);
        payload.push('{');
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                payload.push(',');
            }
            payload.push_str(&format!("{k}=\"{v}\""));
        }
        payload.push_str(&format!("}} {val}\n"));
    }

    for honor_labels in [false, true] {
        let mut expected: Vec<LabelSet> = Vec::new();
        for (name, labels, _) in samples {
            let mut ls = LabelSet::new();
            ls.insert(METRIC_NAME_LABEL.to_owned(), (*name).to_owned());
            for (k, v) in *labels {
                ls.insert((*k).to_owned(), (*v).to_owned());
            }
            merge_target_and_metric_labels(&mut ls, &target_labels, honor_labels);
            if process_in_place(&mut ls, &cfgs) {
                expected.push(ls);
            }
        }

        let opts = DecodeOptions::new()
            .with_target_attributes(Arc::clone(&target))
            .with_honor_labels(honor_labels)
            .with_metric_relabel_configs(cfgs.clone());
        let mut dec = ArrowDecoder::new();
        let rec = dec
            .decode(payload.as_bytes(), &Format::TEXT, &opts)
            .unwrap();

        // Reconstruct each surviving data point's complete Prometheus label set from
        // `UnivariateMetrics.name` + `ResourceAttrs` (reverse-mapping `service.name`/`service.instance.id`) + `NumberDpAttrs`.
        let res_attrs = extract_resource_attrs(rec.resource_attrs());
        let dp_attrs = extract_attrs_by_parent_u32(rec.number_dp_attrs());
        let metrics = rec.univariate_metrics().unwrap();
        let metric_names = metrics
            .column_by_name("name")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let dps = rec.number_data_points().unwrap();
        let dp_parents = dps
            .column_by_name("parent_id")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow_array::UInt16Array>()
            .unwrap();

        let mut actual: Vec<LabelSet> = Vec::new();
        for row in 0..dps.num_rows() {
            let mut ls = BTreeMap::new();
            ls.insert(
                METRIC_NAME_LABEL.to_owned(),
                metric_names
                    .value(usize::from(dp_parents.value(row)))
                    .to_owned(),
            );
            for (rk, rv) in &res_attrs {
                let prom_key = if rk == SERVICE_NAME_ATTR {
                    "job"
                } else if rk == SERVICE_INSTANCE_ID_ATTR {
                    "instance"
                } else {
                    rk.as_str()
                };
                ls.insert(prom_key.to_owned(), rv.clone());
            }
            if let Some(attrs) = dp_attrs.get(&(row as u32)) {
                for (k, v) in attrs {
                    ls.insert(k.clone(), v.clone());
                }
            }
            actual.push(ls);
        }
        assert_eq!(actual, expected, "mismatch for honor_labels={honor_labels}");
    }

    // 2. Removing `__name__` while other labels remain returns `DecodeError::MissingMetricName`,
    //    matching Go Prometheus `errNameLabelMandatory`.
    let strip_name_opts = DecodeOptions::new().with_metric_relabel_configs(vec![Config {
        regex: Regexp::must_new(METRIC_NAME_LABEL),
        action: Action::LabelDrop,
        ..Config::default()
    }]);
    let mut dec = ArrowDecoder::new();
    let err = dec
        .decode(b"foo{a=\"1\"} 1\n", &Format::TEXT, &strip_name_opts)
        .unwrap_err();
    assert!(matches!(err, DecodeError::MissingMetricName));

    // Removing all labels (leaving an empty label set) drops the series cleanly like Go.
    let drop_empty = dec
        .decode(b"foo 1\n", &Format::TEXT, &strip_name_opts)
        .unwrap();
    assert!(drop_empty.is_empty());
}
