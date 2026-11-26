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

//! Integration tests for Prometheus target discovery (`static_configs`, `TargetGroup`, and durations).

use std::time::Duration;

use prometheus_scrape_manager::discovery::{
    ADDRESS_LABEL, DiscoveryConfigs, LabelSet, StaticConfig, TargetGroup, format_duration,
    parse_duration,
};

fn label_set(pairs: &[(&str, &str)]) -> LabelSet {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn static_configs_and_target_group_serde_match_prometheus() {
    let json = r#"{
        "static_configs": [
            {
                "targets": ["127.0.0.1:9090", "[::1]:9100"],
                "labels": {
                    "env": "prod",
                    "job": "prometheus"
                }
            },
            {
                "targets": ["10.0.0.1:8080"]
            }
        ]
    }"#;

    let mut cfg: DiscoveryConfigs = serde_json::from_str(json).expect("deserialize static_configs");
    cfg.validate().expect("validate static_configs");

    let groups = cfg.resolve_static();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].source, "0");
    assert_eq!(
        groups[0].targets,
        vec![
            label_set(&[(ADDRESS_LABEL, "127.0.0.1:9090")]),
            label_set(&[(ADDRESS_LABEL, "[::1]:9100")]),
        ]
    );
    assert_eq!(
        groups[0].labels,
        label_set(&[("env", "prod"), ("job", "prometheus")])
    );
    assert_eq!(groups[1].source, "1");
    assert_eq!(
        groups[1].targets,
        vec![label_set(&[(ADDRESS_LABEL, "10.0.0.1:8080")])]
    );
    assert!(groups[1].labels.is_empty());

    // TargetGroup Display returns its source identifier matching targetgroup.Group.String().
    assert_eq!(groups[0].to_string(), "0");
    assert_eq!(groups[1].to_string(), "1");

    // TargetGroup direct serde round-trip matches Prometheus targetgroup.Group.
    let tg_json = serde_json::to_string(&groups[0]).expect("serialize TargetGroup");
    let roundtrip: TargetGroup = serde_json::from_str(&tg_json).expect("deserialize TargetGroup");
    assert_eq!(roundtrip.targets, groups[0].targets);
    assert_eq!(roundtrip.labels, groups[0].labels);
    assert_eq!(roundtrip.source, "");

    // Targets missing ADDRESS_LABEL serialize as "" rather than being dropped.
    let missing_addr_tg = TargetGroup {
        targets: vec![
            label_set(&[("job", "custom")]),
            label_set(&[(ADDRESS_LABEL, "127.0.0.1:9090"), ("__meta_foo", "bar")]),
        ],
        labels: LabelSet::new(),
        source: "custom".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&missing_addr_tg).expect("serialize missing address TargetGroup"),
        r#"{"targets":["","127.0.0.1:9090"]}"#
    );

    // Empty TargetGroup always serializes `"targets": []` matching Prometheus targetgroup.Group.MarshalJSON.
    let empty_tg = TargetGroup::default();
    let empty_json = serde_json::to_string(&empty_tg).expect("serialize empty TargetGroup");
    assert_eq!(empty_json, r#"{"targets":[]}"#);
    let empty_roundtrip: TargetGroup =
        serde_json::from_str(&empty_json).expect("deserialize empty TargetGroup");
    assert!(empty_roundtrip.targets.is_empty());
    assert!(empty_roundtrip.labels.is_empty());

    // Omitted and explicit `null` fields unmarshal as empty defaults.
    for payload in [
        r#"{}"#,
        r#"{"targets": null, "labels": null}"#,
        r#"{"targets": ["127.0.0.1:9090"], "labels": null}"#,
    ] {
        let sc: StaticConfig = serde_json::from_str(payload).expect("deserialize StaticConfig");
        let tg: TargetGroup = serde_json::from_str(payload).expect("deserialize TargetGroup");
        assert_eq!(sc.into_target_group(""), tg);
    }
    assert_eq!(
        serde_json::to_string(&StaticConfig::default()).unwrap(),
        r#"{"targets":[]}"#
    );
    assert_eq!(
        serde_json::to_string(&DiscoveryConfigs::default()).unwrap(),
        "{}"
    );
    let null_cfg: DiscoveryConfigs =
        serde_json::from_str(r#"{"static_configs": null}"#).expect("deserialize null configs");
    assert!(null_cfg.static_configs.is_empty());

    // Unknown fields are rejected on StaticConfig, TargetGroup, and DiscoveryConfigs.
    assert!(serde_json::from_str::<StaticConfig>(r#"{"target": ["127.0.0.1:80"]}"#).is_err());
    assert!(serde_json::from_str::<TargetGroup>(r#"{"targets": [], "source": "0"}"#).is_err());
    assert!(serde_json::from_str::<DiscoveryConfigs>(r#"{"static_config": []}"#).is_err());
    assert!(
        serde_json::from_str::<TargetGroup>(r#""x""#)
            .unwrap_err()
            .to_string()
            .contains("expected struct TargetGroup")
    );

    // Empty label names in `labels` are rejected matching Prometheus model.LabelSet.UnmarshalJSON.
    let invalid_labels = r#"{"targets":["a:1"],"labels":{"":"x"}}"#;
    assert!(
        serde_json::from_str::<StaticConfig>(invalid_labels)
            .unwrap_err()
            .to_string()
            .contains(r#""" is not a valid label name"#)
    );
    assert!(
        serde_json::from_str::<TargetGroup>(invalid_labels)
            .unwrap_err()
            .to_string()
            .contains(r#""" is not a valid label name"#)
    );
}

#[test]
fn prometheus_duration_parsing_and_formatting() {
    assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
    assert_eq!(parse_duration("0w").unwrap(), Duration::ZERO);
    assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
    assert_eq!(
        parse_duration("2h15m500ms").unwrap(),
        Duration::from_millis((2 * 3600 + 15 * 60) * 1000 + 500)
    );
    assert_eq!(
        parse_duration("4d").unwrap(),
        Duration::from_secs(4 * 24 * 3600)
    );
    assert_eq!(
        parse_duration("1w").unwrap(),
        Duration::from_secs(7 * 24 * 3600)
    );
    assert_eq!(
        parse_duration("14d").unwrap(),
        Duration::from_secs(14 * 24 * 3600)
    );
    assert_eq!(
        parse_duration("3w2d1h").unwrap(),
        Duration::from_secs((23 * 24 + 1) * 3600)
    );
    assert_eq!(
        parse_duration("1y").unwrap(),
        Duration::from_secs(365 * 24 * 3600)
    );
    assert_eq!(
        parse_duration("289y").unwrap(),
        Duration::from_secs(289 * 365 * 24 * 3600)
    );
    let compound = parse_duration("1y2w3d4h5m6s7ms").unwrap();
    assert_eq!(format_duration(compound), "382d4h5m6s7ms");

    assert_eq!(format_duration(Duration::ZERO), "0s");
    assert_eq!(format_duration(Duration::from_nanos(1)), "0s");
    assert_eq!(format_duration(Duration::from_micros(500)), "0s");
    assert_eq!(format_duration(Duration::from_micros(1500)), "1ms");
    assert_eq!(format_duration(Duration::from_secs(30)), "30s");
    assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
    assert_eq!(format_duration(Duration::from_secs(14 * 24 * 3600)), "2w");
    assert_eq!(
        format_duration(Duration::from_secs((23 * 24 + 1) * 3600)),
        "23d1h"
    );
    assert_eq!(format_duration(Duration::from_secs(7 * 24 * 3600)), "1w");
    assert_eq!(format_duration(Duration::from_secs(8 * 24 * 3600)), "8d");
    assert_eq!(format_duration(Duration::from_secs(365 * 24 * 3600)), "1y");
    assert_eq!(format_duration(Duration::MAX), "213503982334601d7h15s999ms");

    assert_eq!(
        parse_duration("").unwrap_err().to_string(),
        "empty duration string"
    );
    for invalid in [
        "d",
        "-3s",
        "+3s",
        "1",
        "1m30",
        "1s1m",
        "1s1s",
        "1y1m1d",
        "18446744073709551616ms",
    ] {
        assert_eq!(
            parse_duration(invalid).unwrap_err().to_string(),
            format!("not a valid duration string: {invalid:?}"),
            "expected invalid duration error for {invalid:?}"
        );
    }
    assert_eq!(
        parse_duration("1.5d").unwrap_err().to_string(),
        "unknown unit \".\" in duration \"1.5d\""
    );
    assert_eq!(
        parse_duration("10x").unwrap_err().to_string(),
        "unknown unit \"x\" in duration \"10x\""
    );
    for overflow in [
        "294y",
        "200y10400w",
        "107675d",
        "2584200h",
        "999999999999999y",
    ] {
        assert_eq!(
            parse_duration(overflow).unwrap_err().to_string(),
            "duration out of range",
            "expected out of range error for {overflow:?}"
        );
    }
}
