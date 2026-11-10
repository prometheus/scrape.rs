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

    // TargetGroup direct serde round-trip matches Prometheus targetgroup.Group.
    let tg_json = serde_json::to_string(&groups[0]).expect("serialize TargetGroup");
    let roundtrip: TargetGroup = serde_json::from_str(&tg_json).expect("deserialize TargetGroup");
    assert_eq!(roundtrip.targets, groups[0].targets);
    assert_eq!(roundtrip.labels, groups[0].labels);

    // Empty TargetGroup always serializes `"targets": []` matching Prometheus targetgroup.Group.MarshalJSON.
    let empty_tg = TargetGroup::default();
    let empty_json = serde_json::to_string(&empty_tg).expect("serialize empty TargetGroup");
    assert_eq!(empty_json, r#"{"targets":[]}"#);
    let empty_roundtrip: TargetGroup =
        serde_json::from_str(&empty_json).expect("deserialize empty TargetGroup");
    assert!(empty_roundtrip.targets.is_empty());
    assert!(empty_roundtrip.labels.is_empty());

    // Unknown fields are rejected on StaticConfig and DiscoveryConfigs.
    assert!(serde_json::from_str::<StaticConfig>(r#"{"target": ["127.0.0.1:80"]}"#).is_err());
    assert!(serde_json::from_str::<DiscoveryConfigs>(r#"{"static_config": []}"#).is_err());
}

#[test]
fn prometheus_duration_parsing_and_formatting() {
    assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
    assert_eq!(parse_duration("0s").unwrap(), Duration::ZERO);
    assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
    assert_eq!(
        parse_duration("2h15m500ms").unwrap(),
        Duration::from_millis((2 * 3600 + 15 * 60) * 1000 + 500)
    );
    assert_eq!(
        parse_duration("1w").unwrap(),
        Duration::from_secs(7 * 24 * 3600)
    );

    assert_eq!(format_duration(Duration::ZERO), "0s");
    assert_eq!(format_duration(Duration::from_micros(500)), "1ms");
    assert_eq!(format_duration(Duration::from_secs(30)), "30s");
    assert_eq!(format_duration(Duration::from_secs(90)), "1m30s");
    assert_eq!(format_duration(Duration::from_secs(7 * 24 * 3600)), "1w");
    assert_eq!(format_duration(Duration::from_secs(8 * 24 * 3600)), "8d");
    assert_eq!(format_duration(Duration::from_secs(365 * 24 * 3600)), "1y");
    assert_ne!(format_duration(Duration::MAX), "0s");

    assert!(parse_duration("").is_err());
    assert!(parse_duration("1s1m").is_err());
    assert!(parse_duration("10x").is_err());
    assert!(parse_duration("999999999999999y").is_err());
}
