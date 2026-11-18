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

//! Integration tests for Prometheus target and metric relabeling (`model/relabel` and
//! `scrape/target.go`).

use std::collections::BTreeMap;

use prometheus_relabel::{
    Action, Config, DEFAULT_REPLACEMENT, DictionaryValueTransform, LabelSet, METRIC_NAME_LABEL,
    Regexp, SingleLabelFilterSummary, SingleLabelKeepCache, SingleLabelTransformCache,
    TargetPopulateConfig, ValidationScheme, eval_key_keep_mask, eval_key_keep_mask_iter,
    eval_single_label_keep_mask, eval_single_label_value_transform, is_valid_legacy_target_label,
    keep_metric_name, merge_target_and_metric_labels, populate_discovered_labels, populate_labels,
    process, resolve_conflicting_exposed_keys, resolve_conflicting_exposed_keys_iter,
    split_metric_name_pushdown,
};

fn label_set(pairs: &[(&str, &str)]) -> LabelSet {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn relabel_matches_prometheus_relabel_test_suite() {
    // Ported from TestRelabel in model/relabel/relabel_test.go.
    let base_input = label_set(&[("a", "foo"), ("b", "bar"), ("c", "baz")]);
    let eq_input = label_set(&[
        ("__tmp_port", "1234"),
        ("__port1", "1234"),
        ("__port2", "5678"),
    ]);
    let multiline_input = label_set(&[("a", "line1\nline2"), ("b", "bar"), ("c", "baz")]);

    let cases: &[(&str, LabelSet, Vec<Config>, Option<LabelSet>)] = &[
        (
            "no relabelings",
            base_input.clone(),
            vec![],
            Some(base_input.clone()),
        ),
        (
            "no matching rule",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a", "b", "c"]),
                regex: Regexp::must_new("bar"),
                target_label: "d".to_owned(),
                replacement: "foo".to_owned(),
                action: Action::Replace,
                ..Config::default()
            }],
            Some(base_input.clone()),
        ),
        (
            "matching rule with empty $1 capture",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a", "b", "c"]),
                regex: Regexp::must_new("foo;bar;baz"),
                target_label: "d".to_owned(),
                action: Action::Replace,
                ..Config::default()
            }],
            Some(base_input.clone()),
        ),
        (
            "capture groups and new target label",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a"]),
                regex: Regexp::must_new("f(.*)"),
                target_label: "d".to_owned(),
                replacement: "ch${1}ch${1}".to_owned(),
                action: Action::Replace,
                ..Config::default()
            }],
            Some(label_set(&[
                ("a", "foo"),
                ("b", "bar"),
                ("c", "baz"),
                ("d", "choochoo"),
            ])),
        ),
        (
            "chaining rules into subsequent source labels",
            base_input.clone(),
            vec![
                Config {
                    source_labels: strs(&["a", "b"]),
                    regex: Regexp::must_new("f(.*);(.*)r"),
                    target_label: "a".to_owned(),
                    replacement: "b${1}${2}m".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
                Config {
                    source_labels: strs(&["c", "a"]),
                    regex: Regexp::must_new("(b).*b(.*)ba(.*)"),
                    target_label: "d".to_owned(),
                    replacement: "$1$2$2$3".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
            ],
            Some(label_set(&[
                ("a", "boobam"),
                ("b", "bar"),
                ("c", "baz"),
                ("d", "boooom"),
            ])),
        ),
        (
            "empty replacement deletes existing label",
            base_input.clone(),
            vec![
                Config {
                    source_labels: strs(&["a"]),
                    regex: Regexp::must_new("foo"),
                    target_label: "a".to_owned(),
                    replacement: String::new(),
                    action: Action::Replace,
                    ..Config::default()
                },
                Config {
                    source_labels: strs(&["b"]),
                    regex: Regexp::must_new(".*"),
                    target_label: "b".to_owned(),
                    replacement: "$1".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
            ],
            Some(label_set(&[("c", "baz")])),
        ),
        (
            "drop matching joined labels",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a", "b"]),
                separator: ";".to_owned(),
                regex: Regexp::must_new("foo;bar"),
                action: Action::Drop,
                ..Config::default()
            }],
            None,
        ),
        (
            "drop non-matching custom separator",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a", "b"]),
                separator: ".*".to_owned(),
                regex: Regexp::must_new("foo;bar"),
                action: Action::Drop,
                ..Config::default()
            }],
            Some(base_input.clone()),
        ),
        (
            "keep non-matching drops sample",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a"]),
                regex: Regexp::must_new("no-match"),
                action: Action::Keep,
                ..Config::default()
            }],
            None,
        ),
        (
            "keep matching retains sample",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["a"]),
                regex: Regexp::must_new("f.*"),
                action: Action::Keep,
                ..Config::default()
            }],
            Some(base_input.clone()),
        ),
        (
            "uppercase and lowercase",
            base_input.clone(),
            vec![
                Config {
                    source_labels: strs(&["a"]),
                    target_label: "a_upper".to_owned(),
                    action: Action::Uppercase,
                    ..Config::default()
                },
                Config {
                    source_labels: strs(&["a_upper"]),
                    target_label: "a_lower".to_owned(),
                    action: Action::Lowercase,
                    ..Config::default()
                },
            ],
            Some(label_set(&[
                ("a", "foo"),
                ("a_lower", "foo"),
                ("a_upper", "FOO"),
                ("b", "bar"),
                ("c", "baz"),
            ])),
        ),
        (
            "hashmod baz % 1000 == 976",
            base_input.clone(),
            vec![Config {
                source_labels: strs(&["c"]),
                modulus: 1000,
                target_label: "d".to_owned(),
                action: Action::HashMod,
                ..Config::default()
            }],
            Some(label_set(&[
                ("a", "foo"),
                ("b", "bar"),
                ("c", "baz"),
                ("d", "976"),
            ])),
        ),
        (
            "hashmod multiline foo\\nbar % 1000 == 734",
            label_set(&[("a", "foo\nbar")]),
            vec![Config {
                source_labels: strs(&["a"]),
                modulus: 1000,
                target_label: "b".to_owned(),
                action: Action::HashMod,
                ..Config::default()
            }],
            Some(label_set(&[("a", "foo\nbar"), ("b", "734")])),
        ),
        (
            "multiline dot-matches-newline",
            multiline_input.clone(),
            vec![Config {
                source_labels: strs(&["a"]),
                regex: Regexp::must_new("line1.*line2"),
                target_label: "d".to_owned(),
                replacement: "match${1}".to_owned(),
                action: Action::Replace,
                ..Config::default()
            }],
            Some(label_set(&[
                ("a", "line1\nline2"),
                ("b", "bar"),
                ("c", "baz"),
                ("d", "match"),
            ])),
        ),
        (
            "labelmap, labeldrop, labelkeep",
            base_input.clone(),
            vec![
                Config {
                    regex: Regexp::must_new("a|b"),
                    replacement: "mapped_${0}".to_owned(),
                    action: Action::LabelMap,
                    ..Config::default()
                },
                Config {
                    regex: Regexp::must_new("c"),
                    action: Action::LabelDrop,
                    ..Config::default()
                },
                Config {
                    regex: Regexp::must_new("mapped_.*"),
                    action: Action::LabelKeep,
                    ..Config::default()
                },
            ],
            Some(label_set(&[("mapped_a", "foo"), ("mapped_b", "bar")])),
        ),
        (
            "dropequal equal drops",
            eq_input.clone(),
            vec![Config {
                source_labels: strs(&["__tmp_port"]),
                target_label: "__port1".to_owned(),
                action: Action::DropEqual,
                ..Config::default()
            }],
            None,
        ),
        (
            "keepequal equal keeps",
            eq_input.clone(),
            vec![Config {
                source_labels: strs(&["__tmp_port"]),
                target_label: "__port1".to_owned(),
                action: Action::KeepEqual,
                ..Config::default()
            }],
            Some(eq_input.clone()),
        ),
        (
            "dropequal unequal keeps",
            eq_input.clone(),
            vec![Config {
                source_labels: strs(&["__tmp_port"]),
                target_label: "__port2".to_owned(),
                action: Action::DropEqual,
                ..Config::default()
            }],
            Some(eq_input.clone()),
        ),
        (
            "keepequal unequal drops",
            eq_input.clone(),
            vec![Config {
                source_labels: strs(&["__tmp_port"]),
                target_label: "__port2".to_owned(),
                action: Action::KeepEqual,
                ..Config::default()
            }],
            None,
        ),
        (
            "named capture groups with braced and unbraced refs",
            multiline_input,
            vec![
                Config {
                    source_labels: strs(&["a"]),
                    regex: Regexp::must_new("(line1).*(?<second>line2)"),
                    target_label: "label1_${1}".to_owned(),
                    replacement: "val_${second}".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
                Config {
                    source_labels: strs(&["a"]),
                    regex: Regexp::must_new("(line1).*(?<second>line2)"),
                    target_label: "label2_$1".to_owned(),
                    replacement: "val_$second".to_owned(),
                    action: Action::Replace,
                    ..Config::default()
                },
            ],
            Some(label_set(&[
                ("a", "line1\nline2"),
                ("b", "bar"),
                ("c", "baz"),
                ("label1_line1", "val_line2"),
                ("label2_line1", "val_line2"),
            ])),
        ),
    ];

    for (idx, (name, input, cfgs, expected)) in cases.iter().enumerate() {
        assert_eq!(
            &process(input, cfgs),
            expected,
            "TestRelabel case #{idx} ({name}) failed"
        );
    }
}

#[test]
fn relabel_validate_matches_prometheus() {
    // Ported from TestRelabelValidate in model/relabel/relabel_test.go.
    let mut replace_no_target = Config {
        action: Action::Replace,
        target_label: String::new(),
        ..Config::default()
    };
    assert!(
        replace_no_target
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string()
            .contains("requires 'target_label' value")
    );

    let mut lower_no_target = Config {
        action: Action::Lowercase,
        target_label: String::new(),
        ..Config::default()
    };
    assert!(
        lower_no_target
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string()
            .contains("requires 'target_label' value")
    );

    let mut lower_utf8_var = Config {
        action: Action::Lowercase,
        replacement: DEFAULT_REPLACEMENT.to_owned(),
        target_label: "${3}".to_owned(),
        name_validation_scheme: ValidationScheme::Utf8,
        ..Config::default()
    };
    assert!(lower_utf8_var.validate(ValidationScheme::Utf8).is_ok());

    let mut lower_legacy_var = Config {
        action: Action::Lowercase,
        replacement: DEFAULT_REPLACEMENT.to_owned(),
        target_label: "${3}".to_owned(),
        name_validation_scheme: ValidationScheme::Legacy,
        ..Config::default()
    };
    assert_eq!(
        lower_legacy_var
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string(),
        "\"${3}\" is invalid 'target_label' for lowercase action"
    );

    let mut replace_utf8_targets = [
        Config {
            source_labels: strs(&["a"]),
            regex: Regexp::must_new("some-([^-]+)-([^,]+)"),
            action: Action::Replace,
            replacement: "${1}".to_owned(),
            target_label: "${3}".to_owned(),
            name_validation_scheme: ValidationScheme::Utf8,
            ..Config::default()
        },
        Config {
            source_labels: strs(&["a"]),
            regex: Regexp::must_new("some-([^-]+)-([^,]+)"),
            action: Action::Replace,
            replacement: "${1}".to_owned(),
            target_label: "0${3}".to_owned(),
            name_validation_scheme: ValidationScheme::Utf8,
            ..Config::default()
        },
        Config {
            source_labels: strs(&["a"]),
            regex: Regexp::must_new("some-([^-]+)-([^,]+)"),
            action: Action::Replace,
            replacement: "${1}".to_owned(),
            target_label: "-${3}".to_owned(),
            name_validation_scheme: ValidationScheme::Utf8,
            ..Config::default()
        },
        Config {
            regex: Regexp::must_new("__meta_kubernetes_pod_label_(strimzi_io_.+)"),
            action: Action::LabelMap,
            replacement: "$1".to_owned(),
            name_validation_scheme: ValidationScheme::Legacy,
            ..Config::default()
        },
        Config {
            regex: Regexp::must_new("__meta_(.+)"),
            action: Action::LabelMap,
            replacement: "${1}".to_owned(),
            name_validation_scheme: ValidationScheme::Legacy,
            ..Config::default()
        },
    ];
    for cfg in &mut replace_utf8_targets {
        cfg.validate(ValidationScheme::Utf8).unwrap();
    }

    // KeepEqual / DropEqual forbid non-default regex, modulus, separator, replacement.
    let mut bad_keepequal = Config {
        source_labels: strs(&["a"]),
        target_label: "b".to_owned(),
        action: Action::KeepEqual,
        separator: ":".to_owned(),
        ..Config::default()
    };
    assert_eq!(
        bad_keepequal
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string(),
        "keepequal action requires only 'source_labels' and `target_label`, and no other fields"
    );

    // LabelDrop / LabelKeep forbid source_labels, target_label, modulus, separator, replacement.
    let mut bad_labeldrop = Config {
        source_labels: strs(&["a"]),
        regex: Regexp::must_new("temp.*"),
        action: Action::LabelDrop,
        ..Config::default()
    };
    assert_eq!(
        bad_labeldrop
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string(),
        "labeldrop action requires only 'regex', and no other fields"
    );

    let mut hashmod_zero = Config {
        source_labels: strs(&["a"]),
        target_label: "b".to_owned(),
        action: Action::HashMod,
        modulus: 0,
        ..Config::default()
    };
    assert_eq!(
        hashmod_zero
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string(),
        "relabel configuration for hashmod requires non-zero modulus"
    );

    let mut lower_with_replacement = Config {
        source_labels: strs(&["a"]),
        target_label: "b".to_owned(),
        replacement: "custom".to_owned(),
        action: Action::Lowercase,
        ..Config::default()
    };
    assert_eq!(
        lower_with_replacement
            .validate(ValidationScheme::Utf8)
            .unwrap_err()
            .to_string(),
        "'replacement' can not be set for lowercase action"
    );

    let mut bad_legacy_labelmap = Config {
        action: Action::LabelMap,
        replacement: "-bad-$1".to_owned(),
        name_validation_scheme: ValidationScheme::Legacy,
        ..Config::default()
    };
    assert_eq!(
        bad_legacy_labelmap
            .validate(ValidationScheme::Legacy)
            .unwrap_err()
            .to_string(),
        "\"-bad-$1\" is invalid 'replacement' for labelmap action"
    );

    let mut bad_legacy_hashmod = Config {
        source_labels: strs(&["a"]),
        target_label: "bad.target".to_owned(),
        modulus: 4,
        action: Action::HashMod,
        name_validation_scheme: ValidationScheme::Legacy,
        ..Config::default()
    };
    assert_eq!(
        bad_legacy_hashmod
            .validate(ValidationScheme::Legacy)
            .unwrap_err()
            .to_string(),
        "\"bad.target\" is invalid 'target_label' for hashmod action"
    );
}

#[test]
fn target_label_legacy_validity_matches_prometheus() {
    // Ported from TestTargetLabelLegacyValidity in model/relabel/relabel_test.go.
    let cases = [
        ("-label", false),
        ("label", true),
        ("label${1}", true),
        ("${1}label", true),
        ("${1}", true),
        ("${", false),
        ("$", false),
        ("${}", false),
        ("foo${", false),
        ("$1", true),
        ("asd$2asd", true),
        ("-foo${1}bar-", false),
        ("bar.foo${1}bar", false),
        ("_${1}_", true),
        ("foo${bar}foo", true),
    ];
    for (input, expected) in cases {
        assert_eq!(
            is_valid_legacy_target_label(input),
            expected,
            "input: {input:?}"
        );
    }
}

#[test]
fn kubernetes_relabel_pipeline_and_serde_roundtrip() {
    // Ported from BenchmarkRelabel ("kubernetes" pipeline) and TestRegexp_JSONUnmarshalThenMarshal
    // in model/relabel/relabel_test.go.
    let k8s_rules_json = r#"[
        {
            "source_labels": ["__meta_kubernetes_pod_container_port_name"],
            "regex": ".*-metrics",
            "action": "keep"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_label_name"],
            "action": "drop",
            "regex": ""
        },
        {
            "source_labels": ["__meta_kubernetes_pod_phase"],
            "regex": "Succeeded|Failed",
            "action": "drop"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_scrape"],
            "regex": "false",
            "action": "drop"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_scheme"],
            "target_label": "__scheme__",
            "regex": "(https?)",
            "replacement": "$1",
            "action": "replace"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_annotation_prometheus_io_path"],
            "target_label": "__metrics_path__",
            "regex": "(.+)",
            "replacement": "$1",
            "action": "replace"
        },
        {
            "source_labels": ["__address__", "__meta_kubernetes_pod_annotation_prometheus_io_port"],
            "target_label": "__address__",
            "regex": "(.+?)(\\:\\d+)?;(\\d+)",
            "replacement": "$1:$3",
            "action": "replace"
        },
        {
            "regex": "__meta_kubernetes_pod_annotation_prometheus_io_param_(.+)",
            "replacement": "__param_$1",
            "action": "labelmap"
        },
        {
            "regex": "__meta_kubernetes_pod_label_prometheus_io_label_(.+)",
            "action": "labelmap"
        },
        {
            "regex": "__meta_kubernetes_pod_annotation_prometheus_io_label_(.+)",
            "action": "labelmap"
        },
        {
            "source_labels": ["__meta_kubernetes_namespace", "__meta_kubernetes_pod_label_name"],
            "separator": "/",
            "target_label": "job",
            "replacement": "$1",
            "action": "replace"
        },
        {
            "source_labels": ["__meta_kubernetes_namespace"],
            "target_label": "namespace",
            "action": "replace"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_name"],
            "target_label": "pod",
            "action": "replace"
        },
        {
            "source_labels": ["__meta_kubernetes_pod_container_name"],
            "target_label": "container",
            "action": "replace"
        },
        {
            "source_labels": [
                "__meta_kubernetes_pod_name",
                "__meta_kubernetes_pod_container_name",
                "__meta_kubernetes_pod_container_port_name"
            ],
            "separator": ":",
            "target_label": "instance",
            "action": "replace"
        },
        {
            "target_label": "cluster",
            "replacement": "dev-us-central-0"
        },
        {
            "source_labels": ["__meta_kubernetes_namespace"],
            "regex": "hosted-grafana",
            "action": "drop"
        },
        {
            "source_labels": ["__address__"],
            "target_label": "__tmp_hash",
            "modulus": 3,
            "action": "hashmod"
        },
        {
            "source_labels": ["__tmp_hash"],
            "regex": "^1$",
            "action": "keep"
        },
        {
            "regex": "__tmp_hash",
            "action": "labeldrop"
        }
    ]"#;

    let mut cfgs: Vec<Config> = serde_json::from_str(k8s_rules_json).unwrap();
    for cfg in &mut cfgs {
        cfg.validate(ValidationScheme::Utf8).unwrap();
    }

    let discovered_target = label_set(&[
        ("__address__", "10.132.183.40:80"),
        ("__meta_kubernetes_namespace", "loki-boltdb-shipper"),
        ("__meta_kubernetes_pod_container_init", "false"),
        ("__meta_kubernetes_pod_container_name", "promtail"),
        ("__meta_kubernetes_pod_container_port_name", "http-metrics"),
        ("__meta_kubernetes_pod_container_port_number", "80"),
        ("__meta_kubernetes_pod_container_port_protocol", "TCP"),
        (
            "__meta_kubernetes_pod_label_name",
            "promtail-loki-boltdb-shipper",
        ),
        (
            "__meta_kubernetes_pod_name",
            "promtail-loki-boltdb-shipper-jgtr7",
        ),
        ("__meta_kubernetes_pod_phase", "Running"),
        ("__meta_kubernetes_pod_ready", "true"),
    ]);

    let pop_cfg = TargetPopulateConfig {
        job_name: "kubernetes-pods".to_owned(),
        scrape_interval: "15s".to_owned(),
        scrape_timeout: "10s".to_owned(),
        metrics_path: "/metrics".to_owned(),
        scheme: "http".to_owned(),
        params: BTreeMap::new(),
    };

    let populated = populate_labels(&discovered_target, &BTreeMap::new(), &pop_cfg, &cfgs)
        .unwrap()
        .expect("target should be kept (10.132.183.40:80 hashmod 3 == 1)");
    assert_eq!(
        populated.public_labels(),
        label_set(&[
            ("cluster", "dev-us-central-0"),
            ("container", "promtail"),
            (
                "instance",
                "promtail-loki-boltdb-shipper-jgtr7:promtail:http-metrics"
            ),
            ("job", "loki-boltdb-shipper/promtail-loki-boltdb-shipper"),
            ("namespace", "loki-boltdb-shipper"),
            ("pod", "promtail-loki-boltdb-shipper-jgtr7"),
        ])
    );

    // Verify JSON round-trip preserves configs and validation (including KeepEqual default regex).
    let serialized = serde_json::to_string(&cfgs).unwrap();
    let mut roundtripped: Vec<Config> = serde_json::from_str(&serialized).unwrap();
    for cfg in &mut roundtripped {
        cfg.validate(ValidationScheme::Utf8).unwrap();
    }
    assert_eq!(roundtripped, cfgs);

    let keepequal_cfg = Config {
        source_labels: strs(&["a"]),
        target_label: "b".to_owned(),
        action: Action::KeepEqual,
        ..Config::default()
    };
    let keepequal_json = serde_json::to_string(&keepequal_cfg).unwrap();
    assert!(!keepequal_json.contains("\"regex\""));
    let mut roundtripped_keepequal: Config = serde_json::from_str(&keepequal_json).unwrap();
    roundtripped_keepequal
        .validate(ValidationScheme::Utf8)
        .unwrap();

    // Explicit empty string `"action": ""` must fail deserialization like Go Action.UnmarshalYAML.
    assert!(serde_json::from_str::<Config>(r#"{"action": ""}"#).is_err());
}

#[test]
fn populate_labels_and_honor_labels_merging_match_prometheus() {
    let target = label_set(&[
        ("__address__", "127.0.0.1:9090"),
        ("__meta_dns_name", "prom.local"),
    ]);
    let group_labels = label_set(&[("env", "prod"), ("team", "obs")]);
    let pop_cfg = TargetPopulateConfig {
        job_name: "prometheus".to_owned(),
        scrape_interval: "30s".to_owned(),
        scrape_timeout: "10s".to_owned(),
        metrics_path: "/metrics".to_owned(),
        scheme: "http".to_owned(),
        params: BTreeMap::from([(
            "module".to_owned(),
            vec!["http_2xx".to_owned(), "ignored".to_owned()],
        )]),
    };

    let discovered = populate_discovered_labels(&target, &group_labels, &pop_cfg);
    assert_eq!(
        discovered.get("__param_module"),
        Some(&"http_2xx".to_owned())
    );
    assert_eq!(
        discovered.get("__meta_dns_name"),
        Some(&"prom.local".to_owned())
    );

    // An explicit empty value in `target` prevents `group_labels` from populating that key.
    let target_with_empty = label_set(&[("__address__", "127.0.0.1:9090"), ("env", "")]);
    let discovered_empty = populate_discovered_labels(&target_with_empty, &group_labels, &pop_cfg);
    assert!(!discovered_empty.contains_key("env"));

    let populated = populate_labels(&target, &group_labels, &pop_cfg, &[])
        .unwrap()
        .unwrap();
    // `__meta_*` is stripped from `labels`, retained in `discovered_labels`, and `instance` defaults to `__address__`.
    assert!(!populated.labels.contains_key("__meta_dns_name"));
    assert!(populated.discovered_labels.contains_key("__meta_dns_name"));
    assert_eq!(
        populated.labels.get("instance"),
        Some(&"127.0.0.1:9090".to_owned())
    );
    assert_eq!(
        populated.public_labels(),
        label_set(&[
            ("env", "prod"),
            ("instance", "127.0.0.1:9090"),
            ("job", "prometheus"),
            ("team", "obs"),
        ])
    );

    // Dropped target returns Ok(None); missing or '/' address returns Err(TargetError).
    let drop_all = [Config {
        action: Action::Drop,
        ..Config::default()
    }];
    assert_eq!(
        populate_labels(&target, &group_labels, &pop_cfg, &drop_all).unwrap(),
        None
    );
    assert!(populate_labels(&LabelSet::new(), &group_labels, &pop_cfg, &[]).is_err());
    let slash_addr = label_set(&[("__address__", "127.0.0.1:9090/metrics")]);
    assert!(populate_labels(&slash_addr, &group_labels, &pop_cfg, &[]).is_err());

    // Scrape interval / timeout validation matching Go `scrape.PopulateLabels`.
    let timeout_gt_interval = label_set(&[
        ("__address__", "127.0.0.1:9090"),
        ("__scrape_interval__", "15s"),
        ("__scrape_timeout__", "30s"),
    ]);
    assert_eq!(
        populate_labels(&timeout_gt_interval, &group_labels, &pop_cfg, &[])
            .unwrap_err()
            .to_string(),
        "scrape timeout cannot be greater than scrape interval (\"30s\" > \"15s\")"
    );

    let zero_interval = label_set(&[
        ("__address__", "127.0.0.1:9090"),
        ("__scrape_interval__", "0"),
    ]);
    assert_eq!(
        populate_labels(&zero_interval, &group_labels, &pop_cfg, &[])
            .unwrap_err()
            .to_string(),
        "scrape interval cannot be 0"
    );

    let bad_unit_order = label_set(&[
        ("__address__", "127.0.0.1:9090"),
        ("__scrape_interval__", "1m1d"),
    ]);
    assert!(
        populate_labels(&bad_unit_order, &group_labels, &pop_cfg, &[])
            .unwrap_err()
            .to_string()
            .contains("error parsing scrape interval")
    );

    let compound_interval = label_set(&[
        ("__address__", "127.0.0.1:9090"),
        ("__scrape_interval__", "1m30s"),
        ("__scrape_timeout__", "45s500ms"),
    ]);
    assert!(
        populate_labels(&compound_interval, &group_labels, &pop_cfg, &[])
            .unwrap()
            .is_some()
    );

    // honor_labels = false: conflicting sample labels are renamed to `exported_<name>`.
    let mut sample_labels = label_set(&[
        ("job", "sample-job"),
        ("exported_job", "existing-exported"),
        ("method", "GET"),
    ]);
    merge_target_and_metric_labels(&mut sample_labels, &populated.labels, false);
    assert_eq!(
        sample_labels,
        label_set(&[
            ("env", "prod"),
            ("exported_exported_job", "sample-job"),
            ("exported_job", "existing-exported"),
            ("instance", "127.0.0.1:9090"),
            ("job", "prometheus"),
            ("method", "GET"),
            ("team", "obs"),
        ])
    );

    // Multi-collision exported_ prefix ordering from Prometheus TestScrapeLoopAppendForConflictingPrefixedLabels.
    let target_colliding = label_set(&[("foo", "3"), ("exported_foo", "4")]);
    let mut metric_colliding = label_set(&[("foo", "1"), ("exported_foo", "2"), ("empty", "")]);
    merge_target_and_metric_labels(&mut metric_colliding, &target_colliding, false);
    assert_eq!(
        metric_colliding,
        label_set(&[
            ("exported_exported_exported_foo", "2"),
            ("exported_exported_foo", "1"),
            ("exported_foo", "4"),
            ("foo", "3"),
        ])
    );

    // honor_labels = true: existing sample labels win over target labels, while empty sample labels are stripped.
    let mut honored_labels = label_set(&[("job", "sample-job"), ("env", ""), ("method", "GET")]);
    merge_target_and_metric_labels(&mut honored_labels, &populated.labels, true);
    assert_eq!(
        honored_labels,
        label_set(&[
            ("env", "prod"),
            ("instance", "127.0.0.1:9090"),
            ("job", "sample-job"),
            ("method", "GET"),
            ("team", "obs"),
        ])
    );
}

#[test]
fn deserialized_legacy_validation_and_template_expansion_edge_cases() {
    // Deserialized and default-constructed configs inherit `ValidationScheme::Legacy` in `validate`.
    let mut deserialized_replace: Config =
        serde_json::from_str(r#"{"target_label": "utf8.label", "replacement": "v"}"#).unwrap();
    assert!(
        deserialized_replace
            .validate(ValidationScheme::Legacy)
            .is_err()
    );

    let mut default_lower = Config {
        action: Action::Lowercase,
        target_label: "${3}".to_owned(),
        ..Config::default()
    };
    assert!(default_lower.validate(ValidationScheme::Legacy).is_err());

    // Go `regexp.ExpandString` edge cases: `$$`, trailing `$`, `${}`, `${a-b}`, `${foo$1}`, unclosed `${1`, leading-zero `$01`/`${01}`, and non-decimal superscript `$1²`.
    let input = label_set(&[("a", "hello")]);
    let expanded = process(
        &input,
        &[Config {
            source_labels: strs(&["a"]),
            regex: Regexp::must_new("(he)(llo)"),
            target_label: "out".to_owned(),
            replacement: "$$-${}-${a-b}-${foo$1}-${1-$01-${01}-$1-$2-$1²-$".to_owned(),
            action: Action::Replace,
            ..Config::default()
        }],
    )
    .unwrap();
    assert_eq!(
        expanded.get("out").map(String::as_str),
        Some("$-${}-${a-b}-${foohe}-${1---he-llo-he²-$")
    );

    // Static `Action::Replace` fast path respects `ValidationScheme::Legacy`.
    let untouched = process(
        &input,
        &[Config {
            target_label: "invalid.legacy".to_owned(),
            replacement: "val".to_owned(),
            action: Action::Replace,
            name_validation_scheme: ValidationScheme::Legacy,
            ..Config::default()
        }],
    )
    .unwrap();
    assert!(!untouched.contains_key("invalid.legacy"));

    // Multi-block MD5 inputs (55, 56, and 70 bytes) in `Action::HashMod`.
    for (len, expected_mod) in [(55usize, "442"), (56, "603"), (70, "469")] {
        let s = "x".repeat(len);
        let res = process(
            &label_set(&[("in", &s)]),
            &[Config {
                source_labels: strs(&["in"]),
                modulus: 1000,
                target_label: "h".to_owned(),
                action: Action::HashMod,
                ..Config::default()
            }],
        )
        .unwrap();
        assert_eq!(res.get("h").map(String::as_str), Some(expected_mod));
    }

    // Go RE2 ASCII Perl classes (`\d`, `\w`, `\s`, `\b`) reject non-ASCII digits/letters while `.` stays Unicode-aware.
    let re_digits = Regexp::must_new(r"\d+");
    assert!(re_digits.is_match("123"));
    assert!(!re_digits.is_match("١٢٣"));
    assert_eq!(re_digits.as_str(), r"\d+");

    let re_word_space = Regexp::must_new(r"[\w]+[\s]+[\d_]+");
    assert!(re_word_space.is_match("abc_1 \t 42_0"));
    assert!(!re_word_space.is_match("αβγ 42"));
    assert!(!re_word_space.is_match("abc\u{00A0}42"));

    let re_boundary = Regexp::must_new(r".*\bfoo\b.*");
    assert!(re_boundary.is_match("١foo"));
    assert!(!re_boundary.is_match("1foo"));

    let re_quoted = Regexp::must_new(r"\Q\d+\E|\\d");
    assert!(re_quoted.is_match(r"\d+"));
    assert!(re_quoted.is_match(r"\d"));
    assert!(!re_quoted.is_match("99"));

    // Go `strings.ToUpper` / `strings.ToLower` simple per-rune case mapping (`"straße"` -> `"STRAßE"`, `"İ"` -> `"i"`, `"ΟΣ"` -> `"οσ"`).
    let case_res = process(
        &label_set(&[("de", "straße"), ("tr", "İ"), ("gr", "ΟΣ")]),
        &[
            Config {
                source_labels: strs(&["de"]),
                target_label: "de_up".to_owned(),
                action: Action::Uppercase,
                ..Config::default()
            },
            Config {
                source_labels: strs(&["tr"]),
                target_label: "tr_lo".to_owned(),
                action: Action::Lowercase,
                ..Config::default()
            },
            Config {
                source_labels: strs(&["gr"]),
                target_label: "gr_lo".to_owned(),
                action: Action::Lowercase,
                ..Config::default()
            },
        ],
    )
    .unwrap();
    assert_eq!(case_res.get("de_up").map(String::as_str), Some("STRAßE"));
    assert_eq!(case_res.get("tr_lo").map(String::as_str), Some("i"));
    assert_eq!(case_res.get("gr_lo").map(String::as_str), Some("οσ"));

    let mut dict_case_transforms = Vec::new();
    eval_single_label_value_transform(
        &["straße", "STRAßE"],
        &Config {
            source_labels: strs(&["de"]),
            target_label: "de".to_owned(),
            action: Action::Uppercase,
            ..Config::default()
        },
        &mut dict_case_transforms,
    )
    .unwrap();
    assert_eq!(
        dict_case_transforms,
        vec![
            DictionaryValueTransform::SetTarget("STRAßE".to_owned()),
            DictionaryValueTransform::KeepExisting,
        ]
    );
}

#[test]
fn stage1_metric_name_pushdown_splits_and_filters_families() {
    let cfgs = [
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL]),
            regex: Regexp::must_new("(http|rpc)_.*"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL]),
            regex: Regexp::must_new(".*_bucket"),
            action: Action::Drop,
            ..Config::default()
        },
        Config {
            source_labels: strs(&["env"]),
            regex: Regexp::must_new("prod"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL]),
            regex: Regexp::must_new("rpc_debug_.*"),
            action: Action::Drop,
            ..Config::default()
        },
    ];

    let (pushdown, remaining) = split_metric_name_pushdown(&cfgs);
    assert_eq!(pushdown.len(), 2);
    assert_eq!(remaining.len(), 2);

    assert!(keep_metric_name("http_requests_total", pushdown));
    assert!(keep_metric_name("rpc_duration_seconds_sum", pushdown));
    assert!(!keep_metric_name("go_gc_duration_seconds", pushdown));
    assert!(!keep_metric_name("http_request_duration_bucket", pushdown));

    // Multi-`__name__` join with custom separator and `KeepEqual` / `DropEqual`.
    let multi_name_cfgs = [
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL, METRIC_NAME_LABEL]),
            separator: ":".to_owned(),
            regex: Regexp::must_new("up:up"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL]),
            target_label: METRIC_NAME_LABEL.to_owned(),
            action: Action::KeepEqual,
            ..Config::default()
        },
    ];
    let (multi_pushdown, multi_rem) = split_metric_name_pushdown(&multi_name_cfgs);
    assert_eq!(multi_pushdown.len(), 2);
    assert!(multi_rem.is_empty());
    assert!(keep_metric_name("up", multi_pushdown));
    assert!(!keep_metric_name("down", multi_pushdown));

    let dropequal_cfg = [Config {
        source_labels: strs(&[METRIC_NAME_LABEL]),
        target_label: METRIC_NAME_LABEL.to_owned(),
        action: Action::DropEqual,
        ..Config::default()
    }];
    assert!(!keep_metric_name("up", &dropequal_cfg));

    let keepequal_false_cfg = [Config {
        source_labels: strs(&[METRIC_NAME_LABEL, METRIC_NAME_LABEL]),
        target_label: METRIC_NAME_LABEL.to_owned(),
        action: Action::KeepEqual,
        ..Config::default()
    }];
    assert!(!keep_metric_name("up", &keepequal_false_cfg));

    let empty_sources_cfg = [Config {
        source_labels: Vec::new(),
        regex: Regexp::must_new(""),
        action: Action::Keep,
        ..Config::default()
    }];
    assert!(keep_metric_name("up", &empty_sources_cfg));
}

#[test]
fn stage2_dictionary_vectorized_honor_labels_and_attribute_transforms() {
    let target_labels = label_set(&[
        ("__address__", "10.0.0.1:9090"),
        ("job", "api"),
        ("instance", "10.0.0.1:9090"),
        ("foo", "target-foo"),
        ("exported_foo", "target-exported-foo"),
    ]);

    // 1. Fast path: no metric key collides with public target labels.
    let mut renamed = Vec::new();
    let clean_keys = ["method", "status", "le"];
    assert!(!resolve_conflicting_exposed_keys(
        &clean_keys,
        &target_labels,
        false,
        &mut renamed,
    ));
    assert!(renamed.is_empty());

    // 2. honor_labels = true: never renames metric keys even on collision.
    let colliding_keys = ["exported_foo", "foo", "job", "method"];
    assert!(!resolve_conflicting_exposed_keys(
        &colliding_keys,
        &target_labels,
        true,
        &mut renamed,
    ));
    assert!(renamed.is_empty());

    // 3. honor_labels = false: resolves collisions in ascending key-length order across the key dictionary.
    assert!(resolve_conflicting_exposed_keys(
        &colliding_keys,
        &target_labels,
        false,
        &mut renamed,
    ));
    assert_eq!(
        renamed,
        vec![
            Some("exported_exported_exported_foo".to_owned()),
            Some("exported_exported_foo".to_owned()),
            Some("exported_job".to_owned()),
            None,
        ]
    );

    // 4. Dictionary `LabelDrop` and `LabelKeep`.
    let dict_keys = ["__name__", "env", "ephemeral_id", "ephemeral_pod", "job"];
    let mut key_mask = Vec::new();
    let drop_cfg = Config {
        regex: Regexp::must_new("ephemeral_.*"),
        action: Action::LabelDrop,
        ..Config::default()
    };
    assert_eq!(
        eval_key_keep_mask(&dict_keys, &drop_cfg, &mut key_mask),
        Some(2)
    );
    assert_eq!(key_mask, vec![true, true, false, false, true]);

    let keep_cfg = Config {
        regex: Regexp::must_new("__name__|env|job"),
        action: Action::LabelKeep,
        ..Config::default()
    };
    assert_eq!(
        eval_key_keep_mask(&dict_keys, &keep_cfg, &mut key_mask),
        Some(2)
    );
    assert_eq!(key_mask, vec![true, true, false, false, true]);

    // 5. Dictionary single-label `Keep` and `Drop`.
    let dict_vals = ["prod", "staging", "dev"];
    let mut val_mask = Vec::new();
    let keep_env = Config {
        source_labels: strs(&["env"]),
        regex: Regexp::must_new("prod|staging"),
        action: Action::Keep,
        ..Config::default()
    };
    assert_eq!(
        eval_single_label_keep_mask(&dict_vals, &keep_env, &mut val_mask),
        Some(SingleLabelFilterSummary {
            keep_when_absent: false,
            kept_values: 2,
        })
    );
    assert_eq!(val_mask, vec![true, true, false]);

    let drop_dev = Config {
        source_labels: strs(&["env"]),
        regex: Regexp::must_new("dev"),
        action: Action::Drop,
        ..Config::default()
    };
    assert_eq!(
        eval_single_label_keep_mask(&dict_vals, &drop_dev, &mut val_mask),
        Some(SingleLabelFilterSummary {
            keep_when_absent: true,
            kept_values: 2,
        })
    );
    assert_eq!(val_mask, vec![true, true, false]);

    // 6. Dictionary single-label value transformations (`Lowercase`, `Uppercase`, `Replace`, `HashMod`, `DeleteTarget`).
    let mut transforms = Vec::new();
    let lower_cfg = Config {
        source_labels: strs(&["env"]),
        target_label: "env".to_owned(),
        action: Action::Lowercase,
        ..Config::default()
    };
    let absent = eval_single_label_value_transform(
        &["prod", "PROD", "Staging", ""],
        &lower_cfg,
        &mut transforms,
    )
    .unwrap();
    assert_eq!(absent, DictionaryValueTransform::KeepExisting);
    assert_eq!(
        transforms,
        vec![
            DictionaryValueTransform::KeepExisting,
            DictionaryValueTransform::SetTarget("prod".to_owned()),
            DictionaryValueTransform::SetTarget("staging".to_owned()),
            DictionaryValueTransform::DeleteTarget,
        ]
    );

    let upper_cross_cfg = Config {
        source_labels: strs(&["env"]),
        target_label: "env_upper".to_owned(),
        action: Action::Uppercase,
        ..Config::default()
    };
    let absent_upper =
        eval_single_label_value_transform(&["prod", "PROD"], &upper_cross_cfg, &mut transforms)
            .unwrap();
    assert_eq!(absent_upper, DictionaryValueTransform::DeleteTarget);
    assert_eq!(
        transforms,
        vec![
            DictionaryValueTransform::SetTarget("PROD".to_owned()),
            DictionaryValueTransform::SetTarget("PROD".to_owned()),
        ]
    );

    let hashmod_cfg = Config {
        source_labels: strs(&["c"]),
        modulus: 1000,
        target_label: "shard".to_owned(),
        action: Action::HashMod,
        ..Config::default()
    };
    let absent_hashmod =
        eval_single_label_value_transform(&["baz", "foo\nbar"], &hashmod_cfg, &mut transforms)
            .unwrap();
    assert!(matches!(
        absent_hashmod,
        DictionaryValueTransform::SetTarget(_)
    ));
    assert_eq!(
        transforms,
        vec![
            DictionaryValueTransform::SetTarget("976".to_owned()),
            DictionaryValueTransform::SetTarget("734".to_owned()),
        ]
    );

    let replace_cfg = Config {
        source_labels: strs(&["pod"]),
        regex: Regexp::must_new("([a-z]+)-[0-9a-f]+|dropme"),
        target_label: "app".to_owned(),
        replacement: "$1".to_owned(),
        action: Action::Replace,
        ..Config::default()
    };
    let replace_inputs = ["api-7f8b", "worker-12ab", "dropme", "unmatched"];
    let absent_replace =
        eval_single_label_value_transform(&replace_inputs, &replace_cfg, &mut transforms).unwrap();
    assert_eq!(absent_replace, DictionaryValueTransform::KeepExisting);
    assert_eq!(
        transforms,
        vec![
            DictionaryValueTransform::SetTargetSlice { start: 0, end: 3 },
            DictionaryValueTransform::SetTargetSlice { start: 0, end: 6 },
            DictionaryValueTransform::DeleteTarget,
            DictionaryValueTransform::KeepExisting,
        ]
    );
    assert_eq!(transforms[0].target_value(replace_inputs[0]), Some("api"));
    assert_eq!(
        transforms[1].target_value(replace_inputs[1]),
        Some("worker")
    );

    // On-demand `SingleLabelKeepCache` and `SingleLabelTransformCache` evaluate only referenced `val_id`s.
    let shared_vals = [
        "prod",
        "dev",
        "api-7f8b",
        "unrelated-uuid-0001",
        "unrelated-uuid-0002",
    ];
    let mut keep_cache = SingleLabelKeepCache::new();
    assert!(keep_cache.prepare(shared_vals.len(), &keep_env));
    assert!(!keep_cache.keep_when_absent());
    assert!(keep_cache.keep_value(0, &shared_vals, &keep_env));
    assert!(!keep_cache.keep_value(1, &shared_vals, &keep_env));

    let mut xform_cache = SingleLabelTransformCache::new();
    assert!(xform_cache.prepare(shared_vals.len(), &replace_cfg));
    assert_eq!(
        xform_cache.when_absent(),
        &DictionaryValueTransform::KeepExisting
    );
    assert_eq!(
        xform_cache
            .transform_value(2, &shared_vals, &replace_cfg)
            .target_value(shared_vals[2]),
        Some("api")
    );
    assert!(keep_cache.keep_str(0, "prod", &keep_env));
    assert!(!keep_cache.keep_str(1, "dev", &keep_env));
    assert!(keep_cache.retained_memory_bytes() >= shared_vals.len());
    assert_eq!(
        xform_cache
            .transform_str(2, "api-7f8b", &replace_cfg)
            .target_value("api-7f8b"),
        Some("api")
    );
    assert_eq!(
        xform_cache
            .eval_single_str("worker-12ab", &replace_cfg)
            .target_value("worker-12ab"),
        Some("worker")
    );
    assert!(xform_cache.retained_memory_bytes() > 0);

    let mut iter_renamed = Vec::new();
    assert!(resolve_conflicting_exposed_keys_iter(
        colliding_keys.iter().copied(),
        &target_labels,
        false,
        &mut iter_renamed,
    ));
    assert_eq!(iter_renamed, renamed);

    let mut iter_mask = Vec::new();
    assert_eq!(
        eval_key_keep_mask_iter(dict_keys.iter().copied(), &drop_cfg, &mut iter_mask),
        Some(2)
    );
    assert_eq!(iter_mask, vec![true, true, false, false, true]);

    // 7. End-to-end equivalence: Stage 1 `__name__` pushdown + Stage 2 dictionary primitives vs per-sample `process`.
    let pipeline_cfgs = [
        Config {
            source_labels: strs(&[METRIC_NAME_LABEL]),
            regex: Regexp::must_new("http_.*"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            regex: Regexp::must_new("debug_.*"),
            action: Action::LabelDrop,
            ..Config::default()
        },
        Config {
            source_labels: strs(&["env"]),
            regex: Regexp::must_new("PROD|STAGING"),
            action: Action::Keep,
            ..Config::default()
        },
        Config {
            source_labels: strs(&["env"]),
            target_label: "env".to_owned(),
            action: Action::Lowercase,
            ..Config::default()
        },
    ];
    let (stage1, stage2) = split_metric_name_pushdown(&pipeline_cfgs);
    assert_eq!(stage1.len(), 1);
    assert_eq!(stage2.len(), 3);

    let batch_keys = ["__name__", "debug_trace", "env"];
    let batch_vals = [
        "DEV",
        "PROD",
        "abc",
        "go_goroutines",
        "http_requests_total",
        "xyz",
    ];

    let mut stage2_key_mask = Vec::new();
    eval_key_keep_mask(&batch_keys, &stage2[0], &mut stage2_key_mask).unwrap();

    let mut stage2_val_keep_mask = Vec::new();
    let keep_summary =
        eval_single_label_keep_mask(&batch_vals, &stage2[1], &mut stage2_val_keep_mask).unwrap();

    let mut stage2_val_transforms = Vec::new();
    let absent_transform =
        eval_single_label_value_transform(&batch_vals, &stage2[2], &mut stage2_val_transforms)
            .unwrap();

    let samples = [
        label_set(&[
            ("__name__", "http_requests_total"),
            ("env", "PROD"),
            ("debug_trace", "xyz"),
        ]),
        label_set(&[
            ("__name__", "http_requests_total"),
            ("env", "DEV"),
            ("debug_trace", "xyz"),
        ]),
        label_set(&[
            ("__name__", "go_goroutines"),
            ("env", "PROD"),
            ("debug_trace", "abc"),
        ]),
    ];
    for sample in &samples {
        let oracle = process(sample, &pipeline_cfgs);
        let name = sample.get(METRIC_NAME_LABEL).unwrap();
        let staged = if !keep_metric_name(name, stage1) {
            None
        } else {
            let mut out = LabelSet::new();
            for (k, v) in sample {
                let key_id = batch_keys.iter().position(|bk| bk == k).unwrap();
                if stage2_key_mask[key_id] {
                    out.insert(k.clone(), v.clone());
                }
            }
            let kept = match out.get("env") {
                Some(v) => {
                    let val_id = batch_vals.iter().position(|bv| bv == v).unwrap();
                    stage2_val_keep_mask[val_id]
                }
                None => keep_summary.keep_when_absent,
            };
            if !kept {
                None
            } else {
                let (src_val, xform) = match out.get("env") {
                    Some(v) => {
                        let val_id = batch_vals.iter().position(|bv| bv == v).unwrap();
                        (batch_vals[val_id], &stage2_val_transforms[val_id])
                    }
                    None => ("", &absent_transform),
                };
                match xform {
                    DictionaryValueTransform::KeepExisting => {}
                    DictionaryValueTransform::DeleteTarget => {
                        out.remove("env");
                    }
                    DictionaryValueTransform::SetTargetSlice { .. }
                    | DictionaryValueTransform::SetTarget(_) => {
                        let new_v = xform.target_value(src_val).unwrap().to_owned();
                        out.insert("env".to_owned(), new_v);
                    }
                }
                Some(out)
            }
        };
        assert_eq!(staged, oracle);
    }
}
