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

//! 1:1 compliance test suite against synced `prometheus/prometheus/config/testdata` and
//! `prometheus/common/config/testdata` fixtures and upstream test expectations.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use prometheus_relabel::ValidationScheme;
use prometheus_scrape_manager::config::{
    Config, GlobalConfig, ScrapeProtocol, generate_checksum, load, load_file, load_file_with_env,
};
use prometheus_scrape_manager::discovery::TargetGroup;
use prometheus_scrape_manager::http_config::{
    ByteSize, Duration, TlsVersion, load_http_config_file, load_tls_config,
};
use serde::Deserialize;

fn testdata_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[derive(Debug, Deserialize)]
struct ConfigExpectations {
    expected_errors: Vec<ExpectedError>,
    get_scrape_configs_cases: Vec<GetScrapeConfigsCase>,
    validation_settings_cases: Vec<ValidationSettingsCase>,
    escaping_settings_cases: Vec<ValidationSettingsCase>,
    invalid_http_client_configs: Vec<ExpectedError>,
    valid_tls_configs: Vec<ValidTlsConfigCase>,
    invalid_tls_configs: Vec<ExpectedError>,
}

#[derive(Debug, Deserialize)]
struct ExpectedError {
    filename: String,
    err_msg: String,
}

#[derive(Debug, Deserialize)]
struct GetScrapeConfigsCase {
    config_file: String,
    #[serde(default)]
    err_msg: String,
    #[serde(default)]
    job_names: Vec<String>,
    #[serde(default)]
    scrape_protocols: Vec<String>,
    scrape_native_histograms: Option<bool>,
    always_scrape_classic_histograms: Option<bool>,
    convert_classic_histograms_to_nhcb: Option<bool>,
    extra_scrape_metrics: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ValidationSettingsCase {
    name: String,
    filename: String,
    #[serde(default)]
    expect_err: bool,
    #[serde(default)]
    expect_validation_scheme: String,
    #[serde(default)]
    expect_escaping_scheme: String,
}

#[derive(Debug, Deserialize)]
struct ValidTlsConfigCase {
    filename: String,
    #[serde(default)]
    insecure_skip_verify: bool,
    #[serde(default)]
    min_version: String,
    #[serde(default)]
    max_version: String,
}

fn load_expectations() -> ConfigExpectations {
    let path = testdata_root().join("config_expected/expectations.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[test]
fn test_prometheus_config_expected_errors() {
    let expectations = load_expectations();
    assert!(
        expectations.expected_errors.len() >= 100,
        "expected at least 100 bad config test cases, got {}",
        expectations.expected_errors.len()
    );

    let config_dir = testdata_root().join("config");
    let mut failures = Vec::new();
    for (idx, ee) in expectations.expected_errors.iter().enumerate() {
        let path = config_dir.join(&ee.filename);
        let res = load_file(&path, false, false);
        match res {
            Ok(_) => {
                failures.push(format!(
                    "case [{idx}] {}: expected error containing {:?}, but load_file succeeded",
                    ee.filename, ee.err_msg
                ));
            }
            Err(err) => {
                if !err.contains(&ee.err_msg) {
                    failures.push(format!(
                        "case [{idx}] {}: expected error to contain {:?}, but got: {}",
                        ee.filename, ee.err_msg, err
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} expected_errors cases failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn test_prometheus_config_all_good_files_parse() {
    let config_dir = testdata_root().join("config");
    let mut count = 0usize;
    for entry in std::fs::read_dir(&config_dir).expect("read testdata/config") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap();
        if name.ends_with(".good.yml") || name.ends_with(".good.yaml") {
            let agent_mode = name.starts_with("agent_mode.");
            let cfg = load_file(&path, agent_mode, false)
                .unwrap_or_else(|e| panic!("failed to parse good config {name}: {e}"));
            let _ = cfg
                .get_scrape_configs()
                .unwrap_or_else(|e| panic!("failed get_scrape_configs on {name}: {e}"));
            count += 1;
        }
    }
    assert!(
        count >= 50,
        "expected at least 50 .good.yml files, got {count}"
    );
}

#[test]
fn test_prometheus_conf_good_secret_redaction_and_fields() {
    let path = testdata_root().join("config/conf.good.yml");
    let cfg = load_file(&path, false, false).expect("load conf.good.yml");

    assert_eq!(cfg.global.scrape_interval, Duration::from_secs(15));
    assert_eq!(cfg.global.scrape_timeout, Duration::from_secs(10));
    assert_eq!(cfg.global.evaluation_interval, Duration::from_secs(30));
    assert_eq!(cfg.global.body_size_limit, ByteSize(15 * 1024 * 1024));
    assert_eq!(cfg.global.sample_limit, 1500);
    assert_eq!(cfg.global.target_limit, 30);
    assert_eq!(cfg.global.label_limit, 30);
    assert_eq!(cfg.global.label_name_length_limit, 200);
    assert_eq!(cfg.global.label_value_length_limit, 200);
    assert_eq!(cfg.runtime.gogc, Some(42));
    assert_eq!(cfg.remote_write.len(), 2);
    assert_eq!(cfg.remote_read.len(), 2);
    assert_eq!(
        cfg.otlp.promote_resource_attributes,
        vec!["k8s.cluster.name", "k8s.job.name", "k8s.namespace.name"]
    );
    assert_eq!(cfg.alerting.alertmanagers.len(), 1);
    assert!(cfg.storage.tsdb.is_some());
    assert_eq!(cfg.tracing.endpoint, "localhost:4317");
    assert_eq!(cfg.tracing.client_type, "grpc");
    assert_eq!(cfg.tracing.compression, "gzip");
    assert_eq!(cfg.tracing.timeout, Duration::from_secs(5));

    // Verify secret redaction matches Go `TestLoadConfig` (29 `<secret>` occurrences, no `"mysecret"`).
    let yaml_out = cfg.to_yaml().expect("serialize conf.good.yml to yaml");
    assert!(
        !yaml_out.contains("mysecret"),
        "expected 'mysecret' to be redacted from YAML output"
    );
    let secret_matches = yaml_out.matches("<secret>").count();
    assert_eq!(
        secret_matches, 29,
        "expected exactly 29 '<secret>' occurrences in serialized conf.good.yml, got {secret_matches}"
    );
}

#[test]
fn test_prometheus_roundtrip_good_yml() {
    let path = testdata_root().join("config/roundtrip.good.yml");
    let want = load_file(&path, false, false).expect("load roundtrip.good.yml");
    let out = want.to_yaml().expect("serialize roundtrip.good.yml");
    let mut got = load(&out, false).expect("reload serialized roundtrip.good.yml");
    let dir = path.parent().unwrap().to_str().unwrap();
    got.set_directory(dir);

    let want_yaml = want.to_yaml().unwrap();
    let got_yaml = got.to_yaml().unwrap();
    assert_eq!(got_yaml, want_yaml);
    assert_eq!(got, want);
}

#[test]
fn test_prometheus_external_labels_env_expansion() {
    let path = testdata_root().join("config/external_labels.good.yml");

    // Case 1: TEST=""
    let cfg = load_file_with_env(&path, false, true, |k| {
        if k == "TEST" {
            Some(String::new())
        } else {
            None
        }
    })
    .expect("load external_labels with TEST=''");
    let expected_empty: BTreeMap<String, String> = [
        ("bar".to_owned(), "foo".to_owned()),
        ("foo".to_owned(), "".to_owned()),
        ("baz".to_owned(), "foobar".to_owned()),
        ("qux".to_owned(), "foo${TEST}".to_owned()),
        ("xyz".to_owned(), "foo$bar".to_owned()),
    ]
    .into_iter()
    .collect();
    assert_eq!(cfg.global.external_labels, expected_empty);

    // Case 2: TEST="TestValue"
    let cfg = load_file_with_env(&path, false, true, |k| {
        if k == "TEST" {
            Some("TestValue".to_owned())
        } else {
            None
        }
    })
    .expect("load external_labels with TEST='TestValue'");
    let expected_val: BTreeMap<String, String> = [
        ("bar".to_owned(), "foo".to_owned()),
        ("foo".to_owned(), "TestValue".to_owned()),
        ("baz".to_owned(), "fooTestValuebar".to_owned()),
        ("qux".to_owned(), "foo${TEST}".to_owned()),
        ("xyz".to_owned(), "foo$bar".to_owned()),
    ]
    .into_iter()
    .collect();
    assert_eq!(cfg.global.external_labels, expected_val);
}

#[test]
fn test_prometheus_get_scrape_configs_cases() {
    let expectations = load_expectations();
    assert_eq!(expectations.get_scrape_configs_cases.len(), 24);

    let config_dir = testdata_root().join("config");
    for tc in &expectations.get_scrape_configs_cases {
        let path = config_dir.join(&tc.config_file);
        let cfg = load_file(&path, false, false)
            .unwrap_or_else(|e| panic!("failed to load {}: {e}", tc.config_file));
        let res = cfg.get_scrape_configs();
        if !tc.err_msg.is_empty() {
            let Err(err) = res else {
                panic!(
                    "{}: expected error containing {:?}, got Ok",
                    tc.config_file, tc.err_msg
                );
            };
            assert!(
                err.contains(&tc.err_msg),
                "{}: expected error containing {:?}, got {}",
                tc.config_file,
                tc.err_msg,
                err
            );
            continue;
        }
        let scfgs = res.unwrap_or_else(|e| {
            panic!(
                "{}: unexpected get_scrape_configs error: {e}",
                tc.config_file
            )
        });
        let got_jobs: Vec<String> = scfgs.iter().map(|s| s.job_name.clone()).collect();
        assert_eq!(
            got_jobs, tc.job_names,
            "{}: job_names mismatch",
            tc.config_file
        );

        for scfg in &scfgs {
            if !tc.scrape_protocols.is_empty() {
                let expected_protos: Vec<ScrapeProtocol> = tc
                    .scrape_protocols
                    .iter()
                    .map(|p| ScrapeProtocol::parse(p).unwrap())
                    .collect();
                assert_eq!(
                    scfg.scrape_protocols.as_deref(),
                    Some(expected_protos.as_slice()),
                    "{}: scrape_protocols mismatch on job {}",
                    tc.config_file,
                    scfg.job_name
                );
            }
            if let Some(expected_nh) = tc.scrape_native_histograms {
                assert_eq!(
                    scfg.scrape_native_histograms,
                    Some(expected_nh),
                    "{}: scrape_native_histograms mismatch on job {}",
                    tc.config_file,
                    scfg.job_name
                );
            }
            if let Some(expected_classic) = tc.always_scrape_classic_histograms {
                assert_eq!(
                    scfg.always_scrape_classic_histograms.unwrap_or(false),
                    expected_classic,
                    "{}: always_scrape_classic_histograms mismatch on job {}",
                    tc.config_file,
                    scfg.job_name
                );
            }
            if let Some(expected_nhcb) = tc.convert_classic_histograms_to_nhcb {
                assert_eq!(
                    scfg.convert_classic_histograms_to_nhcb.unwrap_or(false),
                    expected_nhcb,
                    "{}: convert_classic_histograms_to_nhcb mismatch on job {}",
                    tc.config_file,
                    scfg.job_name
                );
            }
            if let Some(expected_extra) = tc.extra_scrape_metrics {
                assert_eq!(
                    scfg.extra_scrape_metrics,
                    Some(expected_extra),
                    "{}: extra_scrape_metrics mismatch on job {}",
                    tc.config_file,
                    scfg.job_name
                );
            }
        }
    }
}

#[test]
fn test_prometheus_validation_and_escaping_settings() {
    let expectations = load_expectations();
    let config_dir = testdata_root().join("config");

    for tc in expectations
        .validation_settings_cases
        .iter()
        .chain(expectations.escaping_settings_cases.iter())
    {
        let path = config_dir.join(&tc.filename);
        let res = load_file(&path, false, false);
        if tc.expect_err {
            assert!(
                res.is_err(),
                "{} ({}): expected error, got Ok",
                tc.name,
                tc.filename
            );
            continue;
        }
        let cfg =
            res.unwrap_or_else(|e| panic!("{} ({}): unexpected error: {e}", tc.name, tc.filename));
        let scfgs = cfg.get_scrape_configs().unwrap_or_else(|e| {
            panic!(
                "{} ({}): get_scrape_configs error: {e}",
                tc.name, tc.filename
            )
        });
        assert_eq!(scfgs.len(), 1);
        let expected_scheme = match tc.expect_validation_scheme.as_str() {
            "legacy" => ValidationScheme::Legacy,
            _ => ValidationScheme::Utf8,
        };
        assert_eq!(
            scfgs[0].metric_name_validation_scheme,
            Some(expected_scheme),
            "{} ({}): validation scheme mismatch",
            tc.name,
            tc.filename
        );
        assert_eq!(
            scfgs[0].metric_name_escaping_scheme, tc.expect_escaping_scheme,
            "{} ({}): escaping scheme mismatch",
            tc.name, tc.filename
        );
    }
}

#[test]
fn test_prometheus_agent_mode() {
    let config_dir = testdata_root().join("config");
    let cases = [
        ("agent_mode.good.yml", ""),
        (
            "agent_mode.with_alert_manager.yml",
            "field alerting is not allowed in agent mode",
        ),
        (
            "agent_mode.with_alert_relabels.yml",
            "field alerting is not allowed in agent mode",
        ),
        (
            "agent_mode.with_rule_files.yml",
            "field rule_files is not allowed in agent mode",
        ),
        (
            "agent_mode.with_remote_reads.yml",
            "field remote_read is not allowed in agent mode",
        ),
        (
            "agent_mode.without_remote_writes.yml",
            "agent mode requires at least one remote_write",
        ),
    ];

    for (filename, expected_err) in cases {
        let res = load_file(config_dir.join(filename), true, false);
        if expected_err.is_empty() {
            assert!(res.is_ok(), "{filename}: expected Ok, got {:?}", res.err());
        } else {
            let err = res.expect_err(filename);
            assert!(
                err.contains(expected_err),
                "{filename}: expected error containing {expected_err:?}, got {err:?}"
            );
        }
    }
}

#[test]
fn test_prometheus_otlp_configs() {
    let config_dir = testdata_root().join("config");

    let sanitize_cases = [
        ("otlp_label_underscore_sanitization_enabled.good.yml", true),
        (
            "otlp_label_underscore_sanitization_disabled.good.yml",
            false,
        ),
        ("otlp_label_underscore_sanitization_defaults.good.yml", true),
    ];
    for (filename, expected) in sanitize_cases {
        let cfg = load_file(config_dir.join(filename), false, false).expect(filename);
        assert_eq!(
            cfg.otlp.sanitize_resource_attributes(),
            expected,
            "{filename}"
        );
    }

    let utf8_cases = [
        ("otlp_allow_utf8.good.yml", true),
        ("otlp_no_translation.good.yml", true),
        ("otlp_sanitize_default_resource_attributes.good.yml", true),
        ("otlp_empty.yml", true),
    ];
    for (filename, expected) in utf8_cases {
        let cfg = load_file(config_dir.join(filename), false, false).expect(filename);
        assert_eq!(cfg.otlp.allow_utf8(), expected, "{filename}");
    }

    let bad_otlp_cases = [
        (
            "otlp_allow_utf8.bad.yml",
            "unknown OTLP translation strategy \"Invalid\"",
        ),
        (
            "otlp_allow_utf8.incompatible.yml",
            "OTLP translation strategy \"NoUTF8EscapingWithSuffixes\" cannot be used when global metric_name_validation_scheme is legacy",
        ),
        (
            "otlp_no_translation.incompatible.yml",
            "OTLP translation strategy \"NoTranslation\" cannot be used when global metric_name_validation_scheme is legacy",
        ),
        (
            "otlp_ignore_resource_attributes_without_promote_all.bad.yml",
            "'ignore_resource_attributes' cannot be configured when 'promote_all_resource_attributes' is false",
        ),
        (
            "otlp_promote_all_resource_attributes.bad.yml",
            "'promote_all_resource_attributes' and 'promote_resource_attributes' cannot be configured simultaneously",
        ),
        (
            "otlp_sanitize_ignore_resource_attributes.bad.yml",
            "duplicated OTLP ignored resource attribute \"k8s.job.name\"",
        ),
        (
            "otlp_sanitize_promote_resource_attributes.bad.yml",
            "duplicated OTLP promoted resource attribute \"k8s.job.name\"",
        ),
    ];
    for (filename, expected_err) in bad_otlp_cases {
        let err = load_file(config_dir.join(filename), false, false).expect_err(filename);
        assert!(
            err.contains(expected_err),
            "{filename}: expected error containing {expected_err:?}, got {err:?}"
        );
    }

    // Also verify `config_with_deprecated_am_api_config.yml`, `scrape_config_files.bad.yml`,
    // and `scrape_config_files_global_duplicate.bad.yml`.
    let am_v1 = load_file(
        config_dir.join("config_with_deprecated_am_api_config.yml"),
        false,
        false,
    )
    .expect("config_with_deprecated_am_api_config.yml");
    assert_eq!(am_v1.alerting.alertmanagers[0].api_version, "v1");

    let sc_bad = load_file(config_dir.join("scrape_config_files.bad.yml"), false, false)
        .expect_err("scrape_config_files.bad.yml");
    assert!(sc_bad.contains("scrape timeout greater than scrape interval"));

    let sc_dup_cfg = load_file(
        config_dir.join("scrape_config_files_global_duplicate.bad.yml"),
        false,
        false,
    )
    .expect("load scrape_config_files_global_duplicate.bad.yml");
    let sc_dup_err = sc_dup_cfg
        .get_scrape_configs()
        .expect_err("expected duplicate scrape config error");
    assert!(sc_dup_err.contains("found multiple scrape configs with job name \"prometheus\""));
}

#[test]
fn test_prometheus_bad_static_configs() {
    let path = testdata_root().join("config/static_config.bad.yml");
    let raw = std::fs::read_to_string(&path).expect("read static_config.bad.yml");
    let err =
        TargetGroup::from_yaml_str(&raw).expect_err("expected error on static_config.bad.yml");
    assert!(
        err.contains("\"\\xff\" is not a valid label name"),
        "expected label name error, got: {err}"
    );
}

#[test]
fn test_prometheus_empty_and_global_and_runtime_and_tsdb() {
    // Empty and global-only configs match `DefaultConfig`.
    let empty_cfg = load("", false).expect("empty config");
    assert_eq!(empty_cfg, Config::default());

    let ws_cfg = load(" ", false).expect("whitespace config");
    assert_eq!(ws_cfg, Config::default());

    let global_empty = load("global:\n", false).expect("empty global config");
    assert_eq!(global_empty.global, GlobalConfig::default());

    // Runtime log level configs
    let runtime_cases = [
        ("runtime:\n  log_level: debug\n", Some("debug"), ""),
        ("runtime:\n  log_level: info\n", Some("info"), ""),
        ("runtime:\n  log_level: warn\n", Some("warn"), ""),
        ("runtime:\n  log_level: error\n", Some("error"), ""),
        ("runtime:\n  log_level: DEBUG\n", Some("DEBUG"), ""),
        ("runtime:\n  log_level: Info\n", Some("Info"), ""),
        (
            "runtime:\n  log_level: invalid\n",
            None,
            "unrecognized log level invalid (must be one of debug, info, warn, error)",
        ),
        (
            "runtime:\n  log_level: trace\n",
            None,
            "unrecognized log level trace (must be one of debug, info, warn, error)",
        ),
    ];
    for (yaml, exp_level, exp_err) in runtime_cases {
        let res = load(yaml, false);
        if exp_err.is_empty() {
            let cfg = res.unwrap();
            assert_eq!(cfg.runtime.log_level, exp_level.unwrap());
        } else {
            let err = res.unwrap_err();
            assert!(err.contains(exp_err), "expected {exp_err:?}, got {err:?}");
        }
    }

    // TSDB retention percentage float
    let tsdb_cfg = load(
        "storage:\n  tsdb:\n    retention:\n      percentage: 55.5\n",
        false,
    )
    .expect("tsdb retention float");
    assert_eq!(
        tsdb_cfg.storage.tsdb.unwrap().retention.unwrap().percentage,
        55.5
    );

    // TSDB chunk encoding
    let ce_xor = load(
        "storage:\n  tsdb:\n    chunk_encoding:\n      floats: xor\n",
        false,
    )
    .expect("xor chunk encoding");
    assert_eq!(
        ce_xor.storage.tsdb.unwrap().chunk_encoding.unwrap().floats,
        "xor"
    );

    let ce_xor2 = load(
        "storage:\n  tsdb:\n    chunk_encoding:\n      floats: xor2\n",
        false,
    )
    .expect("xor2 chunk encoding");
    assert_eq!(
        ce_xor2.storage.tsdb.unwrap().chunk_encoding.unwrap().floats,
        "xor2"
    );
}

#[test]
fn test_prometheus_generate_checksum() {
    let tmp = std::env::temp_dir().join(format!(
        "prom_scrape_rs_checksum_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create temp dir");

    let rule_path = tmp.join("rule.yml");
    std::fs::write(&rule_path, "groups: []").unwrap();
    let sc_path = tmp.join("scrape_config.yml");
    std::fs::write(&sc_path, "scrape_configs:\n  - job_name: test\n").unwrap();

    let cfg_with_both = tmp.join("config.yml");
    std::fs::write(
        &cfg_with_both,
        "rule_files:\n  - rule.yml\nscrape_config_files:\n  - scrape_config.yml\n",
    )
    .unwrap();

    let orig_checksum = generate_checksum(&cfg_with_both).expect("generate checksum");
    assert_eq!(orig_checksum.len(), 64);

    // Modifying rule_files content changes the checksum.
    std::fs::write(&rule_path, "groups: [{name: test}]").unwrap();
    let rule_changed = generate_checksum(&cfg_with_both).expect("checksum after rule change");
    assert_ne!(orig_checksum, rule_changed);
    std::fs::write(&rule_path, "groups: []").unwrap();
    assert_eq!(
        orig_checksum,
        generate_checksum(&cfg_with_both).expect("restored rule checksum")
    );

    // Modifying scrape_config_files content changes the checksum.
    std::fs::write(&sc_path, "scrape_configs:\n  - job_name: changed\n").unwrap();
    let sc_changed = generate_checksum(&cfg_with_both).expect("checksum after sc change");
    assert_ne!(orig_checksum, sc_changed);
    std::fs::write(&sc_path, "scrape_configs:\n  - job_name: test\n").unwrap();
    assert_eq!(
        orig_checksum,
        generate_checksum(&cfg_with_both).expect("restored sc checksum")
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_common_http_and_tls_config_compliance() {
    let expectations = load_expectations();
    let http_dir = testdata_root().join("http_config");

    // 1. All 17 invalidHTTPClientConfigs from `http_config_test.go`
    assert_eq!(expectations.invalid_http_client_configs.len(), 17);
    for tc in &expectations.invalid_http_client_configs {
        let path = http_dir.join(&tc.filename);
        let res = load_http_config_file(&path);
        let Err(err) = res else {
            panic!(
                "{}: expected error containing {:?}, got Ok",
                tc.filename, tc.err_msg
            );
        };
        assert!(
            err.contains(&tc.err_msg),
            "{}: expected error containing {:?}, got: {err}",
            tc.filename,
            tc.err_msg
        );
    }

    // 2. All 10 validTLSConfigs from `tls_config_test.go`
    assert_eq!(expectations.valid_tls_configs.len(), 10);
    for tc in &expectations.valid_tls_configs {
        let path = http_dir.join(&tc.filename);
        let got = load_tls_config(&path)
            .unwrap_or_else(|e| panic!("failed to load valid TLS config {}: {e}", tc.filename));
        assert_eq!(
            got.insecure_skip_verify, tc.insecure_skip_verify,
            "{}: insecure_skip_verify mismatch",
            tc.filename
        );
        let expected_min = if tc.min_version.is_empty() {
            None
        } else {
            Some(TlsVersion::parse(&tc.min_version).unwrap())
        };
        let expected_max = if tc.max_version.is_empty() {
            None
        } else {
            Some(TlsVersion::parse(&tc.max_version).unwrap())
        };
        assert_eq!(
            got.min_version, expected_min,
            "{}: min_version mismatch",
            tc.filename
        );
        assert_eq!(
            got.max_version, expected_max,
            "{}: max_version mismatch",
            tc.filename
        );
    }

    // 3. All invalidTLSConfigs from `tls_config_test.go`
    assert_eq!(expectations.invalid_tls_configs.len(), 1);
    for tc in &expectations.invalid_tls_configs {
        let path = http_dir.join(&tc.filename);
        let err = load_tls_config(&path).expect_err(&tc.filename);
        assert!(
            err.contains(&tc.err_msg),
            "{}: expected error containing {:?}, got: {err}",
            tc.filename,
            tc.err_msg
        );
    }

    // 4. Verify good HTTP client config files in `testdata/http_config/`
    for good_name in [
        "http.conf.good.yml",
        "http.conf.basic-auth.good.yaml",
        "http.conf.basic-auth.username-file.good.yaml",
        "http.conf.headers.good.yaml",
        "http.conf.headers-multiple.good.yaml",
        "http.conf.oauth2-proxy.good.yml",
        "http.conf.proxy-headers.good.json",
        "http.conf.proxy-headers.good.yml",
    ] {
        let path = http_dir.join(good_name);
        let cfg = load_http_config_file(&path)
            .unwrap_or_else(|e| panic!("failed to parse {good_name}: {e}"));
        assert!(cfg.enable_http2, "{good_name}: expected enable_http2=true");
    }

    // 5. Verify additional TLS good/bad files in `testdata/http_config/`
    for good_tls in [
        "tls_config.max_and_min_version.good.json",
        "tls_config.max_and_min_version_same.good.json",
    ] {
        let got = load_tls_config(&http_dir.join(good_tls)).expect(good_tls);
        assert!(got.min_version.is_some());
        assert!(got.max_version.is_some());
    }

    for (bad_tls, expected_err) in [
        (
            "tls_config.cert_no_key.bad.yml",
            "exactly one of key or key_file must be configured when a client certificate is configured",
        ),
        (
            "tls_config.key_no_cert.bad.yml",
            "exactly one of cert or cert_file must be configured when a client key is configured",
        ),
        ("tls_config.invalid_field.bad.yml", "unknown field"),
        (
            "tls_config.max_and_min_version.bad.json",
            "tls_config.max_version must be greater than or equal to tls_config.min_version if both are specified",
        ),
    ] {
        let err = load_tls_config(&http_dir.join(bad_tls)).expect_err(bad_tls);
        assert!(
            err.contains(expected_err),
            "{bad_tls}: expected {expected_err:?}, got {err:?}"
        );
    }
}
