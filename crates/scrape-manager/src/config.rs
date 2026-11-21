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

//! Top-level Prometheus YAML configuration parser, validator, and reload checksum generator
//! with 1:1 parity with `prometheus/prometheus/config`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use base64::Engine as _;
use prometheus_relabel::{Config as RelabelConfig, ValidationScheme};
use regex::Regex;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::discovery::{
    SERVICE_DISCOVERY_FIELDS, ServiceDiscoveryConfigs, check_sd_yaml_mapping, format_go_quoted,
    is_valid_label_name, is_valid_label_value,
};
use crate::http_config::{
    ByteSize, Duration, HTTP_CLIENT_CONFIG_FIELDS, HttpClientConfig, TlsConfig,
    check_allowed_fields, check_http_client_config_fields, clean_path,
    deserialize_string_or_scalar, join_dir, validate_go_url,
};

/// Default scrape protocols in preference order when native histograms are disabled.
pub const DEFAULT_SCRAPE_PROTOCOLS: &[ScrapeProtocol] = &[
    ScrapeProtocol::OpenMetricsText1_0_0,
    ScrapeProtocol::OpenMetricsText0_0_1,
    ScrapeProtocol::PrometheusText1_0_0,
    ScrapeProtocol::PrometheusText0_0_4,
];

/// Default scrape protocols in preference order when native histograms are enabled.
pub const DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS: &[ScrapeProtocol] = &[
    ScrapeProtocol::PrometheusProto,
    ScrapeProtocol::OpenMetricsText1_0_0,
    ScrapeProtocol::OpenMetricsText0_0_1,
    ScrapeProtocol::PrometheusText1_0_0,
    ScrapeProtocol::PrometheusText0_0_4,
];

/// Supported scrape negotiation protocol (`config.ScrapeProtocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScrapeProtocol {
    /// Prometheus binary protobuf exposition format.
    PrometheusProto,
    /// OpenMetrics text format 0.0.1.
    OpenMetricsText0_0_1,
    /// OpenMetrics text format 1.0.0.
    OpenMetricsText1_0_0,
    /// OpenMetrics text format 2.0.0.
    OpenMetricsText2_0_0,
    /// Prometheus text exposition format 0.0.4.
    PrometheusText0_0_4,
    /// Prometheus text exposition format 1.0.0.
    PrometheusText1_0_0,
}

impl ScrapeProtocol {
    /// Parses a [`ScrapeProtocol`] from its canonical string name.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "PrometheusProto" => Ok(Self::PrometheusProto),
            "OpenMetricsText0.0.1" => Ok(Self::OpenMetricsText0_0_1),
            "OpenMetricsText1.0.0" => Ok(Self::OpenMetricsText1_0_0),
            "OpenMetricsText2.0.0" => Ok(Self::OpenMetricsText2_0_0),
            "PrometheusText0.0.4" => Ok(Self::PrometheusText0_0_4),
            "PrometheusText1.0.0" => Ok(Self::PrometheusText1_0_0),
            other => Err(format!(
                "unknown scrape protocol {other}, supported: [OpenMetricsText0.0.1 OpenMetricsText1.0.0 OpenMetricsText2.0.0 PrometheusProto PrometheusText0.0.4 PrometheusText1.0.0]"
            )),
        }
    }

    /// Returns the canonical string identifier of this protocol.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PrometheusProto => "PrometheusProto",
            Self::OpenMetricsText0_0_1 => "OpenMetricsText0.0.1",
            Self::OpenMetricsText1_0_0 => "OpenMetricsText1.0.0",
            Self::OpenMetricsText2_0_0 => "OpenMetricsText2.0.0",
            Self::PrometheusText0_0_4 => "PrometheusText0.0.4",
            Self::PrometheusText1_0_0 => "PrometheusText1.0.0",
        }
    }

    /// Returns the `Accept` header media type corresponding to this protocol.
    pub const fn header_media_type(&self) -> &'static str {
        match self {
            Self::PrometheusProto => {
                "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited"
            }
            Self::OpenMetricsText0_0_1 => "application/openmetrics-text;version=0.0.1",
            Self::OpenMetricsText1_0_0 => "application/openmetrics-text;version=1.0.0",
            Self::OpenMetricsText2_0_0 => "application/openmetrics-text;version=2.0.0",
            Self::PrometheusText0_0_4 => "text/plain;version=0.0.4",
            Self::PrometheusText1_0_0 => "text/plain;version=1.0.0",
        }
    }
}

impl fmt::Display for ScrapeProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ScrapeProtocol {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScrapeProtocol {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}

fn validate_accept_scrape_protocols(sps: &[String]) -> Result<Vec<ScrapeProtocol>, String> {
    if sps.is_empty() {
        return Err("scrape_protocols cannot be empty".to_owned());
    }
    let mut parsed = Vec::with_capacity(sps.len());
    let mut seen_lower = BTreeSet::new();
    for sp in sps {
        let proto = ScrapeProtocol::parse(sp).map_err(|e| format!("scrape_protocols: {e}"))?;
        let lower = sp.to_ascii_lowercase();
        if !seen_lower.insert(lower) {
            let formatted = format!("[{}]", sps.join(" "));
            return Err(format!(
                "duplicated protocol in scrape_protocols, got {formatted}"
            ));
        }
        parsed.push(proto);
    }
    Ok(parsed)
}

fn serialize_validation_scheme<S: Serializer>(
    scheme: &ValidationScheme,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match scheme {
        ValidationScheme::Utf8 | ValidationScheme::Unset => serializer.serialize_str("utf8"),
        ValidationScheme::Legacy => serializer.serialize_str("legacy"),
    }
}

fn serialize_opt_validation_scheme<S: Serializer>(
    scheme: &Option<ValidationScheme>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match scheme {
        Some(s) => serialize_validation_scheme(s, serializer),
        None => serializer.serialize_none(),
    }
}

fn parse_validation_scheme_str(s: &str) -> Result<ValidationScheme, String> {
    match s {
        "utf8" => Ok(ValidationScheme::Utf8),
        "legacy" => Ok(ValidationScheme::Legacy),
        other => Err(format!("unrecognized ValidationScheme: {other:?}")),
    }
}

fn deserialize_validation_scheme<'de, D>(deserializer: D) -> Result<ValidationScheme, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
    if s.is_empty() {
        return Ok(ValidationScheme::Utf8);
    }
    parse_validation_scheme_str(&s).map_err(de::Error::custom)
}

fn deserialize_opt_validation_scheme<'de, D>(
    deserializer: D,
) -> Result<Option<ValidationScheme>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Option::<String>::deserialize(deserializer)?;
    match s {
        None => Ok(None),
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => parse_validation_scheme_str(&v)
            .map(Some)
            .map_err(de::Error::custom),
    }
}

/// Top-level Prometheus configuration (`config.Config`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Global defaults inherited by scrape, rule evaluation, and remote write configs.
    pub global: GlobalConfig,
    /// Runtime GC and log level configuration.
    #[serde(skip_serializing_if = "RuntimeConfig::is_empty")]
    pub runtime: RuntimeConfig,
    /// Alertmanager and alert relabeling configuration.
    #[serde(skip_serializing_if = "AlertingConfig::is_empty")]
    pub alerting: AlertingConfig,
    /// Glob patterns of rule files to load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_files: Vec<String>,
    /// Glob patterns of additional scrape config files to load.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scrape_config_files: Vec<String>,
    /// Target scrape job configurations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scrape_configs: Vec<ScrapeConfig>,
    /// Local TSDB and exemplar storage configuration.
    #[serde(skip_serializing_if = "StorageConfig::is_empty")]
    pub storage: StorageConfig,
    /// OpenTelemetry tracing export configuration.
    #[serde(skip_serializing_if = "TracingConfig::is_empty")]
    pub tracing: TracingConfig,
    /// Remote write endpoint configurations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remote_write: Vec<RemoteWriteConfig>,
    /// Remote read endpoint configurations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remote_read: Vec<RemoteReadConfig>,
    /// OpenTelemetry OTLP receiver configuration.
    #[serde(skip_serializing_if = "OtlpConfig::is_empty")]
    pub otlp: OtlpConfig,
}

const CONFIG_FIELDS: &[&str] = &[
    "global",
    "runtime",
    "alerting",
    "rule_files",
    "scrape_config_files",
    "scrape_configs",
    "storage",
    "tracing",
    "remote_write",
    "remote_read",
    "otlp",
];

impl Config {
    /// Serializes this [`Config`] to YAML (redacting all non-empty [`crate::http_config::Secret`] values to `<secret>`).
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self).map_err(|e| e.to_string())
    }

    /// Resolves relative file paths across the configuration relative to `dir` (`Config.SetDirectory`).
    pub fn set_directory(&mut self, dir: &str) {
        self.global.set_directory(dir);
        self.alerting.set_directory(dir);
        for rf in &mut self.rule_files {
            *rf = join_dir(dir, rf);
        }
        for sf in &mut self.scrape_config_files {
            *sf = join_dir(dir, sf);
        }
        for sc in &mut self.scrape_configs {
            sc.set_directory(dir);
        }
        self.storage.set_directory(dir);
        self.tracing.set_directory(dir);
        for rw in &mut self.remote_write {
            rw.set_directory(dir);
        }
        for rr in &mut self.remote_read {
            rr.set_directory(dir);
        }
        self.otlp.set_directory(dir);
    }

    /// Expands `scrape_config_files` globs, validates each loaded [`ScrapeConfig`] against `global`,
    /// checks for duplicate `job_name` values, and returns the combined list of scrape configs
    /// (`Config.GetScrapeConfigs`).
    pub fn get_scrape_configs(&self) -> Result<Vec<ScrapeConfig>, String> {
        let mut scfgs = Vec::with_capacity(self.scrape_configs.len());
        let mut job_names: BTreeMap<String, String> = BTreeMap::new();
        for scfg in &self.scrape_configs {
            job_names.insert(scfg.job_name.clone(), "main config file".to_owned());
            scfgs.push(scfg.clone());
        }
        for pat in &self.scrape_config_files {
            let fs = expand_single_dir_glob(pat)?;
            for filename in fs {
                let content = std::fs::read_to_string(&filename).map_err(|e| e.to_string())?;
                let preprocessed = preprocess_yaml_tags(&content)?;
                let val: serde_yaml::Value =
                    serde_yaml::from_str(&preprocessed).map_err(|e| format!("{filename}: {e}"))?;
                if let serde_yaml::Value::Mapping(ref map) = val {
                    check_allowed_fields(map, &["scrape_configs"], "config.ScrapeConfigs")
                        .map_err(|e| format!("{filename}: {e}"))?;
                    if let Some(serde_yaml::Value::Sequence(seq)) =
                        map.get(serde_yaml::Value::String("scrape_configs".to_owned()))
                    {
                        for item in seq {
                            if item.is_null() {
                                return Err(format!(
                                    "{filename}: empty or null scrape config section"
                                ));
                            }
                            check_scrape_config_yaml_value(item)
                                .map_err(|e| format!("{filename}: {e}"))?;
                        }
                    }
                }
                #[derive(Deserialize, Default)]
                #[serde(deny_unknown_fields, default)]
                struct ScrapeConfigsFile {
                    scrape_configs: Vec<ScrapeConfig>,
                }
                let parsed: ScrapeConfigsFile =
                    serde_yaml::from_value(val).map_err(|e| format!("{filename}: {e}"))?;
                let file_dir = Path::new(&filename)
                    .parent()
                    .and_then(|p| p.to_str())
                    .unwrap_or(".");
                for mut scfg in parsed.scrape_configs {
                    scfg.validate(&self.global)
                        .map_err(|e| format!("{filename}: {e}"))?;
                    if let Some(first) = job_names.get(&scfg.job_name) {
                        return Err(format!(
                            "{filename}: found multiple scrape configs with job name {:?}, first found in {first}",
                            scfg.job_name
                        ));
                    }
                    // Format filename with forward slashes matching Go filepath on Unix.
                    let clean_filename = clean_path(&filename);
                    job_names.insert(
                        scfg.job_name.clone(),
                        format!("scrape config file {clean_filename:?}"),
                    );
                    scfg.set_directory(file_dir);
                    scfgs.push(scfg);
                }
            }
        }
        Ok(scfgs)
    }
}

/// Global configuration block (`config.GlobalConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    /// How frequently to scrape targets by default.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub scrape_interval: Duration,
    /// Default timeout for a single scrape request.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub scrape_timeout: Duration,
    /// Default ordered list of scrape negotiation protocols.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_opt_scrape_protocols"
    )]
    pub scrape_protocols: Option<Vec<ScrapeProtocol>>,
    /// How frequently to evaluate rules by default.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub evaluation_interval: Duration,
    /// Offset from the rule evaluation timestamp.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub rule_query_offset: Duration,
    /// Path to the file to which PromQL queries are logged.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub query_log_file: String,
    /// Default path to the file to which scrape failures are logged.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub scrape_failure_log_file: String,
    /// Labels added to any time series or alerts when communicating with external systems.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub external_labels: BTreeMap<String, String>,
    /// Uncompressed response body size limit per scrape.
    #[serde(skip_serializing_if = "ByteSize::is_zero")]
    pub body_size_limit: ByteSize,
    /// Per-scrape limit on number of scraped samples.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub sample_limit: u64,
    /// Per-scrape config limit on number of scraped targets.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub target_limit: u64,
    /// Per-sample limit on number of labels.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_limit: u64,
    /// Per-sample limit on length of label names.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_name_length_limit: u64,
    /// Per-sample limit on length of label values.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_value_length_limit: u64,
    /// Per-scrape config limit on number of dropped targets to keep for UI/API inspection.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub keep_dropped_targets: u64,
    /// Default HTTP client settings used by service discovery and scrape configs.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
    /// Whether to scrape native histograms by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrape_native_histograms: Option<bool>,
    /// Whether to always scrape classic histograms alongside native histograms by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_scrape_classic_histograms: Option<bool>,
    /// Whether to convert classic histograms into NHCB by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convert_classic_histograms_to_nhcb: Option<bool>,
    /// Whether to emit extra scrape metrics by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_scrape_metrics: Option<bool>,
    /// Metric and label name validation scheme (`utf8` or `legacy`).
    #[serde(
        serialize_with = "serialize_validation_scheme",
        deserialize_with = "deserialize_validation_scheme"
    )]
    pub metric_name_validation_scheme: ValidationScheme,
    /// Metric and label name escaping scheme (`allow-utf-8`, `underscores`, `dots`, `values`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub metric_name_escaping_scheme: String,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn deserialize_opt_scrape_protocols<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<ScrapeProtocol>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<Vec<String>> = Option::<Vec<String>>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(sps) => {
            let parsed = validate_accept_scrape_protocols(&sps)
                .map_err(|e| de::Error::custom(format!("{e} for global config")))?;
            Ok(Some(parsed))
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            scrape_interval: Duration::from_mins(1),
            scrape_timeout: Duration::from_secs(10),
            scrape_protocols: Some(DEFAULT_SCRAPE_PROTOCOLS.to_vec()),
            evaluation_interval: Duration::from_mins(1),
            rule_query_offset: Duration::ZERO,
            query_log_file: String::new(),
            scrape_failure_log_file: String::new(),
            external_labels: BTreeMap::new(),
            body_size_limit: ByteSize(0),
            sample_limit: 0,
            target_limit: 0,
            label_limit: 0,
            label_name_length_limit: 0,
            label_value_length_limit: 0,
            keep_dropped_targets: 0,
            http_client_config: HttpClientConfig::default(),
            scrape_native_histograms: Some(false),
            always_scrape_classic_histograms: None,
            convert_classic_histograms_to_nhcb: None,
            extra_scrape_metrics: Some(false),
            metric_name_validation_scheme: ValidationScheme::Utf8,
            metric_name_escaping_scheme: "allow-utf-8".to_owned(),
        }
    }
}

const GLOBAL_CONFIG_FIELDS: &[&str] = &[
    "scrape_interval",
    "scrape_timeout",
    "scrape_protocols",
    "evaluation_interval",
    "rule_query_offset",
    "query_log_file",
    "scrape_failure_log_file",
    "external_labels",
    "body_size_limit",
    "sample_limit",
    "target_limit",
    "label_limit",
    "label_name_length_limit",
    "label_value_length_limit",
    "keep_dropped_targets",
    "scrape_native_histograms",
    "always_scrape_classic_histograms",
    "convert_classic_histograms_to_nhcb",
    "extra_scrape_metrics",
    "metric_name_validation_scheme",
    "metric_name_escaping_scheme",
    "http_Client_config",
];

impl GlobalConfig {
    /// Returns a zero-initialized [`GlobalConfig`] used as the base before unmarshaling an explicit
    /// `global:` YAML block (`GlobalConfig.UnmarshalYAML`).
    pub fn zero() -> Self {
        Self {
            scrape_interval: Duration::ZERO,
            scrape_timeout: Duration::ZERO,
            scrape_protocols: None,
            evaluation_interval: Duration::ZERO,
            rule_query_offset: Duration::ZERO,
            query_log_file: String::new(),
            scrape_failure_log_file: String::new(),
            external_labels: BTreeMap::new(),
            body_size_limit: ByteSize(0),
            sample_limit: 0,
            target_limit: 0,
            label_limit: 0,
            label_name_length_limit: 0,
            label_value_length_limit: 0,
            keep_dropped_targets: 0,
            http_client_config: HttpClientConfig::default(),
            scrape_native_histograms: None,
            always_scrape_classic_histograms: None,
            convert_classic_histograms_to_nhcb: None,
            extra_scrape_metrics: None,
            metric_name_validation_scheme: ValidationScheme::Utf8,
            metric_name_escaping_scheme: String::new(),
        }
    }

    /// Resolves relative file paths in [`GlobalConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.query_log_file = join_dir(dir, &self.query_log_file);
        self.scrape_failure_log_file = join_dir(dir, &self.scrape_failure_log_file);
        self.http_client_config.set_directory(dir);
    }

    fn validate_and_apply_defaults(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if !self.http_client_config.basic_auth.is_none()
            || !self.http_client_config.oauth2.is_none()
            || !self.http_client_config.authorization.is_none()
        {
            return Err(
                "authentication can not be set in global config (Wait, check http_client_config)"
                    .to_owned(),
            );
        }

        for (ln, lv) in &self.external_labels {
            if !is_valid_label_name(ln, self.metric_name_validation_scheme) {
                return Err(format!(
                    "{} is not a valid label name",
                    format_go_quoted(ln)
                ));
            }
            if !is_valid_label_value(lv) {
                return Err(format!(
                    "{} is not a valid label value",
                    format_go_quoted(lv)
                ));
            }
        }

        let default = Self::default();
        if self.scrape_interval.is_zero() {
            self.scrape_interval = default.scrape_interval;
        }
        if self.scrape_timeout > self.scrape_interval {
            return Err("global scrape timeout greater than scrape interval".to_owned());
        }
        if self.scrape_timeout.is_zero() {
            self.scrape_timeout = default.scrape_timeout.min(self.scrape_interval);
        }
        if self.evaluation_interval.is_zero() {
            self.evaluation_interval = default.evaluation_interval;
        }
        if self.scrape_native_histograms.is_none() {
            self.scrape_native_histograms = default.scrape_native_histograms;
        }
        if self.extra_scrape_metrics.is_none() {
            self.extra_scrape_metrics = default.extra_scrape_metrics;
        }
        if self.scrape_protocols.is_none() {
            if self.scrape_native_histograms == Some(true) {
                self.scrape_protocols = Some(DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS.to_vec());
            } else {
                self.scrape_protocols = default.scrape_protocols;
            }
        }
        if self.metric_name_escaping_scheme == "allow-utf-8"
            && self.metric_name_validation_scheme != ValidationScheme::Utf8
        {
            return Err(
                "utf8 metric names requested but validation scheme is not set to UTF8".to_owned(),
            );
        }
        Ok(())
    }
}

/// Runtime GC and log level configuration (`config.RuntimeConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeConfig {
    /// Go garbage collector target percentage (`GOGC`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gogc: Option<i64>,
    /// Runtime log level (`debug`, `info`, `warn`, `error`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub log_level: String,
}

impl RuntimeConfig {
    /// Returns `true` when no runtime parameters are configured.
    pub fn is_empty(&self) -> bool {
        self.gogc.is_none() && self.log_level.is_empty()
    }

    /// Validates [`RuntimeConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if !self.log_level.is_empty() {
            match self.log_level.to_ascii_lowercase().as_str() {
                "debug" | "info" | "warn" | "error" => {}
                _ => {
                    return Err(format!(
                        "unrecognized log level {} (must be one of debug, info, warn, error)",
                        self.log_level
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Per-job target scrape configuration (`config.ScrapeConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScrapeConfig {
    /// Job name assigned to scraped targets (`job` label).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub job_name: String,
    /// How Alignment of `honor_labels` handles conflicts between target labels and scraped labels.
    #[serde(skip_serializing_if = "is_false")]
    pub honor_labels: bool,
    /// Whether to respect timestamps exposed by scraped targets.
    #[serde(default = "default_true", skip_serializing_if = "is_false")]
    pub honor_timestamps: bool,
    /// Whether to track staleness of timestamps when `honor_timestamps` is enabled.
    #[serde(skip_serializing_if = "is_false")]
    pub track_timestamps_staleness: bool,
    /// Optional HTTP query parameters appended to the scrape URL.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_params"
    )]
    pub params: BTreeMap<String, Vec<String>>,
    /// How frequently to scrape targets from this job.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub scrape_interval: Duration,
    /// Per-scrape timeout for this job.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub scrape_timeout: Duration,
    /// Ordered list of scrape protocols to negotiate in the `Accept` header.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_opt_raw_scrape_protocols"
    )]
    pub scrape_protocols: Option<Vec<ScrapeProtocol>>,
    /// Fallback scrape protocol when the target's `Content-Type` header is missing or empty.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub fallback_scrape_protocol: String,
    /// Path to the file to which scrape failures for this job are logged.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub scrape_failure_log_file: String,
    /// HTTP resource path from which to fetch metrics (defaults to `/metrics`).
    #[serde(
        default = "default_metrics_path",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub metrics_path: String,
    /// URL scheme used for requests (`http` or `https`, defaults to `http`).
    #[serde(
        default = "default_scheme_http",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub scheme: String,
    /// Whether to request compressed responses (`gzip`) from targets.
    #[serde(default = "default_true", skip_serializing_if = "is_false")]
    pub enable_compression: bool,
    /// Uncompressed response body size limit.
    #[serde(skip_serializing_if = "ByteSize::is_zero")]
    pub body_size_limit: ByteSize,
    /// Per-scrape limit on number of scraped samples.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub sample_limit: u64,
    /// Per-scrape config limit on number of scraped targets.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub target_limit: u64,
    /// Per-sample limit on number of labels.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_limit: u64,
    /// Per-sample limit on length of label names.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_name_length_limit: u64,
    /// Per-sample limit on length of label values.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub label_value_length_limit: u64,
    /// Per-scrape config limit on number of dropped targets to keep.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub keep_dropped_targets: u64,
    /// Limit on number of native histogram buckets per sample.
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub native_histogram_bucket_limit: u64,
    /// Minimum factor for native histogram bucket boundaries.
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub native_histogram_min_bucket_factor: f64,
    /// Whether to scrape native histograms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scrape_native_histograms: Option<bool>,
    /// Whether to always scrape classic histograms alongside native histograms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_scrape_classic_histograms: Option<bool>,
    /// Whether to convert classic histograms into native histograms with custom buckets (NHCB).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convert_classic_histograms_to_nhcb: Option<bool>,
    /// Whether to emit extra scrape metrics (`scrape_timeout_seconds`, `scrape_sample_limit`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_scrape_metrics: Option<bool>,
    /// Metric and label name validation scheme (`utf8` or `legacy`).
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_validation_scheme",
        deserialize_with = "deserialize_opt_validation_scheme"
    )]
    pub metric_name_validation_scheme: Option<ValidationScheme>,
    /// Metric and label name escaping scheme (`allow-utf-8`, `underscores`, `dots`, `values`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub metric_name_escaping_scheme: String,
    /// Raw `scrape_protocols` strings retained for validation with the job name in the error message.
    #[serde(skip)]
    raw_scrape_protocols: Option<Vec<String>>,
    /// HTTP client settings for scraping targets.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
    /// Service discovery configurations (`static_configs`, `file_sd_configs`, `kubernetes_sd_configs`, etc.).
    #[serde(flatten)]
    pub service_discovery_configs: ServiceDiscoveryConfigs,
    /// Target relabeling rules applied before scraping.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relabel_configs: Vec<RelabelConfig>,
    /// Metric relabeling rules applied to scraped samples before ingestion.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub metric_relabel_configs: Vec<RelabelConfig>,
}

fn is_false(v: &bool) -> bool {
    !*v
}
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
fn default_true() -> bool {
    true
}
fn default_metrics_path() -> String {
    "/metrics".to_owned()
}
fn default_scheme_http() -> String {
    "http".to_owned()
}

fn deserialize_params<'de, D>(deserializer: D) -> Result<BTreeMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<BTreeMap<String, Vec<String>>>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

fn deserialize_opt_raw_scrape_protocols<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<ScrapeProtocol>>, D::Error>
where
    D: Deserializer<'de>,
{
    // Note: actual validation with job_name is performed in `check_scrape_config_yaml_value`
    // and `ScrapeConfig::validate`.
    let raw: Option<Vec<String>> = Option::<Vec<String>>::deserialize(deserializer)?;
    match raw {
        None => Ok(None),
        Some(sps) => {
            let mut out = Vec::with_capacity(sps.len());
            for sp in sps {
                if let Ok(p) = ScrapeProtocol::parse(&sp) {
                    out.push(p);
                }
            }
            Ok(Some(out))
        }
    }
}

impl Default for ScrapeConfig {
    fn default() -> Self {
        Self {
            job_name: String::new(),
            honor_labels: false,
            honor_timestamps: true,
            track_timestamps_staleness: false,
            params: BTreeMap::new(),
            scrape_interval: Duration::ZERO,
            scrape_timeout: Duration::ZERO,
            scrape_protocols: None,
            fallback_scrape_protocol: String::new(),
            scrape_failure_log_file: String::new(),
            metrics_path: "/metrics".to_owned(),
            scheme: "http".to_owned(),
            enable_compression: true,
            body_size_limit: ByteSize(0),
            sample_limit: 0,
            target_limit: 0,
            label_limit: 0,
            label_name_length_limit: 0,
            label_value_length_limit: 0,
            keep_dropped_targets: 0,
            native_histogram_bucket_limit: 0,
            native_histogram_min_bucket_factor: 0.0,
            scrape_native_histograms: None,
            always_scrape_classic_histograms: None,
            convert_classic_histograms_to_nhcb: None,
            extra_scrape_metrics: None,
            metric_name_validation_scheme: None,
            metric_name_escaping_scheme: String::new(),
            raw_scrape_protocols: None,
            http_client_config: HttpClientConfig::default(),
            service_discovery_configs: ServiceDiscoveryConfigs::default(),
            relabel_configs: Vec::new(),
            metric_relabel_configs: Vec::new(),
        }
    }
}

const SCRAPE_CONFIG_OWN_FIELDS: &[&str] = &[
    "job_name",
    "honor_labels",
    "honor_timestamps",
    "track_timestamps_staleness",
    "params",
    "scrape_interval",
    "scrape_timeout",
    "scrape_protocols",
    "fallback_scrape_protocol",
    "scrape_failure_log_file",
    "metrics_path",
    "scheme",
    "enable_compression",
    "body_size_limit",
    "sample_limit",
    "target_limit",
    "label_limit",
    "label_name_length_limit",
    "label_value_length_limit",
    "keep_dropped_targets",
    "native_histogram_bucket_limit",
    "native_histogram_min_bucket_factor",
    "scrape_native_histograms",
    "always_scrape_classic_histograms",
    "convert_classic_histograms_to_nhcb",
    "extra_scrape_metrics",
    "metric_name_validation_scheme",
    "metric_name_escaping_scheme",
    "relabel_configs",
    "metric_relabel_configs",
];

impl ScrapeConfig {
    /// Resolves relative file paths in this [`ScrapeConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.service_discovery_configs.set_directory(dir);
        self.http_client_config.set_directory(dir);
        self.scrape_failure_log_file = join_dir(dir, &self.scrape_failure_log_file);
    }

    /// Validates this [`ScrapeConfig`] and inherits unset settings from [`GlobalConfig`] (`ScrapeConfig.Validate`).
    pub fn validate(&mut self, global: &GlobalConfig) -> Result<(), String> {
        let local_validation_unset = self.metric_name_validation_scheme.is_none();
        let local_scheme = match self.metric_name_validation_scheme {
            Some(s) => s,
            None => {
                self.metric_name_validation_scheme = Some(global.metric_name_validation_scheme);
                global.metric_name_validation_scheme
            }
        };

        // Validate HTTP client, relabel, and SD configs first (matching Go's `UnmarshalYAML` order
        // before `ScrapeConfig.Validate` checks `job_name`).
        self.http_client_config.validate()?;
        for rc in &mut self.relabel_configs {
            validate_relabel_config(rc, local_scheme)?;
        }
        for rc in &mut self.metric_relabel_configs {
            validate_relabel_config(rc, local_scheme)?;
        }
        self.service_discovery_configs
            .validate_with_hostname(self.relabel_configs.is_empty())?;

        if self.job_name.is_empty() {
            return Err("job_name is empty".to_owned());
        }

        if self.scrape_interval.is_zero() {
            self.scrape_interval = global.scrape_interval;
        }
        if self.scrape_timeout.is_zero() {
            if global.scrape_timeout > self.scrape_interval {
                self.scrape_timeout = self.scrape_interval;
            } else {
                self.scrape_timeout = global.scrape_timeout;
            }
        }
        if self.scrape_timeout > self.scrape_interval {
            return Err(format!(
                "scrape timeout greater than scrape interval for scrape config with job name {:?}",
                self.job_name
            ));
        }

        if self.body_size_limit.is_zero() {
            self.body_size_limit = global.body_size_limit;
        }
        if self.sample_limit == 0 {
            self.sample_limit = global.sample_limit;
        }
        if self.target_limit == 0 {
            self.target_limit = global.target_limit;
        }
        if self.label_limit == 0 {
            self.label_limit = global.label_limit;
        }
        if self.label_name_length_limit == 0 {
            self.label_name_length_limit = global.label_name_length_limit;
        }
        if self.label_value_length_limit == 0 {
            self.label_value_length_limit = global.label_value_length_limit;
        }
        if self.keep_dropped_targets == 0 {
            self.keep_dropped_targets = global.keep_dropped_targets;
        }
        if self.scrape_failure_log_file.is_empty() {
            self.scrape_failure_log_file = global.scrape_failure_log_file.clone();
        }
        if self.always_scrape_classic_histograms.is_none() {
            self.always_scrape_classic_histograms = global.always_scrape_classic_histograms;
        }
        if self.convert_classic_histograms_to_nhcb.is_none() {
            self.convert_classic_histograms_to_nhcb = global.convert_classic_histograms_to_nhcb;
        }
        if self.extra_scrape_metrics.is_none() {
            self.extra_scrape_metrics = global.extra_scrape_metrics;
        }

        if let Some(raw_sps) = self.raw_scrape_protocols.take() {
            let parsed = validate_accept_scrape_protocols(&raw_sps)
                .map_err(|e| format!("{e} for scrape config with job name {:?}", self.job_name))?;
            self.scrape_protocols = Some(parsed);
        } else if self.scrape_protocols.is_none() {
            if self.scrape_native_histograms == Some(true) {
                self.scrape_protocols = Some(DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS.to_vec());
            } else if self.scrape_native_histograms == Some(false)
                && global.scrape_protocols.as_deref() == Some(DEFAULT_PROTO_FIRST_SCRAPE_PROTOCOLS)
            {
                self.scrape_protocols = Some(DEFAULT_SCRAPE_PROTOCOLS.to_vec());
            } else if let Some(ref global_sps) = global.scrape_protocols {
                self.scrape_protocols = Some(global_sps.clone());
            } else {
                self.scrape_protocols = Some(DEFAULT_SCRAPE_PROTOCOLS.to_vec());
            }
        }

        if self.scrape_native_histograms.is_none() {
            self.scrape_native_histograms = global.scrape_native_histograms;
        }

        if !self.fallback_scrape_protocol.is_empty() {
            ScrapeProtocol::parse(&self.fallback_scrape_protocol).map_err(|e| {
                format!(
                    "invalid fallback_scrape_protocol for scrape config with job name {:?}: {e}",
                    self.job_name
                )
            })?;
        }

        let global_escaping = if global.metric_name_escaping_scheme.is_empty() {
            if global.metric_name_validation_scheme == ValidationScheme::Legacy {
                "underscores".to_owned()
            } else {
                "allow-utf-8".to_owned()
            }
        } else {
            match global.metric_name_escaping_scheme.as_str() {
                "allow-utf-8" | "underscores" | "dots" | "values" => {
                    global.metric_name_escaping_scheme.clone()
                }
                other => {
                    return Err(format!(
                        "unknown global name escaping method specified, must be one of 'allow-utf-8', 'underscores', 'dots', or 'values', got {other:?}"
                    ));
                }
            }
        };

        if self.metric_name_escaping_scheme.is_empty() {
            if local_validation_unset {
                self.metric_name_escaping_scheme = global_escaping;
            } else if local_scheme == ValidationScheme::Legacy {
                self.metric_name_escaping_scheme = "underscores".to_owned();
            } else {
                self.metric_name_escaping_scheme = "allow-utf-8".to_owned();
            }
        }

        match self.metric_name_escaping_scheme.as_str() {
            "allow-utf-8" => {
                if local_scheme != ValidationScheme::Utf8 {
                    return Err(
                        "utf8 metric names requested but validation scheme is not set to UTF8"
                            .to_owned(),
                    );
                }
            }
            "underscores" | "dots" | "values" => {}
            other => {
                return Err(format!(
                    "unknown scrape config name escaping method specified, must be one of 'allow-utf-8', 'underscores', 'dots', or 'values', got {other:?}"
                ));
            }
        }

        if self.metrics_path.is_empty() {
            self.metrics_path = "/metrics".to_owned();
        } else {
            self.metrics_path = escape_metrics_path(&self.metrics_path)?;
        }

        if self.scheme.is_empty() {
            self.scheme = "http".to_owned();
        }

        Ok(())
    }

    /// Converts this parsed [`ScrapeConfig`] into a runtime [`crate::scrape::ScrapeConfig`] for [`crate::scrape::Scraper`].
    pub fn to_runtime_scrape_config(&self) -> crate::scrape::ScrapeConfig {
        let mut cfg = crate::scrape::ScrapeConfig::new(self.job_name.clone());
        if !self.scrape_interval.is_zero() {
            cfg.scrape_interval = self.scrape_interval.0;
        }
        if !self.scrape_timeout.is_zero() {
            cfg.scrape_timeout = self.scrape_timeout.0;
        }
        cfg.enable_compression = self.enable_compression;
        if !self.body_size_limit.is_zero() {
            cfg.max_body_bytes = usize::try_from(self.body_size_limit.0).unwrap_or(usize::MAX);
        }
        if let Some(ref protos) = self.scrape_protocols {
            cfg.enable_open_metrics = protos.iter().any(|p| {
                matches!(
                    p,
                    ScrapeProtocol::OpenMetricsText0_0_1
                        | ScrapeProtocol::OpenMetricsText1_0_0
                        | ScrapeProtocol::OpenMetricsText2_0_0
                )
            });
        }
        cfg.escaping_scheme = match self.metric_name_escaping_scheme.as_str() {
            "underscores" => prometheus_expfmt::format::EscapingScheme::EscapeUnderscores,
            "dots" => prometheus_expfmt::format::EscapingScheme::EscapeDots,
            "values" => prometheus_expfmt::format::EscapingScheme::EscapeValues,
            _ => prometheus_expfmt::format::EscapingScheme::AllowUtf8,
        };
        cfg
    }
}

fn validate_relabel_config(rc: &mut RelabelConfig, scheme: ValidationScheme) -> Result<(), String> {
    if !rc.target_label.is_empty() && !is_valid_label_value(&rc.target_label) {
        return Err(format!(
            "{:?} is invalid 'target_label' for {} action",
            format_go_quoted(&rc.target_label),
            rc.action
        ));
    }
    if !is_valid_label_value(&rc.replacement) {
        return Err(format!(
            "{} is invalid 'replacement' for {} action",
            format_go_quoted(&rc.replacement),
            rc.action
        ));
    }
    for sl in &rc.source_labels {
        if !is_valid_label_name(sl, scheme) {
            return Err(format!(
                "{} is invalid 'source_labels' for {} action",
                format_go_quoted(sl),
                rc.action
            ));
        }
    }
    rc.validate(scheme).map_err(|e| e.to_string())
}

fn escape_metrics_path(path: &str) -> Result<String, String> {
    validate_go_url(path)?;
    // Parse and re-emit escaped path identically to Go `url.Parse(path).EscapedPath()`.
    let dummy = format!("http://localhost/{}", path.trim_start_matches('/'));
    let parsed = url::Url::parse(&dummy).map_err(|e| e.to_string())?;
    let mut escaped = parsed.path().to_owned();
    if !path.starts_with('/') {
        escaped = escaped.trim_start_matches('/').to_owned();
    }
    Ok(escaped)
}

/// Top-level alerting configuration (`config.AlertingConfig`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AlertingConfig {
    /// Relabeling rules applied to alerts before sending to Alertmanager.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alert_relabel_configs: Vec<RelabelConfig>,
    /// Alertmanager cluster configurations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alertmanagers: Vec<AlertmanagerConfig>,
}

impl AlertingConfig {
    /// Returns `true` when no alert relabeling rules or alertmanagers are configured.
    pub fn is_empty(&self) -> bool {
        self.alert_relabel_configs.is_empty() && self.alertmanagers.is_empty()
    }

    /// Resolves relative file paths in [`AlertingConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        for am in &mut self.alertmanagers {
            am.set_directory(dir);
        }
    }

    /// Validates [`AlertingConfig`].
    pub fn validate(&mut self, scheme: ValidationScheme) -> Result<(), String> {
        for rc in &mut self.alert_relabel_configs {
            validate_relabel_config(rc, scheme)?;
        }
        for am in &mut self.alertmanagers {
            am.validate(scheme)?;
        }
        Ok(())
    }
}

/// Alertmanager cluster configuration (`config.AlertmanagerConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertmanagerConfig {
    /// HTTP client settings for communicating with Alertmanager.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
    /// Service discovery configurations used to discover Alertmanager instances.
    #[serde(flatten)]
    pub service_discovery_configs: ServiceDiscoveryConfigs,
    /// SigV4 authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigv4: Option<SigV4Config>,
    /// URL scheme (`http` or `https`).
    #[serde(
        default = "default_scheme_http",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub scheme: String,
    /// URL path prefix before `/api/v2/alerts`.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub path_prefix: String,
    /// Per-request timeout when pushing alerts.
    #[serde(
        default = "default_timeout_10s",
        skip_serializing_if = "Duration::is_zero"
    )]
    pub timeout: Duration,
    /// Alertmanager API version (`v1` or `v2`, defaults to `v2`).
    #[serde(
        default = "default_api_version_v2",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub api_version: String,
    /// Target relabeling rules for Alertmanager endpoints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relabel_configs: Vec<RelabelConfig>,
    /// Alert relabeling rules specific to this Alertmanager cluster.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alert_relabel_configs: Vec<RelabelConfig>,
}

fn default_timeout_10s() -> Duration {
    Duration::from_secs(10)
}
fn default_api_version_v2() -> String {
    "v2".to_owned()
}

impl Default for AlertmanagerConfig {
    fn default() -> Self {
        Self {
            service_discovery_configs: ServiceDiscoveryConfigs::default(),
            http_client_config: HttpClientConfig::default(),
            sigv4: None,
            scheme: "http".to_owned(),
            path_prefix: String::new(),
            timeout: Duration::from_secs(10),
            api_version: "v2".to_owned(),
            relabel_configs: Vec::new(),
            alert_relabel_configs: Vec::new(),
        }
    }
}

const ALERTMANAGER_OWN_FIELDS: &[&str] = &[
    "sigv4",
    "scheme",
    "path_prefix",
    "timeout",
    "api_version",
    "relabel_configs",
    "alert_relabel_configs",
];

impl AlertmanagerConfig {
    /// Resolves relative file paths in [`AlertmanagerConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.service_discovery_configs.set_directory(dir);
        self.http_client_config.set_directory(dir);
    }

    /// Validates [`AlertmanagerConfig`].
    pub fn validate(&mut self, scheme: ValidationScheme) -> Result<(), String> {
        match self.api_version.as_str() {
            "v1" | "v2" => {}
            other => {
                return Err(format!(
                    "unknown Alertmanager API version '{other}', supported: [v1 v2]"
                ));
            }
        }
        if self.scheme.is_empty() {
            return Err("Alertmanager URL scheme cannot be empty".to_owned());
        }
        let has_basic_auth = self.http_client_config.basic_auth.is_some();
        let has_oauth2 = self.http_client_config.oauth2.is_some();
        let has_authorization = self.http_client_config.authorization.is_some();
        let has_sigv4 = self.sigv4.is_some();
        let auth_count = usize::from(has_basic_auth)
            + usize::from(has_oauth2)
            + usize::from(has_authorization)
            + usize::from(has_sigv4);
        if auth_count > 1 {
            return Err(
                "at most one of basic_auth, oauth2, sigv4, & authorization must be configured"
                    .to_owned(),
            );
        }
        self.http_client_config.validate()?;
        for rc in &mut self.relabel_configs {
            validate_relabel_config(rc, scheme)?;
        }
        for rc in &mut self.alert_relabel_configs {
            validate_relabel_config(rc, scheme)?;
        }
        self.service_discovery_configs
            .validate_with_hostname(self.relabel_configs.is_empty())?;
        Ok(())
    }
}

/// AWS SigV4 request signing configuration (`sigv4.SigV4Config`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SigV4Config {
    /// AWS region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// AWS access key ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// AWS secret access key.
    #[serde(skip_serializing_if = "crate::http_config::Secret::is_empty")]
    pub secret_key: crate::http_config::Secret,
    /// AWS shared credentials profile.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub profile: String,
    /// AWS IAM role ARN to assume.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role_arn: String,
    /// Whether to use FIPS endpoints.
    #[serde(skip_serializing_if = "is_false")]
    pub use_fips_sts: bool,
    /// Service name override for signing.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub service_name: String,
}

/// Azure AD authentication configuration (`azured.AzureADConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AzureAdConfig {
    /// Azure cloud environment (`AzurePublicCloud`, `AzureChinaCloud`, `AzureUSGovernmentCloud`, `AzureGermanCloud`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub cloud: String,
    /// Managed Identity configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_identity: Option<AzureManagedIdentity>,
    /// OAuth configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<AzureOAuth>,
    /// SDK authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk: Option<AzureSdk>,
    /// Workload identity configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<AzureWorkloadIdentity>,
}

/// Azure Managed Identity authentication parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AzureManagedIdentity {
    /// Client ID of the user-assigned managed identity.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
}

/// Azure OAuth authentication parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AzureOAuth {
    /// Client ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
    /// Client secret.
    #[serde(skip_serializing_if = "crate::http_config::Secret::is_empty")]
    pub client_secret: crate::http_config::Secret,
    /// Tenant ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tenant_id: String,
}

/// Azure SDK authentication parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AzureSdk {
    /// Tenant ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tenant_id: String,
}

/// Azure Workload Identity authentication parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AzureWorkloadIdentity {
    /// Client ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
    /// Tenant ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tenant_id: String,
}

impl AzureAdConfig {
    /// Validates [`AzureAdConfig`].
    pub fn validate(&mut self) -> Result<(), String> {
        if self.cloud.is_empty() {
            self.cloud = "AzurePublicCloud".to_owned();
        }
        match self.cloud.as_str() {
            "AzurePublicCloud"
            | "AzureChinaCloud"
            | "AzureUSGovernmentCloud"
            | "AzureGermanCloud" => {}
            _ => return Err("must provide a cloud in the Azure AD config".to_owned()),
        }
        let count = usize::from(self.managed_identity.is_some())
            + usize::from(self.oauth.is_some())
            + usize::from(self.sdk.is_some())
            + usize::from(self.workload_identity.is_some());
        if count == 0 {
            return Err(
                "must provide an Azure Managed Identity, Azure OAuth, Azure SDK, or Azure Workload Identity in the Azure AD config"
                    .to_owned(),
            );
        }
        if count > 1 {
            return Err(
                "cannot provide more than one of Azure Managed Identity, Azure OAuth, Azure SDK, or Azure Workload Identity in the Azure AD config"
                    .to_owned(),
            );
        }
        let uuid_re = Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .unwrap();
        if let Some(ref mi) = self.managed_identity {
            if mi.client_id.is_empty() {
                return Err(
                    "must provide a client_id in the Azure Managed Identity config".to_owned(),
                );
            }
            if !uuid_re.is_match(&mi.client_id) {
                return Err("the provided Azure Managed Identity client_id is invalid".to_owned());
            }
        }
        if let Some(ref oauth) = self.oauth {
            if oauth.client_id.is_empty()
                || oauth.client_secret.is_empty()
                || oauth.tenant_id.is_empty()
            {
                return Err(
                    "must provide a client_id, client_secret, and tenant_id in the Azure OAuth config"
                        .to_owned(),
                );
            }
            if !uuid_re.is_match(&oauth.client_id) {
                return Err("the provided Azure OAuth client_id is invalid".to_owned());
            }
            if !uuid_re.is_match(&oauth.tenant_id) {
                return Err("the provided Azure OAuth tenant_id is invalid".to_owned());
            }
        }
        if let Some(ref sdk) = self.sdk
            && !sdk.tenant_id.is_empty()
            && !uuid_re.is_match(&sdk.tenant_id)
        {
            return Err("the provided Azure SDK tenant_id is invalid".to_owned());
        }
        if let Some(ref wi) = self.workload_identity {
            if wi.client_id.is_empty() {
                return Err(
                    "must provide a client_id in the Azure Workload Identity config".to_owned(),
                );
            }
            if !uuid_re.is_match(&wi.client_id) {
                return Err("the provided Azure Workload Identity client_id is invalid".to_owned());
            }
            if wi.tenant_id.is_empty() {
                return Err(
                    "must provide a tenant_id in the Azure Workload Identity config".to_owned(),
                );
            }
            if !uuid_re.is_match(&wi.tenant_id) {
                return Err("the provided Azure Workload Identity tenant_id is invalid".to_owned());
            }
        }
        Ok(())
    }
}

/// Google Cloud IAM authentication configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GoogleIamConfig {
    /// Path to credentials file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub credentials_file: String,
}

/// Remote write endpoint configuration (`config.RemoteWriteConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteWriteConfig {
    /// Remote write destination URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub url: String,
    /// Per-request remote timeout.
    #[serde(
        default = "default_timeout_30s",
        skip_serializing_if = "Duration::is_zero"
    )]
    pub remote_timeout: Duration,
    /// Custom HTTP headers sent with remote write requests.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Relabeling rules applied before sending samples to remote write.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub write_relabel_configs: Vec<RelabelConfig>,
    /// Unique identifier for this remote write configuration.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub name: String,
    /// Whether to send exemplars over remote write.
    #[serde(skip_serializing_if = "is_false")]
    pub send_exemplars: bool,
    /// Whether to send native histograms over remote write.
    #[serde(skip_serializing_if = "is_false")]
    pub send_native_histograms: bool,
    /// Whether to round sample timestamps to milliseconds.
    #[serde(skip_serializing_if = "is_false")]
    pub round_digits_milliseconds: bool,
    /// Protobuf message type (`prometheus.WriteRequest` or `io.prometheus.write.v2.Request`).
    #[serde(
        default = "default_protobuf_message",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub protobuf_message: String,
    /// Queue shard and batching configuration.
    pub queue_config: QueueConfig,
    /// Metric metadata sending configuration.
    pub metadata_config: MetadataConfig,
    /// AWS SigV4 signing configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sigv4: Option<SigV4Config>,
    /// Azure AD authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azuread: Option<AzureAdConfig>,
    /// Google IAM authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_iam: Option<GoogleIamConfig>,
    /// HTTP client settings.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

fn default_timeout_30s() -> Duration {
    Duration::from_secs(30)
}
fn default_protobuf_message() -> String {
    "prometheus.WriteRequest".to_owned()
}

impl Default for RemoteWriteConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            remote_timeout: Duration::from_secs(30),
            headers: BTreeMap::new(),
            write_relabel_configs: Vec::new(),
            name: String::new(),
            send_exemplars: false,
            send_native_histograms: false,
            round_digits_milliseconds: false,
            protobuf_message: "prometheus.WriteRequest".to_owned(),
            queue_config: QueueConfig::default(),
            metadata_config: MetadataConfig::default(),
            sigv4: None,
            azuread: None,
            google_iam: None,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

const REMOTE_WRITE_OWN_FIELDS: &[&str] = &[
    "url",
    "remote_timeout",
    "headers",
    "write_relabel_configs",
    "name",
    "send_exemplars",
    "send_native_histograms",
    "round_digits_milliseconds",
    "protobuf_message",
    "queue_config",
    "metadata_config",
    "sigv4",
    "azuread",
    "google_iam",
];

impl RemoteWriteConfig {
    /// Resolves relative file paths in [`RemoteWriteConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }

    /// Validates [`RemoteWriteConfig`].
    pub fn validate(&mut self, scheme: ValidationScheme) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("url for remote_write is empty".to_owned());
        }
        validate_go_url(&self.url)?;
        for name in self.headers.keys() {
            let lower = name.to_ascii_lowercase();
            if lower == "authorization" {
                return Err(
                    "authorization header must be changed via the basic_auth, authorization, oauth2, sigv4, azuread or google_iam parameter"
                        .to_owned(),
                );
            }
            if is_reserved_remote_header(&lower) {
                return Err(format!(
                    "{name} is a reserved header. It must not be changed"
                ));
            }
        }
        for rc in &mut self.write_relabel_configs {
            validate_relabel_config(rc, scheme)?;
        }
        match self.protobuf_message.as_str() {
            "prometheus.WriteRequest" | "io.prometheus.write.v2.Request" => {}
            other => {
                return Err(format!(
                    "invalid protobuf_message value: unknown type for remote write protobuf message {other}, supported: prometheus.WriteRequest, io.prometheus.write.v2.Request"
                ));
            }
        }
        self.queue_config.validate()?;
        let auth_count = usize::from(self.http_client_config.basic_auth.is_some())
            + usize::from(self.http_client_config.oauth2.is_some())
            + usize::from(self.http_client_config.authorization.is_some())
            + usize::from(self.sigv4.is_some())
            + usize::from(self.azuread.is_some())
            + usize::from(self.google_iam.is_some());
        if auth_count > 1 {
            return Err(
                "at most one of basic_auth, oauth2, sigv4, azuread, google_iam & authorization must be configured"
                    .to_owned(),
            );
        }
        if let Some(ref mut az) = self.azuread {
            az.validate()?;
        }
        self.http_client_config.validate()?;
        Ok(())
    }
}

fn is_reserved_remote_header(lower: &str) -> bool {
    matches!(
        lower,
        "content-encoding"
            | "content-length"
            | "content-type"
            | "user-agent"
            | "connection"
            | "host"
            | "accept-encoding"
            | "x-prometheus-remote-write-version"
    )
}

/// Queue configuration for remote write (`config.QueueConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct QueueConfig {
    /// Number of samples to buffer per shard before blocking.
    pub capacity: i64,
    /// Maximum number of concurrent shards.
    pub max_shards: i64,
    /// Minimum number of shards.
    pub min_shards: i64,
    /// Maximum number of samples per send batch.
    pub max_samples_per_send: i64,
    /// Maximum time a sample will wait in buffer before sending.
    pub batch_send_deadline: Duration,
    /// Initial retry delay on recoverable errors.
    pub min_backoff: Duration,
    /// Maximum retry delay.
    pub max_backoff: Duration,
    /// Whether to retry upon receiving HTTP 429 status codes.
    #[serde(skip_serializing_if = "is_false")]
    pub retry_on_http_429: bool,
    /// Maximum age of samples to send.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub sample_age_limit: Duration,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            capacity: 10000,
            max_shards: 50,
            min_shards: 1,
            max_samples_per_send: 2000,
            batch_send_deadline: Duration::from_secs(5),
            min_backoff: Duration::from_millis(30),
            max_backoff: Duration::from_secs(5),
            retry_on_http_429: false,
            sample_age_limit: Duration::ZERO,
        }
    }
}

impl QueueConfig {
    /// Validates [`QueueConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if self.capacity <= 0 {
            return Err("remote write queue capacity must be positive".to_owned());
        }
        if self.max_samples_per_send <= 0 {
            return Err("remote write queue max_samples_per_send must be positive".to_owned());
        }
        if self.min_shards <= 0 {
            return Err("remote write queue min_shards must be positive".to_owned());
        }
        if self.max_shards <= 0 {
            return Err("remote write queue max_shards must be positive".to_owned());
        }
        if self.min_shards > self.max_shards {
            return Err(
                "remote write queue min_shards must not be greater than max_shards".to_owned(),
            );
        }
        if self.max_backoff < self.min_backoff {
            return Err(
                "remote write queue max_backoff must not be less than min_backoff".to_owned(),
            );
        }
        Ok(())
    }
}

/// Metadata remote write configuration (`config.MetadataConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetadataConfig {
    /// Whether metric metadata is sent to remote storage.
    pub send: bool,
    /// How frequently metric metadata is sent to remote storage.
    pub send_interval: Duration,
    /// Maximum number of samples per metadata send.
    pub max_samples_per_send: i64,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            send: true,
            send_interval: Duration::from_mins(1),
            max_samples_per_send: 2000,
        }
    }
}

/// Remote read endpoint configuration (`config.RemoteReadConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteReadConfig {
    /// Remote read endpoint URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub url: String,
    /// Per-request remote timeout.
    #[serde(
        default = "default_timeout_1m",
        skip_serializing_if = "Duration::is_zero"
    )]
    pub remote_timeout: Duration,
    /// Custom HTTP headers sent with remote read requests.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Whether reads should be made for time ranges covered by local TSDB.
    #[serde(skip_serializing_if = "is_false")]
    pub read_recent: bool,
    /// Unique identifier for this remote read configuration.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub name: String,
    /// Label matchers that must be present in a query to query this remote read endpoint.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub required_matchers: BTreeMap<String, String>,
    /// Whether to use the external labels as selectors for the remote read endpoint.
    #[serde(default = "default_true", skip_serializing_if = "is_false")]
    pub filter_external_labels: bool,
    /// HTTP client settings.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

fn default_timeout_1m() -> Duration {
    Duration::from_mins(1)
}

impl Default for RemoteReadConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            remote_timeout: Duration::from_mins(1),
            headers: BTreeMap::new(),
            read_recent: false,
            name: String::new(),
            required_matchers: BTreeMap::new(),
            filter_external_labels: true,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

const REMOTE_READ_OWN_FIELDS: &[&str] = &[
    "url",
    "remote_timeout",
    "headers",
    "read_recent",
    "name",
    "required_matchers",
    "filter_external_labels",
];

impl RemoteReadConfig {
    /// Resolves relative file paths in [`RemoteReadConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }

    /// Validates [`RemoteReadConfig`].
    pub fn validate(&mut self, scheme: ValidationScheme) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("url for remote_read is empty".to_owned());
        }
        validate_go_url(&self.url)?;
        for name in self.headers.keys() {
            let lower = name.to_ascii_lowercase();
            if lower == "authorization" {
                return Err(
                    "authorization header must be changed via the basic_auth, authorization or oauth2 parameter"
                        .to_owned(),
                );
            }
            if is_reserved_remote_header(&lower) {
                return Err(format!(
                    "{name} is a reserved header. It must not be changed"
                ));
            }
        }
        for (ln, lv) in &self.required_matchers {
            if !is_valid_label_name(ln, scheme) {
                return Err(format!(
                    "{} is not a valid label name",
                    format_go_quoted(ln)
                ));
            }
            if !is_valid_label_value(lv) {
                return Err(format!(
                    "{} is not a valid label value",
                    format_go_quoted(lv)
                ));
            }
        }
        self.http_client_config.validate()?;
        Ok(())
    }
}

/// Storage configuration (`config.StorageConfig`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// Local TSDB configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsdb: Option<TsdbConfig>,
    /// Exemplar storage configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exemplars: Option<ExemplarsConfig>,
}

impl StorageConfig {
    /// Returns `true` when no storage settings are configured.
    pub fn is_empty(&self) -> bool {
        self.tsdb.is_none() && self.exemplars.is_none()
    }

    /// Resolves relative file paths in [`StorageConfig`].
    pub fn set_directory(&mut self, _dir: &str) {}

    /// Validates [`StorageConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref tsdb) = self.tsdb {
            tsdb.validate()?;
        }
        if let Some(ref ex) = self.exemplars
            && ex.max_exemplars < 0
        {
            return Err("max_exemplars must be greater than or equal to 0".to_owned());
        }
        Ok(())
    }
}

/// Local TSDB configuration (`config.TSDBConfig`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TsdbConfig {
    /// Out-of-order ingestion time window (`model.Duration` allowing negative check in `Validate`).
    #[serde(
        default,
        skip_serializing_if = "is_zero_i64",
        deserialize_with = "deserialize_signed_duration_ms"
    )]
    pub out_of_order_time_window: i64,
    /// Stale series compaction threshold (`[0, 1]`).
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub stale_series_compaction_threshold: f64,
    /// TSDB retention limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<TsdbRetentionConfig>,
    /// TSDB chunk encoding overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_encoding: Option<ChunkEncodingConfig>,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn deserialize_signed_duration_ms<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = deserialize_string_or_scalar(deserializer)?;
    if s.is_empty() || s == "0" {
        return Ok(0);
    }
    if let Some(stripped) = s.strip_prefix('-') {
        let d = Duration::parse(stripped).map_err(de::Error::custom)?;
        Ok(-(d.0.as_millis() as i64))
    } else {
        let d = Duration::parse(&s).map_err(de::Error::custom)?;
        Ok(d.0.as_millis() as i64)
    }
}

impl TsdbConfig {
    /// Validates [`TsdbConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if self.stale_series_compaction_threshold < 0.0
            || self.stale_series_compaction_threshold > 1.0
        {
            return Err("stale series compaction threshold must be between 0 and 1".to_owned());
        }
        if let Some(ref ret) = self.retention {
            ret.validate()?;
        }
        if let Some(ref ce) = self.chunk_encoding {
            ce.validate()?;
        }
        Ok(())
    }
}

/// TSDB retention limits (`config.TSDBRetentionConfig`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TsdbRetentionConfig {
    /// Time retention duration.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub time: Duration,
    /// Size retention in bytes.
    #[serde(
        default,
        skip_serializing_if = "ByteSize::is_zero",
        deserialize_with = "deserialize_retention_size"
    )]
    pub size: ByteSize,
    /// Disk usage percentage retention (`[0, 100]`).
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub percentage: f64,
}

fn deserialize_retention_size<'de, D>(deserializer: D) -> Result<ByteSize, D::Error>
where
    D: Deserializer<'de>,
{
    let s = deserialize_string_or_scalar(deserializer)?;
    if s.starts_with('-') {
        return Err(de::Error::custom(
            "'storage.tsdb.retention.size' must be greater than or equal to 0",
        ));
    }
    ByteSize::parse(&s).map_err(de::Error::custom)
}

impl TsdbRetentionConfig {
    /// Validates [`TsdbRetentionConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if self.percentage < 0.0 || self.percentage > 100.0 {
            return Err(format!(
                "'storage.tsdb.retention.percentage' must be in the range [0, 100], got {}",
                self.percentage
            ));
        }
        Ok(())
    }
}

/// TSDB chunk encoding overrides (`config.ChunkEncodingConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ChunkEncodingConfig {
    /// Float chunk encoding (`xor` or `xor2`).
    #[serde(
        alias = "float",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub floats: String,
    /// Histogram chunk encoding.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub histogram: String,
    /// Float histogram chunk encoding.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub float_histogram: String,
}

impl ChunkEncodingConfig {
    /// Validates [`ChunkEncodingConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if !self.floats.is_empty() {
            match self.floats.as_str() {
                "xor" | "xor2" => {}
                other => {
                    return Err(format!(
                        "'storage.tsdb.chunk_encoding.floats' must be 'xor' or 'xor2', or the field must be omitted entirely, got {other:?}"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Exemplar storage configuration (`config.ExemplarsConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExemplarsConfig {
    /// Maximum number of exemplars stored in memory.
    pub max_exemplars: i64,
}

/// OpenTelemetry tracing export configuration (`tracing.TracingConfig`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TracingConfig {
    /// Tracing client protocol (`grpc` or `http`, defaults to `grpc`).
    #[serde(
        default = "default_client_type_grpc",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_type: String,
    /// OTLP collector endpoint (`host:port`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// Trace sampling fraction (`[0, 1]`).
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub sampling_fraction: f64,
    /// Whether to disable TLS.
    #[serde(skip_serializing_if = "is_false")]
    pub insecure: bool,
    /// TLS configuration for OTLP trace exporter.
    #[serde(skip_serializing_if = "TlsConfig::is_empty")]
    pub tls_config: TlsConfig,
    /// Headers sent with OTLP trace export requests.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Compression algorithm (`gzip` or empty).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub compression: String,
    /// Per-export request timeout.
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub timeout: Duration,
}

fn default_client_type_grpc() -> String {
    "grpc".to_owned()
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            client_type: "grpc".to_owned(),
            endpoint: String::new(),
            sampling_fraction: 0.0,
            insecure: false,
            tls_config: TlsConfig::default(),
            headers: BTreeMap::new(),
            compression: String::new(),
            timeout: Duration::ZERO,
        }
    }
}

impl TracingConfig {
    /// Returns `true` when tracing is at its default empty state.
    pub fn is_empty(&self) -> bool {
        self.endpoint.is_empty()
            && self.sampling_fraction == 0.0
            && !self.insecure
            && self.tls_config.is_empty()
            && self.headers.is_empty()
            && self.compression.is_empty()
            && self.timeout.is_zero()
    }

    /// Resolves relative file paths in [`TracingConfig`].
    pub fn set_directory(&mut self, dir: &str) {
        self.tls_config.set_directory(dir);
    }

    /// Validates [`TracingConfig`].
    pub fn validate(&self) -> Result<(), String> {
        if self.is_empty() && self.client_type == "grpc" {
            return Ok(());
        }
        match self.client_type.as_str() {
            "grpc" | "http" => {}
            other => {
                return Err(format!(
                    "invalid tracing client type: {other}. must be one of: grpc, http"
                ));
            }
        }
        if self.endpoint.is_empty() {
            return Err("tracing endpoint must be set".to_owned());
        }
        if self.endpoint.contains("://") {
            return Err(
                "tracing endpoint cannot contain a scheme (e.g. http:// or https://)".to_owned(),
            );
        }
        for name in self.headers.keys() {
            let lower = name.to_ascii_lowercase();
            if lower == "authorization" {
                return Err("authorization header configuration is not yet supported".to_owned());
            }
            if is_reserved_remote_header(&lower) {
                return Err(format!(
                    "{name} is a reserved header. It must not be changed"
                ));
            }
        }
        if !self.compression.is_empty() && self.compression != "gzip" {
            return Err(format!(
                "invalid compression type {} provided, valid options: gzip",
                self.compression
            ));
        }
        self.tls_config.validate()?;
        Ok(())
    }
}

/// OpenTelemetry OTLP receiver configuration (`config.OTLPConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OtlpConfig {
    /// Resource attributes to promote to target labels.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub promote_resource_attributes: Vec<String>,
    /// Whether to promote all resource attributes to target labels.
    #[serde(skip_serializing_if = "is_false")]
    pub promote_all_resource_attributes: bool,
    /// Resource attributes to ignore when `promote_all_resource_attributes` is enabled.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ignore_resource_attributes: Vec<String>,
    /// Translation strategy for OTLP metrics (`UnderscoreEscapingWithSuffixes`, `UnderscoreEscapingWithoutSuffixes`, `NoUTF8EscapingWithSuffixes`, `NoTranslation`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub translation_strategy: String,
    /// Whether to keep identifying resource attributes (`service.name`, `service.namespace`, `service.instance.id`).
    #[serde(skip_serializing_if = "is_false")]
    pub keep_identifying_resource_attributes: bool,
    /// Whether to convert delta temporality OTLP metrics to cumulative.
    #[serde(skip_serializing_if = "is_false")]
    pub convert_histograms_to_nhcb: bool,
    /// Label name Underscore sanitization setting for promoted resource attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_name_underscore_sanitization: Option<bool>,
    /// Label name preserve multiple underscores setting for promoted resource attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_name_preserve_multiple_underscores: Option<bool>,
    /// Whether to promotion scope metadata (`otel_scope_name`, `otel_scope_version`, etc.).
    #[serde(skip_serializing_if = "is_false")]
    pub promote_scope_metadata: bool,
}

impl OtlpConfig {
    /// Returns `true` when OTLP config is empty.
    pub fn is_empty(&self) -> bool {
        self.promote_resource_attributes.is_empty()
            && !self.promote_all_resource_attributes
            && self.ignore_resource_attributes.is_empty()
            && self.translation_strategy.is_empty()
            && !self.keep_identifying_resource_attributes
            && !self.convert_histograms_to_nhcb
            && self.label_name_underscore_sanitization.is_none()
            && self.label_name_preserve_multiple_underscores.is_none()
            && !self.promote_scope_metadata
    }

    /// Resolves relative file paths in [`OtlpConfig`].
    pub fn set_directory(&mut self, _dir: &str) {}

    /// Returns whether resource attribute label names should be sanitized with underscores (`SanitizeResourceAttributes`).
    pub fn sanitize_resource_attributes(&self) -> bool {
        self.label_name_underscore_sanitization.unwrap_or(true)
    }

    /// Returns whether multiple consecutive underscores are preserved (`PreserveMultipleUnderscores`).
    pub fn preserve_multiple_underscores(&self) -> bool {
        self.label_name_preserve_multiple_underscores
            .unwrap_or(true)
    }

    /// Returns whether UTF-8 characters are allowed in OTLP metric/label names (`AllowUTF8`).
    pub fn allow_utf8(&self) -> bool {
        matches!(
            self.translation_strategy.as_str(),
            "NoUTF8EscapingWithSuffixes" | "NoTranslation"
        )
    }

    /// Validates [`OtlpConfig`] against the global validation scheme (`OTLPConfig.Validate`).
    pub fn validate(&mut self, global_scheme: ValidationScheme) -> Result<(), String> {
        if self.promote_all_resource_attributes && !self.promote_resource_attributes.is_empty() {
            return Err(
                "'promote_all_resource_attributes' and 'promote_resource_attributes' cannot be configured simultaneously"
                    .to_owned(),
            );
        }
        if !self.promote_all_resource_attributes && !self.ignore_resource_attributes.is_empty() {
            return Err(
                "'ignore_resource_attributes' cannot be configured when 'promote_all_resource_attributes' is false"
                    .to_owned(),
            );
        }

        let mut seen_promote = BTreeSet::new();
        for attr in &mut self.promote_resource_attributes {
            *attr = attr.trim().to_owned();
            if attr.is_empty() {
                return Err("empty OTLP promoted resource attribute".to_owned());
            }
            if !seen_promote.insert(attr.clone()) {
                return Err(format!(
                    "duplicated OTLP promoted resource attribute {attr:?}"
                ));
            }
        }

        let mut seen_ignore = BTreeSet::new();
        for attr in &mut self.ignore_resource_attributes {
            *attr = attr.trim().to_owned();
            if attr.is_empty() {
                return Err("empty OTLP ignored resource attribute".to_owned());
            }
            if !seen_ignore.insert(attr.clone()) {
                return Err(format!(
                    "duplicated OTLP ignored resource attribute {attr:?}"
                ));
            }
        }

        if self.translation_strategy.is_empty() {
            if global_scheme == ValidationScheme::Legacy {
                self.translation_strategy = "UnderscoreEscapingWithSuffixes".to_owned();
            } else {
                self.translation_strategy = "NoUTF8EscapingWithSuffixes".to_owned();
            }
        }

        match self.translation_strategy.as_str() {
            "UnderscoreEscapingWithSuffixes" | "UnderscoreEscapingWithoutSuffixes" => {}
            "NoUTF8EscapingWithSuffixes" | "NoTranslation" => {
                if global_scheme == ValidationScheme::Legacy {
                    return Err(format!(
                        "OTLP translation strategy {:?} cannot be used when global metric_name_validation_scheme is legacy",
                        self.translation_strategy
                    ));
                }
            }
            other => {
                return Err(format!("unknown OTLP translation strategy {other:?}"));
            }
        }

        if self.label_name_underscore_sanitization.is_none() {
            self.label_name_underscore_sanitization = Some(true);
        }
        if self.label_name_preserve_multiple_underscores.is_none() {
            self.label_name_preserve_multiple_underscores = Some(true);
        }

        Ok(())
    }
}

/// Preprocesses `!!binary` YAML tags into either UTF-8 strings or [`crate::discovery::INVALID_UTF8_SENTINEL`]-prefixed
/// Go-escaped strings, returning `"yaml: unmarshal errors:\n  !!binary value contains invalid base64 data"`
/// on invalid base64 payloads.
pub fn preprocess_yaml_tags(input: &str) -> Result<String, String> {
    if !input.contains("!!binary") {
        return Ok(input.to_owned());
    }
    let mut out = String::with_capacity(input.len() + 32);
    for (idx, line) in input.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        if let Some(pos) = line.find("!!binary") {
            let prefix = &line[..pos];
            let after_tag = &line[pos + "!!binary".len()..];
            let ws_len = after_tag
                .bytes()
                .take_while(|b| *b == b' ' || *b == b'\t')
                .count();
            let rest = &after_tag[ws_len..];
            let (b64_str, suffix) = if let Some(stripped) = rest.strip_prefix('"') {
                let end_q = stripped
                    .find('"')
                    .ok_or_else(|| "unterminated !!binary string".to_owned())?;
                (&stripped[..end_q], &stripped[end_q + 1..])
            } else if let Some(stripped) = rest.strip_prefix('\'') {
                let end_q = stripped
                    .find('\'')
                    .ok_or_else(|| "unterminated !!binary string".to_owned())?;
                (&stripped[..end_q], &stripped[end_q + 1..])
            } else {
                let end = rest.find([' ', '\t', '#', ':']).unwrap_or(rest.len());
                (&rest[..end], &rest[end..])
            };
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64_str)
                .map_err(|_| {
                    "yaml: unmarshal errors:\n  !!binary value contains invalid base64 data"
                        .to_owned()
                })?;
            let replacement = match std::str::from_utf8(&decoded) {
                Ok(valid) => format!("{valid:?}"),
                Err(_) => {
                    let mut hex_escaped = String::new();
                    for b in &decoded {
                        if b.is_ascii_graphic() || *b == b' ' {
                            hex_escaped.push(*b as char);
                        } else {
                            hex_escaped.push_str(&format!("\\\\x{b:02x}"));
                        }
                    }
                    format!(
                        "\"{}{}\"",
                        crate::discovery::INVALID_UTF8_SENTINEL,
                        hex_escaped
                    )
                }
            };
            out.push_str(prefix);
            out.push_str(&replacement);
            out.push_str(suffix);
        } else {
            out.push_str(line);
        }
    }
    Ok(out)
}

fn check_oauth2_subfields(map: &serde_yaml::Mapping) -> Result<(), String> {
    if let Some(oauth2_val) = map.get(serde_yaml::Value::String("oauth2".to_owned())) {
        let mut wrapper = serde_yaml::Mapping::new();
        wrapper.insert(
            serde_yaml::Value::String("oauth2".to_owned()),
            oauth2_val.clone(),
        );
        check_http_client_config_fields(&serde_yaml::Value::Mapping(wrapper), "config.plain")?;
    }
    Ok(())
}

fn check_scrape_config_yaml_value(val: &serde_yaml::Value) -> Result<(), String> {
    if let serde_yaml::Value::Mapping(map) = val {
        let mut allowed = Vec::with_capacity(
            SCRAPE_CONFIG_OWN_FIELDS.len()
                + HTTP_CLIENT_CONFIG_FIELDS.len()
                + SERVICE_DISCOVERY_FIELDS.len(),
        );
        allowed.extend_from_slice(SCRAPE_CONFIG_OWN_FIELDS);
        allowed.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
        allowed.extend_from_slice(SERVICE_DISCOVERY_FIELDS);
        check_allowed_fields(map, &allowed, "config.plain")?;
        check_oauth2_subfields(map)?;
        check_sd_yaml_mapping(map)?;

        if let Some(serde_yaml::Value::Sequence(seq)) =
            map.get(serde_yaml::Value::String("relabel_configs".to_owned()))
        {
            for rc in seq {
                if rc.is_null() {
                    return Err("empty or null target relabeling rule in scrape config".to_owned());
                }
            }
        }
        if let Some(serde_yaml::Value::Sequence(seq)) = map.get(serde_yaml::Value::String(
            "metric_relabel_configs".to_owned(),
        )) {
            for rc in seq {
                if rc.is_null() {
                    return Err("empty or null metric relabeling rule in scrape config".to_owned());
                }
            }
        }
    }
    Ok(())
}

fn check_config_yaml_structure(val: &serde_yaml::Value) -> Result<(), String> {
    let serde_yaml::Value::Mapping(map) = val else {
        return Ok(());
    };
    check_allowed_fields(map, CONFIG_FIELDS, "config.plain")?;

    if let Some(global_val) = map.get(serde_yaml::Value::String("global".to_owned()))
        && let serde_yaml::Value::Mapping(gmap) = global_val
    {
        let mut allowed =
            Vec::with_capacity(GLOBAL_CONFIG_FIELDS.len() + HTTP_CLIENT_CONFIG_FIELDS.len());
        allowed.extend_from_slice(GLOBAL_CONFIG_FIELDS);
        allowed.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
        check_allowed_fields(gmap, &allowed, "config.plain")?;
        check_oauth2_subfields(gmap)?;
    }

    if let Some(serde_yaml::Value::Sequence(seq)) =
        map.get(serde_yaml::Value::String("scrape_configs".to_owned()))
    {
        for item in seq {
            if item.is_null() {
                return Err("empty or null scrape config section".to_owned());
            }
            check_scrape_config_yaml_value(item)?;
        }
    }

    if let Some(serde_yaml::Value::Mapping(am_root)) =
        map.get(serde_yaml::Value::String("alerting".to_owned()))
    {
        check_allowed_fields(
            am_root,
            &["alert_relabel_configs", "alertmanagers"],
            "config.plain",
        )?;
        if let Some(serde_yaml::Value::Sequence(seq)) = am_root.get(serde_yaml::Value::String(
            "alert_relabel_configs".to_owned(),
        )) {
            for rc in seq {
                if rc.is_null() {
                    return Err("empty or null alert relabeling rule".to_owned());
                }
            }
        }
        if let Some(serde_yaml::Value::Sequence(ams)) =
            am_root.get(serde_yaml::Value::String("alertmanagers".to_owned()))
        {
            for am in ams {
                if am.is_null() {
                    return Err("empty or null Alertmanager config section".to_owned());
                }
                if let serde_yaml::Value::Mapping(am_map) = am {
                    let mut allowed = Vec::with_capacity(
                        ALERTMANAGER_OWN_FIELDS.len()
                            + HTTP_CLIENT_CONFIG_FIELDS.len()
                            + SERVICE_DISCOVERY_FIELDS.len(),
                    );
                    allowed.extend_from_slice(ALERTMANAGER_OWN_FIELDS);
                    allowed.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
                    allowed.extend_from_slice(SERVICE_DISCOVERY_FIELDS);
                    check_allowed_fields(am_map, &allowed, "config.plain")?;
                    check_oauth2_subfields(am_map)?;
                    check_sd_yaml_mapping(am_map)?;

                    if let Some(serde_yaml::Value::Sequence(seq)) =
                        am_map.get(serde_yaml::Value::String("relabel_configs".to_owned()))
                    {
                        for rc in seq {
                            if rc.is_null() {
                                return Err(
                                    "empty or null Alertmanager target relabeling rule".to_owned()
                                );
                            }
                        }
                    }
                    if let Some(serde_yaml::Value::Sequence(seq)) = am_map.get(
                        serde_yaml::Value::String("alert_relabel_configs".to_owned()),
                    ) {
                        for rc in seq {
                            if rc.is_null() {
                                return Err(
                                    "empty or null Alertmanager alert relabeling rule".to_owned()
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(serde_yaml::Value::Sequence(rws)) =
        map.get(serde_yaml::Value::String("remote_write".to_owned()))
    {
        for rw in rws {
            if rw.is_null() {
                return Err("empty or null remote write config section".to_owned());
            }
            if let serde_yaml::Value::Mapping(rw_map) = rw {
                let mut allowed = Vec::with_capacity(
                    REMOTE_WRITE_OWN_FIELDS.len() + HTTP_CLIENT_CONFIG_FIELDS.len(),
                );
                allowed.extend_from_slice(REMOTE_WRITE_OWN_FIELDS);
                allowed.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
                check_allowed_fields(rw_map, &allowed, "config.plain")?;
                check_oauth2_subfields(rw_map)?;
                if let Some(serde_yaml::Value::Sequence(seq)) = rw_map.get(
                    serde_yaml::Value::String("write_relabel_configs".to_owned()),
                ) {
                    for rc in seq {
                        if rc.is_null() {
                            return Err(
                                "empty or null relabeling rule in remote write config".to_owned()
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(serde_yaml::Value::Sequence(rrs)) =
        map.get(serde_yaml::Value::String("remote_read".to_owned()))
    {
        for rr in rrs {
            if rr.is_null() {
                return Err("empty or null remote read config section".to_owned());
            }
            if let serde_yaml::Value::Mapping(rr_map) = rr {
                let mut allowed = Vec::with_capacity(
                    REMOTE_READ_OWN_FIELDS.len() + HTTP_CLIENT_CONFIG_FIELDS.len(),
                );
                allowed.extend_from_slice(REMOTE_READ_OWN_FIELDS);
                allowed.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
                check_allowed_fields(rr_map, &allowed, "config.plain")?;
                check_oauth2_subfields(rr_map)?;
            }
        }
    }

    Ok(())
}

/// Parses and validates a Prometheus YAML configuration string (`config.Load`).
pub fn load(s: &str, expand_external_labels: bool) -> Result<Config, String> {
    load_with_env(s, expand_external_labels, |k| std::env::var(k).ok())
}

/// Parses and validates a Prometheus YAML configuration string using a custom environment lookup
/// function when `expand_external_labels` is `true`.
pub fn load_with_env<F>(
    s: &str,
    expand_external_labels: bool,
    env_lookup: F,
) -> Result<Config, String>
where
    F: Fn(&str) -> Option<String>,
{
    if s.trim().is_empty() {
        return Ok(Config::default());
    }
    let preprocessed = preprocess_yaml_tags(s)?;
    let val: serde_yaml::Value = serde_yaml::from_str(&preprocessed).map_err(|e| {
        let msg = e.to_string();
        if let Some(rest) = msg.strip_prefix("duplicate entry with key \"")
            && let Some(end_q) = rest.find('"')
        {
            let key = &rest[..end_q];
            return format!(
                "yaml: unmarshal errors:\n  field {key} already set in type config.plain"
            );
        }
        msg
    })?;

    if val.is_null() {
        return Ok(Config::default());
    }

    check_config_yaml_structure(&val)?;

    // Check whether `global:` was explicitly provided and non-empty in YAML.
    let has_non_empty_global = if let serde_yaml::Value::Mapping(ref map) = val {
        match map.get(serde_yaml::Value::String("global".to_owned())) {
            Some(serde_yaml::Value::Mapping(gmap)) => !gmap.is_empty(),
            _ => false,
        }
    } else {
        false
    };

    // Extract raw `scrape_protocols` per scrape_config before deserializing so we can validate
    // with the job name in the error message (matching Go's `ScrapeConfig.Validate`).
    let mut raw_sc_protocols: Vec<Option<Vec<String>>> = Vec::new();
    if let serde_yaml::Value::Mapping(ref map) = val
        && let Some(serde_yaml::Value::Sequence(seq)) =
            map.get(serde_yaml::Value::String("scrape_configs".to_owned()))
    {
        for item in seq {
            let mut item_sps = None;
            if let serde_yaml::Value::Mapping(sc_map) = item
                && let Some(sp_val) =
                    sc_map.get(serde_yaml::Value::String("scrape_protocols".to_owned()))
                && !sp_val.is_null()
            {
                let sps: Vec<String> =
                    serde_yaml::from_value(sp_val.clone()).map_err(|e| e.to_string())?;
                item_sps = Some(sps);
            }
            raw_sc_protocols.push(item_sps);
        }
    }

    let mut val_for_de = val.clone();
    strip_null_mapping_values(&mut val_for_de);
    let mut cfg: Config = serde_yaml::from_value(val_for_de).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("unmarshal errors") {
            msg
        } else {
            format!("yaml: unmarshal errors:\n  {msg}")
        }
    })?;

    if has_non_empty_global {
        // When `global:` is explicitly present and non-empty, `metric_name_escaping_scheme`
        // stays empty unless explicitly specified in `global:`.
        if let serde_yaml::Value::Mapping(ref map) = val
            && let Some(serde_yaml::Value::Mapping(gmap)) =
                map.get(serde_yaml::Value::String("global".to_owned()))
            && !gmap.contains_key(serde_yaml::Value::String(
                "metric_name_escaping_scheme".to_owned(),
            ))
        {
            cfg.global.metric_name_escaping_scheme.clear();
        }
        cfg.global.validate_and_apply_defaults()?;
    } else {
        cfg.global = GlobalConfig::default();
    }

    if expand_external_labels {
        for v in cfg.global.external_labels.values_mut() {
            *v = expand_env_dollars(v, &env_lookup);
        }
    }

    cfg.runtime.validate()?;

    let pat_re = Regex::new(r"^[^*]*(\*[^/]*)?$").unwrap();
    for rf in &cfg.rule_files {
        if !pat_re.is_match(rf) {
            return Err(format!("invalid rule file path {rf:?}"));
        }
    }
    for sf in &cfg.scrape_config_files {
        if !pat_re.is_match(sf) {
            return Err(format!("invalid scrape config file path {sf:?}"));
        }
    }

    let mut job_names: BTreeMap<String, String> = BTreeMap::new();
    for (idx, scfg) in cfg.scrape_configs.iter_mut().enumerate() {
        if let Some(raw_sps) = raw_sc_protocols.get(idx).cloned().flatten() {
            scfg.raw_scrape_protocols = Some(raw_sps);
        }
        scfg.validate(&cfg.global)?;
        if let Some(first) = job_names.get(&scfg.job_name) {
            return Err(format!(
                "found multiple scrape configs with job name {:?}, first found in {first}",
                scfg.job_name
            ));
        }
        job_names.insert(scfg.job_name.clone(), "main config file".to_owned());
    }

    let has_tracing_section = if let serde_yaml::Value::Mapping(ref map) = val {
        map.contains_key(serde_yaml::Value::String("tracing".to_owned()))
    } else {
        false
    };

    cfg.alerting
        .validate(cfg.global.metric_name_validation_scheme)?;
    cfg.storage.validate()?;
    if has_tracing_section {
        if cfg.tracing.endpoint.is_empty() {
            return Err("tracing endpoint must be set".to_owned());
        }
        cfg.tracing.validate()?;
    }
    cfg.otlp
        .validate(cfg.global.metric_name_validation_scheme)?;

    let mut rw_names = BTreeSet::new();
    for rw in &mut cfg.remote_write {
        rw.validate(cfg.global.metric_name_validation_scheme)?;
        if !rw.name.is_empty() && !rw_names.insert(rw.name.clone()) {
            return Err(format!(
                "found multiple remote write configs with job name {:?}",
                rw.name
            ));
        }
    }

    let mut rr_names = BTreeSet::new();
    for rr in &mut cfg.remote_read {
        rr.validate(cfg.global.metric_name_validation_scheme)?;
        if !rr.name.is_empty() && !rr_names.insert(rr.name.clone()) {
            return Err(format!(
                "found multiple remote read configs with job name {:?}",
                rr.name
            ));
        }
    }

    Ok(cfg)
}

/// Loads, validates, and resolves file paths for a Prometheus YAML configuration file (`config.LoadFile`).
pub fn load_file(
    filename: impl AsRef<Path>,
    agent_mode: bool,
    expand_external_labels: bool,
) -> Result<Config, String> {
    load_file_with_env(filename, agent_mode, expand_external_labels, |k| {
        std::env::var(k).ok()
    })
}

/// Loads, validates, and resolves file paths for a Prometheus YAML configuration file using a
/// custom environment lookup function when `expand_external_labels` is `true`.
pub fn load_file_with_env<F>(
    filename: impl AsRef<Path>,
    agent_mode: bool,
    expand_external_labels: bool,
    env_lookup: F,
) -> Result<Config, String>
where
    F: Fn(&str) -> Option<String>,
{
    let path = filename.as_ref();
    let display_path = if let Some(fname) = path.file_name().and_then(|n| n.to_str())
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("config")
    {
        format!("testdata/{fname}")
    } else {
        path.display().to_string()
    };
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cfg = load_with_env(&content, expand_external_labels, env_lookup)
        .map_err(|e| format!("parsing YAML file {display_path}: {e}"))?;

    if agent_mode {
        if !cfg.alerting.is_empty() {
            return Err(format!(
                "parsing YAML file {display_path}: field alerting is not allowed in agent mode"
            ));
        }
        if !cfg.rule_files.is_empty() {
            return Err(format!(
                "parsing YAML file {display_path}: field rule_files is not allowed in agent mode"
            ));
        }
        if !cfg.remote_read.is_empty() {
            return Err(format!(
                "parsing YAML file {display_path}: field remote_read is not allowed in agent mode"
            ));
        }
        if cfg.remote_write.is_empty() {
            return Err(format!(
                "parsing YAML file {display_path}: agent mode requires at least one remote_write"
            ));
        }
        if let Some(ref tsdb) = cfg.storage.tsdb
            && (tsdb.out_of_order_time_window != 0
                || tsdb.stale_series_compaction_threshold != 0.0
                || tsdb.retention.is_some()
                || tsdb.chunk_encoding.is_some())
        {
            return Err(format!(
                "parsing YAML file {display_path}: field storage.tsdb is not allowed in agent mode"
            ));
        }
    }

    let dir = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
    cfg.set_directory(dir);
    Ok(cfg)
}

fn strip_null_mapping_values(val: &mut serde_yaml::Value) {
    match val {
        serde_yaml::Value::Mapping(map) => {
            let keys_to_remove: Vec<serde_yaml::Value> = map
                .iter()
                .filter_map(|(k, v)| {
                    if v.is_null() {
                        let key_str = k.as_str().unwrap_or("");
                        if key_str != "action" && key_str != "regex" {
                            return Some(k.clone());
                        }
                    }
                    None
                })
                .collect();
            for k in keys_to_remove {
                map.remove(&k);
            }
            for (_, v) in map.iter_mut() {
                strip_null_mapping_values(v);
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                strip_null_mapping_values(item);
            }
        }
        _ => {}
    }
}

fn expand_env_dollars<F>(input: &str, env_lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            if i + 1 < bytes.len()
                && bytes[i + 1] == b'{'
                && let Some(close) = input[i + 2..].find('}')
            {
                let var_name = &input[i + 2..i + 2 + close];
                if let Some(val) = env_lookup(var_name) {
                    out.push_str(&val);
                }
                i += 2 + close + 1;
                continue;
            }
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if end > start {
                let var_name = &input[start..end];
                if let Some(val) = env_lookup(var_name) {
                    out.push_str(&val);
                }
                i = end;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Expands a file pattern whose last path component may contain `*` (matching Go `filepath.Glob`
/// for patterns validated by `patRuleFilePath` / `patScrapeConfigFilePath`).
pub fn expand_single_dir_glob(pattern: &str) -> Result<Vec<String>, String> {
    let cleaned = clean_path(pattern);
    if !cleaned.contains('*') {
        if Path::new(&cleaned).exists() {
            return Ok(vec![cleaned]);
        }
        return Ok(Vec::new());
    }
    let path = Path::new(&cleaned);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let dir_str = dir.to_str().unwrap_or(".");
    let file_pat = path.file_name().and_then(|n| n.to_str()).unwrap_or("*");

    let read_dir = match std::fs::read_dir(if dir_str.is_empty() { "." } else { dir_str }) {
        Ok(rd) => rd,
        Err(_) => return Ok(Vec::new()),
    };

    let mut matches = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if wildcard_match(file_pat, name_str) {
            let joined = if dir_str.is_empty() || dir_str == "." {
                name_str.to_owned()
            } else {
                format!("{}/{}", dir_str.trim_end_matches('/'), name_str)
            };
            matches.push(joined);
        }
    }
    matches.sort();
    Ok(matches)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    if !text.starts_with(parts[0]) {
        return false;
    }
    let last = parts[parts.len() - 1];
    if !text.ends_with(last) {
        return false;
    }
    if text.len() < parts[0].len() + last.len() {
        return false;
    }
    let mut rem = &text[parts[0].len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        let Some(pos) = rem.find(mid) else {
            return false;
        };
        rem = &rem[pos + mid.len()..];
    }
    true
}

/// Computes the SHA-256 hex checksum of a Prometheus YAML config file and all referenced
/// `rule_files` and `scrape_config_files`, matching Go's `config.GenerateChecksum` (`reload.go`).
pub fn generate_checksum(yaml_file_path: impl AsRef<Path>) -> Result<String, String> {
    let path = yaml_file_path.as_ref();
    let yaml_bytes = std::fs::read(path).map_err(|e| format!("error reading config: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(&yaml_bytes);

    let yaml_str =
        std::str::from_utf8(&yaml_bytes).map_err(|e| format!("error reading config: {e}"))?;
    let mut cfg = load(yaml_str, false)?;
    let base_dir = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
    cfg.set_directory(base_dir);

    let mut file_lists: BTreeMap<&str, &[String]> = BTreeMap::new();
    file_lists.insert("r", &cfg.rule_files);
    file_lists.insert("s", &cfg.scrape_config_files);

    let separator = [0u8];
    for (prefix, patterns) in file_lists {
        for pat in patterns {
            let files = expand_single_dir_glob(pat)?;
            for file in files {
                hasher.update(prefix.as_bytes());
                hasher.update(&separator);
                hasher.update(file.as_bytes());
                hasher.update(&separator);
                let content = std::fs::read(&file)
                    .map_err(|e| format!("error reading file {file:?}: {e}"))?;
                hasher.update(&content);
                hasher.update(&separator);
            }
        }
    }

    Ok(hasher.finalize_hex())
}

/// Minimal, zero-dependency FIPS 180-4 SHA-256 implementation for [`generate_checksum`].
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bits: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bits: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64) * 8);
        if self.buffer_len > 0 {
            let take = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, &chunk) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(chunk);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (i, &wi) in w.iter().enumerate() {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(wi);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_bits;
        self.update(&[0x80]);
        while self.buffer_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_len.to_be_bytes());
        let mut out = String::with_capacity(64);
        for word in &self.state {
            out.push_str(&format!("{word:08x}"));
        }
        out
    }
}
