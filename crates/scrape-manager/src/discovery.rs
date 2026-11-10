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

//! Prometheus-compatible target discovery configuration and target group types with 1:1 parity
//! with `prometheus/prometheus/discovery`.

pub mod dns;
pub mod kubernetes;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration as StdDuration;

pub use dns::{DnsDiscovery, DnsRecord, DnsRecordType, DnsSdConfig, ResolvConf};
pub use kubernetes::{
    KubernetesAttachMetadataConfig, KubernetesMetadataContext, KubernetesNamespaceDiscovery,
    KubernetesRole, KubernetesSdConfig, KubernetesSelectorConfig, Pod, build_pod_target_group,
    build_pod_target_groups,
};
pub use prometheus_relabel::{ADDRESS_LABEL, LabelSet, ValidationScheme};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::http_config::{
    Duration, HTTP_CLIENT_CONFIG_FIELDS, HttpClientConfig, HttpConfigError, Secret, TlsConfig,
    check_allowed_fields, check_http_client_config_fields, deserialize_string_or_scalar, join_dir,
    validate_go_url,
};

/// Error returned when validating or running target discovery.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Configuration validation failed.
    #[error("{0}")]
    InvalidConfig(String),
    /// I/O or filesystem error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP client or transport error during discovery (with any embedded URL password stripped).
    #[error("HTTP error: {0}")]
    Http(#[source] reqwest::Error),
    /// DNS protocol or lookup error.
    #[error("DNS error: {0}")]
    Dns(String),
    /// JSON payload decoding error.
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<reqwest::Error> for DiscoveryError {
    fn from(mut err: reqwest::Error) -> Self {
        // Strip passwords from `reqwest::Error`'s embedded URL so error strings never leak
        // proxy or target credentials.
        if let Some(url) = err.url_mut()
            && url.password().is_some()
        {
            let _ = url.set_password(None);
        }
        Self::Http(err)
    }
}

impl From<HttpConfigError> for DiscoveryError {
    fn from(err: HttpConfigError) -> Self {
        match err {
            HttpConfigError::InvalidConfig(msg) => Self::InvalidConfig(msg),
            HttpConfigError::Io(e) => Self::Io(e),
            HttpConfigError::Http(e) => Self::Http(e),
        }
    }
}

/// Internal noncharacter prefix used to represent decoded `!!binary` YAML scalars whose raw bytes
/// are not valid UTF-8 so that label name and value validators can format them with Go `%q` escaping.
pub const INVALID_UTF8_SENTINEL: char = '\u{FDD0}';

/// Formats a string using Go `%q` escaping when it carries [`INVALID_UTF8_SENTINEL`].
pub fn format_go_quoted(s: &str) -> String {
    if let Some(escaped) = s.strip_prefix(INVALID_UTF8_SENTINEL) {
        format!("\"{escaped}\"")
    } else {
        format!("{s:?}")
    }
}

/// Returns `true` if `s` is a valid Prometheus label name under `scheme` and valid UTF-8.
pub fn is_valid_label_name(s: &str, scheme: ValidationScheme) -> bool {
    if s.starts_with(INVALID_UTF8_SENTINEL) {
        return false;
    }
    scheme.is_valid_label_name(s)
}

/// Returns `true` if `s` is a valid UTF-8 Prometheus label value.
pub fn is_valid_label_value(s: &str) -> bool {
    !s.starts_with(INVALID_UTF8_SENTINEL)
}

pub(crate) fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_label_set<'de, D>(deserializer: D) -> Result<LabelSet, D::Error>
where
    D: Deserializer<'de>,
{
    let labels = Option::<LabelSet>::deserialize(deserializer)?.unwrap_or_default();
    for (name, val) in &labels {
        if !is_valid_label_name(name, ValidationScheme::Utf8) {
            return Err(serde::de::Error::custom(format!(
                "{} is not a valid label name",
                format_go_quoted(name)
            )));
        }
        if !is_valid_label_value(val) {
            return Err(serde::de::Error::custom(format!(
                "{} is not a valid label value",
                format_go_quoted(val)
            )));
        }
    }
    Ok(labels)
}

/// Static target group configuration matching Prometheus `static_configs` entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    /// List of target `"<host>:<port>"` addresses.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub targets: Vec<String>,
    /// Labels assigned to all targets in the group.
    #[serde(
        default,
        deserialize_with = "deserialize_label_set",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub labels: LabelSet,
}

impl StaticConfig {
    /// Converts this static configuration entry into a [`TargetGroup`] with the given `source`.
    pub fn into_target_group(self, source: impl Into<String>) -> TargetGroup {
        let targets = self
            .targets
            .into_iter()
            .map(|addr| BTreeMap::from([(ADDRESS_LABEL.to_owned(), addr)]))
            .collect();
        TargetGroup {
            targets,
            labels: self.labels,
            source: source.into(),
        }
    }

    /// Validates target addresses and label names/values (`targetgroup.Group.UnmarshalYAML`).
    pub fn validate(&self, check_hostname: bool) -> Result<(), String> {
        for target in &self.targets {
            if target.is_empty() {
                return Err("empty target".to_owned());
            }
            if check_hostname && target.contains('/') {
                return Err(format!("{target:?} is not a valid hostname"));
            }
        }
        for (ln, lv) in &self.labels {
            if !is_valid_label_name(ln, ValidationScheme::Utf8) {
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
        Ok(())
    }
}

/// A group of discovered targets sharing a common label set and discovery source,
/// matching Prometheus `discovery/targetgroup.Group`.
///
/// When serialized or deserialized directly with Serde, `TargetGroup` uses the same
/// `{ "targets": ["host:port", ...], "labels": { ... } }` wire format as Prometheus's
/// `targetgroup.Group`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetGroup {
    /// Discovered target label sets (each containing at least [`ADDRESS_LABEL`]).
    pub targets: Vec<LabelSet>,
    /// Common labels shared across all targets in this group.
    pub labels: LabelSet,
    /// Identifier of the discovery source that produced this target group.
    pub source: String,
}

impl fmt::Display for TargetGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Serialize for TargetGroup {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct TargetGroupWire<'a> {
            targets: Vec<&'a str>,
            #[serde(skip_serializing_if = "BTreeMap::is_empty")]
            labels: &'a LabelSet,
        }

        let targets: Vec<&str> = self
            .targets
            .iter()
            .map(|t| t.get(ADDRESS_LABEL).map_or("", String::as_str))
            .collect();
        let raw = TargetGroupWire {
            targets,
            labels: &self.labels,
        };
        raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TargetGroup {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename = "TargetGroup", deny_unknown_fields)]
        struct TargetGroupWire {
            #[serde(default, deserialize_with = "deserialize_null_default")]
            targets: Vec<String>,
            #[serde(default, deserialize_with = "deserialize_label_set")]
            labels: LabelSet,
        }

        let raw = TargetGroupWire::deserialize(deserializer)?;
        Ok(StaticConfig {
            targets: raw.targets,
            labels: raw.labels,
        }
        .into_target_group(String::new()))
    }
}

impl TargetGroup {
    /// Validates target addresses and label names/values (`targetgroup.Group.UnmarshalYAML`).
    pub fn validate(&self, check_hostname: bool) -> Result<(), String> {
        for target_set in &self.targets {
            let addr = target_set.get(ADDRESS_LABEL).map_or("", String::as_str);
            if addr.is_empty() {
                return Err("empty target".to_owned());
            }
            if check_hostname && addr.contains('/') {
                return Err(format!("{addr:?} is not a valid hostname"));
            }
        }
        for (ln, lv) in &self.labels {
            if !is_valid_label_name(ln, ValidationScheme::Utf8) {
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
        Ok(())
    }

    /// Parses and validates a standalone [`TargetGroup`] from YAML (`yaml.UnmarshalStrict`).
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        let preprocessed = crate::config::preprocess_yaml_tags(s)?;
        let val: serde_yaml::Value =
            serde_yaml::from_str(&preprocessed).map_err(|e| e.to_string())?;
        let tg: Self = serde_yaml::from_value(val).map_err(|e| e.to_string())?;
        tg.validate(false)?;
        Ok(tg)
    }
}

/// Resolves a slice of [`StaticConfig`] entries into [`TargetGroup`]s with sequential
/// `"0"`, `"1"`, ... source identifiers matching Prometheus `discovery.StaticConfig`.
pub fn resolve_static_configs(configs: &[StaticConfig]) -> Vec<TargetGroup> {
    configs
        .iter()
        .enumerate()
        .map(|(idx, cfg)| cfg.clone().into_target_group(idx.to_string()))
        .collect()
}

/// Parses a Prometheus duration string (such as `"30s"`, `"1m"`, `"500ms"`, `"1h30m"`, `"7d"`,
/// `"1w"`, `"1y"`, or `"0"`) into a [`std::time::Duration`], matching `prometheus/common/model.ParseDuration`.
pub fn parse_duration(s: &str) -> Result<StdDuration, DiscoveryError> {
    prometheus_relabel::parse_prometheus_duration(s)
        .map(StdDuration::from_nanos)
        .map_err(DiscoveryError::InvalidConfig)
}

/// Formats a [`std::time::Duration`] as a canonical Prometheus duration string (such as `"30s"` or `"1m30s"`),
/// matching `prometheus/common/model.Duration.String`.
pub fn format_duration(d: StdDuration) -> String {
    let mut ms: u128 = d.as_millis();
    if ms == 0 {
        return "0s".to_owned();
    }

    let mut out = String::new();
    let mut append_unit = |unit: &str, mult: u128, exact: bool| {
        if exact && !ms.is_multiple_of(mult) {
            return;
        }
        let v = ms / mult;
        if v > 0 {
            out.push_str(&v.to_string());
            out.push_str(unit);
            ms -= v * mult;
        }
    };

    append_unit("y", 1000 * 60 * 60 * 24 * 365, true);
    append_unit("w", 1000 * 60 * 60 * 24 * 7, true);
    append_unit("d", 1000 * 60 * 60 * 24, false);
    append_unit("h", 1000 * 60 * 60, false);
    append_unit("m", 1000 * 60, false);
    append_unit("s", 1000, false);
    append_unit("ms", 1, false);

    out
}

pub(crate) mod serde_duration {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::{format_duration, parse_duration};

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format_duration(*duration))
    }

    pub fn deserialize_or<'de, D: Deserializer<'de>>(
        deserializer: D,
        default: Duration,
    ) -> Result<Duration, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            Some(s) => parse_duration(&s).map_err(serde::de::Error::custom),
            None => Ok(default),
        }
    }
}

fn default_port_80() -> i32 {
    80
}
fn default_port_9163() -> i32 {
    9163
}
fn default_version_1() -> i32 {
    1
}
fn default_concurrency_20() -> i32 {
    20
}
fn default_refresh_15s() -> Duration {
    Duration::from_secs(15)
}
fn default_refresh_30s() -> Duration {
    Duration::from_secs(30)
}
fn default_refresh_60s() -> Duration {
    Duration::from_secs(60)
}
fn default_refresh_5m() -> Duration {
    Duration::from_mins(5)
}
fn default_fetch_timeout_2m() -> Duration {
    Duration::from_mins(2)
}
fn default_timeout_10s() -> Duration {
    Duration::from_secs(10)
}
fn default_comma() -> String {
    ",".to_owned()
}
fn default_scheme_http() -> String {
    "http".to_owned()
}
fn default_true() -> bool {
    true
}

/// Tag/metadata filter used in EC2 and Docker service discovery (`aws.Filter` / `moby.Filter`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SdFilter {
    /// Filter key name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub name: String,
    /// Filter values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

/// Unified AWS service discovery configuration (`discovery/aws.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsSdConfig {
    /// AWS service role (`ec2`, `ecs`, `elasticache`, `lightsail`, `msk`, `rds`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// AWS region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Custom AWS API endpoint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// AWS access key ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// AWS secret access key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Shared credentials profile name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub profile: String,
    /// IAM role ARN to assume.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role_arn: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Optional EC2 instance filters.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<SdFilter>,
    /// ECS cluster names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    /// Maximum concurrent ECS API requests (defaults to `20`).
    #[serde(default = "default_concurrency_20")]
    pub request_concurrency: i32,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for AwsSdConfig {
    fn default() -> Self {
        Self {
            role: String::new(),
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: Secret::default(),
            profile: String::new(),
            role_arn: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            filters: Vec::new(),
            clusters: Vec::new(),
            request_concurrency: 20,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl AwsSdConfig {
    /// Validates the AWS SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        match self.role.as_str() {
            "ec2" => {
                for f in &self.filters {
                    if f.values.is_empty() {
                        return Err("EC2 SD configuration filter values cannot be empty".to_owned());
                    }
                }
            }
            "ecs" => {
                if self.request_concurrency <= 0 {
                    return Err(format!(
                        "ecs_sd: request_concurrency must be positive, got {}",
                        self.request_concurrency
                    ));
                }
            }
            "elasticache" | "lightsail" | "msk" | "rds" => {}
            "" => {
                return Err(
                    "role missing (one of: ec2, ecs, elasticache, lightsail, msk, rds)".to_owned(),
                );
            }
            other => return Err(format!("unknown AWS SD role {other:?}")),
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// AWS EC2 service discovery configuration (`discovery/aws.EC2SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ec2SdConfig {
    /// AWS region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Custom EC2 endpoint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// AWS access key ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// AWS secret access key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Shared credentials profile name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub profile: String,
    /// IAM role ARN to assume.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role_arn: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// EC2 tag/attribute filters.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<SdFilter>,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for Ec2SdConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: Secret::default(),
            profile: String::new(),
            role_arn: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            filters: Vec::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl Ec2SdConfig {
    /// Validates the EC2 SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        for f in &self.filters {
            if f.values.is_empty() {
                return Err("EC2 SD configuration filter values cannot be empty".to_owned());
            }
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// AWS ECS service discovery configuration (`discovery/aws.ECSSDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EcsSdConfig {
    /// AWS region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Custom ECS endpoint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// AWS access key ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// AWS secret access key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Shared credentials profile name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub profile: String,
    /// IAM role ARN to assume.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role_arn: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// ECS clusters to discover.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    /// Maximum concurrent ECS API requests (defaults to `20`).
    #[serde(default = "default_concurrency_20")]
    pub request_concurrency: i32,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for EcsSdConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: Secret::default(),
            profile: String::new(),
            role_arn: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            clusters: Vec::new(),
            request_concurrency: 20,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl EcsSdConfig {
    /// Validates the ECS SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.request_concurrency <= 0 {
            return Err(format!(
                "ecs_sd: request_concurrency must be positive, got {}",
                self.request_concurrency
            ));
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Common AWS service discovery configuration used by Lightsail, ElastiCache, MSK, and RDS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsCommonSdConfig {
    /// AWS region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Custom AWS endpoint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// AWS access key ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// AWS secret access key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Shared credentials profile name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub profile: String,
    /// IAM role ARN to assume.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role_arn: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Optional clusters filter (for MSK).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for AwsCommonSdConfig {
    fn default() -> Self {
        Self {
            region: String::new(),
            endpoint: String::new(),
            access_key: String::new(),
            secret_key: Secret::default(),
            profile: String::new(),
            role_arn: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            clusters: Vec::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl AwsCommonSdConfig {
    /// Validates the AWS SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// AWS Lightsail SD configuration (`discovery/aws.LightsailSDConfig`).
pub type LightsailSdConfig = AwsCommonSdConfig;
/// AWS ElastiCache SD configuration (`discovery/aws.ElasticacheSDConfig`).
pub type ElastiCacheSdConfig = AwsCommonSdConfig;
/// AWS MSK SD configuration (`discovery/aws.MSKSDConfig`).
pub type MskSdConfig = AwsCommonSdConfig;
/// AWS RDS SD configuration (`discovery/aws.RDSSDConfig`).
pub type RdsSdConfig = AwsCommonSdConfig;

fn default_azure_env() -> String {
    "AzurePublicCloud".to_owned()
}
fn default_azure_auth() -> String {
    "OAuth".to_owned()
}

/// Azure service discovery configuration (`discovery/azure.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureSdConfig {
    /// Azure cloud environment (defaults to `"AzurePublicCloud"`).
    #[serde(
        default = "default_azure_env",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub environment: String,
    /// Port to scrape metrics from (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Azure subscription ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub subscription_id: String,
    /// Azure tenant ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tenant_id: String,
    /// Azure client ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
    /// Azure client secret.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub client_secret: Secret,
    /// Refresh interval (defaults to `5m`).
    #[serde(default = "default_refresh_5m")]
    pub refresh_interval: Duration,
    /// Authentication method (`OAuth`, `ManagedIdentity`, `SDK`, `WorkloadIdentity`).
    #[serde(
        default = "default_azure_auth",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub authentication_method: String,
    /// Optional resource group filter.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub resource_group: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for AzureSdConfig {
    fn default() -> Self {
        Self {
            environment: default_azure_env(),
            port: 80,
            subscription_id: String::new(),
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: Secret::default(),
            refresh_interval: default_refresh_5m(),
            authentication_method: default_azure_auth(),
            resource_group: String::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl AzureSdConfig {
    /// Validates the Azure SD configuration (`azure.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.environment.is_empty() {
            self.environment = default_azure_env();
        }
        if self.authentication_method.is_empty() {
            self.authentication_method = default_azure_auth();
        }
        if self.subscription_id.is_empty() {
            return Err("azure SD configuration requires a subscription_id".to_owned());
        }
        match self.authentication_method.as_str() {
            "OAuth" => {
                if self.tenant_id.is_empty() {
                    return Err("azure SD configuration requires a tenant_id".to_owned());
                }
                if self.client_id.is_empty() {
                    return Err("azure SD configuration requires a client_id".to_owned());
                }
                if self.client_secret.is_empty() {
                    return Err("azure SD configuration requires a client_secret".to_owned());
                }
            }
            "ManagedIdentity" | "SDK" | "WorkloadIdentity" => {}
            other => {
                return Err(format!(
                    "unknown authentication_type {other:?}. Supported types are \"OAuth\", \"ManagedIdentity\", \"SDK\" or \"WorkloadIdentity\""
                ));
            }
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_consul_server() -> String {
    "localhost:8500".to_owned()
}

/// Consul service discovery configuration (`discovery/consul.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsulSdConfig {
    /// Consul server address (defaults to `"localhost:8500"`).
    #[serde(
        default = "default_consul_server",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server: String,
    /// Consul ACL token.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub token: Secret,
    /// Consul datacenter.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub datacenter: String,
    /// Consul Enterprise namespace.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub namespace: String,
    /// Consul Enterprise admin partition.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub partition: String,
    /// URL path prefix.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub path_prefix: String,
    /// Deprecated basic auth username.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username: String,
    /// Deprecated basic auth password.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub password: Secret,
    /// URL scheme (defaults to `"http"`).
    #[serde(
        default = "default_scheme_http",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub scheme: String,
    /// List of services to discover.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    /// Service tags to filter on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Health check filter expression.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub health_filter: String,
    /// Node metadata key/value filters.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub node_meta: BTreeMap<String, String>,
    /// Separator used when joining tags into `__meta_consul_tags` (defaults to `","`).
    #[serde(
        default = "default_comma",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tag_separator: String,
    /// Whether stale Consul reads are allowed (defaults to `true`).
    #[serde(default = "default_true")]
    pub allow_stale: bool,
    /// Refresh interval (defaults to `30s`).
    #[serde(default = "default_refresh_30s")]
    pub refresh_interval: Duration,
    /// Filter expression.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub filter: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for ConsulSdConfig {
    fn default() -> Self {
        Self {
            server: default_consul_server(),
            token: Secret::default(),
            datacenter: String::new(),
            namespace: String::new(),
            partition: String::new(),
            path_prefix: String::new(),
            username: String::new(),
            password: Secret::default(),
            scheme: default_scheme_http(),
            services: Vec::new(),
            tags: Vec::new(),
            health_filter: String::new(),
            node_meta: BTreeMap::new(),
            tag_separator: default_comma(),
            allow_stale: true,
            refresh_interval: default_refresh_30s(),
            filter: String::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl ConsulSdConfig {
    /// Validates the Consul SD configuration (`consul.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.server.trim().is_empty() {
            return Err("consul SD configuration requires a server address".to_owned());
        }
        if (!self.username.is_empty() || !self.password.is_empty())
            && self.http_client_config.basic_auth.is_some()
        {
            return Err(
                "at most one of consul SD configuration username and password and basic auth can be configured"
                    .to_owned(),
            );
        }
        if !self.token.is_empty()
            && (self.http_client_config.authorization.is_some()
                || self.http_client_config.oauth2.is_some())
        {
            return Err(
                "at most one of consul SD token, authorization, or oauth2 can be configured"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_do_role() -> String {
    "droplets".to_owned()
}

/// DigitalOcean service discovery configuration (`discovery/digitalocean.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DigitalOceanSdConfig {
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// DigitalOcean role (`droplets` or `databases`, defaults to `droplets`).
    #[serde(
        default = "default_do_role",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for DigitalOceanSdConfig {
    fn default() -> Self {
        Self {
            refresh_interval: default_refresh_60s(),
            port: 80,
            role: default_do_role(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl DigitalOceanSdConfig {
    /// Validates the DigitalOcean SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        match self.role.as_str() {
            "droplets" | "databases" => Ok(()),
            "" => Err("role missing (one of: droplets, databases)".to_owned()),
            other => Err(format!("unknown DigitalOcean SD role {other:?}")),
        }
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_localhost() -> String {
    "localhost".to_owned()
}

/// Docker Engine service discovery configuration (`discovery/moby.DockerSDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerSdConfig {
    /// Docker daemon address (e.g. `unix:///var/run/docker.sock` or `http://127.0.0.1:2375`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub host: String,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Filters to limit discovered containers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<SdFilter>,
    /// Host to use when container uses host networking (defaults to `"localhost"`).
    #[serde(
        default = "default_localhost",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub host_networking_host: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Match only the first network if container is attached to multiple networks (defaults to `true`).
    #[serde(default = "default_true")]
    pub match_first_network: bool,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for DockerSdConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 80,
            filters: Vec::new(),
            host_networking_host: default_localhost(),
            refresh_interval: default_refresh_60s(),
            match_first_network: true,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl DockerSdConfig {
    /// Validates the Docker SD configuration (`moby.DockerSDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.host.is_empty() {
            return Err("host missing".to_owned());
        }
        validate_go_url(&self.host)?;
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Docker Swarm service discovery configuration (`discovery/moby.DockerSwarmSDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerSwarmSdConfig {
    /// Docker Swarm manager address.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub host: String,
    /// Swarm role (`services`, `nodes`, or `tasks`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// Default port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Filters to limit discovered resources.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<SdFilter>,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for DockerSwarmSdConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            role: String::new(),
            port: 80,
            filters: Vec::new(),
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl DockerSwarmSdConfig {
    /// Validates the Docker Swarm SD configuration (`moby.DockerSwarmSDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.host.is_empty() {
            return Err("host missing".to_owned());
        }
        validate_go_url(&self.host)?;
        match self.role.as_str() {
            "services" | "nodes" | "tasks" => Ok(()),
            "" => Err("role missing (one of: tasks, services, nodes)".to_owned()),
            other => Err(format!(
                "invalid role {other}, expected tasks, services, or nodes"
            )),
        }
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Netflix Eureka service discovery configuration (`discovery/eureka.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EurekaSdConfig {
    /// Eureka server URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server: String,
    /// Refresh interval (defaults to `30s`).
    #[serde(default = "default_refresh_30s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for EurekaSdConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            refresh_interval: default_refresh_30s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl EurekaSdConfig {
    /// Validates the Eureka SD configuration (`eureka.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.server.is_empty() {
            return Err("eureka_sd: empty or null eureka server".to_owned());
        }
        let Ok(parsed) = url::Url::parse(&self.server) else {
            return Err("eureka_sd: invalid eureka server URL".to_owned());
        };
        if parsed.scheme().is_empty() || parsed.host_str().unwrap_or("").is_empty() {
            return Err("eureka_sd: invalid eureka server URL".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// File-based service discovery configuration (`discovery/file.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileSdConfig {
    /// List of file path globs ending in `.json`, `.yml`, or `.yaml`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Refresh interval (defaults to `5m`).
    #[serde(default = "default_refresh_5m")]
    pub refresh_interval: Duration,
}

impl Default for FileSdConfig {
    fn default() -> Self {
        Self {
            files: Vec::new(),
            refresh_interval: default_refresh_5m(),
        }
    }
}

impl FileSdConfig {
    /// Validates the file SD configuration (`file.SDConfig.UnmarshalYAML`).
    pub fn validate(&self) -> Result<(), String> {
        if self.files.is_empty() {
            return Err(
                "file service discovery config must contain at least one path name".to_owned(),
            );
        }
        let pat = Regex::new(r"^[^*]*(\*[^/]*)?\.(json|yml|yaml|JSON|YML|YAML)$").unwrap();
        for name in &self.files {
            if !pat.is_match(name) {
                return Err(format!(
                    "path name {name:?} is not valid for file discovery"
                ));
            }
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        for f in &mut self.files {
            *f = join_dir(dir, f);
        }
    }
}

/// GCE zone list wrapper (`discovery/gce.ZoneConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GceZoneConfig {
    /// List of GCE zone names.
    pub names: Vec<String>,
}

/// Google Compute Engine service discovery configuration (`discovery/gce.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GceSdConfig {
    /// GCP project ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub project: String,
    /// GCE zones to discover.
    pub zone: GceZoneConfig,
    /// Optional instance filter expression.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub filter: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Tag separator (defaults to `","`).
    #[serde(
        default = "default_comma",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tag_separator: String,
}

impl Default for GceSdConfig {
    fn default() -> Self {
        Self {
            project: String::new(),
            zone: GceZoneConfig::default(),
            filter: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            tag_separator: default_comma(),
        }
    }
}

impl GceSdConfig {
    /// Validates the GCE SD configuration (`gce.SDConfig.UnmarshalYAML`).
    pub fn validate(&self) -> Result<(), String> {
        if self.project.is_empty() {
            return Err("GCE SD configuration requires a project".to_owned());
        }
        if self.zone.names.is_empty() {
            return Err("GCE SD configuration requires a zone".to_owned());
        }
        Ok(())
    }
}

/// Hetzner service discovery configuration (`discovery/hetzner.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HetznerSdConfig {
    /// Hetzner role (`robot` or `hcloud`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Optional label selector.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub label_selector: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for HetznerSdConfig {
    fn default() -> Self {
        Self {
            role: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            label_selector: String::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl HetznerSdConfig {
    /// Validates the Hetzner SD configuration (`hetzner.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        match self.role.as_str() {
            "robot" | "hcloud" => Ok(()),
            "" => Err("role missing (one of: robot, hcloud)".to_owned()),
            other => Err(format!("unknown role {other:?}")),
        }
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// HTTP-based service discovery configuration (`discovery/http.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpSdConfig {
    /// HTTP SD endpoint URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub url: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for HttpSdConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl HttpSdConfig {
    /// Validates the HTTP SD configuration (`http.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        validate_http_or_https_url(&self.url)
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn validate_http_or_https_url(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("URL is missing".to_owned());
    }
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err("URL scheme must be 'http' or 'https'".to_owned());
    };
    if scheme != "http" && scheme != "https" {
        return Err("URL scheme must be 'http' or 'https'".to_owned());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    if host_port.is_empty() {
        return Err("host is missing in URL".to_owned());
    }
    Ok(())
}

/// IONOS Cloud service discovery configuration (`discovery/ionos.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IonosSdConfig {
    /// IONOS datacenter UUID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub datacenter_id: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for IonosSdConfig {
    fn default() -> Self {
        Self {
            datacenter_id: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl IonosSdConfig {
    /// Validates the IONOS SD configuration (`ionos.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.datacenter_id.is_empty() {
            return Err("datacenter id can't be empty".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

/// Kuma xDS service discovery configuration (`discovery/xds.KumaSDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KumaSdConfig {
    /// Kuma control plane server URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server: String,
    /// Client ID sent to Kuma xDS server.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
    /// Refresh interval (defaults to `15s`).
    #[serde(default = "default_refresh_15s")]
    pub refresh_interval: Duration,
    /// Fetch timeout (defaults to `2m`).
    #[serde(default = "default_fetch_timeout_2m")]
    pub fetch_timeout: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for KumaSdConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            client_id: String::new(),
            refresh_interval: default_refresh_15s(),
            fetch_timeout: default_fetch_timeout_2m(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl KumaSdConfig {
    /// Validates the Kuma SD configuration (`xds.KumaSDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.server.is_empty() {
            return Err("kuma SD server must not be empty: ".to_owned());
        }
        let Ok(parsed) = url::Url::parse(&self.server) else {
            return Err(format!(
                "kuma SD server must not be empty and have a scheme: {}",
                self.server
            ));
        };
        if parsed.scheme().is_empty() || parsed.host_str().unwrap_or("").is_empty() {
            return Err(format!(
                "kuma SD server must not be empty and have a scheme: {}",
                self.server
            ));
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Linode service discovery configuration (`discovery/linode.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinodeSdConfig {
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Tag separator (defaults to `","`).
    #[serde(
        default = "default_comma",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tag_separator: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Optional region filter.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for LinodeSdConfig {
    fn default() -> Self {
        Self {
            port: 80,
            tag_separator: default_comma(),
            refresh_interval: default_refresh_60s(),
            region: String::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl LinodeSdConfig {
    /// Validates the Linode SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Mesos Marathon service discovery configuration (`discovery/marathon.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MarathonSdConfig {
    /// Marathon server URLs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
    /// Refresh interval (defaults to `30s`).
    #[serde(default = "default_refresh_30s")]
    pub refresh_interval: Duration,
    /// Inline Marathon authentication token.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub auth_token: Secret,
    /// Path to Marathon authentication token file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub auth_token_file: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for MarathonSdConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            refresh_interval: default_refresh_30s(),
            auth_token: Secret::default(),
            auth_token_file: String::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl MarathonSdConfig {
    /// Validates the Marathon SD configuration (`marathon.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        if self.servers.is_empty() {
            return Err("marathon_sd: must contain at least one Marathon server".to_owned());
        }
        if !self.auth_token.is_empty() && !self.auth_token_file.is_empty() {
            return Err(
                "marathon_sd: at most one of auth_token & auth_token_file must be configured"
                    .to_owned(),
            );
        }
        if !self.auth_token.is_empty() || !self.auth_token_file.is_empty() {
            if self.http_client_config.basic_auth.is_some() {
                return Err(
                    "marathon_sd: at most one of basic_auth, auth_token & auth_token_file must be configured"
                        .to_owned(),
                );
            }
            if !self.http_client_config.bearer_token.is_empty()
                || !self.http_client_config.bearer_token_file.is_empty()
            {
                return Err(
                    "marathon_sd: at most one of bearer_token, bearer_token_file, auth_token & auth_token_file must be configured"
                        .to_owned(),
                );
            }
            if self.http_client_config.authorization.is_some() {
                return Err(
                    "marathon_sd: at most one of auth_token, auth_token_file & authorization must be configured"
                        .to_owned(),
                );
            }
        }
        self.http_client_config.validate()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
        self.auth_token_file = join_dir(dir, &self.auth_token_file);
    }
}

/// Zookeeper Nerve / Serverset service discovery configuration
/// (`discovery/zookeeper.NerveSDConfig` and `ServersetSDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ZookeeperSdConfig {
    /// Zookeeper server addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
    /// Zookeeper paths to watch (each must start with `'/'`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Zookeeper session timeout (defaults to `10s`).
    #[serde(default = "default_timeout_10s")]
    pub timeout: Duration,
}

impl Default for ZookeeperSdConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            paths: Vec::new(),
            timeout: default_timeout_10s(),
        }
    }
}

impl ZookeeperSdConfig {
    /// Validates the Zookeeper Nerve or Serverset SD configuration.
    pub fn validate(&self, prefix: &str) -> Result<(), String> {
        if self.servers.is_empty() {
            return Err(format!(
                "{prefix} SD config must contain at least one Zookeeper server"
            ));
        }
        if self.paths.is_empty() {
            return Err(format!("{prefix} SD config must contain at least one path"));
        }
        for path in &self.paths {
            if !path.starts_with('/') {
                return Err(format!(
                    "{prefix} SD config paths must begin with '/': {path}"
                ));
            }
        }
        Ok(())
    }
}

fn default_nomad_namespace() -> String {
    "default".to_owned()
}
fn default_nomad_region() -> String {
    "global".to_owned()
}
fn default_nomad_server() -> String {
    "http://localhost:4646".to_owned()
}

/// HashiCorp Nomad service discovery configuration (`discovery/nomad.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NomadSdConfig {
    /// Whether stale reads are allowed (defaults to `true`).
    #[serde(default = "default_true")]
    pub allow_stale: bool,
    /// Nomad namespace (defaults to `"default"`).
    #[serde(
        default = "default_nomad_namespace",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub namespace: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Nomad region (defaults to `"global"`).
    #[serde(
        default = "default_nomad_region",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Nomad server URL (defaults to `"http://localhost:4646"`).
    #[serde(
        default = "default_nomad_server",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server: String,
    /// Tag separator (defaults to `","`).
    #[serde(
        default = "default_comma",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tag_separator: String,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for NomadSdConfig {
    fn default() -> Self {
        Self {
            allow_stale: true,
            namespace: default_nomad_namespace(),
            refresh_interval: default_refresh_60s(),
            region: default_nomad_region(),
            server: default_nomad_server(),
            tag_separator: default_comma(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl NomadSdConfig {
    /// Validates the Nomad SD configuration (`nomad.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.server.trim().is_empty() {
            return Err("nomad SD configuration requires a server address".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_oci_auth() -> String {
    "api_key".to_owned()
}

/// Oracle Cloud Infrastructure (OCI) service discovery configuration (`discovery/oci.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OciSdConfig {
    /// Authentication method (`api_key` or `instance_principal`, defaults to `api_key`).
    #[serde(
        default = "default_oci_auth",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub auth: String,
    /// OCI region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Tenancy OCID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub tenancy: String,
    /// User OCID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub user: String,
    /// API key fingerprint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub fingerprint: String,
    /// Private key PEM file path.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub key_file: String,
    /// Inline private key passphrase.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub key_passphrase: Secret,
    /// Path to private key passphrase file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub key_passphrase_file: String,
    /// Compartment OCIDs to discover.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compartments: Vec<String>,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for OciSdConfig {
    fn default() -> Self {
        Self {
            auth: default_oci_auth(),
            region: String::new(),
            tenancy: String::new(),
            user: String::new(),
            fingerprint: String::new(),
            key_file: String::new(),
            key_passphrase: Secret::default(),
            key_passphrase_file: String::new(),
            compartments: Vec::new(),
            port: 80,
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl OciSdConfig {
    /// Validates the OCI SD configuration (`oci.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.auth.is_empty() {
            self.auth = default_oci_auth();
        }
        if self.region.is_empty() {
            return Err("oci_sd: region is required".to_owned());
        }
        match self.auth.as_str() {
            "api_key" => {
                if self.tenancy.is_empty() {
                    return Err("oci_sd: tenancy is required for api_key auth".to_owned());
                }
                if self.user.is_empty() {
                    return Err("oci_sd: user is required for api_key auth".to_owned());
                }
                if self.fingerprint.is_empty() {
                    return Err("oci_sd: fingerprint is required for api_key auth".to_owned());
                }
                if self.key_file.is_empty() {
                    return Err("oci_sd: key_file is required for api_key auth".to_owned());
                }
                if !self.key_passphrase.is_empty() && !self.key_passphrase_file.is_empty() {
                    return Err(
                        "oci_sd: at most one of key_passphrase & key_passphrase_file must be configured"
                            .to_owned(),
                    );
                }
                Ok(())
            }
            "instance_principal" => {
                if !self.tenancy.is_empty()
                    || !self.user.is_empty()
                    || !self.fingerprint.is_empty()
                    || !self.key_file.is_empty()
                    || !self.key_passphrase.is_empty()
                    || !self.key_passphrase_file.is_empty()
                {
                    return Err(
                        "oci_sd: tenancy, user, fingerprint, key_file, key_passphrase, and key_passphrase_file must not be set when using instance_principal auth"
                            .to_owned(),
                    );
                }
                Ok(())
            }
            other => Err(format!(
                "oci_sd: unknown auth method {other:?}, expected \"api_key\" or \"instance_principal\""
            )),
        }
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
        self.key_file = join_dir(dir, &self.key_file);
        self.key_passphrase_file = join_dir(dir, &self.key_passphrase_file);
    }
}

fn default_openstack_availability() -> String {
    "public".to_owned()
}

/// OpenStack service discovery configuration (`discovery/openstack.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OpenstackSdConfig {
    /// Keystone identity endpoint URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub identity_endpoint: String,
    /// Username.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username: String,
    /// User ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub userid: String,
    /// Password.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub password: Secret,
    /// Project name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub project_name: String,
    /// Project ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub project_id: String,
    /// Domain name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub domain_name: String,
    /// Domain ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub domain_id: String,
    /// Application credential name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub application_credential_name: String,
    /// Application credential ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub application_credential_id: String,
    /// Application credential secret.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub application_credential_secret: Secret,
    /// OpenStack role (`instance`, `hypervisor`, or `loadbalancer`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// OpenStack region.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Searches all tenants.
    #[serde(skip_serializing_if = "is_false")]
    pub all_tenants: bool,
    /// TLS configuration.
    #[serde(skip_serializing_if = "TlsConfig::is_empty")]
    pub tls_config: TlsConfig,
    /// Endpoint availability (`public`, `internal`, or `admin`; defaults to `public`).
    #[serde(
        default = "default_openstack_availability",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub availability: String,
}

impl Default for OpenstackSdConfig {
    fn default() -> Self {
        Self {
            identity_endpoint: String::new(),
            username: String::new(),
            userid: String::new(),
            password: Secret::default(),
            project_name: String::new(),
            project_id: String::new(),
            domain_name: String::new(),
            domain_id: String::new(),
            application_credential_name: String::new(),
            application_credential_id: String::new(),
            application_credential_secret: Secret::default(),
            role: String::new(),
            region: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            all_tenants: false,
            tls_config: TlsConfig::default(),
            availability: default_openstack_availability(),
        }
    }
}

impl OpenstackSdConfig {
    /// Validates the OpenStack SD configuration (`openstack.SDConfig.UnmarshalYAML`).
    pub fn validate(&self) -> Result<(), String> {
        self.tls_config.validate()?;
        match self.availability.as_str() {
            "public" | "internal" | "admin" => {}
            other => {
                return Err(format!(
                    "unknown availability {other}, must be one of admin, internal or public"
                ));
            }
        }
        match self.role.as_str() {
            "hypervisor" | "instance" | "loadbalancer" => {}
            "" => {
                return Err("role missing (one of: instance, hypervisor, loadbalancer)".to_owned());
            }
            other => return Err(format!("unknown OpenStack SD role {other:?}")),
        }
        if self.region.is_empty() {
            return Err("openstack SD configuration requires a region".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.tls_config.set_directory(dir);
    }
}

fn default_outscale_region() -> String {
    "eu-west-2".to_owned()
}

/// Outscale Cloud service discovery configuration (`discovery/outscale.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutscaleSdConfig {
    /// Outscale API endpoint (defaults to `"https://api.<region>.outscale.com/api/v1"`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// Outscale region (defaults to `"eu-west-2"`).
    #[serde(
        default = "default_outscale_region",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Outscale access key.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// Inline Outscale secret key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Path to Outscale secret key file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub secret_key_file: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for OutscaleSdConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            region: default_outscale_region(),
            access_key: String::new(),
            secret_key: Secret::default(),
            secret_key_file: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl OutscaleSdConfig {
    /// Validates the Outscale SD configuration (`outscale.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.region.is_empty() {
            return Err("outscale SD configuration requires a region".to_owned());
        }
        if self.access_key.is_empty() {
            return Err("outscale SD configuration requires access_key".to_owned());
        }
        if self.secret_key.is_empty() && self.secret_key_file.is_empty() {
            return Err("one of secret_key & secret_key_file must be configured".to_owned());
        }
        if !self.secret_key.is_empty() && !self.secret_key_file.is_empty() {
            return Err(
                "at most one of secret_key & secret_key_file must be configured".to_owned(),
            );
        }
        if self.endpoint.is_empty() {
            self.endpoint = format!("https://api.{}.outscale.com/api/v1", self.region);
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
        self.secret_key_file = join_dir(dir, &self.secret_key_file);
    }
}

fn default_ovh_endpoint() -> String {
    "ovh-eu".to_owned()
}

/// OVHcloud service discovery configuration (`discovery/ovhcloud.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OvhcloudSdConfig {
    /// OVH API endpoint (defaults to `"ovh-eu"`).
    #[serde(
        default = "default_ovh_endpoint",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// OVH application key.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub application_key: String,
    /// OVH application secret.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub application_secret: Secret,
    /// OVH consumer key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub consumer_key: Secret,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// OVHcloud service (`vps` or `dedicated_server`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub service: String,
}

impl Default for OvhcloudSdConfig {
    fn default() -> Self {
        Self {
            endpoint: default_ovh_endpoint(),
            application_key: String::new(),
            application_secret: Secret::default(),
            consumer_key: Secret::default(),
            refresh_interval: default_refresh_60s(),
            service: String::new(),
        }
    }
}

impl OvhcloudSdConfig {
    /// Validates the OVHcloud SD configuration (`ovhcloud.SDConfig.UnmarshalYAML`).
    pub fn validate(&self) -> Result<(), String> {
        if self.endpoint.is_empty() {
            return Err("endpoint can not be empty".to_owned());
        }
        if self.application_key.is_empty() {
            return Err("application key can not be empty".to_owned());
        }
        if self.application_secret.is_empty() {
            return Err("application secret can not be empty".to_owned());
        }
        if self.consumer_key.is_empty() {
            return Err("consumer key can not be empty".to_owned());
        }
        match self.service.as_str() {
            "vps" | "dedicated_server" => Ok(()),
            other => Err(format!("unknown service: {other}")),
        }
    }
}

/// PuppetDB service discovery configuration (`discovery/puppetdb.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PuppetdbSdConfig {
    /// PuppetDB server URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub url: String,
    /// PQL query string.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub query: String,
    /// Whether to include resource parameters as meta labels.
    #[serde(skip_serializing_if = "is_false")]
    pub include_parameters: bool,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for PuppetdbSdConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            query: String::new(),
            include_parameters: false,
            refresh_interval: default_refresh_60s(),
            port: 80,
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl PuppetdbSdConfig {
    /// Validates the PuppetDB SD configuration (`puppetdb.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        validate_http_or_https_url(&self.url)?;
        if self.query.is_empty() {
            return Err("query missing".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_scaleway_api_url() -> String {
    "https://api.scaleway.com".to_owned()
}
fn default_scaleway_zone() -> String {
    "fr-par-1".to_owned()
}

/// Scaleway service discovery configuration (`discovery/scaleway.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScalewaySdConfig {
    /// Scaleway access key.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub access_key: String,
    /// Inline Scaleway secret key.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub secret_key: Secret,
    /// Path to Scaleway secret key file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub secret_key_file: String,
    /// Scaleway project ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub project_id: String,
    /// Scaleway role (`instance` or `baremetal`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Scaleway API URL (defaults to `"https://api.scaleway.com"`).
    #[serde(
        default = "default_scaleway_api_url",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub api_url: String,
    /// Scaleway availability zone (defaults to `"fr-par-1"`).
    #[serde(
        default = "default_scaleway_zone",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub zone: String,
    /// Optional server name filter.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub name_filter: String,
    /// Optional tags filter.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags_filter: Vec<String>,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for ScalewaySdConfig {
    fn default() -> Self {
        Self {
            access_key: String::new(),
            secret_key: Secret::default(),
            secret_key_file: String::new(),
            project_id: String::new(),
            role: String::new(),
            port: 80,
            api_url: default_scaleway_api_url(),
            zone: default_scaleway_zone(),
            name_filter: String::new(),
            tags_filter: Vec::new(),
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl ScalewaySdConfig {
    /// Validates the Scaleway SD configuration (`scaleway.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        match self.role.as_str() {
            "instance" | "baremetal" => {}
            "" => return Err("role missing (one of: instance, baremetal)".to_owned()),
            other => return Err(format!("unknown role {other:?}")),
        }
        if self.project_id.is_empty() {
            return Err("project_id is mandatory".to_owned());
        }
        if self.secret_key.is_empty() && self.secret_key_file.is_empty() {
            return Err("one of secret_key & secret_key_file must be configured".to_owned());
        }
        if !self.secret_key.is_empty() && !self.secret_key_file.is_empty() {
            return Err(
                "at most one of secret_key & secret_key_file must be configured".to_owned(),
            );
        }
        if self.access_key.is_empty() {
            return Err("access_key is mandatory".to_owned());
        }
        let access_key_re = Regex::new(r"^SCW[A-Z0-9]{17}$").unwrap();
        if !access_key_re.is_match(&self.access_key) {
            return Err(format!(
                "invalid access key format '{}', expected SCWXXXXXXXXXXXXXXXXX",
                self.access_key
            ));
        }
        let uuid_re = Regex::new(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$").unwrap();
        if self.secret_key_file.is_empty()
            && self.secret_key.as_str() != "<secret>"
            && !uuid_re.is_match(self.secret_key.as_str())
        {
            return Err(format!(
                "invalid secret key format '{}', expected a UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                self.secret_key.as_str()
            ));
        }
        if !uuid_re.is_match(&self.project_id) {
            return Err(format!(
                "invalid organization ID format '{}', expected a UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                self.project_id
            ));
        }
        let zone_re = Regex::new(r"^[a-z]{2}-[a-z]{3,7}-[0-9]{1,2}$").unwrap();
        if !zone_re.is_match(&self.zone) {
            return Err(format!(
                "invalid zone format '{}', expected xx-xxx-x",
                self.zone
            ));
        }
        if self.api_url.ends_with('/') {
            return Err(format!(
                "invalid API URL '{}', trailing slash is not allowed",
                self.api_url
            ));
        }
        validate_go_url(&self.api_url)?;
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
        self.secret_key_file = join_dir(dir, &self.secret_key_file);
    }
}

fn default_stackit_region() -> String {
    "eu01".to_owned()
}

/// STACKIT IAAS service discovery configuration (`discovery/stackit.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StackitSdConfig {
    /// STACKIT project ID.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub project: String,
    /// Custom API endpoint.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// STACKIT region (defaults to `"eu01"`).
    #[serde(
        default = "default_stackit_region",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub region: String,
    /// Inline service account key JSON.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub service_account_key: Secret,
    /// Path to service account key JSON file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub service_account_key_path: String,
    /// Inline private key PEM.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub private_key: Secret,
    /// Path to private key PEM file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub private_key_path: String,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Label regex filters.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels_regex: BTreeMap<String, String>,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for StackitSdConfig {
    fn default() -> Self {
        Self {
            project: String::new(),
            endpoint: String::new(),
            region: default_stackit_region(),
            service_account_key: Secret::default(),
            service_account_key_path: String::new(),
            private_key: Secret::default(),
            private_key_path: String::new(),
            refresh_interval: default_refresh_60s(),
            port: 80,
            labels_regex: BTreeMap::new(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl StackitSdConfig {
    /// Validates the STACKIT SD configuration (`stackit.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        self.http_client_config.validate()?;
        if !self.endpoint.is_empty() && url::Url::parse(&self.endpoint).is_err() {
            return Err(format!("stackit_sd: invalid endpoint {:?}", self.endpoint));
        }
        if self.project.trim().is_empty() {
            return Err("stackit_sd: project cannot be empty".to_owned());
        }
        if self.endpoint.is_empty() && self.region.is_empty() {
            return Err("stackit_sd: endpoint and region missing".to_owned());
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

fn default_triton_role() -> String {
    "container".to_owned()
}

/// Joyent Triton service discovery configuration (`discovery/triton.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TritonSdConfig {
    /// Triton account name.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub account: String,
    /// Triton role (`container` or `cn`, defaults to `container`).
    #[serde(
        default = "default_triton_role",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub role: String,
    /// Triton CNS DNS suffix.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub dns_suffix: String,
    /// Triton discovery endpoint host.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub endpoint: String,
    /// Container groups filter.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Triton discovery port (defaults to `9163`).
    #[serde(default = "default_port_9163")]
    pub port: i32,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// TLS configuration.
    #[serde(skip_serializing_if = "TlsConfig::is_empty")]
    pub tls_config: TlsConfig,
    /// Triton API version (defaults to `1`).
    #[serde(default = "default_version_1")]
    pub version: i32,
}

impl Default for TritonSdConfig {
    fn default() -> Self {
        Self {
            account: String::new(),
            role: default_triton_role(),
            dns_suffix: String::new(),
            endpoint: String::new(),
            groups: Vec::new(),
            port: 9163,
            refresh_interval: default_refresh_60s(),
            tls_config: TlsConfig::default(),
            version: 1,
        }
    }
}

impl TritonSdConfig {
    /// Validates the Triton SD configuration (`triton.SDConfig.UnmarshalYAML`).
    pub fn validate(&self) -> Result<(), String> {
        self.tls_config.validate()?;
        if !matches!(self.role.as_str(), "container" | "cn") {
            return Err(
                "triton SD configuration requires role to be 'container' or 'cn'".to_owned(),
            );
        }
        if self.account.is_empty() {
            return Err("triton SD configuration requires an account".to_owned());
        }
        if self.dns_suffix.is_empty() {
            return Err("triton SD configuration requires a dns_suffix".to_owned());
        }
        if self.endpoint.is_empty() {
            return Err("triton SD configuration requires an endpoint".to_owned());
        }
        if self.refresh_interval.is_zero() {
            return Err(
                "triton SD configuration requires RefreshInterval to be a positive integer"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.tls_config.set_directory(dir);
    }
}

fn default_uyuni_entitlement() -> String {
    "monitoring_entitled".to_owned()
}

/// Uyuni service discovery configuration (`discovery/uyuni.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UyuniSdConfig {
    /// Uyuni server URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server: String,
    /// Uyuni username.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username: String,
    /// Uyuni password.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub password: Secret,
    /// Uyuni entitlement filter (defaults to `"monitoring_entitled"`).
    #[serde(
        default = "default_uyuni_entitlement",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub entitlement: String,
    /// Group label separator (defaults to `","`).
    #[serde(
        default = "default_comma",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub separator: String,
    /// Refresh interval (defaults to `1m`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for UyuniSdConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            username: String::new(),
            password: Secret::default(),
            entitlement: default_uyuni_entitlement(),
            separator: default_comma(),
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl UyuniSdConfig {
    /// Validates the Uyuni SD configuration (`uyuni.SDConfig.UnmarshalYAML`).
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()?;
        if self.server.is_empty() {
            return Err("Uyuni SD configuration requires server host".to_owned());
        }
        if self.username.is_empty() {
            return Err("Uyuni SD configuration requires a username".to_owned());
        }
        if self.password.is_empty() {
            return Err("Uyuni SD configuration requires a password".to_owned());
        }
        validate_go_url(&self.server)?;
        Ok(())
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Vultr service discovery configuration (`discovery/vultr.SDConfig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VultrSdConfig {
    /// Default target port (defaults to `80`).
    #[serde(default = "default_port_80")]
    pub port: i32,
    /// Refresh interval (defaults to `60s`).
    #[serde(default = "default_refresh_60s")]
    pub refresh_interval: Duration,
    /// HTTP client configuration.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
}

impl Default for VultrSdConfig {
    fn default() -> Self {
        Self {
            port: 80,
            refresh_interval: default_refresh_60s(),
            http_client_config: HttpClientConfig::default(),
        }
    }
}

impl VultrSdConfig {
    /// Validates the Vultr SD configuration.
    pub fn validate(&mut self) -> Result<(), String> {
        self.http_client_config.validate()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
    }
}

/// Top-level discovery configuration container matching the discovery fields on a
/// Prometheus `scrape_config` or `alertmanager_config` (`discovery.Configs`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfigs {
    /// Static target group configurations (`static_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub static_configs: Vec<StaticConfig>,
    /// Unified AWS SD configurations (`aws_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub aws_sd_configs: Vec<AwsSdConfig>,
    /// Azure SD configurations (`azure_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub azure_sd_configs: Vec<AzureSdConfig>,
    /// Consul SD configurations (`consul_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub consul_sd_configs: Vec<ConsulSdConfig>,
    /// DigitalOcean SD configurations (`digitalocean_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub digitalocean_sd_configs: Vec<DigitalOceanSdConfig>,
    /// Docker Engine SD configurations (`docker_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub docker_sd_configs: Vec<DockerSdConfig>,
    /// Docker Swarm SD configurations (`dockerswarm_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dockerswarm_sd_configs: Vec<DockerSwarmSdConfig>,
    /// DNS SD configurations (`dns_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dns_sd_configs: Vec<DnsSdConfig>,
    /// AWS EC2 SD configurations (`ec2_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ec2_sd_configs: Vec<Ec2SdConfig>,
    /// AWS ECS SD configurations (`ecs_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ecs_sd_configs: Vec<EcsSdConfig>,
    /// AWS ElastiCache SD configurations (`elasticache_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub elasticache_sd_configs: Vec<ElastiCacheSdConfig>,
    /// Netflix Eureka SD configurations (`eureka_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub eureka_sd_configs: Vec<EurekaSdConfig>,
    /// File SD configurations (`file_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub file_sd_configs: Vec<FileSdConfig>,
    /// GCE SD configurations (`gce_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub gce_sd_configs: Vec<GceSdConfig>,
    /// Hetzner SD configurations (`hetzner_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub hetzner_sd_configs: Vec<HetznerSdConfig>,
    /// HTTP SD configurations (`http_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub http_sd_configs: Vec<HttpSdConfig>,
    /// IONOS SD configurations (`ionos_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ionos_sd_configs: Vec<IonosSdConfig>,
    /// Kubernetes SD configurations (`kubernetes_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kubernetes_sd_configs: Vec<KubernetesSdConfig>,
    /// Kuma xDS SD configurations (`kuma_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub kuma_sd_configs: Vec<KumaSdConfig>,
    /// AWS Lightsail SD configurations (`lightsail_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub lightsail_sd_configs: Vec<LightsailSdConfig>,
    /// Linode SD configurations (`linode_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub linode_sd_configs: Vec<LinodeSdConfig>,
    /// Marathon SD configurations (`marathon_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub marathon_sd_configs: Vec<MarathonSdConfig>,
    /// AWS MSK SD configurations (`msk_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub msk_sd_configs: Vec<MskSdConfig>,
    /// Zookeeper Nerve SD configurations (`nerve_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub nerve_sd_configs: Vec<ZookeeperSdConfig>,
    /// Nomad SD configurations (`nomad_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub nomad_sd_configs: Vec<NomadSdConfig>,
    /// OCI SD configurations (`oci_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub oci_sd_configs: Vec<OciSdConfig>,
    /// OpenStack SD configurations (`openstack_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub openstack_sd_configs: Vec<OpenstackSdConfig>,
    /// Outscale SD configurations (`outscale_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub outscale_sd_configs: Vec<OutscaleSdConfig>,
    /// OVHcloud SD configurations (`ovhcloud_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ovhcloud_sd_configs: Vec<OvhcloudSdConfig>,
    /// PuppetDB SD configurations (`puppetdb_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub puppetdb_sd_configs: Vec<PuppetdbSdConfig>,
    /// AWS RDS SD configurations (`rds_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub rds_sd_configs: Vec<RdsSdConfig>,
    /// Scaleway SD configurations (`scaleway_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub scaleway_sd_configs: Vec<ScalewaySdConfig>,
    /// Zookeeper Serverset SD configurations (`serverset_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub serverset_sd_configs: Vec<ZookeeperSdConfig>,
    /// STACKIT SD configurations (`stackit_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub stackit_sd_configs: Vec<StackitSdConfig>,
    /// Triton SD configurations (`triton_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub triton_sd_configs: Vec<TritonSdConfig>,
    /// Uyuni SD configurations (`uyuni_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub uyuni_sd_configs: Vec<UyuniSdConfig>,
    /// Vultr SD configurations (`vultr_sd_configs`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub vultr_sd_configs: Vec<VultrSdConfig>,
}

/// Type alias for [`DiscoveryConfigs`].
pub type ServiceDiscoveryConfigs = DiscoveryConfigs;

/// All YAML keys recognized by [`DiscoveryConfigs`].
pub const SERVICE_DISCOVERY_FIELDS: &[&str] = &[
    "static_configs",
    "aws_sd_configs",
    "azure_sd_configs",
    "consul_sd_configs",
    "digitalocean_sd_configs",
    "docker_sd_configs",
    "dockerswarm_sd_configs",
    "dns_sd_configs",
    "ec2_sd_configs",
    "ecs_sd_configs",
    "elasticache_sd_configs",
    "eureka_sd_configs",
    "file_sd_configs",
    "gce_sd_configs",
    "hetzner_sd_configs",
    "http_sd_configs",
    "ionos_sd_configs",
    "kubernetes_sd_configs",
    "kuma_sd_configs",
    "lightsail_sd_configs",
    "linode_sd_configs",
    "marathon_sd_configs",
    "msk_sd_configs",
    "nerve_sd_configs",
    "nomad_sd_configs",
    "oci_sd_configs",
    "openstack_sd_configs",
    "outscale_sd_configs",
    "ovhcloud_sd_configs",
    "puppetdb_sd_configs",
    "rds_sd_configs",
    "scaleway_sd_configs",
    "serverset_sd_configs",
    "stackit_sd_configs",
    "triton_sd_configs",
    "uyuni_sd_configs",
    "vultr_sd_configs",
];

impl DiscoveryConfigs {
    /// Validates all configured service discovery sections according to Prometheus rules.
    pub fn validate(&mut self) -> Result<(), DiscoveryError> {
        self.validate_with_hostname(true)
            .map_err(DiscoveryError::InvalidConfig)
    }

    /// Resolves the configured `static_configs` into [`TargetGroup`]s.
    pub fn resolve_static(&self) -> Vec<TargetGroup> {
        resolve_static_configs(&self.static_configs)
    }

    /// Validates all configured service discovery blocks with optional static target hostname
    /// checking (`check_static_hostname` is `true` when `relabel_configs` is empty on a
    /// `scrape_config`, and `false` on `alertmanagers`).
    pub fn validate_with_hostname(&mut self, check_static_hostname: bool) -> Result<(), String> {
        for sc in &self.static_configs {
            sc.validate(check_static_hostname)?;
        }
        for c in &mut self.aws_sd_configs {
            c.validate()?;
        }
        for c in &mut self.azure_sd_configs {
            c.validate()?;
        }
        for c in &mut self.consul_sd_configs {
            c.validate()?;
        }
        for c in &mut self.digitalocean_sd_configs {
            c.validate()?;
        }
        for c in &mut self.docker_sd_configs {
            c.validate()?;
        }
        for c in &mut self.dockerswarm_sd_configs {
            c.validate()?;
        }
        for c in &mut self.dns_sd_configs {
            c.validate().map_err(|e| e.to_string())?;
        }
        for c in &mut self.ec2_sd_configs {
            c.validate()?;
        }
        for c in &mut self.ecs_sd_configs {
            c.validate()?;
        }
        for c in &mut self.elasticache_sd_configs {
            c.validate()?;
        }
        for c in &mut self.eureka_sd_configs {
            c.validate()?;
        }
        for c in &self.file_sd_configs {
            c.validate()?;
        }
        for c in &self.gce_sd_configs {
            c.validate()?;
        }
        for c in &mut self.hetzner_sd_configs {
            c.validate()?;
        }
        for c in &mut self.http_sd_configs {
            c.validate()?;
        }
        for c in &mut self.ionos_sd_configs {
            c.validate()?;
        }
        for c in &mut self.kubernetes_sd_configs {
            c.validate().map_err(|e| e.to_string())?;
        }
        for c in &mut self.kuma_sd_configs {
            c.validate()?;
        }
        for c in &mut self.lightsail_sd_configs {
            c.validate()?;
        }
        for c in &mut self.linode_sd_configs {
            c.validate()?;
        }
        for c in &mut self.marathon_sd_configs {
            c.validate()?;
        }
        for c in &mut self.msk_sd_configs {
            c.validate()?;
        }
        for c in &self.nerve_sd_configs {
            c.validate("nerve")?;
        }
        for c in &mut self.nomad_sd_configs {
            c.validate()?;
        }
        for c in &mut self.oci_sd_configs {
            c.validate()?;
        }
        for c in &self.openstack_sd_configs {
            c.validate()?;
        }
        for c in &mut self.outscale_sd_configs {
            c.validate()?;
        }
        for c in &self.ovhcloud_sd_configs {
            c.validate()?;
        }
        for c in &mut self.puppetdb_sd_configs {
            c.validate()?;
        }
        for c in &mut self.rds_sd_configs {
            c.validate()?;
        }
        for c in &mut self.scaleway_sd_configs {
            c.validate()?;
        }
        for c in &self.serverset_sd_configs {
            c.validate("serverset")?;
        }
        for c in &mut self.stackit_sd_configs {
            c.validate()?;
        }
        for c in &self.triton_sd_configs {
            c.validate()?;
        }
        for c in &mut self.uyuni_sd_configs {
            c.validate()?;
        }
        for c in &mut self.vultr_sd_configs {
            c.validate()?;
        }
        Ok(())
    }

    /// Joins relative file paths in all service discovery configurations with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        for c in &mut self.aws_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.azure_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.consul_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.digitalocean_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.docker_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.dockerswarm_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.ec2_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.ecs_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.elasticache_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.eureka_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.file_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.hetzner_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.http_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.ionos_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.kubernetes_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.kuma_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.lightsail_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.linode_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.marathon_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.msk_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.nomad_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.oci_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.openstack_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.outscale_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.puppetdb_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.rds_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.scaleway_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.stackit_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.triton_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.uyuni_sd_configs {
            c.set_directory(dir);
        }
        for c in &mut self.vultr_sd_configs {
            c.set_directory(dir);
        }
    }
}

/// Checks raw YAML mapping for null `static_configs` elements and unknown fields inside SD blocks
/// that use `#[serde(flatten)]`.
pub fn check_sd_yaml_mapping(map: &serde_yaml::Mapping) -> Result<(), String> {
    if let Some(serde_yaml::Value::Sequence(seq)) =
        map.get(serde_yaml::Value::String("static_configs".to_owned()))
    {
        for item in seq {
            if item.is_null() {
                return Err("empty or null section in static_configs".to_owned());
            }
        }
    }

    let sd_checks: &[(&str, &[&str], &str)] = &[
        (
            "aws_sd_configs",
            &[
                "role",
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
                "filters",
                "clusters",
                "request_concurrency",
            ],
            "aws.plain",
        ),
        (
            "azure_sd_configs",
            &[
                "environment",
                "port",
                "subscription_id",
                "tenant_id",
                "client_id",
                "client_secret",
                "refresh_interval",
                "authentication_method",
                "resource_group",
            ],
            "azure.plain",
        ),
        (
            "consul_sd_configs",
            &[
                "server",
                "token",
                "datacenter",
                "namespace",
                "partition",
                "path_prefix",
                "username",
                "password",
                "scheme",
                "services",
                "tags",
                "health_filter",
                "node_meta",
                "tag_separator",
                "allow_stale",
                "refresh_interval",
                "filter",
            ],
            "consul.plain",
        ),
        (
            "digitalocean_sd_configs",
            &["refresh_interval", "port", "role"],
            "digitalocean.plain",
        ),
        (
            "docker_sd_configs",
            &[
                "host",
                "port",
                "filters",
                "host_networking_host",
                "refresh_interval",
                "match_first_network",
            ],
            "moby.plain",
        ),
        (
            "dockerswarm_sd_configs",
            &["host", "role", "port", "filters", "refresh_interval"],
            "moby.plain",
        ),
        (
            "ec2_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
                "filters",
            ],
            "aws.plain",
        ),
        (
            "ecs_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
                "clusters",
                "request_concurrency",
            ],
            "aws.plain",
        ),
        (
            "elasticache_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
            ],
            "aws.plain",
        ),
        (
            "eureka_sd_configs",
            &["server", "refresh_interval"],
            "eureka.plain",
        ),
        (
            "hetzner_sd_configs",
            &["role", "refresh_interval", "port", "label_selector"],
            "hetzner.plain",
        ),
        (
            "http_sd_configs",
            &["url", "refresh_interval"],
            "http.plain",
        ),
        (
            "ionos_sd_configs",
            &["datacenter_id", "refresh_interval", "port"],
            "ionos.plain",
        ),
        (
            "kubernetes_sd_configs",
            &[
                "api_server",
                "role",
                "kubeconfig_file",
                "namespaces",
                "selectors",
                "attach_metadata",
            ],
            "kubernetes.plain",
        ),
        (
            "kuma_sd_configs",
            &["server", "client_id", "refresh_interval", "fetch_timeout"],
            "xds.plain",
        ),
        (
            "lightsail_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
            ],
            "aws.plain",
        ),
        (
            "linode_sd_configs",
            &["port", "tag_separator", "refresh_interval", "region"],
            "linode.plain",
        ),
        (
            "marathon_sd_configs",
            &[
                "servers",
                "refresh_interval",
                "auth_token",
                "auth_token_file",
            ],
            "marathon.plain",
        ),
        (
            "msk_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
                "clusters",
            ],
            "aws.plain",
        ),
        (
            "nomad_sd_configs",
            &[
                "allow_stale",
                "namespace",
                "refresh_interval",
                "region",
                "server",
                "tag_separator",
            ],
            "nomad.plain",
        ),
        (
            "oci_sd_configs",
            &[
                "auth",
                "region",
                "tenancy",
                "user",
                "fingerprint",
                "key_file",
                "key_passphrase",
                "key_passphrase_file",
                "compartments",
                "port",
                "refresh_interval",
            ],
            "oci.plain",
        ),
        (
            "outscale_sd_configs",
            &[
                "endpoint",
                "region",
                "access_key",
                "secret_key",
                "secret_key_file",
                "refresh_interval",
                "port",
            ],
            "outscale.plain",
        ),
        (
            "puppetdb_sd_configs",
            &[
                "url",
                "query",
                "include_parameters",
                "refresh_interval",
                "port",
            ],
            "puppetdb.plain",
        ),
        (
            "rds_sd_configs",
            &[
                "region",
                "endpoint",
                "access_key",
                "secret_key",
                "profile",
                "role_arn",
                "refresh_interval",
                "port",
            ],
            "aws.plain",
        ),
        (
            "scaleway_sd_configs",
            &[
                "access_key",
                "secret_key",
                "secret_key_file",
                "project_id",
                "role",
                "port",
                "api_url",
                "zone",
                "name_filter",
                "tags_filter",
                "refresh_interval",
            ],
            "scaleway.plain",
        ),
        (
            "stackit_sd_configs",
            &[
                "project",
                "endpoint",
                "region",
                "service_account_key",
                "service_account_key_path",
                "private_key",
                "private_key_path",
                "refresh_interval",
                "port",
                "labels_regex",
            ],
            "stackit.plain",
        ),
        (
            "uyuni_sd_configs",
            &[
                "server",
                "username",
                "password",
                "entitlement",
                "separator",
                "refresh_interval",
            ],
            "uyuni.plain",
        ),
        (
            "vultr_sd_configs",
            &["port", "refresh_interval"],
            "vultr.plain",
        ),
    ];

    for &(key, sd_fields, type_name) in sd_checks {
        if let Some(serde_yaml::Value::Sequence(seq)) =
            map.get(serde_yaml::Value::String(key.to_owned()))
        {
            let mut combined: Vec<&str> =
                Vec::with_capacity(sd_fields.len() + HTTP_CLIENT_CONFIG_FIELDS.len());
            combined.extend_from_slice(sd_fields);
            combined.extend_from_slice(HTTP_CLIENT_CONFIG_FIELDS);
            for item in seq {
                if let serde_yaml::Value::Mapping(item_map) = item {
                    check_allowed_fields(item_map, &combined, type_name)?;
                    if key == "kubernetes_sd_configs"
                        && let Some(serde_yaml::Value::Mapping(ns_map)) =
                            item_map.get(serde_yaml::Value::String("namespaces".to_owned()))
                    {
                        check_allowed_fields(
                            ns_map,
                            &["own_namespace", "names"],
                            "kubernetes.plain",
                        )?;
                    }
                    check_http_client_config_fields_subset(item_map)?;
                }
            }
        }
    }
    Ok(())
}

fn check_http_client_config_fields_subset(map: &serde_yaml::Mapping) -> Result<(), String> {
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
