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

//! Prometheus-compatible target discovery (`static_configs` and `dns_sd_configs`).

pub mod dns;

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use dns::{DnsDiscovery, DnsRecord, DnsRecordType, DnsSdConfig, ResolvConf};

/// Reserved Prometheus label holding the `<host>:<port>` scrape target address.
pub const ADDRESS_LABEL: &str = "__address__";

/// Ordered map of label names to label values matching Prometheus `model.LabelSet`.
pub type LabelSet = BTreeMap<String, String>;

/// Error returned when validating or running target discovery.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Configuration validation failed.
    #[error("{0}")]
    InvalidConfig(String),
    /// I/O or filesystem error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// DNS protocol or lookup error.
    #[error("DNS error: {0}")]
    Dns(String),
    /// JSON payload decoding error.
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Static target group configuration matching Prometheus `static_configs` entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    /// List of target `"<host>:<port>"` addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Labels assigned to all targets in the group.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
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
            .filter_map(|t| t.get(ADDRESS_LABEL).map(String::as_str))
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
        let raw = StaticConfig::deserialize(deserializer)?;
        Ok(raw.into_target_group(String::new()))
    }
}

/// Resolves a slice of [`StaticConfig`] entries into [`TargetGroup`]s with sequential
/// `"0"`, `"1"`, ... source identifiers matching Prometheus `discovery.NewStaticProvider`.
pub fn resolve_static_configs(configs: &[StaticConfig]) -> Vec<TargetGroup> {
    configs
        .iter()
        .enumerate()
        .map(|(idx, cfg)| cfg.clone().into_target_group(idx.to_string()))
        .collect()
}

/// Top-level discovery configuration container matching the discovery fields on a
/// Prometheus `scrape_config`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfigs {
    /// Static target group configurations (`static_configs`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_configs: Vec<StaticConfig>,
    /// DNS service discovery configurations (`dns_sd_configs`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_sd_configs: Vec<DnsSdConfig>,
}

impl DiscoveryConfigs {
    /// Validates all configured service discovery sections according to Prometheus rules.
    pub fn validate(&mut self) -> Result<(), DiscoveryError> {
        for dns_cfg in &mut self.dns_sd_configs {
            dns_cfg.validate()?;
        }
        Ok(())
    }

    /// Resolves the configured `static_configs` into [`TargetGroup`]s.
    pub fn resolve_static(&self) -> Vec<TargetGroup> {
        resolve_static_configs(&self.static_configs)
    }
}

/// Joins a host and port into `"host:port"` or `"[ipv6]:port"`, matching Go `net.JoinHostPort`.
pub(crate) fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parses a Prometheus duration string (such as `"30s"`, `"1m"`, `"500ms"`, `"1h30m"`, `"7d"`,
/// `"1w"`, `"1y"`, or `"0"`) into a [`Duration`], matching `prometheus/common/model.ParseDuration`.
pub fn parse_duration(s: &str) -> Result<Duration, DiscoveryError> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    if s.is_empty() {
        return Err(DiscoveryError::InvalidConfig(
            "empty duration string".to_owned(),
        ));
    }

    let orig = s;
    let bytes = s.as_bytes();
    let mut idx = 0;
    let mut total_ms: u64 = 0;
    let mut last_unit_pos: u8 = 0;

    while idx < bytes.len() {
        if !bytes[idx].is_ascii_digit() {
            return Err(DiscoveryError::InvalidConfig(format!(
                "not a valid duration string: {orig:?}"
            )));
        }
        let num_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let val: u64 = s[num_start..idx].parse().map_err(|_| {
            DiscoveryError::InvalidConfig(format!("not a valid duration string: {orig:?}"))
        })?;

        let unit_start = idx;
        while idx < bytes.len() && !bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if unit_start == idx {
            return Err(DiscoveryError::InvalidConfig(format!(
                "not a valid duration string: {orig:?}"
            )));
        }
        let unit = &s[unit_start..idx];
        let (pos, mult_ms): (u8, u64) = match unit {
            "y" => (1, 365 * 24 * 60 * 60 * 1000),
            "w" => (2, 7 * 24 * 60 * 60 * 1000),
            "d" => (3, 24 * 60 * 60 * 1000),
            "h" => (4, 60 * 60 * 1000),
            "m" => (5, 60 * 1000),
            "s" => (6, 1000),
            "ms" => (7, 1),
            _ => {
                return Err(DiscoveryError::InvalidConfig(format!(
                    "unknown unit {unit:?} in duration {orig:?}"
                )));
            }
        };
        if pos <= last_unit_pos {
            return Err(DiscoveryError::InvalidConfig(format!(
                "not a valid duration string: {orig:?}"
            )));
        }
        last_unit_pos = pos;

        let part_ms = val
            .checked_mul(mult_ms)
            .ok_or_else(|| DiscoveryError::InvalidConfig("duration out of range".to_owned()))?;
        total_ms = total_ms
            .checked_add(part_ms)
            .ok_or_else(|| DiscoveryError::InvalidConfig("duration out of range".to_owned()))?;
    }

    Ok(Duration::from_millis(total_ms))
}

/// Formats a [`Duration`] as a canonical Prometheus duration string (such as `"30s"` or `"1m30s"`),
/// matching `prometheus/common/model.Duration.String`.
pub fn format_duration(d: Duration) -> String {
    if d.is_zero() {
        return "0s".to_owned();
    }
    let mut ms: u128 = d.as_millis().max(1);

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

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }
}
