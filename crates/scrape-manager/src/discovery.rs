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

//! Prometheus-compatible target discovery configuration and target group types.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use prometheus_relabel::{ADDRESS_LABEL, LabelSet, ValidationScheme};

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
    /// JSON payload decoding error.
    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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
    for name in labels.keys() {
        if !ValidationScheme::Utf8.is_valid_label_name(name) {
            return Err(serde::de::Error::custom(format!(
                "{name:?} is not a valid label name"
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

/// Resolves a slice of [`StaticConfig`] entries into [`TargetGroup`]s with sequential
/// `"0"`, `"1"`, ... source identifiers matching Prometheus `discovery.StaticConfig`.
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
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub static_configs: Vec<StaticConfig>,
}

impl DiscoveryConfigs {
    /// Validates all configured service discovery sections according to Prometheus rules.
    pub fn validate(&mut self) -> Result<(), DiscoveryError> {
        Ok(())
    }

    /// Resolves the configured `static_configs` into [`TargetGroup`]s.
    pub fn resolve_static(&self) -> Vec<TargetGroup> {
        resolve_static_configs(&self.static_configs)
    }
}

/// Parses a Prometheus duration string (such as `"30s"`, `"1m"`, `"500ms"`, `"1h30m"`, `"7d"`,
/// `"1w"`, `"1y"`, or `"0"`) into a [`Duration`], matching `prometheus/common/model.ParseDuration`.
pub fn parse_duration(s: &str) -> Result<Duration, DiscoveryError> {
    prometheus_relabel::parse_prometheus_duration(s)
        .map(Duration::from_nanos)
        .map_err(DiscoveryError::InvalidConfig)
}

/// Formats a [`Duration`] as a canonical Prometheus duration string (such as `"30s"` or `"1m30s"`),
/// matching `prometheus/common/model.Duration.String`.
pub fn format_duration(d: Duration) -> String {
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
