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

use std::time::Duration;

/// Error returned when validating or running target discovery.
#[derive(Debug, thiserror::Error)]
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
