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

#![cfg(feature = "discovery")]

use std::time::Duration;

use expfmt::discovery::{format_duration, parse_duration};

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
