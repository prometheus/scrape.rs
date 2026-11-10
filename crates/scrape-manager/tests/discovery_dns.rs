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

//! Integration tests for Prometheus DNS service discovery (`dns_sd_configs`).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use prometheus_scrape_manager::discovery::{
    DiscoveryConfigs, DiscoveryError, DnsDiscovery, DnsRecord, DnsRecordType, DnsSdConfig,
    LabelSet, ResolvConf, TargetGroup,
};

fn label_set(pairs: &[(&str, &str)]) -> LabelSet {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn dns_sd_config_validation_matches_prometheus() {
    // Ported from TestDNSSDConfigValidation in discovery/dns/dns_test.go.
    let valid_cases = [
        r#"{"names": ["example.com"]}"#,
        r#"{"names": ["example.com"], "type": "SRV"}"#,
        r#"{"names": ["example.com"], "type": "A", "port": 80}"#,
        r#"{"names": ["example.com"], "type": "AAAA", "port": 80}"#,
        r#"{"names": ["example.com"], "type": "MX", "port": 25}"#,
        r#"{"names": ["example.com"], "type": "NS", "port": 53}"#,
        r#"{"names": ["example.com"], "refresh_interval": "15s", "type": "srv"}"#,
    ];
    for case in valid_cases {
        let mut cfg: DnsSdConfig = serde_json::from_str(case).expect(case);
        assert!(cfg.validate().is_ok(), "expected valid config: {case}");
    }

    let invalid_cases = [
        (
            r#"{}"#,
            "DNS-SD config must contain at least one SRV record name",
        ),
        (
            r#"{"names": []}"#,
            "DNS-SD config must contain at least one SRV record name",
        ),
        (
            r#"{"names": ["example.com"], "type": "A"}"#,
            "a port is required in DNS-SD configs for all record types except SRV",
        ),
        (
            r#"{"names": ["example.com"], "type": "AAAA"}"#,
            "a port is required in DNS-SD configs for all record types except SRV",
        ),
        (
            r#"{"names": ["example.com"], "type": "MX"}"#,
            "a port is required in DNS-SD configs for all record types except SRV",
        ),
        (
            r#"{"names": ["example.com"], "type": "NS"}"#,
            "a port is required in DNS-SD configs for all record types except SRV",
        ),
        (
            r#"{"names": ["example.com"], "type": "PTR", "port": 80}"#,
            "invalid DNS-SD records type PTR",
        ),
    ];
    for (case, expected_err) in invalid_cases {
        let mut cfg: DnsSdConfig = serde_json::from_str(case).expect(case);
        let err = cfg.validate().expect_err(case).to_string();
        assert_eq!(err, expected_err, "case: {case}");
    }

    // Unitless integers, overflowing duration strings, and unknown fields are rejected.
    assert!(
        serde_json::from_str::<DnsSdConfig>(
            r#"{"names": ["example.com"], "refresh_interval": 30}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<DnsSdConfig>(
            r#"{"names": ["example.com"], "refresh_interval": "999999999999999y"}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<DiscoveryConfigs>(r#"{"dns_sd_config": []}"#).is_err());
}

#[test]
fn dns_discovery_records_match_prometheus_dns_test() {
    // Ported from TestDNS in discovery/dns/dns_test.go.
    // 1. A record discovery.
    let sd = DnsDiscovery::new(DnsSdConfig {
        names: vec!["web.example.com.".to_owned()],
        refresh_interval: Duration::from_secs(30),
        record_type: "A".to_owned(),
        port: 80,
    })
    .unwrap();
    let groups = sd
        .refresh_with(|name, qtype| {
            assert_eq!(name, "web.example.com.");
            assert_eq!(qtype, DnsRecordType::A);
            Ok(vec![DnsRecord::A(Ipv4Addr::new(192, 0, 2, 2))])
        })
        .unwrap();
    assert_eq!(
        groups,
        vec![TargetGroup {
            source: "web.example.com.".to_owned(),
            labels: BTreeMap::new(),
            targets: vec![label_set(&[
                ("__address__", "192.0.2.2:80"),
                ("__meta_dns_name", "web.example.com."),
                ("__meta_dns_srv_record_target", ""),
                ("__meta_dns_srv_record_port", ""),
                ("__meta_dns_mx_record_target", ""),
                ("__meta_dns_ns_record_target", ""),
            ])],
        }]
    );

    // 2. AAAA record discovery.
    let sd = DnsDiscovery::new(DnsSdConfig {
        names: vec!["web.example.com.".to_owned()],
        refresh_interval: Duration::from_secs(30),
        record_type: "AAAA".to_owned(),
        port: 80,
    })
    .unwrap();
    let groups = sd
        .refresh_with(|_, qtype| {
            assert_eq!(qtype, DnsRecordType::Aaaa);
            Ok(vec![DnsRecord::Aaaa(
                "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            )])
        })
        .unwrap();
    assert_eq!(
        groups,
        vec![TargetGroup {
            source: "web.example.com.".to_owned(),
            labels: BTreeMap::new(),
            targets: vec![label_set(&[
                ("__address__", "[2001:db8::2]:80"),
                ("__meta_dns_name", "web.example.com."),
                ("__meta_dns_srv_record_target", ""),
                ("__meta_dns_srv_record_port", ""),
                ("__meta_dns_mx_record_target", ""),
                ("__meta_dns_ns_record_target", ""),
            ])],
        }]
    );

    // 3. SRV record discovery with CNAME in answer section.
    let sd = DnsDiscovery::new(DnsSdConfig {
        names: vec!["_mysql._tcp.db.example.com.".to_owned()],
        refresh_interval: Duration::from_secs(30),
        record_type: "SRV".to_owned(),
        port: 0,
    })
    .unwrap();
    let groups = sd
        .refresh_with(|_, qtype| {
            assert_eq!(qtype, DnsRecordType::Srv);
            Ok(vec![
                DnsRecord::Cname("_mysql._tcp.alias.example.com.".to_owned()),
                DnsRecord::Srv {
                    priority: 0,
                    weight: 0,
                    port: 3306,
                    target: "db1.example.com.".to_owned(),
                },
                DnsRecord::Srv {
                    priority: 0,
                    weight: 0,
                    port: 3306,
                    target: "db2.example.com.".to_owned(),
                },
            ])
        })
        .unwrap();
    assert_eq!(
        groups,
        vec![TargetGroup {
            source: "_mysql._tcp.db.example.com.".to_owned(),
            labels: BTreeMap::new(),
            targets: vec![
                label_set(&[
                    ("__address__", "db1.example.com:3306"),
                    ("__meta_dns_name", "_mysql._tcp.db.example.com."),
                    ("__meta_dns_srv_record_target", "db1.example.com."),
                    ("__meta_dns_srv_record_port", "3306"),
                    ("__meta_dns_mx_record_target", ""),
                    ("__meta_dns_ns_record_target", ""),
                ]),
                label_set(&[
                    ("__address__", "db2.example.com:3306"),
                    ("__meta_dns_name", "_mysql._tcp.db.example.com."),
                    ("__meta_dns_srv_record_target", "db2.example.com."),
                    ("__meta_dns_srv_record_port", "3306"),
                    ("__meta_dns_mx_record_target", ""),
                    ("__meta_dns_ns_record_target", ""),
                ]),
            ],
        }]
    );

    // 4. MX record discovery.
    let sd = DnsDiscovery::new(DnsSdConfig {
        names: vec!["example.com.".to_owned()],
        refresh_interval: Duration::from_secs(30),
        record_type: "MX".to_owned(),
        port: 25,
    })
    .unwrap();
    let groups = sd
        .refresh_with(|_, _| {
            Ok(vec![
                DnsRecord::Mx {
                    preference: 10,
                    target: "smtp1.example.com.".to_owned(),
                },
                DnsRecord::Mx {
                    preference: 20,
                    target: "smtp2.example.com.".to_owned(),
                },
            ])
        })
        .unwrap();
    assert_eq!(
        groups[0].targets,
        vec![
            label_set(&[
                ("__address__", "smtp1.example.com:25"),
                ("__meta_dns_name", "example.com."),
                ("__meta_dns_srv_record_target", ""),
                ("__meta_dns_srv_record_port", ""),
                ("__meta_dns_mx_record_target", "smtp1.example.com."),
                ("__meta_dns_ns_record_target", ""),
            ]),
            label_set(&[
                ("__address__", "smtp2.example.com:25"),
                ("__meta_dns_name", "example.com."),
                ("__meta_dns_srv_record_target", ""),
                ("__meta_dns_srv_record_port", ""),
                ("__meta_dns_mx_record_target", "smtp2.example.com."),
                ("__meta_dns_ns_record_target", ""),
            ]),
        ]
    );

    // 5. NS record discovery + NXDOMAIN empty answer + per-name lookup failure isolation.
    let sd = DnsDiscovery::new(DnsSdConfig {
        names: vec![
            "servfail.example.com.".to_owned(),
            "example.com.".to_owned(),
            "nxdomain.example.com.".to_owned(),
        ],
        refresh_interval: Duration::from_secs(30),
        record_type: "NS".to_owned(),
        port: 53,
    })
    .unwrap();
    let groups = sd
        .refresh_with(|name, _| {
            if name == "servfail.example.com." {
                Err(DiscoveryError::Dns("SERVFAIL".to_owned()))
            } else if name == "nxdomain.example.com." {
                Ok(vec![])
            } else {
                Ok(vec![DnsRecord::Ns {
                    target: "ns1.example.com.".to_owned(),
                }])
            }
        })
        .unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(
        groups[0].targets,
        vec![label_set(&[
            ("__address__", "ns1.example.com:53"),
            ("__meta_dns_name", "example.com."),
            ("__meta_dns_srv_record_target", ""),
            ("__meta_dns_srv_record_port", ""),
            ("__meta_dns_mx_record_target", ""),
            ("__meta_dns_ns_record_target", "ns1.example.com."),
        ])]
    );
    assert_eq!(groups[1].source, "nxdomain.example.com.");
    assert!(groups[1].targets.is_empty());

    assert!(ResolvConf::from_file(std::path::Path::new("/nonexistent/resolv.conf")).is_err());
}
