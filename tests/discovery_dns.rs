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

#![cfg(feature = "discovery")]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use expfmt::discovery::{
    ADDRESS_LABEL, DiscoveryConfigs, DiscoveryError, DnsDiscovery, DnsRecord, DnsRecordType,
    DnsSdConfig, LabelSet, ResolvConf, TargetGroup,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

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

fn decode_qname_from_query(qbuf: &[u8]) -> (String, usize) {
    let mut offset = 12;
    let mut labels = Vec::new();
    while qbuf[offset] != 0 {
        let len = qbuf[offset] as usize;
        let label = std::str::from_utf8(&qbuf[offset + 1..offset + 1 + len]).unwrap();
        labels.push(label.to_owned());
        offset += 1 + len;
    }
    let qend = offset + 1 + 4;
    let fqdn = if labels.is_empty() {
        ".".to_owned()
    } else {
        format!("{}.", labels.join("."))
    };
    (fqdn, qend)
}

#[tokio::test]
async fn dns_discovery_live_udp_and_tcp_fallback_with_search_path() {
    let parsed_resolv = ResolvConf::parse(
        r#"
        # Comment line
        ; Semicolon comment
        nameserver 10.96.0.10
        nameserver [::1]:5353
        domain old.example.com.
        search svc.cluster.local. cluster.local.
        options ndots:3 timeout:4
        "#,
    );
    assert_eq!(
        parsed_resolv.servers,
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)), 53),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
        ]
    );
    assert_eq!(
        parsed_resolv.search,
        vec!["svc.cluster.local".to_owned(), "cluster.local".to_owned()]
    );
    assert_eq!(parsed_resolv.ndots, 3);
    assert_eq!(parsed_resolv.timeout, Duration::from_secs(4));

    let udp_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = udp_listener.local_addr().unwrap();
    let tcp_listener = TcpListener::bind(server_addr).await.unwrap();

    // Spawn a local DNS server that returns TC=1 (truncated) over UDP so the client falls back
    // to TCP, and returns an SRV record over TCP for `_metrics._tcp.svc.cluster.local.`.
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        if let Ok((len, peer)) = udp_listener.recv_from(&mut buf).await {
            assert!(len >= 12);
            let mut resp = Vec::with_capacity(12);
            resp.extend_from_slice(&buf[0..2]);
            resp.extend_from_slice(&0x8200u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            let _ = udp_listener.send_to(&resp, peer).await;
        }
    });

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = tcp_listener.accept().await {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let qlen = u16::from_be_bytes(len_buf) as usize;
            let mut qbuf = vec![0u8; qlen];
            stream.read_exact(&mut qbuf).await.unwrap();

            let (_, qname_end) = decode_qname_from_query(&qbuf);
            let mut resp = Vec::new();
            resp.extend_from_slice(&qbuf[0..2]);
            resp.extend_from_slice(&0x8180u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&qbuf[12..qname_end]);

            resp.push(0);
            resp.extend_from_slice(&33u16.to_be_bytes()); // SRV
            resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            resp.extend_from_slice(&60u32.to_be_bytes());

            let mut rdata = Vec::new();
            rdata.extend_from_slice(&10u16.to_be_bytes());
            rdata.extend_from_slice(&5u16.to_be_bytes());
            rdata.extend_from_slice(&9100u16.to_be_bytes());
            for label in ["pod1", "cluster", "local"] {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
            rdata.push(0);

            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);

            stream
                .write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&resp).await.unwrap();
        }
    });

    let resolv = ResolvConf {
        servers: vec![server_addr],
        search: vec!["svc.cluster.local".to_owned()],
        ndots: 5,
        timeout: Duration::from_secs(2),
    };
    let sd = DnsDiscovery::with_resolv_conf(
        DnsSdConfig {
            names: vec!["_metrics._tcp".to_owned()],
            refresh_interval: Duration::from_secs(15),
            record_type: "SRV".to_owned(),
            port: 0,
        },
        resolv,
    )
    .unwrap();

    assert!(sd.resolv_conf().is_some());
    let groups = sd.refresh().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].source, "_metrics._tcp");
    assert_eq!(
        groups[0].targets,
        vec![label_set(&[
            ("__address__", "pod1.cluster.local:9100"),
            ("__meta_dns_name", "_metrics._tcp"),
            ("__meta_dns_srv_record_target", "pod1.cluster.local."),
            ("__meta_dns_srv_record_port", "9100"),
            ("__meta_dns_mx_record_target", ""),
            ("__meta_dns_ns_record_target", ""),
        ])]
    );
}

#[test]
fn dns_multi_server_fallback_search_path_and_localset() {
    let clamped = ResolvConf::parse(
        "domain first.example.com. ignored.example.com.\noptions ndots:99 timeout:999\n",
    );
    assert_eq!(clamped.search, vec!["first.example.com".to_owned()]);
    assert_eq!(clamped.ndots, 15);
    assert_eq!(clamped.timeout, Duration::from_secs(30));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let udp1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv1_addr = udp1.local_addr().unwrap();
        let tcp1 = TcpListener::bind(srv1_addr).await.unwrap();

        let udp2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv2_addr = udp2.local_addr().unwrap();

        tokio::task::spawn_local(async move {
            if tcp1.accept().await.is_ok() {
                panic!("non-truncated UDP response must not trigger TCP fallback");
            }
        });

        let srv2_queries = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let srv2_queries_clone = std::rc::Rc::clone(&srv2_queries);

        tokio::task::spawn_local(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = udp1.recv_from(&mut buf).await {
                let (qname, qend) = decode_qname_from_query(&buf[..len]);
                let rcode: u16 = match qname.as_str() {
                    "hit.two.local." | "flaky.one.local." => 2, // SERVFAIL
                    "nodata.one.local." => 0,                   // NODATA (ANCOUNT=0)
                    _ => 3,                                     // NXDOMAIN
                };
                let mut resp = Vec::new();
                resp.extend_from_slice(&buf[0..2]);
                resp.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&buf[12..qend]);
                let _ = udp1.send_to(&resp, peer).await;
            }
        });

        tokio::task::spawn_local(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = udp2.recv_from(&mut buf).await {
                let (qname, qend) = decode_qname_from_query(&buf[..len]);
                srv2_queries_clone.borrow_mut().push(qname.clone());
                let mut resp = Vec::new();
                resp.extend_from_slice(&buf[0..2]);
                if qname == "hit.two.local." {
                    resp.extend_from_slice(&0x8180u16.to_be_bytes());
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&buf[12..qend]);
                    resp.push(0);
                    resp.extend_from_slice(&1u16.to_be_bytes()); // A
                    resp.extend_from_slice(&1u16.to_be_bytes()); // IN
                    resp.extend_from_slice(&60u32.to_be_bytes());
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&[10, 1, 2, 3]);
                } else {
                    resp.extend_from_slice(&0x8182u16.to_be_bytes()); // SERVFAIL
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&buf[12..qend]);
                }
                let _ = udp2.send_to(&resp, peer).await;
            }
        });

        let resolv = ResolvConf {
            servers: vec![srv1_addr, srv2_addr],
            search: vec!["one.local".to_owned(), "two.local".to_owned()],
            ndots: 2,
            timeout: Duration::from_secs(2),
        };
        let sd = DnsDiscovery::with_resolv_conf(
            DnsSdConfig {
                names: vec![
                    "hit".to_owned(),
                    "gone".to_owned(),
                    "flaky".to_owned(),
                    "nodata".to_owned(),
                ],
                refresh_interval: Duration::from_secs(15),
                record_type: "A".to_owned(),
                port: 9100,
            },
            resolv,
        )
        .unwrap();

        let groups = tokio::task::spawn_local(async move { sd.refresh().await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].source, "hit");
        assert_eq!(
            groups[0].targets[0].get(ADDRESS_LABEL),
            Some(&"10.1.2.3:9100".to_owned())
        );
        assert_eq!(groups[1].source, "gone");
        assert!(groups[1].targets.is_empty());
        assert_eq!(groups[2].source, "nodata");
        assert!(groups[2].targets.is_empty());

        assert_eq!(
            *srv2_queries.borrow(),
            vec!["hit.two.local.".to_owned(), "flaky.one.local.".to_owned()]
        );
    });
}
