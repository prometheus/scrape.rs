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

//! Prometheus-compatible DNS service discovery (`dns_sd_configs`).

use std::collections::BTreeMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{ADDRESS_LABEL, DiscoveryError, LabelSet, TargetGroup, join_host_port, serde_duration};

/// Meta label storing the queried record name.
pub const DNS_NAME_LABEL: &str = "__meta_dns_name";
/// Meta label storing the target field of an SRV record.
pub const DNS_SRV_RECORD_TARGET_LABEL: &str = "__meta_dns_srv_record_target";
/// Meta label storing the port field of an SRV record.
pub const DNS_SRV_RECORD_PORT_LABEL: &str = "__meta_dns_srv_record_port";
/// Meta label storing the target field of an MX record.
pub const DNS_MX_RECORD_TARGET_LABEL: &str = "__meta_dns_mx_record_target";
/// Meta label storing the target field of an NS record.
pub const DNS_NS_RECORD_TARGET_LABEL: &str = "__meta_dns_ns_record_target";

const fn default_refresh_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_record_type() -> String {
    "SRV".to_owned()
}

/// Supported DNS record query types in Prometheus `dns_sd_configs`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DnsRecordType {
    /// RFC 2782 `SRV` service record (default).
    #[default]
    Srv,
    /// IPv4 `A` address record.
    A,
    /// IPv6 `AAAA` address record.
    Aaaa,
    /// Mail exchange `MX` record.
    Mx,
    /// Name server `NS` record.
    Ns,
}

impl DnsRecordType {
    /// Parses a case-insensitive DNS record type string (`"SRV"`, `"A"`, `"AAAA"`, `"MX"`, `"NS"`).
    pub fn parse(s: &str) -> Result<Self, DiscoveryError> {
        match s.to_ascii_uppercase().as_str() {
            "SRV" => Ok(Self::Srv),
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "MX" => Ok(Self::Mx),
            "NS" => Ok(Self::Ns),
            _ => Err(DiscoveryError::InvalidConfig(format!(
                "invalid DNS-SD records type {s}"
            ))),
        }
    }
}

/// Parsed DNS answer record used to populate discovered targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecord {
    /// `SRV` answer record.
    Srv {
        /// Priority of the target host.
        priority: u16,
        /// Relative weight for records with the same priority.
        weight: u16,
        /// TCP/UDP port on the target host.
        port: u16,
        /// Target domain name (typically with trailing dot).
        target: String,
    },
    /// IPv4 `A` answer record.
    A(Ipv4Addr),
    /// IPv6 `AAAA` answer record.
    Aaaa(Ipv6Addr),
    /// `MX` answer record.
    Mx {
        /// Preference value given to this RR.
        preference: u16,
        /// Mail exchange host domain name.
        target: String,
    },
    /// `NS` answer record.
    Ns {
        /// Authoritative name server host domain name.
        target: String,
    },
    /// `CNAME` alias record (skipped when constructing targets, matching Prometheus).
    Cname(String),
}

/// DNS service discovery configuration matching Prometheus `discovery/dns.SDConfig`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSdConfig {
    /// DNS domain names to query.
    #[serde(default)]
    pub names: Vec<String>,
    /// Refresh interval between DNS lookups (defaults to `30s`).
    #[serde(default = "default_refresh_interval", with = "serde_duration")]
    pub refresh_interval: Duration,
    /// DNS record type to query: `"SRV"` (default), `"A"`, `"AAAA"`, `"MX"`, or `"NS"`.
    #[serde(rename = "type", default = "default_record_type")]
    pub record_type: String,
    /// Port number used for record types other than `"SRV"` (ignored for `"SRV"`).
    #[serde(default, skip_serializing_if = "is_zero_port")]
    pub port: u16,
}

const fn is_zero_port(port: &u16) -> bool {
    *port == 0
}

impl Default for DnsSdConfig {
    fn default() -> Self {
        Self {
            names: Vec::new(),
            refresh_interval: default_refresh_interval(),
            record_type: default_record_type(),
            port: 0,
        }
    }
}

impl DnsSdConfig {
    /// Validates this configuration according to Prometheus `dns.SDConfig.UnmarshalYAML`.
    pub fn validate(&mut self) -> Result<(), DiscoveryError> {
        if self.names.is_empty() {
            return Err(DiscoveryError::InvalidConfig(
                "DNS-SD config must contain at least one SRV record name".to_owned(),
            ));
        }
        if self.record_type.is_empty() {
            self.record_type = default_record_type();
        }
        let parsed = DnsRecordType::parse(&self.record_type)?;
        if parsed != DnsRecordType::Srv && self.port == 0 {
            return Err(DiscoveryError::InvalidConfig(
                "a port is required in DNS-SD configs for all record types except SRV".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the parsed [`DnsRecordType`] after validation.
    pub fn parsed_record_type(&self) -> Result<DnsRecordType, DiscoveryError> {
        DnsRecordType::parse(&self.record_type)
    }
}

/// Parsed `/etc/resolv.conf` settings used for search-path DNS resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvConf {
    /// Nameserver socket addresses (default `127.0.0.1:53`).
    pub servers: Vec<SocketAddr>,
    /// Search domain suffixes.
    pub search: Vec<String>,
    /// Threshold of dots in a query name before initial absolute lookup (`ndots`, default `1`).
    pub ndots: usize,
    /// Per-query timeout (default `5s`).
    pub timeout: Duration,
}

impl Default for ResolvConf {
    fn default() -> Self {
        Self {
            servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            search: Vec::new(),
            ndots: 1,
            timeout: Duration::from_secs(5),
        }
    }
}

impl ResolvConf {
    /// Parses a `resolv.conf` file from disk, returning an I/O error if unreadable.
    pub fn from_file(path: &Path) -> Result<Self, DiscoveryError> {
        let content = fs::read_to_string(path)?;
        Ok(Self::parse(&content))
    }

    /// Parses the textual contents of an `/etc/resolv.conf` file.
    pub fn parse(content: &str) -> Self {
        let mut servers = Vec::new();
        let mut search = Vec::new();
        let mut ndots = 1usize;
        let mut timeout = Duration::from_secs(5);

        for raw_line in content.lines() {
            let line = raw_line.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(directive) = parts.next() else {
                continue;
            };
            match directive {
                "nameserver" => {
                    if let Some(addr_str) = parts.next() {
                        if let Ok(ip) = addr_str.parse::<IpAddr>() {
                            servers.push(SocketAddr::new(ip, 53));
                        } else if let Ok(sa) = addr_str.parse::<SocketAddr>() {
                            servers.push(sa);
                        }
                    }
                }
                "domain" => {
                    search.clear();
                    if let Some(dom) = parts.next() {
                        let clean = dom.trim_end_matches('.');
                        if !clean.is_empty() {
                            search.push(clean.to_owned());
                        }
                    }
                }
                "search" => {
                    search.clear();
                    for dom in parts {
                        let clean = dom.trim_end_matches('.');
                        if !clean.is_empty() {
                            search.push(clean.to_owned());
                        }
                    }
                }
                "options" => {
                    for opt in parts {
                        if let Some(val) = opt.strip_prefix("ndots:") {
                            if let Ok(n) = val.parse::<usize>() {
                                ndots = n.min(15);
                            }
                        } else if let Some(val) = opt.strip_prefix("timeout:")
                            && let Ok(secs) = val.parse::<u64>()
                        {
                            timeout = Duration::from_secs(secs.clamp(1, 30));
                        }
                    }
                }
                _ => {}
            }
        }

        if servers.is_empty() {
            servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53));
        }

        Self {
            servers,
            search,
            ndots,
            timeout,
        }
    }
}

/// DNS service discovery runner matching Prometheus `discovery/dns.Discovery`.
#[derive(Clone, Debug)]
pub struct DnsDiscovery {
    config: DnsSdConfig,
    record_type: DnsRecordType,
    resolv_conf: Option<ResolvConf>,
}

impl DnsDiscovery {
    /// Creates a new [`DnsDiscovery`] after validating `config`, reading `/etc/resolv.conf` on each refresh.
    pub fn new(mut config: DnsSdConfig) -> Result<Self, DiscoveryError> {
        config.validate()?;
        let record_type = config.parsed_record_type()?;
        Ok(Self {
            config,
            record_type,
            resolv_conf: None,
        })
    }

    /// Creates a new [`DnsDiscovery`] with an explicit [`ResolvConf`].
    pub fn with_resolv_conf(
        mut config: DnsSdConfig,
        resolv_conf: ResolvConf,
    ) -> Result<Self, DiscoveryError> {
        config.validate()?;
        let record_type = config.parsed_record_type()?;
        Ok(Self {
            config,
            record_type,
            resolv_conf: Some(resolv_conf),
        })
    }

    /// Returns the validated [`DnsSdConfig`].
    pub fn config(&self) -> &DnsSdConfig {
        &self.config
    }

    /// Returns the explicit [`ResolvConf`] if configured via [`DnsDiscovery::with_resolv_conf`].
    pub fn resolv_conf(&self) -> Option<&ResolvConf> {
        self.resolv_conf.as_ref()
    }

    /// Performs a single discovery refresh using a caller-supplied synchronous lookup function.
    ///
    /// If the lookup function returns an empty record list (for example on `NXDOMAIN`), an empty
    /// [`TargetGroup`] with `source = name` is emitted so previously discovered targets for that
    /// source are cleared; if it returns `Err`, that name is skipped so previous targets are
    /// preserved while remaining names continue, matching Prometheus `dns.Discovery.refresh`.
    pub fn refresh_with<F>(&self, mut lookup_fn: F) -> Result<Vec<TargetGroup>, DiscoveryError>
    where
        F: FnMut(&str, DnsRecordType) -> Result<Vec<DnsRecord>, DiscoveryError>,
    {
        let mut groups = Vec::with_capacity(self.config.names.len());
        for name in &self.config.names {
            if let Ok(records) = lookup_fn(name, self.record_type) {
                groups.push(records_to_target_group(
                    name,
                    self.record_type,
                    self.config.port,
                    &records,
                ));
            }
        }
        Ok(groups)
    }
}

/// Converts a slice of resolved [`DnsRecord`]s for `name` into a Prometheus [`TargetGroup`],
/// matching `discovery/dns.Discovery.refreshOne`.
pub(crate) fn records_to_target_group(
    name: &str,
    record_type: DnsRecordType,
    default_port: u16,
    records: &[DnsRecord],
) -> TargetGroup {
    let mut targets = Vec::new();
    for record in records {
        let mut target_host_raw = String::new();
        let mut srv_target = String::new();
        let mut srv_port = String::new();
        let mut mx_target = String::new();
        let mut ns_target = String::new();
        let addr_port: u16;

        match (record_type, record) {
            (_, DnsRecord::Cname(_)) => continue,
            (DnsRecordType::Srv, DnsRecord::Srv { port, target, .. }) => {
                if !is_safe_domain_target(target) {
                    continue;
                }
                target_host_raw.clone_from(target);
                srv_target.clone_from(target);
                srv_port = port.to_string();
                addr_port = *port;
            }
            (DnsRecordType::Mx, DnsRecord::Mx { target, .. }) => {
                if !is_safe_domain_target(target) {
                    continue;
                }
                target_host_raw.clone_from(target);
                mx_target.clone_from(target);
                addr_port = default_port;
            }
            (DnsRecordType::Ns, DnsRecord::Ns { target }) => {
                if !is_safe_domain_target(target) {
                    continue;
                }
                target_host_raw.clone_from(target);
                ns_target.clone_from(target);
                addr_port = default_port;
            }
            (DnsRecordType::A, DnsRecord::A(ip)) => {
                target_host_raw = ip.to_string();
                addr_port = default_port;
            }
            (DnsRecordType::Aaaa, DnsRecord::Aaaa(ip)) => {
                target_host_raw = ip.to_string();
                addr_port = default_port;
            }
            _ => continue,
        }

        // Remove the trailing dot from rooted DNS names to make them look more usual.
        let host = target_host_raw.trim_end_matches('.');
        let address = join_host_port(host, &addr_port.to_string());

        let mut labels = LabelSet::new();
        labels.insert(ADDRESS_LABEL.to_owned(), address);
        labels.insert(DNS_NAME_LABEL.to_owned(), name.to_owned());
        labels.insert(DNS_SRV_RECORD_TARGET_LABEL.to_owned(), srv_target);
        labels.insert(DNS_SRV_RECORD_PORT_LABEL.to_owned(), srv_port);
        labels.insert(DNS_MX_RECORD_TARGET_LABEL.to_owned(), mx_target);
        labels.insert(DNS_NS_RECORD_TARGET_LABEL.to_owned(), ns_target);
        targets.push(labels);
    }

    TargetGroup {
        targets,
        labels: BTreeMap::new(),
        source: name.to_owned(),
    }
}

fn is_safe_dns_label(label: &str) -> bool {
    !label.bytes().any(|b| {
        b.is_ascii_control()
            || b.is_ascii_whitespace()
            || matches!(b, b'@' | b'/' | b'\\' | b'?' | b'#' | b':' | b'[' | b']')
    })
}

fn is_safe_domain_target(target: &str) -> bool {
    let trimmed = target.trim_end_matches('.');
    trimmed.is_empty() || trimmed.split('.').all(is_safe_dns_label)
}
