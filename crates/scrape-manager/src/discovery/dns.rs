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
use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::{
    ADDRESS_LABEL, DiscoveryError, LabelSet, TargetGroup, deserialize_null_default, join_host_port,
    serde_duration,
};

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

const QTYPE_A: u16 = 1;
const QTYPE_NS: u16 = 2;
const QTYPE_CNAME: u16 = 5;
const QTYPE_MX: u16 = 15;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SRV: u16 = 33;
const QTYPE_OPT: u16 = 41;
const QCLASS_IN: u16 = 1;

const RCODE_SUCCESS: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

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

    /// Returns the DNS wire protocol QTYPE code for this record type.
    const fn qtype(self) -> u16 {
        match self {
            Self::A => QTYPE_A,
            Self::Ns => QTYPE_NS,
            Self::Mx => QTYPE_MX,
            Self::Aaaa => QTYPE_AAAA,
            Self::Srv => QTYPE_SRV,
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

fn deserialize_refresh_interval<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Duration, D::Error> {
    serde_duration::deserialize_or(deserializer, default_refresh_interval())
}

fn deserialize_record_type<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_else(default_record_type))
}

/// DNS service discovery configuration matching Prometheus `discovery/dns.SDConfig`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSdConfig {
    /// DNS domain names to query.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub names: Vec<String>,
    /// Refresh interval between DNS lookups (defaults to `30s`).
    #[serde(
        default = "default_refresh_interval",
        serialize_with = "serde_duration::serialize",
        deserialize_with = "deserialize_refresh_interval"
    )]
    pub refresh_interval: Duration,
    /// DNS record type to query: `"SRV"` (default), `"A"`, `"AAAA"`, `"MX"`, or `"NS"`.
    #[serde(
        rename = "type",
        default = "default_record_type",
        deserialize_with = "deserialize_record_type"
    )]
    pub record_type: String,
    /// Port number used for record types other than `"SRV"` (ignored for `"SRV"`).
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "is_zero_port"
    )]
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

    /// Performs a single discovery refresh across all configured DNS names using the configured
    /// nameservers and search paths.
    ///
    /// Lookup failures for individual names are skipped so previously discovered targets for
    /// those sources are preserved while healthy names still emit [`TargetGroup`]s, matching
    /// Prometheus `dns.Discovery.refresh`.
    pub async fn refresh(&self) -> Result<Vec<TargetGroup>, DiscoveryError> {
        let owned_conf;
        let conf = match &self.resolv_conf {
            Some(c) => c,
            None => {
                owned_conf = ResolvConf::from_file(Path::new("/etc/resolv.conf"))?;
                &owned_conf
            }
        };
        let mut groups = Vec::with_capacity(self.config.names.len());
        for name in &self.config.names {
            if let Ok(records) = self.lookup_with_search_path(name, conf).await {
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

    async fn lookup_with_search_path(
        &self,
        name: &str,
        resolv_conf: &ResolvConf,
    ) -> Result<Vec<DnsRecord>, DiscoveryError> {
        let candidates = candidate_query_names(name, resolv_conf);
        let mut last_err: Option<DiscoveryError> = None;

        for candidate in &candidates {
            match self.lookup_all_servers(candidate, resolv_conf).await {
                Ok(Some(records)) => return Ok(records),
                Ok(None) => {
                    // NXDOMAIN: continue trying remaining search path candidates, and if none
                    // match, return an empty target group (matching Prometheus).
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if let Some(err) = last_err {
            Err(err)
        } else {
            Ok(Vec::new())
        }
    }

    async fn lookup_all_servers(
        &self,
        fqdn: &str,
        resolv_conf: &ResolvConf,
    ) -> Result<Option<Vec<DnsRecord>>, DiscoveryError> {
        let qtype = self.record_type.qtype();
        let mut last_err = None;

        for &server in &resolv_conf.servers {
            match query_dns_server(server, fqdn, qtype, resolv_conf.timeout).await {
                Ok(DnsLookupOutcome::Records(records)) => return Ok(Some(records)),
                Ok(DnsLookupOutcome::NxDomain) => return Ok(None),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err
            .unwrap_or_else(|| DiscoveryError::Dns("no DNS nameservers configured".to_owned())))
    }
}

/// Converts a slice of resolved [`DnsRecord`]s for `name` into a Prometheus [`TargetGroup`],
/// matching `discovery/dns.Discovery.refreshOne`.
fn records_to_target_group(
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

fn candidate_query_names(name: &str, conf: &ResolvConf) -> Vec<String> {
    if name.ends_with('.') {
        return vec![name.to_owned()];
    }
    let dots = name.bytes().filter(|&b| b == b'.').count();
    let mut search_names: Vec<String> = conf
        .search
        .iter()
        .map(|domain| domain.trim_end_matches('.'))
        .filter(|domain| !domain.is_empty())
        .map(|domain| format!("{name}.{domain}."))
        .filter(|cand| wire_qname_len(cand).is_some_and(|n| n <= 255))
        .collect();
    let rooted = format!("{name}.");

    if dots >= conf.ndots {
        let mut out = Vec::with_capacity(1 + search_names.len());
        out.push(rooted);
        out.extend(search_names);
        out
    } else {
        search_names.push(rooted);
        search_names
    }
}

fn wire_qname_len(fqdn: &str) -> Option<usize> {
    let trimmed = fqdn.strip_suffix('.').unwrap_or(fqdn);
    if trimmed.is_empty() {
        return Some(1);
    }
    let mut len = 1usize;
    for label in trimmed.split('.') {
        if !is_safe_dns_label(label) {
            return None;
        }
        len += 1 + label.len();
    }
    Some(len)
}

fn is_safe_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.bytes().any(|b| {
            b.is_ascii_control()
                || b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'.' | b'@' | b'/' | b'\\' | b'?' | b'#' | b':' | b'[' | b']'
                )
        })
}

fn is_safe_domain_target(target: &str) -> bool {
    let trimmed = target.strip_suffix('.').unwrap_or(target);
    trimmed.is_empty() || trimmed.split('.').all(is_safe_dns_label)
}

enum DnsLookupOutcome {
    Records(Vec<DnsRecord>),
    NxDomain,
}

fn next_dns_txid() -> u16 {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    RandomState::new().hash_one(n) as u16
}

async fn query_dns_server(
    server: SocketAddr,
    fqdn: &str,
    qtype: u16,
    timeout: Duration,
) -> Result<DnsLookupOutcome, DiscoveryError> {
    let udp_id = next_dns_txid();
    let query_pkt = encode_dns_query(udp_id, fqdn, qtype, true)?;
    let bind_addr = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let udp = UdpSocket::bind(bind_addr).await?;
    udp.connect(server).await?;
    udp.send(&query_pkt).await?;

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(timeout, udp.recv(&mut buf))
        .await
        .map_err(|_| DiscoveryError::Dns(format!("DNS UDP read timeout from {server}")))??;
    match decode_dns_response(udp_id, fqdn, qtype, &buf[..len])? {
        DecodedDnsMessage::Truncated => {}
        DecodedDnsMessage::NxDomain => return Ok(DnsLookupOutcome::NxDomain),
        DecodedDnsMessage::Records(records) => return Ok(DnsLookupOutcome::Records(records)),
    }

    // Fallback to TCP on TC=1 truncation bit without EDNS0 OPT, matching Prometheus askServerForName.
    let tcp_id = next_dns_txid();
    let tcp_query_pkt = encode_dns_query(tcp_id, fqdn, qtype, false)?;
    let tcp_query_len = u16::try_from(tcp_query_pkt.len())
        .map_err(|_| DiscoveryError::Dns("DNS TCP query packet exceeds u16 length".to_owned()))?;
    let resp_buf = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_all(&tcp_query_len.to_be_bytes()).await?;
        stream.write_all(&tcp_query_pkt).await?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        Ok::<Vec<u8>, std::io::Error>(resp_buf)
    })
    .await
    .map_err(|_| DiscoveryError::Dns(format!("DNS TCP exchange timeout with {server}")))??;

    match decode_dns_response(tcp_id, fqdn, qtype, &resp_buf)? {
        DecodedDnsMessage::Truncated => Err(DiscoveryError::Dns(
            "truncated DNS response over TCP".to_owned(),
        )),
        DecodedDnsMessage::NxDomain => Ok(DnsLookupOutcome::NxDomain),
        DecodedDnsMessage::Records(records) => Ok(DnsLookupOutcome::Records(records)),
    }
}

/// Encodes an RFC 1035 DNS wire query message, optionally including an EDNS0 OPT pseudo-record
/// (4096-byte UDP payload).
fn encode_dns_query(
    id: u16,
    fqdn: &str,
    qtype: u16,
    edns: bool,
) -> Result<Vec<u8>, DiscoveryError> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&id.to_be_bytes());
    // Flags: RD=1 (recursion desired, 0x0100).
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 1 when EDNS0 is enabled.
    let arcount: u16 = u16::from(edns);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&arcount.to_be_bytes());

    let trimmed = fqdn.strip_suffix('.').unwrap_or(fqdn);
    let mut wire_qname_len = 1usize;
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if !is_safe_dns_label(label) {
                return Err(DiscoveryError::Dns(format!(
                    "invalid DNS label in query name {fqdn:?}"
                )));
            }
            wire_qname_len += 1 + label.len();
            if wire_qname_len > 255 {
                return Err(DiscoveryError::Dns(format!(
                    "DNS query name {fqdn:?} exceeds 255 octets"
                )));
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

    if edns {
        // EDNS0 OPT record: root name (0), TYPE = 41 (OPT), CLASS = 4096 (UDP payload size),
        // TTL = 0, RDLENGTH = 0.
        pkt.push(0);
        pkt.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        pkt.extend_from_slice(&4096u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
    }

    Ok(pkt)
}

enum DecodedDnsMessage {
    Records(Vec<DnsRecord>),
    NxDomain,
    Truncated,
}

fn canonical_fqdn(fqdn: &str) -> String {
    let trimmed = fqdn.strip_suffix('.').unwrap_or(fqdn);
    if trimmed.is_empty() {
        ".".to_owned()
    } else {
        format!("{trimmed}.")
    }
}

fn decode_dns_response(
    expected_id: u16,
    expected_qname: &str,
    expected_qtype: u16,
    msg: &[u8],
) -> Result<DecodedDnsMessage, DiscoveryError> {
    if msg.len() < 12 {
        return Err(DiscoveryError::Dns("DNS response too short".to_owned()));
    }
    let resp_id = u16::from_be_bytes([msg[0], msg[1]]);
    if resp_id != expected_id {
        return Err(DiscoveryError::Dns(format!(
            "DNS response transaction ID mismatch: expected {expected_id:#06x}, got {resp_id:#06x}"
        )));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if (flags & 0x8000) == 0 {
        return Err(DiscoveryError::Dns(
            "DNS packet is a query (QR=0), expected response (QR=1)".to_owned(),
        ));
    }
    let tc = (flags & 0x0200) != 0;
    if tc {
        return Ok(DecodedDnsMessage::Truncated);
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;
    if qdcount != 1 {
        return Err(DiscoveryError::Dns(format!(
            "unexpected DNS question count {qdcount}, expected 1"
        )));
    }

    let (qname, next) = decode_dns_name(msg, 12)?;
    if next + 4 > msg.len() {
        return Err(DiscoveryError::Dns("truncated DNS question".to_owned()));
    }
    let qtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
    let qclass = u16::from_be_bytes([msg[next + 2], msg[next + 3]]);
    let want_qname = canonical_fqdn(expected_qname);
    if !qname.eq_ignore_ascii_case(&want_qname) || qtype != expected_qtype || qclass != QCLASS_IN {
        return Err(DiscoveryError::Dns(format!(
            "DNS response question mismatch: expected ({want_qname}, {expected_qtype}, {QCLASS_IN}), got ({qname}, {qtype}, {qclass})"
        )));
    }
    let mut offset = next + 4;

    let rcode = (flags & 0x000F) as u8;
    if rcode == RCODE_NXDOMAIN {
        return Ok(DecodedDnsMessage::NxDomain);
    }
    if rcode != RCODE_SUCCESS {
        return Err(DiscoveryError::Dns(format!(
            "DNS response returned non-zero RCODE {rcode}"
        )));
    }

    // Each resource record requires at least 1 byte for a root/pointer name plus 10 header bytes.
    let max_possible_rrs = msg.len().saturating_sub(offset) / 11;
    let mut records = Vec::with_capacity(ancount.min(max_possible_rrs));
    for _ in 0..ancount {
        let (_, next) = decode_dns_name(msg, offset)?;
        if next + 10 > msg.len() {
            return Err(DiscoveryError::Dns(
                "truncated DNS resource record header".to_owned(),
            ));
        }
        let rtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
        let rclass = u16::from_be_bytes([msg[next + 2], msg[next + 3]]);
        let rdlength = u16::from_be_bytes([msg[next + 8], msg[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlength;
        if rdata_end > msg.len() {
            return Err(DiscoveryError::Dns(
                "truncated DNS resource record rdata".to_owned(),
            ));
        }
        if rclass != QCLASS_IN {
            offset = rdata_end;
            continue;
        }
        let rdata = &msg[rdata_start..rdata_end];

        match rtype {
            QTYPE_A => {
                if rdata.len() != 4 {
                    return Err(DiscoveryError::Dns("invalid A record length".to_owned()));
                }
                records.push(DnsRecord::A(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            QTYPE_AAAA => {
                if rdata.len() != 16 {
                    return Err(DiscoveryError::Dns("invalid AAAA record length".to_owned()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                records.push(DnsRecord::Aaaa(Ipv6Addr::from(octets)));
            }
            QTYPE_SRV => {
                if rdata.len() < 7 {
                    return Err(DiscoveryError::Dns("invalid SRV record length".to_owned()));
                }
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let (target, next_rdata) =
                    decode_dns_name_bounded(msg, rdata_start + 6, rdata_end)?;
                if next_rdata != rdata_end {
                    return Err(DiscoveryError::Dns("invalid SRV record length".to_owned()));
                }
                records.push(DnsRecord::Srv {
                    priority,
                    weight,
                    port,
                    target,
                });
            }
            QTYPE_MX => {
                if rdata.len() < 3 {
                    return Err(DiscoveryError::Dns("invalid MX record length".to_owned()));
                }
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (target, next_rdata) =
                    decode_dns_name_bounded(msg, rdata_start + 2, rdata_end)?;
                if next_rdata != rdata_end {
                    return Err(DiscoveryError::Dns("invalid MX record length".to_owned()));
                }
                records.push(DnsRecord::Mx { preference, target });
            }
            QTYPE_NS => {
                let (target, next_rdata) = decode_dns_name_bounded(msg, rdata_start, rdata_end)?;
                if next_rdata != rdata_end {
                    return Err(DiscoveryError::Dns("invalid NS record length".to_owned()));
                }
                records.push(DnsRecord::Ns { target });
            }
            QTYPE_CNAME => {
                let (target, next_rdata) = decode_dns_name_bounded(msg, rdata_start, rdata_end)?;
                if next_rdata != rdata_end {
                    return Err(DiscoveryError::Dns(
                        "invalid CNAME record length".to_owned(),
                    ));
                }
                records.push(DnsRecord::Cname(target));
            }
            _ => {}
        }

        offset = rdata_end;
    }

    for _ in 0..nscount.saturating_add(arcount) {
        let (_, next) = decode_dns_name(msg, offset)?;
        if next + 10 > msg.len() {
            return Err(DiscoveryError::Dns(
                "truncated DNS resource record header".to_owned(),
            ));
        }
        let rtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
        let rdlength = u16::from_be_bytes([msg[next + 8], msg[next + 9]]) as usize;
        let rdata_end = next + 10 + rdlength;
        if rdata_end > msg.len() {
            return Err(DiscoveryError::Dns(
                "truncated DNS resource record rdata".to_owned(),
            ));
        }
        if rtype == QTYPE_OPT && msg[next + 4] != 0 {
            let ext_rcode = ((msg[next + 4] as u16) << 4) | (rcode as u16);
            return Err(DiscoveryError::Dns(format!(
                "DNS response returned non-zero extended RCODE {ext_rcode}"
            )));
        }
        offset = rdata_end;
    }

    Ok(DecodedDnsMessage::Records(records))
}

fn decode_dns_name(msg: &[u8], offset: usize) -> Result<(String, usize), DiscoveryError> {
    decode_dns_name_bounded(msg, offset, msg.len())
}

fn decode_dns_name_bounded(
    msg: &[u8],
    mut offset: usize,
    inline_bound: usize,
) -> Result<(String, usize), DiscoveryError> {
    let mut labels = Vec::new();
    let mut end_offset = None;
    let mut jumps = 0usize;
    let mut total_len = 1usize;

    loop {
        let active_bound = if end_offset.is_none() {
            inline_bound
        } else {
            msg.len()
        };
        if offset >= active_bound {
            return Err(DiscoveryError::Dns(
                "unexpected EOF while decoding DNS domain name".to_owned(),
            ));
        }
        let len = msg[offset];
        if len == 0 {
            let final_offset = end_offset.unwrap_or(offset + 1);
            let fqdn = if labels.is_empty() {
                ".".to_owned()
            } else {
                let mut s = labels.join(".");
                s.push('.');
                s
            };
            return Ok((fqdn, final_offset));
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= active_bound {
                return Err(DiscoveryError::Dns(
                    "truncated DNS name compression pointer".to_owned(),
                ));
            }
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (msg[offset + 1] as usize);
            if ptr < 12 || ptr >= msg.len() {
                return Err(DiscoveryError::Dns(
                    "DNS name compression pointer out of bounds".to_owned(),
                ));
            }
            offset = ptr;
            jumps += 1;
            if jumps > 64 {
                return Err(DiscoveryError::Dns(
                    "DNS name compression pointer loop detected".to_owned(),
                ));
            }
            continue;
        }
        if (len & 0xC0) != 0 {
            return Err(DiscoveryError::Dns(
                "invalid DNS label length byte".to_owned(),
            ));
        }
        let label_len = len as usize;
        let start = offset + 1;
        let end = start + label_len;
        if end > active_bound {
            return Err(DiscoveryError::Dns("truncated DNS label".to_owned()));
        }
        total_len += label_len + 1;
        if total_len > 255 {
            return Err(DiscoveryError::Dns(
                "DNS domain name exceeds 255 bytes".to_owned(),
            ));
        }
        let label = std::str::from_utf8(&msg[start..end])
            .map_err(|e| DiscoveryError::Dns(format!("non-UTF-8 DNS label: {e}")))?;
        if !is_safe_dns_label(label) {
            return Err(DiscoveryError::Dns(format!(
                "unsafe character in DNS label {label:?}"
            )));
        }
        labels.push(label.to_owned());
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_dns_response_compression_pointers_and_rdata_bounds() {
        // Build a response with QDCOUNT=1 (`_http._tcp.example.com.`) at offset 12,
        // where `example.com.` starts at offset 23 (12 + 6 ("_http") + 5 ("_tcp") = 23).
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x5052u16.to_be_bytes()); // ID
        pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2 (CNAME + SRV)
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());

        // Question: _http._tcp.example.com.
        for label in ["_http", "_tcp", "example", "com"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&QTYPE_SRV.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

        // Answer 1: CNAME with owner pointer 0xC00C -> `alias` + pointer 0xC017 (`example.com.`)
        pkt.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        pkt.extend_from_slice(&QTYPE_CNAME.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&60u32.to_be_bytes());
        let cname_rdata = [5, b'a', b'l', b'i', b'a', b's', 0xC0, 0x17];
        pkt.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&cname_rdata);

        // Answer 2: SRV with owner pointer 0xC00C -> target `node1` + pointer 0xC017 (`example.com.`)
        pkt.extend_from_slice(&[0xC0, 0x0C]);
        pkt.extend_from_slice(&QTYPE_SRV.to_be_bytes());
        pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        pkt.extend_from_slice(&60u32.to_be_bytes());
        let mut srv_rdata = Vec::new();
        srv_rdata.extend_from_slice(&10u16.to_be_bytes());
        srv_rdata.extend_from_slice(&20u16.to_be_bytes());
        srv_rdata.extend_from_slice(&8080u16.to_be_bytes());
        srv_rdata.extend_from_slice(&[5, b'n', b'o', b'd', b'e', b'1', 0xC0, 0x17]);
        pkt.extend_from_slice(&(srv_rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&srv_rdata);

        let DecodedDnsMessage::Records(records) =
            decode_dns_response(0x5052, "_http._tcp.example.com.", QTYPE_SRV, &pkt).unwrap()
        else {
            panic!("expected decoded DNS records");
        };
        assert_eq!(
            records,
            vec![
                DnsRecord::Cname("alias.example.com.".to_owned()),
                DnsRecord::Srv {
                    priority: 10,
                    weight: 20,
                    port: 8080,
                    target: "node1.example.com.".to_owned(),
                },
            ]
        );

        // Wrong transaction ID or mismatched question is rejected.
        assert!(decode_dns_response(0x1234, "_http._tcp.example.com.", QTYPE_SRV, &pkt).is_err());
        assert!(decode_dns_response(0x5052, "_other._tcp.example.com.", QTYPE_SRV, &pkt).is_err());
        assert!(decode_dns_response(0x5052, "_http._tcp.example.com.", QTYPE_A, &pkt).is_err());

        // Malformed NS record with RDLENGTH=0 followed by trailing root byte must fail instead of reading past RDATA.
        let mut bad_ns = Vec::new();
        bad_ns.extend_from_slice(&0x5052u16.to_be_bytes());
        bad_ns.extend_from_slice(&0x8180u16.to_be_bytes());
        bad_ns.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        bad_ns.extend_from_slice(&1u16.to_be_bytes());
        bad_ns.extend_from_slice(&0u16.to_be_bytes());
        bad_ns.extend_from_slice(&1u16.to_be_bytes());
        bad_ns.push(0); // question: root
        bad_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        bad_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        bad_ns.push(0); // owner: root
        bad_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        bad_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        bad_ns.extend_from_slice(&60u32.to_be_bytes());
        bad_ns.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0 (invalid for NS)
        bad_ns.push(0); // trailing OPT root name byte
        assert!(decode_dns_response(0x5052, ".", QTYPE_NS, &bad_ns).is_err());

        // QR=0 query packet is rejected.
        let query_pkt = encode_dns_query(0x5052, "example.com.", QTYPE_A, true).unwrap();
        assert!(decode_dns_response(0x5052, "example.com.", QTYPE_A, &query_pkt).is_err());

        // EDNS0 controls ARCOUNT (1 vs 0), and >255-octet or unsafe QNAMEs are rejected.
        let no_edns_pkt = encode_dns_query(0x5052, "example.com.", QTYPE_A, false).unwrap();
        assert_eq!(u16::from_be_bytes([query_pkt[10], query_pkt[11]]), 1);
        assert_eq!(u16::from_be_bytes([no_edns_pkt[10], no_edns_pkt[11]]), 0);
        let overlong_qname = format!("{}.", vec!["a".repeat(60); 5].join("."));
        assert!(encode_dns_query(1, &overlong_qname, QTYPE_A, true).is_err());
        assert!(encode_dns_query(1, &"a".repeat(64), QTYPE_A, true).is_err());
        assert!(encode_dns_query(1, "bad@host.example.com.", QTYPE_A, true).is_err());

        // Compression pointer loop (self-pointer at offset 12) is rejected.
        let mut loop_pkt = Vec::new();
        loop_pkt.extend_from_slice(&0x5052u16.to_be_bytes());
        loop_pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        loop_pkt.extend_from_slice(&1u16.to_be_bytes());
        loop_pkt.extend_from_slice(&0u16.to_be_bytes());
        loop_pkt.extend_from_slice(&0u16.to_be_bytes());
        loop_pkt.extend_from_slice(&0u16.to_be_bytes());
        loop_pkt.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert!(decode_dns_response(0x5052, "example.com.", QTYPE_A, &loop_pkt).is_err());

        // Out-of-bounds compression pointer is rejected.
        let mut oob_pkt = loop_pkt.clone();
        oob_pkt[12] = 0xC0;
        oob_pkt[13] = 0xFF;
        assert!(decode_dns_response(0x5052, "example.com.", QTYPE_A, &oob_pkt).is_err());

        // Unsafe characters in decoded SRV/NS target hostnames are rejected.
        let mut unsafe_ns = Vec::new();
        unsafe_ns.extend_from_slice(&0x5052u16.to_be_bytes());
        unsafe_ns.extend_from_slice(&0x8180u16.to_be_bytes());
        unsafe_ns.extend_from_slice(&1u16.to_be_bytes());
        unsafe_ns.extend_from_slice(&1u16.to_be_bytes());
        unsafe_ns.extend_from_slice(&0u16.to_be_bytes());
        unsafe_ns.extend_from_slice(&0u16.to_be_bytes());
        unsafe_ns.push(0);
        unsafe_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        unsafe_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        unsafe_ns.push(0);
        unsafe_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        unsafe_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        unsafe_ns.extend_from_slice(&60u32.to_be_bytes());
        let bad_target = b"\x0bad@evil.com\x00";
        unsafe_ns.extend_from_slice(&(bad_target.len() as u16).to_be_bytes());
        unsafe_ns.extend_from_slice(bad_target);
        assert!(decode_dns_response(0x5052, ".", QTYPE_NS, &unsafe_ns).is_err());

        // Trailing extra byte inside NS RDATA is rejected.
        let mut trailing_ns = Vec::new();
        trailing_ns.extend_from_slice(&0x5052u16.to_be_bytes());
        trailing_ns.extend_from_slice(&0x8180u16.to_be_bytes());
        trailing_ns.extend_from_slice(&1u16.to_be_bytes());
        trailing_ns.extend_from_slice(&1u16.to_be_bytes());
        trailing_ns.extend_from_slice(&0u16.to_be_bytes());
        trailing_ns.extend_from_slice(&0u16.to_be_bytes());
        trailing_ns.push(0);
        trailing_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        trailing_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        trailing_ns.push(0);
        trailing_ns.extend_from_slice(&QTYPE_NS.to_be_bytes());
        trailing_ns.extend_from_slice(&QCLASS_IN.to_be_bytes());
        trailing_ns.extend_from_slice(&60u32.to_be_bytes());
        trailing_ns.extend_from_slice(&5u16.to_be_bytes());
        trailing_ns.extend_from_slice(b"\x02ns\x00\x00");
        assert!(decode_dns_response(0x5052, ".", QTYPE_NS, &trailing_ns).is_err());

        // candidate_query_names honors ndots ordering, trailing dot, and 255-octet search filtering.
        let conf = ResolvConf {
            servers: ResolvConf::default().servers,
            search: vec![
                "svc.cluster.local".to_owned(),
                vec!["x".repeat(60); 5].join("."),
            ],
            ndots: 2,
            timeout: Duration::from_secs(5),
        };
        assert_eq!(
            candidate_query_names("api.ns", &conf),
            vec!["api.ns.svc.cluster.local.", "api.ns."]
        );
        assert_eq!(
            candidate_query_names("a.b.c", &conf),
            vec!["a.b.c.", "a.b.c.svc.cluster.local."]
        );
        assert_eq!(candidate_query_names("rooted.", &conf), vec!["rooted."]);

        // Decode AAAA, MX, NS, non-IN class (skipped), unknown RR type (skipped), and EDNS0 OPT=0.
        let mut multi_pkt = Vec::new();
        multi_pkt.extend_from_slice(&0x5052u16.to_be_bytes());
        multi_pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        multi_pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        multi_pkt.extend_from_slice(&5u16.to_be_bytes()); // ANCOUNT=5 (AAAA, MX, NS, CH-class A, TXT)
        multi_pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        multi_pkt.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT=1 (EDNS0 OPT)
        multi_pkt.push(0); // question: root "."
        multi_pkt.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        multi_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

        // Answer 1: AAAA 2001:db8::1
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
        multi_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        multi_pkt.extend_from_slice(&60u32.to_be_bytes());
        multi_pkt.extend_from_slice(&16u16.to_be_bytes());
        multi_pkt.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());

        // Answer 2: MX 10 mx.local.
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&QTYPE_MX.to_be_bytes());
        multi_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        multi_pkt.extend_from_slice(&60u32.to_be_bytes());
        let mx_rdata = b"\x00\x0a\x02mx\x05local\x00";
        multi_pkt.extend_from_slice(&(mx_rdata.len() as u16).to_be_bytes());
        multi_pkt.extend_from_slice(mx_rdata);

        // Answer 3: NS ns.local.
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&QTYPE_NS.to_be_bytes());
        multi_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        multi_pkt.extend_from_slice(&60u32.to_be_bytes());
        let ns_rdata = b"\x02ns\x05local\x00";
        multi_pkt.extend_from_slice(&(ns_rdata.len() as u16).to_be_bytes());
        multi_pkt.extend_from_slice(ns_rdata);

        // Answer 4: non-IN class (CH = 3) A record -> skipped
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&QTYPE_A.to_be_bytes());
        multi_pkt.extend_from_slice(&3u16.to_be_bytes());
        multi_pkt.extend_from_slice(&60u32.to_be_bytes());
        multi_pkt.extend_from_slice(&4u16.to_be_bytes());
        multi_pkt.extend_from_slice(&[127, 0, 0, 1]);

        // Answer 5: TXT (16) -> skipped
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&16u16.to_be_bytes());
        multi_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        multi_pkt.extend_from_slice(&60u32.to_be_bytes());
        multi_pkt.extend_from_slice(&1u16.to_be_bytes());
        multi_pkt.push(0);

        // Additional 1: EDNS0 OPT with extended RCODE = 0
        multi_pkt.push(0);
        multi_pkt.extend_from_slice(&QTYPE_OPT.to_be_bytes());
        multi_pkt.extend_from_slice(&4096u16.to_be_bytes());
        multi_pkt.extend_from_slice(&0u32.to_be_bytes());
        multi_pkt.extend_from_slice(&0u16.to_be_bytes());

        let DecodedDnsMessage::Records(multi_records) =
            decode_dns_response(0x5052, ".", QTYPE_AAAA, &multi_pkt).unwrap()
        else {
            panic!("expected decoded multi records");
        };
        assert_eq!(
            multi_records,
            vec![
                DnsRecord::Aaaa("2001:db8::1".parse().unwrap()),
                DnsRecord::Mx {
                    preference: 10,
                    target: "mx.local.".to_owned(),
                },
                DnsRecord::Ns {
                    target: "ns.local.".to_owned(),
                },
            ]
        );

        // EDNS0 extended RCODE (e.g. BADVERS = 16 -> upper 8 bits = 1) in OPT record is rejected.
        let opt_ttl_offset = multi_pkt.len() - 6;
        multi_pkt[opt_ttl_offset] = 1;
        assert!(decode_dns_response(0x5052, ".", QTYPE_AAAA, &multi_pkt).is_err());

        // Header pointer (< 12) and wire label containing embedded '.' are rejected.
        let mut hdr_ptr_pkt = loop_pkt.clone();
        hdr_ptr_pkt[12] = 0xC0;
        hdr_ptr_pkt[13] = 0x04;
        assert!(decode_dns_response(0x5052, "example.com.", QTYPE_A, &hdr_ptr_pkt).is_err());

        let mut dot_label_pkt = Vec::new();
        dot_label_pkt.extend_from_slice(&0x5052u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(&1u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(&0u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(&0u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(&0u16.to_be_bytes());
        dot_label_pkt.extend_from_slice(b"\x07foo.bar\x03com\x00");
        dot_label_pkt.extend_from_slice(&QTYPE_A.to_be_bytes());
        dot_label_pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert!(decode_dns_response(0x5052, "foo.bar.com.", QTYPE_A, &dot_label_pkt).is_err());
    }
}
