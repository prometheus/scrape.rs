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

//! Prometheus-compatible `HTTPClientConfig` schema, validation, and `reqwest` client helpers.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const REDACTED_SECRET: &str = "<secret>";

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "host",
    "content-encoding",
    "content-length",
    "content-type",
    "user-agent",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    "accept-encoding",
    "x-prometheus-remote-write-version",
    "x-prometheus-remote-read-version",
    "x-prometheus-scrape-timeout-seconds",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
];

const fn default_true() -> bool {
    true
}

/// Error returned when validating or constructing an [`HttpClientConfig`].
#[derive(Debug, thiserror::Error)]
pub enum HttpConfigError {
    /// Configuration validation failed.
    #[error("{0}")]
    InvalidConfig(String),
    /// I/O error reading a referenced credentials, certificate, or header file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP client construction error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// TLS protocol version matching Prometheus `config.TLSVersion`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.0 (`"TLS10"`).
    Tls10,
    /// TLS 1.1 (`"TLS11"`).
    Tls11,
    /// TLS 1.2 (`"TLS12"`).
    Tls12,
    /// TLS 1.3 (`"TLS13"`).
    Tls13,
}

impl TlsVersion {
    /// Returns the Prometheus string identifier for this TLS version.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls10 => "TLS10",
            Self::Tls11 => "TLS11",
            Self::Tls12 => "TLS12",
            Self::Tls13 => "TLS13",
        }
    }

    const fn to_reqwest(self) -> reqwest::tls::Version {
        match self {
            Self::Tls10 => reqwest::tls::Version::TLS_1_0,
            Self::Tls11 => reqwest::tls::Version::TLS_1_1,
            Self::Tls12 => reqwest::tls::Version::TLS_1_2,
            Self::Tls13 => reqwest::tls::Version::TLS_1_3,
        }
    }
}

impl Serialize for TlsVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TlsVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "TLS10" => Ok(Self::Tls10),
            "TLS11" => Ok(Self::Tls11),
            "TLS12" => Ok(Self::Tls12),
            "TLS13" => Ok(Self::Tls13),
            _ => Err(serde::de::Error::custom(format!(
                "unknown TLS version: {s}"
            ))),
        }
    }
}

/// HTTP Basic authentication configuration matching Prometheus `config.BasicAuth`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    /// Inline HTTP basic auth username.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Path to file containing the HTTP basic auth username.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username_file: String,
    /// Secret manager reference for the HTTP basic auth username.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username_ref: String,
    /// Inline HTTP basic auth password.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub password: String,
    /// Path to file containing the HTTP basic auth password.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_file: String,
    /// Secret manager reference for the HTTP basic auth password.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_ref: String,
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("username", &self.username)
            .field("username_file", &self.username_file)
            .field("username_ref", &self.username_ref)
            .field("password", &redact_str(&self.password))
            .field("password_file", &self.password_file)
            .field("password_ref", &self.password_ref)
            .finish()
    }
}

impl BasicAuth {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.username_file = join_dir(dir, &self.username_file);
        self.password_file = join_dir(dir, &self.password_file);
    }

    fn resolve_username(&self) -> Result<String, HttpConfigError> {
        if !self.username_file.is_empty() {
            Ok(fs::read_to_string(&self.username_file)?.trim().to_owned())
        } else {
            Ok(self.username.clone())
        }
    }

    fn resolve_password(&self) -> Result<String, HttpConfigError> {
        if !self.password_file.is_empty() {
            Ok(fs::read_to_string(&self.password_file)?.trim().to_owned())
        } else {
            Ok(self.password.clone())
        }
    }
}

/// HTTP `Authorization` header configuration matching Prometheus `config.Authorization`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    /// Authentication scheme type (defaults to `"Bearer"`).
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub auth_type: String,
    /// Inline credentials token.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub credentials: String,
    /// Path to file containing the credentials token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credentials_file: String,
    /// Secret manager reference for the credentials token.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credentials_ref: String,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("auth_type", &self.auth_type)
            .field("credentials", &redact_str(&self.credentials))
            .field("credentials_file", &self.credentials_file)
            .field("credentials_ref", &self.credentials_ref)
            .finish()
    }
}

impl Authorization {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.credentials_file = join_dir(dir, &self.credentials_file);
    }

    fn resolve_header_value(&self) -> Result<Option<String>, HttpConfigError> {
        let creds = if !self.credentials_file.is_empty() {
            fs::read_to_string(&self.credentials_file)?
                .trim()
                .to_owned()
        } else {
            self.credentials.trim().to_owned()
        };
        if creds.is_empty() {
            return Ok(None);
        }
        let scheme = if self.auth_type.trim().is_empty() {
            "Bearer"
        } else {
            self.auth_type.trim()
        };
        Ok(Some(format!("{scheme} {creds}")))
    }
}

/// TLS connection configuration matching Prometheus `config.TLSConfig`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Inline CA certificate PEM text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca: String,
    /// Inline client certificate PEM text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert: String,
    /// Inline client private key PEM text.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub key: String,
    /// Path to CA certificate PEM file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_file: String,
    /// Path to client certificate PEM file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_file: String,
    /// Path to client private key PEM file.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_file: String,
    /// Secret manager reference for CA certificate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_ref: String,
    /// Secret manager reference for client certificate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_ref: String,
    /// Secret manager reference for client private key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_ref: String,
    /// ServerName used to verify the hostname on returned certificates.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    /// Disables target certificate validation.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Minimum acceptable TLS version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
    /// Maximum acceptable TLS version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<TlsVersion>,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("ca", &self.ca)
            .field("cert", &self.cert)
            .field("key", &redact_str(&self.key))
            .field("ca_file", &self.ca_file)
            .field("cert_file", &self.cert_file)
            .field("key_file", &self.key_file)
            .field("ca_ref", &self.ca_ref)
            .field("cert_ref", &self.cert_ref)
            .field("key_ref", &self.key_ref)
            .field("server_name", &self.server_name)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .finish()
    }
}

impl TlsConfig {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.ca_file = join_dir(dir, &self.ca_file);
        self.cert_file = join_dir(dir, &self.cert_file);
        self.key_file = join_dir(dir, &self.key_file);
    }

    /// Validates this TLS configuration according to Prometheus `TLSConfig.Validate`.
    pub fn validate(&self) -> Result<(), HttpConfigError> {
        if non_empty_count(&[&self.ca, &self.ca_file, &self.ca_ref]) > 1 {
            return Err(HttpConfigError::InvalidConfig(
                "at most one of ca, ca_file & ca_ref must be configured".to_owned(),
            ));
        }
        if non_empty_count(&[&self.cert, &self.cert_file, &self.cert_ref]) > 1 {
            return Err(HttpConfigError::InvalidConfig(
                "at most one of cert, cert_file & cert_ref must be configured".to_owned(),
            ));
        }
        if non_empty_count(&[&self.key, &self.key_file, &self.key_ref]) > 1 {
            return Err(HttpConfigError::InvalidConfig(
                "at most one of key and key_file must be configured".to_owned(),
            ));
        }
        if self.using_client_cert() && !self.using_client_key() {
            return Err(HttpConfigError::InvalidConfig(
                "exactly one of key or key_file must be configured when a client certificate is configured".to_owned(),
            ));
        }
        if self.using_client_key() && !self.using_client_cert() {
            return Err(HttpConfigError::InvalidConfig(
                "exactly one of cert or cert_file must be configured when a client key is configured".to_owned(),
            ));
        }
        if let (Some(min), Some(max)) = (self.min_version, self.max_version)
            && max < min
        {
            return Err(HttpConfigError::InvalidConfig(
                "tls_config.max_version must be greater than or equal to tls_config.min_version if both are specified".to_owned(),
            ));
        }
        Ok(())
    }

    fn using_client_cert(&self) -> bool {
        !self.cert.is_empty() || !self.cert_file.is_empty() || !self.cert_ref.is_empty()
    }

    fn using_client_key(&self) -> bool {
        !self.key.is_empty() || !self.key_file.is_empty() || !self.key_ref.is_empty()
    }

    fn apply_to_builder(
        &self,
        mut builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, HttpConfigError> {
        self.validate()?;
        if !self.ca_ref.is_empty() || !self.cert_ref.is_empty() || !self.key_ref.is_empty() {
            return Err(HttpConfigError::InvalidConfig(
                "cannot use secret ref without manager".to_owned(),
            ));
        }
        if !self.server_name.is_empty() {
            return Err(HttpConfigError::InvalidConfig(
                "tls_config.server_name override is not yet supported".to_owned(),
            ));
        }
        if self.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if !self.ca.is_empty() || !self.ca_file.is_empty() {
            let ca_pem = if !self.ca.is_empty() {
                self.ca.as_bytes().to_vec()
            } else {
                fs::read(&self.ca_file)?
            };
            let certs = reqwest::Certificate::from_pem_bundle(&ca_pem)?;
            if certs.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "unable to parse CA certificate PEM".to_owned(),
                ));
            }
            builder = builder.tls_certs_only(certs);
        }
        if self.using_client_cert() {
            let cert_pem = if !self.cert.is_empty() {
                self.cert.as_bytes().to_vec()
            } else {
                fs::read(&self.cert_file)?
            };
            let key_pem = if !self.key.is_empty() {
                self.key.as_bytes().to_vec()
            } else {
                fs::read(&self.key_file)?
            };
            let mut combined = Vec::with_capacity(cert_pem.len() + 1 + key_pem.len());
            combined.extend_from_slice(&cert_pem);
            if !combined.ends_with(b"\n") {
                combined.push(b'\n');
            }
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)?;
            builder = builder.identity(identity);
        }
        if let Some(min) = self.min_version {
            builder = builder.min_tls_version(min.to_reqwest());
        }
        if let Some(max) = self.max_version {
            builder = builder.max_tls_version(max.to_reqwest());
        }
        Ok(builder)
    }
}

/// HTTP proxy configuration matching Prometheus `config.ProxyConfig`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// HTTP proxy server URL.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_url"
    )]
    pub proxy_url: Option<String>,
    /// Comma-separated addresses that should bypass the proxy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub no_proxy: String,
    /// Reads proxy settings from environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub proxy_from_environment: bool,
    /// Headers sent to proxies during `CONNECT` requests.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        serialize_with = "serialize_secret_header_map"
    )]
    pub proxy_connect_header: BTreeMap<String, Vec<String>>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_url = self.proxy_url.as_deref().map(redact_url);
        let redacted_headers: BTreeMap<&str, Vec<&str>> = self
            .proxy_connect_header
            .iter()
            .map(|(k, vals)| {
                (
                    k.as_str(),
                    vals.iter().map(|v| redact_str(v.as_str())).collect(),
                )
            })
            .collect();
        f.debug_struct("ProxyConfig")
            .field("proxy_url", &redacted_url)
            .field("no_proxy", &self.no_proxy)
            .field("proxy_from_environment", &self.proxy_from_environment)
            .field("proxy_connect_header", &redacted_headers)
            .finish()
    }
}

impl ProxyConfig {
    /// Validates proxy settings according to Prometheus `ProxyConfig.Validate`.
    pub fn validate(&self) -> Result<(), HttpConfigError> {
        let has_proxy_url = self.proxy_url.as_deref().is_some_and(|u| !u.is_empty());
        if let Some(url) = &self.proxy_url
            && !url.is_empty()
        {
            let parsed = reqwest::Url::parse(url).map_err(|e| {
                HttpConfigError::InvalidConfig(format!("invalid proxy_url {url:?}: {e}"))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(HttpConfigError::InvalidConfig(format!(
                    "invalid proxy_url scheme {:?} in {url:?}, expected \"http\" or \"https\"",
                    parsed.scheme()
                )));
            }
        }
        if !self.proxy_connect_header.is_empty() && !self.proxy_from_environment && !has_proxy_url {
            return Err(HttpConfigError::InvalidConfig(
                "if proxy_connect_header is configured, proxy_url or proxy_from_environment must also be configured".to_owned(),
            ));
        }
        if self.proxy_from_environment && has_proxy_url {
            return Err(HttpConfigError::InvalidConfig(
                "if proxy_from_environment is configured, proxy_url must not be configured"
                    .to_owned(),
            ));
        }
        if self.proxy_from_environment && !self.no_proxy.is_empty() {
            return Err(HttpConfigError::InvalidConfig(
                "if proxy_from_environment is configured, no_proxy must not be configured"
                    .to_owned(),
            ));
        }
        if !has_proxy_url && !self.no_proxy.is_empty() {
            return Err(HttpConfigError::InvalidConfig(
                "if no_proxy is configured, proxy_url must also be configured".to_owned(),
            ));
        }
        Ok(())
    }
}

/// OAuth2 client credentials configuration matching Prometheus `config.OAuth2`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2 {
    /// OAuth2 client ID.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    /// Inline OAuth2 client secret.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub client_secret: String,
    /// Path to file containing the OAuth2 client secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_secret_file: String,
    /// Secret manager reference for the OAuth2 client secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_secret_ref: String,
    /// Key ID for JWT bearer client certificate authentication.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_certificate_key_id: String,
    /// Inline client certificate private key for JWT bearer grant.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub client_certificate_key: String,
    /// File path to client certificate private key for JWT bearer grant.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_certificate_key_file: String,
    /// Secret manager reference to client certificate private key for JWT bearer grant.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_certificate_key_ref: String,
    /// OAuth2 grant type (`"client_credentials"` or `"urn:ietf:params:oauth:grant-type:jwt-bearer"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub grant_type: String,
    /// RSA signature algorithm (`"RS256"`, `"RS384"`, `"RS512"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_algorithm: String,
    /// OAuth2 JWT issuer claim.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iss: String,
    /// OAuth2 JWT audience claim.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience: String,
    /// Additional JWT claims.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, serde_json::Value>,
    /// OAuth2 scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// OAuth2 token endpoint URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_url: String,
    /// Additional parameters appended to token endpoint requests.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoint_params: BTreeMap<String, String>,
    /// TLS configuration for token requests.
    #[serde(default, skip_serializing_if = "is_default_tls")]
    pub tls_config: TlsConfig,
    /// Proxy configuration for token requests.
    #[serde(flatten)]
    pub proxy_config: ProxyConfig,
}

impl fmt::Debug for OAuth2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2")
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_str(&self.client_secret))
            .field("client_secret_file", &self.client_secret_file)
            .field("client_secret_ref", &self.client_secret_ref)
            .field("client_certificate_key_id", &self.client_certificate_key_id)
            .field(
                "client_certificate_key",
                &redact_str(&self.client_certificate_key),
            )
            .field(
                "client_certificate_key_file",
                &self.client_certificate_key_file,
            )
            .field(
                "client_certificate_key_ref",
                &self.client_certificate_key_ref,
            )
            .field("grant_type", &self.grant_type)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("iss", &self.iss)
            .field("audience", &self.audience)
            .field("claims", &self.claims)
            .field("scopes", &self.scopes)
            .field("token_url", &self.token_url)
            .field("endpoint_params", &self.endpoint_params)
            .field("tls_config", &self.tls_config)
            .field("proxy_config", &self.proxy_config)
            .finish()
    }
}

impl OAuth2 {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.client_secret_file = join_dir(dir, &self.client_secret_file);
        self.client_certificate_key_file = join_dir(dir, &self.client_certificate_key_file);
        self.tls_config.set_directory(dir);
    }
}

/// Configuration for a single custom HTTP header matching Prometheus `config.Header`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    /// Plaintext header values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Secret header values.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_secret_vec"
    )]
    pub secrets: Vec<String>,
    /// Paths to files containing header values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

impl fmt::Debug for HttpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_secrets: Vec<&str> = self.secrets.iter().map(|s| redact_str(s)).collect();
        f.debug_struct("HttpHeader")
            .field("values", &self.values)
            .field("secrets", &redacted_secrets)
            .field("files", &self.files)
            .finish()
    }
}

impl HttpHeader {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        for file in &mut self.files {
            *file = join_dir(dir, file);
        }
    }
}

/// Custom HTTP headers configuration matching Prometheus `config.Headers`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeaders {
    /// Map of header name to header value sources.
    #[serde(flatten)]
    pub headers: BTreeMap<String, HttpHeader>,
}

impl HttpHeaders {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        for header in self.headers.values_mut() {
            header.set_directory(dir);
        }
    }

    /// Validates that no reserved Prometheus headers are configured.
    pub fn validate(&self) -> Result<(), HttpConfigError> {
        for name in self.headers.keys() {
            let lower = name.to_ascii_lowercase();
            if RESERVED_HEADERS.contains(&lower.as_str()) {
                return Err(HttpConfigError::InvalidConfig(format!(
                    "setting header {:?} is not allowed",
                    canonical_header_key(name)
                )));
            }
        }
        Ok(())
    }
}

/// HTTP client configuration matching Prometheus `config.HTTPClientConfig`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "HttpClientConfigWire")]
pub struct HttpClientConfig {
    /// HTTP basic authentication credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
    /// HTTP `Authorization` header credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    /// OAuth2 client credentials configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuth2>,
    /// Inline bearer token (deprecated in Prometheus in favor of `authorization.credentials`).
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        serialize_with = "serialize_secret"
    )]
    pub bearer_token: String,
    /// Bearer token file path (deprecated in Prometheus in favor of `authorization.credentials_file`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bearer_token_file: String,
    /// TLS configuration.
    #[serde(default, skip_serializing_if = "is_default_tls")]
    pub tls_config: TlsConfig,
    /// Specifies whether the client should follow HTTP 3xx redirects (defaults to `true`).
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    /// Specifies whether HTTP/2 should be enabled (defaults to `true`).
    #[serde(default = "default_true")]
    pub enable_http2: bool,
    /// HTTP proxy configuration.
    #[serde(flatten)]
    pub proxy_config: ProxyConfig,
    /// Custom HTTP headers injected into requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<HttpHeaders>,
}

// Flat wire representation without nested `#[serde(flatten)]` so `HttpClientConfig` can be
// flattened inside outer SD/scrape configs while enforcing `deny_unknown_fields` on both.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpClientConfigWire {
    #[serde(default)]
    basic_auth: Option<BasicAuth>,
    #[serde(default)]
    authorization: Option<Authorization>,
    #[serde(default)]
    oauth2: Option<OAuth2>,
    #[serde(default)]
    bearer_token: String,
    #[serde(default)]
    bearer_token_file: String,
    #[serde(default)]
    tls_config: TlsConfig,
    #[serde(default = "default_true")]
    follow_redirects: bool,
    #[serde(default = "default_true")]
    enable_http2: bool,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    no_proxy: String,
    #[serde(default)]
    proxy_from_environment: bool,
    #[serde(default)]
    proxy_connect_header: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    http_headers: Option<HttpHeaders>,
}

impl From<HttpClientConfigWire> for HttpClientConfig {
    fn from(w: HttpClientConfigWire) -> Self {
        Self {
            basic_auth: w.basic_auth,
            authorization: w.authorization,
            oauth2: w.oauth2,
            bearer_token: w.bearer_token,
            bearer_token_file: w.bearer_token_file,
            tls_config: w.tls_config,
            follow_redirects: w.follow_redirects,
            enable_http2: w.enable_http2,
            proxy_config: ProxyConfig {
                proxy_url: w.proxy_url,
                no_proxy: w.no_proxy,
                proxy_from_environment: w.proxy_from_environment,
                proxy_connect_header: w.proxy_connect_header,
            },
            http_headers: w.http_headers,
        }
    }
}

impl fmt::Debug for HttpClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClientConfig")
            .field("basic_auth", &self.basic_auth)
            .field("authorization", &self.authorization)
            .field("oauth2", &self.oauth2)
            .field("bearer_token", &redact_str(&self.bearer_token))
            .field("bearer_token_file", &self.bearer_token_file)
            .field("tls_config", &self.tls_config)
            .field("follow_redirects", &self.follow_redirects)
            .field("enable_http2", &self.enable_http2)
            .field("proxy_config", &self.proxy_config)
            .field("http_headers", &self.http_headers)
            .finish()
    }
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            basic_auth: None,
            authorization: None,
            oauth2: None,
            bearer_token: String::new(),
            bearer_token_file: String::new(),
            tls_config: TlsConfig::default(),
            follow_redirects: true,
            enable_http2: true,
            proxy_config: ProxyConfig::default(),
            http_headers: None,
        }
    }
}

impl HttpClientConfig {
    /// Returns `true` if this configuration equals Prometheus `DefaultHTTPClientConfig`.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.tls_config.set_directory(dir);
        if let Some(basic_auth) = &mut self.basic_auth {
            basic_auth.set_directory(dir);
        }
        if let Some(auth) = &mut self.authorization {
            auth.set_directory(dir);
        }
        if let Some(oauth2) = &mut self.oauth2 {
            oauth2.set_directory(dir);
        }
        if let Some(headers) = &mut self.http_headers {
            headers.set_directory(dir);
        }
        self.bearer_token_file = join_dir(dir, &self.bearer_token_file);
    }

    /// Validates and normalizes this HTTP client configuration according to
    /// Prometheus `HTTPClientConfig.Validate`.
    pub fn validate(&mut self) -> Result<(), HttpConfigError> {
        if !self.bearer_token.is_empty() && !self.bearer_token_file.is_empty() {
            return Err(HttpConfigError::InvalidConfig(
                "at most one of bearer_token & bearer_token_file must be configured".to_owned(),
            ));
        }
        if (self.basic_auth.is_some() || self.oauth2.is_some())
            && (!self.bearer_token.is_empty() || !self.bearer_token_file.is_empty())
        {
            return Err(HttpConfigError::InvalidConfig(
                "at most one of basic_auth, oauth2, bearer_token & bearer_token_file must be configured".to_owned(),
            ));
        }
        if let Some(basic_auth) = &self.basic_auth {
            if non_empty_count(&[
                &basic_auth.username,
                &basic_auth.username_file,
                &basic_auth.username_ref,
            ]) > 1
            {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of basic_auth username, username_file & username_ref must be configured".to_owned(),
                ));
            }
            if non_empty_count(&[
                &basic_auth.password,
                &basic_auth.password_file,
                &basic_auth.password_ref,
            ]) > 1
            {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of basic_auth password, password_file & password_ref must be configured".to_owned(),
                ));
            }
        }
        if let Some(auth) = &mut self.authorization {
            if !self.bearer_token.is_empty() || !self.bearer_token_file.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "authorization is not compatible with bearer_token & bearer_token_file"
                        .to_owned(),
                ));
            }
            if non_empty_count(&[
                &auth.credentials,
                &auth.credentials_file,
                &auth.credentials_ref,
            ]) > 1
            {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of authorization credentials & credentials_file must be configured"
                        .to_owned(),
                ));
            }
            auth.auth_type = auth.auth_type.trim().to_owned();
            if auth.auth_type.is_empty() {
                auth.auth_type = "Bearer".to_owned();
            }
            if auth.auth_type.eq_ignore_ascii_case("basic") {
                return Err(HttpConfigError::InvalidConfig(
                    "authorization type cannot be set to \"basic\", use \"basic_auth\" instead"
                        .to_owned(),
                ));
            }
            if self.basic_auth.is_some() || self.oauth2.is_some() {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of basic_auth, oauth2 & authorization must be configured"
                        .to_owned(),
                ));
            }
        } else {
            if !self.bearer_token.is_empty() {
                self.authorization = Some(Authorization {
                    auth_type: "Bearer".to_owned(),
                    credentials: std::mem::take(&mut self.bearer_token),
                    credentials_file: String::new(),
                    credentials_ref: String::new(),
                });
            }
            if !self.bearer_token_file.is_empty() {
                self.authorization = Some(Authorization {
                    auth_type: "Bearer".to_owned(),
                    credentials: String::new(),
                    credentials_file: std::mem::take(&mut self.bearer_token_file),
                    credentials_ref: String::new(),
                });
            }
        }

        if let Some(oauth2) = &self.oauth2 {
            if self.basic_auth.is_some() {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of basic_auth, oauth2 & authorization must be configured"
                        .to_owned(),
                ));
            }
            if oauth2.client_id.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "oauth2 client_id must be configured".to_owned(),
                ));
            }
            if oauth2.token_url.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "oauth2 token_url must be configured".to_owned(),
                ));
            }
            if oauth2.grant_type == GRANT_TYPE_JWT_BEARER {
                if non_empty_count(&[
                    &oauth2.client_certificate_key,
                    &oauth2.client_certificate_key_file,
                    &oauth2.client_certificate_key_ref,
                ]) > 1
                {
                    return Err(HttpConfigError::InvalidConfig(
                        "at most one of oauth2 client_certificate_key, client_certificate_key_file & client_certificate_key_ref must be configured using grant-type=urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned(),
                    ));
                }
                if !oauth2.signature_algorithm.is_empty()
                    && !matches!(
                        oauth2.signature_algorithm.as_str(),
                        "RS256" | "RS384" | "RS512"
                    )
                {
                    return Err(HttpConfigError::InvalidConfig(
                        "valid signature algorithms are RS256, RS384 and RS512".to_owned(),
                    ));
                }
            } else if non_empty_count(&[
                &oauth2.client_secret,
                &oauth2.client_secret_file,
                &oauth2.client_secret_ref,
            ]) > 1
            {
                return Err(HttpConfigError::InvalidConfig(
                    "at most one of oauth2 client_secret, client_secret_file & client_secret_ref must be configured using grant-type=client_credentials".to_owned(),
                ));
            }
            oauth2.tls_config.validate()?;
            oauth2.proxy_config.validate()?;
        }

        self.tls_config.validate()?;
        self.proxy_config.validate()?;
        if let Some(headers) = &self.http_headers {
            headers.validate()?;
        }
        Ok(())
    }

    /// Builds a [`reqwest::Client`] configured with the TLS, HTTP/2, redirect, timeout, and proxy
    /// policies from this config.
    pub fn build_client(&self) -> Result<reqwest::Client, HttpConfigError> {
        self.check_unsupported_runtime_auth()?;
        self.proxy_config.validate()?;
        if let Some(headers) = &self.http_headers {
            headers.validate()?;
        }

        let mut builder = reqwest::Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT);
        if !self.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        if !self.enable_http2 {
            builder = builder.http1_only();
        }
        builder = self.tls_config.apply_to_builder(builder)?;

        let proxy_headers = build_proxy_header_map(&self.proxy_config.proxy_connect_header)?;
        if self.proxy_config.proxy_from_environment {
            if !proxy_headers.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "proxy_connect_header with proxy_from_environment is not yet supported"
                        .to_owned(),
                ));
            }
        } else if let Some(proxy_url) = &self.proxy_config.proxy_url
            && !proxy_url.is_empty()
        {
            let mut proxy = reqwest::Proxy::all(proxy_url)?;
            if !self.proxy_config.no_proxy.is_empty() {
                let np = reqwest::NoProxy::from_string(&self.proxy_config.no_proxy).ok_or_else(
                    || {
                        HttpConfigError::InvalidConfig(format!(
                            "invalid no_proxy {:?}",
                            self.proxy_config.no_proxy
                        ))
                    },
                )?;
                proxy = proxy.no_proxy(Some(np));
            }
            if !proxy_headers.is_empty() {
                proxy = proxy.headers(proxy_headers);
            }
            builder = builder.proxy(proxy);
        } else {
            builder = builder.no_proxy();
        }
        Ok(builder.build()?)
    }

    /// Applies authentication (`basic_auth`, `authorization`, `bearer_token`, `bearer_token_file`)
    /// and custom `http_headers` to an outgoing [`reqwest::RequestBuilder`].
    pub fn apply_to_request(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, HttpConfigError> {
        self.check_unsupported_runtime_auth()?;
        if let Some(basic_auth) = &self.basic_auth {
            let username = basic_auth.resolve_username()?;
            let password = basic_auth.resolve_password()?;
            req = req.basic_auth(
                username,
                if password.is_empty() {
                    None
                } else {
                    Some(password)
                },
            );
        } else if let Some(auth) = &self.authorization {
            if let Some(header_val) = auth.resolve_header_value()? {
                req = req.header(AUTHORIZATION, sensitive_header_value(&header_val)?);
            }
        } else if !self.bearer_token.is_empty() {
            let val = format!("Bearer {}", self.bearer_token.trim());
            req = req.header(AUTHORIZATION, sensitive_header_value(&val)?);
        } else if !self.bearer_token_file.is_empty() {
            let token = fs::read_to_string(&self.bearer_token_file)?
                .trim()
                .to_owned();
            if !token.is_empty() {
                let val = format!("Bearer {token}");
                req = req.header(AUTHORIZATION, sensitive_header_value(&val)?);
            }
        }

        if let Some(headers) = &self.http_headers {
            headers.validate()?;
            for (name, header) in &headers.headers {
                let hdr_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    HttpConfigError::InvalidConfig(format!(
                        "invalid HTTP header name {name:?}: {e}"
                    ))
                })?;
                for v in &header.values {
                    let hdr_val = HeaderValue::from_str(v).map_err(|e| {
                        HttpConfigError::InvalidConfig(format!(
                            "invalid HTTP header value for {name:?}: {e}"
                        ))
                    })?;
                    req = req.header(&hdr_name, hdr_val);
                }
                for v in &header.secrets {
                    req = req.header(&hdr_name, sensitive_header_value(v)?);
                }
                for file in &header.files {
                    let content = fs::read_to_string(file).map_err(|e| {
                        HttpConfigError::InvalidConfig(format!(
                            "unable to read headers file {file}: {e}"
                        ))
                    })?;
                    req = req.header(&hdr_name, sensitive_header_value(content.trim())?);
                }
            }
        }

        Ok(req)
    }

    fn check_unsupported_runtime_auth(&self) -> Result<(), HttpConfigError> {
        if self.oauth2.is_some() {
            return Err(HttpConfigError::InvalidConfig(
                "oauth2 authentication is not yet supported at runtime".to_owned(),
            ));
        }
        if let Some(basic_auth) = &self.basic_auth
            && (!basic_auth.username_ref.is_empty() || !basic_auth.password_ref.is_empty())
        {
            return Err(HttpConfigError::InvalidConfig(
                "cannot use secret ref without manager".to_owned(),
            ));
        }
        if let Some(auth) = &self.authorization
            && !auth.credentials_ref.is_empty()
        {
            return Err(HttpConfigError::InvalidConfig(
                "cannot use secret ref without manager".to_owned(),
            ));
        }
        Ok(())
    }
}

fn build_proxy_header_map(
    headers: &BTreeMap<String, Vec<String>>,
) -> Result<HeaderMap, HttpConfigError> {
    let mut map = HeaderMap::new();
    for (name, values) in headers {
        let hdr_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
            HttpConfigError::InvalidConfig(format!(
                "invalid proxy_connect_header name {name:?}: {e}"
            ))
        })?;
        for value in values {
            let mut hdr_val = HeaderValue::from_str(value).map_err(|e| {
                HttpConfigError::InvalidConfig(format!(
                    "invalid proxy_connect_header value for {name:?}: {e}"
                ))
            })?;
            hdr_val.set_sensitive(true);
            map.append(&hdr_name, hdr_val);
        }
    }
    Ok(map)
}

fn sensitive_header_value(value: &str) -> Result<HeaderValue, HttpConfigError> {
    let mut hdr_val = HeaderValue::from_str(value)
        .map_err(|e| HttpConfigError::InvalidConfig(format!("invalid HTTP header value: {e}")))?;
    hdr_val.set_sensitive(true);
    Ok(hdr_val)
}

fn redact_str(s: &str) -> &str {
    if s.is_empty() { "" } else { REDACTED_SECRET }
}

fn redact_url(raw: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(raw)
        && parsed.password().is_some()
    {
        let _ = parsed.set_password(Some("xxxxx"));
        return parsed.into();
    }
    raw.to_owned()
}

fn serialize_secret<S: Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(redact_str(value))
}

fn serialize_secret_vec<S: Serializer>(
    values: &[String],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let redacted: Vec<&str> = values.iter().map(|v| redact_str(v)).collect();
    redacted.serialize(serializer)
}

fn serialize_secret_header_map<S: Serializer>(
    headers: &BTreeMap<String, Vec<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let redacted: BTreeMap<&str, Vec<&str>> = headers
        .iter()
        .map(|(k, vals)| (k.as_str(), vals.iter().map(|v| redact_str(v)).collect()))
        .collect();
    redacted.serialize(serializer)
}

fn serialize_opt_url<S: Serializer>(
    url: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match url {
        Some(u) => serializer.serialize_some(&redact_url(u)),
        None => serializer.serialize_none(),
    }
}

fn non_empty_count(values: &[&str]) -> usize {
    values.iter().filter(|v| !v.is_empty()).count()
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_default_tls(tls: &TlsConfig) -> bool {
    *tls == TlsConfig::default()
}

fn join_dir(dir: &Path, path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let p = Path::new(path);
    if p.is_absolute() {
        path.to_owned()
    } else {
        dir.join(p).to_string_lossy().into_owned()
    }
}

fn canonical_header_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for ch in s.chars() {
        if ch == '-' {
            out.push('-');
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}
