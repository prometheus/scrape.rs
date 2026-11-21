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

//! HTTP client and TLS configuration types with 1:1 parity with `prometheus/common/config`.
//!
//! # Secret redaction
//!
//! [`Secret`] values and passwords embedded in [`ProxyConfig::proxy_url`] are irreversibly
//! redacted in both [`fmt::Debug`] and [`serde::Serialize`] (to `"<secret>"` and `"xxxxx"`
//! respectively), matching Prometheus config marshaling. Round-tripping through `Serialize` ->
//! `Deserialize` does not preserve secret values.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error returned when validating or constructing a [`reqwest::Client`] or request from
/// [`HttpClientConfig`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpConfigError {
    /// Configuration validation or unsupported runtime option error.
    #[error("{0}")]
    InvalidConfig(String),
    /// I/O error reading a referenced credentials, certificate, or header file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// HTTP client or request error (with any embedded URL password stripped).
    #[error("HTTP error: {0}")]
    Http(#[source] reqwest::Error),
}

impl From<reqwest::Error> for HttpConfigError {
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

/// Placeholder emitted when marshaling non-empty [`Secret`] values to YAML or JSON.
pub const SECRET_TOKEN: &str = "<secret>";

/// Joins `dir` and `path` when `path` is relative and non-empty, cleaning `.` and `..` segments
/// identically to Go's `config.JoinDir` (`filepath.Join(dir, path)`).
pub fn join_dir(dir: &str, path: &str) -> String {
    if path.is_empty() || Path::new(path).is_absolute() {
        return path.to_owned();
    }
    if dir.is_empty() || dir == "." {
        return clean_path(path);
    }
    clean_path(&format!("{}/{}", dir.trim_end_matches('/'), path))
}

/// Lexically cleans a slash-separated path matching Go's `filepath.Clean`.
pub fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if let Some(&last) = stack.last() {
                    if last != ".." {
                        stack.pop();
                    } else if !rooted {
                        stack.push("..");
                    }
                } else if !rooted {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    if rooted {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// Deserializes a `String` while also accepting integer, float, or boolean YAML scalars
/// (matching Go `gopkg.in/yaml.v2` scalar-to-string coercion).
pub fn deserialize_string_or_scalar<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrScalarVisitor;

    impl Visitor<'_> for StringOrScalarVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a string or scalar value")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.to_owned())
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(v.to_string())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(String::new())
        }
    }

    deserializer.deserialize_any(StringOrScalarVisitor)
}

/// Sensitive string value that redacts to `<secret>` when serialized (`common/config.Secret`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(pub String);

impl Secret {
    /// Creates a new [`Secret`] from a string value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the underlying unredacted secret string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` when the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("Secret(\"\")")
        } else {
            f.write_str("Secret(\"<secret>\")")
        }
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.is_empty() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str(SECRET_TOKEN)
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_string_or_scalar(deserializer).map(Secret)
    }
}

/// TLS protocol version (`common/config.TLSVersion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.0 (`0x0301`).
    TLS10,
    /// TLS 1.1 (`0x0302`).
    TLS11,
    /// TLS 1.2 (`0x0303`).
    TLS12,
    /// TLS 1.3 (`0x0304`).
    TLS13,
    /// Unrecognized numeric TLS version code.
    Custom(u16),
}

impl TlsVersion {
    /// Returns the numeric TLS wire version code.
    pub fn code(self) -> u16 {
        match self {
            Self::TLS10 => 0x0301,
            Self::TLS11 => 0x0302,
            Self::TLS12 => 0x0303,
            Self::TLS13 => 0x0304,
            Self::Custom(code) => code,
        }
    }

    /// Parses a TLS version name (`TLS10`, `TLS11`, `TLS12`, `TLS13`).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "TLS10" => Ok(Self::TLS10),
            "TLS11" => Ok(Self::TLS11),
            "TLS12" => Ok(Self::TLS12),
            "TLS13" => Ok(Self::TLS13),
            other => Err(format!("unknown TLS version: {other}")),
        }
    }

    fn to_reqwest(self) -> Result<reqwest::tls::Version, HttpConfigError> {
        match self {
            Self::TLS10 => Ok(reqwest::tls::Version::TLS_1_0),
            Self::TLS11 => Ok(reqwest::tls::Version::TLS_1_1),
            Self::TLS12 => Ok(reqwest::tls::Version::TLS_1_2),
            Self::TLS13 => Ok(reqwest::tls::Version::TLS_1_3),
            Self::Custom(code) => Err(HttpConfigError::InvalidConfig(format!(
                "unknown TLS version: {code}"
            ))),
        }
    }
}

impl PartialOrd for TlsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TlsVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.code().cmp(&other.code())
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TLS10 => f.write_str("TLS10"),
            Self::TLS11 => f.write_str("TLS11"),
            Self::TLS12 => f.write_str("TLS12"),
            Self::TLS13 => f.write_str("TLS13"),
            Self::Custom(0) => Ok(()),
            Self::Custom(code) => write!(f, "{code}"),
        }
    }
}

impl Serialize for TlsVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::TLS10 => serializer.serialize_str("TLS10"),
            Self::TLS11 => serializer.serialize_str("TLS11"),
            Self::TLS12 => serializer.serialize_str("TLS12"),
            Self::TLS13 => serializer.serialize_str("TLS13"),
            Self::Custom(code) => Err(serde::ser::Error::custom(format!(
                "unknown TLS version: {code}"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for TlsVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = deserialize_string_or_scalar(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}

/// TLS connection configuration (`common/config.TLSConfig`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Inline CA certificate PEM.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub ca: String,
    /// Inline client certificate PEM.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub cert: String,
    /// Inline client private key PEM.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub key: Secret,
    /// Path to the CA certificate file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub ca_file: String,
    /// Path to the client certificate file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub cert_file: String,
    /// Path to the client private key file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub key_file: String,
    /// Secret manager reference for CA certificate.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub ca_ref: String,
    /// Secret manager reference for client certificate.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub cert_ref: String,
    /// Secret manager reference for client key.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub key_ref: String,
    /// ServerName used to verify target hostname.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub server_name: String,
    /// Disables target certificate verification.
    pub insecure_skip_verify: bool,
    /// Minimum TLS protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
    /// Maximum TLS protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_version: Option<TlsVersion>,
}

impl TlsConfig {
    /// Returns `true` when all TLS fields are at their default values.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.ca_file = join_dir(dir, &self.ca_file);
        self.cert_file = join_dir(dir, &self.cert_file);
        self.key_file = join_dir(dir, &self.key_file);
    }

    /// Validates mutual exclusions and client certificate/key pairing (`TLSConfig.Validate`).
    pub fn validate(&self) -> Result<(), String> {
        if count_true(&[
            !self.ca.is_empty(),
            !self.ca_file.is_empty(),
            !self.ca_ref.is_empty(),
        ]) > 1
        {
            return Err("at most one of ca, ca_file & ca_ref must be configured".to_owned());
        }
        if count_true(&[
            !self.cert.is_empty(),
            !self.cert_file.is_empty(),
            !self.cert_ref.is_empty(),
        ]) > 1
        {
            return Err("at most one of cert, cert_file & cert_ref must be configured".to_owned());
        }
        if count_true(&[
            !self.key.is_empty(),
            !self.key_file.is_empty(),
            !self.key_ref.is_empty(),
        ]) > 1
        {
            return Err("at most one of key and key_file must be configured".to_owned());
        }
        let using_cert =
            !self.cert.is_empty() || !self.cert_file.is_empty() || !self.cert_ref.is_empty();
        let using_key =
            !self.key.is_empty() || !self.key_file.is_empty() || !self.key_ref.is_empty();
        if using_cert && !using_key {
            return Err(
                "exactly one of key or key_file must be configured when a client certificate is configured"
                    .to_owned(),
            );
        }
        if using_key && !using_cert {
            return Err(
                "exactly one of cert or cert_file must be configured when a client key is configured"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Validates both [`TlsConfig::validate`] and `max_version >= min_version` (`NewTLSConfig`).
    pub fn validate_version_bounds(&self) -> Result<(), String> {
        self.validate()?;
        if let (Some(min), Some(max)) = (self.min_version, self.max_version)
            && max < min
        {
            return Err(
                "tls_config.max_version must be greater than or equal to tls_config.min_version if both are specified"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn using_client_cert(&self) -> bool {
        !self.cert.is_empty() || !self.cert_file.is_empty() || !self.cert_ref.is_empty()
    }

    fn apply_to_builder(
        &self,
        mut builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder, HttpConfigError> {
        self.validate_version_bounds()
            .map_err(HttpConfigError::InvalidConfig)?;
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
                self.key.as_str().as_bytes().to_vec()
            } else {
                fs::read(&self.key_file)?
            };
            // Match Go `crypto/tls.X509KeyPair`: extract only `CERTIFICATE` blocks from the cert
            // input and the first private key block from the key input, skipping non-matching
            // blocks so a combined `tls.pem` (pointed to by both `cert_file` and `key_file`) or
            // auxiliary blocks like `EC PARAMETERS` work without duplicating certificates. All
            // base64, DER, and cryptographic verification still happens in `reqwest`/`rustls`.
            let cert_blocks = extract_pem_blocks(&cert_pem, &[b"CERTIFICATE"], None)?;
            if cert_blocks.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "client cert PEM must contain at least one CERTIFICATE block".to_owned(),
                ));
            }
            let key_blocks = extract_pem_blocks(
                &key_pem,
                &[b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY"],
                Some(1),
            )?;
            if key_blocks.is_empty() {
                return Err(HttpConfigError::InvalidConfig(
                    "client key PEM must contain a private key block".to_owned(),
                ));
            }
            let mut combined = Vec::with_capacity(cert_blocks.len() + key_blocks.len());
            combined.extend_from_slice(&cert_blocks);
            combined.extend_from_slice(&key_blocks);
            let identity = reqwest::Identity::from_pem(&combined)?;
            builder = builder.identity(identity);
        }
        if let Some(min) = self.min_version {
            builder = builder.tls_version_min(min.to_reqwest()?);
        }
        if let Some(max) = self.max_version {
            let max_req = max.to_reqwest()?;
            if max < TlsVersion::TLS12 {
                return Err(HttpConfigError::InvalidConfig(
                    "tls_config.max_version below TLS12 is not supported by rustls".to_owned(),
                ));
            }
            builder = builder.tls_version_max(max_req);
        }
        Ok(builder)
    }
}

/// HTTP Basic authentication credentials (`common/config.BasicAuth`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BasicAuth {
    /// Inline username.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username: String,
    /// Path to username file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username_file: String,
    /// Secret manager reference for username.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub username_ref: String,
    /// Inline password.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub password: Secret,
    /// Path to password file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub password_file: String,
    /// Secret manager reference for password.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub password_ref: String,
}

impl BasicAuth {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.password_file = join_dir(dir, &self.password_file);
        self.username_file = join_dir(dir, &self.username_file);
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
            Ok(self.password.as_str().to_owned())
        }
    }
}

/// HTTP `Authorization` header configuration (`common/config.Authorization`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Authorization {
    /// Authorization scheme (defaults to `"Bearer"`).
    #[serde(
        rename = "type",
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub auth_type: String,
    /// Inline credentials token.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub credentials: Secret,
    /// Path to credentials file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub credentials_file: String,
    /// Secret manager reference for credentials.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub credentials_ref: String,
}

impl Authorization {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.credentials_file = join_dir(dir, &self.credentials_file);
    }

    fn resolve_header_value(&self) -> Result<String, HttpConfigError> {
        let creds = if !self.credentials_file.is_empty() {
            fs::read_to_string(&self.credentials_file)?
                .trim()
                .to_owned()
        } else {
            self.credentials.as_str().to_owned()
        };
        let scheme = if self.auth_type.trim().is_empty() {
            "Bearer"
        } else {
            self.auth_type.trim()
        };
        Ok(format!("{scheme} {creds}"))
    }
}

/// Proxy configuration embedded in [`HttpClientConfig`] and [`OAuth2`] (`common/config.ProxyConfig`).
///
/// [`fmt::Debug`] and [`serde::Serialize`] redact passwords in `proxy_url` to `"xxxxx"` and
/// [`Secret`] entries in `proxy_connect_header` to `"<secret>"`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// HTTP proxy server URL.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_url"
    )]
    pub proxy_url: Option<String>,
    /// Comma-separated addresses that bypass the proxy.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub no_proxy: String,
    /// Uses environment proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`).
    #[serde(skip_serializing_if = "is_false")]
    pub proxy_from_environment: bool,
    /// Headers sent to proxies during `CONNECT` requests.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub proxy_connect_header: BTreeMap<String, Vec<Secret>>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_url = self.proxy_url.as_deref().map(redact_url);
        f.debug_struct("ProxyConfig")
            .field("proxy_url", &redacted_url)
            .field("no_proxy", &self.no_proxy)
            .field("proxy_from_environment", &self.proxy_from_environment)
            .field("proxy_connect_header", &self.proxy_connect_header)
            .finish()
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl ProxyConfig {
    /// Validates proxy settings (`ProxyConfig.Validate`).
    pub fn validate(&self) -> Result<(), String> {
        let proxy_url_str = self.proxy_url.as_deref().unwrap_or("");
        if let Some(u) = &self.proxy_url {
            validate_go_url(u)?;
        }
        if !self.proxy_connect_header.is_empty()
            && !self.proxy_from_environment
            && proxy_url_str.is_empty()
        {
            return Err(
                "if proxy_connect_header is configured, proxy_url or proxy_from_environment must also be configured"
                    .to_owned(),
            );
        }
        if self.proxy_from_environment && !proxy_url_str.is_empty() {
            return Err(
                "if proxy_from_environment is configured, proxy_url must not be configured"
                    .to_owned(),
            );
        }
        if self.proxy_from_environment && !self.no_proxy.is_empty() {
            return Err(
                "if proxy_from_environment is configured, no_proxy must not be configured"
                    .to_owned(),
            );
        }
        if self.proxy_url.is_none() && !self.no_proxy.is_empty() {
            return Err("if no_proxy is configured, proxy_url must also be configured".to_owned());
        }
        Ok(())
    }
}

/// OAuth2 client configuration (`common/config.OAuth2`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuth2 {
    /// OAuth2 client identifier.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_id: String,
    /// Inline OAuth2 client secret.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub client_secret: Secret,
    /// Path to OAuth2 client secret file.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_secret_file: String,
    /// Secret manager reference for client secret.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_secret_ref: String,
    /// Key ID for JWT bearer client certificate.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_certificate_key_id: String,
    /// Inline client certificate private key for JWT bearer grant.
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub client_certificate_key: Secret,
    /// Path to client certificate private key file for JWT bearer grant.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_certificate_key_file: String,
    /// Secret manager reference for client certificate key.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub client_certificate_key_ref: String,
    /// Grant type (`client_credentials` or `urn:ietf:params:oauth:grant-type:jwt-bearer`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub grant_type: String,
    /// RSA signature algorithm for JWT bearer (`RS256`, `RS384`, `RS512`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub signature_algorithm: String,
    /// JWT issuer (`iss`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub iss: String,
    /// JWT audience (`aud`).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub audience: String,
    /// Extra JWT claims.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, serde_json::Value>,
    /// OAuth2 scopes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Token endpoint URL.
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub token_url: String,
    /// Extra parameters appended to token endpoint requests.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoint_params: BTreeMap<String, String>,
    /// TLS configuration for token requests.
    #[serde(skip_serializing_if = "TlsConfig::is_empty")]
    pub tls_config: TlsConfig,
    /// Proxy configuration for token requests.
    #[serde(flatten)]
    pub proxy_config: ProxyConfig,
}

impl OAuth2 {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.client_secret_file = join_dir(dir, &self.client_secret_file);
        self.tls_config.set_directory(dir);
    }

    /// Validates nested TLS and proxy configurations (`OAuth2.Validate`).
    pub fn validate(&self) -> Result<(), String> {
        self.tls_config.validate()?;
        self.proxy_config.validate()
    }
}

/// Configuration for a single HTTP request header (`common/config.Header`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Header {
    /// Plaintext header values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Secret header values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<Secret>,
    /// Paths to files containing header values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}

impl Header {
    /// Joins relative file paths with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        for f in &mut self.files {
            *f = join_dir(dir, f);
        }
    }
}

/// Reserved HTTP headers that cannot be overridden via [`Headers`] (`common/config.ReservedHeaders`).
pub const RESERVED_HEADERS: &[&str] = &[
    "Authorization",
    "Host",
    "Content-Encoding",
    "Content-Length",
    "Content-Type",
    "User-Agent",
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Www-Authenticate",
    "Accept-Encoding",
    "X-Prometheus-Remote-Write-Version",
    "X-Prometheus-Remote-Read-Version",
    "X-Prometheus-Scrape-Timeout-Seconds",
    "X-Amz-Date",
    "X-Amz-Security-Token",
    "X-Amz-Content-Sha256",
];

/// Formats a header key in Go `http.CanonicalHeaderKey` format.
pub fn canonical_header_key(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for ch in name.chars() {
        if upper {
            out.extend(ch.to_uppercase());
        } else {
            out.extend(ch.to_lowercase());
        }
        upper = ch == '-';
    }
    out
}

/// Custom HTTP request headers map (`common/config.Headers`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Headers {
    /// Map of header name to [`Header`] configuration.
    #[serde(flatten)]
    pub headers: BTreeMap<String, Header>,
}

impl Headers {
    /// Joins relative file paths in all headers with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        for h in self.headers.values_mut() {
            h.set_directory(dir);
        }
    }

    /// Validates that no reserved headers are configured (`Headers.Validate`).
    pub fn validate(&self) -> Result<(), String> {
        for name in self.headers.keys() {
            if RESERVED_HEADERS
                .iter()
                .any(|reserved| reserved.eq_ignore_ascii_case(name))
            {
                return Err(format!(
                    "setting header {:?} is not allowed",
                    canonical_header_key(name)
                ));
            }
        }
        Ok(())
    }
}

/// OAuth2 JWT bearer grant type constant.
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

fn default_true() -> bool {
    true
}

/// HTTP client configuration (`common/config.HTTPClientConfig`).
///
/// Both [`fmt::Debug`] and [`serde::Serialize`] irreversibly redact [`Secret`] fields to
/// `"<secret>"` and `proxy_url` passwords to `"xxxxx"`, so serializing a config is intentionally
/// lossy for secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpClientConfig {
    /// HTTP basic authentication credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
    /// HTTP `Authorization` header credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    /// OAuth2 client credentials configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuth2>,
    /// Deprecated inline bearer token (migrated into `authorization` during validation).
    #[serde(skip_serializing_if = "Secret::is_empty")]
    pub bearer_token: Secret,
    /// Deprecated bearer token file path (migrated into `authorization` during validation).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub bearer_token_file: String,
    /// TLS configuration.
    #[serde(skip_serializing_if = "TlsConfig::is_empty")]
    pub tls_config: TlsConfig,
    /// Whether the HTTP client should follow 3xx redirects (defaults to `true`).
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    /// Whether the HTTP client should enable HTTP/2 (defaults to `true`).
    #[serde(default = "default_true")]
    pub enable_http2: bool,
    /// Proxy configuration.
    #[serde(flatten)]
    pub proxy_config: ProxyConfig,
    /// Additional HTTP headers to attach to requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<Headers>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            basic_auth: None,
            authorization: None,
            oauth2: None,
            bearer_token: Secret::default(),
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
    /// Returns `true` when this config equals `DefaultHTTPClientConfig`.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Joins relative file paths with `dir` (`HTTPClientConfig.SetDirectory`).
    pub fn set_directory(&mut self, dir: &str) {
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

    /// Validates the HTTP client configuration and normalizes `bearer_token` / `bearer_token_file`
    /// into `authorization` (`HTTPClientConfig.Validate`).
    ///
    /// Returns without mutating `self` if any validation check fails.
    pub fn validate(&mut self) -> Result<(), String> {
        self.validate_fields()?;

        if let Some(auth) = &mut self.authorization {
            let trimmed = auth.auth_type.trim();
            auth.auth_type = if trimmed.is_empty() {
                "Bearer".to_owned()
            } else {
                trimmed.to_owned()
            };
        } else if !self.bearer_token.is_empty() {
            let token = std::mem::take(&mut self.bearer_token);
            self.authorization = Some(Authorization {
                auth_type: "Bearer".to_owned(),
                credentials: token,
                credentials_file: String::new(),
                credentials_ref: String::new(),
            });
        } else if !self.bearer_token_file.is_empty() {
            let file = std::mem::take(&mut self.bearer_token_file);
            self.authorization = Some(Authorization {
                auth_type: "Bearer".to_owned(),
                credentials: Secret::default(),
                credentials_file: file,
                credentials_ref: String::new(),
            });
        }
        Ok(())
    }

    fn validate_auth(&self) -> Result<(), String> {
        if !self.bearer_token.is_empty() && !self.bearer_token_file.is_empty() {
            return Err(
                "at most one of bearer_token & bearer_token_file must be configured".to_owned(),
            );
        }
        if (self.basic_auth.is_some() || self.oauth2.is_some())
            && (!self.bearer_token.is_empty() || !self.bearer_token_file.is_empty())
        {
            return Err(
                "at most one of basic_auth, oauth2, bearer_token & bearer_token_file must be configured"
                    .to_owned(),
            );
        }
        if let Some(ba) = &self.basic_auth {
            if count_true(&[
                !ba.username.is_empty(),
                !ba.username_file.is_empty(),
                !ba.username_ref.is_empty(),
            ]) > 1
            {
                return Err(
                    "at most one of basic_auth username, username_file & username_ref must be configured"
                        .to_owned(),
                );
            }
            if count_true(&[
                !ba.password.is_empty(),
                !ba.password_file.is_empty(),
                !ba.password_ref.is_empty(),
            ]) > 1
            {
                return Err(
                    "at most one of basic_auth password, password_file & password_ref must be configured"
                        .to_owned(),
                );
            }
        }
        if let Some(auth) = &self.authorization {
            if !self.bearer_token.is_empty() || !self.bearer_token_file.is_empty() {
                return Err(
                    "authorization is not compatible with bearer_token & bearer_token_file"
                        .to_owned(),
                );
            }
            if count_true(&[
                !auth.credentials.is_empty(),
                !auth.credentials_file.is_empty(),
                !auth.credentials_ref.is_empty(),
            ]) > 1
            {
                return Err(
                    "at most one of authorization credentials & credentials_file must be configured"
                        .to_owned(),
                );
            }
            if auth.auth_type.trim().eq_ignore_ascii_case("basic") {
                return Err(
                    "authorization type cannot be set to \"basic\", use \"basic_auth\" instead"
                        .to_owned(),
                );
            }
            if self.basic_auth.is_some() || self.oauth2.is_some() {
                return Err(
                    "at most one of basic_auth, oauth2 & authorization must be configured"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), String> {
        self.tls_config.validate()?;
        self.validate_auth()?;

        if let Some(oauth2) = &self.oauth2 {
            oauth2.validate()?;
            if self.basic_auth.is_some() {
                return Err(
                    "at most one of basic_auth, oauth2 & authorization must be configured"
                        .to_owned(),
                );
            }
            if oauth2.client_id.is_empty() {
                return Err("oauth2 client_id must be configured".to_owned());
            }
            if oauth2.token_url.is_empty() {
                return Err("oauth2 token_url must be configured".to_owned());
            }
            if oauth2.grant_type == GRANT_TYPE_JWT_BEARER {
                if count_true(&[
                    !oauth2.client_certificate_key.is_empty(),
                    !oauth2.client_certificate_key_file.is_empty(),
                    !oauth2.client_certificate_key_ref.is_empty(),
                ]) > 1
                {
                    return Err(
                        "at most one of oauth2 client_certificate_key, client_certificate_key_file & client_certificate_key_ref must be configured using grant-type=urn:ietf:params:oauth:grant-type:jwt-bearer"
                            .to_owned(),
                    );
                }
                if !oauth2.signature_algorithm.is_empty()
                    && !matches!(
                        oauth2.signature_algorithm.as_str(),
                        "RS256" | "RS384" | "RS512"
                    )
                {
                    return Err("valid signature algorithms are RS256, RS384 and RS512".to_owned());
                }
            } else if count_true(&[
                !oauth2.client_secret.is_empty(),
                !oauth2.client_secret_file.is_empty(),
                !oauth2.client_secret_ref.is_empty(),
            ]) > 1
            {
                return Err(
                    "at most one of oauth2 client_secret, client_secret_file & client_secret_ref must be configured using grant-type=client_credentials"
                        .to_owned(),
                );
            }
        }
        self.proxy_config.validate()?;
        if let Some(headers) = &self.http_headers {
            headers.validate()?;
        }
        Ok(())
    }

    /// Returns a [`reqwest::ClientBuilder`] configured with the TLS, HTTP/2, redirect, and proxy
    /// policies from this config.
    ///
    /// Automatic response decompression is disabled to match Prometheus (`DisableCompression: true`)
    /// and [`crate::scrape::ReqwestFetcher::with_client`], `rustls` is explicitly selected, and no
    /// client-level request timeout is configured so callers can apply per-request timeouts or
    /// layer additional builder options (such as `pool_idle_timeout` or `connect_timeout`).
    pub fn client_builder(&self) -> Result<reqwest::ClientBuilder, HttpConfigError> {
        self.validate_fields()
            .map_err(HttpConfigError::InvalidConfig)?;
        self.check_unsupported_runtime_auth()?;

        // Explicitly select rustls (so `Identity::from_pem` remains valid if a downstream crate
        // enables `reqwest/native-tls`) and disable automatic decompression (matching Prometheus
        // `DisableCompression: true` and `ReqwestFetcher`'s `max_body_bytes` enforcement).
        // Request timeouts are left to per-request deadlines or caller builder customization.
        let mut builder = reqwest::Client::builder()
            .tls_backend_rustls()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate();
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
            let parsed = reqwest::Url::parse(proxy_url).map_err(|e| {
                HttpConfigError::InvalidConfig(format!(
                    "invalid proxy_url {:?}: {e}",
                    redact_url(proxy_url)
                ))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(HttpConfigError::InvalidConfig(format!(
                    "invalid proxy_url scheme {:?} in {:?}, expected \"http\" or \"https\"",
                    parsed.scheme(),
                    redact_url(proxy_url)
                )));
            }
            let no_proxy = if !self.proxy_config.no_proxy.is_empty() {
                Some(
                    reqwest::NoProxy::from_string(&self.proxy_config.no_proxy).ok_or_else(
                        || {
                            HttpConfigError::InvalidConfig(format!(
                                "invalid no_proxy {:?}",
                                self.proxy_config.no_proxy
                            ))
                        },
                    )?,
                )
            } else {
                None
            };
            if proxy_headers.is_empty() {
                let proxy = reqwest::Proxy::all(proxy_url)?.no_proxy(no_proxy);
                builder = builder.proxy(proxy);
            } else {
                // Attach `proxy_connect_header` only to HTTPS `CONNECT` proxies so proxy secrets
                // are not injected into plain `http://` requests forwarded to origin servers.
                let https_proxy = reqwest::Proxy::https(proxy_url)?
                    .no_proxy(no_proxy.clone())
                    .headers(proxy_headers);
                let http_proxy = reqwest::Proxy::http(proxy_url)?.no_proxy(no_proxy);
                builder = builder.proxy(https_proxy).proxy(http_proxy);
            }
        } else {
            builder = builder.no_proxy();
        }
        Ok(builder)
    }

    /// Builds a [`reqwest::Client`] from [`Self::client_builder`].
    pub fn build_client(&self) -> Result<reqwest::Client, HttpConfigError> {
        Ok(self.client_builder()?.build()?)
    }

    /// Applies authentication (`basic_auth`, `authorization`, `bearer_token`, `bearer_token_file`)
    /// and custom `http_headers` to an outgoing [`reqwest::RequestBuilder`].
    ///
    /// Matches Prometheus `http_config.go` by leaving any pre-existing `Authorization` header
    /// untouched rather than appending a duplicate value.
    pub fn apply_to_request(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, HttpConfigError> {
        // Keep per-request validation allocation-free: only check auth and reserved headers used
        // here rather than reparsing `proxy_url` or re-checking TLS settings on every request.
        self.validate_auth()
            .map_err(HttpConfigError::InvalidConfig)?;
        self.check_unsupported_runtime_auth()?;
        if let Some(headers) = &self.http_headers {
            headers.validate().map_err(HttpConfigError::InvalidConfig)?;
        }

        let (client, built_res) = req.build_split();
        let built = built_res?;
        let has_authorization = built.headers().contains_key(AUTHORIZATION);
        let mut req = reqwest::RequestBuilder::from_parts(client, built);

        // Match Prometheus `http_config.go`: skip injecting `Authorization` when the request
        // already carries one (for example from caller headers or URL userinfo).
        if !has_authorization {
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
                let header_val = auth.resolve_header_value()?;
                req = req.header(AUTHORIZATION, sensitive_header_value(&header_val)?);
            } else if !self.bearer_token.is_empty() {
                let val = format!("Bearer {}", self.bearer_token.as_str());
                req = req.header(AUTHORIZATION, sensitive_header_value(&val)?);
            } else if !self.bearer_token_file.is_empty() {
                let token = fs::read_to_string(&self.bearer_token_file)?;
                let val = format!("Bearer {}", token.trim());
                req = req.header(AUTHORIZATION, sensitive_header_value(&val)?);
            }
        }

        if let Some(headers) = &self.http_headers {
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
                    req = req.header(&hdr_name, sensitive_header_value(v.as_str())?);
                }
                for file in &header.files {
                    let content = fs::read_to_string(file).map_err(|e| {
                        HttpConfigError::Io(std::io::Error::new(
                            e.kind(),
                            format!("unable to read headers file {file}: {e}"),
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
    headers: &BTreeMap<String, Vec<Secret>>,
) -> Result<HeaderMap, HttpConfigError> {
    let mut map = HeaderMap::new();
    for (name, values) in headers {
        let hdr_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
            HttpConfigError::InvalidConfig(format!(
                "invalid proxy_connect_header name {name:?}: {e}"
            ))
        })?;
        for value in values {
            let mut hdr_val = HeaderValue::from_str(value.as_str()).map_err(|e| {
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

fn extract_pem_blocks(
    pem: &[u8],
    wanted: &[&[u8]],
    limit: Option<usize>,
) -> Result<Vec<u8>, HttpConfigError> {
    let mut out = Vec::new();
    let mut active_label: Option<&[u8]> = None;
    let mut keep_active = false;
    let mut matched = 0usize;

    for raw_line in pem.split(|&b| b == b'\n') {
        let trimmed = raw_line
            .strip_suffix(b"\r")
            .unwrap_or(raw_line)
            .trim_ascii();
        if let Some(label) = trimmed
            .strip_prefix(b"-----BEGIN ")
            .and_then(|rest| rest.strip_suffix(b"-----"))
            && !label.is_empty()
            && !label.starts_with(b"-")
            && !label.ends_with(b"-")
        {
            if active_label.is_some() {
                return Err(HttpConfigError::InvalidConfig(
                    "malformed PEM: nested BEGIN marker before END".to_owned(),
                ));
            }
            active_label = Some(label);
            keep_active = wanted.contains(&label) && limit.is_none_or(|max| matched < max);
            if keep_active {
                out.extend_from_slice(trimmed);
                out.push(b'\n');
            }
            continue;
        }

        if let Some(label) = active_label {
            if let Some(end_label) = trimmed
                .strip_prefix(b"-----END ")
                .and_then(|rest| rest.strip_suffix(b"-----"))
                && end_label == label
            {
                if keep_active {
                    out.extend_from_slice(trimmed);
                    out.push(b'\n');
                    matched += 1;
                }
                active_label = None;
                keep_active = false;
                continue;
            }
            if keep_active {
                out.extend_from_slice(trimmed);
                out.push(b'\n');
            }
        }
    }

    if active_label.is_some() {
        return Err(HttpConfigError::InvalidConfig(
            "malformed PEM: missing END marker".to_owned(),
        ));
    }

    Ok(out)
}

/// Known field names of [`HttpClientConfig`] (including flattened [`ProxyConfig`]).
pub const HTTP_CLIENT_CONFIG_FIELDS: &[&str] = &[
    "basic_auth",
    "authorization",
    "oauth2",
    "bearer_token",
    "bearer_token_file",
    "tls_config",
    "follow_redirects",
    "enable_http2",
    "proxy_url",
    "no_proxy",
    "proxy_from_environment",
    "proxy_connect_header",
    "http_headers",
];

/// Known field names of [`OAuth2`] (including flattened [`ProxyConfig`]).
pub const OAUTH2_FIELDS: &[&str] = &[
    "client_id",
    "client_secret",
    "client_secret_file",
    "client_secret_ref",
    "client_certificate_key_id",
    "client_certificate_key",
    "client_certificate_key_file",
    "client_certificate_key_ref",
    "grant_type",
    "signature_algorithm",
    "iss",
    "audience",
    "claims",
    "scopes",
    "token_url",
    "endpoint_params",
    "tls_config",
    "proxy_url",
    "no_proxy",
    "proxy_from_environment",
    "proxy_connect_header",
];

/// Validates that a mapping only contains allowed keys (needed when `#[serde(flatten)]` is used,
/// since `serde` does not support `#[serde(deny_unknown_fields)]` alongside `#[serde(flatten)]`).
pub fn check_allowed_fields(
    map: &serde_yaml::Mapping,
    allowed: &[&str],
    type_name: &str,
) -> Result<(), String> {
    for k in map.keys() {
        if let Some(key_str) = k.as_str()
            && !allowed.contains(&key_str)
        {
            return Err(format!(
                "yaml: unmarshal errors:\n  field {key_str} not found in type {type_name}"
            ));
        }
    }
    Ok(())
}

/// Validates a [`serde_yaml::Value`] representing an [`HttpClientConfig`] for unknown fields
/// (including nested `oauth2`).
pub fn check_http_client_config_fields(
    val: &serde_yaml::Value,
    type_name: &str,
) -> Result<(), String> {
    if let serde_yaml::Value::Mapping(map) = val {
        check_allowed_fields(map, HTTP_CLIENT_CONFIG_FIELDS, type_name)?;
        if let Some(serde_yaml::Value::Mapping(oauth2_map)) =
            map.get(serde_yaml::Value::String("oauth2".to_owned()))
        {
            check_allowed_fields(oauth2_map, OAUTH2_FIELDS, "config.plain")?;
        }
    }
    Ok(())
}

/// Parses a YAML or JSON string into an [`HttpClientConfig`] and validates it (`LoadHTTPConfig`).
pub fn load_http_config(s: &str) -> Result<HttpClientConfig, String> {
    let val: serde_yaml::Value = serde_yaml::from_str(s).map_err(|e| e.to_string())?;
    if val.is_null() {
        let mut cfg = HttpClientConfig::default();
        cfg.validate()?;
        return Ok(cfg);
    }
    check_http_client_config_fields(&val, "config.plain")?;
    let mut cfg: HttpClientConfig = serde_yaml::from_value(val).map_err(|e| e.to_string())?;
    cfg.validate()?;
    Ok(cfg)
}

/// Loads an [`HttpClientConfig`] from a YAML or JSON file, validates it, and resolves relative paths
/// (`LoadHTTPConfigFile`).
pub fn load_http_config_file(path: &Path) -> Result<HttpClientConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cfg = load_http_config(&content)?;
    let dir = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
    cfg.set_directory(dir);
    Ok(cfg)
}

/// Loads and validates a [`TlsConfig`] from a `.yml`, `.yaml`, or `.json` file (`LoadTLSConfig`).
pub fn load_tls_config(path: &Path) -> Result<TlsConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let cfg: TlsConfig = match ext {
        "yml" | "yaml" => {
            if content.trim().is_empty() {
                TlsConfig::default()
            } else {
                serde_yaml::from_str(&content).map_err(|e| e.to_string())?
            }
        }
        "json" => serde_json::from_str(&content).map_err(|e| e.to_string())?,
        other => return Err(format!("Unknown extension: .{other}")),
    };
    cfg.validate_version_bounds()?;
    Ok(cfg)
}

/// Counts how many booleans in `flags` are `true`.
pub fn count_true(flags: &[bool]) -> usize {
    flags.iter().filter(|&&b| b).count()
}

fn is_valid_url_scheme(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn redact_authority_password(raw: &str, authority_start: usize) -> Option<String> {
    let rest = &raw[authority_start..];
    let authority_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let at_pos = authority.rfind('@')?;
    let colon_pos = authority[..at_pos].find(':')?;
    let prefix = &raw[..authority_start + colon_pos + 1];
    let suffix = &raw[authority_start + at_pos..];
    Some(format!("{prefix}xxxxx{suffix}"))
}

fn redact_url(raw: &str) -> String {
    let authority_start = raw
        .find("://")
        .filter(|&idx| is_valid_url_scheme(&raw[..idx]))
        .map_or(0, |idx| idx + 3);

    if let Ok(mut parsed) = url::Url::parse(raw)
        && !parsed.cannot_be_a_base()
    {
        if parsed.password().is_some() {
            // Preserve the original URL spelling (matching Go's `url.URL.Redacted()`, which does
            // not append a trailing `/` to `http://u:p@host:8080`). Fall back to `Url::set_password`
            // only if WHATWG parsing accepted a non-standard separator.
            if authority_start > 0
                && let Some(redacted) = redact_authority_password(raw, authority_start)
            {
                return redacted;
            }
            let _ = parsed.set_password(Some("xxxxx"));
            return parsed.into();
        }
        return raw.to_owned();
    }

    // Fallback for malformed or schemeless URLs (for example `http://u:p@proxy:99999`,
    // `u:p@proxy:8080`, or `u:p@proxy://x`) so userinfo credentials are never echoed raw.
    if let Some(redacted) = redact_authority_password(raw, authority_start) {
        return redacted;
    }
    let rest = &raw[authority_start..];
    if let Some(last_at) = rest.rfind('@')
        && rest[..last_at].contains(':')
    {
        return SECRET_TOKEN.to_owned();
    }
    raw.to_owned()
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

/// Validates that `s` can be parsed by Go's `net/url.Parse`.
pub fn validate_go_url(s: &str) -> Result<(), String> {
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "net/url: invalid control character in URL {:?}",
            redact_url(s)
        ));
    }
    if s.contains("://") {
        let base_parse = url::Url::parse(s);
        if let Err(err) = base_parse {
            return Err(format!("parse {:?}: {err}", redact_url(s)));
        }
    }
    Ok(())
}

/// Prometheus duration wrapper (`model.Duration`) supporting `y`, `w`, `d`, `h`, `m`, `s`, `ms`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(pub std::time::Duration);

impl Duration {
    /// Zero duration (`0s`).
    pub const ZERO: Self = Self(std::time::Duration::ZERO);

    /// Creates a [`Duration`] from seconds.
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    /// Creates a [`Duration`] from milliseconds.
    pub const fn from_millis(millis: u64) -> Self {
        Self(std::time::Duration::from_millis(millis))
    }

    /// Creates a [`Duration`] from minutes.
    pub const fn from_mins(mins: u64) -> Self {
        Self(std::time::Duration::from_secs(mins * 60))
    }

    /// Returns `true` when the duration is zero.
    pub const fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Returns the duration in milliseconds.
    pub const fn as_millis(self) -> u128 {
        self.0.as_millis()
    }

    /// Parses a Prometheus duration string (`model.ParseDuration`).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "0" => return Ok(Self(std::time::Duration::ZERO)),
            "" => return Err("empty duration string".to_owned()),
            _ => {}
        }
        let orig = s;
        let mut rem = s;
        let mut total_ns: u64 = 0;
        let mut last_unit_pos: u8 = 0;

        while !rem.is_empty() {
            if !rem.as_bytes()[0].is_ascii_digit() {
                return Err(format!("not a valid duration string: {orig:?}"));
            }
            let num_len = rem.bytes().take_while(|b| b.is_ascii_digit()).count();
            let v: u64 = rem[..num_len]
                .parse()
                .map_err(|_| format!("not a valid duration string: {orig:?}"))?;
            rem = &rem[num_len..];

            let unit_len = rem.bytes().take_while(|b| !b.is_ascii_digit()).count();
            if unit_len == 0 {
                return Err(format!("not a valid duration string: {orig:?}"));
            }
            let u = &rem[..unit_len];
            rem = &rem[unit_len..];

            let (pos, mult_ns): (u8, u64) = match u {
                "y" => (1, 365 * 24 * 3600 * 1_000_000_000),
                "w" => (2, 7 * 24 * 3600 * 1_000_000_000),
                "d" => (3, 24 * 3600 * 1_000_000_000),
                "h" => (4, 3600 * 1_000_000_000),
                "m" => (5, 60 * 1_000_000_000),
                "s" => (6, 1_000_000_000),
                "ms" => (7, 1_000_000),
                _ => return Err(format!("unknown unit {u:?} in duration {orig:?}")),
            };
            if pos <= last_unit_pos {
                return Err(format!("not a valid duration string: {orig:?}"));
            }
            last_unit_pos = pos;
            if v > (1u64 << 63) / mult_ns {
                return Err("duration out of range".to_owned());
            }
            let prod = v
                .checked_mul(mult_ns)
                .ok_or_else(|| "duration out of range".to_owned())?;
            total_ns = total_ns
                .checked_add(prod)
                .ok_or_else(|| "duration out of range".to_owned())?;
            if total_ns > i64::MAX as u64 {
                return Err("duration out of range".to_owned());
            }
        }
        Ok(Self(std::time::Duration::from_nanos(total_ns)))
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ms = self.0.as_millis() as i64;
        if ms == 0 {
            return f.write_str("0s");
        }
        let mut out = String::new();
        let mut apply = |unit: &str, mult: i64, exact: bool| {
            if exact && ms % mult != 0 {
                return;
            }
            let v = ms / mult;
            if v > 0 {
                out.push_str(&format!("{v}{unit}"));
                ms -= v * mult;
            }
        };
        apply("y", 1000 * 60 * 60 * 24 * 365, true);
        apply("w", 1000 * 60 * 60 * 24 * 7, true);
        apply("d", 1000 * 60 * 60 * 24, false);
        apply("h", 1000 * 60 * 60, false);
        apply("m", 1000 * 60, false);
        apply("s", 1000, false);
        apply("ms", 1, false);
        f.write_str(&out)
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = deserialize_string_or_scalar(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}

/// Base-2 byte count (`alecthomas/units.Base2Bytes`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Returns `true` when the byte count is zero.
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Parses a base-2 byte size string (`units.ParseBase2Bytes`).
    pub fn parse(s: &str) -> Result<Self, String> {
        parse_unit_base2(s, true).or_else(|_| parse_unit_base2(s, false))
    }
}

fn parse_unit_base2(s: &str, iec_suffix: bool) -> Result<ByteSize, String> {
    let orig = s;
    let mut rem = s;
    let mut neg = false;
    if let Some(first) = rem.bytes().next()
        && (first == b'-' || first == b'+')
    {
        neg = first == b'-';
        rem = &rem[1..];
    }
    if rem == "0" {
        return Ok(ByteSize(0));
    }
    if rem.is_empty() {
        return Err(format!("units: invalid {orig}"));
    }
    let mut total: f64 = 0.0;
    while !rem.is_empty() {
        let first = rem.as_bytes()[0];
        if !(first == b'.' || first.is_ascii_digit()) {
            return Err(format!("units: invalid {orig}"));
        }
        let int_len = rem.bytes().take_while(|b| b.is_ascii_digit()).count();
        let pre = int_len > 0;
        let mut g: f64 = if pre {
            rem[..int_len]
                .parse::<i64>()
                .map_err(|_| format!("units: invalid {orig}"))? as f64
        } else {
            0.0
        };
        rem = &rem[int_len..];

        let mut post = false;
        if rem.starts_with('.') {
            rem = &rem[1..];
            let frac_len = rem.bytes().take_while(|b| b.is_ascii_digit()).count();
            post = frac_len > 0;
            if post {
                let frac_int = rem[..frac_len]
                    .parse::<i64>()
                    .map_err(|_| format!("units: invalid {orig}"))?;
                let scale = 10f64.powi(frac_len as i32);
                g += (frac_int as f64) / scale;
                rem = &rem[frac_len..];
            }
        }
        if !pre && !post {
            return Err(format!("units: invalid {orig}"));
        }

        let unit_len = rem
            .bytes()
            .take_while(|b| !(*b == b'.' || b.is_ascii_digit()))
            .count();
        let u = &rem[..unit_len];
        rem = &rem[unit_len..];

        let mult: f64 = if iec_suffix {
            match u {
                "B" => 1.0,
                "KiB" => 1024.0,
                "MiB" => 1024.0 * 1024.0,
                "GiB" => 1024.0f64.powi(3),
                "TiB" => 1024.0f64.powi(4),
                "PiB" => 1024.0f64.powi(5),
                "EiB" => 1024.0f64.powi(6),
                _ => return Err(format!("units: unknown unit {u} in {orig}")),
            }
        } else {
            match u {
                "B" => 1.0,
                "KB" => 1024.0,
                "MB" => 1024.0 * 1024.0,
                "GB" => 1024.0f64.powi(3),
                "TB" => 1024.0f64.powi(4),
                "PB" => 1024.0f64.powi(5),
                "EB" => 1024.0f64.powi(6),
                _ => return Err(format!("units: unknown unit {u} in {orig}")),
            }
        };
        total += g * mult;
    }
    if neg || total < 0.0 {
        return Err("body_size_limit cannot be negative".to_owned());
    }
    if total > (i64::MAX as f64) {
        return Err("units: overflow parsing unit".to_owned());
    }
    Ok(ByteSize(total as u64))
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: &[&str] = &["", "K", "M", "G", "T", "P", "E"];
        let mut n = self.0;
        if n == 0 {
            return f.write_str("0B");
        }
        let mut parts: Vec<String> = Vec::new();
        for (i, prefix) in UNITS.iter().enumerate() {
            let rem = n % 1024;
            if rem != 0 {
                let suffix = if i == 0 { "B" } else { "iB" };
                parts.push(format!("{rem}{prefix}{suffix}"));
            }
            n /= 1024;
            if n == 0 {
                break;
            }
        }
        parts.reverse();
        f.write_str(&parts.join(""))
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = deserialize_string_or_scalar(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}
