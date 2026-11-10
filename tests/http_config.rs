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

//! Integration tests for Prometheus `HttpClientConfig` validation, secret redaction, and `reqwest` client construction.

#![cfg(feature = "http-config")]

use std::collections::BTreeMap;
use std::path::Path;

use expfmt::http_config::{
    Authorization, BasicAuth, HttpClientConfig, HttpHeader, HttpHeaders, OAuth2, ProxyConfig,
    TlsConfig, TlsVersion,
};

#[test]
fn http_client_config_validation_set_directory_and_secret_redaction() {
    assert!(HttpClientConfig::default().is_default());

    // Unknown fields are rejected across ProxyConfig, OAuth2, and HttpClientConfig.
    assert!(serde_json::from_str::<ProxyConfig>(r#"{"proxy_urls": "http://x"}"#).is_err());
    assert!(serde_json::from_str::<HttpClientConfig>(r#"{"bearer_tokens": "abc"}"#).is_err());
    assert!(
        serde_json::from_str::<OAuth2>(
            r#"{"client_id": "id", "token_url": "https://x", "proxy_url": "http://p:8080"}"#
        )
        .is_ok()
    );
    assert!(
        serde_json::from_str::<OAuth2>(r#"{"client_id": "id", "token_urls": "https://x"}"#)
            .is_err()
    );

    // bearer_token + bearer_token_file conflict.
    let mut both_bearer: HttpClientConfig =
        serde_json::from_str(r#"{"bearer_token": "tok", "bearer_token_file": "/path/to/tok"}"#)
            .unwrap();
    assert_eq!(
        both_bearer.validate().unwrap_err().to_string(),
        "at most one of bearer_token & bearer_token_file must be configured"
    );

    // Reserved HTTP header rejection.
    let mut reserved_hdr: HttpClientConfig =
        serde_json::from_str(r#"{"http_headers": {"Authorization": {"values": ["Bearer foo"]}}}"#)
            .unwrap();
    assert_eq!(
        reserved_hdr.validate().unwrap_err().to_string(),
        "setting header \"Authorization\" is not allowed"
    );

    // Empty authorization.type defaults to "Bearer"; "basic" is rejected.
    let mut auth_cfg = HttpClientConfig {
        authorization: Some(Authorization {
            auth_type: String::new(),
            credentials: "my-token".to_owned(),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    auth_cfg.validate().unwrap();
    assert_eq!(auth_cfg.authorization.unwrap().auth_type, "Bearer");

    let mut basic_type = HttpClientConfig {
        authorization: Some(Authorization {
            auth_type: "Basic".to_owned(),
            credentials: "abc".to_owned(),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    assert!(basic_type.validate().is_err());

    // TlsConfig and ProxyConfig negative validation checks.
    assert!(
        TlsConfig {
            min_version: Some(TlsVersion::Tls13),
            max_version: Some(TlsVersion::Tls12),
            ..TlsConfig::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        TlsConfig {
            cert: "cert".to_owned(),
            ..TlsConfig::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        ProxyConfig {
            proxy_url: Some("ftp://127.0.0.1:21".to_owned()),
            ..ProxyConfig::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        ProxyConfig {
            no_proxy: "localhost".to_owned(),
            ..ProxyConfig::default()
        }
        .validate()
        .is_err()
    );

    // set_directory resolves relative paths and preserves absolute paths across all structs.
    let mut dir_cfg = HttpClientConfig {
        bearer_token_file: "secrets/token".to_owned(),
        basic_auth: Some(BasicAuth {
            username_file: "secrets/user".to_owned(),
            password_file: "/abs/pass".to_owned(),
            ..BasicAuth::default()
        }),
        authorization: Some(Authorization {
            credentials_file: "secrets/creds".to_owned(),
            ..Authorization::default()
        }),
        tls_config: TlsConfig {
            ca_file: "certs/ca.pem".to_owned(),
            cert_file: "certs/client.crt".to_owned(),
            key_file: "/abs/client.key".to_owned(),
            ..TlsConfig::default()
        },
        oauth2: Some(OAuth2 {
            client_secret_file: "oauth/secret".to_owned(),
            client_certificate_key_file: "oauth/jwt.key".to_owned(),
            tls_config: TlsConfig {
                ca_file: "oauth/ca.pem".to_owned(),
                ..TlsConfig::default()
            },
            ..OAuth2::default()
        }),
        http_headers: Some(HttpHeaders {
            headers: BTreeMap::from([(
                "X-Secret".to_owned(),
                HttpHeader {
                    files: vec!["headers/tok.txt".to_owned(), "/abs/tok.txt".to_owned()],
                    ..HttpHeader::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    dir_cfg.set_directory(Path::new("/etc/prometheus"));
    assert_eq!(dir_cfg.bearer_token_file, "/etc/prometheus/secrets/token");
    let ba = dir_cfg.basic_auth.unwrap();
    assert_eq!(ba.username_file, "/etc/prometheus/secrets/user");
    assert_eq!(ba.password_file, "/abs/pass");
    assert_eq!(
        dir_cfg.authorization.unwrap().credentials_file,
        "/etc/prometheus/secrets/creds"
    );
    assert_eq!(dir_cfg.tls_config.ca_file, "/etc/prometheus/certs/ca.pem");
    assert_eq!(
        dir_cfg.tls_config.cert_file,
        "/etc/prometheus/certs/client.crt"
    );
    assert_eq!(dir_cfg.tls_config.key_file, "/abs/client.key");
    let oa = dir_cfg.oauth2.unwrap();
    assert_eq!(oa.client_secret_file, "/etc/prometheus/oauth/secret");
    assert_eq!(
        oa.client_certificate_key_file,
        "/etc/prometheus/oauth/jwt.key"
    );
    assert_eq!(oa.tls_config.ca_file, "/etc/prometheus/oauth/ca.pem");
    assert_eq!(
        dir_cfg.http_headers.unwrap().headers["X-Secret"].files,
        vec![
            "/etc/prometheus/headers/tok.txt".to_owned(),
            "/abs/tok.txt".to_owned()
        ]
    );

    // Secret redaction in Debug and Serialize.
    let secret_cfg = HttpClientConfig {
        basic_auth: Some(BasicAuth {
            username: "alice".to_owned(),
            password: "top-secret-password".to_owned(),
            ..BasicAuth::default()
        }),
        bearer_token: "super-secret-bearer".to_owned(),
        tls_config: TlsConfig {
            key: "super-secret-private-key".to_owned(),
            ..TlsConfig::default()
        },
        proxy_config: ProxyConfig {
            proxy_url: Some("http://proxyuser:proxypass@127.0.0.1:8080".to_owned()),
            proxy_connect_header: BTreeMap::from([(
                "Proxy-Token".to_owned(),
                vec!["proxy-secret-val".to_owned()],
            )]),
            ..ProxyConfig::default()
        },
        http_headers: Some(HttpHeaders {
            headers: BTreeMap::from([(
                "X-Api-Key".to_owned(),
                HttpHeader {
                    secrets: vec!["header-secret-val".to_owned()],
                    ..HttpHeader::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    let dbg = format!("{secret_cfg:?}");
    let json = serde_json::to_string(&secret_cfg).unwrap();
    for leaked in [
        "top-secret-password",
        "super-secret-bearer",
        "super-secret-private-key",
        "proxypass",
        "proxy-secret-val",
        "header-secret-val",
    ] {
        assert!(!dbg.contains(leaked), "Debug leaked {leaked}: {dbg}");
        assert!(!json.contains(leaked), "Serialize leaked {leaked}: {json}");
    }
    assert!(json.contains("<secret>"));
}
