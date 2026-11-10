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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use expfmt::http_config::{
    Authorization, BasicAuth, HttpClientConfig, HttpHeader, HttpHeaders, OAuth2, ProxyConfig,
    TlsConfig, TlsVersion,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

const TEST_CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBSzCB8qADAgECAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgRGlz\n\
Y292ZXJ5IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAcMRow\n\
GAYDVQQDDBFUZXN0IERpc2NvdmVyeSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n\
A0IABIh8inO1e0XFBqDBtcxv3BmM0MHgV2PZeF+BswiHPsQ63K6Xt/xGZS9ziRh8\n\
bErqSNtv7W9shFuHxVmIuf+ROo+jIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n\
AQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUCIQCXh/u32CC/j81T+3oEJnRR0P8A\n\
ZCXcq24++2iU8RQHuAIgTvD813EN4j4Wd++SFXpG+evSLLk+fyJse98OIktvI/E=\n\
-----END CERTIFICATE-----\n";

const TEST_SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBVzCB/aADAgECAgECMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgRGlz\n\
Y292ZXJ5IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAUMRIw\n\
EAYDVQQDDAkxMjcuMC4wLjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASgpvT7\n\
pxvHJ9b0hfVl1OSzVw4wXXNbMgOcQuzTJyWIdPLOgN4uV3uYNUCGBoOmzZiSHQNV\n\
kxosSi48IIZKN66CozYwNDAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBH8AAAEw\n\
EwYDVR0lBAwwCgYIKwYBBQUHAwEwCgYIKoZIzj0EAwIDSQAwRgIhAL8MTVC7DzUW\n\
S6c9vBHZmQpTHRttDCHL5pJuJjYfD6UIAiEA4Svgdadp5oYsNbiccD3xiOxd2f0C\n\
gcCEe0UeZFy+qgs=\n\
-----END CERTIFICATE-----\n";

const TEST_SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglO/xnuT6hNqAa1Au\n\
8mCUOEYEuik/fdi8Fp1fJTvPI/mhRANCAASgpvT7pxvHJ9b0hfVl1OSzVw4wXXNb\n\
MgOcQuzTJyWIdPLOgN4uV3uYNUCGBoOmzZiSHQNVkxosSi48IIZKN66C\n\
-----END PRIVATE KEY-----\n";

const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBRzCB7qADAgECAgEDMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgRGlz\n\
Y292ZXJ5IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAWMRQw\n\
EgYDVQQDDAtwcm9tLWNsaWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPaV\n\
o6u67B6wO8kr/rbYTvsvDXIxURJaLinfvVeqsPW3SDYaUTM9f8tSa7xbvmBwLbmr\n\
y1s7cN7v0Pfo5lYFU5CjJTAjMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB\n\
BQUHAwIwCgYIKoZIzj0EAwIDSAAwRQIgNdIcz83GyYDyCadBNBtP+jxPeCBBpQY4\n\
c/Mzu1lyEr8CIQDZMeAQYUPozmcVavNzujS3wddD9dNSIpZBGsOd9p4Kdg==\n\
-----END CERTIFICATE-----\n";

const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOcr6T6T9duo1QH4u\n\
nR6BDYL+R0s2UDkIdWN9ry1Z60ihRANCAAT2laOruuwesDvJK/622E77Lw1yMVES\n\
Wi4p371XqrD1t0g2GlEzPX/LUmu8W75gcC25q8tbO3De79D36OZWBVOQ\n\
-----END PRIVATE KEY-----\n";

#[test]
fn build_client_rejects_unsupported_runtime_options() {
    let mut oauth_http = HttpClientConfig {
        oauth2: Some(OAuth2 {
            client_id: "my-client".to_owned(),
            token_url: "https://auth.example.com/token".to_owned(),
            ..OAuth2::default()
        }),
        ..HttpClientConfig::default()
    };
    oauth_http.validate().unwrap();
    assert!(
        oauth_http
            .build_client()
            .unwrap_err()
            .to_string()
            .contains("oauth2")
    );

    let ref_http = HttpClientConfig {
        basic_auth: Some(BasicAuth {
            username_ref: "secret-ref".to_owned(),
            ..BasicAuth::default()
        }),
        ..HttpClientConfig::default()
    };
    assert!(ref_http.build_client().is_err());

    let tls_ref_http = HttpClientConfig {
        tls_config: TlsConfig {
            ca_ref: "ca-secret".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(tls_ref_http.build_client().is_err());

    let sni_http = HttpClientConfig {
        tls_config: TlsConfig {
            server_name: "custom.sni.local".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(sni_http.build_client().is_err());

    let env_proxy_hdr = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_from_environment: true,
            proxy_connect_header: BTreeMap::from([(
                "Proxy-Token".to_owned(),
                vec!["secret".to_owned()],
            )]),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(env_proxy_hdr.build_client().is_err());
}

#[test]
fn build_client_and_apply_to_request_https_mtls_and_localset() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let dir =
            std::env::temp_dir().join(format!("scrape-rs-http-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let user_file = dir.join("user.txt");
        let pass_file = dir.join("pass.txt");
        let hdr_file = dir.join("hdr.txt");
        std::fs::write(&user_file, "prom-user\n").unwrap();
        std::fs::write(&pass_file, "prom-pass\n").unwrap();
        std::fs::write(&hdr_file, "from-file\n").unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(TEST_CA_CERT_PEM.as_bytes()).unwrap())
            .unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(
            client_roots,
        ))
        .build()
        .unwrap();
        let server_cert = CertificateDer::from_pem_slice(TEST_SERVER_CERT_PEM.as_bytes()).unwrap();
        let server_key = PrivateKeyDer::from_pem_slice(TEST_SERVER_KEY_PEM.as_bytes()).unwrap();
        let tls_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_cfg));

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::task::spawn_local(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls_stream) = acceptor.accept(tcp).await else {
                return;
            };
            let mut req_buf = vec![0u8; 4096];
            let n = tls_stream.read(&mut req_buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&req_buf[..n]);
            assert!(
                req_str.lines().any(|l| l.eq_ignore_ascii_case(
                    "authorization: Basic cHJvbS11c2VyOnByb20tcGFzcw=="
                )),
                "missing basic auth in:\n{req_str}"
            );
            assert!(
                req_str
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("x-trace: plain-val")),
                "missing plain header in:\n{req_str}"
            );
            assert!(
                req_str
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("x-trace: secret-val")),
                "missing secret header in:\n{req_str}"
            );
            assert!(
                req_str
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("x-trace: from-file")),
                "missing file header in:\n{req_str}"
            );

            let body = "ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tls_stream.write_all(resp.as_bytes()).await;
            let _ = tls_stream.shutdown().await;
        });

        let mut cfg = HttpClientConfig {
            basic_auth: Some(BasicAuth {
                username_file: user_file.to_string_lossy().into_owned(),
                password_file: pass_file.to_string_lossy().into_owned(),
                ..BasicAuth::default()
            }),
            enable_http2: false,
            follow_redirects: false,
            tls_config: TlsConfig {
                ca: TEST_CA_CERT_PEM.to_owned(),
                cert: TEST_CLIENT_CERT_PEM.to_owned(),
                key: TEST_CLIENT_KEY_PEM.to_owned(),
                min_version: Some(TlsVersion::Tls12),
                max_version: Some(TlsVersion::Tls13),
                ..TlsConfig::default()
            },
            http_headers: Some(HttpHeaders {
                headers: BTreeMap::from([(
                    "X-Trace".to_owned(),
                    HttpHeader {
                        values: vec!["plain-val".to_owned()],
                        secrets: vec!["secret-val".to_owned()],
                        files: vec![hdr_file.to_string_lossy().into_owned()],
                    },
                )]),
            }),
            ..HttpClientConfig::default()
        };
        cfg.validate().unwrap();
        let client = cfg.build_client().unwrap();

        let body = tokio::task::spawn_local(async move {
            let req = cfg
                .apply_to_request(client.get(format!("https://{addr}/metrics")))
                .unwrap();
            req.send().await.unwrap().text().await.unwrap()
        })
        .await
        .unwrap();
        assert_eq!(body, "ok");

        let _ = std::fs::remove_dir_all(&dir);
    });
}
