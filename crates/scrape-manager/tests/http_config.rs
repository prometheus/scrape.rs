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

//! Integration tests for Prometheus `HttpClientConfig` secret redaction, `reqwest` client
//! construction, request header injection, TLS/mTLS, proxy routing, redirects, and HTTP/2 ALPN.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use prometheus_scrape_manager::http_config::{
    Authorization, BasicAuth, Header, Headers, HttpClientConfig, HttpConfigError, OAuth2,
    ProxyConfig, Secret, TlsConfig, TlsVersion,
};
use reqwest::header::AUTHORIZATION;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scrape-rs-http-cfg-{label}-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn read_http_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> String {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await.expect("read HTTP request");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
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
    assert_eq!(
        ref_http.build_client().unwrap_err().to_string(),
        "cannot use secret ref without manager"
    );

    let tls_ref_http = HttpClientConfig {
        tls_config: TlsConfig {
            ca_ref: "ca-secret".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert_eq!(
        tls_ref_http.build_client().unwrap_err().to_string(),
        "cannot use secret ref without manager"
    );

    let sni_http = HttpClientConfig {
        tls_config: TlsConfig {
            server_name: "custom.sni.local".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert_eq!(
        sni_http.build_client().unwrap_err().to_string(),
        "tls_config.server_name override is not yet supported"
    );

    let env_proxy_hdr = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_from_environment: true,
            proxy_connect_header: BTreeMap::from([(
                "Proxy-Token".to_owned(),
                vec![Secret::from("secret")],
            )]),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(
        env_proxy_hdr
            .build_client()
            .unwrap_err()
            .to_string()
            .contains("proxy_connect_header with proxy_from_environment")
    );

    // Non-http/https proxy scheme fails at client build time without leaking the proxy password.
    let ftp_proxy = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_url: Some("ftp://u:ftp-secret@127.0.0.1:21".to_owned()),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    let err = ftp_proxy.build_client().unwrap_err().to_string();
    assert!(
        err.contains("invalid proxy_url scheme"),
        "unexpected: {err}"
    );
    assert!(!err.contains("ftp-secret"), "error leaked password: {err}");

    // Custom TLS version fails cleanly at client build time.
    let custom_tls = HttpClientConfig {
        tls_config: TlsConfig {
            min_version: Some(TlsVersion::Custom(0x0399)),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        custom_tls.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));
}

#[test]
fn atomic_validate_and_secret_redaction_covers_all_types_malformed_urls_and_errors() {
    // Failing late checks (for example proxy_config) must not partially normalize bearer_token.
    let mut atomic_cfg = HttpClientConfig {
        bearer_token: Secret::from("my-token"),
        proxy_config: ProxyConfig {
            no_proxy: "localhost".to_owned(),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(atomic_cfg.validate().is_err());
    assert_eq!(atomic_cfg.bearer_token.as_str(), "my-token");
    assert!(atomic_cfg.authorization.is_none());

    // Failing auth conflict must not mutate authorization.auth_type.
    let mut atomic_auth = HttpClientConfig {
        basic_auth: Some(BasicAuth::default()),
        authorization: Some(Authorization {
            auth_type: String::new(),
            credentials: Secret::from("tok"),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    assert!(atomic_auth.validate().is_err());
    assert!(atomic_auth.authorization.unwrap().auth_type.is_empty());

    // Secret redaction in Debug and Serialize across all secret-bearing structs.
    let cfg = HttpClientConfig {
        basic_auth: Some(BasicAuth {
            username: "alice".to_owned(),
            password: Secret::from("basic-pw-secret"),
            ..BasicAuth::default()
        }),
        authorization: Some(Authorization {
            auth_type: "Token".to_owned(),
            credentials: Secret::from("auth-cred-secret"),
            ..Authorization::default()
        }),
        bearer_token: Secret::from("bearer-secret"),
        tls_config: TlsConfig {
            key: Secret::from("tls-key-secret"),
            ..TlsConfig::default()
        },
        oauth2: Some(OAuth2 {
            client_id: "cid".to_owned(),
            client_secret: Secret::from("oauth-client-secret"),
            client_certificate_key: Secret::from("oauth-jwt-key-secret"),
            token_url: "https://auth.example.com/token".to_owned(),
            tls_config: TlsConfig {
                key: Secret::from("oauth-tls-key-secret"),
                ..TlsConfig::default()
            },
            proxy_config: ProxyConfig {
                proxy_url: Some("http://puser:oauth-proxy-pass@127.0.0.1:8080".to_owned()),
                proxy_connect_header: BTreeMap::from([(
                    "Proxy-Auth".to_owned(),
                    vec![Secret::from("oauth-proxy-hdr-secret"), Secret::default()],
                )]),
                ..ProxyConfig::default()
            },
            ..OAuth2::default()
        }),
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "X-Api-Key".to_owned(),
                Header {
                    secrets: vec![Secret::from("header-secret-val")],
                    ..Header::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };

    let dbg = format!("{cfg:?}");
    let json_val: serde_json::Value = serde_json::to_value(&cfg).unwrap();
    let json_str = serde_json::to_string(&cfg).unwrap();
    for secret in [
        "basic-pw-secret",
        "auth-cred-secret",
        "bearer-secret",
        "tls-key-secret",
        "oauth-client-secret",
        "oauth-jwt-key-secret",
        "oauth-tls-key-secret",
        "oauth-proxy-pass",
        "oauth-proxy-hdr-secret",
        "header-secret-val",
    ] {
        assert!(!dbg.contains(secret), "Debug leaked {secret}: {dbg}");
        assert!(
            !json_str.contains(secret),
            "Serialize leaked {secret}: {json_str}"
        );
    }
    assert_eq!(json_val["basic_auth"]["password"], "<secret>");
    assert_eq!(json_val["authorization"]["credentials"], "<secret>");
    assert_eq!(json_val["bearer_token"], "<secret>");
    assert_eq!(json_val["tls_config"]["key"], "<secret>");
    assert_eq!(json_val["oauth2"]["client_secret"], "<secret>");
    assert_eq!(json_val["oauth2"]["client_certificate_key"], "<secret>");
    assert_eq!(json_val["oauth2"]["tls_config"]["key"], "<secret>");
    assert_eq!(
        json_val["oauth2"]["proxy_url"],
        "http://puser:xxxxx@127.0.0.1:8080"
    );
    assert_eq!(
        json_val["oauth2"]["proxy_connect_header"]["Proxy-Auth"],
        serde_json::json!(["<secret>", ""])
    );
    assert_eq!(
        json_val["http_headers"]["X-Api-Key"]["secrets"],
        serde_json::json!(["<secret>"])
    );

    // Passwordless proxy_url (including `@` in the path) stays unredacted, and malformed URLs
    // without `:` before `@` are not blanked.
    for unredacted in [
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8080/a@b",
        "http://[bad/a@b",
    ] {
        let proxy = ProxyConfig {
            proxy_url: Some(unredacted.to_owned()),
            ..ProxyConfig::default()
        };
        assert_eq!(
            serde_json::to_value(&proxy).unwrap()["proxy_url"],
            unredacted
        );
    }

    // Malformed, schemeless, and disallowed-scheme proxy URLs never leak passwords in Debug,
    // Serialize, ProxyConfig::validate(), or build_client() errors.
    for (raw, secret) in [
        ("ftp://u:ftp-secret@127.0.0.1:21", "ftp-secret"),
        ("http://u:badport-secret@127.0.0.1:99999", "badport-secret"),
        ("u:schemeless-secret@proxy:8080", "schemeless-secret"),
        ("u:late-scheme-secret@proxy://x", "late-scheme-secret"),
        ("http://u:slash/secret@proxy:8080", "slash/secret"),
    ] {
        let proxy = ProxyConfig {
            proxy_url: Some(raw.to_owned()),
            ..ProxyConfig::default()
        };
        if let Err(err) = proxy.validate() {
            assert!(!err.contains(secret), "validate() leaked {secret}: {err}");
        }
        let cfg = HttpClientConfig {
            proxy_config: proxy.clone(),
            ..HttpClientConfig::default()
        };
        let build_err = cfg.build_client().unwrap_err().to_string();
        let pdbg = format!("{proxy:?}");
        let pjson = serde_json::to_string(&proxy).unwrap();
        assert!(
            !build_err.contains(secret),
            "build_client() leaked {secret}: {build_err}"
        );
        assert!(!pdbg.contains(secret), "Debug leaked {secret}: {pdbg}");
        assert!(
            !pjson.contains(secret),
            "Serialize leaked {secret}: {pjson}"
        );
    }

    // `From<reqwest::Error>` strips embedded URL passwords.
    let client = HttpClientConfig::default().build_client().unwrap();
    let default_cfg = HttpClientConfig::default();
    let err = default_cfg
        .apply_to_request(client.get("http://u:req-url-secret@127.0.0.1:99999/metrics"))
        .unwrap_err();
    assert!(matches!(err, HttpConfigError::Http(_)));
    let err_str = err.to_string();
    assert!(
        !err_str.contains("req-url-secret"),
        "HttpConfigError::Http leaked password: {err_str}"
    );
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
        let dir = TempDir::new("mtls");
        let user_file = dir.path().join("user.txt");
        let pass_file = dir.path().join("pass.txt");
        let hdr_file = dir.path().join("hdr.txt");
        std::fs::write(&user_file, "prom-user\n").unwrap();
        std::fs::write(&pass_file, "prom-pass\n").unwrap();
        std::fs::write(&hdr_file, "from-file\n").unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(TEST_CA_CERT_PEM.as_bytes()).unwrap())
            .unwrap();
        let verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .unwrap();
        let server_cert = CertificateDer::from_pem_slice(TEST_SERVER_CERT_PEM.as_bytes()).unwrap();
        let server_key = PrivateKeyDer::from_pem_slice(TEST_SERVER_KEY_PEM.as_bytes()).unwrap();
        let tls_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::task::spawn_local(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP connection");
            let mut tls_stream = acceptor.accept(tcp).await.expect("accept mTLS handshake");
            let req_str = read_http_head(&mut tls_stream).await;
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
            tls_stream
                .write_all(resp.as_bytes())
                .await
                .expect("write HTTP response");
            tls_stream.shutdown().await.expect("shutdown TLS stream");
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
                key: Secret::from(TEST_CLIENT_KEY_PEM),
                min_version: Some(TlsVersion::TLS12),
                max_version: Some(TlsVersion::TLS13),
                ..TlsConfig::default()
            },
            http_headers: Some(Headers {
                headers: BTreeMap::from([(
                    "X-Trace".to_owned(),
                    Header {
                        values: vec!["plain-val".to_owned()],
                        secrets: vec![Secret::from("secret-val")],
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
        server.await.unwrap();
    });
}

#[test]
fn apply_to_request_auth_headers_and_error_paths() {
    let dir = TempDir::new("apply-req");
    let tok_file = dir.path().join("token.txt");
    let empty_tok_file = dir.path().join("empty.txt");
    let hdr_file = dir.path().join("hdr.txt");
    let bad_hdr_file = dir.path().join("bad_hdr.txt");
    std::fs::write(&tok_file, "  file-token \n").unwrap();
    std::fs::write(&empty_tok_file, " \n ").unwrap();
    std::fs::write(&hdr_file, " file-hdr \n").unwrap();
    std::fs::write(&bad_hdr_file, "bad\r\nvalue").unwrap();

    let client = HttpClientConfig::default().build_client().unwrap();

    // BasicAuth inline with empty password encodes "alice:" (`YWxpY2U6`).
    let ba_empty_pw = HttpClientConfig {
        basic_auth: Some(BasicAuth {
            username: "alice".to_owned(),
            ..BasicAuth::default()
        }),
        ..HttpClientConfig::default()
    };
    let req = ba_empty_pw
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    let auth = req.headers().get(AUTHORIZATION).unwrap();
    assert_eq!(auth, "Basic YWxpY2U6");
    assert!(auth.is_sensitive());

    // Authorization: custom type, empty inline credentials (Go emits "<type> "), verbatim inline
    // whitespace, and credentials_file trimming.
    let auth_empty_creds = HttpClientConfig {
        authorization: Some(Authorization {
            auth_type: "APIKEY".to_owned(),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    let req = auth_empty_creds
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "APIKEY ");

    let auth_inline_ws = HttpClientConfig {
        authorization: Some(Authorization {
            auth_type: "Token".to_owned(),
            credentials: Secret::from("  spaced "),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    let req = auth_inline_ws
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Token   spaced ");
    assert!(req.headers().get(AUTHORIZATION).unwrap().is_sensitive());

    // Whitespace-only bearer_token behaves identically before and after validate().
    let mut ws_bearer = HttpClientConfig {
        bearer_token: Secret::from("  "),
        ..HttpClientConfig::default()
    };
    let pre = ws_bearer
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    ws_bearer.validate().unwrap();
    let post = ws_bearer
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        pre.headers().get(AUTHORIZATION),
        post.headers().get(AUTHORIZATION)
    );
    assert_eq!(pre.headers().get(AUTHORIZATION).unwrap(), "Bearer   ");

    // bearer_token_file trims whitespace and emits "Bearer " when empty, matching post-validate().
    let mut file_bearer = HttpClientConfig {
        bearer_token_file: tok_file.to_string_lossy().into_owned(),
        ..HttpClientConfig::default()
    };
    let req = file_bearer
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req.headers().get(AUTHORIZATION).unwrap(),
        "Bearer file-token"
    );
    file_bearer.validate().unwrap();
    let req2 = file_bearer
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        req2.headers().get(AUTHORIZATION).unwrap(),
        "Bearer file-token"
    );

    let empty_file_bearer = HttpClientConfig {
        bearer_token_file: empty_tok_file.to_string_lossy().into_owned(),
        ..HttpClientConfig::default()
    };
    let req = empty_file_bearer
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(req.headers().get(AUTHORIZATION).unwrap(), "Bearer ");

    // Pre-existing Authorization header (explicit or from URL userinfo) is preserved without
    // appending a duplicate Authorization header.
    let req_with_hdr = ba_empty_pw
        .apply_to_request(
            client
                .get("http://127.0.0.1/metrics")
                .header(AUTHORIZATION, "Custom existing"),
        )
        .unwrap()
        .build()
        .unwrap();
    let vals: Vec<&str> = req_with_hdr
        .headers()
        .get_all(AUTHORIZATION)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(vals, vec!["Custom existing"]);

    let req_with_userinfo = ba_empty_pw
        .apply_to_request(client.get("http://urluser:urlpass@127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    let vals: Vec<&str> = req_with_userinfo
        .headers()
        .get_all(AUTHORIZATION)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(vals.len(), 1);
    assert_eq!(vals[0], "Basic dXJsdXNlcjp1cmxwYXNz");

    // Unvalidated invalid configs fail in both build_client() and apply_to_request().
    let bad_auth = HttpClientConfig {
        authorization: Some(Authorization {
            auth_type: "Basic".to_owned(),
            credentials: Secret::from("tok"),
            ..Authorization::default()
        }),
        ..HttpClientConfig::default()
    };
    assert!(bad_auth.build_client().is_err());
    assert!(
        bad_auth
            .apply_to_request(client.get("http://127.0.0.1/metrics"))
            .is_err()
    );

    // Unsupported runtime refs fail in apply_to_request().
    for ref_cfg in [
        HttpClientConfig {
            basic_auth: Some(BasicAuth {
                password_ref: "pw-ref".to_owned(),
                ..BasicAuth::default()
            }),
            ..HttpClientConfig::default()
        },
        HttpClientConfig {
            authorization: Some(Authorization {
                credentials_ref: "cred-ref".to_owned(),
                ..Authorization::default()
            }),
            ..HttpClientConfig::default()
        },
    ] {
        assert!(ref_cfg.build_client().is_err());
        assert!(
            ref_cfg
                .apply_to_request(client.get("http://127.0.0.1/metrics"))
                .is_err()
        );
    }

    // Missing header file returns HttpConfigError::Io with NotFound kind.
    let missing_hdr_file = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "X-Missing".to_owned(),
                Header {
                    files: vec![
                        dir.path()
                            .join("does-not-exist")
                            .to_string_lossy()
                            .into_owned(),
                    ],
                    ..Header::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    let err = missing_hdr_file
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap_err();
    match err {
        HttpConfigError::Io(io_err) => {
            assert_eq!(io_err.kind(), io::ErrorKind::NotFound);
            assert!(io_err.to_string().contains("unable to read headers file"));
        }
        other => panic!("expected HttpConfigError::Io, got {other:?}"),
    }

    // Reserved header rejected in apply_to_request even without prior validate().
    let reserved_hdr = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "x-prometheus-scrape-timeout-seconds".to_owned(),
                Header::default(),
            )]),
        }),
        ..HttpClientConfig::default()
    };
    assert_eq!(
        reserved_hdr
            .apply_to_request(client.get("http://127.0.0.1/metrics"))
            .unwrap_err()
            .to_string(),
        "setting header \"X-Prometheus-Scrape-Timeout-Seconds\" is not allowed"
    );

    // Invalid header name, inline value, and file value return InvalidConfig; valid header
    // sensitivity flags match source kind.
    let bad_hdr_name = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([("Bad Name".to_owned(), Header::default())]),
        }),
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        bad_hdr_name.apply_to_request(client.get("http://127.0.0.1/metrics")),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let bad_hdr_val = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "X-Bad".to_owned(),
                Header {
                    values: vec!["line1\r\nline2".to_owned()],
                    ..Header::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        bad_hdr_val.apply_to_request(client.get("http://127.0.0.1/metrics")),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let bad_file_hdr = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "X-Bad-File".to_owned(),
                Header {
                    files: vec![bad_hdr_file.to_string_lossy().into_owned()],
                    ..Header::default()
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        bad_file_hdr.apply_to_request(client.get("http://127.0.0.1/metrics")),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let mixed_hdrs = HttpClientConfig {
        http_headers: Some(Headers {
            headers: BTreeMap::from([(
                "X-Mix".to_owned(),
                Header {
                    values: vec!["plain".to_owned()],
                    secrets: vec![Secret::from("sec")],
                    files: vec![hdr_file.to_string_lossy().into_owned()],
                },
            )]),
        }),
        ..HttpClientConfig::default()
    };
    let req = mixed_hdrs
        .apply_to_request(client.get("http://127.0.0.1/metrics"))
        .unwrap()
        .build()
        .unwrap();
    let entries: Vec<(&str, bool)> = req
        .headers()
        .get_all("x-mix")
        .iter()
        .map(|v| (v.to_str().unwrap(), v.is_sensitive()))
        .collect();
    assert_eq!(
        entries,
        vec![("plain", false), ("sec", true), ("file-hdr", true)]
    );
}

#[test]
fn tls_files_pem_validation_versions_and_insecure_skip_verify() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let dir = TempDir::new("tls-files");
    let ca_file = dir.path().join("ca.pem");
    let cert_file = dir.path().join("client.crt");
    let key_file = dir.path().join("client.key");
    std::fs::write(&ca_file, TEST_CA_CERT_PEM).unwrap();
    std::fs::write(&cert_file, TEST_CLIENT_CERT_PEM.trim_end()).unwrap();
    std::fs::write(&key_file, TEST_CLIENT_KEY_PEM).unwrap();

    // Missing CA file -> Io error.
    let missing_ca = HttpClientConfig {
        tls_config: TlsConfig {
            ca_file: dir
                .path()
                .join("missing.pem")
                .to_string_lossy()
                .into_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        missing_ca.build_client(),
        Err(HttpConfigError::Io(_))
    ));

    // Non-PEM CA -> InvalidConfig.
    let non_pem_ca = HttpClientConfig {
        tls_config: TlsConfig {
            ca: "not a pem certificate".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert_eq!(
        non_pem_ca.build_client().unwrap_err().to_string(),
        "unable to parse CA certificate PEM"
    );

    // Swapped cert and key are rejected independently.
    let swapped = HttpClientConfig {
        tls_config: TlsConfig {
            cert: TEST_CLIENT_KEY_PEM.to_owned(),
            key: Secret::from(TEST_CLIENT_CERT_PEM),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        swapped.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    // Combined cert+key in `cert` paired with junk `key` is rejected.
    let combined_in_cert = HttpClientConfig {
        tls_config: TlsConfig {
            cert: format!("{TEST_CLIENT_CERT_PEM}{TEST_CLIENT_KEY_PEM}"),
            key: Secret::from("not-a-key"),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        combined_in_cert.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    // Malformed PEM markers (missing END or nested BEGIN) are rejected.
    let unclosed_cert = HttpClientConfig {
        tls_config: TlsConfig {
            cert: "-----BEGIN CERTIFICATE-----\nAAAA\n".to_owned(),
            key: Secret::from(TEST_CLIENT_KEY_PEM),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        unclosed_cert.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let nested_begin = HttpClientConfig {
        tls_config: TlsConfig {
            cert: format!("-----BEGIN CERTIFICATE-----\n{TEST_CLIENT_CERT_PEM}"),
            key: Secret::from(TEST_CLIENT_KEY_PEM),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        nested_begin.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    // Paired cert_ref + key_ref passes validate() and fails build_client().
    let mut cert_refs = HttpClientConfig {
        tls_config: TlsConfig {
            cert_ref: "c".to_owned(),
            key_ref: "k".to_owned(),
            ..TlsConfig::default()
        },
        ..HttpClientConfig::default()
    };
    cert_refs.validate().unwrap();
    assert_eq!(
        cert_refs.build_client().unwrap_err().to_string(),
        "cannot use secret ref without manager"
    );

    // max_version below TLS12 returns a clear InvalidConfig under rustls.
    for max_ver in [TlsVersion::TLS10, TlsVersion::TLS11] {
        let low_tls = HttpClientConfig {
            tls_config: TlsConfig {
                max_version: Some(max_ver),
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        };
        let err = low_tls.build_client().unwrap_err();
        assert!(matches!(err, HttpConfigError::InvalidConfig(_)));
        assert!(err.to_string().contains("TLS12"), "unexpected error: {err}");
    }

    // Live HTTPS tests: file-backed mTLS, combined tls.pem + EC PARAMETERS, and
    // insecure_skip_verify.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let server_cert = CertificateDer::from_pem_slice(TEST_SERVER_CERT_PEM.as_bytes()).unwrap();
        let server_key = PrivateKeyDer::from_pem_slice(TEST_SERVER_KEY_PEM.as_bytes()).unwrap();
        let plain_tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert.clone()], server_key.clone_key())
            .unwrap();
        let plain_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(plain_tls_cfg));
        let plain_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let plain_addr = plain_listener.local_addr().unwrap();

        let plain_server = tokio::task::spawn_local(async move {
            // First connection is rejected by client (untrusted self-signed CA).
            let (tcp1, _) = plain_listener.accept().await.unwrap();
            let _ = plain_acceptor.accept(tcp1).await;

            // Second connection uses insecure_skip_verify: true and succeeds.
            let (tcp2, _) = plain_listener.accept().await.unwrap();
            let mut tls = plain_acceptor.accept(tcp2).await.unwrap();
            let req = read_http_head(&mut tls).await;
            assert!(
                req.lines()
                    .any(|l| l.eq_ignore_ascii_case("user-agent: custom-prom")),
                "missing custom user-agent from client_builder() in:\n{req}"
            );
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ninsecure";
            tls.write_all(resp.as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let strict_client = HttpClientConfig {
            enable_http2: false,
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        assert!(
            strict_client
                .get(format!("https://{plain_addr}/metrics"))
                .send()
                .await
                .is_err()
        );

        let insecure_client = HttpClientConfig {
            enable_http2: false,
            tls_config: TlsConfig {
                insecure_skip_verify: true,
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .client_builder()
        .unwrap()
        .user_agent("custom-prom")
        .build()
        .unwrap();
        let body = insecure_client
            .get(format!("https://{plain_addr}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "insecure");
        plain_server.await.unwrap();

        // File-backed mTLS and combined tls.pem (with EC PARAMETERS) presenting 1 cert.
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from_pem_slice(TEST_CA_CERT_PEM.as_bytes()).unwrap())
            .unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let mtls_cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        let mtls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(mtls_cfg));
        let mtls_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let mtls_addr = mtls_listener.local_addr().unwrap();
        let mtls_server = tokio::task::spawn_local(async move {
            for _ in 0..2 {
                let (tcp, _) = mtls_listener.accept().await.unwrap();
                let mut tls = mtls_acceptor.accept(tcp).await.unwrap();
                assert_eq!(
                    tls.get_ref().1.peer_certificates().unwrap().len(),
                    1,
                    "client must present exactly one certificate"
                );
                let _ = read_http_head(&mut tls).await;
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmtls";
                tls.write_all(resp.as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            }
        });

        let file_mtls_client = HttpClientConfig {
            enable_http2: false,
            tls_config: TlsConfig {
                ca_file: ca_file.to_string_lossy().into_owned(),
                cert_file: cert_file.to_string_lossy().into_owned(),
                key_file: key_file.to_string_lossy().into_owned(),
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let body = file_mtls_client
            .get(format!("https://{mtls_addr}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "mtls");

        let combined_file = dir.path().join("tls.pem");
        std::fs::write(
            &combined_file,
            format!(
                "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n\
                 {TEST_CLIENT_CERT_PEM}{TEST_CLIENT_KEY_PEM}"
            ),
        )
        .unwrap();
        let combined_mtls_client = HttpClientConfig {
            enable_http2: false,
            tls_config: TlsConfig {
                ca_file: ca_file.to_string_lossy().into_owned(),
                cert_file: combined_file.to_string_lossy().into_owned(),
                key_file: combined_file.to_string_lossy().into_owned(),
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let body2 = combined_mtls_client
            .get(format!("https://{mtls_addr}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body2, "mtls");
        mtls_server.await.unwrap();
    });
}

#[test]
fn proxy_routing_connect_headers_redirects_and_http2() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // proxy_from_environment without proxy_connect_header succeeds.
    let env_proxy = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_from_environment: true,
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    env_proxy.build_client().unwrap();

    // Invalid proxy_connect_header name/value rejected.
    let bad_proxy_hdr_name = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_url: Some("http://127.0.0.1:8080".to_owned()),
            proxy_connect_header: BTreeMap::from([(
                "Bad Header".to_owned(),
                vec![Secret::from("v")],
            )]),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        bad_proxy_hdr_name.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let bad_proxy_hdr_val = HttpClientConfig {
        proxy_config: ProxyConfig {
            proxy_url: Some("http://127.0.0.1:8080".to_owned()),
            proxy_connect_header: BTreeMap::from([(
                "Proxy-Token".to_owned(),
                vec![Secret::from("bad\r\nval")],
            )]),
            ..ProxyConfig::default()
        },
        ..HttpClientConfig::default()
    };
    assert!(matches!(
        bad_proxy_hdr_val.build_client(),
        Err(HttpConfigError::InvalidConfig(_))
    ));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        // 1. Proxy routing: plain HTTP must NOT receive proxy_connect_header; HTTPS CONNECT MUST
        // receive proxy_connect_header; no_proxy must bypass the proxy.
        let proxy_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let direct_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let direct_addr = direct_listener.local_addr().unwrap();

        let proxy_server = tokio::task::spawn_local(async move {
            // Connection 1: plain HTTP request routed through proxy.
            let (mut s1, _) = proxy_listener.accept().await.unwrap();
            let req1 = read_http_head(&mut s1).await;
            assert!(
                req1.starts_with("GET http://target.example:9090/metrics HTTP/1.1"),
                "expected proxied GET, got:\n{req1}"
            );
            assert!(
                !req1.to_ascii_lowercase().contains("proxy-token"),
                "proxy_connect_header leaked onto plain HTTP request:\n{req1}"
            );
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied";
            s1.write_all(resp.as_bytes()).await.unwrap();
            s1.shutdown().await.unwrap();

            // Connection 2: HTTPS CONNECT request carrying proxy_connect_header.
            let (mut s2, _) = proxy_listener.accept().await.unwrap();
            let req2 = read_http_head(&mut s2).await;
            assert!(
                req2.starts_with("CONNECT target.example:443 HTTP/1.1"),
                "expected CONNECT request, got:\n{req2}"
            );
            assert!(
                req2.lines()
                    .any(|l| l.eq_ignore_ascii_case("proxy-token: connect-secret")),
                "missing proxy_connect_header on CONNECT:\n{req2}"
            );
            let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            s2.write_all(resp.as_bytes()).await.unwrap();
            s2.shutdown().await.unwrap();
        });

        let direct_server = tokio::task::spawn_local(async move {
            let (mut s, _) = direct_listener.accept().await.unwrap();
            let req = read_http_head(&mut s).await;
            assert!(req.starts_with("GET /direct HTTP/1.1"), "unexpected:\n{req}");
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect";
            s.write_all(resp.as_bytes()).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let proxy_client = HttpClientConfig {
            enable_http2: false,
            proxy_config: ProxyConfig {
                proxy_url: Some(format!("http://{proxy_addr}")),
                no_proxy: "127.0.0.1".to_owned(),
                proxy_connect_header: BTreeMap::from([(
                    "Proxy-Token".to_owned(),
                    vec![Secret::from("connect-secret")],
                )]),
                ..ProxyConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();

        let body = proxy_client
            .get("http://target.example:9090/metrics")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "proxied");

        // HTTPS request triggers CONNECT with proxy_connect_header (mock proxy replies 502).
        assert!(
            proxy_client
                .get("https://target.example:443/metrics")
                .send()
                .await
                .is_err()
        );

        // Request to 127.0.0.1 matches no_proxy and connects directly.
        let direct_body = proxy_client
            .get(format!("http://{direct_addr}/direct"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(direct_body, "direct");

        proxy_server.await.unwrap();
        direct_server.await.unwrap();

        // 2. Redirect policy: follow_redirects = false returns 302, true follows to 200.
        let redir_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let redir_addr = redir_listener.local_addr().unwrap();
        let redir_server = tokio::task::spawn_local(async move {
            for _ in 0..3 {
                let (mut s, _) = redir_listener.accept().await.unwrap();
                let req = read_http_head(&mut s).await;
                let resp = if req.starts_with("GET /start ") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{redir_addr}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded"
                        .to_owned()
                };
                s.write_all(resp.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
            }
        });

        let no_redir_client = HttpClientConfig {
            follow_redirects: false,
            enable_http2: false,
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let resp = no_redir_client
            .get(format!("http://{redir_addr}/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::FOUND);

        let follow_client = HttpClientConfig {
            follow_redirects: true,
            enable_http2: false,
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let resp = follow_client
            .get(format!("http://{redir_addr}/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "landed");
        redir_server.await.unwrap();

        // 3. enable_http2 controls ALPN negotiation ("h2" vs "http/1.1").
        let server_cert = CertificateDer::from_pem_slice(TEST_SERVER_CERT_PEM.as_bytes()).unwrap();
        let server_key = PrivateKeyDer::from_pem_slice(TEST_SERVER_KEY_PEM.as_bytes()).unwrap();
        let mut alpn_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap();
        alpn_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let alpn_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(alpn_cfg));
        let alpn_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let alpn_addr = alpn_listener.local_addr().unwrap();

        let alpn_server = tokio::task::spawn_local(async move {
            let mut negotiated = Vec::new();
            for _ in 0..2 {
                let (tcp, _) = alpn_listener.accept().await.unwrap();
                let mut tls = alpn_acceptor.accept(tcp).await.unwrap();
                let proto = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned());
                negotiated.push(proto);
                let _ = tls.shutdown().await;
            }
            negotiated
        });

        let h1_client = HttpClientConfig {
            enable_http2: false,
            tls_config: TlsConfig {
                ca: TEST_CA_CERT_PEM.to_owned(),
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let _ = h1_client
            .get(format!("https://{alpn_addr}/metrics"))
            .send()
            .await;

        let h2_client = HttpClientConfig {
            enable_http2: true,
            tls_config: TlsConfig {
                ca: TEST_CA_CERT_PEM.to_owned(),
                ..TlsConfig::default()
            },
            ..HttpClientConfig::default()
        }
        .build_client()
        .unwrap();
        let _ = h2_client
            .get(format!("https://{alpn_addr}/metrics"))
            .send()
            .await;

        let negotiated = alpn_server.await.unwrap();
        assert_eq!(
            negotiated,
            vec![Some("http/1.1".to_owned()), Some("h2".to_owned())]
        );
    });
}
