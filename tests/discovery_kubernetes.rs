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

//! Integration tests for Kubernetes pod service discovery (`kubernetes_sd_configs` for `role: pod`).

#![cfg(feature = "discovery-kubernetes")]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use expfmt::discovery::kubernetes::{
    Job, KubernetesAttachMetadataConfig, KubernetesMetadataContext, KubernetesNamespaceDiscovery,
    KubernetesPodDiscovery, KubernetesRole, KubernetesSdConfig, KubernetesSelectorConfig,
    Namespace, Node, OwnerReference, ReplicaSet, build_pod_target_group,
};
use expfmt::discovery::{
    ADDRESS_LABEL, Authorization, BasicAuth, DiscoveryConfigs, HttpClientConfig, HttpHeader,
    HttpHeaders, LabelSet, OAuth2, Pod, TlsConfig, TlsVersion,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn label_set(pairs: &[(&str, &str)]) -> LabelSet {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn kubernetes_sd_config_validation_matches_prometheus() {
    // Unknown fields on KubernetesSdConfig and DiscoveryConfigs are rejected even with flattened HttpClientConfig.
    assert!(
        serde_json::from_str::<KubernetesSdConfig>(
            r#"{"role": "pod", "api_server": "https://127.0.0.1:6443", "bearer_tokens": "abc"}"#
        )
        .is_err()
    );
    let mut top_cfg: DiscoveryConfigs = serde_json::from_str(
        r#"{"kubernetes_sd_configs": [{"role": "pod", "api_server": "https://127.0.0.1:6443", "bearer_token": "abc"}]}"#,
    )
    .unwrap();
    top_cfg.validate().unwrap();

    // Missing role.
    let mut cfg = KubernetesSdConfig::default();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "role missing (one of: pod, service, endpoints, endpointslice, node, ingress)"
    );

    // Both api_server and kubeconfig_file.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "api_server": "https://127.0.0.1:6443",
            "kubeconfig_file": "/etc/kubeconfig"
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "cannot use 'kubeconfig_file' and 'api_server' simultaneously"
    );

    // Custom HTTP client config without api_server.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "bearer_token": "secret-token"
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "to use custom HTTP client configuration please provide the 'api_server' URL explicitly"
    );

    // api_server with namespaces.own_namespace.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "api_server": "https://127.0.0.1:6443",
            "namespaces": { "own_namespace": true }
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "cannot use 'api_server' and 'namespaces.own_namespace' simultaneously"
    );

    // Duplicated selector role.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "selectors": [
                { "role": "pod", "label": "app=web" },
                { "role": "pod", "field": "status.phase=Running" }
            ]
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "duplicated selector role: pod"
    );

    // Disallowed selector role for pod.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "selectors": [
                { "role": "service", "label": "app=web" }
            ]
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "pod role supports only pod, node selectors"
    );

    // HTTPClientConfig validation: bearer_token + bearer_token_file.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "api_server": "https://127.0.0.1:6443",
            "bearer_token": "tok",
            "bearer_token_file": "/path/to/tok"
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "at most one of bearer_token & bearer_token_file must be configured"
    );

    // Reserved HTTP header.
    let mut cfg: KubernetesSdConfig = serde_json::from_str(
        r#"{
            "role": "pod",
            "api_server": "https://127.0.0.1:6443",
            "http_headers": {
                "Authorization": { "values": ["Bearer foo"] }
            }
        }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.validate().unwrap_err().to_string(),
        "setting header \"Authorization\" is not allowed"
    );

    // Valid pod config with pod + node selectors, TLS, and custom header.
    let mut cfg = KubernetesSdConfig {
        api_server: Some("https://127.0.0.1:6443".to_owned()),
        role: Some(KubernetesRole::Pod),
        kubeconfig_file: String::new(),
        http_client_config: HttpClientConfig {
            basic_auth: Some(BasicAuth {
                username: "prom".to_owned(),
                password: "secret".to_owned(),
                ..BasicAuth::default()
            }),
            tls_config: TlsConfig {
                min_version: Some(TlsVersion::Tls12),
                max_version: Some(TlsVersion::Tls13),
                ..TlsConfig::default()
            },
            http_headers: Some(HttpHeaders {
                headers: BTreeMap::from([(
                    "X-Custom-Scope".to_owned(),
                    HttpHeader {
                        values: vec!["otap".to_owned()],
                        ..HttpHeader::default()
                    },
                )]),
            }),
            ..HttpClientConfig::default()
        },
        namespaces: KubernetesNamespaceDiscovery {
            own_namespace: false,
            names: vec!["default".to_owned(), "monitoring".to_owned()],
        },
        selectors: vec![
            KubernetesSelectorConfig {
                role: Some(KubernetesRole::Pod),
                label: "app=prometheus".to_owned(),
                field: "status.phase=Running".to_owned(),
            },
            KubernetesSelectorConfig {
                role: Some(KubernetesRole::Node),
                label: "region=eu-west-1".to_owned(),
                field: String::new(),
            },
        ],
        attach_metadata: KubernetesAttachMetadataConfig {
            node: true,
            namespace: true,
            deployment: true,
            job: true,
            cronjob: true,
        },
    };
    cfg.validate().expect("valid KubernetesSdConfig");

    // set_directory resolves relative paths across kubeconfig_file and http_client_config.
    let mut dir_cfg = KubernetesSdConfig {
        kubeconfig_file: "certs/kubeconfig".to_owned(),
        http_client_config: HttpClientConfig {
            bearer_token_file: "secrets/token".to_owned(),
            authorization: Some(Authorization {
                credentials_file: "secrets/creds".to_owned(),
                ..Authorization::default()
            }),
            oauth2: Some(OAuth2 {
                client_secret_file: "oauth/secret".to_owned(),
                ..OAuth2::default()
            }),
            ..HttpClientConfig::default()
        },
        ..KubernetesSdConfig::default()
    };
    dir_cfg.set_directory(std::path::Path::new("/etc/prometheus"));
    assert_eq!(dir_cfg.kubeconfig_file, "/etc/prometheus/certs/kubeconfig");
    assert_eq!(
        dir_cfg.http_client_config.bearer_token_file,
        "/etc/prometheus/secrets/token"
    );
}

#[test]
fn kubernetes_pod_target_groups_match_prometheus_pod_test() {
    // Ported from TestPodDiscoveryAdd in discovery/kubernetes/pod_test.go.
    let empty_meta = KubernetesMetadataContext::default();
    let no_attach = KubernetesAttachMetadataConfig::default();

    // 1. Single container + multiple ports + portless container + initContainer.
    let pod: Pod = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "testpod",
            "namespace": "default",
            "uid": "deadbeef",
            "labels": { "test/label": "value1" },
            "annotations": { "test/annotation": "value2" },
            "ownerReferences": [{
                "kind": "ReplicaSet",
                "name": "testdeployment-4228282135",
                "controller": true
            }]
        },
        "spec": {
            "nodeName": "testnode",
            "containers": [
                {
                    "name": "c1",
                    "image": "c1:latest",
                    "ports": [
                        { "name": "mainport", "containerPort": 9000, "protocol": "TCP" },
                        { "name": "mgmtport", "containerPort": 9001, "protocol": "UDP" }
                    ]
                },
                {
                    "name": "c2_portless",
                    "image": "c2:latest",
                    "ports": []
                }
            ],
            "initContainers": [{
                "name": "init_c",
                "image": "busybox:latest",
                "ports": [{ "name": "initport", "containerPort": 9100, "protocol": "TCP" }]
            }]
        },
        "status": {
            "phase": "Running",
            "podIP": "10.0.0.1",
            "hostIP": "192.168.1.10",
            "conditions": [{ "type": "Ready", "status": "True" }],
            "containerStatuses": [
                { "name": "c1", "containerID": "docker://c1-id" },
                { "name": "c2_portless", "containerID": "docker://c2-id" }
            ],
            "initContainerStatuses": [
                { "name": "init_c", "containerID": "docker://init-id" }
            ]
        }
    }))
    .unwrap();

    let node: Node = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "testnode",
            "labels": { "node.k8s.io/zone": "us-east1-b" },
            "annotations": { "node.k8s.io/ann": "nval" }
        }
    }))
    .unwrap();
    let ns: Namespace = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "default",
            "labels": { "ns-label": "nsval" },
            "annotations": { "ns-ann": "nsannval" }
        }
    }))
    .unwrap();
    let rs: ReplicaSet = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "testdeployment-4228282135",
            "namespace": "default",
            "ownerReferences": [{
                "kind": "Deployment",
                "name": "testdeployment",
                "controller": true
            }]
        }
    }))
    .unwrap();
    let meta = KubernetesMetadataContext::from_items(vec![node], vec![ns], vec![rs], vec![]);
    let attach_all = KubernetesAttachMetadataConfig {
        node: true,
        namespace: true,
        deployment: true,
        job: true,
        cronjob: true,
    };

    let tg = build_pod_target_group(&pod, &meta, &attach_all);
    assert_eq!(tg.source, "pod/default/testpod");
    assert_eq!(
        tg.labels,
        label_set(&[
            ("__meta_kubernetes_namespace", "default"),
            ("__meta_kubernetes_namespace_annotation_ns_ann", "nsannval"),
            (
                "__meta_kubernetes_namespace_annotationpresent_ns_ann",
                "true"
            ),
            ("__meta_kubernetes_namespace_label_ns_label", "nsval"),
            ("__meta_kubernetes_namespace_labelpresent_ns_label", "true"),
            ("__meta_kubernetes_node_annotation_node_k8s_io_ann", "nval"),
            (
                "__meta_kubernetes_node_annotationpresent_node_k8s_io_ann",
                "true"
            ),
            (
                "__meta_kubernetes_node_label_node_k8s_io_zone",
                "us-east1-b"
            ),
            (
                "__meta_kubernetes_node_labelpresent_node_k8s_io_zone",
                "true"
            ),
            ("__meta_kubernetes_node_name", "testnode"),
            ("__meta_kubernetes_pod_annotation_test_annotation", "value2"),
            (
                "__meta_kubernetes_pod_annotationpresent_test_annotation",
                "true"
            ),
            ("__meta_kubernetes_pod_controller_kind", "ReplicaSet"),
            (
                "__meta_kubernetes_pod_controller_name",
                "testdeployment-4228282135"
            ),
            ("__meta_kubernetes_pod_deployment_name", "testdeployment"),
            ("__meta_kubernetes_pod_host_ip", "192.168.1.10"),
            ("__meta_kubernetes_pod_ip", "10.0.0.1"),
            ("__meta_kubernetes_pod_label_test_label", "value1"),
            ("__meta_kubernetes_pod_labelpresent_test_label", "true"),
            ("__meta_kubernetes_pod_name", "testpod"),
            ("__meta_kubernetes_pod_node_name", "testnode"),
            ("__meta_kubernetes_pod_phase", "Running"),
            ("__meta_kubernetes_pod_ready", "true"),
            ("__meta_kubernetes_pod_uid", "deadbeef"),
        ])
    );
    assert_eq!(
        tg.targets,
        vec![
            label_set(&[
                ("__address__", "10.0.0.1:9000"),
                ("__meta_kubernetes_pod_container_id", "docker://c1-id"),
                ("__meta_kubernetes_pod_container_image", "c1:latest"),
                ("__meta_kubernetes_pod_container_init", "false"),
                ("__meta_kubernetes_pod_container_name", "c1"),
                ("__meta_kubernetes_pod_container_port_name", "mainport"),
                ("__meta_kubernetes_pod_container_port_number", "9000"),
                ("__meta_kubernetes_pod_container_port_protocol", "TCP"),
            ]),
            label_set(&[
                ("__address__", "10.0.0.1:9001"),
                ("__meta_kubernetes_pod_container_id", "docker://c1-id"),
                ("__meta_kubernetes_pod_container_image", "c1:latest"),
                ("__meta_kubernetes_pod_container_init", "false"),
                ("__meta_kubernetes_pod_container_name", "c1"),
                ("__meta_kubernetes_pod_container_port_name", "mgmtport"),
                ("__meta_kubernetes_pod_container_port_number", "9001"),
                ("__meta_kubernetes_pod_container_port_protocol", "UDP"),
            ]),
            label_set(&[
                ("__address__", "10.0.0.1"),
                ("__meta_kubernetes_pod_container_id", "docker://c2-id"),
                ("__meta_kubernetes_pod_container_image", "c2:latest"),
                ("__meta_kubernetes_pod_container_init", "false"),
                ("__meta_kubernetes_pod_container_name", "c2_portless"),
            ]),
            label_set(&[
                ("__address__", "10.0.0.1:9100"),
                ("__meta_kubernetes_pod_container_id", "docker://init-id"),
                ("__meta_kubernetes_pod_container_image", "busybox:latest"),
                ("__meta_kubernetes_pod_container_init", "true"),
                ("__meta_kubernetes_pod_container_name", "init_c"),
                ("__meta_kubernetes_pod_container_port_name", "initport"),
                ("__meta_kubernetes_pod_container_port_number", "9100"),
                ("__meta_kubernetes_pod_container_port_protocol", "TCP"),
            ]),
        ]
    );

    // 2. Pending / Evicted pod without PodIP returns empty TargetGroup.
    let mut pending_pod = pod.clone();
    pending_pod.status.pod_ip.clear();
    let pending_tg = build_pod_target_group(&pending_pod, &empty_meta, &no_attach);
    assert_eq!(pending_tg.source, "pod/default/testpod");
    assert!(pending_tg.targets.is_empty());
    assert!(pending_tg.labels.is_empty());

    // 3. Node filtering when attach_metadata.node = true and pod's node is absent from store.
    let filtered_tg = build_pod_target_group(&pod, &empty_meta, &attach_all);
    assert_eq!(filtered_tg.source, "pod/default/testpod");
    assert!(filtered_tg.targets.is_empty());
    assert!(filtered_tg.labels.is_empty());

    // 4. Job -> CronJob resolution when attach_metadata.job and attach_metadata.cronjob are true.
    let mut job_owner = OwnerReference::default();
    job_owner.kind = "Job".to_owned();
    job_owner.name = "nightly-job-123".to_owned();
    job_owner.controller = Some(true);
    let mut job_pod = pod;
    job_pod.metadata.owner_references = vec![job_owner];
    let job: Job = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": "nightly-job-123",
            "namespace": "default",
            "ownerReferences": [{
                "kind": "CronJob",
                "name": "nightly-job",
                "controller": true
            }]
        }
    }))
    .unwrap();
    let job_meta = KubernetesMetadataContext::from_items(vec![], vec![], vec![], vec![job]);
    let job_attach = KubernetesAttachMetadataConfig {
        job: true,
        cronjob: true,
        ..KubernetesAttachMetadataConfig::default()
    };
    let job_tg = build_pod_target_group(&job_pod, &job_meta, &job_attach);
    assert_eq!(
        job_tg.labels.get("__meta_kubernetes_pod_controller_kind"),
        Some(&"Job".to_owned())
    );
    assert_eq!(
        job_tg.labels.get("__meta_kubernetes_pod_job_name"),
        Some(&"nightly-job-123".to_owned())
    );
    assert_eq!(
        job_tg.labels.get("__meta_kubernetes_pod_cronjob_name"),
        Some(&"nightly-job".to_owned())
    );
}

#[test]
fn kubernetes_model_and_validation_edge_cases() {
    assert!(serde_json::from_str::<KubernetesSdConfig>(r#"{"role": "POD"}"#).is_err());
    let mut bad_scheme: KubernetesSdConfig =
        serde_json::from_str(r#"{"role": "pod", "api_server": "ftp://k8s.local"}"#).unwrap();
    assert!(bad_scheme.validate().is_err());
    let mut bad_query: KubernetesSdConfig =
        serde_json::from_str(r#"{"role": "pod", "api_server": "https://k8s.local?watch=true"}"#)
            .unwrap();
    assert!(bad_query.validate().is_err());
    let mut bad_ns: KubernetesSdConfig =
        serde_json::from_str(r#"{"role": "pod", "namespaces": {"names": ["default?watch=true"]}}"#)
            .unwrap();
    assert!(bad_ns.validate().is_err());

    let ipv6_null_pod: Pod = serde_json::from_str(
        r#"{
            "metadata": {
                "name": "v6pod",
                "namespace": "prod",
                "labels": null,
                "annotations": null,
                "ownerReferences": [
                    {"kind": "Job", "name": "non-controller", "controller": false},
                    {"kind": "Job", "name": "cron-child-1", "controller": true}
                ]
            },
            "spec": {
                "nodeName": "n1",
                "containers": [
                    {"name": "app", "image": "app:v1", "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}]},
                    {"name": "sidecar", "image": "sc:v1", "ports": null}
                ],
                "initContainers": null
            },
            "status": {
                "phase": "Running",
                "podIP": "2001:db8::9",
                "conditions": [{"type": "Ready", "status": "False"}],
                "containerStatuses": null,
                "initContainerStatuses": null
            }
        }"#,
    )
    .unwrap();

    // Nameless Namespace entry in KubernetesMetadataContext must NOT clobber __meta_kubernetes_namespace.
    let ns_without_name: Namespace =
        serde_json::from_str(r#"{"metadata": {"labels": {"team": "obs"}}}"#).unwrap();
    let job_item: Job = serde_json::from_str(
        r#"{"metadata": {"name": "cron-child-1", "namespace": "prod", "ownerReferences": [{"kind": "CronJob", "name": "hourly", "controller": true}]}}"#,
    )
    .unwrap();
    let mut ctx = KubernetesMetadataContext::from_items(vec![], vec![], vec![], vec![job_item]);
    ctx.namespaces.insert("prod".to_owned(), ns_without_name);

    let tg_cron_only = build_pod_target_group(
        &ipv6_null_pod,
        &ctx,
        &KubernetesAttachMetadataConfig {
            namespace: true,
            job: false,
            cronjob: true,
            ..KubernetesAttachMetadataConfig::default()
        },
    );
    assert_eq!(
        tg_cron_only.labels.get("__meta_kubernetes_namespace"),
        Some(&"prod".to_owned())
    );
    assert_eq!(
        tg_cron_only
            .labels
            .get("__meta_kubernetes_namespace_label_team"),
        Some(&"obs".to_owned())
    );
    assert_eq!(
        tg_cron_only.labels.get("__meta_kubernetes_pod_ready"),
        Some(&"false".to_owned())
    );
    assert!(
        !tg_cron_only
            .labels
            .contains_key("__meta_kubernetes_pod_job_name")
    );
    assert_eq!(
        tg_cron_only
            .labels
            .get("__meta_kubernetes_pod_cronjob_name"),
        Some(&"hourly".to_owned())
    );
    assert_eq!(
        tg_cron_only.targets[0].get(ADDRESS_LABEL),
        Some(&"[2001:db8::9]:8080".to_owned())
    );
    assert_eq!(
        tg_cron_only.targets[1].get(ADDRESS_LABEL),
        Some(&"2001:db8::9".to_owned())
    );
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

#[tokio::test]
async fn kubernetes_pod_discovery_reqwest_end_to_end() {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut req_buf = vec![0u8; 4096];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req_str = String::from_utf8_lossy(&req_buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");
                assert!(
                    req_str
                        .lines()
                        .any(|l| l.eq_ignore_ascii_case("authorization: Bearer test-k8s-token")),
                    "missing bearer token header in:\n{req_str}"
                );

                let body = if first_line.starts_with(
                    "GET /api/v1/namespaces/monitoring/pods?labelSelector=app%3Dmetrics&fieldSelector=status.phase%3DRunning ",
                ) {
                    r#"{
                        "items": [{
                            "metadata": {
                                "name": "metrics-pod-0",
                                "namespace": "monitoring",
                                "uid": "uid-123",
                                "labels": {"app": "metrics"},
                                "ownerReferences": [{
                                    "kind": "ReplicaSet",
                                    "name": "metrics-rs",
                                    "controller": true
                                }]
                            },
                            "spec": {
                                "nodeName": "node-1",
                                "containers": [{
                                    "name": "exporter",
                                    "image": "prom/exporter:v1",
                                    "ports": [{
                                        "name": "http-metrics",
                                        "containerPort": 9100,
                                        "protocol": "TCP"
                                    }]
                                }]
                            },
                            "status": {
                                "phase": "Running",
                                "podIP": "10.244.0.9",
                                "hostIP": "192.168.10.5",
                                "conditions": [{"type": "Ready", "status": "True"}],
                                "containerStatuses": [{
                                    "name": "exporter",
                                    "containerID": "containerd://abc123"
                                }]
                            }
                        }]
                    }"#
                } else if first_line.starts_with("GET /api/v1/nodes?labelSelector=role%3Dworker ") {
                    r#"{
                        "items": [{
                            "metadata": {
                                "name": "node-1",
                                "labels": {"role": "worker"}
                            }
                        }]
                    }"#
                } else if first_line
                    .starts_with("GET /apis/apps/v1/namespaces/monitoring/replicasets ")
                {
                    r#"{
                        "items": [{
                            "metadata": {
                                "name": "metrics-rs",
                                "namespace": "monitoring",
                                "ownerReferences": [{
                                    "kind": "Deployment",
                                    "name": "metrics-deploy",
                                    "controller": true
                                }]
                            }
                        }]
                    }"#
                } else {
                    panic!("unexpected request line: {first_line}");
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    let cfg: KubernetesSdConfig = serde_json::from_str(&format!(
        r#"{{
            "api_server": "http://{addr}",
            "role": "pod",
            "bearer_token": "test-k8s-token",
            "namespaces": {{
                "names": ["monitoring"]
            }},
            "selectors": [
                {{
                    "role": "pod",
                    "label": "app=metrics",
                    "field": "status.phase=Running"
                }},
                {{
                    "role": "node",
                    "label": "role=worker"
                }}
            ],
            "attach_metadata": {{
                "node": true,
                "deployment": true
            }}
        }}"#
    ))
    .unwrap();

    let discovery = KubernetesPodDiscovery::new(cfg).unwrap();
    let groups = discovery.discover().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].source, "pod/monitoring/metrics-pod-0");
    assert_eq!(
        groups[0]
            .labels
            .get("__meta_kubernetes_pod_deployment_name"),
        Some(&"metrics-deploy".to_owned())
    );
    assert_eq!(
        groups[0].labels.get("__meta_kubernetes_node_label_role"),
        Some(&"worker".to_owned())
    );
    assert_eq!(
        groups[0].targets,
        vec![label_set(&[
            ("__address__", "10.244.0.9:9100"),
            ("__meta_kubernetes_pod_container_id", "containerd://abc123"),
            ("__meta_kubernetes_pod_container_image", "prom/exporter:v1"),
            ("__meta_kubernetes_pod_container_init", "false"),
            ("__meta_kubernetes_pod_container_name", "exporter"),
            ("__meta_kubernetes_pod_container_port_name", "http-metrics"),
            ("__meta_kubernetes_pod_container_port_number", "9100"),
            ("__meta_kubernetes_pod_container_port_protocol", "TCP"),
        ])]
    );
}

#[test]
fn https_mtls_all_namespaces_404_tolerance_and_localset_execution() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let dir =
            std::env::temp_dir().join(format!("scrape-rs-https-k8s-test-{}", std::process::id()));
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
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::task::spawn_local(async move {
                    let Ok(mut tls_stream) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut req_buf = vec![0u8; 4096];
                    let n = tls_stream.read(&mut req_buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&req_buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");
                    assert!(
                        req_str.lines().any(|l| l.eq_ignore_ascii_case(
                            "authorization: Basic cHJvbS11c2VyOnByb20tcGFzcw=="
                        )),
                        "missing basic auth in:\n{req_str}"
                    );
                    assert!(
                        req_str
                            .lines()
                            .any(|l| l.eq_ignore_ascii_case("x-trace-file: from-file")),
                        "missing file header in:\n{req_str}"
                    );

                    let (status, body) = if first_line.starts_with("GET /api/v1/pods ") {
                        (
                            "200 OK",
                            r#"{"items":[{"metadata":{"name":"job-pod","namespace":"batch-ns","ownerReferences":[{"kind":"Job","name":"job-1","controller":true}]},"spec":{"containers":[{"name":"worker","image":"worker:1","ports":[{"containerPort":9091,"protocol":"TCP"}]}]},"status":{"phase":"Running","podIP":"10.9.0.2"}}]}"#,
                        )
                    } else if first_line.starts_with("GET /api/v1/namespaces ") {
                        (
                            "200 OK",
                            r#"{"items":[{"metadata":{"name":"batch-ns","labels":{"tier":"batch"}}}]}"#,
                        )
                    } else if first_line.starts_with("GET /apis/batch/v1/jobs ") {
                        (
                            "200 OK",
                            r#"{"items":[{"metadata":{"name":"job-1","namespace":"batch-ns","ownerReferences":[{"kind":"CronJob","name":"nightly","controller":true}]}}]}"#,
                        )
                    } else if first_line.starts_with("GET /api/v1/namespaces/missing-ns ") {
                        ("404 Not Found", r#"{"status":"Failure","code":404}"#)
                    } else if first_line.starts_with("GET /api/v1/namespaces/missing-ns/pods ") {
                        ("200 OK", r#"{"items":null}"#)
                    } else if first_line.starts_with("GET /api/v1/namespaces/batch-ns ") {
                        (
                            "200 OK",
                            r#"{"metadata":{"name":"batch-ns","labels":{"tier":"batch"}}}"#,
                        )
                    } else if first_line.starts_with("GET /api/v1/namespaces/batch-ns/pods ") {
                        (
                            "200 OK",
                            r#"{"items":[{"metadata":{"name":"job-pod","namespace":"batch-ns"},"spec":{"containers":[{"name":"worker","image":"worker:1","ports":null}]},"status":{"phase":"Running","podIP":"10.9.0.2"}}]}"#,
                        )
                    } else {
                        panic!("unexpected HTTPS request: {first_line}");
                    };

                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls_stream.write_all(resp.as_bytes()).await;
                    let _ = tls_stream.shutdown().await;
                });
            }
        });

        let base_http = HttpClientConfig {
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
                    "X-Trace-File".to_owned(),
                    HttpHeader {
                        files: vec![hdr_file.to_string_lossy().into_owned()],
                        ..HttpHeader::default()
                    },
                )]),
            }),
            ..HttpClientConfig::default()
        };

        // 1. All-namespaces HTTPS mTLS discovery with attach_metadata.{namespace, job, cronjob}.
        let all_ns_disc = KubernetesPodDiscovery::new(KubernetesSdConfig {
            api_server: Some(format!("https://{addr}")),
            role: Some(KubernetesRole::Pod),
            http_client_config: base_http.clone(),
            attach_metadata: KubernetesAttachMetadataConfig {
                namespace: true,
                job: true,
                cronjob: true,
                ..KubernetesAttachMetadataConfig::default()
            },
            ..KubernetesSdConfig::default()
        })
        .unwrap();

        let groups = tokio::task::spawn_local(async move { all_ns_disc.discover().await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0]
                .labels
                .get("__meta_kubernetes_namespace_label_tier"),
            Some(&"batch".to_owned())
        );
        assert_eq!(
            groups[0].labels.get("__meta_kubernetes_pod_cronjob_name"),
            Some(&"nightly".to_owned())
        );

        // 2. Multi-namespace HTTPS mTLS discovery where `missing-ns` returns `items: null` for pods
        // and `404 Not Found` for `GET /api/v1/namespaces/missing-ns` without aborting `batch-ns`.
        let multi_ns_disc = KubernetesPodDiscovery::new(KubernetesSdConfig {
            api_server: Some(format!("https://{addr}")),
            role: Some(KubernetesRole::Pod),
            http_client_config: base_http,
            namespaces: KubernetesNamespaceDiscovery {
                own_namespace: false,
                names: vec!["missing-ns".to_owned(), "batch-ns".to_owned()],
            },
            attach_metadata: KubernetesAttachMetadataConfig {
                namespace: true,
                ..KubernetesAttachMetadataConfig::default()
            },
            ..KubernetesSdConfig::default()
        })
        .unwrap();

        let multi_groups = tokio::task::spawn_local(async move { multi_ns_disc.discover().await })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(multi_groups.len(), 1);
        assert_eq!(multi_groups[0].source, "pod/batch-ns/job-pod");
        assert_eq!(
            multi_groups[0]
                .labels
                .get("__meta_kubernetes_namespace_label_tier"),
            Some(&"batch".to_owned())
        );

        let _ = std::fs::remove_dir_all(&dir);
    });
}
