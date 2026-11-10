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

use expfmt::discovery::kubernetes::{
    Job, KubernetesAttachMetadataConfig, KubernetesMetadataContext, KubernetesNamespaceDiscovery,
    KubernetesRole, KubernetesSdConfig, KubernetesSelectorConfig, Namespace, Node, OwnerReference,
    ReplicaSet, build_pod_target_group,
};
use expfmt::discovery::{
    ADDRESS_LABEL, Authorization, BasicAuth, DiscoveryConfigs, HttpClientConfig, HttpHeader,
    HttpHeaders, LabelSet, OAuth2, Pod, TlsConfig, TlsVersion,
};

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
