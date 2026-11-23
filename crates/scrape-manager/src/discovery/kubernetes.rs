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

//! Prometheus-compatible Kubernetes service discovery (`kubernetes_sd_configs`),
//! with `reqwest`-based discovery for `role: pod`.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::http_config::{
    HttpClientConfig, deserialize_string_or_scalar, join_dir, validate_go_url,
};

use super::{
    ADDRESS_LABEL, DiscoveryError, LabelSet, TargetGroup, deserialize_null_default, is_false,
};

const IN_CLUSTER_TOKEN_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const IN_CLUSTER_CA_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const IN_CLUSTER_NAMESPACE_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const USER_AGENT: &str = concat!("prometheus-scrape-manager/", env!("CARGO_PKG_VERSION"));

/// Meta label prefix for all Kubernetes discovery labels (`"__meta_kubernetes_"`).
pub const META_LABEL_PREFIX: &str = "__meta_kubernetes_";
/// Meta label storing the Kubernetes object namespace.
pub const NAMESPACE_LABEL: &str = "__meta_kubernetes_namespace";
/// Meta label storing the Kubernetes node name.
pub const NODE_NAME_LABEL: &str = "__meta_kubernetes_node_name";
/// Meta label storing the Kubernetes pod name.
pub const POD_NAME_LABEL: &str = "__meta_kubernetes_pod_name";
/// Meta label storing the Kubernetes pod IP address.
pub const POD_IP_LABEL: &str = "__meta_kubernetes_pod_ip";
/// Meta label storing the Kubernetes pod ready condition status (`"true"`, `"false"`, `"unknown"`).
pub const POD_READY_LABEL: &str = "__meta_kubernetes_pod_ready";
/// Meta label storing the Kubernetes pod lifecycle phase.
pub const POD_PHASE_LABEL: &str = "__meta_kubernetes_pod_phase";
/// Meta label storing the scheduled node name on the pod spec.
pub const POD_NODE_NAME_LABEL: &str = "__meta_kubernetes_pod_node_name";
/// Meta label storing the host IP where the pod is running.
pub const POD_HOST_IP_LABEL: &str = "__meta_kubernetes_pod_host_ip";
/// Meta label storing the pod UID.
pub const POD_UID_LABEL: &str = "__meta_kubernetes_pod_uid";
/// Meta label storing the pod controller kind.
pub const POD_CONTROLLER_KIND_LABEL: &str = "__meta_kubernetes_pod_controller_kind";
/// Meta label storing the pod controller name.
pub const POD_CONTROLLER_NAME_LABEL: &str = "__meta_kubernetes_pod_controller_name";
/// Meta label storing the owning Deployment name when `attach_metadata.deployment` is enabled.
pub const POD_DEPLOYMENT_NAME_LABEL: &str = "__meta_kubernetes_pod_deployment_name";
/// Meta label storing the owning Job name when `attach_metadata.job` is enabled.
pub const POD_JOB_NAME_LABEL: &str = "__meta_kubernetes_pod_job_name";
/// Meta label storing the owning CronJob name when `attach_metadata.cronjob` is enabled.
pub const POD_CRONJOB_NAME_LABEL: &str = "__meta_kubernetes_pod_cronjob_name";
/// Meta label storing the pod container name.
pub const POD_CONTAINER_NAME_LABEL: &str = "__meta_kubernetes_pod_container_name";
/// Meta label storing the pod container runtime ID.
pub const POD_CONTAINER_ID_LABEL: &str = "__meta_kubernetes_pod_container_id";
/// Meta label storing the pod container image.
pub const POD_CONTAINER_IMAGE_LABEL: &str = "__meta_kubernetes_pod_container_image";
/// Meta label storing the pod container port name.
pub const POD_CONTAINER_PORT_NAME_LABEL: &str = "__meta_kubernetes_pod_container_port_name";
/// Meta label storing the pod container port number.
pub const POD_CONTAINER_PORT_NUMBER_LABEL: &str = "__meta_kubernetes_pod_container_port_number";
/// Meta label storing the pod container port protocol (`"TCP"`, `"UDP"`, `"SCTP"`).
pub const POD_CONTAINER_PORT_PROTOCOL_LABEL: &str = "__meta_kubernetes_pod_container_port_protocol";
/// Meta label indicating whether the container is an `initContainer` (`"true"` or `"false"`).
pub const POD_CONTAINER_IS_INIT_LABEL: &str = "__meta_kubernetes_pod_container_init";

/// Kubernetes service discovery role matching Prometheus `discovery/kubernetes.Role`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KubernetesRole {
    /// Node discovery role (`"node"`).
    Node,
    /// Pod discovery role (`"pod"`).
    Pod,
    /// Service discovery role (`"service"`).
    Service,
    /// Endpoints discovery role (`"endpoints"`).
    Endpoints,
    /// EndpointSlice discovery role (`"endpointslice"`).
    EndpointSlice,
    /// Ingress discovery role (`"ingress"`).
    Ingress,
}

impl KubernetesRole {
    /// Returns the lowercase Prometheus string representation of this role.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Pod => "pod",
            Self::Service => "service",
            Self::Endpoints => "endpoints",
            Self::EndpointSlice => "endpointslice",
            Self::Ingress => "ingress",
        }
    }

    /// Parses a role name matching Prometheus `Role.UnmarshalYAML`.
    pub fn parse(s: &str) -> Result<Self, DiscoveryError> {
        match s {
            "node" => Ok(Self::Node),
            "pod" => Ok(Self::Pod),
            "service" => Ok(Self::Service),
            "endpoints" => Ok(Self::Endpoints),
            "endpointslice" => Ok(Self::EndpointSlice),
            "ingress" => Ok(Self::Ingress),
            _ => Err(DiscoveryError::InvalidConfig(format!(
                "unknown Kubernetes SD role {s:?}"
            ))),
        }
    }

    fn allowed_selector_roles(self) -> &'static [Self] {
        match self {
            Self::Pod => &[Self::Pod, Self::Node],
            Self::Service => &[Self::Service],
            Self::EndpointSlice => &[Self::Pod, Self::Service, Self::EndpointSlice],
            Self::Endpoints => &[Self::Pod, Self::Service, Self::Endpoints],
            Self::Node => &[Self::Node],
            Self::Ingress => &[Self::Ingress],
        }
    }

    fn allowed_selector_error_msg(self) -> &'static str {
        match self {
            Self::Pod => "pod role supports only pod, node selectors",
            Self::Service => "service role supports only service selectors",
            Self::EndpointSlice => {
                "endpointslice role supports only pod, service, endpointslice selectors"
            }
            Self::Endpoints => "endpoints role supports only pod, service, endpoints selectors",
            Self::Node => "node role supports only node selectors",
            Self::Ingress => "ingress role supports only ingress selectors",
        }
    }
}

impl Serialize for KubernetesRole {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KubernetesRole {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = deserialize_string_or_scalar(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Namespace discovery filtering options matching Prometheus `kubernetes.NamespaceDiscovery`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KubernetesNamespaceDiscovery {
    /// Includes the pod's own in-cluster namespace.
    #[serde(skip_serializing_if = "is_false")]
    pub own_namespace: bool,
    /// Explicit list of namespaces to query. If empty and `own_namespace` is `false`,
    /// queries across all namespaces.
    #[serde(
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub names: Vec<String>,
}

impl KubernetesNamespaceDiscovery {
    /// Returns `true` when both `own_namespace` is `false` and `names` is empty.
    pub fn is_empty(&self) -> bool {
        !self.own_namespace && self.names.is_empty()
    }
}

/// Resource label/field selector matching Prometheus `kubernetes.SelectorConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KubernetesSelectorConfig {
    /// Kubernetes role to which this selector applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<KubernetesRole>,
    /// Label selector string (`labelSelector` query parameter).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub label: String,
    /// Field selector string (`fieldSelector` query parameter).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub field: String,
}

/// Optional metadata attachment flags matching Prometheus `kubernetes.AttachMetadataConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KubernetesAttachMetadataConfig {
    /// Attaches node labels and annotations (`__meta_kubernetes_node_*`) and filters pods
    /// by the node selector if configured.
    #[serde(skip_serializing_if = "is_false")]
    pub node: bool,
    /// Attaches namespace labels and annotations (`__meta_kubernetes_namespace_*`).
    #[serde(skip_serializing_if = "is_false")]
    pub namespace: bool,
    /// Resolves owning `ReplicaSet` -> `Deployment` name (`__meta_kubernetes_pod_deployment_name`).
    #[serde(skip_serializing_if = "is_false")]
    pub deployment: bool,
    /// Attaches owning `Job` name (`__meta_kubernetes_pod_job_name`).
    #[serde(skip_serializing_if = "is_false")]
    pub job: bool,
    /// Resolves owning `Job` -> `CronJob` name (`__meta_kubernetes_pod_cronjob_name`).
    #[serde(skip_serializing_if = "is_false")]
    pub cronjob: bool,
}

impl KubernetesAttachMetadataConfig {
    /// Returns `true` when all attachment flags are `false`.
    pub fn is_empty(&self) -> bool {
        !self.node && !self.namespace && !self.deployment && !self.job && !self.cronjob
    }
}

/// Kubernetes service discovery configuration matching Prometheus `kubernetes.SDConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KubernetesSdConfig {
    /// Kubernetes API server URL. If omitted, in-cluster environment variables are used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_server: Option<String>,
    /// Kubernetes discovery role (`"pod"`, `"service"`, `"endpoints"`, `"endpointslice"`,
    /// `"node"`, or `"ingress"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<KubernetesRole>,
    /// Path to a kubeconfig file (mutually exclusive with `api_server` and custom HTTP config).
    #[serde(
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_string_or_scalar"
    )]
    pub kubeconfig_file: String,
    /// Inlined Prometheus `HTTPClientConfig`.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
    /// Namespace discovery configuration.
    #[serde(skip_serializing_if = "KubernetesNamespaceDiscovery::is_empty")]
    pub namespaces: KubernetesNamespaceDiscovery,
    /// Label and field selectors per Kubernetes resource role.
    #[serde(
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub selectors: Vec<KubernetesSelectorConfig>,
    /// Additional metadata attachment flags.
    #[serde(skip_serializing_if = "KubernetesAttachMetadataConfig::is_empty")]
    pub attach_metadata: KubernetesAttachMetadataConfig,
}

impl KubernetesSdConfig {
    /// Joins relative file paths in `kubeconfig_file` and `http_client_config` with `dir`.
    pub fn set_directory(&mut self, dir: &str) {
        self.http_client_config.set_directory(dir);
        self.kubeconfig_file = join_dir(dir, &self.kubeconfig_file);
    }

    /// Validates this configuration according to Prometheus `kubernetes.SDConfig.UnmarshalYAML`.
    pub fn validate(&mut self) -> Result<(), DiscoveryError> {
        let Some(role) = self.role else {
            return Err(DiscoveryError::InvalidConfig(
                "role missing (one of: pod, service, endpoints, endpointslice, node, ingress)"
                    .to_owned(),
            ));
        };

        if self.api_server.as_deref() == Some("") {
            self.api_server = None;
        }
        if let Some(api_server) = &self.api_server {
            validate_go_url(api_server).map_err(DiscoveryError::InvalidConfig)?;
        }

        let is_default_http = self.http_client_config.is_default();
        self.http_client_config
            .validate()
            .map_err(DiscoveryError::InvalidConfig)?;

        if self.api_server.is_some() && !self.kubeconfig_file.is_empty() {
            return Err(DiscoveryError::InvalidConfig(
                "cannot use 'kubeconfig_file' and 'api_server' simultaneously".to_owned(),
            ));
        }
        if !self.kubeconfig_file.is_empty() && !is_default_http {
            return Err(DiscoveryError::InvalidConfig(
                "cannot use a custom HTTP client configuration together with 'kubeconfig_file'"
                    .to_owned(),
            ));
        }
        if self.api_server.is_none() && !is_default_http {
            return Err(DiscoveryError::InvalidConfig(
                "to use custom HTTP client configuration please provide the 'api_server' URL explicitly".to_owned(),
            ));
        }
        if self.api_server.is_some() && self.namespaces.own_namespace {
            return Err(DiscoveryError::InvalidConfig(
                "cannot use 'api_server' and 'namespaces.own_namespace' simultaneously".to_owned(),
            ));
        }
        if !self.kubeconfig_file.is_empty() && self.namespaces.own_namespace {
            return Err(DiscoveryError::InvalidConfig(
                "cannot use 'kubeconfig_file' and 'namespaces.own_namespace' simultaneously"
                    .to_owned(),
            ));
        }

        let allowed = role.allowed_selector_roles();
        let mut seen_selector_roles = BTreeSet::new();
        for selector in &self.selectors {
            let Some(sel_role) = selector.role else {
                return Err(DiscoveryError::InvalidConfig(
                    role.allowed_selector_error_msg().to_owned(),
                ));
            };
            if !seen_selector_roles.insert(sel_role) {
                return Err(DiscoveryError::InvalidConfig(format!(
                    "duplicated selector role: {}",
                    sel_role.as_str()
                )));
            }
            if !allowed.contains(&sel_role) {
                return Err(DiscoveryError::InvalidConfig(
                    role.allowed_selector_error_msg().to_owned(),
                ));
            }
            if !selector.field.is_empty() {
                validate_k8s_field_selector(&selector.field)?;
            }
            if !selector.label.is_empty() {
                validate_k8s_label_selector(&selector.label)?;
            }
        }

        Ok(())
    }

    fn selector_for(&self, role: KubernetesRole) -> Option<&KubernetesSelectorConfig> {
        self.selectors.iter().find(|s| s.role == Some(role))
    }
}

/// Kubernetes `metav1.OwnerReference` representation.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerReference {
    /// Kind of the owning Kubernetes resource (e.g. `"ReplicaSet"`, `"DaemonSet"`, `"Job"`).
    #[serde(default)]
    pub kind: String,
    /// Name of the owning Kubernetes resource.
    #[serde(default)]
    pub name: String,
    /// Whether this reference points to the managing controller.
    #[serde(default)]
    pub controller: Option<bool>,
}

/// Kubernetes `metav1.ObjectMeta` representation.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Object name within its namespace.
    #[serde(default)]
    pub name: String,
    /// Object namespace.
    #[serde(default)]
    pub namespace: String,
    /// Unique identifier (`metadata.uid`).
    #[serde(default)]
    pub uid: String,
    /// Map of string keys and values (`metadata.labels`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub labels: BTreeMap<String, String>,
    /// Map of unstructured annotations (`metadata.annotations`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub annotations: BTreeMap<String, String>,
    /// List of objects depended by this object (`metadata.ownerReferences`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub owner_references: Vec<OwnerReference>,
}

impl ObjectMeta {
    /// Returns the first [`OwnerReference`] with `controller == Some(true)`, matching
    /// Kubernetes `metav1.GetControllerOf`.
    pub fn controller_of(&self) -> Option<&OwnerReference> {
        self.owner_references
            .iter()
            .find(|r| r.controller == Some(true))
    }
}

/// Kubernetes container port definition (`corev1.ContainerPort`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    /// Optional port name.
    #[serde(default)]
    pub name: String,
    /// Port number exposed on the pod's IP address.
    #[serde(default)]
    pub container_port: u32,
    /// Protocol for port (`"TCP"`, `"UDP"`, or `"SCTP"`).
    #[serde(default)]
    pub protocol: String,
}

/// Kubernetes container definition (`corev1.Container`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Container name.
    #[serde(default)]
    pub name: String,
    /// Container image name.
    #[serde(default)]
    pub image: String,
    /// List of ports to expose from the container.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub ports: Vec<ContainerPort>,
}

/// Kubernetes pod specification (`corev1.PodSpec`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// Scheduled node name (`spec.nodeName`).
    #[serde(default)]
    pub node_name: String,
    /// Application containers belonging to the pod (`spec.containers`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub containers: Vec<Container>,
    /// Initialization containers belonging to the pod (`spec.initContainers`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub init_containers: Vec<Container>,
}

/// Kubernetes pod condition (`corev1.PodCondition`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodCondition {
    /// Type of pod condition (e.g. `"Ready"`).
    #[serde(rename = "type", default)]
    pub condition_type: String,
    /// Status of the condition (`"True"`, `"False"`, `"Unknown"`).
    #[serde(default)]
    pub status: String,
}

/// Kubernetes container runtime status (`corev1.ContainerStatus`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerStatus {
    /// Container name.
    #[serde(default)]
    pub name: String,
    /// Container ID in the format `<type>://<container_id>`.
    #[serde(rename = "containerID", alias = "containerId", default)]
    pub container_id: String,
}

/// Kubernetes pod status (`corev1.PodStatus`).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodStatus {
    /// Current lifecycle phase of the pod (`"Pending"`, `"Running"`, `"Succeeded"`, `"Failed"`, `"Unknown"`).
    #[serde(default)]
    pub phase: String,
    /// IP address allocated to the pod (`status.podIP`).
    #[serde(rename = "podIP", default)]
    pub pod_ip: String,
    /// IP address of the host to which the pod is assigned (`status.hostIP`).
    #[serde(rename = "hostIP", default)]
    pub host_ip: String,
    /// Current service state conditions of the pod (`status.conditions`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub conditions: Vec<PodCondition>,
    /// Statuses of regular containers (`status.containerStatuses`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub container_statuses: Vec<ContainerStatus>,
    /// Statuses of init containers (`status.initContainerStatuses`).
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub init_container_statuses: Vec<ContainerStatus>,
}

/// Kubernetes `corev1.Pod` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pod {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
    /// Specification of the desired behavior of the pod.
    #[serde(default)]
    pub spec: PodSpec,
    /// Most recently observed status of the pod.
    #[serde(default)]
    pub status: PodStatus,
}

/// Kubernetes `corev1.PodList` response payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct PodList {
    /// List of pods.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub items: Vec<Pod>,
}

/// Kubernetes `corev1.Node` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `corev1.NodeList` response payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct NodeList {
    /// List of nodes.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub items: Vec<Node>,
}

/// Kubernetes `corev1.Namespace` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `corev1.NamespaceList` response payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct NamespaceList {
    /// List of namespaces.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub items: Vec<Namespace>,
}

/// Kubernetes `appsv1.ReplicaSet` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaSet {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `appsv1.ReplicaSetList` response payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct ReplicaSetList {
    /// List of ReplicaSets.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub items: Vec<ReplicaSet>,
}

/// Kubernetes `batchv1.Job` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `batchv1.JobList` response payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct JobList {
    /// List of Jobs.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub items: Vec<Job>,
}

/// Auxiliary cluster metadata indexed for `attach_metadata` enrichment during pod discovery.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KubernetesMetadataContext {
    /// Nodes indexed by `metadata.name`.
    pub nodes: BTreeMap<String, Node>,
    /// Namespaces indexed by `metadata.name`.
    pub namespaces: BTreeMap<String, Namespace>,
    /// ReplicaSets indexed by `"{namespace}/{name}"`.
    pub replicasets: BTreeMap<String, ReplicaSet>,
    /// Jobs indexed by `"{namespace}/{name}"`.
    pub jobs: BTreeMap<String, Job>,
}

impl KubernetesMetadataContext {
    /// Indexes slices of nodes, namespaces, ReplicaSets, and Jobs into a lookup context.
    pub fn from_items(
        nodes: impl IntoIterator<Item = Node>,
        namespaces: impl IntoIterator<Item = Namespace>,
        replicasets: impl IntoIterator<Item = ReplicaSet>,
        jobs: impl IntoIterator<Item = Job>,
    ) -> Self {
        let nodes = nodes
            .into_iter()
            .map(|n| (n.metadata.name.clone(), n))
            .collect();
        let namespaces = namespaces
            .into_iter()
            .map(|ns| (ns.metadata.name.clone(), ns))
            .collect();
        let replicasets = replicasets
            .into_iter()
            .map(|rs| {
                (
                    namespaced_name(&rs.metadata.namespace, &rs.metadata.name),
                    rs,
                )
            })
            .collect();
        let jobs = jobs
            .into_iter()
            .map(|j| (namespaced_name(&j.metadata.namespace, &j.metadata.name), j))
            .collect();
        Self {
            nodes,
            namespaces,
            replicasets,
            jobs,
        }
    }
}

/// Builds a Prometheus [`TargetGroup`] for a single Kubernetes [`Pod`], matching
/// `discovery/kubernetes.Pod.buildPod` in Prometheus.
pub fn build_pod_target_group(
    pod: &Pod,
    metadata: &KubernetesMetadataContext,
    attach: &KubernetesAttachMetadataConfig,
) -> TargetGroup {
    let source = pod_source(&pod.metadata.namespace, &pod.metadata.name);
    let mut tg = TargetGroup {
        targets: Vec::new(),
        labels: LabelSet::new(),
        source,
    };

    // PodIP can be empty when a pod is starting or has been evicted.
    if pod.status.pod_ip.is_empty() {
        return tg;
    }

    // Filter out pods scheduled on nodes that are not in the node store, as
    // these were filtered out by node selectors.
    if attach.node && !metadata.nodes.contains_key(&pod.spec.node_name) {
        return tg;
    }

    let mut labels = pod_labels(pod, metadata, attach);
    labels.insert(NAMESPACE_LABEL.to_owned(), pod.metadata.namespace.clone());
    if attach.node {
        add_node_labels(&mut labels, metadata, &pod.spec.node_name);
    }
    if attach.namespace {
        add_namespace_labels(&mut labels, metadata, &pod.metadata.namespace);
    }
    tg.labels = labels;

    let regular_len = pod.spec.containers.len();
    for (idx, container) in pod
        .spec
        .containers
        .iter()
        .chain(pod.spec.init_containers.iter())
        .enumerate()
    {
        let is_init = idx >= regular_len;
        let is_init_str = if is_init { "true" } else { "false" };
        let statuses = if is_init {
            &pod.status.init_container_statuses
        } else {
            &pod.status.container_statuses
        };
        let container_id = find_pod_container_id(statuses, &container.name);

        if container.ports.is_empty() {
            let mut target = LabelSet::new();
            target.insert(ADDRESS_LABEL.to_owned(), pod.status.pod_ip.clone());
            target.insert(POD_CONTAINER_NAME_LABEL.to_owned(), container.name.clone());
            target.insert(POD_CONTAINER_ID_LABEL.to_owned(), container_id.to_owned());
            target.insert(
                POD_CONTAINER_IMAGE_LABEL.to_owned(),
                container.image.clone(),
            );
            target.insert(
                POD_CONTAINER_IS_INIT_LABEL.to_owned(),
                is_init_str.to_owned(),
            );
            tg.targets.push(target);
            continue;
        }

        for port in &container.ports {
            let port_str = port.container_port.to_string();
            let addr = join_host_port(&pod.status.pod_ip, &port_str);

            let mut target = LabelSet::new();
            target.insert(ADDRESS_LABEL.to_owned(), addr);
            target.insert(POD_CONTAINER_NAME_LABEL.to_owned(), container.name.clone());
            target.insert(POD_CONTAINER_ID_LABEL.to_owned(), container_id.to_owned());
            target.insert(
                POD_CONTAINER_IMAGE_LABEL.to_owned(),
                container.image.clone(),
            );
            target.insert(POD_CONTAINER_PORT_NUMBER_LABEL.to_owned(), port_str);
            target.insert(POD_CONTAINER_PORT_NAME_LABEL.to_owned(), port.name.clone());
            target.insert(
                POD_CONTAINER_PORT_PROTOCOL_LABEL.to_owned(),
                port.protocol.clone(),
            );
            target.insert(
                POD_CONTAINER_IS_INIT_LABEL.to_owned(),
                is_init_str.to_owned(),
            );
            tg.targets.push(target);
        }
    }

    tg
}

/// Builds Prometheus [`TargetGroup`]s for a slice of Kubernetes [`Pod`]s.
pub fn build_pod_target_groups(
    pods: &[Pod],
    metadata: &KubernetesMetadataContext,
    attach: &KubernetesAttachMetadataConfig,
) -> Vec<TargetGroup> {
    pods.iter()
        .map(|pod| build_pod_target_group(pod, metadata, attach))
        .collect()
}

fn pod_labels(
    pod: &Pod,
    metadata: &KubernetesMetadataContext,
    attach: &KubernetesAttachMetadataConfig,
) -> LabelSet {
    let mut ls = LabelSet::new();
    ls.insert(POD_IP_LABEL.to_owned(), pod.status.pod_ip.clone());
    ls.insert(POD_READY_LABEL.to_owned(), pod_ready(pod));
    ls.insert(POD_PHASE_LABEL.to_owned(), pod.status.phase.clone());
    ls.insert(POD_NODE_NAME_LABEL.to_owned(), pod.spec.node_name.clone());
    ls.insert(POD_HOST_IP_LABEL.to_owned(), pod.status.host_ip.clone());
    ls.insert(POD_UID_LABEL.to_owned(), pod.metadata.uid.clone());

    add_object_meta_labels(&mut ls, &pod.metadata, "pod");

    if let Some(created_by) = pod.metadata.controller_of() {
        if !created_by.kind.is_empty() {
            ls.insert(
                POD_CONTROLLER_KIND_LABEL.to_owned(),
                created_by.kind.clone(),
            );
        }
        if !created_by.name.is_empty() {
            ls.insert(
                POD_CONTROLLER_NAME_LABEL.to_owned(),
                created_by.name.clone(),
            );
        }
        match created_by.kind.as_str() {
            "ReplicaSet" => {
                if attach.deployment {
                    let key = namespaced_name(&pod.metadata.namespace, &created_by.name);
                    if let Some(rs) = metadata.replicasets.get(&key)
                        && let Some(rs_owner) = rs.metadata.controller_of()
                        && rs_owner.kind == "Deployment"
                    {
                        ls.insert(POD_DEPLOYMENT_NAME_LABEL.to_owned(), rs_owner.name.clone());
                    }
                }
            }
            "Job" => {
                if attach.job {
                    ls.insert(POD_JOB_NAME_LABEL.to_owned(), created_by.name.clone());
                }
                if attach.cronjob {
                    let key = namespaced_name(&pod.metadata.namespace, &created_by.name);
                    if let Some(job) = metadata.jobs.get(&key)
                        && let Some(job_owner) = job.metadata.controller_of()
                        && job_owner.kind == "CronJob"
                    {
                        ls.insert(POD_CRONJOB_NAME_LABEL.to_owned(), job_owner.name.clone());
                    }
                }
            }
            _ => {}
        }
    }

    ls
}

fn add_node_labels(ls: &mut LabelSet, metadata: &KubernetesMetadataContext, node_name: &str) {
    if node_name.is_empty() {
        return;
    }
    ls.insert(NODE_NAME_LABEL.to_owned(), node_name.to_owned());
    if let Some(node) = metadata.nodes.get(node_name) {
        add_object_meta_labels(ls, &node.metadata, "node");
    }
}

fn add_namespace_labels(ls: &mut LabelSet, metadata: &KubernetesMetadataContext, namespace: &str) {
    if let Some(ns) = metadata.namespaces.get(namespace) {
        add_object_meta_labels(ls, &ns.metadata, "namespace");
    }
}

fn add_object_meta_labels(ls: &mut LabelSet, meta: &ObjectMeta, role: &str) {
    // Namespace name is already populated from `pod.metadata.namespace` (matching Prometheus
    // `addNamespaceMetaLabels`), and empty auxiliary `meta.name` must not clobber `node_name`.
    if role != "namespace" && !meta.name.is_empty() {
        ls.insert(format!("{META_LABEL_PREFIX}{role}_name"), meta.name.clone());
    }

    for (k, v) in &meta.labels {
        let ln = sanitize_label_name(k);
        ls.insert(format!("{META_LABEL_PREFIX}{role}_label_{ln}"), v.clone());
        ls.insert(
            format!("{META_LABEL_PREFIX}{role}_labelpresent_{ln}"),
            "true".to_owned(),
        );
    }

    for (k, v) in &meta.annotations {
        let ln = sanitize_label_name(k);
        ls.insert(
            format!("{META_LABEL_PREFIX}{role}_annotation_{ln}"),
            v.clone(),
        );
        ls.insert(
            format!("{META_LABEL_PREFIX}{role}_annotationpresent_{ln}"),
            "true".to_owned(),
        );
    }
}

fn find_pod_container_id<'a>(statuses: &'a [ContainerStatus], container_name: &str) -> &'a str {
    statuses
        .iter()
        .find(|s| s.name == container_name)
        .map_or("", |s| s.container_id.as_str())
}

fn pod_ready(pod: &Pod) -> String {
    for cond in &pod.status.conditions {
        if cond.condition_type == "Ready" {
            return cond.status.to_ascii_lowercase();
        }
    }
    "unknown".to_owned()
}

fn namespaced_name(namespace: &str, name: &str) -> String {
    format!("{namespace}/{name}")
}

fn pod_source(namespace: &str, name: &str) -> String {
    format!("pod/{}", namespaced_name(namespace, name))
}

/// `reqwest`-based Kubernetes Pod service discovery runner (`role: pod`).
#[derive(Clone, Debug)]
pub struct KubernetesPodDiscovery {
    config: KubernetesSdConfig,
    client: Option<reqwest::Client>,
    own_namespace_file: String,
    in_cluster_token_file: String,
    in_cluster_ca_file: String,
}

impl KubernetesPodDiscovery {
    /// Creates a new [`KubernetesPodDiscovery`] after validating `config` (`role` must be `Pod`)
    /// and building a [`reqwest::Client`] when `api_server` is configured.
    ///
    /// In-cluster mode (`api_server: None`) builds its TLS client using the service account CA
    /// bundle and token when [`KubernetesPodDiscovery::discover`] runs.
    pub fn new(mut config: KubernetesSdConfig) -> Result<Self, DiscoveryError> {
        validate_pod_runner_config(&mut config)?;
        let client = if config.api_server.is_some() {
            Some(config.http_client_config.build_client()?)
        } else {
            None
        };
        Ok(Self {
            config,
            client,
            own_namespace_file: IN_CLUSTER_NAMESPACE_FILE.to_owned(),
            in_cluster_token_file: IN_CLUSTER_TOKEN_FILE.to_owned(),
            in_cluster_ca_file: IN_CLUSTER_CA_FILE.to_owned(),
        })
    }

    /// Creates a new [`KubernetesPodDiscovery`] using a caller-supplied [`reqwest::Client`].
    pub fn with_client(
        mut config: KubernetesSdConfig,
        client: reqwest::Client,
    ) -> Result<Self, DiscoveryError> {
        validate_pod_runner_config(&mut config)?;
        Ok(Self {
            config,
            client: Some(client),
            own_namespace_file: IN_CLUSTER_NAMESPACE_FILE.to_owned(),
            in_cluster_token_file: IN_CLUSTER_TOKEN_FILE.to_owned(),
            in_cluster_ca_file: IN_CLUSTER_CA_FILE.to_owned(),
        })
    }

    /// Overrides the path used to read the in-cluster service account namespace when
    /// `namespaces.own_namespace` is `true` (defaults to
    /// `"/var/run/secrets/kubernetes.io/serviceaccount/namespace"`).
    pub fn with_own_namespace_file(mut self, path: impl Into<String>) -> Self {
        self.own_namespace_file = path.into();
        self
    }

    /// Returns the validated [`KubernetesSdConfig`].
    pub fn config(&self) -> &KubernetesSdConfig {
        &self.config
    }

    /// Queries the Kubernetes API server over HTTP(S) using `reqwest` and returns the discovered
    /// pod [`TargetGroup`]s.
    pub async fn discover(&self) -> Result<Vec<TargetGroup>, DiscoveryError> {
        let (base_url, client, effective_http) = self.resolve_endpoint_and_auth()?;
        let namespaces = self.resolve_namespaces()?;

        let pod_selector = self.config.selector_for(KubernetesRole::Pod);
        let node_selector = self.config.selector_for(KubernetesRole::Node);

        let mut all_pods = Vec::new();
        if namespaces.is_empty() {
            let url = build_resource_url(&base_url, &["api", "v1", "pods"], pod_selector)?;
            let list: PodList = self.get_json(&client, url, &effective_http).await?;
            all_pods.extend(list.items);
        } else {
            for ns in &namespaces {
                let url = build_resource_url(
                    &base_url,
                    &["api", "v1", "namespaces", ns, "pods"],
                    pod_selector,
                )?;
                let list: PodList = self.get_json(&client, url, &effective_http).await?;
                all_pods.extend(list.items);
            }
        }

        let mut metadata = KubernetesMetadataContext::default();
        let attach = &self.config.attach_metadata;

        if attach.node {
            let url = build_resource_url(&base_url, &["api", "v1", "nodes"], node_selector)?;
            let list: NodeList = self.get_json(&client, url, &effective_http).await?;
            for node in list.items {
                metadata.nodes.insert(node.metadata.name.clone(), node);
            }
        }

        if attach.namespace {
            if namespaces.is_empty() {
                let url = build_resource_url(&base_url, &["api", "v1", "namespaces"], None)?;
                let list: NamespaceList = self.get_json(&client, url, &effective_http).await?;
                for ns in list.items {
                    metadata.namespaces.insert(ns.metadata.name.clone(), ns);
                }
            } else {
                for ns_name in &namespaces {
                    let url =
                        build_resource_url(&base_url, &["api", "v1", "namespaces", ns_name], None)?;
                    if let Some(ns) = self
                        .get_optional_json::<Namespace>(&client, url, &effective_http)
                        .await?
                    {
                        metadata.namespaces.insert(ns.metadata.name.clone(), ns);
                    }
                }
            }
        }

        if attach.deployment {
            if namespaces.is_empty() {
                let url =
                    build_resource_url(&base_url, &["apis", "apps", "v1", "replicasets"], None)?;
                let list: ReplicaSetList = self.get_json(&client, url, &effective_http).await?;
                for rs in list.items {
                    metadata.replicasets.insert(
                        namespaced_name(&rs.metadata.namespace, &rs.metadata.name),
                        rs,
                    );
                }
            } else {
                for ns in &namespaces {
                    let url = build_resource_url(
                        &base_url,
                        &["apis", "apps", "v1", "namespaces", ns, "replicasets"],
                        None,
                    )?;
                    let list: ReplicaSetList = self.get_json(&client, url, &effective_http).await?;
                    for rs in list.items {
                        metadata.replicasets.insert(
                            namespaced_name(&rs.metadata.namespace, &rs.metadata.name),
                            rs,
                        );
                    }
                }
            }
        }

        if attach.cronjob {
            if namespaces.is_empty() {
                let url = build_resource_url(&base_url, &["apis", "batch", "v1", "jobs"], None)?;
                let list: JobList = self.get_json(&client, url, &effective_http).await?;
                for job in list.items {
                    metadata.jobs.insert(
                        namespaced_name(&job.metadata.namespace, &job.metadata.name),
                        job,
                    );
                }
            } else {
                for ns in &namespaces {
                    let url = build_resource_url(
                        &base_url,
                        &["apis", "batch", "v1", "namespaces", ns, "jobs"],
                        None,
                    )?;
                    let list: JobList = self.get_json(&client, url, &effective_http).await?;
                    for job in list.items {
                        metadata.jobs.insert(
                            namespaced_name(&job.metadata.namespace, &job.metadata.name),
                            job,
                        );
                    }
                }
            }
        }

        Ok(build_pod_target_groups(&all_pods, &metadata, attach))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        client: &reqwest::Client,
        url: reqwest::Url,
        http_cfg: &HttpClientConfig,
    ) -> Result<T, DiscoveryError> {
        let req = client
            .get(url)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT);
        let req = http_cfg.apply_to_request(req)?;
        let resp = req.send().await?.error_for_status()?;
        let body = resp.bytes().await?;
        Ok(serde_json::from_slice(&body)?)
    }

    async fn get_optional_json<T: for<'de> Deserialize<'de>>(
        &self,
        client: &reqwest::Client,
        url: reqwest::Url,
        http_cfg: &HttpClientConfig,
    ) -> Result<Option<T>, DiscoveryError> {
        let req = client
            .get(url)
            .header("Accept", "application/json")
            .header("User-Agent", USER_AGENT);
        let req = http_cfg.apply_to_request(req)?;
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        let body = resp.bytes().await?;
        Ok(Some(serde_json::from_slice(&body)?))
    }

    fn resolve_endpoint_and_auth(
        &self,
    ) -> Result<(String, reqwest::Client, HttpClientConfig), DiscoveryError> {
        if let Some(api_server) = &self.config.api_server {
            let client = match &self.client {
                Some(c) => c.clone(),
                None => self.config.http_client_config.build_client()?,
            };
            return Ok((
                api_server.clone(),
                client,
                self.config.http_client_config.clone(),
            ));
        }

        let host = env::var("KUBERNETES_SERVICE_HOST").unwrap_or_default();
        let port = env::var("KUBERNETES_SERVICE_PORT").unwrap_or_default();
        self.resolve_in_cluster_endpoint_and_auth(&host, &port)
    }

    fn resolve_in_cluster_endpoint_and_auth(
        &self,
        host: &str,
        port: &str,
    ) -> Result<(String, reqwest::Client, HttpClientConfig), DiscoveryError> {
        // In-cluster configuration matching client-go rest.InClusterConfig().
        if host.is_empty() || port.is_empty() {
            return Err(DiscoveryError::InvalidConfig(
                "unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined".to_owned(),
            ));
        }
        let base_url = format!("https://{}", join_host_port(host, port));
        let mut http_cfg = self.config.http_client_config.clone();
        if http_cfg.basic_auth.is_none()
            && http_cfg.authorization.is_none()
            && http_cfg.bearer_token.is_empty()
            && http_cfg.bearer_token_file.is_empty()
        {
            let token = fs::read_to_string(&self.in_cluster_token_file).map_err(|e| {
                DiscoveryError::InvalidConfig(format!(
                    "unable to read in-cluster token file {}: {e}",
                    self.in_cluster_token_file
                ))
            })?;
            if token.trim().is_empty() {
                return Err(DiscoveryError::InvalidConfig(format!(
                    "in-cluster token file {} is empty",
                    self.in_cluster_token_file
                )));
            }
            http_cfg
                .bearer_token_file
                .clone_from(&self.in_cluster_token_file);
        }
        let client = match &self.client {
            Some(c) => c.clone(),
            None => {
                if http_cfg.tls_config.ca.is_empty()
                    && http_cfg.tls_config.ca_file.is_empty()
                    && !http_cfg.tls_config.insecure_skip_verify
                {
                    if !Path::new(&self.in_cluster_ca_file).exists() {
                        return Err(DiscoveryError::InvalidConfig(format!(
                            "unable to read in-cluster CA certificate file {}",
                            self.in_cluster_ca_file
                        )));
                    }
                    http_cfg
                        .tls_config
                        .ca_file
                        .clone_from(&self.in_cluster_ca_file);
                }
                http_cfg.build_client()?
            }
        };
        Ok((base_url, client, http_cfg))
    }

    fn resolve_namespaces(&self) -> Result<Vec<String>, DiscoveryError> {
        let mut names = Vec::with_capacity(self.config.namespaces.names.len() + 1);
        for ns in &self.config.namespaces.names {
            validate_namespace_path_segment(ns)?;
            if !names.contains(ns) {
                names.push(ns.clone());
            }
        }
        if self.config.namespaces.own_namespace {
            let own_ns = fs::read_to_string(&self.own_namespace_file)
                .map_err(|e| {
                    DiscoveryError::InvalidConfig(format!(
                        "unable to read in-cluster namespace file {}: {e}",
                        self.own_namespace_file
                    ))
                })?
                .trim()
                .to_owned();
            if own_ns.is_empty() {
                return Err(DiscoveryError::InvalidConfig(
                    "could not read own namespace name (empty file)".to_owned(),
                ));
            }
            validate_namespace_path_segment(&own_ns)?;
            if !names.contains(&own_ns) {
                names.push(own_ns);
            }
        }
        Ok(names)
    }
}

// Reject dot-segments and path delimiters at discovery time (matching `client-go`
// `IsValidPathSegmentName`) because `url::PathSegmentsMut::push("..")` pops the preceding
// segment instead of percent-encoding it, which would turn a namespaced query into a
// cluster-wide `/api/v1/pods` request.
fn validate_namespace_path_segment(ns: &str) -> Result<(), DiscoveryError> {
    if ns.is_empty() || ns == "." || ns == ".." || ns.contains(['/', '%']) {
        return Err(DiscoveryError::InvalidConfig(format!(
            "invalid Kubernetes namespace name {ns:?}"
        )));
    }
    Ok(())
}

fn validate_k8s_field_selector(selector: &str) -> Result<(), DiscoveryError> {
    for term in selector.split(',') {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        if !term.contains('=') {
            return Err(DiscoveryError::InvalidConfig(format!(
                "invalid selector: '{selector}'; can't understand '{term}'"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabelToken<'a> {
    End,
    ClosedPar,
    Comma,
    DoesNotExist,
    DoubleEquals,
    Equals,
    GreaterThan,
    Identifier(&'a str),
    In,
    LessThan,
    NotEquals,
    NotIn,
    OpenPar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LabelParserCtx {
    KeyAndOperator,
    Values,
}

struct LabelSelectorParser<'a> {
    tokens: Vec<(LabelToken<'a>, &'a str)>,
    pos: usize,
}

impl<'a> LabelSelectorParser<'a> {
    fn new(input: &'a str) -> Self {
        let mut tokens = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }
            let (tok, lit, len) = match bytes[i] {
                b'=' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => {
                    (LabelToken::DoubleEquals, "==", 2)
                }
                b'!' if i + 1 < bytes.len() && bytes[i + 1] == b'=' => {
                    (LabelToken::NotEquals, "!=", 2)
                }
                b'=' => (LabelToken::Equals, "=", 1),
                b'!' => (LabelToken::DoesNotExist, "!", 1),
                b'(' => (LabelToken::OpenPar, "(", 1),
                b')' => (LabelToken::ClosedPar, ")", 1),
                b',' => (LabelToken::Comma, ",", 1),
                b'>' => (LabelToken::GreaterThan, ">", 1),
                b'<' => (LabelToken::LessThan, "<", 1),
                _ => {
                    let start = i;
                    while i < bytes.len()
                        && !matches!(
                            bytes[i],
                            b' ' | b'\t'
                                | b'\r'
                                | b'\n'
                                | b'='
                                | b'!'
                                | b'('
                                | b')'
                                | b','
                                | b'>'
                                | b'<'
                        )
                    {
                        i += 1;
                    }
                    let lit = &input[start..i];
                    let tok = match lit {
                        "in" => LabelToken::In,
                        "notin" => LabelToken::NotIn,
                        _ => LabelToken::Identifier(lit),
                    };
                    tokens.push((tok, lit));
                    continue;
                }
            };
            tokens.push((tok, lit));
            i += len;
        }
        tokens.push((LabelToken::End, ""));
        Self { tokens, pos: 0 }
    }

    fn peek(&self, ctx: LabelParserCtx) -> (LabelToken<'a>, &'a str) {
        let (tok, lit) = self.tokens[self.pos];
        if ctx == LabelParserCtx::Values && matches!(tok, LabelToken::In | LabelToken::NotIn) {
            (LabelToken::Identifier(lit), lit)
        } else {
            (tok, lit)
        }
    }

    fn consume(&mut self, ctx: LabelParserCtx) -> (LabelToken<'a>, &'a str) {
        let res = self.peek(ctx);
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        res
    }

    fn parse(&mut self) -> Result<(), DiscoveryError> {
        loop {
            let (tok, lit) = self.peek(LabelParserCtx::Values);
            match tok {
                LabelToken::Identifier(_) | LabelToken::DoesNotExist => {
                    self.parse_requirement()?;
                    let (t, l) = self.consume(LabelParserCtx::Values);
                    match t {
                        LabelToken::End => return Ok(()),
                        LabelToken::Comma => {
                            let (t2, l2) = self.peek(LabelParserCtx::Values);
                            if !matches!(t2, LabelToken::Identifier(_) | LabelToken::DoesNotExist) {
                                return Err(DiscoveryError::InvalidConfig(format!(
                                    "found '{l2}', expected: identifier after ','"
                                )));
                            }
                        }
                        _ => {
                            return Err(DiscoveryError::InvalidConfig(format!(
                                "found '{l}', expected: ',' or 'end of string'"
                            )));
                        }
                    }
                }
                LabelToken::End => return Ok(()),
                _ => {
                    return Err(DiscoveryError::InvalidConfig(format!(
                        "found '{lit}', expected: !, identifier, or 'end of string'"
                    )));
                }
            }
        }
    }

    fn parse_requirement(&mut self) -> Result<(), DiscoveryError> {
        let (mut tok, mut lit) = self.consume(LabelParserCtx::Values);
        let is_not = tok == LabelToken::DoesNotExist;
        if is_not {
            (tok, lit) = self.consume(LabelParserCtx::Values);
        }
        let LabelToken::Identifier(key) = tok else {
            return Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: found '{lit}', expected: identifier"
            )));
        };
        if !is_valid_k8s_label_key(key) {
            return Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: invalid label key {key:?}"
            )));
        }
        if is_not
            || matches!(
                self.peek(LabelParserCtx::Values).0,
                LabelToken::End | LabelToken::Comma
            )
        {
            return Ok(());
        }

        let (op_tok, op_lit) = self.consume(LabelParserCtx::KeyAndOperator);
        match op_tok {
            LabelToken::In | LabelToken::NotIn => self.parse_set_values(),
            LabelToken::Equals | LabelToken::DoubleEquals | LabelToken::NotEquals => {
                let val = self.parse_exact_value()?;
                validate_k8s_label_value(val)
            }
            LabelToken::GreaterThan | LabelToken::LessThan => {
                let val = self.parse_exact_value()?;
                if val.parse::<i64>().is_err() {
                    return Err(DiscoveryError::InvalidConfig(format!(
                        "unable to parse requirement: for '{op_lit}' operator, value {val:?} must be an integer"
                    )));
                }
                validate_k8s_label_value(val)
            }
            _ => Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: found '{op_lit}', expected: in, notin, =, ==, !=, >, <"
            ))),
        }
    }

    fn parse_set_values(&mut self) -> Result<(), DiscoveryError> {
        let (tok, lit) = self.consume(LabelParserCtx::Values);
        if tok != LabelToken::OpenPar {
            return Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: found '{lit}', expected: '('"
            )));
        }
        let (tok, lit) = self.peek(LabelParserCtx::Values);
        match tok {
            LabelToken::ClosedPar => {
                self.consume(LabelParserCtx::Values);
                Ok(())
            }
            LabelToken::Identifier(_) | LabelToken::Comma => {
                loop {
                    let (t, l) = self.consume(LabelParserCtx::Values);
                    match t {
                        LabelToken::Identifier(val) => {
                            validate_k8s_label_value(val)?;
                            let (t2, l2) = self.peek(LabelParserCtx::Values);
                            match t2 {
                                LabelToken::Comma => continue,
                                LabelToken::ClosedPar => break,
                                _ => {
                                    return Err(DiscoveryError::InvalidConfig(format!(
                                        "unable to parse requirement: found '{l2}', expected: ',' or ')'"
                                    )));
                                }
                            }
                        }
                        LabelToken::Comma => {
                            if self.peek(LabelParserCtx::Values).0 == LabelToken::ClosedPar {
                                break;
                            }
                        }
                        _ => {
                            return Err(DiscoveryError::InvalidConfig(format!(
                                "unable to parse requirement: found '{l}', expected: ',', or identifier"
                            )));
                        }
                    }
                }
                let (close_tok, close_lit) = self.consume(LabelParserCtx::Values);
                if close_tok != LabelToken::ClosedPar {
                    return Err(DiscoveryError::InvalidConfig(format!(
                        "unable to parse requirement: found '{close_lit}', expected: ')'"
                    )));
                }
                Ok(())
            }
            _ => Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: found '{lit}', expected: ',', ')' or identifier"
            ))),
        }
    }

    fn parse_exact_value(&mut self) -> Result<&'a str, DiscoveryError> {
        if matches!(
            self.peek(LabelParserCtx::Values).0,
            LabelToken::End | LabelToken::Comma
        ) {
            return Ok("");
        }
        let (tok, lit) = self.consume(LabelParserCtx::Values);
        if let LabelToken::Identifier(val) = tok {
            Ok(val)
        } else {
            Err(DiscoveryError::InvalidConfig(format!(
                "unable to parse requirement: found '{lit}', expected: identifier"
            )))
        }
    }
}

/// Validates a Kubernetes label selector matching `k8s.io/apimachinery/pkg/labels.Parse`.
fn validate_k8s_label_selector(selector: &str) -> Result<(), DiscoveryError> {
    LabelSelectorParser::new(selector).parse()
}

fn is_ascii_lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn is_valid_dns_subdomain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            let b = label.as_bytes();
            !b.is_empty()
                && is_ascii_lower_alnum(b[0])
                && is_ascii_lower_alnum(b[b.len() - 1])
                && b.iter().all(|&c| is_ascii_lower_alnum(c) || c == b'-')
        })
}

fn is_valid_k8s_label_name_part(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

fn is_valid_k8s_label_key(key: &str) -> bool {
    match key.split_once('/') {
        Some((prefix, name)) => {
            !name.contains('/')
                && is_valid_dns_subdomain(prefix)
                && is_valid_k8s_label_name_part(name)
        }
        None => is_valid_k8s_label_name_part(key),
    }
}

fn validate_k8s_label_value(val: &str) -> Result<(), DiscoveryError> {
    if val.is_empty() || is_valid_k8s_label_name_part(val) {
        Ok(())
    } else {
        Err(DiscoveryError::InvalidConfig(format!(
            "unable to parse requirement: invalid label value {val:?}"
        )))
    }
}

/// Formats `host` and `port` as `host:port`, bracketing IPv6 literals to match Go `net.JoinHostPort`.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Sanitizes an arbitrary string into a valid Prometheus ASCII label name suffix by replacing
/// any character outside `[a-zA-Z0-9_]` with `'_'`, matching Prometheus `strutil.SanitizeLabelName`.
fn sanitize_label_name(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn validate_pod_runner_config(config: &mut KubernetesSdConfig) -> Result<(), DiscoveryError> {
    config.validate()?;
    if config.role != Some(KubernetesRole::Pod) {
        return Err(DiscoveryError::InvalidConfig(format!(
            "KubernetesPodDiscovery requires role \"pod\", got {:?}",
            config.role.map(KubernetesRole::as_str)
        )));
    }
    if !config.kubeconfig_file.is_empty() {
        return Err(DiscoveryError::InvalidConfig(
            "kubeconfig_file is not supported by KubernetesPodDiscovery; configure api_server and HTTP credentials instead".to_owned(),
        ));
    }
    if let Some(api_server) = &config.api_server {
        let parsed = reqwest::Url::parse(api_server).map_err(|e| {
            DiscoveryError::InvalidConfig(format!("invalid api_server URL {api_server:?}: {e}"))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DiscoveryError::InvalidConfig(format!(
                "invalid api_server URL scheme {:?}, expected \"http\" or \"https\"",
                parsed.scheme()
            )));
        }
        if parsed.cannot_be_a_base() {
            return Err(DiscoveryError::InvalidConfig(format!(
                "Kubernetes base URL {api_server:?} cannot be a base"
            )));
        }
    }
    Ok(())
}

fn build_resource_url(
    base_url: &str,
    segments: &[&str],
    selector: Option<&KubernetesSelectorConfig>,
) -> Result<reqwest::Url, DiscoveryError> {
    let mut url = reqwest::Url::parse(base_url).map_err(|e| {
        DiscoveryError::InvalidConfig(format!("invalid Kubernetes base URL {base_url:?}: {e}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(DiscoveryError::InvalidConfig(format!(
            "invalid Kubernetes base URL scheme {:?}, expected \"http\" or \"https\"",
            url.scheme()
        )));
    }
    // Strip any query or fragment carried by `api_server` before appending selector query pairs
    // because `query_pairs_mut().append_pair` appends rather than overwriting, matching `client-go`
    // `Request.URL()`.
    url.set_query(None);
    url.set_fragment(None);
    {
        let mut path_segs = url.path_segments_mut().map_err(|()| {
            DiscoveryError::InvalidConfig(format!(
                "Kubernetes base URL {base_url:?} cannot be a base"
            ))
        })?;
        path_segs.pop_if_empty();
        path_segs.extend(segments);
    }
    if let Some(sel) = selector {
        let mut pairs = url.query_pairs_mut();
        if !sel.label.is_empty() {
            pairs.append_pair("labelSelector", &sel.label);
        }
        if !sel.field.is_empty() {
            pairs.append_pair("fieldSelector", &sel.field);
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_resource_url_strips_base_query_and_fragment() {
        let sel = KubernetesSelectorConfig {
            role: Some(KubernetesRole::Pod),
            label: "app=web".to_owned(),
            field: String::new(),
        };
        let with_sel = build_resource_url(
            "https://k8s.local/prefix/?watch=true#frag",
            &["api", "v1", "pods"],
            Some(&sel),
        )
        .unwrap();
        assert_eq!(
            with_sel.as_str(),
            "https://k8s.local/prefix/api/v1/pods?labelSelector=app%3Dweb"
        );

        let without_sel = build_resource_url(
            "https://k8s.local/?watch=true#frag",
            &["api", "v1", "pods"],
            None,
        )
        .unwrap();
        assert_eq!(without_sel.as_str(), "https://k8s.local/api/v1/pods");
    }

    #[test]
    fn resolve_namespaces_allows_non_dns_names_and_rejects_path_traversal() {
        let cfg = KubernetesSdConfig {
            role: Some(KubernetesRole::Pod),
            namespaces: KubernetesNamespaceDiscovery {
                own_namespace: false,
                names: vec!["UPPERCASE".to_owned(), "default?watch=true".to_owned()],
            },
            ..KubernetesSdConfig::default()
        };
        let disc = KubernetesPodDiscovery::new(cfg).unwrap();
        let resolved = disc.resolve_namespaces().unwrap();
        assert_eq!(resolved, vec!["UPPERCASE", "default?watch=true"]);

        let url = build_resource_url(
            "https://k8s.local",
            &["api", "v1", "namespaces", "default?watch=true", "pods"],
            None,
        )
        .unwrap();
        assert_eq!(url.query(), None);
        assert_eq!(url.path(), "/api/v1/namespaces/default%3Fwatch=true/pods");

        for bad in ["", ".", "..", "a/b", "a%2Fb"] {
            let bad_cfg = KubernetesSdConfig {
                role: Some(KubernetesRole::Pod),
                namespaces: KubernetesNamespaceDiscovery {
                    own_namespace: false,
                    names: vec![bad.to_owned()],
                },
                ..KubernetesSdConfig::default()
            };
            let bad_disc = KubernetesPodDiscovery::new(bad_cfg).unwrap();
            assert!(
                bad_disc.resolve_namespaces().is_err(),
                "expected path-segment error for namespace {bad:?}"
            );
        }
    }

    #[test]
    fn resolve_namespaces_rejects_empty_own_namespace_file() {
        let cfg = KubernetesSdConfig {
            role: Some(KubernetesRole::Pod),
            namespaces: KubernetesNamespaceDiscovery {
                own_namespace: true,
                names: Vec::new(),
            },
            ..KubernetesSdConfig::default()
        };
        let disc = KubernetesPodDiscovery::new(cfg)
            .unwrap()
            .with_own_namespace_file("/dev/null");
        let err = disc.resolve_namespaces().unwrap_err().to_string();
        assert_eq!(err, "could not read own namespace name (empty file)");
    }

    #[test]
    fn in_cluster_auth_ca_and_namespace_validation() {
        let kubeconfig_cfg = KubernetesSdConfig {
            role: Some(KubernetesRole::Pod),
            kubeconfig_file: "/etc/kubeconfig".to_owned(),
            ..KubernetesSdConfig::default()
        };
        assert!(KubernetesPodDiscovery::new(kubeconfig_cfg).is_err());

        let node_cfg = KubernetesSdConfig {
            role: Some(KubernetesRole::Node),
            ..KubernetesSdConfig::default()
        };
        assert!(KubernetesPodDiscovery::new(node_cfg).is_err());

        let dir = std::env::temp_dir().join(format!("scrape-rs-k8s-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ns_file = dir.join("namespace");
        let tok_file = dir.join("token");
        let ca_file = dir.join("ca.crt");
        fs::write(&ns_file, "  monitoring \n").unwrap();
        fs::write(&tok_file, "  in-cluster-jwt \n").unwrap();
        fs::write(
            &ca_file,
            "-----BEGIN CERTIFICATE-----\n\
MIIBSzCB8qADAgECAgEBMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEVRlc3QgRGlz\n\
Y292ZXJ5IENBMCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAcMRow\n\
GAYDVQQDDBFUZXN0IERpc2NvdmVyeSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n\
A0IABIh8inO1e0XFBqDBtcxv3BmM0MHgV2PZeF+BswiHPsQ63K6Xt/xGZS9ziRh8\n\
bErqSNtv7W9shFuHxVmIuf+ROo+jIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P\n\
AQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUCIQCXh/u32CC/j81T+3oEJnRR0P8A\n\
ZCXcq24++2iU8RQHuAIgTvD813EN4j4Wd++SFXpG+evSLLk+fyJse98OIktvI/E=\n\
-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let mut disc = KubernetesPodDiscovery::new(KubernetesSdConfig {
            role: Some(KubernetesRole::Pod),
            namespaces: KubernetesNamespaceDiscovery {
                own_namespace: true,
                names: vec![
                    "default".to_owned(),
                    "monitoring".to_owned(),
                    "default".to_owned(),
                ],
            },
            ..KubernetesSdConfig::default()
        })
        .unwrap()
        .with_own_namespace_file(ns_file.to_string_lossy());

        assert_eq!(
            disc.resolve_namespaces().unwrap(),
            vec!["default".to_owned(), "monitoring".to_owned()]
        );

        assert!(
            disc.resolve_in_cluster_endpoint_and_auth("", "443")
                .is_err()
        );
        disc.in_cluster_token_file = dir.join("missing-token").to_string_lossy().into_owned();
        assert!(
            disc.resolve_in_cluster_endpoint_and_auth("10.96.0.1", "443")
                .is_err()
        );
        disc.in_cluster_token_file = tok_file.to_string_lossy().into_owned();
        disc.in_cluster_ca_file = dir.join("missing-ca").to_string_lossy().into_owned();
        assert!(
            disc.resolve_in_cluster_endpoint_and_auth("10.96.0.1", "443")
                .is_err()
        );
        disc.in_cluster_ca_file = ca_file.to_string_lossy().into_owned();
        let (base_url, _client, eff_http) = disc
            .resolve_in_cluster_endpoint_and_auth("fd00::1", "6443")
            .unwrap();
        assert_eq!(base_url, "https://[fd00::1]:6443");
        assert_eq!(eff_http.bearer_token_file, disc.in_cluster_token_file);
        assert_eq!(eff_http.tls_config.ca_file, disc.in_cluster_ca_file);

        let _ = fs::remove_dir_all(&dir);
    }
}
