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

//! Prometheus-compatible Kubernetes service discovery (`kubernetes_sd_configs`) schema and
//! pod target group builder (`role: pod`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::http_config::HttpClientConfig;

use super::{
    ADDRESS_LABEL, DiscoveryError, LabelSet, TargetGroup, join_host_port, sanitize_label_name,
};

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
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Namespace discovery filtering options matching Prometheus `kubernetes.NamespaceDiscovery`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesNamespaceDiscovery {
    /// Includes the pod's own in-cluster namespace.
    #[serde(default, skip_serializing_if = "is_false")]
    pub own_namespace: bool,
    /// Explicit list of namespaces to query. If empty and `own_namespace` is `false`,
    /// queries across all namespaces.
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub names: Vec<String>,
}

/// Resource label/field selector matching Prometheus `kubernetes.SelectorConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesSelectorConfig {
    /// Kubernetes role to which this selector applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<KubernetesRole>,
    /// Label selector string (`labelSelector` query parameter).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Field selector string (`fieldSelector` query parameter).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field: String,
}

/// Optional metadata attachment flags matching Prometheus `kubernetes.AttachMetadataConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAttachMetadataConfig {
    /// Attaches node labels and annotations (`__meta_kubernetes_node_*`) and filters pods
    /// by the node selector if configured.
    #[serde(default, skip_serializing_if = "is_false")]
    pub node: bool,
    /// Attaches namespace labels and annotations (`__meta_kubernetes_namespace_*`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub namespace: bool,
    /// Resolves owning `ReplicaSet` -> `Deployment` name (`__meta_kubernetes_pod_deployment_name`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub deployment: bool,
    /// Attaches owning `Job` name (`__meta_kubernetes_pod_job_name`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub job: bool,
    /// Resolves owning `Job` -> `CronJob` name (`__meta_kubernetes_pod_cronjob_name`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub cronjob: bool,
}

/// Kubernetes service discovery configuration matching Prometheus `kubernetes.SDConfig`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesSdConfig {
    /// Kubernetes API server URL. If omitted, in-cluster environment variables are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server: Option<String>,
    /// Kubernetes discovery role (`"pod"`, `"service"`, `"endpoints"`, `"endpointslice"`,
    /// `"node"`, or `"ingress"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<KubernetesRole>,
    /// Path to a kubeconfig file (mutually exclusive with `api_server` and custom HTTP config).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kubeconfig_file: String,
    /// Inlined Prometheus `HTTPClientConfig`.
    #[serde(flatten)]
    pub http_client_config: HttpClientConfig,
    /// Namespace discovery configuration.
    #[serde(default, skip_serializing_if = "is_default_namespaces")]
    pub namespaces: KubernetesNamespaceDiscovery,
    /// Label and field selectors per Kubernetes resource role.
    #[serde(
        default,
        deserialize_with = "deserialize_null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub selectors: Vec<KubernetesSelectorConfig>,
    /// Additional metadata attachment flags.
    #[serde(default, skip_serializing_if = "is_default_attach_metadata")]
    pub attach_metadata: KubernetesAttachMetadataConfig,
}

impl KubernetesSdConfig {
    /// Joins relative file paths in `kubeconfig_file` and `http_client_config` with `dir`.
    pub fn set_directory(&mut self, dir: &Path) {
        self.http_client_config.set_directory(dir);
        if !self.kubeconfig_file.is_empty() {
            let p = Path::new(&self.kubeconfig_file);
            if !p.is_absolute() {
                self.kubeconfig_file = dir.join(p).to_string_lossy().into_owned();
            }
        }
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
            let parsed = reqwest::Url::parse(api_server).map_err(|e| {
                DiscoveryError::InvalidConfig(format!("invalid api_server URL {api_server:?}: {e}"))
            })?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(DiscoveryError::InvalidConfig(format!(
                    "invalid api_server URL scheme {:?}, expected \"http\" or \"https\"",
                    parsed.scheme()
                )));
            }
            if parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(DiscoveryError::InvalidConfig(format!(
                    "api_server URL {api_server:?} must not contain query parameters or fragments"
                )));
            }
        }

        for ns in &self.namespaces.names {
            validate_k8s_namespace_name(ns)?;
        }

        let is_default_http = self.http_client_config.is_default();
        self.http_client_config.validate()?;

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
                    "role missing in selector (one of: pod, service, endpoints, endpointslice, node, ingress)".to_owned(),
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
        }

        Ok(())
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_default_namespaces(ns: &KubernetesNamespaceDiscovery) -> bool {
    *ns == KubernetesNamespaceDiscovery::default()
}

fn is_default_attach_metadata(am: &KubernetesAttachMetadataConfig) -> bool {
    *am == KubernetesAttachMetadataConfig::default()
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
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

/// Kubernetes `corev1.Node` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `corev1.Namespace` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `appsv1.ReplicaSet` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaSet {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
}

/// Kubernetes `batchv1.Job` resource.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// Standard object metadata.
    #[serde(default)]
    pub metadata: ObjectMeta,
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

fn validate_k8s_namespace_name(ns: &str) -> Result<(), DiscoveryError> {
    let bytes = ns.as_bytes();
    let is_valid = !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase() | bytes[0].is_ascii_digit()
        && bytes[bytes.len() - 1].is_ascii_lowercase() | bytes[bytes.len() - 1].is_ascii_digit()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !is_valid {
        return Err(DiscoveryError::InvalidConfig(format!(
            "invalid Kubernetes namespace name {ns:?}"
        )));
    }
    Ok(())
}
