// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! KubeVirt compute driver — manages VirtualMachine / VirtualMachineInstance
//! resources on an OpenShift / Kubernetes cluster with KubeVirt installed.

use crate::types::{vm_api_resource, vmi_api_resource};
use futures::{Stream, StreamExt, TryStreamExt};
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverSandbox as Sandbox, DriverSandboxStatus as SandboxStatus,
    GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

/// Timeout for individual Kubernetes API calls.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);

/// SSH port used by the sandbox supervisor inside the VM.
const SANDBOX_SSH_PORT: u16 = 2222;

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, KubevirtDriverError>> + Send>>;

/// Configuration for the KubeVirt compute driver.
#[derive(Debug, Clone)]
pub struct KubevirtDriverConfig {
    /// Kubernetes namespace for VMs.
    pub namespace: String,
    /// Default sandbox OCI image.
    pub default_image: String,
    /// Log level for sandboxes.
    pub log_level: String,
    /// Number of vCPUs per VM.
    pub vcpus: u32,
    /// Memory in MiB per VM.
    pub memory_mib: u32,
    /// Path to OPA rego rules file for standalone (gateway-less) mode.
    /// When set (along with `policy_data_path`), the driver embeds these
    /// files in cloud-init so the supervisor can start without a gateway.
    pub policy_rules_path: Option<String>,
    /// Path to policy data YAML file for standalone mode.
    pub policy_data_path: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KubevirtDriverError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Message(String),
}

impl KubevirtDriverError {
    fn from_kube(err: KubeError) -> Self {
        match err {
            KubeError::Api(api) if api.code == 409 => Self::AlreadyExists,
            other => Self::Message(other.to_string()),
        }
    }
}

impl From<KubevirtDriverError> for openshell_core::ComputeDriverError {
    fn from(err: KubevirtDriverError) -> Self {
        match err {
            KubevirtDriverError::AlreadyExists => Self::AlreadyExists,
            KubevirtDriverError::InvalidArgument(m) => Self::InvalidArgument(m),
            KubevirtDriverError::Precondition(m) => Self::Precondition(m),
            KubevirtDriverError::Message(m) => Self::Message(m),
        }
    }
}

#[derive(Clone)]
pub struct KubevirtComputeDriver {
    client: Client,
    watch_client: Client,
    config: KubevirtDriverConfig,
    /// Pre-loaded OPA rules content for standalone (gateway-less) mode.
    policy_rules_content: Option<String>,
    /// Pre-loaded policy data YAML content for standalone mode.
    policy_data_content: Option<String>,
}

impl std::fmt::Debug for KubevirtComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubevirtComputeDriver")
            .field("namespace", &self.config.namespace)
            .field("default_image", &self.config.default_image)
            .finish()
    }
}

impl KubevirtComputeDriver {
    pub async fn new(config: KubevirtDriverConfig) -> Result<Self, KubevirtDriverError> {
        let base_config = match kube::Config::incluster() {
            Ok(c) => c,
            Err(_) => kube::Config::infer()
                .await
                .map_err(kube::Error::InferConfig)
                .map_err(KubevirtDriverError::from_kube)?,
        };

        let mut kube_config = base_config.clone();
        kube_config.connect_timeout = Some(Duration::from_secs(10));
        kube_config.read_timeout = Some(Duration::from_secs(30));
        kube_config.write_timeout = Some(Duration::from_secs(30));
        let client = Client::try_from(kube_config).map_err(KubevirtDriverError::from_kube)?;

        let mut watch_kube_config = base_config;
        watch_kube_config.connect_timeout = Some(Duration::from_secs(10));
        watch_kube_config.read_timeout = None;
        watch_kube_config.write_timeout = Some(Duration::from_secs(30));
        let watch_client =
            Client::try_from(watch_kube_config).map_err(KubevirtDriverError::from_kube)?;

        // Pre-load standalone policy files if configured
        let policy_rules_content = config
            .policy_rules_path
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path).map_err(|err| {
                    KubevirtDriverError::Message(format!(
                        "failed to read policy rules file {path}: {err}"
                    ))
                })
            })
            .transpose()?;

        let policy_data_content = config
            .policy_data_path
            .as_ref()
            .map(|path| {
                std::fs::read_to_string(path).map_err(|err| {
                    KubevirtDriverError::Message(format!(
                        "failed to read policy data file {path}: {err}"
                    ))
                })
            })
            .transpose()?;

        if policy_rules_content.is_some() && policy_data_content.is_some() {
            info!("Standalone policy mode enabled — policy files will be embedded in cloud-init");
        }

        Ok(Self {
            client,
            watch_client,
            config,
            policy_rules_content,
            policy_data_content,
        })
    }

    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, String> {
        Ok(openshell_core::driver_utils::build_capabilities_response(
            "kubevirt",
            openshell_core::VERSION,
            &self.config.default_image,
        ))
    }

    fn vm_api(&self, client: Client) -> Api<DynamicObject> {
        Api::namespaced_with(client, &self.config.namespace, &vm_api_resource())
    }

    fn vmi_api(&self, client: Client) -> Api<DynamicObject> {
        Api::namespaced_with(client, &self.config.namespace, &vmi_api_resource())
    }

    // -----------------------------------------------------------------------
    // CRUD operations
    // -----------------------------------------------------------------------

    pub async fn get_sandbox(&self, name: &str) -> Result<Option<Sandbox>, String> {
        info!(
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Fetching KubeVirt VM"
        );

        let vmi_api = self.vmi_api(self.client.clone());
        match tokio::time::timeout(KUBE_API_TIMEOUT, vmi_api.get(name)).await {
            Ok(Ok(obj)) => sandbox_from_vmi(&self.config.namespace, obj).map(Some),
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(sandbox_name = %name, "VMI not found");
                Ok(None)
            }
            Ok(Err(err)) => {
                warn!(sandbox_name = %name, error = %err, "Failed to fetch VMI");
                Err(err.to_string())
            }
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, String> {
        info!(
            namespace = %self.config.namespace,
            "Listing KubeVirt VMIs"
        );

        let vmi_api = self.vmi_api(self.client.clone());
        let label_selector = format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}");
        let lp = ListParams::default().labels(&label_selector);
        match tokio::time::timeout(KUBE_API_TIMEOUT, vmi_api.list(&lp)).await {
            Ok(Ok(list)) => {
                let mut sandboxes = list
                    .items
                    .into_iter()
                    .map(|obj| sandbox_from_vmi(&self.config.namespace, obj))
                    .collect::<Result<Vec<_>, _>>()?;
                sandboxes.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(sandboxes)
            }
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), KubevirtDriverError> {
        let name = sandbox.name.as_str();
        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Creating KubeVirt VM"
        );

        let image = sandbox
            .spec
            .as_ref()
            .and_then(|s| s.template.as_ref())
            .map(|t| t.image.as_str())
            .filter(|i| !i.is_empty())
            .unwrap_or(&self.config.default_image);

        let vm_api = self.vm_api(self.client.clone());
        let vm_resource = vm_api_resource();

        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED_BY.to_string(), LABEL_MANAGED_BY_VALUE.to_string());
        labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());

        // Merge any labels from the template
        if let Some(spec) = sandbox.spec.as_ref() {
            if let Some(tmpl) = spec.template.as_ref() {
                for (k, v) in &tmpl.labels {
                    labels.insert(k.clone(), v.clone());
                }
            }
        }

        // Gather environment variables from the sandbox spec
        let spec_env = sandbox
            .spec
            .as_ref()
            .map(|s| &s.environment)
            .cloned()
            .unwrap_or_default();

        let template_env = sandbox
            .spec
            .as_ref()
            .and_then(|s| s.template.as_ref())
            .map(|t| &t.environment)
            .cloned()
            .unwrap_or_default();

        let mut environment = spec_env;
        environment.extend(template_env);

        // Extract gateway endpoint and sandbox token from the spec
        let gateway_endpoint = environment
            .remove("OPENSHELL_ENDPOINT")
            .unwrap_or_default();
        let sandbox_token = sandbox
            .spec
            .as_ref()
            .map(|s| s.sandbox_token.as_str())
            .unwrap_or_default()
            .to_string();

        // Build cloud-init userdata
        let cloud_init = build_cloud_init_userdata(&CloudInitParams {
            sandbox_id: &sandbox.id,
            sandbox_name: name,
            log_level: &self.config.log_level,
            gateway_endpoint: &gateway_endpoint,
            sandbox_token: &sandbox_token,
            environment: &environment,
            policy_rules_content: self.policy_rules_content.as_deref(),
            policy_data_content: self.policy_data_content.as_deref(),
        });

        // KubeVirt limits inline cloudInitNoCloud userdata to 2048 bytes.
        // Always create a Secret with the userdata and reference it via
        // userDataSecretRef to avoid hitting that limit when policy files
        // are embedded.
        let secret_name = format!("{name}-cloudinit");
        let secret_api: Api<k8s_openapi::api::core::v1::Secret> =
            Api::namespaced(self.client.clone(), &self.config.namespace);

        let secret = k8s_openapi::api::core::v1::Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(self.config.namespace.clone()),
                labels: Some(labels.clone()),
                // Owner reference will be the VM — cleaned up when VM is deleted
                ..Default::default()
            },
            string_data: Some(
                [("userdata".to_string(), cloud_init)]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };

        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            secret_api.create(&PostParams::default(), &secret),
        )
        .await
        {
            Ok(Ok(_)) => {
                debug!(secret = %secret_name, "Created cloud-init secret");
            }
            Ok(Err(err)) => {
                warn!(error = %err, "Failed to create cloud-init secret");
                return Err(KubevirtDriverError::from_kube(err));
            }
            Err(_elapsed) => {
                return Err(KubevirtDriverError::Message(
                    "timed out creating cloud-init secret".to_string(),
                ));
            }
        }

        let vcpus = self.config.vcpus;
        let memory_mib = self.config.memory_mib;

        let vm_spec = json!({
            "spec": {
            "running": true,
            "template": {
                "metadata": {
                    "labels": labels,
                },
                "spec": {
                    "domain": {
                        "cpu": {
                            "cores": vcpus,
                        },
                        "devices": {
                            "disks": [
                                {
                                    "name": "containerdisk",
                                    "disk": {
                                        "bus": "virtio",
                                    },
                                },
                                {
                                    "name": "cloudinitdisk",
                                    "disk": {
                                        "bus": "virtio",
                                    },
                                },
                            ],
                            "interfaces": [
                                {
                                    "name": "default",
                                    "masquerade": {},
                                },
                            ],
                        },
                        "resources": {
                            "requests": {
                                "memory": format!("{memory_mib}Mi"),
                            },
                        },
                    },
                    "networks": [
                        {
                            "name": "default",
                            "pod": {},
                        },
                    ],
                    "volumes": [
                        {
                            "name": "containerdisk",
                            "containerDisk": {
                                "image": image,
                            },
                        },
                        {
                            "name": "cloudinitdisk",
                            "cloudInitNoCloud": {
                                "secretRef": {
                                    "name": secret_name,
                                },
                            },
                        },
                    ],
                },
            },
            },
        });

        let mut obj = DynamicObject::new(name, &vm_resource);
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(self.config.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        };
        obj.data = vm_spec;

        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            vm_api.create(&PostParams::default(), &obj),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "KubeVirt VM created successfully"
                );
                Ok(())
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create KubeVirt VM"
                );
                Err(KubevirtDriverError::from_kube(err))
            }
            Err(_elapsed) => Err(KubevirtDriverError::Message(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ))),
        }
    }

    pub async fn stop_sandbox(&self, name: &str) -> Result<(), String> {
        info!(
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Stopping KubeVirt VM"
        );

        // To stop a VM, we patch running=false on the VirtualMachine object
        let vm_api = self.vm_api(self.client.clone());
        let patch = serde_json::json!({
            "spec": {
                "running": false,
            }
        });
        let patch_params = kube::api::PatchParams::default();
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            vm_api.patch(name, &patch_params, &kube::api::Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(sandbox_name = %name, "KubeVirt VM stopped");
                Ok(())
            }
            Ok(Err(err)) => {
                warn!(sandbox_name = %name, error = %err, "Failed to stop KubeVirt VM");
                Err(err.to_string())
            }
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, String> {
        info!(
            sandbox_name = %name,
            namespace = %self.config.namespace,
            "Deleting KubeVirt VM"
        );

        // Clean up the cloud-init secret (best-effort)
        let secret_name = format!("{name}-cloudinit");
        let secret_api: Api<k8s_openapi::api::core::v1::Secret> =
            Api::namespaced(self.client.clone(), &self.config.namespace);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            secret_api.delete(&secret_name, &DeleteParams::default()),
        )
        .await
        {
            Ok(Ok(_)) => debug!(secret = %secret_name, "Deleted cloud-init secret"),
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(secret = %secret_name, "Cloud-init secret not found (already deleted)");
            }
            Ok(Err(err)) => {
                warn!(secret = %secret_name, error = %err, "Failed to delete cloud-init secret");
            }
            Err(_) => {
                warn!(secret = %secret_name, "Timed out deleting cloud-init secret");
            }
        }

        let vm_api = self.vm_api(self.client.clone());
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            vm_api.delete(name, &DeleteParams::default()),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(sandbox_name = %name, "KubeVirt VM deleted");
                Ok(true)
            }
            Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                debug!(sandbox_name = %name, "KubeVirt VM not found (already deleted)");
                Ok(false)
            }
            Ok(Err(err)) => {
                warn!(sandbox_name = %name, error = %err, "Failed to delete KubeVirt VM");
                Err(err.to_string())
            }
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Watch
    // -----------------------------------------------------------------------

    pub async fn watch_sandboxes(&self) -> Result<WatchStream, String> {
        let namespace = self.config.namespace.clone();
        let vmi_api = self.vmi_api(self.watch_client.clone());
        let watcher_config = watcher::Config::default();
        let mut vmi_stream = watcher::watcher(vmi_api, watcher_config).boxed();
        let (tx, rx) = mpsc::channel(256);

        tokio::spawn(async move {
            loop {
                match vmi_stream.try_next().await {
                    Ok(Some(Event::Applied(obj))) => {
                        match sandbox_from_vmi(&namespace, obj) {
                            Ok(sandbox) => {
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent {
                                            sandbox: Some(sandbox),
                                        },
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                if tx
                                    .send(Err(KubevirtDriverError::Message(err)))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(Some(Event::Deleted(obj))) => {
                        match sandbox_id_from_object(&obj) {
                            Ok(sandbox_id) => {
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Deleted(
                                        WatchSandboxesDeletedEvent { sandbox_id },
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                if tx
                                    .send(Err(KubevirtDriverError::Message(err)))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    Ok(Some(Event::Restarted(objs))) => {
                        for obj in objs {
                            match sandbox_from_vmi(&namespace, obj) {
                                Ok(sandbox) => {
                                    let event = WatchSandboxesEvent {
                                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                            WatchSandboxesSandboxEvent {
                                                sandbox: Some(sandbox),
                                            },
                                        )),
                                    };
                                    if tx.send(Ok(event)).await.is_err() {
                                        return;
                                    }
                                }
                                Err(err) => {
                                    if tx
                                        .send(Err(KubevirtDriverError::Message(err)))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        let _ = tx
                            .send(Err(KubevirtDriverError::Message(
                                "VMI watcher stream ended unexpectedly".to_string(),
                            )))
                            .await;
                        break;
                    }
                    Err(err) => {
                        let _ = tx
                            .send(Err(KubevirtDriverError::Message(err.to_string())))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a sandbox ID from a KubeVirt object's labels.
fn sandbox_id_from_object(obj: &DynamicObject) -> Result<String, String> {
    obj.metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .cloned()
        .ok_or_else(|| {
            format!(
                "object {} missing {} label",
                obj.metadata.name.as_deref().unwrap_or("<unknown>"),
                LABEL_SANDBOX_ID
            )
        })
}

/// Convert a KubeVirt `VirtualMachineInstance` `DynamicObject` into a
/// driver-native [`Sandbox`] snapshot.
fn sandbox_from_vmi(namespace: &str, obj: DynamicObject) -> Result<Sandbox, String> {
    let name = obj
        .metadata
        .name
        .as_deref()
        .unwrap_or_default()
        .to_string();
    let sandbox_id = sandbox_id_from_object(&obj)?;

    // Extract VMI phase from .status.phase
    let phase = obj
        .data
        .get("status")
        .and_then(|s| s.get("phase"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Unknown")
        .to_string();

    // Extract pod IP from .status.interfaces[0].ipAddress
    let pod_ip = obj
        .data
        .get("status")
        .and_then(|s| s.get("interfaces"))
        .and_then(serde_json::Value::as_array)
        .and_then(|interfaces| interfaces.first())
        .and_then(|iface| iface.get("ipAddress"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    // Determine readiness based on VMI phase
    let is_ready = phase == "Running";

    let mut conditions = Vec::new();
    conditions.push(DriverCondition {
        r#type: "Ready".to_string(),
        status: if is_ready {
            "True".to_string()
        } else {
            "False".to_string()
        },
        reason: phase.clone(),
        message: format!("VMI phase: {phase}"),
        last_transition_time: String::new(),
    });

    // Build the agent endpoint from pod IP + SSH port
    let agent_fd = if !pod_ip.is_empty() && is_ready {
        format!("{pod_ip}:{SANDBOX_SSH_PORT}")
    } else {
        String::new()
    };

    let deleting = obj.metadata.deletion_timestamp.is_some();

    Ok(Sandbox {
        id: sandbox_id,
        name: name.clone(),
        namespace: namespace.to_string(),
        spec: None,
        status: Some(SandboxStatus {
            sandbox_name: name,
            instance_id: obj
                .metadata
                .uid
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            agent_fd,
            sandbox_fd: String::new(),
            conditions,
            deleting,
        }),
    })
}

/// Parameters for building cloud-init userdata.
struct CloudInitParams<'a> {
    sandbox_id: &'a str,
    sandbox_name: &'a str,
    log_level: &'a str,
    /// Gateway gRPC endpoint (e.g. `https://gateway.openshell.svc:8443`).
    /// When empty, the supervisor runs in local/standalone mode.
    gateway_endpoint: &'a str,
    /// Per-sandbox JWT token issued by the gateway.
    sandbox_token: &'a str,
    /// Additional environment variables to inject into the supervisor.
    environment: &'a std::collections::HashMap<String, String>,
    /// OPA rego rules content for standalone mode.
    policy_rules_content: Option<&'a str>,
    /// Policy data YAML content for standalone mode.
    policy_data_content: Option<&'a str>,
}

/// Build cloud-init userdata that configures the sandbox VM.
///
/// The userdata:
/// 1. Writes the sandbox identity and credentials to well-known paths.
/// 2. Configures SSH on the sandbox port.
/// 3. Starts the openshell-sandbox supervisor as a systemd service so it
///    survives cloud-init and can be monitored/restarted.
fn build_cloud_init_userdata(params: &CloudInitParams<'_>) -> String {
    use openshell_core::driver_utils::{
        SANDBOX_TOKEN_MOUNT_PATH, SUPERVISOR_CONTAINER_BINARY,
    };

    let CloudInitParams {
        sandbox_id,
        sandbox_name,
        log_level,
        gateway_endpoint,
        sandbox_token,
        environment,
        policy_rules_content,
        policy_data_content,
    } = params;

    // Build the Environment= lines for the systemd unit
    let mut env_lines = Vec::new();
    env_lines.push(format!("Environment=OPENSHELL_SANDBOX_ID={sandbox_id}"));
    env_lines.push(format!("Environment=OPENSHELL_SANDBOX={sandbox_name}"));
    env_lines.push(format!("Environment=OPENSHELL_LOG_LEVEL={log_level}"));
    env_lines.push(format!(
        "Environment=OPENSHELL_SSH_SOCKET_PATH=/run/openshell/ssh.sock"
    ));
    env_lines.push(format!("Environment=OPENSHELL_SANDBOX_UID=10001"));
    env_lines.push(format!("Environment=OPENSHELL_SANDBOX_GID=10001"));

    if !gateway_endpoint.is_empty() {
        env_lines.push(format!(
            "Environment=OPENSHELL_ENDPOINT={gateway_endpoint}"
        ));
    }
    if !sandbox_token.is_empty() {
        env_lines.push(format!(
            "Environment=OPENSHELL_SANDBOX_TOKEN_FILE={SANDBOX_TOKEN_MOUNT_PATH}"
        ));
    }

    // Standalone policy mode: point the supervisor at embedded policy files
    let has_standalone_policy = policy_rules_content.is_some() && policy_data_content.is_some();
    if has_standalone_policy {
        env_lines.push(format!(
            "Environment=OPENSHELL_POLICY_RULES=/etc/openshell/policy/rules.rego"
        ));
        env_lines.push(format!(
            "Environment=OPENSHELL_POLICY_DATA=/etc/openshell/policy/data.yaml"
        ));
    }

    // Propagate extra environment variables from the sandbox spec
    for (k, v) in environment.iter() {
        env_lines.push(format!("Environment={k}={v}"));
    }

    let env_block = env_lines.join("\n      ");

    // Build write_files entries for credentials
    let mut write_files = String::new();
    write_files.push_str(&format!(
        r#"  - path: /etc/openshell/sandbox-id
    content: "{sandbox_id}"
    permissions: "0644"
"#
    ));

    if !sandbox_token.is_empty() {
        write_files.push_str(&format!(
            r#"  - path: {SANDBOX_TOKEN_MOUNT_PATH}
    content: "{sandbox_token}"
    permissions: "0400"
"#
        ));
    }

    // Embed standalone policy files
    if let (Some(rules), Some(data)) = (policy_rules_content, policy_data_content) {
        // Indent the rego content for YAML block scalar
        let rules_indented: String = rules
            .lines()
            .map(|line| format!("      {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_files.push_str(&format!(
            r#"  - path: /etc/openshell/policy/rules.rego
    permissions: "0644"
    content: |
{rules_indented}
"#
        ));

        let data_indented: String = data
            .lines()
            .map(|line| format!("      {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_files.push_str(&format!(
            r#"  - path: /etc/openshell/policy/data.yaml
    permissions: "0644"
    content: |
{data_indented}
"#
        ));
    }

    format!(
        r#"#cloud-config
users:
  - name: sandbox
    uid: "10001"
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL

write_files:
{write_files}
  - path: /etc/systemd/system/openshell-sandbox.service
    permissions: "0644"
    content: |
      [Unit]
      Description=OpenShell Sandbox Supervisor
      After=network-online.target sshd.service
      Wants=network-online.target

      [Service]
      Type=simple
      ExecStart={SUPERVISOR_CONTAINER_BINARY}
      Restart=on-failure
      RestartSec=5
      {env_block}

      [Install]
      WantedBy=multi-user.target

runcmd:
  - |
    # Configure SSH on port {SANDBOX_SSH_PORT}
    sed -i 's/^#\?Port .*/Port {SANDBOX_SSH_PORT}/' /etc/ssh/sshd_config
    systemctl restart sshd || true
  - |
    # Ensure run directory exists
    mkdir -p /run/openshell
  - |
    # Enable and start the supervisor
    systemctl daemon-reload
    systemctl enable --now openshell-sandbox.service
"#
    )
}
