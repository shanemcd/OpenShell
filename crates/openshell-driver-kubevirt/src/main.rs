// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use futures::Stream;
use miette::{IntoDiagnostic, Result};
use openshell_core::VERSION;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_kubevirt::{ComputeDriverService, KubevirtComputeDriver};
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{UnixListener, UnixStream};
use tracing::info;
use tracing_subscriber::EnvFilter;

use openshell_driver_kubevirt::driver::KubevirtDriverConfig;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-kubevirt")]
#[command(version = VERSION)]
struct Args {
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_BIND")]
    bind_address: Option<SocketAddr>,

    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: Option<PathBuf>,

    #[arg(long, hide = true)]
    expected_peer_pid: Option<u32>,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_UNAUTHENTICATED_TCP",
        default_value_t = false
    )]
    allow_unauthenticated_tcp: bool,

    #[arg(
        long,
        env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER",
        default_value_t = false
    )]
    allow_same_uid_peer: bool,

    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE", default_value = "")]
    default_image: String,

    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    #[arg(
        long,
        env = "OPENSHELL_KUBEVIRT_VCPUS",
        default_value_t = 2
    )]
    vcpus: u32,

    #[arg(
        long,
        env = "OPENSHELL_KUBEVIRT_MEMORY_MIB",
        default_value_t = 2048
    )]
    memory_mib: u32,

    /// Path to OPA rego rules file for standalone (gateway-less) mode.
    /// When set with --policy-data, the driver embeds these files in
    /// cloud-init so the supervisor can start without a gateway.
    #[arg(long, env = "OPENSHELL_POLICY_RULES")]
    policy_rules: Option<String>,

    /// Path to policy data YAML file for standalone mode.
    /// When set with --policy-rules, the driver embeds these files in
    /// cloud-init so the supervisor can start without a gateway.
    #[arg(long, env = "OPENSHELL_POLICY_DATA")]
    policy_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ListenMode {
    Unix {
        socket_path: PathBuf,
        expected_peer_pid: Option<u32>,
    },
    Tcp(SocketAddr),
}

fn determine_listen_mode(args: &Args) -> std::result::Result<ListenMode, String> {
    if let Some(socket_path) = args.bind_socket.clone() {
        if args.expected_peer_pid.is_none() && !args.allow_same_uid_peer {
            return Err(
                "--expected-peer-pid is required with --bind-socket; use --allow-same-uid-peer only for local development"
                    .to_string(),
            );
        }
        return Ok(ListenMode::Unix {
            socket_path,
            expected_peer_pid: args.expected_peer_pid,
        });
    }

    if !args.allow_unauthenticated_tcp {
        return Err(
            "--bind-socket is required; unauthenticated TCP mode is disabled unless --allow-unauthenticated-tcp is set"
                .to_string(),
        );
    }

    let Some(bind_address) = args.bind_address else {
        return Err("--bind-address is required with --allow-unauthenticated-tcp".to_string());
    };

    Ok(ListenMode::Tcp(bind_address))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let listen_mode = determine_listen_mode(&args).map_err(|err| miette::miette!("{err}"))?;

    let driver = KubevirtComputeDriver::new(KubevirtDriverConfig {
        namespace: args.sandbox_namespace.clone(),
        default_image: args.default_image.clone(),
        log_level: args.log_level.clone(),
        vcpus: args.vcpus,
        memory_mib: args.memory_mib,
        policy_rules_path: args.policy_rules,
        policy_data_path: args.policy_data,
    })
    .await
    .into_diagnostic()?;

    let service = ComputeDriverService::new(driver);

    match listen_mode {
        ListenMode::Unix {
            socket_path,
            expected_peer_pid,
        } => {
            prepare_socket(&socket_path).map_err(|err| miette::miette!("{err}"))?;

            info!(socket = %socket_path.display(), "Starting KubeVirt compute driver");
            let listener = UnixListener::bind(&socket_path).into_diagnostic()?;
            restrict_socket_permissions(&socket_path)
                .map_err(|err| miette::miette!("{err}"))?;
            let result = tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(service))
                .serve_with_incoming(AuthenticatedUnixIncoming::new(listener, expected_peer_pid))
                .await
                .into_diagnostic();
            let _ = std::fs::remove_file(&socket_path);
            result
        }
        ListenMode::Tcp(bind_address) => {
            info!(address = %bind_address, "Starting unauthenticated dev KubeVirt compute driver");
            tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(service))
                .serve(bind_address)
                .await
                .into_diagnostic()
        }
    }
}

// ---------------------------------------------------------------------------
// UDS socket helpers (modeled after openshell-driver-vm)
// ---------------------------------------------------------------------------

fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn prepare_socket(socket_path: &Path) -> std::result::Result<(), String> {
    let Some(parent) = socket_path.parent() else {
        return Err(format!(
            "socket path '{}' has no parent directory",
            socket_path.display()
        ));
    };
    let expected_uid = current_euid();
    prepare_private_socket_dir(parent, expected_uid)?;
    remove_stale_socket(socket_path, expected_uid)
}

fn prepare_private_socket_dir(
    socket_dir: &Path,
    expected_uid: u32,
) -> std::result::Result<(), String> {
    std::fs::create_dir_all(socket_dir)
        .map_err(|err| format!("create socket dir {}: {err}", socket_dir.display()))?;
    let metadata = std::fs::symlink_metadata(socket_dir)
        .map_err(|err| format!("stat socket dir {}: {err}", socket_dir.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "socket dir {} is a symlink; refusing to use it",
            socket_dir.display()
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "socket dir {} is not a directory",
            socket_dir.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket dir {} owned by uid {} but current euid is {}",
            socket_dir.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("chmod socket dir {}: {err}", socket_dir.display()))
}

fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> std::result::Result<(), String> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("stat socket {}: {err}", socket_path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "socket {} is a symlink; refusing to remove it",
            socket_path.display()
        ));
    }
    if metadata.uid() != expected_uid {
        return Err(format!(
            "socket {} owned by uid {} but current euid is {}",
            socket_path.display(),
            metadata.uid(),
            expected_uid
        ));
    }
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "socket path {} exists but is not a Unix socket",
            socket_path.display()
        ));
    }
    std::fs::remove_file(socket_path)
        .map_err(|err| format!("remove stale socket {}: {err}", socket_path.display()))
}

fn restrict_socket_permissions(socket_path: &Path) -> std::result::Result<(), String> {
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("chmod socket {}: {err}", socket_path.display()))
}

#[derive(Debug, Clone, Copy)]
struct PeerCredentials {
    uid: u32,
    pid: Option<i32>,
}

fn peer_credentials(stream: &UnixStream) -> std::result::Result<PeerCredentials, String> {
    let credentials = stream
        .peer_cred()
        .map_err(|err| format!("read peer credentials: {err}"))?;
    Ok(PeerCredentials {
        uid: credentials.uid(),
        pid: credentials.pid(),
    })
}

fn authorize_peer(
    peer: PeerCredentials,
    driver_uid: u32,
    gateway_pid: Option<u32>,
) -> std::result::Result<(), String> {
    if peer.uid != driver_uid {
        return Err(format!(
            "peer uid {} does not match current euid {}",
            peer.uid, driver_uid
        ));
    }
    let Some(gateway_pid) = gateway_pid else {
        return Ok(());
    };
    let Some(peer_pid) = peer.pid.and_then(|pid| u32::try_from(pid).ok()) else {
        return Err(format!(
            "peer pid is unavailable; expected gateway pid {gateway_pid}"
        ));
    };
    if peer_pid != gateway_pid {
        return Err(format!(
            "peer pid {peer_pid} does not match expected gateway pid {gateway_pid}"
        ));
    }
    Ok(())
}

struct AuthenticatedUnixIncoming {
    listener: UnixListener,
    expected_uid: u32,
    expected_peer_pid: Option<u32>,
}

impl AuthenticatedUnixIncoming {
    fn new(listener: UnixListener, expected_peer_pid: Option<u32>) -> Self {
        Self {
            listener,
            expected_uid: current_euid(),
            expected_peer_pid,
        }
    }
}

impl Stream for AuthenticatedUnixIncoming {
    type Item = io::Result<UnixStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _addr))) => {
                    let authorized = peer_credentials(&stream)
                        .and_then(|peer| authorize_peer(peer, this.expected_uid, this.expected_peer_pid));
                    match authorized {
                        Ok(()) => return Poll::Ready(Some(Ok(stream))),
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "rejected KubeVirt compute driver UDS client"
                            );
                        }
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
