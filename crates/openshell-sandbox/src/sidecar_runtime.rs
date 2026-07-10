// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime coordination files for network-only (sidecar) supervisor mode.
//!
//! When `--mode=network`, the supervisor does not spawn the workload. A sibling
//! service (e.g. systemd `nemoclaw.service`) enters the supervisor's netns and
//! runs the app. These well-known files let the two cooperate:
//!
//! - `/run/openshell/netns` — absolute path of the active sandbox netns
//! - `/run/openshell/provider.env` — `KEY=placeholder` lines for credential env
//! - `/run/openshell/entrypoint.pid` — PID of a process inside the sandbox netns
//!   (written by the sibling); the proxy needs this for `/proc/<pid>/net/tcp`
//!   identity binding

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tracing::{info, warn};

pub const RUN_DIR: &str = "/run/openshell";
pub const NETNS_PATH_FILE: &str = "/run/openshell/netns";
pub const PROVIDER_ENV_FILE: &str = "/run/openshell/provider.env";
pub const ENTRYPOINT_PID_FILE: &str = "/run/openshell/entrypoint.pid";

/// Publish netns path + provider placeholder env for a sibling workload service.
pub fn publish_sidecar_runtime_files(
    netns_name: &str,
    provider_env: &HashMap<String, String>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(RUN_DIR)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(RUN_DIR, std::fs::Permissions::from_mode(0o755));
    }

    let netns_path = format!("/run/netns/{netns_name}");
    atomic_write(Path::new(NETNS_PATH_FILE), format!("{netns_path}\n").as_bytes())?;

    let mut body = String::new();
    let mut keys: Vec<_> = provider_env.keys().collect();
    keys.sort();
    for key in keys {
        let Some(value) = provider_env.get(key) else {
            continue;
        };
        // Env files cannot carry newlines; skip anything unsafe.
        if key.contains('=') || key.contains('\n') || value.contains('\n') {
            warn!(key = %key, "skipping provider env entry with unsafe characters");
            continue;
        }
        body.push_str(key);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    atomic_write(Path::new(PROVIDER_ENV_FILE), body.as_bytes())?;

    info!(
        netns = %netns_path,
        provider_env_keys = provider_env.len(),
        "Published sidecar runtime files under /run/openshell"
    );
    Ok(())
}

/// Watch for an externally published entrypoint PID and feed it to the proxy.
///
/// The sibling workload must write a PID that lives in the sandbox netns so
/// `/proc/<pid>/net/tcp` reflects sandbox sockets.
pub fn spawn_external_entrypoint_watcher(entrypoint_pid: Arc<AtomicU32>) {
    tokio::spawn(async move {
        let mut last_published = 0u32;
        loop {
            match read_entrypoint_pid(Path::new(ENTRYPOINT_PID_FILE)) {
                Ok(Some(pid)) if pid != last_published => {
                    entrypoint_pid.store(pid, Ordering::Release);
                    last_published = pid;
                    info!(
                        pid,
                        path = ENTRYPOINT_PID_FILE,
                        "Adopted external entrypoint PID for proxy identity binding"
                    );
                }
                Ok(Some(pid)) => {
                    // Refresh if the previously published PID disappeared
                    // (workload restarted under a new PID we haven't seen yet
                    // is handled above; here we clear a stale dead PID).
                    if !Path::new(&format!("/proc/{pid}")).exists()
                        && entrypoint_pid.load(Ordering::Acquire) == pid
                    {
                        entrypoint_pid.store(0, Ordering::Release);
                        last_published = 0;
                        warn!(
                            pid,
                            "External entrypoint PID is gone; clearing until republished"
                        );
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    debug_read_error(&err);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

fn read_entrypoint_pid(path: &Path) -> std::io::Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match trimmed.parse::<u32>() {
        Ok(pid) if pid > 1 => Ok(Some(pid)),
        Ok(_) => Ok(None),
        Err(_) => {
            warn!(path = %path.display(), value = %trimmed, "invalid entrypoint PID file contents");
            Ok(None)
        }
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn debug_read_error(err: &std::io::Error) {
    // Avoid log spam for expected races (file replaced mid-read).
    if err.kind() == std::io::ErrorKind::NotFound {
        return;
    }
    warn!(error = %err, path = ENTRYPOINT_PID_FILE, "failed reading external entrypoint PID");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn read_entrypoint_pid_parses_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entrypoint.pid");
        std::fs::write(&path, "12345\n").unwrap();
        assert_eq!(read_entrypoint_pid(&path).unwrap(), Some(12345));
    }

    #[test]
    fn read_entrypoint_pid_rejects_pid_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entrypoint.pid");
        std::fs::write(&path, "1\n").unwrap();
        assert_eq!(read_entrypoint_pid(&path).unwrap(), None);
    }

    #[test]
    fn provider_env_roundtrip_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.env");
        let mut env = HashMap::new();
        env.insert(
            "DISCORD_BOT_TOKEN".into(),
            "openshell:resolve:env:DISCORD_BOT_TOKEN".into(),
        );
        env.insert(
            "SLACK_BOT_TOKEN".into(),
            "openshell:resolve:env:SLACK_BOT_TOKEN".into(),
        );
        let mut body = String::new();
        let mut keys: Vec<_> = env.keys().collect();
        keys.sort();
        for key in keys {
            body.push_str(key);
            body.push('=');
            body.push_str(&env[key]);
            body.push('\n');
        }
        std::fs::write(&path, body).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("DISCORD_BOT_TOKEN=openshell:resolve:env:DISCORD_BOT_TOKEN"));
        assert!(text.contains("SLACK_BOT_TOKEN=openshell:resolve:env:SLACK_BOT_TOKEN"));
    }
}
