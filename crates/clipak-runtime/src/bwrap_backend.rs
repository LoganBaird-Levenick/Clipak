//! Unprivileged mount namespacing backend powered by Bubblewrap (`bwrap`).
//!
//! Configures Bubblewrap to mount `/app` (and `/usr`) while passing through
//! the host filesystem, devices, `/proc`, `/sys`, and network/PID namespaces.
//! This allows unprivileged users to execute tools that need host access.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Spawns the tool process inside an unconfined mount namespace using Bubblewrap.
pub fn execute_with_bwrap(
    runtime_usr_path: &Path,
    tool_app_path: &Path,
    binary_path: &Path,
    args: &[String],
    env: &HashMap<String, String>,
) -> Result<i32> {
    let mut cmd = Command::new("bwrap");

    // Host pass-through mounts for unconfined developer utilities
    cmd.arg("--dev-bind").arg("/dev").arg("/dev");
    cmd.arg("--proc").arg("/proc");
    cmd.arg("--bind").arg("/sys").arg("/sys");
    cmd.arg("--bind").arg("/run").arg("/run");
    cmd.arg("--bind").arg("/tmp").arg("/tmp");
    cmd.arg("--bind").arg("/var").arg("/var");
    cmd.arg("--bind").arg("/etc").arg("/etc");

    if Path::new("/home").exists() {
        cmd.arg("--bind").arg("/home").arg("/home");
    }
    if Path::new("/var/home").exists() {
        cmd.arg("--bind").arg("/var/home").arg("/var/home");
    }

    // Root mounts
    if Path::new("/root").exists() {
        cmd.arg("--bind").arg("/root").arg("/root");
    }

    // Bind Runtime /usr
    if runtime_usr_path.exists() {
        cmd.arg("--ro-bind").arg(runtime_usr_path).arg("/usr");
    } else {
        cmd.arg("--ro-bind").arg("/usr").arg("/usr");
    }

    // Standard symlinks to /usr
    cmd.arg("--symlink").arg("usr/lib").arg("/lib");
    cmd.arg("--symlink").arg("usr/lib64").arg("/lib64");
    cmd.arg("--symlink").arg("usr/bin").arg("/bin");
    cmd.arg("--symlink").arg("usr/sbin").arg("/sbin");

    // Bind Tool /app
    cmd.arg("--ro-bind").arg(tool_app_path).arg("/app");

    // Notice: We do NOT pass --unshare-pid, --unshare-net, --unshare-ipc!
    // This guarantees PID, Network, and IPC namespaces remain host-unconfined.

    // Inject environment variables
    for (k, v) in env {
        cmd.arg("--setenv").arg(k).arg(v);
    }

    // Target binary and arguments
    cmd.arg(binary_path);
    for arg in args {
        cmd.arg(arg);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| "Failed to spawn bubblewrap for Clipak mount namespace")?;

    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}
