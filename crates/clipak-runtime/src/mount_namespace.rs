use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use std::fs;
use std::path::Path;

/// Sets up a specialized mount namespace using native Linux system calls.
/// All other namespaces (PID, Network, IPC, User) remain unconfined on the host.
pub fn enter_native_mount_namespace(
    runtime_usr_path: &Path,
    tool_app_path: &Path,
) -> Result<()> {
    // 1. Call unshare(CLONE_NEWNS)
    // If not root, also try CLONE_NEWUSER so unprivileged users can create mount namespaces
    let euid = nix::unistd::geteuid();
    if euid.is_root() {
        unshare(CloneFlags::CLONE_NEWNS)
            .context("Failed to unshare CLONE_NEWNS as root")?;
    } else {
        // Attempt unshare CLONE_NEWUSER | CLONE_NEWNS
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();

        unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS)
            .context("Failed to unshare CLONE_NEWUSER | CLONE_NEWNS for unprivileged mount namespace")?;

        // Write uid_map and gid_map to map current user to 0 inside namespace (or keep 1:1)
        let _ = fs::write("/proc/self/setgroups", "deny");
        let uid_map = format!("0 {} 1\n", uid);
        let gid_map = format!("0 {} 1\n", gid);
        fs::write("/proc/self/uid_map", uid_map)?;
        fs::write("/proc/self/gid_map", gid_map)?;
    }

    // 2. Set root propagation to private
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("Failed to set root mount propagation to MS_PRIVATE")?;

    // 3. Ensure mount point /app exists in namespace
    let app_target = Path::new("/app");
    if !app_target.exists() {
        let _ = fs::create_dir_all(app_target);
    }

    // 4. Bind mount tool payload onto /app
    if tool_app_path.exists() {
        mount(
            Some(tool_app_path),
            app_target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| format!("Failed to bind mount {} to /app", tool_app_path.display()))?;
    }

    // 5. If runtime_usr_path is specified and different from /usr, bind mount it onto /usr
    if runtime_usr_path.exists() && runtime_usr_path != Path::new("/usr") {
        let usr_target = Path::new("/usr");
        mount(
            Some(runtime_usr_path),
            usr_target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| format!("Failed to bind mount {} to /usr", runtime_usr_path.display()))?;
    }

    // 6. Host pass-through paths (/home, /etc, /var, /tmp, /dev, /proc, /sys, /run)
    // In unshare(CLONE_NEWNS), since we started from host root and only changed /app and /usr,
    // all host mounts already remain pass-through and unconfined!
    // We additionally ensure /dev, /proc, and /sys are accessible and unconfined.

    Ok(())
}
