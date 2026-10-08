//! Runtime isolation and execution backends for Clipak packages.
//!
//! Unlike sandboxed application runtimes (such as Flatpak), Clipak runs
//! developer tools with unconfined access to the host's PID, network, IPC,
//! and devices. Only the filesystem mount namespace is privatized to layer
//! the package's `/app` hierarchy and base runtime `/usr` over the host.
//!
//! Supported backends:
//! - [`bwrap_backend`]: Unprivileged mount namespacing via Bubblewrap.
//! - [`mount_namespace`]: Direct kernel `unshare(CLONE_NEWNS)` namespacing.
//! - [`ddi_mounter`]: Payload extraction and loopback preparation.
//! - [`dispatcher`]: Tool discovery, verification, and execution dispatch.

pub mod bwrap_backend;
pub mod ddi_mounter;
pub mod dispatcher;
pub mod mount_namespace;

pub use dispatcher::{ClipakDispatcher, InstalledTool, ToolRegistry};
