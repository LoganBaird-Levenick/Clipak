//! Package installation lifecycle, environment setup, and host PATH shims.
//!
//! Provides the system integration layer that links installed Clipak tools
//! directly into the user's interactive shell and terminal environment:
//! - [`installer`]: Installs, verifies, and uninstalls package trees.
//! - [`shim_manager`]: Generates host execution wrappers in `PATH` (`~/.local/share/clipak/bin` or `/var/lib/clipak/bin`).

pub mod installer;
pub mod shim_manager;

pub use installer::PackageInstaller;
pub use shim_manager::{ShimManager, ShimMode};
