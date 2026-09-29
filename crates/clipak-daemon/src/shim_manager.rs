use anyhow::{Context, Result};
use clipak_core::constants::*;
use clipak_runtime::{InstalledTool, ToolRegistry};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub enum ShimMode {
    Symlink,
    ShellScript,
}

/// Manages registration of exported binaries into host PATH
pub struct ShimManager {
    bin_dir: PathBuf,
    mode: ShimMode,
}

impl ShimManager {
    /// Creates a ShimManager for the appropriate scope (user or system)
    pub fn new(is_system: bool, mode: ShimMode) -> Result<Self> {
        let bin_dir = if is_system {
            PathBuf::from(SYSTEM_BIN_DIR)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(USER_LOCAL_BIN_REL)
        };

        fs::create_dir_all(&bin_dir)?;
        Ok(Self { bin_dir, mode })
    }

    /// Returns the active bin directory
    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// Installs shims for a specific tool
    pub fn install_shims_for_tool(
        &self,
        tool: &InstalledTool,
        clipak_binary_path: &Path,
    ) -> Result<Vec<PathBuf>> {
        let mut created = Vec::new();

        for export in &tool.manifest.binaries {
            let shim_path = self.bin_dir.join(&export.name);

            match self.mode {
                ShimMode::Symlink => {
                    // Create symbolic link to the clipak dispatcher binary
                    let _ = fs::remove_file(&shim_path);
                    std::os::unix::fs::symlink(clipak_binary_path, &shim_path).with_context(|| {
                        format!("Failed to create symlink {} -> {}", shim_path.display(), clipak_binary_path.display())
                    })?;
                }
                ShimMode::ShellScript => {
                    let script = format!(
                        r#"#!/bin/sh
# Auto-generated Clipak execution shim for {}
exec {} run "{}" "{}" "$@"
"#,
                        export.name,
                        clipak_binary_path.display(),
                        tool.id,
                        export.name
                    );
                    fs::write(&shim_path, script)?;
                    let mut perms = fs::metadata(&shim_path)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&shim_path, perms)?;
                }
            }

            created.push(shim_path);
        }

        Ok(created)
    }

    /// Removes shims associated with a tool
    pub fn remove_shims_for_tool(&self, tool: &InstalledTool) -> Result<()> {
        for export in &tool.manifest.binaries {
            let shim_path = self.bin_dir.join(&export.name);
            if shim_path.exists() {
                let _ = fs::remove_file(shim_path);
            }
        }
        Ok(())
    }

    /// Synchronizes all shims against currently installed tools
    pub fn sync_all_shims(&self, clipak_binary_path: &Path) -> Result<usize> {
        let tools = ToolRegistry::list_tools()?;
        let mut count = 0;

        for tool in &tools {
            let shims = self.install_shims_for_tool(tool, clipak_binary_path)?;
            count += shims.len();
        }

        Ok(count)
    }

    /// Generates environment profile scripts prepending the binary path
    pub fn write_environment_scripts(&self, is_system: bool) -> Result<()> {
        let script = r#"# Clipak Environment PATH Integration
# Prepending dedicated unconfined developer tool directories

if [ -d "/var/lib/clipak/bin" ]; then
    case ":$PATH:" in
        *":/var/lib/clipak/bin:"*) ;;
        *) export PATH="/var/lib/clipak/bin:$PATH" ;;
    esac
fi

if [ -n "$HOME" ] && [ -d "$HOME/.local/share/clipak/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/share/clipak/bin:"*) ;;
        *) export PATH="$HOME/.local/share/clipak/bin:$PATH" ;;
    esac
fi
"#;

        if is_system {
            let profile_path = Path::new(SYSTEM_PROFILE_PATH);
            if let Some(parent) = profile_path.parent() {
                if parent.exists() {
                    let _ = fs::write(profile_path, script);
                }
            }
        } else if let Ok(home) = std::env::var("HOME") {
            let bashrc_d = PathBuf::from(&home).join(".bashrc.d");
            if !bashrc_d.exists() {
                let _ = fs::create_dir_all(&bashrc_d);
            }
            let _ = fs::write(bashrc_d.join("clipak.sh"), script);

            // Also systemd environment.d
            let env_d = PathBuf::from(&home).join(".config/environment.d");
            if !env_d.exists() {
                let _ = fs::create_dir_all(&env_d);
            }
            let conf = format!("PATH={}:/var/lib/clipak/bin:$PATH\n", self.bin_dir.display());
            let _ = fs::write(env_d.join("10-clipak.conf"), conf);
        }

        Ok(())
    }
}
