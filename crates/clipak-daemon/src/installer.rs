use anyhow::{bail, Context, Result};
use clipak_core::constants::*;
use clipak_core::manifest::ToolManifest;
use clipak_runtime::{ClipakDispatcher, InstalledTool, ToolRegistry};
use std::fs;
use std::path::{Path, PathBuf};

use crate::shim_manager::{ShimManager, ShimMode};

pub struct PackageInstaller {
    is_system: bool,
    dispatcher: ClipakDispatcher,
    shim_mgr: ShimManager,
}

impl PackageInstaller {
    pub fn new(is_system: bool, allow_unverified: bool) -> Result<Self> {
        let dispatcher = ClipakDispatcher::new(allow_unverified)?;
        let shim_mgr = ShimManager::new(is_system, ShimMode::ShellScript)?;
        Ok(Self {
            is_system,
            dispatcher,
            shim_mgr,
        })
    }

    /// Installs a tool package from a DDI and manifest
    pub fn install(
        &self,
        ddi_path: &Path,
        manifest_path: &Path,
        clipak_bin_path: &Path,
    ) -> Result<InstalledTool> {
        let manifest_str = fs::read_to_string(manifest_path)?;
        let manifest = ToolManifest::from_json_str(&manifest_str)?;

        // Verify DDI integrity
        self.dispatcher.verify_ddi(ddi_path)?;

        let target_base = if self.is_system {
            PathBuf::from(SYSTEM_TOOLS_DIR)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
            PathBuf::from(home).join(USER_TOOLS_REL)
        };

        let tool_dir = target_base.join(&manifest.id);
        fs::create_dir_all(&tool_dir)?;

        let target_ddi = tool_dir.join("image.ddi");
        let target_manifest = tool_dir.join("manifest.json");

        fs::copy(ddi_path, &target_ddi)?;
        fs::copy(manifest_path, &target_manifest)?;

        let tool = InstalledTool {
            id: manifest.id.clone(),
            install_dir: tool_dir,
            ddi_path: target_ddi,
            manifest,
        };

        // Create host shims for exported binaries
        self.shim_mgr.install_shims_for_tool(&tool, clipak_bin_path)?;

        // Ensure profile scripts are in place
        self.shim_mgr.write_environment_scripts(self.is_system)?;

        Ok(tool)
    }

    /// Uninstalls an installed tool package
    pub fn uninstall(&self, tool_id: &str) -> Result<()> {
        let tool_opt = ToolRegistry::find_tool(tool_id)?;
        let tool = match tool_opt {
            Some(t) => t,
            None => bail!("Tool '{}' is not installed", tool_id),
        };

        // Remove host shims
        self.shim_mgr.remove_shims_for_tool(&tool)?;

        // Remove tool directory
        if tool.install_dir.exists() {
            fs::remove_dir_all(&tool.install_dir)
                .with_context(|| format!("Failed to remove {}", tool.install_dir.display()))?;
        }

        Ok(())
    }
}
