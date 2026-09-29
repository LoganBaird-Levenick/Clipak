use anyhow::{bail, Result};
use clipak_core::constants::*;
use clipak_core::crypto::verify_root_hash_signature;
use clipak_core::gpt::read_ddi_image;
use clipak_core::manifest::ToolManifest;
use clipak_core::policy::{EnforcementMode, TrustStore};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::bwrap_backend::execute_with_bwrap;
use crate::ddi_mounter::prepare_ddi_payload;
use crate::mount_namespace::enter_native_mount_namespace;

/// Describes an installed Clipak tool installation
#[derive(Debug, Clone)]
pub struct InstalledTool {
    pub id: String,
    pub install_dir: PathBuf,
    pub ddi_path: PathBuf,
    pub manifest: ToolManifest,
}

impl InstalledTool {
    /// Loads an installed tool from a directory
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self> {
        let dir = dir.as_ref();
        let manifest_path = dir.join("manifest.json");
        if !manifest_path.exists() {
            bail!("manifest.json not found in {}", dir.display());
        }
        let manifest_str = fs::read_to_string(&manifest_path)?;
        let manifest = ToolManifest::from_json_str(&manifest_str)?;

        let ddi_path = dir.join("image.ddi");
        if !ddi_path.exists() {
            bail!("image.ddi not found in {}", dir.display());
        }

        Ok(Self {
            id: manifest.id.clone(),
            install_dir: dir.to_path_buf(),
            ddi_path,
            manifest,
        })
    }
}

/// Registry of installed tools across user and system directories
pub struct ToolRegistry;

impl ToolRegistry {
    /// Discovers an installed tool by ID or by exported binary name
    pub fn find_tool(identifier_or_binary: &str) -> Result<Option<InstalledTool>> {
        let mut search_dirs = Vec::new();

        // User tools directory: ~/.local/share/clipak/tools
        if let Ok(home) = std::env::var("HOME") {
            search_dirs.push(PathBuf::from(home).join(USER_TOOLS_REL));
        }
        // System tools directory: /var/lib/clipak/tools
        search_dirs.push(PathBuf::from(SYSTEM_TOOLS_DIR));

        for base in search_dirs {
            if !base.exists() {
                continue;
            }
            // Check direct match by ID
            let direct_path = base.join(identifier_or_binary);
            if direct_path.exists() {
                if let Ok(tool) = InstalledTool::load_from_dir(&direct_path) {
                    return Ok(Some(tool));
                }
            }

            // Check matching exported binary
            if let Ok(entries) = fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Ok(tool) = InstalledTool::load_from_dir(&path) {
                            if tool.manifest.binaries.iter().any(|b| b.name == identifier_or_binary) {
                                return Ok(Some(tool));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Lists all installed tools
    pub fn list_tools() -> Result<Vec<InstalledTool>> {
        let mut tools = Vec::new();
        let mut search_dirs = Vec::new();

        if let Ok(home) = std::env::var("HOME") {
            search_dirs.push(PathBuf::from(home).join(USER_TOOLS_REL));
        }
        search_dirs.push(PathBuf::from(SYSTEM_TOOLS_DIR));

        for base in search_dirs {
            if !base.exists() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Ok(tool) = InstalledTool::load_from_dir(&path) {
                            tools.push(tool);
                        }
                    }
                }
            }
        }

        Ok(tools)
    }
}

/// Executes a Clipak tool with isolation, verification, and environment setup
pub struct ClipakDispatcher {
    pub allow_unverified: bool,
    pub trust_store: TrustStore,
}

impl ClipakDispatcher {
    pub fn new(allow_unverified: bool) -> Result<Self> {
        let trust_store = TrustStore::load_defaults()?;
        Ok(Self {
            allow_unverified,
            trust_store,
        })
    }

    /// Verifies the cryptographic block integrity and signatures of a tool's DDI
    pub fn verify_ddi(&self, ddi_path: &Path) -> Result<()> {
        let ddi = read_ddi_image(ddi_path)?;

        let root_part = ddi
            .find_root_partition()
            .ok_or_else(|| anyhow::anyhow!("Missing root partition in DDI"))?;
        let verity_part = ddi.find_verity_partition();
        let sig_part = ddi.find_verity_sig_partition();

        if verity_part.is_none() && self.trust_store.mode == EnforcementMode::Enforcing && !self.allow_unverified {
            bail!("Security violation: DDI has no dm-verity partition and security policy is ENFORCING");
        }

        // If verity and sig are present, verify
        if let (Some(vpart), Some(spart)) = (verity_part, sig_part) {
            let mut file = File::open(ddi_path)?;

            // Read verity superblock
            file.seek(SeekFrom::Start(vpart.byte_offset()))?;
            let mut sb_buf = [0u8; 512];
            file.read_exact(&mut sb_buf)?;

            if &sb_buf[0..8] == b"verity\0\0" {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&sb_buf[88..120]);

                // Read signature bytes
                file.seek(SeekFrom::Start(spart.byte_offset()))?;
                let mut sig_bytes = vec![0u8; spart.byte_size() as usize];
                file.read_exact(&mut sig_bytes)?;
                // Trim trailing zeros from signature partition
                let non_zero_len = sig_bytes.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
                sig_bytes.truncate(non_zero_len);

                // Read root partition payload to compute root hash
                file.seek(SeekFrom::Start(root_part.byte_offset()))?;
                let mut root_data = vec![0u8; root_part.byte_size() as usize];
                file.read_exact(&mut root_data)?;

                let verity_calc = clipak_core::verity::compute_verity_tree(&root_data, Some(salt))?;

                // Verify PKCS#7 signature over computed root hash
                let trusted_certs = self.trust_store.certificates();
                let sig_ok = verify_root_hash_signature(&verity_calc.root_hash, &sig_bytes, trusted_certs);
                if sig_ok.is_err() && self.trust_store.mode == EnforcementMode::Enforcing && !self.allow_unverified {
                    bail!("Cryptographic attestation failed: PKCS#7 signature could not be verified: {:?}", sig_ok.err());
                }
            }
        }

        Ok(())
    }

    /// Dispatches execution of a target tool binary
    pub fn dispatch(
        &self,
        tool: &InstalledTool,
        binary_name: &str,
        args: &[String],
    ) -> Result<i32> {
        // 1. Verify DDI
        self.verify_ddi(&tool.ddi_path)?;

        // 2. Prepare payload mount/extracted directory for /app
        let app_payload = prepare_ddi_payload(&tool.ddi_path, None)?;

        // 3. Locate /usr runtime (or fallback to host /usr)
        let runtime_path = PathBuf::from("/usr");

        // 4. Build Environment Variables
        let mut env: HashMap<String, String> = std::env::vars().collect();

        // PATH: /app/bin:/usr/bin:$PATH
        let host_path = env.get("PATH").cloned().unwrap_or_else(|| "/usr/bin:/bin".into());
        env.insert("PATH".into(), format!("/app/bin:/usr/bin:{}", host_path));

        // LD_LIBRARY_PATH: /app/lib64:/app/lib:/usr/lib64:/usr/lib
        let host_ld = env.get("LD_LIBRARY_PATH").cloned();
        let ld_path = match host_ld {
            Some(ld) => format!("/app/lib64:/app/lib:/usr/lib64:/usr/lib:{}", ld),
            None => "/app/lib64:/app/lib:/usr/lib64:/usr/lib".into(),
        };
        env.insert("LD_LIBRARY_PATH".into(), ld_path);

        // XDG_DATA_DIRS: /app/share:/usr/share
        let xdg_data = env.get("XDG_DATA_DIRS").cloned().unwrap_or_else(|| "/usr/local/share:/usr/share".into());
        env.insert("XDG_DATA_DIRS".into(), format!("/app/share:/usr/share:{}", xdg_data));

        // Inject tool specific env vars
        for (k, v) in &tool.manifest.environment {
            env.insert(k.clone(), v.clone());
        }

        env.insert("CLIPAK_ACTIVE".into(), "1".into());
        env.insert("CLIPAK_TOOL_ID".into(), tool.id.clone());
        env.insert("CLIPAK_TOOL_VERSION".into(), tool.manifest.version.clone());

        // Target binary within /app
        let target_binary = format!("/app/bin/{}", binary_name);
        let target_binary_path = Path::new(&target_binary);

        // Try execution with Bubblewrap backend first for unprivileged host integration
        let bwrap_available = std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if bwrap_available {
            return execute_with_bwrap(
                &runtime_path,
                &app_payload.mount_path,
                target_binary_path,
                args,
                &env,
            );
        }

        // Alternatively use native unshare mount namespace
        enter_native_mount_namespace(&runtime_path, &app_payload.mount_path)?;

        // Execute via standard command
        let mut cmd = std::process::Command::new(&target_binary);
        cmd.args(args);
        cmd.envs(env);
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(0))
    }
}
