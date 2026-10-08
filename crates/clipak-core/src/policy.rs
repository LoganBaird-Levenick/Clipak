//! Security policy validation, certificate trust stores, and Flatpak exclusion gatekeeping.
//!
//! Clipak enforces a strict curation rule: software that can run inside standard
//! Flatpak sandboxes belongs in Flatpak. Clipak only accepts tools requiring
//! unconfined host access (e.g. ptrace, raw kernel interfaces, eBPF, perf).

use anyhow::{bail, Result};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::manifest::ToolManifest;

/// Security enforcement modes for verifying disk images at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// Strictly requires valid dm-verity and trusted cryptographic signatures.
    #[default]
    Enforcing,
    /// Verifies signatures and logs warnings, but permits execution.
    Permissive,
    /// Logs all execution attempts and cryptographic status for compliance auditing.
    Audit,
}

/// System-wide and user trust store managing trusted certificates
pub struct TrustStore {
    trusted_certificates: Vec<X509>,
    pub mode: EnforcementMode,
}

impl TrustStore {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            trusted_certificates: Vec::new(),
            mode,
        }
    }

    /// Loads trusted certificates from standard system (/etc/clipak/keys) and user (~/.config/clipak/keys) paths
    pub fn load_defaults() -> Result<Self> {
        let mut store = Self::new(EnforcementMode::Enforcing);

        // Check system keys directory
        let sys_keys = Path::new(crate::constants::SYSTEM_CONFIG_DIR).join("keys");
        if sys_keys.exists() {
            store.load_from_dir(&sys_keys)?;
        }

        // Check user keys directory
        if let Ok(home) = std::env::var("HOME") {
            let user_keys = PathBuf::from(home)
                .join(crate::constants::USER_CONFIG_REL)
                .join("keys");
            if user_keys.exists() {
                store.load_from_dir(&user_keys)?;
            }
        }

        Ok(store)
    }

    pub fn load_from_dir<P: AsRef<Path>>(&mut self, dir: P) -> Result<()> {
        if !dir.as_ref().exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "crt" || ext == "pem" || ext == "cer" {
                        if let Ok(data) = fs::read(&path) {
                            if let Ok(cert) = X509::from_pem(&data) {
                                self.trusted_certificates.push(cert);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn add_cert(&mut self, cert: X509) {
        self.trusted_certificates.push(cert);
    }

    pub fn certificates(&self) -> &[X509] {
        &self.trusted_certificates
    }
}

/// Policy validator enforcing the Flatpak Exclusion Policy and host-access rules
pub struct CurationValidator;

impl CurationValidator {
    /// Validates that a tool package satisfies Clipak curation gatekeeping rules
    pub fn validate_curation(manifest: &ToolManifest) -> Result<()> {
        let curation = &manifest.curation;

        if !curation.flatpak_incompatible {
            bail!(
                "Rejection by Clipak Repository Curation Gatekeeper: \
                '{}' does not claim Flatpak incompatibility. \
                Software capable of functioning inside a standard Flatpak sandbox \
                MUST be packaged as a Flatpak rather than Clipak.",
                manifest.id
            );
        }

        if curation.unconfined_reason.trim().is_empty() {
            bail!(
                "Rejection by Clipak Repository Curation Gatekeeper: \
                Package '{}' must provide a detailed 'unconfined_reason' justifying \
                why unconfined host access is required.",
                manifest.id
            );
        }

        if curation.required_host_capabilities.is_empty() {
            bail!(
                "Rejection by Clipak Repository Curation Gatekeeper: \
                Package '{}' must declare specific required host capabilities \
                (e.g., ptrace, bpf, perf, host-processes, raw-devices).",
                manifest.id
            );
        }

        // Validate that exported binaries exist
        if manifest.binaries.is_empty() {
            bail!(
                "Rejection: Package '{}' exports no binaries.",
                manifest.id
            );
        }

        Ok(())
    }
}
