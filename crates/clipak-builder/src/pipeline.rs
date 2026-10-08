//! End-to-end package build pipeline and validation driver.
//!
//! Coordinates manifest validation, step execution, dependency bundling,
//! SBOM generation (SPDX and CycloneDX), CAS caching, and DDI packaging.

use anyhow::{bail, Context, Result};
use clipak_core::cas::CasStore;
use clipak_core::crypto::SigningIdentity;
use clipak_core::manifest::ToolManifest;
use clipak_core::policy::CurationValidator;
use clipak_core::sbom::{generate_cyclonedx_sbom, generate_spdx_sbom};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundler::DependencyBundler;
use crate::ddi_packager::DdiPackager;

/// Artifact outputs from a successful package build.
#[derive(Debug)]
pub struct BuildResult {
    pub ddi_path: PathBuf,
    pub spdx_sbom_path: PathBuf,
    pub cyclonedx_sbom_path: PathBuf,
    pub manifest_path: PathBuf,
    pub ddi_hash: String,
}

/// The deterministic Clipak build pipeline
pub struct BuildPipeline {
    pub cas: CasStore,
}

impl BuildPipeline {
    pub fn new() -> Result<Self> {
        let cas = CasStore::default_store()?;
        Ok(Self { cas })
    }

    /// Builds a tool package from a manifest file or object
    pub fn build(
        &self,
        manifest: &ToolManifest,
        output_dir: &Path,
        signing_identity: Option<&SigningIdentity>,
    ) -> Result<BuildResult> {
        // 1. Curation Gatekeeper validation
        CurationValidator::validate_curation(manifest)
            .context("Build failed curation validation")?;

        fs::create_dir_all(output_dir)?;

        let temp_dir = tempfile::tempdir()?;
        let app_dir = temp_dir.path().join("app");
        fs::create_dir_all(app_dir.join("bin"))?;
        fs::create_dir_all(app_dir.join("lib"))?;
        fs::create_dir_all(app_dir.join("share"))?;

        // 2. Execute build steps if present
        if let Some(build_spec) = &manifest.build {
            for step in &build_spec.steps {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(&step.command);
                cmd.env("PREFIX", "/app");
                cmd.env("DESTDIR", &app_dir);
                for (k, v) in &build_spec.build_env {
                    cmd.env(k, v);
                }

                let status = cmd.status().with_context(|| format!("Failed to run build step: {}", step.name))?;
                if !status.success() {
                    bail!("Build step '{}' failed with status: {}", step.name, status);
                }
            }
        }

        // 3. Enforce Dependency Encapsulation & Bundling
        let bundled_libs = DependencyBundler::bundle_dependencies(&app_dir)?;
        let mut sub_components = Vec::new();
        for lib in bundled_libs {
            if let Some(file_name) = lib.file_name() {
                sub_components.push((
                    file_name.to_string_lossy().to_string(),
                    "bundled".to_string(),
                    manifest.license.clone(),
                ));
            }
        }

        // 4. Generate Machine-Readable SBOMs (SPDX 2.3 and CycloneDX 1.5)
        let spdx = generate_spdx_sbom(
            &manifest.name,
            &manifest.version,
            &manifest.license,
            &manifest.description,
            &sub_components,
        );
        let spdx_path = output_dir.join(format!("{}.spdx.json", manifest.id));
        fs::write(&spdx_path, serde_json::to_string_pretty(&spdx)?)?;

        let cyclonedx = generate_cyclonedx_sbom(
            &manifest.name,
            &manifest.version,
            &manifest.license,
            &manifest.description,
            &sub_components,
        );
        let cyclonedx_path = output_dir.join(format!("{}.cyclonedx.json", manifest.id));
        fs::write(&cyclonedx_path, serde_json::to_string_pretty(&cyclonedx)?)?;

        // 5. Package into compliant UAPI.3 DDI
        let ddi_filename = format!("{}-{}.ddi", manifest.id, manifest.version);
        let ddi_path = output_dir.join(&ddi_filename);
        DdiPackager::create_ddi(&app_dir, &ddi_path, signing_identity)?;

        // 6. Record into CAS cache
        let ddi_hash = self.cas.put_file(&ddi_path)?;

        // 7. Save finalized manifest in output directory
        let manifest_path = output_dir.join("manifest.json");
        fs::write(&manifest_path, manifest.to_json_pretty()?)?;

        Ok(BuildResult {
            ddi_path,
            spdx_sbom_path: spdx_path,
            cyclonedx_sbom_path: cyclonedx_path,
            manifest_path,
            ddi_hash,
        })
    }
}
