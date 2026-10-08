//! Shared library dependency analysis and encapsulation.
//!
//! Inspects built executables with `ldd` and copies any shared libraries that
//! are not part of the standard glibc runtime baseline into `/app/lib`. This
//! ensures packages run reliably across different host distribution versions.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

/// Standard baseline libraries guaranteed by base /usr runtime image
const RUNTIME_BASE_LIBS: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
    "ld-linux-aarch64.so.1",
];

/// Bundles shared library dependencies into /app/lib to enforce the Clipak bundling contract
pub struct DependencyBundler;

impl DependencyBundler {
    /// Inspects all binaries under app_dir/bin and app_dir/lib, copies non-baseline libraries to app_dir/lib
    pub fn bundle_dependencies(app_dir: &Path) -> Result<Vec<PathBuf>> {
        let bin_dir = app_dir.join("bin");
        let lib_dir = app_dir.join("lib");
        fs::create_dir_all(&lib_dir)?;

        if !bin_dir.exists() {
            return Ok(Vec::new());
        }

        let mut bundled = Vec::new();
        let mut processed_libs: HashSet<String> = HashSet::new();

        // Collect all executable files in bin/
        for entry in WalkDir::new(&bin_dir).into_iter().flatten() {
            let path = entry.path();
            if path.is_file() {
                let deps = Self::detect_dependencies(path)?;
                for (lib_name, lib_path) in deps {
                    if Self::should_bundle(&lib_name) && processed_libs.insert(lib_name.clone()) {
                        let target_path = lib_dir.join(&lib_name);
                        if !target_path.exists() && lib_path.exists() {
                            fs::copy(&lib_path, &target_path).with_context(|| {
                                format!("Failed to bundle library {} -> {}", lib_path.display(), target_path.display())
                            })?;
                            bundled.push(target_path);
                        }
                    }
                }
            }
        }

        Ok(bundled)
    }

    /// Determines if a library must be bundled inside /app/lib
    fn should_bundle(lib_name: &str) -> bool {
        for base in RUNTIME_BASE_LIBS {
            if lib_name.starts_with(base) {
                return false;
            }
        }
        true
    }

    /// Runs ldd on a binary to discover shared library dependencies and their resolved paths
    fn detect_dependencies(binary: &Path) -> Result<Vec<(String, PathBuf)>> {
        let output = Command::new("ldd").arg(binary).output();
        let mut results = Vec::new();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                // Format: libfoo.so.1 => /usr/lib64/libfoo.so.1 (0x...)
                if let Some(pos) = trimmed.find("=>") {
                    let lib_name = trimmed[..pos].trim().to_string();
                    let right = trimmed[pos + 2..].trim();
                    if let Some(path_end) = right.find(' ') {
                        let resolved_path = PathBuf::from(&right[..path_end]);
                        if resolved_path.is_absolute() {
                            results.push((lib_name, resolved_path));
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}
