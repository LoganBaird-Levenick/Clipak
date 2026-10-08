//! Remote repository management and package index handling.
//!
//! Handles fetching package indexes (`index.json`), searching remote packages,
//! and downloading signed DDI disk images and manifests over HTTP/HTTPS or local paths.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_OFFICIAL_REPO_NAME: &str = "clipak-official";
pub const DEFAULT_OFFICIAL_REPO_URL: &str = "https://raw.githubusercontent.com/LoganBaird-Levenick/Clipak-Repository/main/repository";

/// An entry in a Clipak software repository index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPackageEntry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub summary: String,
    pub license: String,
    pub ddi_filename: String,
    pub ddi_sha256: String,
    pub root_hash_hex: String,
    pub ddi_size_bytes: u64,
    pub exported_binaries: Vec<String>,
    #[serde(default)]
    pub manifest_filename: Option<String>,
    #[serde(default)]
    pub sbom_spdx_filename: Option<String>,
    #[serde(default)]
    pub sbom_cyclonedx_filename: Option<String>,
}

/// Software repository index metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndex {
    pub name: String,
    pub description: String,
    pub url: String,
    pub updated_at: String,
    pub packages: Vec<RepoPackageEntry>,
}

impl RepositoryIndex {
    pub fn new(name: &str, description: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            url: url.to_string(),
            updated_at: format!("{:?}", std::time::SystemTime::now()),
            packages: Vec::new(),
        }
    }
}

/// Remote repository configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRepo {
    pub name: String,
    pub url: String,
    pub enabled: bool,
}

/// Remote repositories manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub remotes: Vec<RemoteRepo>,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            remotes: vec![RemoteRepo {
                name: DEFAULT_OFFICIAL_REPO_NAME.to_string(),
                url: DEFAULT_OFFICIAL_REPO_URL.to_string(),
                enabled: true,
            }],
        }
    }
}

impl RemoteConfig {
    /// Loads configured remotes from ~/.config/clipak/remotes.json or default
    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(config) = serde_json::from_str::<RemoteConfig>(&content) {
                    return config;
                }
            }
        }
        Self::default()
    }

    /// Saves remotes configuration to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".config/clipak/remotes.json")
    }

    /// Adds or updates a remote
    pub fn add_or_update(&mut self, name: &str, url: &str) {
        if let Some(r) = self.remotes.iter_mut().find(|r| r.name == name) {
            r.url = url.trim_end_matches('/').to_string();
            r.enabled = true;
        } else {
            self.remotes.push(RemoteRepo {
                name: name.to_string(),
                url: url.trim_end_matches('/').to_string(),
                enabled: true,
            });
        }
    }

    /// Removes a remote by name
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.remotes.len();
        self.remotes.retain(|r| r.name != name);
        self.remotes.len() < len_before
    }

    /// Path to cached index directory for a remote
    pub fn cache_dir_for_remote(remote_name: &str) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home)
            .join(".local/share/clipak/remotes")
            .join(remote_name)
    }

    /// Fetches and updates index.json for all enabled remotes
    pub fn update_all() -> Result<Vec<(String, std::result::Result<usize, String>)>> {
        let config = Self::load();
        let mut results = Vec::new();

        for remote in &config.remotes {
            if !remote.enabled {
                continue;
            }

            let cache_dir = Self::cache_dir_for_remote(&remote.name);
            fs::create_dir_all(&cache_dir)?;
            let index_path = cache_dir.join("index.json");

            // Construct index URL (supports both HTTP/HTTPS and local file:// paths)
            let index_url = format!("{}/index.json", remote.url);

            let fetch_res: Result<()> = (|| {
                if remote.url.starts_with("file://") || Path::new(&remote.url).exists() {
                    let local_path = remote.url.strip_prefix("file://").unwrap_or(&remote.url);
                    let src_index = Path::new(local_path).join("index.json");
                    if src_index.exists() {
                        fs::copy(&src_index, &index_path)?;
                        Ok(())
                    } else {
                        bail!("Local repository index not found at {}", src_index.display());
                    }
                } else {
                    // Fetch via curl
                    let status = Command::new("curl")
                        .arg("-sSL")
                        .arg("-f")
                        .arg("--connect-timeout")
                        .arg("5")
                        .arg("-o")
                        .arg(&index_path)
                        .arg(&index_url)
                        .status();

                    match status {
                        Ok(st) if st.success() => Ok(()),
                        Ok(st) => bail!("HTTP fetch error (curl exited with code {:?})", st.code()),
                        Err(e) => bail!("Failed to invoke curl: {}", e),
                    }
                }
            })();

            match fetch_res {
                Ok(()) => {
                    let count = if let Ok(data) = fs::read_to_string(&index_path) {
                        if let Ok(idx) = serde_json::from_str::<RepositoryIndex>(&data) {
                            idx.packages.len()
                        } else {
                            0
                        }
                    } else {
                        0
                    };
                    results.push((remote.name.clone(), Ok(count)));
                }
                Err(err) => {
                    results.push((remote.name.clone(), Err(err.to_string())));
                }
            }
        }

        Ok(results)
    }

    /// Finds a package across all cached remote indices
    pub fn find_package(package_id: &str) -> Option<(RemoteRepo, RepoPackageEntry)> {
        let config = Self::load();
        for remote in &config.remotes {
            if !remote.enabled {
                continue;
            }
            let index_path = Self::cache_dir_for_remote(&remote.name).join("index.json");
            if let Ok(data) = fs::read_to_string(&index_path) {
                if let Ok(idx) = serde_json::from_str::<RepositoryIndex>(&data) {
                    if let Some(pkg) = idx.packages.into_iter().find(|p| p.id == package_id) {
                        return Some((remote.clone(), pkg));
                    }
                }
            }
        }
        None
    }

    /// Searches packages across all cached remote indices
    pub fn search(query: &str) -> Vec<(String, RepoPackageEntry)> {
        let config = Self::load();
        let mut matches = Vec::new();
        let query_lower = query.to_lowercase();

        for remote in &config.remotes {
            if !remote.enabled {
                continue;
            }
            let index_path = Self::cache_dir_for_remote(&remote.name).join("index.json");
            if let Ok(data) = fs::read_to_string(&index_path) {
                if let Ok(idx) = serde_json::from_str::<RepositoryIndex>(&data) {
                    for pkg in idx.packages {
                        if pkg.id.to_lowercase().contains(&query_lower)
                            || pkg.name.to_lowercase().contains(&query_lower)
                            || pkg.summary.to_lowercase().contains(&query_lower)
                            || pkg.exported_binaries.iter().any(|b| b.to_lowercase().contains(&query_lower))
                        {
                            matches.push((remote.name.clone(), pkg));
                        }
                    }
                }
            }
        }
        matches
    }

    /// Downloads a package DDI from a remote repository into a target directory
    pub fn download_package(
        remote: &RemoteRepo,
        pkg: &RepoPackageEntry,
        dest_dir: &Path,
    ) -> Result<(PathBuf, PathBuf)> {
        fs::create_dir_all(dest_dir)?;

        let ddi_dest = dest_dir.join(&pkg.ddi_filename);
        let manifest_filename = pkg.manifest_filename.clone().unwrap_or_else(|| "manifest.json".into());
        let manifest_dest = dest_dir.join(&manifest_filename);

        let ddi_url = format!("{}/{}", remote.url, pkg.ddi_filename);
        let manifest_url = format!("{}/{}", remote.url, manifest_filename);

        if remote.url.starts_with("file://") || Path::new(&remote.url).exists() {
            let local_base = remote.url.strip_prefix("file://").unwrap_or(&remote.url);
            let src_ddi = Path::new(local_base).join(&pkg.ddi_filename);
            let src_manifest = Path::new(local_base).join(&manifest_filename);

            fs::copy(&src_ddi, &ddi_dest).with_context(|| format!("Failed to copy DDI from {}", src_ddi.display()))?;
            fs::copy(&src_manifest, &manifest_dest).with_context(|| format!("Failed to copy manifest from {}", src_manifest.display()))?;
        } else {
            // Download DDI via curl
            let status = Command::new("curl")
                .arg("-sSL")
                .arg("-f")
                .arg("--progress-bar")
                .arg("-o")
                .arg(&ddi_dest)
                .arg(&ddi_url)
                .status()
                .with_context(|| format!("Failed to download DDI from {}", ddi_url))?;

            if !status.success() {
                bail!("Failed to download DDI image from {}", ddi_url);
            }

            // Download manifest via curl
            let m_status = Command::new("curl")
                .arg("-sSL")
                .arg("-f")
                .arg("-o")
                .arg(&manifest_dest)
                .arg(&manifest_url)
                .status()
                .with_context(|| format!("Failed to download manifest from {}", manifest_url))?;

            if !m_status.success() {
                bail!("Failed to download manifest from {}", manifest_url);
            }
        }

        Ok((ddi_dest, manifest_dest))
    }
}
