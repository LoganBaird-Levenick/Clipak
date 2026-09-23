use serde::{Deserialize, Serialize};

/// An entry in a Clipak software repository index
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
