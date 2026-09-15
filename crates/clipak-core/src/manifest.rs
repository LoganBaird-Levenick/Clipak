use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata declaring unconfined justification for repository curation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurationPolicy {
    /// Why this tool cannot function inside a standard Flatpak sandbox
    pub unconfined_reason: String,
    /// Host access requirements (e.g., "ptrace", "perf", "bpf", "raw-devices", "kernel-modules")
    pub required_host_capabilities: Vec<String>,
    /// Confirms that Flatpak exclusion criteria have been satisfied
    pub flatpak_incompatible: bool,
}

impl Default for CurationPolicy {
    fn default() -> Self {
        Self {
            unconfined_reason: "Developer diagnostic or low-level tool requiring host inspection".into(),
            required_host_capabilities: vec!["host-processes".into(), "host-filesystem".into()],
            flatpak_incompatible: true,
        }
    }
}

/// Description of an exported executable binary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportedBinary {
    /// The binary name in /app/bin (e.g., "gdb")
    pub name: String,
    /// Optional custom target path if different from /app/bin/<name>
    #[serde(default)]
    pub target: Option<String>,
    /// Optional description of this binary
    #[serde(default)]
    pub summary: Option<String>,
}

/// Source specification for building a toolpak image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum SourceSpec {
    #[serde(rename = "archive")]
    Archive {
        url: String,
        sha256: String,
        strip_components: Option<usize>,
    },
    #[serde(rename = "git")]
    Git {
        url: String,
        commit: String,
        tag: Option<String>,
    },
    #[serde(rename = "local")]
    Local {
        path: String,
    },
}

/// A discrete build command or step in the build harness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildStep {
    pub name: String,
    pub command: String,
}

/// Build pipeline definition for deterministic packaging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BuildSpec {
    #[serde(default)]
    pub sources: Vec<SourceSpec>,
    #[serde(default)]
    pub steps: Vec<BuildStep>,
    /// Prefix to configure (default /app)
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Additional library patterns or paths to bundle into /app/lib
    #[serde(default)]
    pub bundle_libraries: Vec<String>,
    /// Environment variables during build
    #[serde(default)]
    pub build_env: HashMap<String, String>,
}

fn default_prefix() -> String {
    "/app".to_string()
}

/// The complete manifest specification for a Clipak tool package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolManifest {
    /// Reverse-DNS package identifier (e.g. "org.gnu.gdb", "io.github.htop")
    pub id: String,
    /// Human readable name
    pub name: String,
    /// Semantic version
    pub version: String,
    /// Short summary
    pub summary: String,
    /// Detailed description
    #[serde(default)]
    pub description: String,
    /// SPDX license expression
    pub license: String,
    /// Category (e.g. "Development", "Diagnostics", "Profiling", "Compiler")
    #[serde(default = "default_category")]
    pub category: String,
    /// Required base runtime DDI (e.g. "org.clipak.Runtime//1.0")
    #[serde(default = "default_runtime")]
    pub runtime: String,
    /// List of binaries exported to the host's PATH shims
    pub binaries: Vec<ExportedBinary>,
    /// Optional environment variables injected into the private mount namespace
    #[serde(default)]
    pub environment: HashMap<String, String>,
    /// Curation rationale for distribution acceptance
    #[serde(default)]
    pub curation: CurationPolicy,
    /// Build instructions (optional when distributing prebuilt DDIs)
    #[serde(default)]
    pub build: Option<BuildSpec>,
}

fn default_category() -> String {
    "Development".to_string()
}

fn default_runtime() -> String {
    format!("{}//{}", crate::constants::DEFAULT_RUNTIME_ID, crate::constants::DEFAULT_RUNTIME_VERSION)
}

impl ToolManifest {
    pub fn from_json_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_yaml_str(s: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(s)
    }

    pub fn to_yaml_string(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}
