//! Software Bill of Materials (SBOM) generation in SPDX 2.3 and CycloneDX 1.5 formats.
//!
//! Generates machine-readable dependency inventories for built Clipak packages,
//! detailing bundled shared libraries, licenses, and component hashes.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// SPDX 2.3 Package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub version_info: String,
    pub download_location: String,
    pub files_analyzed: bool,
    pub license_concluded: String,
    pub license_declared: String,
    pub copyright_text: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// SPDX 2.3 Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    pub spdx_version: String,
    #[serde(rename = "dataLicense")]
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub packages: Vec<SpdxPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxCreationInfo {
    pub created: String,
    pub creators: Vec<String>,
}

/// CycloneDX 1.5 Component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub licenses: Vec<CycloneDxLicenseWrapper>,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicenseWrapper {
    pub license: CycloneDxLicense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxLicense {
    pub id: String,
}

/// CycloneDX 1.5 BOM Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneDxTool>,
    pub component: CycloneDxComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

fn iso_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}-01-01T00:00:00Z", 1970 + (now / 31536000))
}

pub fn generate_spdx_sbom(
    package_name: &str,
    version: &str,
    license: &str,
    description: &str,
    sub_components: &[(String, String, String)], // (name, version, license)
) -> SpdxDocument {
    let mut packages = Vec::new();

    // Main package
    packages.push(SpdxPackage {
        spdx_id: format!("SPDXRef-Package-{}", package_name),
        name: package_name.to_string(),
        version_info: version.to_string(),
        download_location: "NOASSERTION".to_string(),
        files_analyzed: false,
        license_concluded: license.to_string(),
        license_declared: license.to_string(),
        copyright_text: "NOASSERTION".to_string(),
        description: Some(description.to_string()),
    });

    for (sub_name, sub_ver, sub_lic) in sub_components {
        packages.push(SpdxPackage {
            spdx_id: format!("SPDXRef-Component-{}", sub_name),
            name: sub_name.clone(),
            version_info: sub_ver.clone(),
            download_location: "NOASSERTION".to_string(),
            files_analyzed: false,
            license_concluded: sub_lic.clone(),
            license_declared: sub_lic.clone(),
            copyright_text: "NOASSERTION".to_string(),
            description: None,
        });
    }

    SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: format!("{}-{}", package_name, version),
        document_namespace: format!("https://clipak.org/spdx/{}/{}", package_name, version),
        creation_info: SpdxCreationInfo {
            created: iso_timestamp(),
            creators: vec!["Tool: Clipak-0.1.0".to_string(), "Organization: Clipak".to_string()],
        },
        packages,
    }
}

pub fn generate_cyclonedx_sbom(
    package_name: &str,
    version: &str,
    license: &str,
    description: &str,
    sub_components: &[(String, String, String)],
) -> CycloneDxBom {
    let main_comp = CycloneDxComponent {
        component_type: "application".to_string(),
        name: package_name.to_string(),
        version: version.to_string(),
        description: Some(description.to_string()),
        licenses: vec![CycloneDxLicenseWrapper {
            license: CycloneDxLicense {
                id: license.to_string(),
            },
        }],
        purl: Some(format!("pkg:generic/{}@{}", package_name, version)),
    };

    let mut components = Vec::new();
    for (sub_name, sub_ver, sub_lic) in sub_components {
        components.push(CycloneDxComponent {
            component_type: "library".to_string(),
            name: sub_name.clone(),
            version: sub_ver.clone(),
            description: None,
            licenses: vec![CycloneDxLicenseWrapper {
                license: CycloneDxLicense {
                    id: sub_lic.clone(),
                },
            }],
            purl: Some(format!("pkg:generic/{}@{}", sub_name, sub_ver)),
        });
    }

    CycloneDxBom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: iso_timestamp(),
            tools: vec![CycloneDxTool {
                vendor: "Clipak".to_string(),
                name: "clipak-builder".to_string(),
                version: "0.1.0".to_string(),
            }],
            component: main_comp,
        },
        components,
    }
}
