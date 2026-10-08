//! Core data types, disk structures, and verification primitives for Clipak.
//!
//! Clipak packages low-level developer tools (like debuggers, profilers, and
//! system utilities) as systemd UAPI Discoverable Disk Images (DDIs) with
//! cryptographic integrity guarantees.
//!
//! This crate contains the format definitions and low-level engines:
//! - [`gpt`]: UAPI-compliant GPT disk image builder and parser.
//! - [`verity`]: dm-verity Merkle tree generation and superblock calculation.
//! - [`crypto`]: PKCS#7 digital signature generation and certificate validation.
//! - [`cas`]: Content-Addressable Storage for reproducible builds and caching.
//! - [`manifest`]: Tool package manifest definition (`clipak.yaml` / `manifest.json`).
//! - [`policy`]: Flatpak exclusion curation rules and enforcement trust store.
//! - [`repo`]: Remote repository indexes and package catalogs.
//! - [`sbom`]: SPDX 2.3 and CycloneDX 1.5 supply chain metadata generation.

pub mod cas;
pub mod constants;
pub mod crypto;
pub mod gpt;
pub mod manifest;
pub mod policy;
pub mod repo;
pub mod sbom;
pub mod verity;

pub use constants::*;
pub use gpt::{DdiImage, GptPartition};
pub use manifest::ToolManifest;

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_gpt_build_and_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let image_path = temp_dir.path().join("test.ddi");
        let disk_guid = Uuid::new_v4();

        let part1 = GptPartition {
            type_guid: constants::uapi_root_x86_64(),
            unique_guid: Uuid::new_v4(),
            first_lba: 0,
            last_lba: 0,
            flags: 0,
            name: "root-x86-64".into(),
        };
        let payload_data = vec![0xABu8; 8192];

        let built = gpt::build_ddi_disk_image(&image_path, disk_guid, &[(part1.clone(), payload_data)]).unwrap();
        assert_eq!(built.disk_guid, disk_guid);
        assert_eq!(built.partitions.len(), 1);

        let read = gpt::read_ddi_image(&image_path).unwrap();
        assert_eq!(read.disk_guid, disk_guid);
        assert_eq!(read.partitions.len(), 1);
        assert_eq!(read.partitions[0].name, "root-x86-64");
        assert_eq!(read.partitions[0].type_guid, constants::uapi_root_x86_64());
        assert!(read.find_root_partition().is_some());
    }

    #[test]
    fn test_dm_verity_compute_and_verify() {
        let test_data = vec![0x42u8; 16384]; // 4 data blocks
        let result = verity::compute_verity_tree(&test_data, None).unwrap();
        assert_eq!(result.data_blocks, 4);
        assert!(!result.root_hash_hex.is_empty());

        let valid = verity::verify_data_against_root(&test_data, &result.salt, &result.root_hash_hex).unwrap();
        assert!(valid);

        // Corrupted data should fail verification
        let mut bad_data = test_data.clone();
        bad_data[100] ^= 0xFF;
        let invalid = verity::verify_data_against_root(&bad_data, &result.salt, &result.root_hash_hex).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_pkcs7_signing_and_verification() {
        let id = crypto::SigningIdentity::generate("Clipak Test Authority", 30).unwrap();
        let root_hash = [0x55u8; 32];
        let sig = crypto::sign_root_hash(&root_hash, &id).unwrap();
        assert!(!sig.is_empty());

        let trusted = vec![id.cert.clone()];
        let ok = crypto::verify_root_hash_signature(&root_hash, &sig, &trusted).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_cas_put_get() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cas = cas::CasStore::new(temp_dir.path()).unwrap();

        let data = b"Hello, Clipak Reproducible CAS!";
        let hash = cas.put_bytes(data).unwrap();
        assert!(cas.has_object(&hash));

        let retrieved = cas.get_bytes(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_curation_policy_validation() {
        let mut manifest = manifest::ToolManifest {
            id: "org.kernel.bpftrace".into(),
            name: "bpftrace".into(),
            version: "0.21.0".into(),
            summary: "High-level tracing language for Linux eBPF".into(),
            description: "Linux tracing tool".into(),
            license: "Apache-2.0".into(),
            category: "Diagnostics".into(),
            runtime: "org.clipak.Runtime//1.0".into(),
            binaries: vec![manifest::ExportedBinary {
                name: "bpftrace".into(),
                target: None,
                summary: Some("eBPF tracer".into()),
            }],
            environment: Default::default(),
            curation: manifest::CurationPolicy {
                unconfined_reason: "Requires bpf system call, kprobes, tracepoints".into(),
                required_host_capabilities: vec!["bpf".into(), "perf".into()],
                flatpak_incompatible: true,
            },
            build: None,
        };

        assert!(policy::CurationValidator::validate_curation(&manifest).is_ok());

        // Flatpak compatible should fail gatekeeper
        manifest.curation.flatpak_incompatible = false;
        assert!(policy::CurationValidator::validate_curation(&manifest).is_err());
    }
}
