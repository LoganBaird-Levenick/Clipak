use anyhow::{bail, Context, Result};
use clipak_core::constants::*;
use clipak_core::crypto::{sign_root_hash, SigningIdentity};
use clipak_core::gpt::{build_ddi_disk_image, DdiImage, GptPartition};
use clipak_core::verity::compute_verity_tree;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

pub enum ReadOnlyFs {
    Erofs,
    Squashfs,
}

/// Packages an application tree into a compliant UAPI.3 Discoverable Disk Image
pub struct DdiPackager;

impl DdiPackager {
    /// Builds a filesystem image from a directory
    pub fn build_fs_image(
        source_dir: &Path,
        output_fs: &Path,
        fs_type: ReadOnlyFs,
    ) -> Result<()> {
        match fs_type {
            ReadOnlyFs::Erofs => {
                // Try mkfs.erofs
                let mut cmd = Command::new("mkfs.erofs");
                cmd.arg("-z").arg("lz4hc");
                cmd.arg(output_fs);
                cmd.arg(source_dir);

                let status = cmd.status().context("Failed to execute mkfs.erofs")?;
                if !status.success() {
                    bail!("mkfs.erofs failed with status {}", status);
                }
            }
            ReadOnlyFs::Squashfs => {
                // Try mksquashfs
                let mut cmd = Command::new("mksquashfs");
                cmd.arg(source_dir);
                cmd.arg(output_fs);
                cmd.arg("-comp").arg("zstd");
                cmd.arg("-noappend");

                let status = cmd.status().context("Failed to execute mksquashfs")?;
                if !status.success() {
                    bail!("mksquashfs failed with status {}", status);
                }
            }
        }

        Ok(())
    }

    /// Complete pipeline to build a signed UAPI.3 DDI image
    pub fn create_ddi(
        app_source_dir: &Path,
        output_ddi_path: &Path,
        signing_identity: Option<&SigningIdentity>,
    ) -> Result<DdiImage> {
        let temp_dir = tempfile::tempdir()?;
        let temp_fs_img = temp_dir.path().join("payload.img");

        // Prefer erofs, fallback to squashfs
        let has_erofs = Command::new("mkfs.erofs").arg("-V").output().is_ok();
        if has_erofs {
            Self::build_fs_image(app_source_dir, &temp_fs_img, ReadOnlyFs::Erofs)?;
        } else {
            Self::build_fs_image(app_source_dir, &temp_fs_img, ReadOnlyFs::Squashfs)?;
        }

        // Read payload bytes
        let mut payload_bytes = Vec::new();
        File::open(&temp_fs_img)?.read_to_end(&mut payload_bytes)?;

        // Calculate dm-verity tree
        let verity_res = compute_verity_tree(&payload_bytes, None)?;

        // Prepare partitions list
        let mut partitions_data = Vec::new();

        // 1. Root Partition
        let root_part_meta = GptPartition {
            type_guid: uapi_root_x86_64(),
            unique_guid: Uuid::new_v4(),
            first_lba: 0,
            last_lba: 0,
            flags: 0,
            name: "root-x86-64".into(),
        };
        partitions_data.push((root_part_meta, payload_bytes));

        // 2. Verity Hash Partition
        let verity_part_meta = GptPartition {
            type_guid: uapi_verity_x86_64(),
            unique_guid: Uuid::new_v4(),
            first_lba: 0,
            last_lba: 0,
            flags: 0,
            name: "root-verity-x86-64".into(),
        };
        partitions_data.push((verity_part_meta, verity_res.hash_device_bytes));

        // 3. Verity PKCS#7 Signature Partition
        let sig_bytes = if let Some(identity) = signing_identity {
            sign_root_hash(&verity_res.root_hash, identity)?
        } else {
            // Generate ephemeral identity if none provided
            let ephemeral_id = SigningIdentity::generate("Clipak Developer Authority", 365)?;
            sign_root_hash(&verity_res.root_hash, &ephemeral_id)?
        };

        let sig_part_meta = GptPartition {
            type_guid: uapi_verity_sig_x86_64(),
            unique_guid: Uuid::new_v4(),
            first_lba: 0,
            last_lba: 0,
            flags: 0,
            name: "root-verity-sig-x86-64".into(),
        };
        partitions_data.push((sig_part_meta, sig_bytes));

        // Build GPT DDI disk image
        let disk_guid = Uuid::new_v4();
        let ddi = build_ddi_disk_image(output_ddi_path, disk_guid, &partitions_data)?;

        Ok(ddi)
    }
}
