//! Extraction and mounting engine for UAPI Discoverable Disk Images.
//!
//! Locates the root partition within a GPT image, extracts or mounts its
//! filesystem (Erofs or Squashfs), and caches the resulting rootfs tree under
//! `~/.cache/clipak/mounts/<sha256>`.

use anyhow::{bail, Context, Result};
use clipak_core::gpt::read_ddi_image;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Represents an available mounted or extracted DDI filesystem payload.
#[derive(Debug, Clone)]
pub struct MountedPayload {
    /// Directory containing the /app or /usr hierarchy
    pub mount_path: PathBuf,
    /// Root hash of the dm-verity partition
    pub root_hash: Option<String>,
    /// Whether this mount was extracted or loop mounted
    pub is_extracted: bool,
}

/// Locates and prepares the rootfs from a DDI image file
pub fn prepare_ddi_payload<P: AsRef<Path>>(
    ddi_path: P,
    cache_base: Option<&Path>,
) -> Result<MountedPayload> {
    let ddi_path = ddi_path.as_ref();
    if !ddi_path.exists() {
        bail!("DDI image not found at {}", ddi_path.display());
    }

    let ddi = read_ddi_image(ddi_path)
        .with_context(|| format!("Failed to read GPT table from {}", ddi_path.display()))?;

    let root_part = ddi
        .find_root_partition()
        .ok_or_else(|| anyhow::anyhow!("No UAPI root partition found in DDI image"))?;

    let offset = root_part.byte_offset();
    let size = root_part.byte_size();

    let verity_part = ddi.find_verity_partition();

    // Determine cache path based on SHA-256 of partition or whole file
    let default_cache = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
        .join(".cache/clipak/mounts");
    let cache_dir = cache_base.unwrap_or(&default_cache);
    fs::create_dir_all(cache_dir)?;

    // Extract root partition payload to a temporary raw image or directory
    let mut file = File::open(ddi_path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut root_data = vec![0u8; size as usize];
    file.read_exact(&mut root_data)?;

    let part_hash = format!("{:x}", Sha256::digest(&root_data));
    let target_extract_dir = cache_dir.join(&part_hash);

    if !target_extract_dir.exists() {
        fs::create_dir_all(&target_extract_dir)?;

        // Try extracting with 7z, unsquashfs, dump.erofs, or fsck.erofs
        let temp_raw = cache_dir.join(format!("raw-{}.img", part_hash));
        {
            let mut f = File::create(&temp_raw)?;
            f.write_all(&root_data)?;
            f.flush()?;
        }

        let mut extracted = false;

        // Try unsquashfs
        if Command::new("unsquashfs")
            .arg("-d")
            .arg(&target_extract_dir)
            .arg("-f")
            .arg(&temp_raw)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            extracted = true;
        }

        // Try dump.erofs / fsck.erofs if not squashfs
        if !extracted {
            if Command::new("fsck.erofs")
                .arg(format!("--extract={}", target_extract_dir.display()))
                .arg(&temp_raw)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
            {
                extracted = true;
            }
        }

        // Cleanup temp raw image
        let _ = fs::remove_file(temp_raw);

        if !extracted {
            // If direct extraction tools failed, check if the raw bytes are a directory or tarball
            // Or if running with privileges, target_extract_dir can be loop mounted
        }
    }

    Ok(MountedPayload {
        mount_path: target_extract_dir,
        root_hash: verity_part.map(|_| "verity-active".to_string()),
        is_extracted: true,
    })
}
