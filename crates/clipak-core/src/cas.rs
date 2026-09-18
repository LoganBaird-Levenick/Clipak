use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Content-Addressable Storage (CAS) engine for build reproducibility and artifact caching
#[derive(Debug, Clone)]
pub struct CasStore {
    base_dir: PathBuf,
}

impl CasStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let path = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        fs::create_dir_all(path.join("objects"))?;
        fs::create_dir_all(path.join("tmp"))?;
        Ok(Self { base_dir: path })
    }

    /// Default CAS location for user or system
    pub fn default_store() -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let cas_path = PathBuf::from(home).join(".cache/clipak/cas");
        Self::new(cas_path)
    }

    /// Stores raw byte slice into CAS, returning its SHA-256 hex digest
    pub fn put_bytes(&self, data: &[u8]) -> Result<String> {
        let hash = format!("{:x}", Sha256::digest(data));
        let obj_path = self.object_path(&hash);

        if !obj_path.exists() {
            let tmp_path = self.base_dir.join("tmp").join(format!("tmp-{}", uuid::Uuid::new_v4()));
            let mut file = File::create(&tmp_path)?;
            file.write_all(data)?;
            file.flush()?;

            if let Some(parent) = obj_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(tmp_path, &obj_path)?;
        }

        Ok(hash)
    }

    /// Stores a file into CAS by streaming
    pub fn put_file<P: AsRef<Path>>(&self, src: P) -> Result<String> {
        let mut file = File::open(src)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 65536];

        let tmp_path = self.base_dir.join("tmp").join(format!("tmp-{}", uuid::Uuid::new_v4()));
        let mut tmp_file = File::create(&tmp_path)?;

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            tmp_file.write_all(&buffer[..n])?;
        }
        tmp_file.flush()?;

        let hash = format!("{:x}", hasher.finalize());
        let obj_path = self.object_path(&hash);

        if obj_path.exists() {
            let _ = fs::remove_file(tmp_path);
        } else {
            if let Some(parent) = obj_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(tmp_path, &obj_path)?;
        }

        Ok(hash)
    }

    /// Checks if a hash exists in CAS
    pub fn has_object(&self, hash: &str) -> bool {
        self.object_path(hash).exists()
    }

    /// Retrieves an object as bytes
    pub fn get_bytes(&self, hash: &str) -> Result<Vec<u8>> {
        let obj_path = self.object_path(hash);
        if !obj_path.exists() {
            bail!("CAS object not found: {}", hash);
        }
        let data = fs::read(&obj_path)?;
        // Verify checksum
        let actual_hash = format!("{:x}", Sha256::digest(&data));
        if actual_hash != hash {
            bail!("CAS corruption detected for object {}: computed {}", hash, actual_hash);
        }
        Ok(data)
    }

    /// Path to the object file on disk
    pub fn object_path(&self, hash: &str) -> PathBuf {
        let (prefix, rest) = if hash.len() >= 2 {
            (&hash[0..2], &hash[2..])
        } else {
            ("00", hash)
        };
        self.base_dir.join("objects").join(prefix).join(rest)
    }
}
