use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const VERITY_SIGNATURE: &[u8; 8] = b"verity\0\0";
pub const VERITY_VERSION: u32 = 1;
pub const VERITY_HASH_TYPE_NORMAL: u32 = 1;
pub const VERITY_BLOCK_SIZE: usize = 4096;
pub const VERITY_DIGEST_SIZE: usize = 32; // SHA-256
pub const HASHES_PER_BLOCK: usize = VERITY_BLOCK_SIZE / VERITY_DIGEST_SIZE; // 128

/// dm-verity computed metadata
#[derive(Debug, Clone)]
pub struct VerityResult {
    /// Root hash as hex string
    pub root_hash_hex: String,
    /// Root hash binary digest (32 bytes)
    pub root_hash: [u8; 32],
    /// Salt (32 bytes)
    pub salt: [u8; 32],
    pub salt_hex: String,
    /// Number of 4096-byte data blocks
    pub data_blocks: u64,
    /// The complete serialized dm-verity hash device payload (header + tree)
    pub hash_device_bytes: Vec<u8>,
}

/// Compute SHA-256 with salt: sha256(salt || data)
fn hash_block(salt: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes dm-verity Merkle tree and generates hash device payload
pub fn compute_verity_tree(data: &[u8], custom_salt: Option<[u8; 32]>) -> Result<VerityResult> {
    if data.is_empty() {
        bail!("Cannot compute dm-verity tree on empty data");
    }

    let salt = custom_salt.unwrap_or_else(|| {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(13);
        }
        s
    });

    let num_data_blocks = ((data.len() + VERITY_BLOCK_SIZE - 1) / VERITY_BLOCK_SIZE) as u64;

    // Pad data to multiple of 4KB
    let mut padded_data = data.to_vec();
    let expected_len = (num_data_blocks as usize) * VERITY_BLOCK_SIZE;
    if padded_data.len() < expected_len {
        padded_data.resize(expected_len, 0);
    }

    // 1. Compute Level 0: Hashes of data blocks
    let mut current_level_hashes: Vec<[u8; 32]> = Vec::with_capacity(num_data_blocks as usize);
    for chunk in padded_data.chunks_exact(VERITY_BLOCK_SIZE) {
        current_level_hashes.push(hash_block(&salt, chunk));
    }

    let mut tree_levels: Vec<Vec<u8>> = Vec::new();

    // Loop through levels until we reach a single root hash
    while current_level_hashes.len() > 1 {
        // Pack current level hashes into 4KB hash blocks
        let mut level_blocks_bytes: Vec<u8> = Vec::new();
        let mut next_level_hashes: Vec<[u8; 32]> = Vec::new();

        for chunk_of_hashes in current_level_hashes.chunks(HASHES_PER_BLOCK) {
            let mut block_buf = vec![0u8; VERITY_BLOCK_SIZE];
            for (idx, hash) in chunk_of_hashes.iter().enumerate() {
                let start = idx * VERITY_DIGEST_SIZE;
                block_buf[start..start + VERITY_DIGEST_SIZE].copy_from_slice(hash);
            }

            // The hash of this 4KB hash block becomes the entry in the next level
            next_level_hashes.push(hash_block(&salt, &block_buf));
            level_blocks_bytes.extend_from_slice(&block_buf);
        }

        tree_levels.push(level_blocks_bytes);
        current_level_hashes = next_level_hashes;
    }

    // When only 1 hash remains in level, that is the root hash
    let root_hash = if current_level_hashes.is_empty() {
        bail!("Failed to calculate root hash");
    } else {
        current_level_hashes[0]
    };

    // Build the dm-verity superblock (512 bytes)
    let mut sb = vec![0u8; 512];
    sb[0..8].copy_from_slice(VERITY_SIGNATURE);
    sb[8..12].copy_from_slice(&VERITY_VERSION.to_le_bytes());
    sb[12..16].copy_from_slice(&VERITY_HASH_TYPE_NORMAL.to_le_bytes());

    let uuid = Uuid::new_v4();
    sb[16..32].copy_from_slice(uuid.as_bytes());

    let algo = b"sha256\0";
    sb[32..32 + algo.len()].copy_from_slice(algo);

    sb[64..68].copy_from_slice(&(VERITY_BLOCK_SIZE as u32).to_le_bytes());
    sb[68..72].copy_from_slice(&(VERITY_BLOCK_SIZE as u32).to_le_bytes());
    sb[72..80].copy_from_slice(&num_data_blocks.to_le_bytes());
    sb[80..82].copy_from_slice(&(32u16).to_le_bytes()); // salt_size = 32
    sb[88..120].copy_from_slice(&salt);

    // Pad superblock to full 4KB block
    let mut hash_device = vec![0u8; VERITY_BLOCK_SIZE];
    hash_device[..512].copy_from_slice(&sb);

    // Append tree levels
    for level_bytes in tree_levels {
        hash_device.extend_from_slice(&level_bytes);
    }

    // Pad total hash device to 4KB alignment
    let remainder = hash_device.len() % VERITY_BLOCK_SIZE;
    if remainder != 0 {
        hash_device.resize(hash_device.len() + (VERITY_BLOCK_SIZE - remainder), 0);
    }

    let root_hash_hex = hex::encode(root_hash);
    let salt_hex = hex::encode(salt);

    Ok(VerityResult {
        root_hash_hex,
        root_hash,
        salt,
        salt_hex,
        data_blocks: num_data_blocks,
        hash_device_bytes: hash_device,
    })
}

/// Verifies that the provided data blocks match the expected root hash using dm-verity
pub fn verify_data_against_root(
    data: &[u8],
    salt: &[u8; 32],
    expected_root_hash_hex: &str,
) -> Result<bool> {
    let result = compute_verity_tree(data, Some(*salt))?;
    Ok(result.root_hash_hex.eq_ignore_ascii_case(expected_root_hash_hex))
}
