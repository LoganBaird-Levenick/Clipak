use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use uuid::Uuid;

pub const SECTOR_SIZE: u64 = 512;
pub const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
pub const GPT_REVISION: u32 = 0x0001_0000;
pub const GPT_HEADER_SIZE: u32 = 92;
pub const GPT_PARTITION_ENTRY_SIZE: u32 = 128;
pub const GPT_NUM_ENTRIES: u32 = 128;
pub const GPT_ENTRIES_SECTORS: u64 = (GPT_NUM_ENTRIES as u64 * GPT_PARTITION_ENTRY_SIZE as u64) / SECTOR_SIZE;

/// Represents a GPT partition entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartition {
    pub type_guid: Uuid,
    pub unique_guid: Uuid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub flags: u64,
    pub name: String,
}

impl GptPartition {
    pub fn sector_count(&self) -> u64 {
        if self.last_lba >= self.first_lba {
            self.last_lba - self.first_lba + 1
        } else {
            0
        }
    }

    pub fn byte_size(&self) -> u64 {
        self.sector_count() * SECTOR_SIZE
    }

    pub fn byte_offset(&self) -> u64 {
        self.first_lba * SECTOR_SIZE
    }
}

/// Represents the inspected partitions and metadata of a UAPI.3 DDI
#[derive(Debug, Clone)]
pub struct DdiImage {
    pub disk_guid: Uuid,
    pub total_sectors: u64,
    pub partitions: Vec<GptPartition>,
}

impl DdiImage {
    /// Finds partition by Type GUID
    pub fn find_partition_by_type(&self, type_guid: &Uuid) -> Option<&GptPartition> {
        self.partitions.iter().find(|p| &p.type_guid == type_guid)
    }

    /// Finds root payload partition (x86_64 or aarch64)
    pub fn find_root_partition(&self) -> Option<&GptPartition> {
        self.partitions.iter().find(|p| {
            p.type_guid == crate::constants::uapi_root_x86_64()
                || p.type_guid == crate::constants::uapi_root_aarch64()
        })
    }

    /// Finds verity hash partition (x86_64 or aarch64)
    pub fn find_verity_partition(&self) -> Option<&GptPartition> {
        self.partitions.iter().find(|p| {
            p.type_guid == crate::constants::uapi_verity_x86_64()
                || p.type_guid == crate::constants::uapi_verity_aarch64()
        })
    }

    /// Finds verity PKCS#7 signature partition (x86_64 or aarch64)
    pub fn find_verity_sig_partition(&self) -> Option<&GptPartition> {
        self.partitions.iter().find(|p| {
            p.type_guid == crate::constants::uapi_verity_sig_x86_64()
                || p.type_guid == crate::constants::uapi_verity_sig_aarch64()
        })
    }
}

/// Computes CRC32 with standard IEEE 802.3 polynomial
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Converts a mixed-endian EFI GUID slice (16 bytes) to Uuid
pub fn efi_bytes_to_uuid(bytes: &[u8; 16]) -> Uuid {
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut d4 = [0u8; 8];
    d4.copy_from_slice(&bytes[8..16]);
    Uuid::from_fields(d1, d2, d3, &d4)
}

/// Converts a Uuid to mixed-endian EFI GUID bytes (16 bytes)
pub fn uuid_to_efi_bytes(uuid: &Uuid) -> [u8; 16] {
    let (d1, d2, d3, d4) = uuid.as_fields();
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&d1.to_le_bytes());
    out[4..6].copy_from_slice(&d2.to_le_bytes());
    out[6..8].copy_from_slice(&d3.to_le_bytes());
    out[8..16].copy_from_slice(d4);
    out
}

/// Parses an existing DDI image file
pub fn read_ddi_image<P: AsRef<Path>>(path: P) -> Result<DdiImage> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SECTOR_SIZE * 34 {
        bail!("File too small to be a valid GPT disk image");
    }
    let total_sectors = file_len / SECTOR_SIZE;

    // Read LBA 1 (Primary GPT Header)
    file.seek(SeekFrom::Start(SECTOR_SIZE))?;
    let mut header_buf = [0u8; SECTOR_SIZE as usize];
    file.read_exact(&mut header_buf)?;

    if &header_buf[0..8] != GPT_SIGNATURE {
        bail!("Invalid GPT signature");
    }

    let revision = u32::from_le_bytes(header_buf[8..12].try_into()?);
    if revision != GPT_REVISION {
        bail!("Unsupported GPT revision: {:#x}", revision);
    }

    let header_size = u32::from_le_bytes(header_buf[12..16].try_into()?);
    if header_size < GPT_HEADER_SIZE || (header_size as usize) > header_buf.len() {
        bail!("Invalid GPT header size: {}", header_size);
    }

    let read_crc = u32::from_le_bytes(header_buf[16..20].try_into()?);
    let mut zeroed_hdr = header_buf[..header_size as usize].to_vec();
    zeroed_hdr[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let calc_crc = crc32(&zeroed_hdr);
    if read_crc != calc_crc {
        bail!("GPT header CRC32 mismatch: expected {:#x}, got {:#x}", calc_crc, read_crc);
    }

    let mut disk_guid_bytes = [0u8; 16];
    disk_guid_bytes.copy_from_slice(&header_buf[56..72]);
    let disk_guid = efi_bytes_to_uuid(&disk_guid_bytes);

    let partition_entry_lba = u64::from_le_bytes(header_buf[72..80].try_into()?);
    let num_entries = u32::from_le_bytes(header_buf[80..84].try_into()?);
    let entry_size = u32::from_le_bytes(header_buf[84..88].try_into()?);
    let entries_crc = u32::from_le_bytes(header_buf[88..92].try_into()?);

    // Read partition entries array
    let total_entries_bytes = (num_entries as u64) * (entry_size as u64);
    file.seek(SeekFrom::Start(partition_entry_lba * SECTOR_SIZE))?;
    let mut entries_buf = vec![0u8; total_entries_bytes as usize];
    file.read_exact(&mut entries_buf)?;

    let calc_entries_crc = crc32(&entries_buf);
    if entries_crc != calc_entries_crc {
        bail!("GPT partition entries array CRC32 mismatch");
    }

    let mut partitions = Vec::new();
    for i in 0..num_entries as usize {
        let offset = i * (entry_size as usize);
        let entry = &entries_buf[offset..offset + (entry_size as usize)];

        let mut type_guid_bytes = [0u8; 16];
        type_guid_bytes.copy_from_slice(&entry[0..16]);
        let type_guid = efi_bytes_to_uuid(&type_guid_bytes);
        if type_guid.is_nil() {
            continue;
        }

        let mut uniq_guid_bytes = [0u8; 16];
        uniq_guid_bytes.copy_from_slice(&entry[16..32]);
        let unique_guid = efi_bytes_to_uuid(&uniq_guid_bytes);

        let first_lba = u64::from_le_bytes(entry[32..40].try_into()?);
        let last_lba = u64::from_le_bytes(entry[40..48].try_into()?);
        let flags = u64::from_le_bytes(entry[48..56].try_into()?);

        // UTF-16LE partition name (72 bytes max = 36 chars)
        let name_bytes = &entry[56..128];
        let mut u16_chars = Vec::new();
        for chunk in name_bytes.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                break;
            }
            u16_chars.push(ch);
        }
        let name = String::from_utf16_lossy(&u16_chars);

        partitions.push(GptPartition {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            flags,
            name,
        });
    }

    Ok(DdiImage {
        disk_guid,
        total_sectors,
        partitions,
    })
}

/// Helper to write a Protective MBR
pub fn write_protective_mbr<W: Write>(w: &mut W, total_sectors: u64) -> Result<()> {
    let mut mbr = [0u8; SECTOR_SIZE as usize];
    // Partition 1 offset: 446 (0x1BE)
    let p1_offset = 446;
    mbr[p1_offset] = 0x00; // Boot indicator (non-bootable)
    mbr[p1_offset + 1] = 0x00; // Starting CHS head
    mbr[p1_offset + 2] = 0x02; // Starting CHS sector
    mbr[p1_offset + 3] = 0x00; // Starting CHS cylinder
    mbr[p1_offset + 4] = 0xEE; // Partition type: GPT Protective
    mbr[p1_offset + 5] = 0xFF; // Ending CHS head
    mbr[p1_offset + 6] = 0xFF; // Ending CHS sector
    mbr[p1_offset + 7] = 0xFF; // Ending CHS cylinder
    mbr[p1_offset + 8..p1_offset + 12].copy_from_slice(&1u32.to_le_bytes()); // Starting LBA = 1

    let mbr_sectors = if total_sectors > 0xFFFF_FFFF {
        0xFFFF_FFFFu32
    } else {
        (total_sectors - 1) as u32
    };
    mbr[p1_offset + 12..p1_offset + 16].copy_from_slice(&mbr_sectors.to_le_bytes());

    // Boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    w.write_all(&mbr)?;
    Ok(())
}

/// Writes a fresh UAPI.3 DDI raw GPT image file containing specified partition payloads
pub fn build_ddi_disk_image<P: AsRef<Path>>(
    output_path: P,
    disk_guid: Uuid,
    payload_partitions: &[(GptPartition, Vec<u8>)],
) -> Result<DdiImage> {
    let mut file = File::create(&output_path)?;

    // Calculate sectors needed
    // First usable LBA: 34 (LBA 0: MBR, LBA 1: Header, LBA 2..33: Entries)
    let mut current_lba = 34u64;
    // Align first partition to 1MB boundary (2048 sectors) if possible, or 8 sectors (4KB)
    let alignment_sectors = 8u64; // 4096 bytes block alignment
    if current_lba % alignment_sectors != 0 {
        current_lba += alignment_sectors - (current_lba % alignment_sectors);
    }

    let mut configured_partitions = Vec::new();
    let mut partition_data_list = Vec::new();

    for (part_meta, data) in payload_partitions {
        let data_len = data.len() as u64;
        let mut sectors_needed = (data_len + SECTOR_SIZE - 1) / SECTOR_SIZE;
        // Align partition size to 4KB (8 sectors)
        if sectors_needed % alignment_sectors != 0 {
            sectors_needed += alignment_sectors - (sectors_needed % alignment_sectors);
        }
        if sectors_needed == 0 {
            sectors_needed = alignment_sectors;
        }

        let first_lba = current_lba;
        let last_lba = first_lba + sectors_needed - 1;

        let part = GptPartition {
            type_guid: part_meta.type_guid,
            unique_guid: part_meta.unique_guid,
            first_lba,
            last_lba,
            flags: part_meta.flags,
            name: part_meta.name.clone(),
        };

        configured_partitions.push(part);
        partition_data_list.push(data);

        current_lba = last_lba + 1;
        if current_lba % alignment_sectors != 0 {
            current_lba += alignment_sectors - (current_lba % alignment_sectors);
        }
    }

    let last_usable_lba = current_lba - 1;
    let backup_entries_lba = current_lba;
    let backup_header_lba = backup_entries_lba + GPT_ENTRIES_SECTORS;
    let total_sectors = backup_header_lba + 1;

    // 1. Write Protective MBR (LBA 0)
    write_protective_mbr(&mut file, total_sectors)?;

    // 2. Build Partition Entries Array (128 entries * 128 bytes)
    let mut entries_buf = vec![0u8; (GPT_NUM_ENTRIES * GPT_PARTITION_ENTRY_SIZE) as usize];
    for (i, part) in configured_partitions.iter().enumerate() {
        let offset = i * (GPT_PARTITION_ENTRY_SIZE as usize);
        entries_buf[offset..offset + 16].copy_from_slice(&uuid_to_efi_bytes(&part.type_guid));
        entries_buf[offset + 16..offset + 32].copy_from_slice(&uuid_to_efi_bytes(&part.unique_guid));
        entries_buf[offset + 32..offset + 40].copy_from_slice(&part.first_lba.to_le_bytes());
        entries_buf[offset + 40..offset + 48].copy_from_slice(&part.last_lba.to_le_bytes());
        entries_buf[offset + 48..offset + 56].copy_from_slice(&part.flags.to_le_bytes());

        // UTF-16LE partition name
        let mut name_offset = offset + 56;
        for ch in part.name.encode_utf16().take(36) {
            entries_buf[name_offset..name_offset + 2].copy_from_slice(&ch.to_le_bytes());
            name_offset += 2;
        }
    }
    let entries_crc = crc32(&entries_buf);

    // 3. Build Primary GPT Header (LBA 1)
    let mut primary_hdr = [0u8; SECTOR_SIZE as usize];
    primary_hdr[0..8].copy_from_slice(GPT_SIGNATURE);
    primary_hdr[8..12].copy_from_slice(&GPT_REVISION.to_le_bytes());
    primary_hdr[12..16].copy_from_slice(&GPT_HEADER_SIZE.to_le_bytes());
    primary_hdr[16..20].copy_from_slice(&0u32.to_le_bytes()); // zero for CRC calculation
    primary_hdr[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    primary_hdr[24..32].copy_from_slice(&1u64.to_le_bytes()); // MyLBA = 1
    primary_hdr[32..40].copy_from_slice(&backup_header_lba.to_le_bytes()); // AlternateLBA
    primary_hdr[40..48].copy_from_slice(&34u64.to_le_bytes()); // FirstUsableLBA
    primary_hdr[48..56].copy_from_slice(&last_usable_lba.to_le_bytes()); // LastUsableLBA
    primary_hdr[56..72].copy_from_slice(&uuid_to_efi_bytes(&disk_guid));
    primary_hdr[72..80].copy_from_slice(&2u64.to_le_bytes()); // PartitionEntryLBA = 2
    primary_hdr[80..84].copy_from_slice(&GPT_NUM_ENTRIES.to_le_bytes());
    primary_hdr[84..88].copy_from_slice(&GPT_PARTITION_ENTRY_SIZE.to_le_bytes());
    primary_hdr[88..92].copy_from_slice(&entries_crc.to_le_bytes());

    let primary_hdr_crc = crc32(&primary_hdr[..GPT_HEADER_SIZE as usize]);
    primary_hdr[16..20].copy_from_slice(&primary_hdr_crc.to_le_bytes());

    file.write_all(&primary_hdr)?;

    // 4. Write Primary Partition Entries (LBA 2..33)
    file.write_all(&entries_buf)?;

    // 5. Zero fill up to first partition
    let current_pos = file.stream_position()?;
    let first_part_pos = configured_partitions
        .first()
        .map(|p| p.first_lba * SECTOR_SIZE)
        .unwrap_or(current_pos);
    if first_part_pos > current_pos {
        let gap = (first_part_pos - current_pos) as usize;
        file.write_all(&vec![0u8; gap])?;
    }

    // 6. Write Partition Data Payloads
    for (part, &data) in configured_partitions.iter().zip(partition_data_list.iter()) {
        file.seek(SeekFrom::Start(part.first_lba * SECTOR_SIZE))?;
        file.write_all(data)?;
        let written = data.len() as u64;
        let expected = part.byte_size();
        if expected > written {
            let pad = (expected - written) as usize;
            file.write_all(&vec![0u8; pad])?;
        }
    }

    // 7. Write Backup Partition Entries (LBA backup_entries_lba)
    file.seek(SeekFrom::Start(backup_entries_lba * SECTOR_SIZE))?;
    file.write_all(&entries_buf)?;

    // 8. Build & Write Backup GPT Header (LBA backup_header_lba)
    let mut backup_hdr = primary_hdr;
    backup_hdr[16..20].copy_from_slice(&0u32.to_le_bytes());
    backup_hdr[24..32].copy_from_slice(&backup_header_lba.to_le_bytes()); // MyLBA = backup
    backup_hdr[32..40].copy_from_slice(&1u64.to_le_bytes()); // AlternateLBA = 1
    backup_hdr[72..80].copy_from_slice(&backup_entries_lba.to_le_bytes()); // PartitionEntryLBA = backup_entries

    let backup_hdr_crc = crc32(&backup_hdr[..GPT_HEADER_SIZE as usize]);
    backup_hdr[16..20].copy_from_slice(&backup_hdr_crc.to_le_bytes());

    file.seek(SeekFrom::Start(backup_header_lba * SECTOR_SIZE))?;
    file.write_all(&backup_hdr)?;
    file.flush()?;

    Ok(DdiImage {
        disk_guid,
        total_sectors,
        partitions: configured_partitions,
    })
}
