//! Well-known partition GUIDs, directory layouts, and runtime constants.
//!
//! Partition type GUIDs follow the systemd Discoverable Partitions Specification (DPS):
//! <https://uapi-group.org/specifications/specs/discoverable_partitions_specification/>

use uuid::Uuid;

/// Linux UAPI Discoverable Partitions Specification GUIDs for root partitions.
pub const UAPI_ROOT_X86_64_STR: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const UAPI_ROOT_AARCH64_STR: &str = "b921b045-1df0-41c3-af44-4c6f280d3fae";

/// dm-verity hash partitions
pub const UAPI_VERITY_X86_64_STR: &str = "773f0e2a-0923-4214-bc5e-bd5da224f77b";
pub const UAPI_VERITY_AARCH64_STR: &str = "c215d751-7bcd-46da-be4f-eb6e909407f1";

/// dm-verity signature partitions (PKCS#7)
pub const UAPI_VERITY_SIG_X86_64_STR: &str = "410a7d05-b643-4fc8-bc55-ab6316b45102";
pub const UAPI_VERITY_SIG_AARCH64_STR: &str = "6db69de6-29f4-4758-a7a5-962197f000a0";

pub fn uapi_root_x86_64() -> Uuid {
    Uuid::parse_str(UAPI_ROOT_X86_64_STR).unwrap()
}

pub fn uapi_root_aarch64() -> Uuid {
    Uuid::parse_str(UAPI_ROOT_AARCH64_STR).unwrap()
}

pub fn uapi_verity_x86_64() -> Uuid {
    Uuid::parse_str(UAPI_VERITY_X86_64_STR).unwrap()
}

pub fn uapi_verity_aarch64() -> Uuid {
    Uuid::parse_str(UAPI_VERITY_AARCH64_STR).unwrap()
}

pub fn uapi_verity_sig_x86_64() -> Uuid {
    Uuid::parse_str(UAPI_VERITY_SIG_X86_64_STR).unwrap()
}

pub fn uapi_verity_sig_aarch64() -> Uuid {
    Uuid::parse_str(UAPI_VERITY_SIG_AARCH64_STR).unwrap()
}

/// Clipak standard system paths
pub const SYSTEM_BASE_DIR: &str = "/var/lib/clipak";
pub const SYSTEM_BIN_DIR: &str = "/var/lib/clipak/bin";
pub const SYSTEM_CONFIG_DIR: &str = "/etc/clipak";
pub const SYSTEM_RUNTIMES_DIR: &str = "/var/lib/clipak/runtimes";
pub const SYSTEM_TOOLS_DIR: &str = "/var/lib/clipak/tools";
pub const SYSTEM_PROFILE_PATH: &str = "/etc/profile.d/clipak.sh";

/// Clipak standard user relative paths (relative to HOME)
pub const USER_LOCAL_BASE_REL: &str = ".local/share/clipak";
pub const USER_LOCAL_BIN_REL: &str = ".local/share/clipak/bin";
pub const USER_CONFIG_REL: &str = ".config/clipak";
pub const USER_RUNTIMES_REL: &str = ".local/share/clipak/runtimes";
pub const USER_TOOLS_REL: &str = ".local/share/clipak/tools";
pub const USER_BASHRC_D_REL: &str = ".bashrc.d/clipak.sh";

/// Block size for dm-verity and disk partitions (standard 4096 bytes)
pub const BLOCK_SIZE: usize = 4096;

/// Default Clipak Runtime Identifier
pub const DEFAULT_RUNTIME_ID: &str = "org.clipak.Runtime";
pub const DEFAULT_RUNTIME_VERSION: &str = "1.0";
