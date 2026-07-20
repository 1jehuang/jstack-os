use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

pub const CONTRACT_SCHEMA_VERSION: u32 = 1;
pub const XBOOTLDR_TYPE_GUID: &str = "bc13c2ff-59e6-4262-a352-b275fd6f7172";
pub const LINUX_ROOT_X86_64_TYPE_GUID: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
pub const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const MSR_TYPE_GUID: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
pub const WINDOWS_BASIC_DATA_TYPE_GUID: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
pub const WINDOWS_RECOVERY_TYPE_GUID: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Hash256(String);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum Hash256Error {
    #[error("SHA-256 must be exactly 64 lowercase hexadecimal characters")]
    Invalid,
}

impl Hash256 {
    pub fn parse(value: impl Into<String>) -> Result<Self, Hash256Error> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(Hash256Error::Invalid)
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self(output)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Hash256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub schema_version: u32,
    pub collected_at_unix_ms: u64,
    pub host: HostInventory,
    pub readiness: PlatformReadiness,
    pub system_disk: DiskInventory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostInventory {
    pub windows_version: String,
    pub architecture: Architecture,
    pub firmware: FirmwareMode,
    pub secure_boot: SecureBootState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareMode {
    Uefi,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootState {
    Disabled,
    EnabledTrusted,
    EnabledUntrusted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlatformReadiness {
    pub elevated: bool,
    pub firmware_variables_writable: bool,
    pub basic_gpt_disk: bool,
    pub single_system_disk: bool,
    pub windows_servicing_idle: bool,
    pub storage_health_acceptable: bool,
    pub power_safe: bool,
    pub bitlocker_recovery_material_confirmed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiskInventory {
    pub disk_guid: Uuid,
    pub size_bytes: u64,
    pub logical_sector_bytes: u32,
    pub physical_sector_bytes: u32,
    pub partitions: Vec<PartitionInventory>,
    pub windows: WindowsVolume,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartitionInventory {
    pub partition_guid: Uuid,
    pub type_guid: Uuid,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub role: PartitionRole,
    pub filesystem: Option<Filesystem>,
    pub filesystem_free_bytes: Option<u64>,
    pub volume_id: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    Esp,
    Msr,
    Windows,
    Recovery,
    Other,
    Xbootldr,
    JstackRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Filesystem {
    Fat32,
    Ntfs,
    Btrfs,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowsVolume {
    pub partition_guid: Uuid,
    pub volume_id: String,
    pub current_size_bytes: u64,
    pub supported_min_size_bytes: u64,
    pub supported_max_size_bytes: u64,
    pub bitlocker: BitLockerState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitLockerState {
    Disabled,
    Protected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseRequirements {
    pub schema_version: u32,
    pub release_id: String,
    pub release_manifest_hash: Hash256,
    pub state_model_id: String,
    pub alignment_bytes: u64,
    pub xbootldr_size_bytes: u64,
    pub minimum_root_size_bytes: u64,
    pub safety_margin_bytes: u64,
    pub minimum_total_allocation_bytes: u64,
    pub esp_loader_required_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallPlan {
    pub schema_version: u32,
    pub plan_hash: Hash256,
    pub body: InstallPlanBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallPlanBody {
    pub source_inventory_hash: Hash256,
    pub install_id: Uuid,
    pub partition_fingerprints: PartitionFingerprints,
    pub release_manifest_hash: Hash256,
    pub state_model_id: String,
    pub disk_guid: Uuid,
    pub alignment_bytes: u64,
    pub windows_resize: WindowsResizePlan,
    pub allocation_interval: ByteInterval,
    pub before_layout: Vec<PartitionLayout>,
    pub after_layout: Vec<PartitionLayout>,
    pub created_partitions: Vec<PlannedPartition>,
    pub rollback_objects: Vec<RollbackObject>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartitionFingerprints {
    pub source: Hash256,
    pub windows_reserved: Hash256,
    pub windows_handoff: Hash256,
    pub installed: Hash256,
}

impl PartitionFingerprints {
    pub fn for_phase(&self, phase: PartitionFingerprintPhase) -> &Hash256 {
        match phase {
            PartitionFingerprintPhase::Source => &self.source,
            PartitionFingerprintPhase::WindowsReserved => &self.windows_reserved,
            PartitionFingerprintPhase::WindowsHandoff => &self.windows_handoff,
            PartitionFingerprintPhase::Installed => &self.installed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionFingerprintPhase {
    Source,
    WindowsReserved,
    WindowsHandoff,
    Installed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WindowsResizePlan {
    pub partition_guid: Uuid,
    pub volume_id: String,
    pub original_size_bytes: u64,
    pub target_size_bytes: u64,
    pub released_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByteInterval {
    pub start_bytes: u64,
    pub end_bytes: u64,
}

impl ByteInterval {
    pub fn size_bytes(self) -> u64 {
        self.end_bytes - self.start_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartitionLayout {
    pub partition_guid: Uuid,
    pub type_guid: Uuid,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub role: PartitionRole,
    pub filesystem: Option<Filesystem>,
    pub volume_id: Option<String>,
    pub name: Option<String>,
}

impl From<&PartitionInventory> for PartitionLayout {
    fn from(value: &PartitionInventory) -> Self {
        Self {
            partition_guid: value.partition_guid,
            type_guid: value.type_guid,
            offset_bytes: value.offset_bytes,
            size_bytes: value.size_bytes,
            role: value.role,
            filesystem: value.filesystem,
            volume_id: value.volume_id.clone(),
            name: value.name.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlannedPartition {
    pub partition_guid: Uuid,
    pub type_guid: Uuid,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub role: PartitionRole,
    pub filesystem: Filesystem,
    pub name: String,
}

impl From<&PlannedPartition> for PartitionLayout {
    fn from(value: &PlannedPartition) -> Self {
        Self {
            partition_guid: value.partition_guid,
            type_guid: value.type_guid,
            offset_bytes: value.offset_bytes,
            size_bytes: value.size_bytes,
            role: value.role,
            filesystem: Some(value.filesystem),
            volume_id: None,
            name: Some(value.name.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackObject {
    pub kind: RollbackObjectKind,
    pub stable_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackObjectKind {
    Partition,
    EspPath,
    BootEntry,
    WindowsFinalizer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Confirmation {
    pub schema_version: u32,
    pub plan_hash: Hash256,
    pub display_digest: Hash256,
    pub confirmed_at_unix_ms: u64,
    pub authorization: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub previous_record_hash: Option<Hash256>,
    pub actor: String,
    pub transition_id: String,
    pub record_type: JournalRecordType,
    pub precondition_hash: Hash256,
    pub postcondition_hash: Option<Hash256>,
    pub plan_hash: Hash256,
    pub created_objects: Vec<RollbackObject>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalRecordType {
    ActionIntent,
    ActionCommitted,
    StateAdvanced,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Handoff {
    pub schema_version: u32,
    pub graph_model_id: String,
    pub control_state: String,
    pub journal_head_hash: Hash256,
    pub release_manifest_hash: Hash256,
    pub plan_hash: Hash256,
    pub disk_guid: Uuid,
    pub partition_phase: PartitionFingerprintPhase,
    pub partition_fingerprint: Hash256,
    pub intended_boot_target: String,
    pub nonce: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_deserialization_rejects_noncanonical_values() {
        for invalid in [
            format!("\"{}\"", "a".repeat(63)),
            format!("\"{}\"", "A".repeat(64)),
            format!("\"{}g\"", "a".repeat(63)),
        ] {
            assert!(serde_json::from_str::<Hash256>(&invalid).is_err());
        }
        let valid = format!("\"{}\"", "ab".repeat(32));
        assert_eq!(
            serde_json::from_str::<Hash256>(&valid).unwrap().as_str(),
            "ab".repeat(32)
        );
    }
}
