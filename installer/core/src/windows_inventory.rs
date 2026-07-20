use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    Architecture, BitLockerState, CONTRACT_SCHEMA_VERSION, DiskInventory, ESP_TYPE_GUID,
    Filesystem, FirmwareMode, HostInventory, Inventory, LINUX_ROOT_X86_64_TYPE_GUID, MSR_TYPE_GUID,
    PartitionInventory, PartitionRole, PlatformReadiness, SecureBootState,
    WINDOWS_BASIC_DATA_TYPE_GUID, WINDOWS_RECOVERY_TYPE_GUID, WindowsVolume, XBOOTLDR_TYPE_GUID,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsStorageSnapshot {
    pub schema_version: u32,
    pub collected_at_unix_ms: u64,
    pub windows_version: String,
    pub architecture: String,
    pub firmware: SnapshotFirmwareMode,
    pub secure_boot_enabled: Option<bool>,
    pub elevated: bool,
    pub firmware_environment_readable: bool,
    pub windows_servicing_idle: bool,
    pub system_drive: String,
    pub power: PowerObservation,
    pub disks: Vec<ObservedDisk>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotFirmwareMode {
    Uefi,
    Legacy,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerObservation {
    pub battery_present: bool,
    pub on_ac_power: Option<bool>,
    pub charge_percent: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedDisk {
    pub number: u32,
    pub guid: Option<String>,
    pub partition_style: String,
    pub size_bytes: u64,
    pub logical_sector_bytes: u32,
    pub physical_sector_bytes: u32,
    pub health_status: String,
    pub operational_status: Vec<String>,
    pub partitions: Vec<ObservedPartition>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPartition {
    pub number: u32,
    pub guid: Option<String>,
    pub type_guid: Option<String>,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub is_boot: bool,
    pub is_system: bool,
    pub drive_letter: Option<String>,
    pub name: Option<String>,
    pub volume: Option<ObservedVolume>,
    pub resize: Option<ObservedResizeBounds>,
    pub bitlocker: Option<ObservedBitLocker>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedVolume {
    pub unique_id: String,
    pub filesystem: String,
    pub size_bytes: u64,
    pub size_remaining_bytes: u64,
    pub health_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedResizeBounds {
    pub minimum_bytes: u64,
    pub maximum_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedBitLocker {
    pub protection_status: String,
    pub volume_status: String,
    pub recovery_password_protector_present: bool,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum InventoryAdapterError {
    #[error("unsupported Windows snapshot schema version {0}")]
    UnsupportedSchema(u32),
    #[error("unsupported Windows architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("Windows was not booted in UEFI mode")]
    UnsupportedFirmware,
    #[error("invalid Windows snapshot: {0}")]
    InvalidSnapshot(String),
    #[error("system volume identity is ambiguous")]
    AmbiguousSystemVolume,
    #[error("system volume was not found")]
    MissingSystemVolume,
}

pub fn normalize_windows_snapshot(
    snapshot: &WindowsStorageSnapshot,
) -> Result<Inventory, InventoryAdapterError> {
    if snapshot.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(InventoryAdapterError::UnsupportedSchema(
            snapshot.schema_version,
        ));
    }
    if !matches!(
        snapshot.architecture.trim().to_ascii_lowercase().as_str(),
        "amd64" | "x86_64"
    ) {
        return Err(InventoryAdapterError::UnsupportedArchitecture(
            snapshot.architecture.clone(),
        ));
    }
    if snapshot.firmware != SnapshotFirmwareMode::Uefi {
        return Err(InventoryAdapterError::UnsupportedFirmware);
    }
    if snapshot.windows_version.trim().is_empty() {
        return Err(invalid("Windows version is empty"));
    }
    validate_snapshot_shape(snapshot)?;
    let system_drive = normalize_drive_letter(&snapshot.system_drive)
        .ok_or_else(|| invalid("system drive is not a drive letter"))?;

    let candidates: Vec<(&ObservedDisk, &ObservedPartition)> = snapshot
        .disks
        .iter()
        .flat_map(|disk| {
            disk.partitions
                .iter()
                .filter(|partition| {
                    partition.is_boot
                        && partition
                            .drive_letter
                            .as_deref()
                            .and_then(normalize_drive_letter)
                            .as_deref()
                            == Some(system_drive.as_str())
                })
                .map(move |partition| (disk, partition))
        })
        .collect();
    let (system_disk, system_partition) = match candidates.as_slice() {
        [] => return Err(InventoryAdapterError::MissingSystemVolume),
        [candidate] => *candidate,
        _ => return Err(InventoryAdapterError::AmbiguousSystemVolume),
    };
    let active_system_partitions: Vec<(&ObservedDisk, &ObservedPartition)> = snapshot
        .disks
        .iter()
        .flat_map(|disk| {
            disk.partitions
                .iter()
                .filter(|partition| partition.is_system)
                .map(move |partition| (disk, partition))
        })
        .collect();
    let (firmware_disk, firmware_partition) = match active_system_partitions.as_slice() {
        [candidate] => *candidate,
        _ => return Err(invalid("exactly one active system partition is required")),
    };
    if firmware_disk.number != system_disk.number
        || parse_required_guid(
            firmware_partition.type_guid.as_deref(),
            "system partition type GUID",
        )? != parse_constant_guid(ESP_TYPE_GUID)
    {
        return Err(invalid(
            "active EFI system partition is not on the Windows disk",
        ));
    }
    if !system_disk.partition_style.eq_ignore_ascii_case("gpt") {
        return Err(invalid("system disk is not GPT"));
    }
    if system_disk.size_bytes == 0
        || system_disk.logical_sector_bytes == 0
        || system_disk.physical_sector_bytes == 0
    {
        return Err(invalid("disk or sector size is zero"));
    }

    validate_selected_disk(system_disk)?;
    let disk_guid = parse_required_guid(system_disk.guid.as_deref(), "disk GUID")?;
    if snapshot
        .disks
        .iter()
        .filter(|disk| disk.number != system_disk.number)
        .filter_map(|disk| disk.guid.as_deref())
        .filter_map(|value| parse_guid(value, "disk GUID").ok())
        .any(|other_guid| other_guid == disk_guid)
    {
        return Err(invalid(
            "system disk GUID is duplicated by another observed disk",
        ));
    }
    let system_partition_guid =
        parse_required_guid(system_partition.guid.as_deref(), "system partition GUID")?;
    let mut partitions = Vec::with_capacity(system_disk.partitions.len());
    for partition in &system_disk.partitions {
        let partition_guid = parse_required_guid(partition.guid.as_deref(), "partition GUID")?;
        let type_guid = parse_required_guid(partition.type_guid.as_deref(), "partition type GUID")?;
        let role = if partition.number == system_partition.number {
            if type_guid != parse_constant_guid(WINDOWS_BASIC_DATA_TYPE_GUID) {
                return Err(invalid("Windows partition is not Microsoft basic data"));
            }
            PartitionRole::Windows
        } else {
            role_from_type(type_guid)
        };
        let filesystem = partition
            .volume
            .as_ref()
            .map(|volume| filesystem_from_name(&volume.filesystem));
        if partition.drive_letter.is_some() && partition.volume.is_none() {
            return Err(invalid("mounted partition volume metadata is unavailable"));
        }
        if role == PartitionRole::Recovery && partition.volume.is_none() {
            return Err(invalid("Windows recovery volume metadata is unavailable"));
        }
        let filesystem_free_bytes = if role == PartitionRole::Esp {
            let volume = partition
                .volume
                .as_ref()
                .ok_or_else(|| invalid("ESP volume metadata is unavailable"))?;
            if filesystem != Some(Filesystem::Fat32) {
                return Err(invalid("ESP is not FAT32"));
            }
            Some(volume.size_remaining_bytes)
        } else {
            None
        };
        let volume_id = partition.volume.as_ref().and_then(|volume| {
            let value = volume.unique_id.trim();
            (!value.is_empty()).then(|| value.to_owned())
        });
        partitions.push(PartitionInventory {
            partition_guid,
            type_guid,
            offset_bytes: partition.offset_bytes,
            size_bytes: partition.size_bytes,
            role,
            filesystem,
            filesystem_free_bytes,
            volume_id,
            name: nonempty(partition.name.as_deref()),
        });
    }
    partitions.sort_by_key(|partition| partition.offset_bytes);

    let windows_volume = system_partition
        .volume
        .as_ref()
        .ok_or_else(|| invalid("Windows volume metadata is unavailable"))?;
    if filesystem_from_name(&windows_volume.filesystem) != Filesystem::Ntfs {
        return Err(invalid("Windows volume is not NTFS"));
    }
    let windows_volume_id = windows_volume.unique_id.trim();
    if windows_volume_id.is_empty() {
        return Err(invalid("Windows volume ID is empty"));
    }
    let resize = system_partition
        .resize
        .as_ref()
        .ok_or_else(|| invalid("Windows resize bounds are unavailable"))?;
    if resize.minimum_bytes > system_partition.size_bytes
        || resize.maximum_bytes < system_partition.size_bytes
    {
        return Err(invalid(
            "Windows resize bounds exclude the current partition size",
        ));
    }
    let bitlocker = system_partition
        .bitlocker
        .as_ref()
        .ok_or_else(|| invalid("BitLocker status is unavailable"))?;
    let bitlocker_state = if bitlocker.protection_status.eq_ignore_ascii_case("off")
        && bitlocker
            .volume_status
            .eq_ignore_ascii_case("fullydecrypted")
    {
        BitLockerState::Disabled
    } else {
        BitLockerState::Protected
    };

    Ok(Inventory {
        schema_version: CONTRACT_SCHEMA_VERSION,
        collected_at_unix_ms: snapshot.collected_at_unix_ms,
        host: HostInventory {
            windows_version: snapshot.windows_version.trim().to_owned(),
            architecture: Architecture::X86_64,
            firmware: FirmwareMode::Uefi,
            secure_boot: match snapshot.secure_boot_enabled {
                Some(false) => SecureBootState::Disabled,
                Some(true) | None => SecureBootState::EnabledUntrusted,
            },
        },
        readiness: PlatformReadiness {
            elevated: snapshot.elevated,
            // A read-only collector cannot prove that a firmware write will work.
            firmware_variables_writable: false,
            basic_gpt_disk: true,
            single_system_disk: true,
            windows_servicing_idle: snapshot.windows_servicing_idle,
            storage_health_acceptable: storage_is_healthy(system_disk),
            power_safe: power_is_safe(&snapshot.power),
            // Recovery-material possession is a user attestation, not a storage observation.
            bitlocker_recovery_material_confirmed: false,
        },
        system_disk: DiskInventory {
            disk_guid,
            size_bytes: system_disk.size_bytes,
            logical_sector_bytes: system_disk.logical_sector_bytes,
            physical_sector_bytes: system_disk.physical_sector_bytes,
            partitions,
            windows: WindowsVolume {
                partition_guid: system_partition_guid,
                volume_id: windows_volume_id.to_owned(),
                current_size_bytes: system_partition.size_bytes,
                supported_min_size_bytes: resize.minimum_bytes,
                supported_max_size_bytes: resize.maximum_bytes,
                bitlocker: bitlocker_state,
            },
        },
    })
}

fn role_from_type(type_guid: Uuid) -> PartitionRole {
    if type_guid == parse_constant_guid(ESP_TYPE_GUID) {
        PartitionRole::Esp
    } else if type_guid == parse_constant_guid(MSR_TYPE_GUID) {
        PartitionRole::Msr
    } else if type_guid == parse_constant_guid(WINDOWS_RECOVERY_TYPE_GUID) {
        PartitionRole::Recovery
    } else if type_guid == parse_constant_guid(XBOOTLDR_TYPE_GUID) {
        PartitionRole::Xbootldr
    } else if type_guid == parse_constant_guid(LINUX_ROOT_X86_64_TYPE_GUID) {
        PartitionRole::JstackRoot
    } else {
        PartitionRole::Other
    }
}

fn validate_snapshot_shape(snapshot: &WindowsStorageSnapshot) -> Result<(), InventoryAdapterError> {
    let mut disk_numbers = BTreeSet::new();
    if snapshot
        .power
        .charge_percent
        .is_some_and(|charge| charge > 100)
    {
        return Err(invalid("battery charge exceeds 100 percent"));
    }
    for disk in &snapshot.disks {
        if !disk_numbers.insert(disk.number) {
            return Err(invalid("duplicate Windows disk number"));
        }
        let mut partition_numbers = BTreeSet::new();
        for partition in &disk.partitions {
            if !partition_numbers.insert(partition.number) {
                return Err(invalid("duplicate partition number on disk"));
            }
            if partition.number == 0 || partition.size_bytes == 0 {
                return Err(invalid("partition number or size is zero"));
            }
            if partition
                .drive_letter
                .as_deref()
                .is_some_and(|letter| normalize_drive_letter(letter).is_none())
            {
                return Err(invalid("partition drive letter is invalid"));
            }
            if partition
                .name
                .as_deref()
                .is_some_and(|name| name.trim().is_empty())
            {
                return Err(invalid("partition name is empty"));
            }
        }
    }
    Ok(())
}

fn validate_selected_disk(disk: &ObservedDisk) -> Result<(), InventoryAdapterError> {
    parse_required_guid(disk.guid.as_deref(), "disk GUID")?;
    if disk.size_bytes == 0 || disk.logical_sector_bytes == 0 || disk.physical_sector_bytes == 0 {
        return Err(invalid("disk or sector size is zero"));
    }
    if disk.health_status.trim().is_empty() || disk.operational_status.is_empty() {
        return Err(invalid("disk health observation is incomplete"));
    }
    let mut partition_guids = BTreeSet::new();
    let mut ordered_partitions: Vec<&ObservedPartition> = disk.partitions.iter().collect();
    ordered_partitions.sort_by_key(|partition| partition.offset_bytes);
    let mut previous_end = 0_u64;
    for partition in ordered_partitions {
        let partition_guid = parse_required_guid(partition.guid.as_deref(), "partition GUID")?;
        if !partition_guids.insert(partition_guid) {
            return Err(invalid("duplicate partition GUID"));
        }
        parse_required_guid(partition.type_guid.as_deref(), "partition type GUID")?;
        let logical_sector = u64::from(disk.logical_sector_bytes);
        if partition.offset_bytes % logical_sector != 0
            || partition.size_bytes % logical_sector != 0
        {
            return Err(invalid("partition is not logically sector aligned"));
        }
        let partition_end = partition
            .offset_bytes
            .checked_add(partition.size_bytes)
            .ok_or_else(|| invalid("partition end overflows"))?;
        if partition.offset_bytes < previous_end || partition_end > disk.size_bytes {
            return Err(invalid("partition is overlapping or outside its disk"));
        }
        previous_end = partition_end;
        if let Some(volume) = &partition.volume {
            if volume.size_bytes == 0
                || volume.size_bytes > partition.size_bytes
                || volume.size_remaining_bytes > volume.size_bytes
            {
                return Err(invalid(
                    "volume geometry is inconsistent with its partition",
                ));
            }
            if volume.unique_id.trim().is_empty()
                || volume.filesystem.trim().is_empty()
                || volume.health_status.trim().is_empty()
            {
                return Err(invalid("volume identity or status is empty"));
            }
        }
        if let Some(resize) = &partition.resize {
            if resize.minimum_bytes == 0
                || resize.maximum_bytes == 0
                || resize.minimum_bytes > resize.maximum_bytes
            {
                return Err(invalid("partition resize bounds are invalid"));
            }
        }
        if let Some(bitlocker) = &partition.bitlocker {
            if bitlocker.protection_status.trim().is_empty()
                || bitlocker.volume_status.trim().is_empty()
            {
                return Err(invalid("BitLocker status is empty"));
            }
        }
    }
    Ok(())
}

fn filesystem_from_name(value: &str) -> Filesystem {
    if value.eq_ignore_ascii_case("fat32") {
        Filesystem::Fat32
    } else if value.eq_ignore_ascii_case("ntfs") {
        Filesystem::Ntfs
    } else if value.eq_ignore_ascii_case("btrfs") {
        Filesystem::Btrfs
    } else {
        Filesystem::Unknown
    }
}

fn storage_is_healthy(disk: &ObservedDisk) -> bool {
    disk.health_status.eq_ignore_ascii_case("healthy")
        && disk.operational_status.iter().all(|status| {
            status.eq_ignore_ascii_case("ok") || status.eq_ignore_ascii_case("online")
        })
        && disk.partitions.iter().all(|partition| {
            partition
                .volume
                .as_ref()
                .is_none_or(|volume| volume.health_status.eq_ignore_ascii_case("healthy"))
        })
}

fn power_is_safe(power: &PowerObservation) -> bool {
    if !power.battery_present {
        return true;
    }
    power.on_ac_power == Some(true) && power.charge_percent.is_some_and(|charge| charge >= 20)
}

fn normalize_drive_letter(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(':');
    let bytes = trimmed.as_bytes();
    (bytes.len() == 1 && bytes[0].is_ascii_alphabetic())
        .then(|| format!("{}:", (bytes[0] as char).to_ascii_uppercase()))
}

fn parse_required_guid(value: Option<&str>, label: &str) -> Result<Uuid, InventoryAdapterError> {
    parse_guid(
        value.ok_or_else(|| invalid(format!("{label} is unavailable")))?,
        label,
    )
}

fn parse_guid(value: &str, label: &str) -> Result<Uuid, InventoryAdapterError> {
    let trimmed = value.trim().trim_matches(['{', '}']);
    let guid = Uuid::parse_str(trimmed).map_err(|_| invalid(format!("{label} is invalid")))?;
    if guid.is_nil() {
        return Err(invalid(format!("{label} is nil")));
    }
    Ok(guid)
}

fn parse_constant_guid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("constant GPT type GUID")
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn invalid(message: impl Into<String>) -> InventoryAdapterError {
    InventoryAdapterError::InvalidSnapshot(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReleaseRequirements;

    fn snapshot() -> WindowsStorageSnapshot {
        serde_json::from_str(include_str!("../fixtures/windows-storage-snapshot.json"))
            .expect("valid snapshot fixture")
    }

    #[test]
    fn normalizes_observed_snapshot_conservatively() {
        let inventory = normalize_windows_snapshot(&snapshot()).expect("snapshot normalizes");
        assert_eq!(
            inventory.host.secure_boot,
            SecureBootState::EnabledUntrusted
        );
        assert!(!inventory.readiness.firmware_variables_writable);
        assert!(!inventory.readiness.bitlocker_recovery_material_confirmed);
        assert_eq!(inventory.system_disk.partitions[0].role, PartitionRole::Esp);
        assert_eq!(inventory.system_disk.partitions[1].role, PartitionRole::Msr);
        assert_eq!(
            inventory.system_disk.partitions[2].role,
            PartitionRole::Windows
        );
        assert_eq!(
            inventory.system_disk.partitions[3].role,
            PartitionRole::Recovery
        );
        assert_eq!(
            inventory.system_disk.windows.bitlocker,
            BitLockerState::Protected
        );
    }

    #[test]
    fn normalization_is_independent_of_observation_order() {
        let original = snapshot();
        let mut reordered = original.clone();
        reordered.disks.reverse();
        for disk in &mut reordered.disks {
            disk.partitions.reverse();
        }
        assert_eq!(
            normalize_windows_snapshot(&original),
            normalize_windows_snapshot(&reordered)
        );
    }

    #[test]
    fn rejects_ambiguous_system_volume() {
        let mut input = snapshot();
        let mut duplicate = input.disks[0].partitions[2].clone();
        duplicate.guid = Some("99999999-9999-4999-8999-999999999999".to_owned());
        duplicate.offset_bytes = 1048576;
        duplicate.size_bytes = 34359738368;
        let volume = duplicate.volume.as_mut().expect("Windows volume");
        volume.unique_id = "volume-shadow-c".to_owned();
        volume.size_bytes = duplicate.size_bytes;
        volume.size_remaining_bytes = duplicate.size_bytes / 2;
        let resize = duplicate.resize.as_mut().expect("resize bounds");
        resize.minimum_bytes = 17179869184;
        resize.maximum_bytes = duplicate.size_bytes;
        input.disks[1].partitions.push(duplicate);
        assert_eq!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::AmbiguousSystemVolume)
        );
    }

    #[test]
    fn rejects_non_gpt_system_disk() {
        let mut input = snapshot();
        input.disks[0].partition_style = "MBR".to_owned();
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "system disk is not GPT"
        ));
    }

    #[test]
    fn rejects_split_windows_and_firmware_boot_disks() {
        let mut input = snapshot();
        input.disks[0].partitions[0].is_system = false;
        let mut remote_esp = input.disks[0].partitions[0].clone();
        remote_esp.number = 2;
        remote_esp.guid = Some("99999999-9999-4999-8999-999999999999".to_owned());
        remote_esp.offset_bytes = 1048576;
        remote_esp.is_system = true;
        input.disks[1].partitions.push(remote_esp);
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "active EFI system partition is not on the Windows disk"
        ));
    }

    #[test]
    fn unknown_secure_boot_and_user_attestations_fail_closed() {
        let mut input = snapshot();
        input.secure_boot_enabled = None;
        input.elevated = false;
        input.firmware_environment_readable = false;
        let inventory = normalize_windows_snapshot(&input).expect("snapshot normalizes");
        assert_eq!(
            inventory.host.secure_boot,
            SecureBootState::EnabledUntrusted
        );
        assert!(!inventory.readiness.firmware_variables_writable);
        assert!(!inventory.readiness.bitlocker_recovery_material_confirmed);
    }

    #[test]
    fn additional_basic_data_partition_is_not_misidentified_as_windows() {
        let mut input = snapshot();
        let data = &mut input.disks[0].partitions[3];
        data.type_guid = Some(WINDOWS_BASIC_DATA_TYPE_GUID.to_owned());
        data.is_boot = false;
        data.drive_letter = Some("D".to_owned());
        data.resize = None;
        data.bitlocker = None;
        let volume = data.volume.as_mut().expect("copied volume");
        volume.unique_id = "volume-d".to_owned();
        let inventory = normalize_windows_snapshot(&input).expect("snapshot normalizes");
        assert_eq!(
            inventory
                .system_disk
                .partitions
                .iter()
                .filter(|partition| partition.role == PartitionRole::Windows)
                .count(),
            1
        );
        assert_eq!(
            inventory
                .system_disk
                .partitions
                .iter()
                .filter(|partition| partition.role == PartitionRole::Other)
                .count(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_observation_identities() {
        let mut input = snapshot();
        input.disks.push(input.disks[0].clone());
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "duplicate Windows disk number"
        ));

        let mut input = snapshot();
        let duplicate = input.disks[0].partitions[0].clone();
        input.disks[0].partitions.push(duplicate);
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "duplicate partition number on disk"
        ));
    }

    #[test]
    fn rejects_impossible_volume_geometry() {
        let mut input = snapshot();
        input.disks[0].partitions[0]
            .volume
            .as_mut()
            .expect("ESP volume")
            .size_remaining_bytes = u64::MAX;
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "volume geometry is inconsistent with its partition"
        ));
    }

    #[test]
    fn recognizes_existing_jstack_partition_types() {
        let mut input = snapshot();
        let xbootldr = &mut input.disks[0].partitions[3];
        xbootldr.type_guid = Some(XBOOTLDR_TYPE_GUID.to_owned());
        xbootldr.is_boot = false;
        xbootldr.drive_letter = None;
        xbootldr.resize = None;
        xbootldr.bitlocker = None;
        let volume = xbootldr.volume.as_mut().expect("copied volume");
        volume.unique_id = "jstack-xbootldr".to_owned();
        volume.filesystem = "FAT32".to_owned();
        volume.size_bytes = xbootldr.size_bytes;
        volume.size_remaining_bytes = xbootldr.size_bytes / 2;
        let inventory = normalize_windows_snapshot(&input).expect("snapshot normalizes");
        assert!(
            inventory
                .system_disk
                .partitions
                .iter()
                .any(|partition| partition.role == PartitionRole::Xbootldr)
        );
    }

    #[test]
    fn raw_snapshot_contract_is_strict_and_health_is_nonvacuous() {
        let mut document = serde_json::to_value(snapshot()).expect("serialize snapshot");
        document
            .as_object_mut()
            .expect("snapshot object")
            .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<WindowsStorageSnapshot>(document).is_err());

        let mut input = snapshot();
        input.disks[0].operational_status.clear();
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "disk health observation is incomplete"
        ));
    }

    #[test]
    fn observed_inventory_cannot_authorize_planning() {
        let inventory = normalize_windows_snapshot(&snapshot()).expect("snapshot normalizes");
        let requirements: ReleaseRequirements =
            serde_json::from_str(include_str!("../fixtures/release-requirements.json"))
                .expect("requirements fixture");
        assert!(crate::planner::create_install_plan_unverified(&inventory, &requirements).is_err());
    }

    #[test]
    fn unrelated_mbr_disk_does_not_invalidate_the_gpt_system_disk() {
        let input = snapshot();
        assert_eq!(input.disks[1].partition_style, "MBR");
        assert!(input.disks[1].guid.is_none());
        assert!(input.disks[1].partitions[0].guid.is_none());
        assert!(input.disks[1].partitions[0].type_guid.is_none());
        assert!(normalize_windows_snapshot(&input).is_ok());
    }

    #[test]
    fn duplicate_system_disk_guid_is_rejected() {
        let mut input = snapshot();
        input.disks[1].guid = input.disks[0].guid.clone();
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "system disk GUID is duplicated by another observed disk"
        ));
    }

    #[test]
    fn mounted_partition_without_volume_health_fails_closed() {
        let mut input = snapshot();
        let data = &mut input.disks[0].partitions[3];
        data.type_guid = Some(WINDOWS_BASIC_DATA_TYPE_GUID.to_owned());
        data.drive_letter = Some("D".to_owned());
        data.volume = None;
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "mounted partition volume metadata is unavailable"
        ));
    }

    #[test]
    fn missing_recovery_volume_health_fails_closed() {
        let mut input = snapshot();
        input.disks[0].partitions[3].volume = None;
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "Windows recovery volume metadata is unavailable"
        ));
    }

    #[test]
    fn resize_bounds_must_include_current_windows_size() {
        let mut input = snapshot();
        input.disks[0].partitions[2]
            .resize
            .as_mut()
            .expect("resize bounds")
            .maximum_bytes -= 1;
        assert!(matches!(
            normalize_windows_snapshot(&input),
            Err(InventoryAdapterError::InvalidSnapshot(message))
                if message == "Windows resize bounds exclude the current partition size"
        ));
    }
}
