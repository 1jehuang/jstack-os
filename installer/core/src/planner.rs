use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::canonical::{CanonicalError, canonical_sha256};
use crate::model::*;
use crate::release::VerifiedReleaseRequirements;

#[derive(Serialize)]
struct StableDiskFingerprint {
    disk_guid: Uuid,
    size_bytes: u64,
    logical_sector_bytes: u32,
    physical_sector_bytes: u32,
    partitions: Vec<StablePartitionFingerprint>,
}

#[derive(Serialize)]
struct StablePartitionFingerprint {
    partition_guid: Uuid,
    type_guid: Uuid,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("unsupported contract schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("unsupported or unsafe platform: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("invalid inventory: {0}")]
    InvalidInventory(&'static str),
    #[error("invalid release requirements: {0}")]
    InvalidRequirements(&'static str),
    #[error(
        "insufficient shrinkable space: required {required_bytes} bytes, available {available_bytes} bytes"
    )]
    InsufficientSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("checked byte arithmetic overflow")]
    ArithmeticOverflow,
    #[error("canonical hashing failed: {0}")]
    Canonical(#[from] CanonicalError),
}

pub fn create_install_plan(
    inventory: &Inventory,
    verified_requirements: &VerifiedReleaseRequirements,
) -> Result<InstallPlan, PlanError> {
    create_install_plan_unverified(inventory, verified_requirements.as_requirements())
}

pub(crate) fn create_install_plan_unverified(
    inventory: &Inventory,
    requirements: &ReleaseRequirements,
) -> Result<InstallPlan, PlanError> {
    validate_inventory(inventory)?;
    validate_requirements(requirements)?;
    validate_compatibility(inventory, requirements)?;

    let inventory_hash = canonical_sha256(inventory)?;
    let mut before_layout: Vec<PartitionLayout> = inventory
        .system_disk
        .partitions
        .iter()
        .map(PartitionLayout::from)
        .collect();
    before_layout.sort_by_key(|partition| partition.offset_bytes);
    let source_gpt_fingerprint = partition_fingerprint(inventory)?;
    let install_id = deterministic_install_id(
        &source_gpt_fingerprint,
        &requirements.release_manifest_hash,
        inventory.system_disk.disk_guid,
        &requirements.state_model_id,
    );

    let windows_partition = inventory
        .system_disk
        .partitions
        .iter()
        .find(|partition| partition.partition_guid == inventory.system_disk.windows.partition_guid)
        .ok_or(PlanError::InvalidInventory(
            "Windows partition GUID is absent",
        ))?;
    let esp_partition = inventory
        .system_disk
        .partitions
        .iter()
        .find(|partition| partition.role == PartitionRole::Esp)
        .expect("inventory validation requires one ESP");

    let component_total = checked_add3(
        requirements.xbootldr_size_bytes,
        requirements.minimum_root_size_bytes,
        requirements.safety_margin_bytes,
    )?;
    let required_release = component_total.max(requirements.minimum_total_allocation_bytes);
    let shrinkable = inventory
        .system_disk
        .windows
        .current_size_bytes
        .checked_sub(inventory.system_disk.windows.supported_min_size_bytes)
        .ok_or(PlanError::InvalidInventory(
            "Windows supported minimum exceeds current size",
        ))?;
    if shrinkable < required_release {
        return Err(PlanError::InsufficientSpace {
            required_bytes: required_release,
            available_bytes: shrinkable,
        });
    }

    let target_unaligned = inventory
        .system_disk
        .windows
        .current_size_bytes
        .checked_sub(required_release)
        .ok_or(PlanError::ArithmeticOverflow)?;
    let target_size = align_down(target_unaligned, requirements.alignment_bytes);
    if target_size < inventory.system_disk.windows.supported_min_size_bytes {
        return Err(PlanError::InsufficientSpace {
            required_bytes: required_release,
            available_bytes: shrinkable,
        });
    }

    let original_end = checked_add(
        windows_partition.offset_bytes,
        inventory.system_disk.windows.current_size_bytes,
    )?;
    let interval_start = checked_add(windows_partition.offset_bytes, target_size)?;
    let allocation_interval = ByteInterval {
        start_bytes: interval_start,
        end_bytes: original_end,
    };

    let xbootldr_size = align_up(
        requirements.xbootldr_size_bytes,
        requirements.alignment_bytes,
    )?;
    let xbootldr_end = checked_add(interval_start, xbootldr_size)?;
    let root_end_limit = original_end
        .checked_sub(requirements.safety_margin_bytes)
        .ok_or(PlanError::ArithmeticOverflow)?;
    if xbootldr_end > root_end_limit {
        return Err(PlanError::InsufficientSpace {
            required_bytes: required_release,
            available_bytes: allocation_interval.size_bytes(),
        });
    }
    let root_size = align_down(root_end_limit - xbootldr_end, requirements.alignment_bytes);
    if root_size < requirements.minimum_root_size_bytes {
        return Err(PlanError::InsufficientSpace {
            required_bytes: required_release,
            available_bytes: allocation_interval.size_bytes(),
        });
    }

    let xbootldr = PlannedPartition {
        partition_guid: deterministic_partition_guid(
            &source_gpt_fingerprint,
            &requirements.release_manifest_hash,
            inventory.system_disk.disk_guid,
            "xbootldr",
        ),
        type_guid: Uuid::parse_str(XBOOTLDR_TYPE_GUID).expect("constant XBOOTLDR GUID"),
        offset_bytes: interval_start,
        size_bytes: xbootldr_size,
        role: PartitionRole::Xbootldr,
        filesystem: Filesystem::Fat32,
        name: "JSTACK-BOOT".into(),
    };
    let root = PlannedPartition {
        partition_guid: deterministic_partition_guid(
            &source_gpt_fingerprint,
            &requirements.release_manifest_hash,
            inventory.system_disk.disk_guid,
            "root",
        ),
        type_guid: Uuid::parse_str(LINUX_ROOT_X86_64_TYPE_GUID).expect("constant Linux root GUID"),
        offset_bytes: xbootldr_end,
        size_bytes: root_size,
        role: PartitionRole::JstackRoot,
        filesystem: Filesystem::Btrfs,
        name: "JSTACK-ROOT".into(),
    };
    let created_partitions = vec![xbootldr, root];
    let created_guids: std::collections::BTreeSet<_> = created_partitions
        .iter()
        .map(|partition| partition.partition_guid)
        .collect();
    if created_guids.len() != created_partitions.len()
        || created_partitions.iter().any(|created| {
            inventory
                .system_disk
                .partitions
                .iter()
                .any(|existing| existing.partition_guid == created.partition_guid)
        })
    {
        return Err(PlanError::InvalidInventory(
            "deterministic partition GUID collides with existing layout",
        ));
    }

    let mut windows_reserved_layout = before_layout.clone();
    let after_windows = windows_reserved_layout
        .iter_mut()
        .find(|partition| partition.partition_guid == windows_partition.partition_guid)
        .expect("Windows partition copied from inventory");
    after_windows.size_bytes = target_size;
    let mut windows_handoff_layout = windows_reserved_layout.clone();
    windows_handoff_layout.push(PartitionLayout::from(&created_partitions[0]));
    windows_handoff_layout.sort_by_key(|partition| partition.offset_bytes);
    let mut after_layout = windows_handoff_layout.clone();
    after_layout.push(PartitionLayout::from(&created_partitions[1]));
    after_layout.sort_by_key(|partition| partition.offset_bytes);

    let partition_fingerprints = PartitionFingerprints {
        source: source_gpt_fingerprint,
        windows_reserved: layout_partition_fingerprint(inventory, &windows_reserved_layout)?,
        windows_handoff: layout_partition_fingerprint(inventory, &windows_handoff_layout)?,
        installed: layout_partition_fingerprint(inventory, &after_layout)?,
    };

    let esp_namespace = format!(r"\EFI\JStack\Installations\{install_id}");

    let rollback_objects = vec![
        RollbackObject {
            kind: RollbackObjectKind::Partition,
            stable_id: created_partitions[0].partition_guid.to_string(),
        },
        RollbackObject {
            kind: RollbackObjectKind::Partition,
            stable_id: created_partitions[1].partition_guid.to_string(),
        },
        RollbackObject {
            kind: RollbackObjectKind::EspPath,
            stable_id: format!("esp:{};path:{esp_namespace}", esp_partition.partition_guid,),
        },
        RollbackObject {
            kind: RollbackObjectKind::WindowsFinalizer,
            stable_id: format!(r"task:\JStack\InstallerFinalizer-{install_id}"),
        },
    ];

    let body = InstallPlanBody {
        source_inventory_hash: inventory_hash,
        install_id,
        partition_fingerprints,
        release_manifest_hash: requirements.release_manifest_hash.clone(),
        state_model_id: requirements.state_model_id.clone(),
        disk_guid: inventory.system_disk.disk_guid,
        alignment_bytes: requirements.alignment_bytes,
        windows_resize: WindowsResizePlan {
            partition_guid: windows_partition.partition_guid,
            volume_id: inventory.system_disk.windows.volume_id.clone(),
            original_size_bytes: inventory.system_disk.windows.current_size_bytes,
            target_size_bytes: target_size,
            released_bytes: inventory.system_disk.windows.current_size_bytes - target_size,
        },
        allocation_interval,
        before_layout,
        after_layout,
        created_partitions,
        rollback_objects,
    };
    let plan_hash = canonical_sha256(&body)?;
    Ok(InstallPlan {
        schema_version: CONTRACT_SCHEMA_VERSION,
        plan_hash,
        body,
    })
}

fn validate_inventory(inventory: &Inventory) -> Result<(), PlanError> {
    if inventory.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(PlanError::UnsupportedSchema(inventory.schema_version));
    }
    let readiness = &inventory.readiness;
    for (ready, reason) in [
        (readiness.elevated, "administrator elevation is required"),
        (
            readiness.firmware_variables_writable,
            "UEFI variables are not writable",
        ),
        (readiness.basic_gpt_disk, "system disk is not basic GPT"),
        (
            readiness.single_system_disk,
            "system disk identity is ambiguous",
        ),
        (
            readiness.windows_servicing_idle,
            "Windows servicing owns a pending reboot",
        ),
        (
            readiness.storage_health_acceptable,
            "storage health is not acceptable",
        ),
        (readiness.power_safe, "power state is not safe"),
    ] {
        if !ready {
            return Err(PlanError::UnsupportedPlatform(reason));
        }
    }
    if inventory.host.secure_boot == SecureBootState::EnabledUntrusted {
        return Err(PlanError::UnsupportedPlatform(
            "Secure Boot trust chain is not accepted",
        ));
    }
    if inventory.system_disk.logical_sector_bytes == 0
        || inventory.system_disk.physical_sector_bytes == 0
    {
        return Err(PlanError::InvalidInventory("sector size is zero"));
    }
    if inventory.system_disk.windows.bitlocker == BitLockerState::Protected
        && !readiness.bitlocker_recovery_material_confirmed
    {
        return Err(PlanError::UnsupportedPlatform(
            "BitLocker recovery material is not confirmed",
        ));
    }

    let mut partitions = inventory.system_disk.partitions.clone();
    partitions.sort_by_key(|partition| partition.offset_bytes);
    if partitions
        .iter()
        .filter(|p| p.role == PartitionRole::Esp)
        .count()
        != 1
    {
        return Err(PlanError::InvalidInventory("exactly one ESP is required"));
    }
    if partitions
        .iter()
        .filter(|p| p.role == PartitionRole::Msr)
        .count()
        != 1
    {
        return Err(PlanError::InvalidInventory("exactly one MSR is required"));
    }
    if !partitions
        .iter()
        .any(|partition| partition.role == PartitionRole::Recovery)
    {
        return Err(PlanError::InvalidInventory(
            "at least one Windows recovery partition is required",
        ));
    }
    if partitions
        .iter()
        .filter(|p| p.role == PartitionRole::Windows)
        .count()
        != 1
    {
        return Err(PlanError::InvalidInventory(
            "exactly one Windows partition is required",
        ));
    }
    if partitions.iter().any(|partition| {
        matches!(
            partition.role,
            PartitionRole::Xbootldr | PartitionRole::JstackRoot
        )
    }) {
        return Err(PlanError::InvalidInventory(
            "existing JStack partitions are unsupported in v1",
        ));
    }
    let mut previous_end = 0_u64;
    let mut guids = std::collections::BTreeSet::new();
    for partition in &partitions {
        if partition.size_bytes == 0 {
            return Err(PlanError::InvalidInventory("partition size is zero"));
        }
        if partition.offset_bytes % u64::from(inventory.system_disk.logical_sector_bytes) != 0
            || partition.size_bytes % u64::from(inventory.system_disk.logical_sector_bytes) != 0
        {
            return Err(PlanError::InvalidInventory(
                "partition is not aligned to the logical sector size",
            ));
        }
        let expected_type = match partition.role {
            PartitionRole::Esp => Some(ESP_TYPE_GUID),
            PartitionRole::Msr => Some(MSR_TYPE_GUID),
            PartitionRole::Windows => Some(WINDOWS_BASIC_DATA_TYPE_GUID),
            PartitionRole::Recovery => Some(WINDOWS_RECOVERY_TYPE_GUID),
            PartitionRole::Other => None,
            PartitionRole::Xbootldr | PartitionRole::JstackRoot => unreachable!(),
        };
        if expected_type.is_some_and(|expected| {
            partition.type_guid != Uuid::parse_str(expected).expect("constant GPT type GUID")
        }) {
            return Err(PlanError::InvalidInventory(
                "partition role does not match its GPT type GUID",
            ));
        }
        if partition
            .filesystem_free_bytes
            .is_some_and(|free| free > partition.size_bytes)
        {
            return Err(PlanError::InvalidInventory(
                "filesystem free space exceeds partition size",
            ));
        }
        if !guids.insert(partition.partition_guid) {
            return Err(PlanError::InvalidInventory("duplicate partition GUID"));
        }
        if partition.offset_bytes < previous_end {
            return Err(PlanError::InvalidInventory("partitions overlap"));
        }
        let end = checked_add(partition.offset_bytes, partition.size_bytes)?;
        if end > inventory.system_disk.size_bytes {
            return Err(PlanError::InvalidInventory("partition exceeds disk size"));
        }
        previous_end = end;
    }
    let windows = partitions
        .iter()
        .find(|partition| partition.partition_guid == inventory.system_disk.windows.partition_guid)
        .ok_or(PlanError::InvalidInventory("Windows partition is absent"))?;
    if windows.role != PartitionRole::Windows
        || windows.filesystem != Some(Filesystem::Ntfs)
        || windows.size_bytes != inventory.system_disk.windows.current_size_bytes
        || windows.volume_id.as_deref() != Some(&inventory.system_disk.windows.volume_id)
    {
        return Err(PlanError::InvalidInventory(
            "Windows volume metadata does not match its partition",
        ));
    }
    if inventory.system_disk.windows.supported_min_size_bytes
        > inventory.system_disk.windows.current_size_bytes
        || inventory.system_disk.windows.supported_max_size_bytes
            < inventory.system_disk.windows.current_size_bytes
    {
        return Err(PlanError::InvalidInventory(
            "Windows supported resize bounds exclude the current size",
        ));
    }
    Ok(())
}

fn validate_requirements(requirements: &ReleaseRequirements) -> Result<(), PlanError> {
    if requirements.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(PlanError::UnsupportedSchema(requirements.schema_version));
    }
    if requirements.release_id.is_empty() || requirements.state_model_id.is_empty() {
        return Err(PlanError::InvalidRequirements(
            "release and state model IDs must be non-empty",
        ));
    }
    if requirements.alignment_bytes == 0 || !requirements.alignment_bytes.is_power_of_two() {
        return Err(PlanError::InvalidRequirements(
            "alignment must be a non-zero power of two",
        ));
    }
    if requirements.xbootldr_size_bytes == 0 || requirements.minimum_root_size_bytes == 0 {
        return Err(PlanError::InvalidRequirements(
            "partition minimums must be non-zero",
        ));
    }
    if requirements.esp_loader_required_bytes == 0 {
        return Err(PlanError::InvalidRequirements(
            "ESP loader requirement must be non-zero",
        ));
    }
    Ok(())
}

fn validate_compatibility(
    inventory: &Inventory,
    requirements: &ReleaseRequirements,
) -> Result<(), PlanError> {
    let logical = u64::from(inventory.system_disk.logical_sector_bytes);
    let physical = u64::from(inventory.system_disk.physical_sector_bytes);
    if requirements.alignment_bytes < physical
        || requirements.alignment_bytes % logical != 0
        || requirements.alignment_bytes % physical != 0
    {
        return Err(PlanError::InvalidRequirements(
            "alignment must be divisible by logical and physical sector sizes",
        ));
    }
    let windows = inventory
        .system_disk
        .partitions
        .iter()
        .find(|partition| partition.role == PartitionRole::Windows)
        .expect("inventory validation requires one Windows partition");
    if windows.offset_bytes % requirements.alignment_bytes != 0 {
        return Err(PlanError::InvalidInventory(
            "Windows partition start is not planner-aligned",
        ));
    }
    let esp = inventory
        .system_disk
        .partitions
        .iter()
        .find(|partition| partition.role == PartitionRole::Esp)
        .expect("inventory validation requires one ESP");
    if esp.filesystem != Some(Filesystem::Fat32)
        || esp.filesystem_free_bytes.unwrap_or(0) < requirements.esp_loader_required_bytes
    {
        return Err(PlanError::UnsupportedPlatform(
            "ESP lacks required FAT32 loader capacity",
        ));
    }
    Ok(())
}

fn deterministic_partition_guid(
    partition_fingerprint: &Hash256,
    release_hash: &Hash256,
    disk_guid: Uuid,
    role: &str,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"jstack-partition-guid-v1\0");
    hasher.update(partition_fingerprint.as_str().as_bytes());
    hasher.update(release_hash.as_str().as_bytes());
    hasher.update(disk_guid.as_bytes());
    hasher.update(role.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80; // RFC 9562 UUID version 8.
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_install_id(
    partition_fingerprint: &Hash256,
    release_hash: &Hash256,
    disk_guid: Uuid,
    state_model_id: &str,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"jstack-install-instance-v1\0");
    hasher.update(partition_fingerprint.as_str().as_bytes());
    hasher.update(release_hash.as_str().as_bytes());
    hasher.update(disk_guid.as_bytes());
    hasher.update(state_model_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub fn partition_fingerprint(inventory: &Inventory) -> Result<Hash256, CanonicalError> {
    let mut partitions: Vec<_> = inventory
        .system_disk
        .partitions
        .iter()
        .map(|partition| StablePartitionFingerprint {
            partition_guid: partition.partition_guid,
            type_guid: partition.type_guid,
            offset_bytes: partition.offset_bytes,
            size_bytes: partition.size_bytes,
        })
        .collect();
    partitions.sort_by_key(|partition| partition.offset_bytes);
    canonical_sha256(&StableDiskFingerprint {
        disk_guid: inventory.system_disk.disk_guid,
        size_bytes: inventory.system_disk.size_bytes,
        logical_sector_bytes: inventory.system_disk.logical_sector_bytes,
        physical_sector_bytes: inventory.system_disk.physical_sector_bytes,
        partitions,
    })
}

fn layout_partition_fingerprint(
    inventory: &Inventory,
    layout: &[PartitionLayout],
) -> Result<Hash256, CanonicalError> {
    let mut partitions: Vec<_> = layout
        .iter()
        .map(|partition| StablePartitionFingerprint {
            partition_guid: partition.partition_guid,
            type_guid: partition.type_guid,
            offset_bytes: partition.offset_bytes,
            size_bytes: partition.size_bytes,
        })
        .collect();
    partitions.sort_by_key(|partition| partition.offset_bytes);
    canonical_sha256(&StableDiskFingerprint {
        disk_guid: inventory.system_disk.disk_guid,
        size_bytes: inventory.system_disk.size_bytes,
        logical_sector_bytes: inventory.system_disk.logical_sector_bytes,
        physical_sector_bytes: inventory.system_disk.physical_sector_bytes,
        partitions,
    })
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> Result<u64, PlanError> {
    let adjusted = checked_add(value, alignment - 1)?;
    Ok(align_down(adjusted, alignment))
}

fn checked_add(left: u64, right: u64) -> Result<u64, PlanError> {
    left.checked_add(right).ok_or(PlanError::ArithmeticOverflow)
}

fn checked_add3(first: u64, second: u64, third: u64) -> Result<u64, PlanError> {
    checked_add(checked_add(first, second)?, third)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) const GIB: u64 = 1024 * 1024 * 1024;
    pub(crate) const MIB: u64 = 1024 * 1024;

    fn guid(value: &str) -> Uuid {
        Uuid::parse_str(value).unwrap()
    }

    pub(crate) fn fixture() -> (Inventory, ReleaseRequirements) {
        let esp = PartitionInventory {
            partition_guid: guid("11111111-1111-4111-8111-111111111111"),
            type_guid: guid("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
            offset_bytes: MIB,
            size_bytes: 512 * MIB,
            role: PartitionRole::Esp,
            filesystem: Some(Filesystem::Fat32),
            filesystem_free_bytes: Some(200 * MIB),
            volume_id: None,
            name: Some("EFI".into()),
        };
        let msr = PartitionInventory {
            partition_guid: guid("22222222-2222-4222-8222-222222222222"),
            type_guid: guid("e3c9e316-0b5c-4db8-817d-f92df00215ae"),
            offset_bytes: 513 * MIB,
            size_bytes: 16 * MIB,
            role: PartitionRole::Msr,
            filesystem: None,
            filesystem_free_bytes: None,
            volume_id: None,
            name: None,
        };
        let windows_offset = 529 * MIB;
        let windows_size = 400 * GIB;
        let windows_guid = guid("33333333-3333-4333-8333-333333333333");
        let windows = PartitionInventory {
            partition_guid: windows_guid,
            type_guid: guid("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
            offset_bytes: windows_offset,
            size_bytes: windows_size,
            role: PartitionRole::Windows,
            filesystem: Some(Filesystem::Ntfs),
            filesystem_free_bytes: None,
            volume_id: Some("volume-c".into()),
            name: Some("Windows".into()),
        };
        let recovery = PartitionInventory {
            partition_guid: guid("44444444-4444-4444-8444-444444444444"),
            type_guid: guid("de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
            offset_bytes: windows_offset + windows_size,
            size_bytes: GIB,
            role: PartitionRole::Recovery,
            filesystem: Some(Filesystem::Ntfs),
            filesystem_free_bytes: None,
            volume_id: Some("winre".into()),
            name: Some("Windows RE".into()),
        };
        let inventory = Inventory {
            schema_version: 1,
            collected_at_unix_ms: 1_800_000_000_000,
            host: HostInventory {
                windows_version: "11-24H2".into(),
                architecture: Architecture::X86_64,
                firmware: FirmwareMode::Uefi,
                secure_boot: SecureBootState::EnabledTrusted,
            },
            readiness: PlatformReadiness {
                elevated: true,
                firmware_variables_writable: true,
                basic_gpt_disk: true,
                single_system_disk: true,
                windows_servicing_idle: true,
                storage_health_acceptable: true,
                power_safe: true,
                bitlocker_recovery_material_confirmed: true,
            },
            system_disk: DiskInventory {
                disk_guid: guid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                size_bytes: windows_offset + windows_size + GIB + MIB,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
                partitions: vec![esp, msr, windows, recovery],
                windows: WindowsVolume {
                    partition_guid: windows_guid,
                    volume_id: "volume-c".into(),
                    current_size_bytes: windows_size,
                    supported_min_size_bytes: 250 * GIB,
                    supported_max_size_bytes: windows_size,
                    bitlocker: BitLockerState::Protected,
                },
            },
        };
        let requirements = ReleaseRequirements {
            schema_version: 1,
            release_id: "jstack-2026.07".into(),
            release_manifest_hash: Hash256::parse("ab".repeat(32)).unwrap(),
            state_model_id: "jstack-no-usb-dual-boot-v1".into(),
            alignment_bytes: MIB,
            xbootldr_size_bytes: 8 * GIB,
            minimum_root_size_bytes: 48 * GIB,
            safety_margin_bytes: 2 * GIB,
            minimum_total_allocation_bytes: 64 * GIB,
            esp_loader_required_bytes: 16 * MIB,
        };
        (inventory, requirements)
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{GIB, MIB, fixture};
    use super::*;

    #[test]
    fn planner_is_deterministic_and_preserves_windows_resources() {
        let (inventory, requirements) = fixture();
        let first = create_install_plan_unverified(&inventory, &requirements).unwrap();
        let second = create_install_plan_unverified(&inventory, &requirements).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.body.created_partitions.len(), 2);
        assert!(first.body.windows_resize.released_bytes >= 64 * GIB);
        for original in &inventory.system_disk.partitions {
            let planned = first
                .body
                .after_layout
                .iter()
                .find(|partition| partition.partition_guid == original.partition_guid)
                .unwrap();
            assert_eq!(planned.offset_bytes, original.offset_bytes);
            if original.role != PartitionRole::Windows {
                assert_eq!(planned.size_bytes, original.size_bytes);
                assert_eq!(planned.type_guid, original.type_guid);
            }
        }
        let esp_guid = inventory
            .system_disk
            .partitions
            .iter()
            .find(|partition| partition.role == PartitionRole::Esp)
            .unwrap()
            .partition_guid
            .to_string();
        assert!(first.body.rollback_objects.iter().any(|object| {
            object.kind == RollbackObjectKind::EspPath && object.stable_id.contains(&esp_guid)
        }));
        assert!(
            first
                .body
                .rollback_objects
                .iter()
                .all(|object| object.kind != RollbackObjectKind::BootEntry)
        );
        let install_id = first.body.install_id.to_string();
        assert!(first.body.rollback_objects.iter().any(|object| {
            object.kind == RollbackObjectKind::EspPath && object.stable_id.contains(&install_id)
        }));
        assert!(first.body.rollback_objects.iter().any(|object| {
            object.kind == RollbackObjectKind::WindowsFinalizer
                && object.stable_id.contains(&install_id)
        }));
    }

    #[test]
    fn every_created_partition_is_aligned_and_inside_released_interval() {
        let (inventory, requirements) = fixture();
        let plan = create_install_plan_unverified(&inventory, &requirements).unwrap();
        for partition in &plan.body.created_partitions {
            assert_eq!(partition.offset_bytes % requirements.alignment_bytes, 0);
            assert_eq!(partition.size_bytes % requirements.alignment_bytes, 0);
            assert!(partition.offset_bytes >= plan.body.allocation_interval.start_bytes);
            assert!(
                partition.offset_bytes + partition.size_bytes
                    <= plan.body.allocation_interval.end_bytes
            );
        }
        assert!(plan.body.created_partitions[1].size_bytes >= requirements.minimum_root_size_bytes);
    }

    #[test]
    fn generated_boundary_cases_never_underallocate_or_escape() {
        let (mut inventory, requirements) = fixture();
        for extra_gib in 64..=149 {
            inventory.system_disk.windows.supported_min_size_bytes =
                inventory.system_disk.windows.current_size_bytes - extra_gib * GIB;
            let plan = create_install_plan_unverified(&inventory, &requirements).unwrap();
            assert!(
                plan.body.windows_resize.released_bytes
                    >= requirements.minimum_total_allocation_bytes
            );
            assert!(
                plan.body.created_partitions[1].size_bytes >= requirements.minimum_root_size_bytes
            );
            assert!(plan.body.allocation_interval.end_bytes <= inventory.system_disk.size_bytes);
        }
    }

    #[test]
    fn rejects_insufficient_space_without_a_partial_plan() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.windows.supported_min_size_bytes =
            inventory.system_disk.windows.current_size_bytes - 63 * GIB;
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::InsufficientSpace { .. })
        ));
    }

    #[test]
    fn rejects_overlapping_or_ambiguous_inventory() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.partitions[1].offset_bytes = MIB;
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::InvalidInventory("partitions overlap"))
        ));
    }

    #[test]
    fn rejects_unconfirmed_bitlocker_recovery_material() {
        let (mut inventory, requirements) = fixture();
        inventory.readiness.bitlocker_recovery_material_confirmed = false;
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::UnsupportedPlatform(
                "BitLocker recovery material is not confirmed"
            ))
        ));
    }

    #[test]
    fn transient_inventory_fields_do_not_change_partition_guids() {
        let (inventory, requirements) = fixture();
        let first = create_install_plan_unverified(&inventory, &requirements).unwrap();
        let mut recollected = inventory.clone();
        recollected.collected_at_unix_ms += 60_000;
        recollected.system_disk.partitions[2].name = Some("Renamed Windows".into());
        let second = create_install_plan_unverified(&recollected, &requirements).unwrap();
        assert_eq!(
            first.body.partition_fingerprints.source,
            second.body.partition_fingerprints.source
        );
        assert_eq!(
            first.body.created_partitions,
            second.body.created_partitions
        );
        assert_ne!(
            first.body.source_inventory_hash,
            second.body.source_inventory_hash
        );
        assert_ne!(first.plan_hash, second.plan_hash);
    }

    #[test]
    fn every_phase_fingerprint_is_reconstructable_from_observed_gpt() {
        let (inventory, requirements) = fixture();
        let plan = create_install_plan_unverified(&inventory, &requirements).unwrap();

        let observed = |layout: &[PartitionLayout]| {
            let mut inventory = inventory.clone();
            inventory.system_disk.partitions = layout
                .iter()
                .map(|partition| PartitionInventory {
                    partition_guid: partition.partition_guid,
                    type_guid: partition.type_guid,
                    offset_bytes: partition.offset_bytes,
                    size_bytes: partition.size_bytes,
                    role: partition.role,
                    filesystem: partition.filesystem,
                    filesystem_free_bytes: None,
                    volume_id: partition.volume_id.clone(),
                    name: partition.name.clone(),
                })
                .collect();
            inventory
        };

        assert_eq!(
            partition_fingerprint(&inventory).unwrap(),
            plan.body.partition_fingerprints.source
        );
        let mut reserved = plan.body.before_layout.clone();
        reserved
            .iter_mut()
            .find(|partition| partition.role == PartitionRole::Windows)
            .unwrap()
            .size_bytes = plan.body.windows_resize.target_size_bytes;
        assert_eq!(
            partition_fingerprint(&observed(&reserved)).unwrap(),
            plan.body.partition_fingerprints.windows_reserved
        );
        let windows_handoff: Vec<_> = plan
            .body
            .after_layout
            .iter()
            .filter(|partition| partition.role != PartitionRole::JstackRoot)
            .cloned()
            .collect();
        assert_eq!(
            partition_fingerprint(&observed(&windows_handoff)).unwrap(),
            plan.body.partition_fingerprints.windows_handoff
        );
        assert_eq!(
            partition_fingerprint(&observed(&plan.body.after_layout)).unwrap(),
            plan.body.partition_fingerprints.installed
        );
    }

    #[test]
    fn rejects_partition_role_and_type_mismatch() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.partitions[0].type_guid =
            Uuid::parse_str(WINDOWS_BASIC_DATA_TYPE_GUID).unwrap();
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::InvalidInventory(
                "partition role does not match its GPT type GUID"
            ))
        ));
    }

    #[test]
    fn rejects_missing_msr() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.partitions[1].role = PartitionRole::Other;
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::InvalidInventory("exactly one MSR is required"))
        ));
    }

    #[test]
    fn rejects_impossible_esp_free_space_measurement() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.partitions[0].filesystem_free_bytes =
            Some(inventory.system_disk.partitions[0].size_bytes + 1);
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::InvalidInventory(
                "filesystem free space exceeds partition size"
            ))
        ));
    }

    #[test]
    fn rejects_insufficient_measured_esp_capacity() {
        let (mut inventory, requirements) = fixture();
        inventory.system_disk.partitions[0].filesystem_free_bytes =
            Some(requirements.esp_loader_required_bytes - 1);
        assert!(matches!(
            create_install_plan_unverified(&inventory, &requirements),
            Err(PlanError::UnsupportedPlatform(
                "ESP lacks required FAT32 loader capacity"
            ))
        ));
    }
}
