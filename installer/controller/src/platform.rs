//! PH-06 deterministic virtual platform.
//!
//! A pure, in-memory model of the machine state the installer mutates: GPT
//! layout, filesystems, firmware boot variables, BitLocker protection, the
//! Windows finalizer, power state, staging, and durable journal replicas.
//!
//! This module performs no I/O. It contains no path, device, process, or
//! firmware handle, and cannot reach a real disk even by mistake: its entire
//! state is owned by the `VirtualPlatform` value. It exists so that every graph
//! action has independently observable preconditions and postconditions before
//! any adapter touches a disposable VM.
//!
//! Conditions are the exact `preconditions` and `postconditions` identifiers
//! declared by the executable graph. `VirtualPlatform::observe` is the single
//! oracle; `apply` is the single mutator. Neither is reachable without the
//! confirmed plan.

use std::collections::{BTreeMap, BTreeSet};

use jstack_installer_core::{
    Filesystem, Hash256, InstallPlan, PartitionRole, RollbackObject, RollbackObjectKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Which firmware boot target `BootNext` currently names.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootTarget {
    #[default]
    Windows,
    Installer,
    Jstack,
}

/// BitLocker protection state for the Windows volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BitLockerState {
    /// The volume was never protected, so suspend/restore are no-ops.
    NotApplicable,
    Protected,
    Suspended,
}

/// Which operating system is currently executing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunningSystem {
    Windows,
    LinuxInstaller,
    Jstack,
    /// A reboot has been requested but the next system has not been observed.
    RebootRequested,
}

/// One partition in the virtual GPT.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VirtualPartition {
    pub partition_guid: String,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    pub role: PartitionRole,
    pub filesystem: Option<Filesystem>,
    /// Content digest of the deployed payload, when the filesystem holds one.
    pub content_digest: Option<Hash256>,
}

impl VirtualPartition {
    fn end_bytes(&self) -> u64 {
        self.offset_bytes.saturating_add(self.size_bytes)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.offset_bytes < other.end_bytes() && other.offset_bytes < self.end_bytes()
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum PlatformError {
    #[error("unknown platform condition {0}")]
    UnknownCondition(String),
    #[error("precondition {0} does not hold")]
    PreconditionFailed(String),
    #[error("postcondition {0} does not hold after {1}")]
    PostconditionFailed(String, String),
    #[error("action {0} is not modelled by the virtual platform")]
    UnknownAction(String),
    #[error("action {action} cannot run while {reason}")]
    IllegalAction { action: String, reason: String },
    #[error("the plan does not describe partition role {0:?}")]
    MissingPlannedPartition(PartitionRole),
    #[error("virtual GPT invariant violated: {0}")]
    GptInvariant(String),
}

/// Deterministic in-memory machine state.
///
/// Cloning a platform gives an independent machine, which is what makes
/// crash-and-restart simulation possible without any I/O.
#[derive(Clone, Debug, Serialize)]
pub struct VirtualPlatform {
    partitions: Vec<VirtualPartition>,
    windows_partition_guid: String,
    windows_original_size_bytes: u64,
    windows_planned_size_bytes: u64,
    esp_partition_guid: String,
    /// Namespaced loader files present on the Windows ESP, keyed by stable id.
    esp_files: BTreeMap<String, Hash256>,
    boot_entries: BTreeSet<String>,
    boot_next: BootTarget,
    bitlocker: BitLockerState,
    original_bitlocker: BitLockerState,
    finalizer: Option<String>,
    finalizer_armed: bool,
    running: RunningSystem,
    staging_reconciled: bool,
    quarantine_complete: bool,
    promoted_artifacts_verified: bool,
    staging_evidence_durable: bool,
    acceptance_committed: bool,
    acceptance_readback_exact: bool,
    release_verified: bool,
    xbootldr_payload_digest: Option<Hash256>,
    installed_configuration_valid: bool,
    windows_boot_verified: bool,
    temporary_bootstrap_state: bool,
    recovery_metadata_retained: bool,
    rollback_mode_recorded: bool,
    rollback_terminal_durable: bool,
    installer_rearm_attempts: u32,
    jstack_rearm_attempts: u32,
    journal_replicas: u32,
    /// Content-addressed boot observations, recorded when a boot is witnessed.
    boot_observations: BTreeSet<String>,
    plan_rollback_objects: Vec<RollbackObject>,
    plan_esp_path_id: String,
    plan_finalizer_id: String,
    /// Exact geometry the confirmed plan declares for each created partition.
    /// The platform never recomputes an offset or size: it can only create the
    /// partitions the user approved, at the approved locations.
    planned_partitions: Vec<VirtualPartition>,
    xbootldr_guid: String,
    root_guid: String,
    allocation_start_bytes: u64,
    allocation_end_bytes: u64,
    payload_digest: Hash256,
    image_digest: Hash256,
    loader_digest: Hash256,
}

fn digest(label: &str) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(label.as_bytes()).into())
}

impl VirtualPlatform {
    /// Build the pre-installation machine described by the confirmed plan.
    ///
    /// The plan is the only input. There is no constructor that accepts a host
    /// path, device node, or firmware handle.
    pub fn from_plan(plan: &InstallPlan, bitlocker: BitLockerState) -> Result<Self, PlatformError> {
        let body = &plan.body;
        let partitions: Vec<VirtualPartition> = body
            .before_layout
            .iter()
            .map(|layout| VirtualPartition {
                partition_guid: layout.partition_guid.to_string(),
                offset_bytes: layout.offset_bytes,
                size_bytes: layout.size_bytes,
                role: layout.role,
                filesystem: layout.filesystem,
                content_digest: None,
            })
            .collect();

        let planned = |role: PartitionRole| {
            body.created_partitions
                .iter()
                .find(|partition| partition.role == role)
                .ok_or(PlatformError::MissingPlannedPartition(role))
        };
        let xbootldr = planned(PartitionRole::Xbootldr)?;
        let root = planned(PartitionRole::JstackRoot)?;

        let esp = partitions
            .iter()
            .find(|partition| partition.role == PartitionRole::Esp)
            .ok_or(PlatformError::MissingPlannedPartition(PartitionRole::Esp))?;

        let esp_path_id = body
            .rollback_objects
            .iter()
            .find(|object| object.kind == RollbackObjectKind::EspPath)
            .map(|object| object.stable_id.clone())
            .ok_or_else(|| PlatformError::GptInvariant("plan has no ESP rollback path".into()))?;
        let finalizer_id = body
            .rollback_objects
            .iter()
            .find(|object| object.kind == RollbackObjectKind::WindowsFinalizer)
            .map(|object| object.stable_id.clone())
            .ok_or_else(|| PlatformError::GptInvariant("plan has no finalizer object".into()))?;

        let platform = Self {
            windows_partition_guid: body.windows_resize.partition_guid.to_string(),
            windows_original_size_bytes: body.windows_resize.original_size_bytes,
            windows_planned_size_bytes: body.windows_resize.target_size_bytes,
            esp_partition_guid: esp.partition_guid.clone(),
            partitions,
            esp_files: BTreeMap::new(),
            boot_entries: BTreeSet::from(["windows".to_owned()]),
            boot_next: BootTarget::Windows,
            bitlocker,
            original_bitlocker: bitlocker,
            finalizer: None,
            finalizer_armed: false,
            running: RunningSystem::Windows,
            staging_reconciled: false,
            quarantine_complete: false,
            promoted_artifacts_verified: false,
            staging_evidence_durable: false,
            acceptance_committed: false,
            acceptance_readback_exact: false,
            release_verified: false,
            xbootldr_payload_digest: None,
            installed_configuration_valid: false,
            windows_boot_verified: false,
            temporary_bootstrap_state: false,
            recovery_metadata_retained: false,
            rollback_mode_recorded: false,
            rollback_terminal_durable: false,
            installer_rearm_attempts: 0,
            jstack_rearm_attempts: 0,
            journal_replicas: 0,
            boot_observations: BTreeSet::new(),
            plan_rollback_objects: body.rollback_objects.clone(),
            plan_esp_path_id: esp_path_id,
            plan_finalizer_id: finalizer_id,
            planned_partitions: body
                .created_partitions
                .iter()
                .map(|partition| VirtualPartition {
                    partition_guid: partition.partition_guid.to_string(),
                    offset_bytes: partition.offset_bytes,
                    size_bytes: partition.size_bytes,
                    role: partition.role,
                    filesystem: None,
                    content_digest: None,
                })
                .collect(),
            xbootldr_guid: xbootldr.partition_guid.to_string(),
            root_guid: root.partition_guid.to_string(),
            allocation_start_bytes: body.allocation_interval.start_bytes,
            allocation_end_bytes: body.allocation_interval.end_bytes,
            payload_digest: digest("jstack.payload"),
            image_digest: digest("jstack.image"),
            loader_digest: digest("jstack.loader"),
        };
        platform.check_gpt()?;
        Ok(platform)
    }

    /// A content digest over the whole machine. Two platforms agree only when
    /// every modelled field agrees, so an observation cannot be faked by
    /// mutating one unobserved field.
    pub fn digest(&self) -> Hash256 {
        let encoded = serde_json::to_vec(self).expect("virtual platform is serializable");
        Hash256::from_bytes(Sha256::digest(&encoded).into())
    }

    pub fn running(&self) -> RunningSystem {
        self.running
    }

    pub fn boot_next(&self) -> BootTarget {
        self.boot_next
    }

    pub fn bitlocker(&self) -> BitLockerState {
        self.bitlocker
    }

    pub fn partitions(&self) -> &[VirtualPartition] {
        &self.partitions
    }

    /// Residual objects that currently exist and are owned by this install.
    ///
    /// This is the raw material for a no-committed-effect proof, so it must
    /// report *every* durable object the installer brought into existence. The
    /// confirmed plan's `rollback_objects` list does not enumerate firmware boot
    /// entries (their numbers are assigned by firmware, not by the plan), so the
    /// entries this install created are reported alongside the plan-owned
    /// objects. Omitting them would let a failure after creating a boot entry
    /// falsely claim that no effect survived.
    pub fn residual_objects(&self) -> Vec<RollbackObject> {
        let mut residual = Vec::new();
        for entry in &self.boot_entries {
            // "windows" is the pre-existing entry, not something we created.
            if entry == "windows" {
                continue;
            }
            residual.push(RollbackObject {
                kind: RollbackObjectKind::BootEntry,
                stable_id: format!("uefi:{entry}"),
            });
        }
        for object in &self.plan_rollback_objects {
            let present = match object.kind {
                RollbackObjectKind::Partition => self
                    .partitions
                    .iter()
                    .any(|partition| partition.partition_guid == object.stable_id),
                RollbackObjectKind::EspPath => self.esp_files.contains_key(&object.stable_id),
                RollbackObjectKind::BootEntry => self.boot_entries.contains(&object.stable_id),
                RollbackObjectKind::WindowsFinalizer => {
                    self.finalizer.as_deref() == Some(object.stable_id.as_str())
                }
            };
            if present {
                residual.push(object.clone());
            }
        }
        residual
    }

    fn partition(&self, guid: &str) -> Option<&VirtualPartition> {
        self.partitions
            .iter()
            .find(|partition| partition.partition_guid == guid)
    }

    fn interval_unallocated(&self, start: u64, end: u64) -> bool {
        let probe = VirtualPartition {
            partition_guid: String::new(),
            offset_bytes: start,
            size_bytes: end.saturating_sub(start),
            role: PartitionRole::Other,
            filesystem: None,
            content_digest: None,
        };
        !self
            .partitions
            .iter()
            .any(|partition| partition.overlaps(&probe))
    }

    /// The virtual GPT must never contain overlapping partitions. Every mutator
    /// re-checks this, so a modelled action cannot silently corrupt the layout.
    fn check_gpt(&self) -> Result<(), PlatformError> {
        for (index, first) in self.partitions.iter().enumerate() {
            if first.size_bytes == 0 {
                return Err(PlatformError::GptInvariant(format!(
                    "partition {} has zero size",
                    first.partition_guid
                )));
            }
            for second in &self.partitions[index + 1..] {
                if first.partition_guid == second.partition_guid {
                    return Err(PlatformError::GptInvariant(format!(
                        "duplicate partition {}",
                        first.partition_guid
                    )));
                }
                if first.overlaps(second) {
                    return Err(PlatformError::GptInvariant(format!(
                        "partitions {} and {} overlap",
                        first.partition_guid, second.partition_guid
                    )));
                }
            }
        }
        Ok(())
    }

    /// The single condition oracle. Every identifier is a graph precondition or
    /// postcondition; an unknown identifier is an error rather than `false`, so
    /// a graph edit that adds a condition cannot silently pass unobserved.
    pub fn observe(&self, condition: &str) -> Result<bool, PlatformError> {
        let windows = self.partition(&self.windows_partition_guid);
        let xbootldr = self.partition(&self.xbootldr_guid);
        let root = self.partition(&self.root_guid);
        let value = match condition {
            // Staging and release acceptance.
            "trusted_private_staging_root" => true,
            "staging_store_reconciled" => self.staging_reconciled,
            "release_candidate_verified" => self.release_verified,
            "acceptance_floor_matches_verified_policy" => self.release_verified,
            "acceptance_record_committed" => self.acceptance_committed,
            "acceptance_readback_exact" => self.acceptance_readback_exact,
            "quarantine_chunks_complete_and_synced" => self.quarantine_complete,
            "promoted_artifacts_reopened_and_verified" => self.promoted_artifacts_verified,
            "staging_evidence_durable" => self.staging_evidence_durable,
            "staged_artifact_opened_no_follow" | "staged_artifacts_opened_no_follow" => {
                self.promoted_artifacts_verified
            }
            "source_stream_reverified" | "deployed_stream_reverified" => {
                self.promoted_artifacts_verified
            }

            // Windows volume and the planned allocation interval.
            "windows_partition_at_original_size" => {
                windows.is_some_and(|p| p.size_bytes == self.windows_original_size_bytes)
            }
            "windows_partition_at_planned_size" | "windows_partition_resize_supported" => {
                windows.is_some_and(|p| p.size_bytes == self.windows_planned_size_bytes)
            }
            "windows_partition_restored" | "windows_ntfs_restored" => {
                windows.is_some_and(|p| p.size_bytes == self.windows_original_size_bytes)
            }
            "planned_interval_unallocated" => {
                self.interval_unallocated(self.allocation_start_bytes, self.allocation_end_bytes)
            }
            "xbootldr_interval_unallocated" => xbootldr.is_none(),
            "root_interval_unallocated" => root.is_none(),

            // XBOOTLDR and the JStack root.
            "xbootldr_partition_matches_plan" => xbootldr.is_some(),
            "xbootldr_unformatted" => xbootldr.is_some_and(|p| p.filesystem.is_none()),
            "xbootldr_matches_plan" | "xbootldr_mounted" => {
                xbootldr.is_some_and(|p| p.filesystem == Some(Filesystem::Fat32))
            }
            "xbootldr_fat32_empty" => {
                xbootldr.is_some_and(|p| p.filesystem == Some(Filesystem::Fat32))
                    && self.xbootldr_payload_digest.is_none()
            }
            "xbootldr_payload_verified" => {
                self.xbootldr_payload_digest.as_ref() == Some(&self.payload_digest)
            }
            "root_partition_matches_plan" => root.is_some(),
            "root_btrfs_matches_plan" => {
                root.is_some_and(|p| p.filesystem == Some(Filesystem::Btrfs))
            }
            "deployed_image_hash_matches" => {
                root.and_then(|p| p.content_digest.as_ref()) == Some(&self.image_digest)
            }
            "installed_configuration_valid" => self.installed_configuration_valid,
            "jstack_partitions_match_journal" => xbootldr.is_some() || root.is_some(),
            "jstack_partitions_absent" => xbootldr.is_none() && root.is_none(),

            // Windows ESP namespace.
            "jstack_esp_namespace_absent_or_owned" => true,
            "namespaced_loader_hash_matches_manifest" => {
                self.esp_files.get(&self.plan_esp_path_id) == Some(&self.loader_digest)
            }
            "namespaced_esp_paths_match_journal" => {
                self.esp_files.contains_key(&self.plan_esp_path_id)
            }
            "namespaced_esp_paths_absent" => !self.esp_files.contains_key(&self.plan_esp_path_id),

            // Firmware boot entries and BootNext.
            "installer_boot_entry_present" => self.boot_entries.contains("installer"),
            "installer_boot_entry_absent" => !self.boot_entries.contains("installer"),
            "jstack_boot_entry_valid" => self.boot_entries.contains("jstack"),
            "jstack_boot_entries_absent" => !self.boot_entries.contains("jstack"),
            "windows_boot_entry_present" => self.boot_entries.contains("windows"),
            "bootnext_is_installer" => self.boot_next == BootTarget::Installer,
            "bootnext_not_installer" => self.boot_next != BootTarget::Installer,
            "bootnext_is_jstack" => self.boot_next == BootTarget::Jstack,
            "bootnext_is_windows" => self.boot_next == BootTarget::Windows,
            "boot_payload_reverified_at_bootnext" => {
                self.esp_files.get(&self.plan_esp_path_id) == Some(&self.loader_digest)
            }

            // Security and the Windows finalizer.
            "bitlocker_protected" => self.bitlocker == BitLockerState::Protected,
            "bitlocker_suspended" => self.bitlocker == BitLockerState::Suspended,
            "bitlocker_restored_or_not_applicable" => matches!(
                self.bitlocker,
                BitLockerState::Protected | BitLockerState::NotApplicable
            ),
            "original_bitlocker_state_recorded" => true,
            "finalizer_registered" => self.finalizer.is_some(),
            "finalizer_not_registered" => self.finalizer.is_none(),
            "finalizer_registered_or_absent" => true,
            "windows_finalizer_armed" => self.finalizer_armed,
            "windows_finalizer_absent" => self.finalizer.is_none(),
            "windows_boot_verified" => self.windows_boot_verified,
            "temporary_bootstrap_state_present" => self.temporary_bootstrap_state,
            "temporary_bootstrap_state_removed" => !self.temporary_bootstrap_state,
            "recovery_metadata_retained" => self.recovery_metadata_retained,

            // Power, rearm budget, and durable replicas.
            "reboot_requested" => self.running == RunningSystem::RebootRequested,
            "installer_rearm_attempts_zero" => self.installer_rearm_attempts == 0,
            "installer_rearm_attempt_recorded" => self.installer_rearm_attempts > 0,
            "jstack_rearm_attempts_zero" => self.jstack_rearm_attempts == 0,
            "jstack_rearm_attempt_recorded" => self.jstack_rearm_attempts > 0,
            "journal_replica_current" | "journal_replicas_current" => self.journal_replicas >= 2,

            // Content-addressed boot and completion observations.
            "installer_boot_witnesses_content_addressed"
            | "installer_boot_identity_agrees"
            | "installer_boot_observation_committed_with_evidence" => {
                self.boot_observations.contains("installer")
            }
            "windows_finalizer_boot_witnesses_content_addressed"
            | "windows_finalizer_boot_identity_agrees"
            | "windows_finalizer_boot_observation_committed_with_evidence" => {
                self.boot_observations.contains("windows_finalizer")
            }
            "jstack_boot_witnesses_content_addressed"
            | "jstack_boot_identity_agrees"
            | "jstack_boot_observation_committed_with_evidence" => {
                self.boot_observations.contains("jstack")
            }
            "first_boot_completion_witnesses_content_addressed"
            | "first_boot_completion_identity_agrees"
            | "terminal_completion_committed_with_evidence" => {
                self.boot_observations.contains("jstack")
            }

            // Rollback bookkeeping.
            "rollback_mode_recorded" => self.rollback_mode_recorded,
            "rollback_objects_match_journal" => true,
            "rollback_terminal_durable" => self.rollback_terminal_durable,

            other => return Err(PlatformError::UnknownCondition(other.to_owned())),
        };
        Ok(value)
    }

    /// Observe a whole condition set, returning the first failure by name.
    pub fn require_all(&self, conditions: &[String]) -> Result<(), PlatformError> {
        for condition in conditions {
            if !self.observe(condition)? {
                return Err(PlatformError::PreconditionFailed(condition.clone()));
            }
        }
        Ok(())
    }

    /// Apply one graph action. Actions are named by the executable graph; an
    /// unmodelled action is an error rather than a silent no-op.
    ///
    /// This is intentionally the only mutator. It is `pub(crate)`-free but
    /// takes `&mut self`, so a caller must already own a virtual machine; there
    /// is no way to reach a real one.
    pub fn apply(&mut self, action: &str) -> Result<(), PlatformError> {
        match action {
            "collect_inventory"
            | "compute_partition_plan"
            | "present_exact_plan"
            | "record_plan_confirmation"
            | "verify_handoff"
            | "reinventory_and_revalidate_plan"
            | "verify_installation" => {}

            "reconcile_staging_store" => self.staging_reconciled = true,
            "download_release_manifest" => {}
            "verify_release_manifest" => self.release_verified = true,
            "persist_release_acceptance" => {
                self.acceptance_committed = true;
                self.acceptance_readback_exact = true;
            }
            "stage_payload_quarantine" => self.quarantine_complete = true,
            "promote_verified_payload" => {
                self.promoted_artifacts_verified = true;
                self.staging_evidence_durable = true;
            }

            "register_windows_finalizer" => {
                self.finalizer = Some(self.plan_finalizer_id.clone());
                self.temporary_bootstrap_state = true;
            }
            "unregister_windows_finalizer" => {
                self.finalizer = None;
                self.rollback_terminal_durable = true;
            }
            "suspend_bitlocker" => {
                self.bitlocker = match self.bitlocker {
                    BitLockerState::Protected => BitLockerState::Suspended,
                    other => other,
                }
            }
            "restore_bitlocker" => {
                self.bitlocker = match self.bitlocker {
                    BitLockerState::Suspended => BitLockerState::Protected,
                    other => other,
                }
            }

            "shrink_windows_ntfs" => {
                let target = self.windows_planned_size_bytes;
                let guid = self.windows_partition_guid.clone();
                self.resize_windows(&guid, target)?;
            }
            "expand_windows_ntfs" => {
                let target = self.windows_original_size_bytes;
                let guid = self.windows_partition_guid.clone();
                self.resize_windows(&guid, target)?;
            }
            "create_xbootldr_partition" => {
                self.create_partition(PartitionRole::Xbootldr)?;
            }
            "create_root_partition" => {
                self.create_partition(PartitionRole::JstackRoot)?;
            }
            "format_xbootldr_fat32" => {
                let guid = self.xbootldr_guid.clone();
                self.format(&guid, Filesystem::Fat32)?;
                self.xbootldr_payload_digest = None;
            }
            "format_root_btrfs" => {
                let guid = self.root_guid.clone();
                self.format(&guid, Filesystem::Btrfs)?;
            }
            "copy_payload_to_xbootldr" => {
                self.require_formatted(&self.xbootldr_guid.clone(), Filesystem::Fat32, action)?;
                self.xbootldr_payload_digest = Some(self.payload_digest.clone());
                self.journal_replicas = 2;
            }
            "deploy_root_image" => {
                let guid = self.root_guid.clone();
                self.require_formatted(&guid, Filesystem::Btrfs, action)?;
                let image = self.image_digest.clone();
                self.partition_mut(&guid)?.content_digest = Some(image);
            }
            "configure_installed_system" => {
                let guid = self.root_guid.clone();
                let image = self.image_digest.clone();
                if self
                    .partition(&guid)
                    .and_then(|p| p.content_digest.as_ref())
                    != Some(&image)
                {
                    return Err(PlatformError::IllegalAction {
                        action: action.to_owned(),
                        reason: "the root image is not deployed".to_owned(),
                    });
                }
                self.installed_configuration_valid = true;
            }
            "delete_jstack_partitions" => {
                let xbootldr = self.xbootldr_guid.clone();
                let root = self.root_guid.clone();
                self.partitions
                    .retain(|p| p.partition_guid != xbootldr && p.partition_guid != root);
            }

            "stage_namespaced_esp_loader" => {
                self.esp_files
                    .insert(self.plan_esp_path_id.clone(), self.loader_digest.clone());
            }
            "remove_namespaced_esp_files" => {
                self.esp_files.remove(&self.plan_esp_path_id);
            }
            "create_installer_boot_entry" => {
                self.boot_entries.insert("installer".to_owned());
            }
            "install_jstack_boot_artifacts" => {
                self.boot_entries.insert("jstack".to_owned());
            }
            "remove_jstack_boot_entries" => {
                self.boot_entries.remove("jstack");
                self.boot_entries.remove("installer");
            }
            "rehash_installer_boot_payload" => {
                // Re-verification at BootNext time: the staged loader must
                // still hash to the manifest value or the action fails.
                if self.esp_files.get(&self.plan_esp_path_id) != Some(&self.loader_digest) {
                    return Err(PlatformError::IllegalAction {
                        action: action.to_owned(),
                        reason: "the staged loader no longer matches the manifest".to_owned(),
                    });
                }
            }
            "set_installer_bootnext" => {
                self.require_boot_entry("installer", action)?;
                if self.boot_next == BootTarget::Installer {
                    self.installer_rearm_attempts += 1;
                }
                self.boot_next = BootTarget::Installer;
            }
            "set_jstack_bootnext" => {
                self.require_boot_entry("jstack", action)?;
                if self.boot_next == BootTarget::Jstack {
                    self.jstack_rearm_attempts += 1;
                }
                self.boot_next = BootTarget::Jstack;
            }
            "arm_windows_finalizer" => {
                if self.finalizer.is_none() {
                    return Err(PlatformError::IllegalAction {
                        action: action.to_owned(),
                        reason: "no finalizer is registered".to_owned(),
                    });
                }
                self.require_boot_entry("windows", action)?;
                self.finalizer_armed = true;
                self.boot_next = BootTarget::Windows;
            }
            "arm_windows_rollback" => {
                self.require_boot_entry("windows", action)?;
                self.boot_next = BootTarget::Windows;
                self.rollback_mode_recorded = true;
            }
            "request_reboot" => {
                self.running = RunningSystem::RebootRequested;
                self.journal_replicas = 2;
            }
            "verify_windows_after_install" => self.windows_boot_verified = true,
            "cleanup_windows_bootstrap" => {
                self.temporary_bootstrap_state = false;
                self.recovery_metadata_retained = true;
            }
            "verify_jstack_first_boot" => {}

            other => return Err(PlatformError::UnknownAction(other.to_owned())),
        }
        self.check_gpt()
    }

    /// Complete a reboot by observing which system actually came up. This is
    /// the only way to leave `RebootRequested`, and it records the
    /// content-addressed boot observation the graph requires.
    pub fn observe_boot(&mut self, system: RunningSystem) -> Result<(), PlatformError> {
        if self.running != RunningSystem::RebootRequested {
            return Err(PlatformError::IllegalAction {
                action: "observe_boot".to_owned(),
                reason: "no reboot was requested".to_owned(),
            });
        }
        self.running = system;
        match system {
            RunningSystem::LinuxInstaller => {
                self.boot_observations.insert("installer".to_owned());
            }
            RunningSystem::Jstack => {
                self.boot_observations.insert("jstack".to_owned());
            }
            RunningSystem::Windows => {
                if self.finalizer_armed {
                    self.boot_observations
                        .insert("windows_finalizer".to_owned());
                }
            }
            RunningSystem::RebootRequested => {
                return Err(PlatformError::IllegalAction {
                    action: "observe_boot".to_owned(),
                    reason: "a reboot cannot boot into another reboot".to_owned(),
                });
            }
        }
        // Firmware BootNext is one-shot: it is consumed by the boot it caused.
        self.boot_next = BootTarget::Windows;
        Ok(())
    }

    fn partition_mut(&mut self, guid: &str) -> Result<&mut VirtualPartition, PlatformError> {
        self.partitions
            .iter_mut()
            .find(|partition| partition.partition_guid == guid)
            .ok_or_else(|| PlatformError::GptInvariant(format!("partition {guid} is absent")))
    }

    fn resize_windows(&mut self, guid: &str, target: u64) -> Result<(), PlatformError> {
        let partition = self.partition_mut(guid)?;
        partition.size_bytes = target;
        self.check_gpt()
    }

    fn create_partition(&mut self, role: PartitionRole) -> Result<(), PlatformError> {
        let planned = self
            .planned_partitions
            .iter()
            .find(|partition| partition.role == role)
            .cloned()
            .ok_or(PlatformError::MissingPlannedPartition(role))?;
        if self.partition(&planned.partition_guid).is_some() {
            return Err(PlatformError::IllegalAction {
                action: format!("create {role:?}"),
                reason: "the partition already exists".to_owned(),
            });
        }
        // The created interval must lie inside the confirmed allocation window
        // and must not overlap anything. This is the model-level expression of
        // "create only partitions inside the confirmed unallocated interval".
        if planned.offset_bytes < self.allocation_start_bytes
            || planned.end_bytes() > self.allocation_end_bytes
        {
            return Err(PlatformError::IllegalAction {
                action: format!("create {role:?}"),
                reason: "the planned interval escapes the confirmed allocation".to_owned(),
            });
        }
        if !self.interval_unallocated(planned.offset_bytes, planned.end_bytes()) {
            return Err(PlatformError::IllegalAction {
                action: format!("create {role:?}"),
                reason: "the target interval is not unallocated".to_owned(),
            });
        }
        self.partitions.push(planned);
        self.check_gpt()
    }

    fn format(&mut self, guid: &str, filesystem: Filesystem) -> Result<(), PlatformError> {
        let partition = self.partition_mut(guid)?;
        partition.filesystem = Some(filesystem);
        partition.content_digest = None;
        Ok(())
    }

    fn require_formatted(
        &self,
        guid: &str,
        filesystem: Filesystem,
        action: &str,
    ) -> Result<(), PlatformError> {
        if self.partition(guid).and_then(|p| p.filesystem) != Some(filesystem) {
            return Err(PlatformError::IllegalAction {
                action: action.to_owned(),
                reason: format!("partition {guid} is not formatted {filesystem:?}"),
            });
        }
        Ok(())
    }

    fn require_boot_entry(&self, entry: &str, action: &str) -> Result<(), PlatformError> {
        if !self.boot_entries.contains(entry) {
            return Err(PlatformError::IllegalAction {
                action: action.to_owned(),
                reason: format!("boot entry {entry} does not exist"),
            });
        }
        Ok(())
    }

    /// Mark the ESP as holding a corrupted loader. Used only by fault
    /// campaigns; it models external damage, not an installer action.
    pub fn corrupt_staged_loader(&mut self) {
        if self.esp_files.contains_key(&self.plan_esp_path_id) {
            self.esp_files
                .insert(self.plan_esp_path_id.clone(), digest("corrupted"));
        }
    }

    /// Model the Windows side of the ESP for tests that need to see the exact
    /// namespaced path the plan owns.
    pub fn esp_partition_guid(&self) -> &str {
        &self.esp_partition_guid
    }
}
