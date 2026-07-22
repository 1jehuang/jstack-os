use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ArtifactRole, CONTRACT_SCHEMA_VERSION, Hash256, InstallPlan, JournalRecord, JournalRecordType,
    PartitionFingerprintPhase, PartitionRole, RollbackObject, RollbackObjectKind,
    VerifiedArtifactBytes, VerifiedReleaseManifest, canonical_sha256, hash_journal_record,
    validate_journal_record, validate_plan_hash,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationPlacement {
    XbootldrInstallerUki,
    XbootldrOfflineSystemImage,
    XbootldrRecoveryUki,
    EspBootstrapLoader,
    RootImageDeployment,
    InstalledInstallerUki,
    InstalledRecoveryUki,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTransform {
    ExactFileCopy,
    RawImageWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationTransition {
    CopyVerifiedPayload,
    StageInstallerLoader,
    DeployJstackImage,
    InstallJstackBoot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactBinding {
    pub manifest_digest: Hash256,
    pub role: ArtifactRole,
    pub sha256: Hash256,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationIdentity {
    pub disk_guid: Uuid,
    pub partition_guid: Uuid,
    pub placement: DestinationPlacement,
    pub transform: DeploymentTransform,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationArtifactIntent {
    pub artifact: ArtifactBinding,
    pub destination: DestinationIdentity,
}

/// One graph transition's complete, canonically ordered destination mutation intent.
///
/// Multi-artifact transitions deliberately use one intent so the durable journal retains the
/// required `ActionIntent -> ActionCommitted -> StateAdvanced` phase sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationIntentEvidence {
    pub schema_version: u32,
    pub graph_model_id: String,
    pub transition_id: String,
    pub actor: String,
    pub plan_hash: Hash256,
    pub staging_evidence_hash: Hash256,
    pub partition_phase: PartitionFingerprintPhase,
    pub partition_fingerprint: Hash256,
    pub artifacts: Vec<DestinationArtifactIntent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationArtifactCommit {
    pub artifact: ArtifactBinding,
    pub destination: DestinationIdentity,
    pub written_size_bytes: u64,
    pub written_sha256: Hash256,
}

/// Completion evidence for one complete destination transition.
///
/// This binds the already-durable action-intent record. It intentionally does not contain the
/// action-commit record hash because that record's postcondition is the hash of this value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationCommitEvidence {
    pub schema_version: u32,
    pub graph_model_id: String,
    pub transition_id: String,
    pub actor: String,
    pub plan_hash: Hash256,
    pub intent_hash: Hash256,
    pub action_intent_record_hash: Hash256,
    pub artifacts: Vec<DestinationArtifactCommit>,
}

#[derive(Debug, Error)]
pub enum DestinationEvidenceError {
    #[error(
        "destination evidence does not match the verified release, confirmed plan, graph transition, or durable journal"
    )]
    InvalidBinding,
    #[error("destination evidence uses an unsupported schema version {0}")]
    UnsupportedSchema(u32),
    #[error("destination evidence cannot be canonicalized: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    #[error("confirmed install plan or journal is invalid: {0}")]
    Integrity(#[from] crate::integrity::IntegrityError),
    #[error("verified release artifact is invalid: {0}")]
    Release(#[from] crate::release::ReleaseError),
}

#[derive(Clone, Copy)]
struct PlacementContract {
    role: ArtifactRole,
    partition_role: PartitionRole,
    transform: DeploymentTransform,
}

const COPY_VERIFIED_PAYLOAD_PLACEMENTS: &[DestinationPlacement] = &[
    DestinationPlacement::XbootldrInstallerUki,
    DestinationPlacement::XbootldrOfflineSystemImage,
    DestinationPlacement::XbootldrRecoveryUki,
];
const STAGE_INSTALLER_LOADER_PLACEMENTS: &[DestinationPlacement] =
    &[DestinationPlacement::EspBootstrapLoader];
const DEPLOY_JSTACK_IMAGE_PLACEMENTS: &[DestinationPlacement] =
    &[DestinationPlacement::RootImageDeployment];
const INSTALL_JSTACK_BOOT_PLACEMENTS: &[DestinationPlacement] = &[
    DestinationPlacement::InstalledInstallerUki,
    DestinationPlacement::InstalledRecoveryUki,
];

impl DestinationTransition {
    pub fn transition_id(self) -> &'static str {
        match self {
            Self::CopyVerifiedPayload => "copy_verified_payload",
            Self::StageInstallerLoader => "stage_installer_loader",
            Self::DeployJstackImage => "deploy_jstack_image",
            Self::InstallJstackBoot => "install_jstack_boot",
        }
    }

    pub fn actor(self) -> &'static str {
        match self {
            Self::CopyVerifiedPayload | Self::StageInstallerLoader => "windows_bootstrap",
            Self::DeployJstackImage | Self::InstallJstackBoot => "linux_installer",
        }
    }

    pub fn partition_phase(self) -> PartitionFingerprintPhase {
        match self {
            Self::CopyVerifiedPayload | Self::StageInstallerLoader => {
                PartitionFingerprintPhase::WindowsHandoff
            }
            Self::DeployJstackImage | Self::InstallJstackBoot => {
                PartitionFingerprintPhase::Installed
            }
        }
    }

    pub fn resulting_state(self) -> &'static str {
        match self {
            Self::CopyVerifiedPayload => "windows.payload_staged",
            Self::StageInstallerLoader => "windows.installer_loader_files_staged",
            Self::DeployJstackImage => "linux.image_deployed",
            Self::InstallJstackBoot => "linux.bootloader_ready",
        }
    }

    pub fn placements(self) -> &'static [DestinationPlacement] {
        match self {
            Self::CopyVerifiedPayload => COPY_VERIFIED_PAYLOAD_PLACEMENTS,
            Self::StageInstallerLoader => STAGE_INSTALLER_LOADER_PLACEMENTS,
            Self::DeployJstackImage => DEPLOY_JSTACK_IMAGE_PLACEMENTS,
            Self::InstallJstackBoot => INSTALL_JSTACK_BOOT_PLACEMENTS,
        }
    }
}

impl DestinationPlacement {
    fn contract(self) -> PlacementContract {
        match self {
            Self::XbootldrInstallerUki | Self::InstalledInstallerUki => PlacementContract {
                role: ArtifactRole::InstallerUki,
                partition_role: PartitionRole::Xbootldr,
                transform: DeploymentTransform::ExactFileCopy,
            },
            Self::XbootldrOfflineSystemImage => PlacementContract {
                role: ArtifactRole::OfflineSystemImage,
                partition_role: PartitionRole::Xbootldr,
                transform: DeploymentTransform::ExactFileCopy,
            },
            Self::XbootldrRecoveryUki | Self::InstalledRecoveryUki => PlacementContract {
                role: ArtifactRole::RecoveryUki,
                partition_role: PartitionRole::Xbootldr,
                transform: DeploymentTransform::ExactFileCopy,
            },
            Self::EspBootstrapLoader => PlacementContract {
                role: ArtifactRole::EspLoader,
                partition_role: PartitionRole::Esp,
                transform: DeploymentTransform::ExactFileCopy,
            },
            Self::RootImageDeployment => PlacementContract {
                role: ArtifactRole::OfflineSystemImage,
                partition_role: PartitionRole::JstackRoot,
                transform: DeploymentTransform::RawImageWrite,
            },
        }
    }
}

pub fn create_destination_intent(
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
) -> Result<DestinationIntentEvidence, DestinationEvidenceError> {
    validate_plan_hash(plan)?;
    let requirements = release.verified_release_requirements();
    let requirements = requirements.as_requirements();
    if plan.body.release_manifest_hash != *release.manifest_digest()
        || plan.body.state_model_id != requirements.state_model_id
    {
        return Err(DestinationEvidenceError::InvalidBinding);
    }

    let mut artifacts = Vec::with_capacity(transition.placements().len());
    for placement in transition.placements() {
        let contract = placement.contract();
        let descriptor = release.artifact_descriptor(contract.role)?;
        artifacts.push(DestinationArtifactIntent {
            artifact: ArtifactBinding {
                manifest_digest: release.manifest_digest().clone(),
                role: descriptor.role,
                sha256: descriptor.sha256.clone(),
                size_bytes: descriptor.size_bytes,
            },
            destination: DestinationIdentity {
                disk_guid: plan.body.disk_guid,
                partition_guid: partition_guid_for(plan, contract.partition_role)?,
                placement: *placement,
                transform: contract.transform,
            },
        });
    }

    let partition_phase = transition.partition_phase();
    Ok(DestinationIntentEvidence {
        schema_version: CONTRACT_SCHEMA_VERSION,
        graph_model_id: plan.body.state_model_id.clone(),
        transition_id: transition.transition_id().to_owned(),
        actor: transition.actor().to_owned(),
        plan_hash: plan.plan_hash.clone(),
        staging_evidence_hash: staging_evidence_hash.clone(),
        partition_phase,
        partition_fingerprint: plan
            .body
            .partition_fingerprints
            .for_phase(partition_phase)
            .clone(),
        artifacts,
    })
}

pub fn validate_destination_intent(
    intent: &DestinationIntentEvidence,
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
) -> Result<(), DestinationEvidenceError> {
    if intent.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(DestinationEvidenceError::UnsupportedSchema(
            intent.schema_version,
        ));
    }
    let expected =
        create_destination_intent(release, plan, expected_staging_evidence_hash, transition)?;
    if intent != &expected {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    Ok(())
}

pub fn create_destination_action_intent_record(
    previous: Option<&JournalRecord>,
    intent: &DestinationIntentEvidence,
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
) -> Result<JournalRecord, DestinationEvidenceError> {
    validate_destination_intent(
        intent,
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
    )?;
    let sequence = match previous {
        Some(record) => record
            .sequence
            .checked_add(1)
            .ok_or(DestinationEvidenceError::InvalidBinding)?,
        None => 0,
    };
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence,
        previous_record_hash: previous.map(hash_journal_record).transpose()?,
        actor: intent.actor.clone(),
        transition_id: intent.transition_id.clone(),
        record_type: JournalRecordType::ActionIntent,
        precondition_hash: canonical_sha256(intent)?,
        postcondition_hash: None,
        plan_hash: intent.plan_hash.clone(),
        created_objects: Vec::new(),
    };
    validate_journal_record(&record, previous)?;
    Ok(record)
}

pub fn create_destination_commit(
    intent: &DestinationIntentEvidence,
    action_intent_record: &JournalRecord,
    written: &[VerifiedArtifactBytes],
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
) -> Result<DestinationCommitEvidence, DestinationEvidenceError> {
    validate_destination_intent(
        intent,
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
    )?;
    validate_action_intent_record(intent, action_intent_record)?;
    if written.len() != intent.artifacts.len() {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    let artifacts = intent
        .artifacts
        .iter()
        .zip(written)
        .map(|(expected, verified)| {
            if verified.role() != expected.artifact.role
                || verified.size_bytes() != expected.artifact.size_bytes
                || verified.sha256() != &expected.artifact.sha256
            {
                return Err(DestinationEvidenceError::InvalidBinding);
            }
            Ok(DestinationArtifactCommit {
                artifact: expected.artifact.clone(),
                destination: expected.destination.clone(),
                written_size_bytes: verified.size_bytes(),
                written_sha256: verified.sha256().clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DestinationCommitEvidence {
        schema_version: CONTRACT_SCHEMA_VERSION,
        graph_model_id: intent.graph_model_id.clone(),
        transition_id: intent.transition_id.clone(),
        actor: intent.actor.clone(),
        plan_hash: intent.plan_hash.clone(),
        intent_hash: canonical_sha256(intent)?,
        action_intent_record_hash: hash_journal_record(action_intent_record)?,
        artifacts,
    })
}

pub fn validate_destination_commit(
    commit: &DestinationCommitEvidence,
    intent: &DestinationIntentEvidence,
    action_intent_record: &JournalRecord,
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
) -> Result<(), DestinationEvidenceError> {
    if commit.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(DestinationEvidenceError::UnsupportedSchema(
            commit.schema_version,
        ));
    }
    validate_destination_intent(
        intent,
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
    )?;
    validate_action_intent_record(intent, action_intent_record)?;
    if commit.graph_model_id != intent.graph_model_id
        || commit.transition_id != intent.transition_id
        || commit.actor != intent.actor
        || commit.plan_hash != intent.plan_hash
        || commit.intent_hash != canonical_sha256(intent)?
        || commit.action_intent_record_hash != hash_journal_record(action_intent_record)?
        || commit.artifacts.len() != intent.artifacts.len()
        || !commit
            .artifacts
            .iter()
            .zip(&intent.artifacts)
            .all(|(actual, expected)| {
                actual.artifact == expected.artifact
                    && actual.destination == expected.destination
                    && actual.written_size_bytes == expected.artifact.size_bytes
                    && actual.written_sha256 == expected.artifact.sha256
            })
    {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    Ok(())
}

pub fn create_destination_action_committed_record(
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
    intent: &DestinationIntentEvidence,
    action_intent_record: &JournalRecord,
    commit: &DestinationCommitEvidence,
) -> Result<JournalRecord, DestinationEvidenceError> {
    validate_plan_hash(plan)?;
    validate_destination_intent(
        intent,
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
    )?;
    validate_destination_commit(
        commit,
        intent,
        action_intent_record,
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
    )?;
    if plan.plan_hash != intent.plan_hash {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    if transition_from_intent(intent)? != transition {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: action_intent_record
            .sequence
            .checked_add(1)
            .ok_or(DestinationEvidenceError::InvalidBinding)?,
        previous_record_hash: Some(hash_journal_record(action_intent_record)?),
        actor: intent.actor.clone(),
        transition_id: intent.transition_id.clone(),
        record_type: JournalRecordType::ActionCommitted,
        precondition_hash: action_intent_record.precondition_hash.clone(),
        postcondition_hash: Some(canonical_sha256(commit)?),
        plan_hash: intent.plan_hash.clone(),
        created_objects: created_objects_for_transition(plan, transition)?,
    };
    validate_journal_record(&record, Some(action_intent_record))?;
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub fn create_destination_state_advanced_record(
    release: &VerifiedReleaseManifest,
    plan: &InstallPlan,
    expected_staging_evidence_hash: &Hash256,
    transition: DestinationTransition,
    intent: &DestinationIntentEvidence,
    action_intent_record: &JournalRecord,
    commit: &DestinationCommitEvidence,
    action_committed_record: &JournalRecord,
) -> Result<JournalRecord, DestinationEvidenceError> {
    let expected_committed = create_destination_action_committed_record(
        release,
        plan,
        expected_staging_evidence_hash,
        transition,
        intent,
        action_intent_record,
        commit,
    )?;
    if action_committed_record != &expected_committed {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    let commit_hash = canonical_sha256(commit)?;
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: action_committed_record
            .sequence
            .checked_add(1)
            .ok_or(DestinationEvidenceError::InvalidBinding)?,
        previous_record_hash: Some(hash_journal_record(action_committed_record)?),
        actor: intent.actor.clone(),
        transition_id: intent.transition_id.clone(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: commit_hash,
        postcondition_hash: Some(crate::control_state_hash(transition.resulting_state())?),
        plan_hash: intent.plan_hash.clone(),
        created_objects: Vec::new(),
    };
    validate_journal_record(&record, Some(action_committed_record))?;
    Ok(record)
}

fn validate_action_intent_record(
    intent: &DestinationIntentEvidence,
    record: &JournalRecord,
) -> Result<(), DestinationEvidenceError> {
    if record.schema_version != CONTRACT_SCHEMA_VERSION
        || record.actor != intent.actor
        || record.transition_id != intent.transition_id
        || record.record_type != JournalRecordType::ActionIntent
        || record.precondition_hash != canonical_sha256(intent)?
        || record.postcondition_hash.is_some()
        || record.plan_hash != intent.plan_hash
        || !record.created_objects.is_empty()
    {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    Ok(())
}

fn transition_from_intent(
    intent: &DestinationIntentEvidence,
) -> Result<DestinationTransition, DestinationEvidenceError> {
    [
        DestinationTransition::CopyVerifiedPayload,
        DestinationTransition::StageInstallerLoader,
        DestinationTransition::DeployJstackImage,
        DestinationTransition::InstallJstackBoot,
    ]
    .into_iter()
    .find(|transition| {
        intent.transition_id == transition.transition_id() && intent.actor == transition.actor()
    })
    .ok_or(DestinationEvidenceError::InvalidBinding)
}

fn created_objects_for_transition(
    plan: &InstallPlan,
    transition: DestinationTransition,
) -> Result<Vec<RollbackObject>, DestinationEvidenceError> {
    if transition != DestinationTransition::StageInstallerLoader {
        return Ok(Vec::new());
    }
    let matches = plan
        .body
        .rollback_objects
        .iter()
        .filter(|object| object.kind == RollbackObjectKind::EspPath)
        .cloned()
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    Ok(matches)
}

fn partition_guid_for(
    plan: &InstallPlan,
    role: PartitionRole,
) -> Result<Uuid, DestinationEvidenceError> {
    let mut matches = if role == PartitionRole::Esp {
        plan.body
            .before_layout
            .iter()
            .filter(|partition| partition.role == role)
            .map(|partition| partition.partition_guid)
            .collect::<Vec<_>>()
    } else {
        plan.body
            .created_partitions
            .iter()
            .filter(|partition| partition.role == role)
            .map(|partition| partition.partition_guid)
            .collect::<Vec<_>>()
    };
    if matches.len() != 1 {
        return Err(DestinationEvidenceError::InvalidBinding);
    }
    Ok(matches.remove(0))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::planner::tests_support::fixture;
    use crate::{
        Architecture, ReleaseChannel, ReleaseTrustPolicy, ReleaseVerificationMode,
        SignedReleaseManifest, TrustedReleaseKey, create_install_plan, verify_release_manifest,
    };

    const NOW: u64 = 1_800_000_000;
    const MANIFEST: &[u8] = include_bytes!("../fixtures/signed-release-manifest.json");

    fn release_and_plan() -> (VerifiedReleaseManifest, InstallPlan) {
        let envelope: SignedReleaseManifest = serde_json::from_slice(MANIFEST).unwrap();
        let trusted_keys = [[1_u8; 32], [2_u8; 32]]
            .into_iter()
            .map(|seed| TrustedReleaseKey {
                public_key: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                channels: vec![ReleaseChannel::Stable],
            })
            .collect();
        let policy = ReleaseTrustPolicy {
            channel: ReleaseChannel::Stable,
            architecture: Architecture::X86_64,
            state_model_id: envelope.signed.state_model_id.clone(),
            state_model_sha256: envelope.signed.state_model_sha256.clone(),
            installer_protocol_version: 1,
            now_unix_secs: NOW,
            maximum_future_skew_secs: 300,
            maximum_manifest_lifetime_secs: 86_400,
            maximum_manifest_bytes: 1024 * 1024,
            maximum_signatures: 16,
            maximum_artifacts: 4,
            maximum_chunks_per_artifact: 4096,
            maximum_artifact_bytes: 1024 * 1024,
            maximum_chunk_size_bytes: 1024 * 1024,
            signature_threshold: 2,
            trusted_keys,
            previous_acceptance: None,
        };
        let pending =
            verify_release_manifest(MANIFEST, &policy, ReleaseVerificationMode::Acquire).unwrap();
        let persisted = pending.required_acceptance().clone();
        let release = pending.accept_after_persist(&persisted).unwrap();
        let (inventory, _) = fixture();
        let plan =
            create_install_plan(&inventory, &release.verified_release_requirements()).unwrap();
        (release, plan)
    }

    #[test]
    fn transition_contracts_have_exact_ordered_artifact_sets_and_phases() {
        let (release, plan) = release_and_plan();
        let staging = Hash256::parse("a".repeat(64)).unwrap();
        let cases = [
            (
                DestinationTransition::CopyVerifiedPayload,
                vec![
                    ArtifactRole::InstallerUki,
                    ArtifactRole::OfflineSystemImage,
                    ArtifactRole::RecoveryUki,
                ],
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            (
                DestinationTransition::StageInstallerLoader,
                vec![ArtifactRole::EspLoader],
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            (
                DestinationTransition::DeployJstackImage,
                vec![ArtifactRole::OfflineSystemImage],
                PartitionFingerprintPhase::Installed,
            ),
            (
                DestinationTransition::InstallJstackBoot,
                vec![ArtifactRole::InstallerUki, ArtifactRole::RecoveryUki],
                PartitionFingerprintPhase::Installed,
            ),
        ];
        for (transition, roles, phase) in cases {
            let intent = create_destination_intent(&release, &plan, &staging, transition).unwrap();
            assert_eq!(
                intent
                    .artifacts
                    .iter()
                    .map(|item| item.artifact.role)
                    .collect::<Vec<_>>(),
                roles
            );
            assert_eq!(intent.partition_phase, phase);
            assert_eq!(
                intent.partition_fingerprint,
                *plan.body.partition_fingerprints.for_phase(phase)
            );
            validate_destination_intent(&intent, &release, &plan, &staging, transition).unwrap();
        }
    }

    #[test]
    fn destination_transition_contracts_match_the_executable_graph() {
        let graph: serde_json::Value =
            serde_json::from_str(include_str!("../../model/installer-state-graph.json")).unwrap();
        let transitions = graph["transitions"].as_array().unwrap();
        let cases = [
            (
                DestinationTransition::CopyVerifiedPayload,
                "windows.xbootldr_ready",
                "windows.payload_staged",
                "copy_payload_to_xbootldr",
            ),
            (
                DestinationTransition::StageInstallerLoader,
                "windows.payload_staged",
                "windows.installer_loader_files_staged",
                "stage_namespaced_esp_loader",
            ),
            (
                DestinationTransition::DeployJstackImage,
                "linux.root_filesystem_ready",
                "linux.image_deployed",
                "deploy_root_image",
            ),
            (
                DestinationTransition::InstallJstackBoot,
                "linux.system_configured",
                "linux.bootloader_ready",
                "install_jstack_boot_artifacts",
            ),
        ];
        for (transition, from, to, action) in cases {
            let matches = transitions
                .iter()
                .filter(|candidate| candidate["id"] == transition.transition_id())
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1);
            let graph_transition = matches[0];
            assert_eq!(graph_transition["from"], from);
            assert_eq!(graph_transition["to"], to);
            assert_eq!(transition.resulting_state(), to);
            assert_eq!(graph_transition["actor"], transition.actor());
            assert_eq!(graph_transition["actions"], serde_json::json!([action]));
            assert_eq!(graph_transition["journal"]["intent_before_actions"], true);
            assert_eq!(
                graph_transition["journal"]["commit_after_postconditions"],
                true
            );
            assert!(
                graph_transition["authorization"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == "confirmed_plan")
            );
        }
    }

    #[test]
    fn intent_validation_rejects_reordered_missing_and_mutated_items() {
        let (release, plan) = release_and_plan();
        let staging = Hash256::parse("b".repeat(64)).unwrap();
        let expected = create_destination_intent(
            &release,
            &plan,
            &staging,
            DestinationTransition::CopyVerifiedPayload,
        )
        .unwrap();

        let mut reordered = expected.clone();
        reordered.artifacts.swap(0, 1);
        assert!(
            validate_destination_intent(
                &reordered,
                &release,
                &plan,
                &staging,
                DestinationTransition::CopyVerifiedPayload
            )
            .is_err()
        );

        let mut missing = expected.clone();
        missing.artifacts.pop();
        assert!(
            validate_destination_intent(
                &missing,
                &release,
                &plan,
                &staging,
                DestinationTransition::CopyVerifiedPayload
            )
            .is_err()
        );

        let mut fingerprint = expected;
        fingerprint.partition_fingerprint = Hash256::parse("c".repeat(64)).unwrap();
        assert!(
            validate_destination_intent(
                &fingerprint,
                &release,
                &plan,
                &staging,
                DestinationTransition::CopyVerifiedPayload
            )
            .is_err()
        );
    }

    #[test]
    fn action_intent_record_is_bound_without_a_commit_hash_cycle() {
        let (release, plan) = release_and_plan();
        let staging = Hash256::parse("d".repeat(64)).unwrap();
        let intent = create_destination_intent(
            &release,
            &plan,
            &staging,
            DestinationTransition::StageInstallerLoader,
        )
        .unwrap();
        let record = create_destination_action_intent_record(
            None,
            &intent,
            &release,
            &plan,
            &staging,
            DestinationTransition::StageInstallerLoader,
        )
        .unwrap();
        assert_eq!(record.precondition_hash, canonical_sha256(&intent).unwrap());
        assert_eq!(record.record_type, JournalRecordType::ActionIntent);
        assert!(record.postcondition_hash.is_none());

        let mut wrong_actor = intent.clone();
        wrong_actor.actor = "linux_installer".into();
        let mut wrong_phase = intent.clone();
        wrong_phase.partition_phase = PartitionFingerprintPhase::Installed;
        let mut wrong_placement = intent.clone();
        wrong_placement.artifacts[0].destination.placement =
            DestinationPlacement::RootImageDeployment;
        for invalid in [wrong_actor, wrong_phase, wrong_placement] {
            assert!(
                create_destination_action_intent_record(
                    None,
                    &invalid,
                    &release,
                    &plan,
                    &staging,
                    DestinationTransition::StageInstallerLoader,
                )
                .is_err()
            );
        }
        assert!(
            create_destination_action_intent_record(
                None,
                &intent,
                &release,
                &plan,
                &staging,
                DestinationTransition::DeployJstackImage,
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_destination_contracts_reject_unknown_fields() {
        let (release, plan) = release_and_plan();
        let staging = Hash256::parse("e".repeat(64)).unwrap();
        let intent = create_destination_intent(
            &release,
            &plan,
            &staging,
            DestinationTransition::DeployJstackImage,
        )
        .unwrap();
        let mut value = serde_json::to_value(intent).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<DestinationIntentEvidence>(value).is_err());
    }

    #[test]
    fn generated_commit_is_runtime_bound_and_cross_field_tampering_is_rejected() {
        let (release, plan) = release_and_plan();
        let intent: DestinationIntentEvidence =
            serde_json::from_str(include_str!("../generated/example-destination-intent.json"))
                .unwrap();
        let commit: DestinationCommitEvidence =
            serde_json::from_str(include_str!("../generated/example-destination-commit.json"))
                .unwrap();
        let transition = DestinationTransition::CopyVerifiedPayload;
        let action_intent = create_destination_action_intent_record(
            None,
            &intent,
            &release,
            &plan,
            &intent.staging_evidence_hash,
            transition,
        )
        .unwrap();
        validate_destination_commit(
            &commit,
            &intent,
            &action_intent,
            &release,
            &plan,
            &intent.staging_evidence_hash,
            transition,
        )
        .unwrap();

        let mut wrong_size = commit.clone();
        wrong_size.artifacts[0].written_size_bytes -= 1;
        assert!(
            validate_destination_commit(
                &wrong_size,
                &intent,
                &action_intent,
                &release,
                &plan,
                &intent.staging_evidence_hash,
                transition,
            )
            .is_err()
        );
        let mut wrong_digest = commit.clone();
        wrong_digest.artifacts[0].written_sha256 = Hash256::parse("f".repeat(64)).unwrap();
        assert!(
            validate_destination_commit(
                &wrong_digest,
                &intent,
                &action_intent,
                &release,
                &plan,
                &intent.staging_evidence_hash,
                transition,
            )
            .is_err()
        );
        let mut wrong_destination = commit;
        wrong_destination.artifacts[0].destination.partition_guid = Uuid::nil();
        assert!(
            validate_destination_commit(
                &wrong_destination,
                &intent,
                &action_intent,
                &release,
                &plan,
                &intent.staging_evidence_hash,
                transition,
            )
            .is_err()
        );
    }
}
