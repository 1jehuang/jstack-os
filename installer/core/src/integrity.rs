use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{CanonicalError, canonical_sha256};
use crate::model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDisplay {
    pub schema_version: u32,
    pub plan_hash: Hash256,
    pub disk_guid: uuid::Uuid,
    pub windows_partition_guid: uuid::Uuid,
    pub windows_original_size_bytes: u64,
    pub windows_target_size_bytes: u64,
    pub allocation_interval: ByteInterval,
    pub created_partitions: Vec<PlannedPartition>,
}

impl From<&InstallPlan> for PlanDisplay {
    fn from(plan: &InstallPlan) -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            plan_hash: plan.plan_hash.clone(),
            disk_guid: plan.body.disk_guid,
            windows_partition_guid: plan.body.windows_resize.partition_guid,
            windows_original_size_bytes: plan.body.windows_resize.original_size_bytes,
            windows_target_size_bytes: plan.body.windows_resize.target_size_bytes,
            allocation_interval: plan.body.allocation_interval,
            created_partitions: plan.body.created_partitions.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("unsupported contract schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("plan hash does not match the canonical plan body")]
    PlanHashMismatch,
    #[error("confirmation is not bound to the current plan")]
    ConfirmationPlanMismatch,
    #[error("confirmation display digest does not match the displayed plan")]
    ConfirmationDisplayMismatch,
    #[error("confirmation authorization is invalid")]
    InvalidAuthorization,
    #[error("journal sequence or previous-record hash is invalid")]
    InvalidJournalChain,
    #[error("journal record fields do not match its record type")]
    InvalidJournalRecord,
    #[error("failure evidence is not bound to its action intent")]
    InvalidFailureEvidence,
    #[error("handoff does not match the current plan, journal, or expected target")]
    InvalidHandoff,
    #[error("canonical hashing failed: {0}")]
    Canonical(#[from] CanonicalError),
}

pub fn validate_plan_hash(plan: &InstallPlan) -> Result<(), IntegrityError> {
    if plan.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(plan.schema_version));
    }
    if canonical_sha256(&plan.body)? != plan.plan_hash {
        return Err(IntegrityError::PlanHashMismatch);
    }
    Ok(())
}

pub fn create_confirmation(
    plan: &InstallPlan,
    displayed: &PlanDisplay,
    confirmed_at_unix_ms: u64,
) -> Result<Confirmation, IntegrityError> {
    validate_plan_hash(plan)?;
    if displayed != &PlanDisplay::from(plan) {
        return Err(IntegrityError::ConfirmationDisplayMismatch);
    }
    Ok(Confirmation {
        schema_version: CONTRACT_SCHEMA_VERSION,
        plan_hash: plan.plan_hash.clone(),
        display_digest: canonical_sha256(displayed)?,
        confirmed_at_unix_ms,
        authorization: "explicit_user_confirmation".into(),
    })
}

pub fn validate_confirmation(
    plan: &InstallPlan,
    displayed: &PlanDisplay,
    confirmation: &Confirmation,
) -> Result<(), IntegrityError> {
    validate_plan_hash(plan)?;
    if confirmation.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(
            confirmation.schema_version,
        ));
    }
    if confirmation.plan_hash != plan.plan_hash {
        return Err(IntegrityError::ConfirmationPlanMismatch);
    }
    if displayed != &PlanDisplay::from(plan)
        || confirmation.display_digest != canonical_sha256(displayed)?
    {
        return Err(IntegrityError::ConfirmationDisplayMismatch);
    }
    if confirmation.authorization != "explicit_user_confirmation" {
        return Err(IntegrityError::InvalidAuthorization);
    }
    Ok(())
}

pub fn hash_journal_record(record: &JournalRecord) -> Result<Hash256, IntegrityError> {
    Ok(canonical_sha256(record)?)
}

pub fn validate_journal_record(
    record: &JournalRecord,
    previous: Option<&JournalRecord>,
) -> Result<(), IntegrityError> {
    validate_journal_shape(record)?;
    let expected_sequence = previous.and_then(|record| record.sequence.checked_add(1));
    match previous {
        None if record.sequence == 0
            && record.previous_record_hash.is_none()
            && matches!(
                record.record_type,
                JournalRecordType::ActionIntent | JournalRecordType::StateAdvanced
            ) => {}
        Some(previous)
            if Some(record.sequence) == expected_sequence
                && record.previous_record_hash.as_ref()
                    == Some(&hash_journal_record(previous)?) =>
        {
            if record.plan_hash != previous.plan_hash || !valid_journal_phase(previous, record) {
                return Err(IntegrityError::InvalidJournalChain);
            }
        }
        _ => return Err(IntegrityError::InvalidJournalChain),
    }
    Ok(())
}

pub fn validate_journal_chain(records: &[JournalRecord]) -> Result<&JournalRecord, IntegrityError> {
    let (first, rest) = records
        .split_first()
        .ok_or(IntegrityError::InvalidJournalChain)?;
    validate_journal_record(first, None)?;
    let mut previous = first;
    for record in rest {
        validate_journal_record(record, Some(previous))?;
        previous = record;
    }
    Ok(previous)
}

fn valid_journal_phase(previous: &JournalRecord, current: &JournalRecord) -> bool {
    match (previous.record_type, current.record_type) {
        (JournalRecordType::ActionIntent, JournalRecordType::ActionCommitted) => {
            current.actor == previous.actor
                && current.transition_id == previous.transition_id
                && current.precondition_hash == previous.precondition_hash
        }
        (JournalRecordType::ActionIntent, JournalRecordType::ActionFailed) => {
            current.actor == previous.actor
                && current.transition_id == previous.transition_id
                && current.precondition_hash == previous.precondition_hash
        }
        (JournalRecordType::ActionCommitted, JournalRecordType::StateAdvanced) => {
            current.actor == previous.actor
                && current.transition_id == previous.transition_id
                && previous.postcondition_hash.as_ref() == Some(&current.precondition_hash)
        }
        (JournalRecordType::ActionFailed, JournalRecordType::StateAdvanced) => {
            current.actor == previous.actor
                && current.transition_id == previous.transition_id
                && previous.postcondition_hash.as_ref() == Some(&current.precondition_hash)
        }
        (JournalRecordType::StateAdvanced, JournalRecordType::ActionIntent) => true,
        (JournalRecordType::StateAdvanced, JournalRecordType::StateAdvanced) => {
            previous.postcondition_hash.as_ref() == Some(&current.precondition_hash)
        }
        _ => false,
    }
}

fn validate_journal_shape(record: &JournalRecord) -> Result<(), IntegrityError> {
    if record.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(record.schema_version));
    }
    let shape_valid = match record.record_type {
        JournalRecordType::ActionIntent => {
            record.postcondition_hash.is_none() && record.created_objects.is_empty()
        }
        JournalRecordType::ActionCommitted => record.postcondition_hash.is_some(),
        JournalRecordType::ActionFailed => record.postcondition_hash.is_some(),
        JournalRecordType::StateAdvanced => {
            record.postcondition_hash.is_some() && record.created_objects.is_empty()
        }
    };
    let mut object_ids = std::collections::BTreeSet::new();
    let objects_valid = record.created_objects.iter().all(|object| {
        !object.stable_id.is_empty() && object_ids.insert((object.kind, object.stable_id.as_str()))
    });
    if !shape_valid || !objects_valid || record.actor.is_empty() || record.transition_id.is_empty()
    {
        return Err(IntegrityError::InvalidJournalRecord);
    }
    Ok(())
}

pub fn create_failure_evidence(
    action_intent: &JournalRecord,
    graph_model_id: impl Into<String>,
    failure_state: impl Into<String>,
    error_class: FailureClass,
    no_committed_effect_hash: Hash256,
    residual_objects: Vec<RollbackObject>,
) -> Result<FailureEvidence, IntegrityError> {
    validate_journal_shape(action_intent)?;
    if action_intent.record_type != JournalRecordType::ActionIntent {
        return Err(IntegrityError::InvalidFailureEvidence);
    }
    let evidence = FailureEvidence {
        schema_version: CONTRACT_SCHEMA_VERSION,
        graph_model_id: graph_model_id.into(),
        transition_id: action_intent.transition_id.clone(),
        actor: action_intent.actor.clone(),
        plan_hash: action_intent.plan_hash.clone(),
        action_intent_record_hash: hash_journal_record(action_intent)?,
        failure_state: failure_state.into(),
        error_class,
        no_committed_effect_hash,
        residual_objects,
    };
    validate_failure_evidence(&evidence, action_intent)?;
    Ok(evidence)
}

pub fn validate_failure_evidence(
    evidence: &FailureEvidence,
    action_intent: &JournalRecord,
) -> Result<(), IntegrityError> {
    validate_journal_shape(action_intent)?;
    let mut residual_ids = std::collections::BTreeSet::new();
    let residuals_valid = evidence.residual_objects.iter().all(|object| {
        !object.stable_id.is_empty()
            && residual_ids.insert((object.kind, object.stable_id.as_str()))
    });
    if evidence.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(evidence.schema_version));
    }
    if action_intent.record_type != JournalRecordType::ActionIntent
        || evidence.graph_model_id.is_empty()
        || evidence.failure_state.is_empty()
        || evidence.transition_id != action_intent.transition_id
        || evidence.actor != action_intent.actor
        || evidence.plan_hash != action_intent.plan_hash
        || evidence.action_intent_record_hash != hash_journal_record(action_intent)?
        || !residuals_valid
    {
        return Err(IntegrityError::InvalidFailureEvidence);
    }
    Ok(())
}

pub fn create_action_failed_record(
    action_intent: &JournalRecord,
    evidence: &FailureEvidence,
) -> Result<JournalRecord, IntegrityError> {
    validate_failure_evidence(evidence, action_intent)?;
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: action_intent
            .sequence
            .checked_add(1)
            .ok_or(IntegrityError::InvalidJournalChain)?,
        previous_record_hash: Some(hash_journal_record(action_intent)?),
        actor: action_intent.actor.clone(),
        transition_id: action_intent.transition_id.clone(),
        record_type: JournalRecordType::ActionFailed,
        precondition_hash: action_intent.precondition_hash.clone(),
        postcondition_hash: Some(canonical_sha256(evidence)?),
        plan_hash: action_intent.plan_hash.clone(),
        created_objects: evidence.residual_objects.clone(),
    };
    validate_journal_record(&record, Some(action_intent))?;
    Ok(record)
}

pub fn create_failure_state_advanced_record(
    action_intent: &JournalRecord,
    action_failed: &JournalRecord,
    evidence: &FailureEvidence,
) -> Result<JournalRecord, IntegrityError> {
    let expected_failed = create_action_failed_record(action_intent, evidence)?;
    if action_failed != &expected_failed {
        return Err(IntegrityError::InvalidFailureEvidence);
    }
    let evidence_hash = canonical_sha256(evidence)?;
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: action_failed
            .sequence
            .checked_add(1)
            .ok_or(IntegrityError::InvalidJournalChain)?,
        previous_record_hash: Some(hash_journal_record(action_failed)?),
        actor: action_failed.actor.clone(),
        transition_id: action_failed.transition_id.clone(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: evidence_hash,
        postcondition_hash: Some(control_state_hash(&evidence.failure_state)?),
        plan_hash: action_failed.plan_hash.clone(),
        created_objects: Vec::new(),
    };
    validate_journal_record(&record, Some(action_failed))?;
    Ok(record)
}

pub fn control_state_hash(control_state: &str) -> Result<Hash256, IntegrityError> {
    Ok(canonical_sha256(&control_state)?)
}

fn validate_journal_for_handoff<'a>(
    plan: &InstallPlan,
    journal: &'a [JournalRecord],
    control_state: &str,
) -> Result<&'a JournalRecord, IntegrityError> {
    let head = validate_journal_chain(journal)?;
    // Generic core validation cannot prove graph targets for direct or failed
    // advances. They are useful for controller replay, but may not authorize a
    // cross-actor handoff until a graph-aware validator checks the transition
    // class, failure evidence, and exact target state.
    let graph_unvalidated_advance = journal.iter().enumerate().any(|(index, record)| {
        record.record_type == JournalRecordType::StateAdvanced
            && !matches!(
                index
                    .checked_sub(1)
                    .and_then(|previous| journal.get(previous))
                    .map(|record| record.record_type),
                Some(JournalRecordType::ActionCommitted)
            )
    });
    if head.plan_hash != plan.plan_hash
        || head.record_type != JournalRecordType::StateAdvanced
        || head.postcondition_hash.as_ref() != Some(&control_state_hash(control_state)?)
        || graph_unvalidated_advance
    {
        return Err(IntegrityError::InvalidHandoff);
    }
    validate_created_object_ownership(plan, journal)?;
    Ok(head)
}

fn validate_created_object_ownership(
    plan: &InstallPlan,
    journal: &[JournalRecord],
) -> Result<(), IntegrityError> {
    for record in journal {
        for object in &record.created_objects {
            let owned = match object.kind {
                RollbackObjectKind::BootEntry => {
                    matches!(
                        record.transition_id.as_str(),
                        "create_installer_entry" | "install_jstack_boot"
                    ) && is_actual_uefi_boot_id(&object.stable_id)
                }
                _ => plan.body.rollback_objects.contains(object),
            };
            if !owned {
                return Err(IntegrityError::InvalidHandoff);
            }
        }
    }
    Ok(())
}

pub fn journaled_rollback_objects(
    plan: &InstallPlan,
    journal: &[JournalRecord],
) -> Result<Vec<RollbackObject>, IntegrityError> {
    validate_plan_hash(plan)?;
    let head = validate_journal_chain(journal)?;
    if head.plan_hash != plan.plan_hash {
        return Err(IntegrityError::InvalidJournalChain);
    }
    validate_created_object_ownership(plan, journal)?;
    let mut seen = std::collections::BTreeSet::new();
    Ok(journal
        .iter()
        .filter(|record| {
            matches!(
                record.record_type,
                JournalRecordType::ActionCommitted | JournalRecordType::ActionFailed
            )
        })
        .flat_map(|record| record.created_objects.iter())
        .filter(|object| seen.insert((object.kind, object.stable_id.clone())))
        .cloned()
        .collect())
}

fn is_actual_uefi_boot_id(stable_id: &str) -> bool {
    stable_id.strip_prefix("uefi:Boot").is_some_and(|suffix| {
        suffix.len() == 4
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    })
}

pub fn create_handoff(
    plan: &InstallPlan,
    journal: &[JournalRecord],
    control_state: impl Into<String>,
    intended_boot_target: impl Into<String>,
    nonce: impl Into<String>,
    staging_evidence_hash: &Hash256,
    partition_phase: PartitionFingerprintPhase,
) -> Result<Handoff, IntegrityError> {
    validate_plan_hash(plan)?;
    let control_state = control_state.into();
    let intended_boot_target = intended_boot_target.into();
    let nonce = nonce.into();
    if control_state.is_empty() || intended_boot_target.is_empty() || nonce.is_empty() {
        return Err(IntegrityError::InvalidHandoff);
    }
    let journal_head = validate_journal_for_handoff(plan, journal, &control_state)?;
    Ok(Handoff {
        schema_version: CONTRACT_SCHEMA_VERSION,
        graph_model_id: plan.body.state_model_id.clone(),
        control_state,
        journal_head_hash: hash_journal_record(journal_head)?,
        release_manifest_hash: plan.body.release_manifest_hash.clone(),
        staging_evidence_hash: staging_evidence_hash.clone(),
        plan_hash: plan.plan_hash.clone(),
        disk_guid: plan.body.disk_guid,
        partition_phase,
        partition_fingerprint: plan
            .body
            .partition_fingerprints
            .for_phase(partition_phase)
            .clone(),
        intended_boot_target,
        nonce,
    })
}

pub fn validate_handoff(
    handoff: &Handoff,
    plan: &InstallPlan,
    journal: &[JournalRecord],
    expected_state: &str,
    expected_boot_target: &str,
    expected_staging_evidence_hash: &Hash256,
    expected_partition_phase: PartitionFingerprintPhase,
) -> Result<(), IntegrityError> {
    validate_plan_hash(plan)?;
    let journal_head = validate_journal_for_handoff(plan, journal, expected_state)?;
    if handoff.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(handoff.schema_version));
    }
    if handoff.graph_model_id != plan.body.state_model_id
        || handoff.control_state != expected_state
        || handoff.journal_head_hash != hash_journal_record(journal_head)?
        || journal_head.plan_hash != plan.plan_hash
        || handoff.release_manifest_hash != plan.body.release_manifest_hash
        || handoff.staging_evidence_hash != *expected_staging_evidence_hash
        || handoff.plan_hash != plan.plan_hash
        || handoff.disk_guid != plan.body.disk_guid
        || handoff.partition_phase != expected_partition_phase
        || handoff.partition_fingerprint
            != *plan
                .body
                .partition_fingerprints
                .for_phase(expected_partition_phase)
        || handoff.intended_boot_target != expected_boot_target
        || handoff.nonce.is_empty()
    {
        return Err(IntegrityError::InvalidHandoff);
    }
    Ok(())
}

pub fn validate_observed_partition_fingerprint(
    handoff: &Handoff,
    observed: &Hash256,
) -> Result<(), IntegrityError> {
    if &handoff.partition_fingerprint != observed {
        return Err(IntegrityError::InvalidHandoff);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::tests_support::fixture;

    fn hash(byte: &str) -> Hash256 {
        Hash256::parse(byte.repeat(64)).unwrap()
    }

    fn append_transition(
        journal: &mut Vec<JournalRecord>,
        plan: &InstallPlan,
        transition_id: &str,
        resulting_state: &str,
        created_objects: Vec<RollbackObject>,
    ) {
        let sequence = journal.len() as u64;
        let previous_record_hash = journal
            .last()
            .map(|record| hash_journal_record(record).unwrap());
        let precondition_hash = hash("1");
        let action_postcondition_hash = hash("2");
        let intent = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence,
            previous_record_hash,
            actor: "windows_bootstrap".into(),
            transition_id: transition_id.into(),
            record_type: JournalRecordType::ActionIntent,
            precondition_hash: precondition_hash.clone(),
            postcondition_hash: None,
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        let committed = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: sequence + 1,
            previous_record_hash: Some(hash_journal_record(&intent).unwrap()),
            actor: "windows_bootstrap".into(),
            transition_id: transition_id.into(),
            record_type: JournalRecordType::ActionCommitted,
            precondition_hash,
            postcondition_hash: Some(action_postcondition_hash.clone()),
            plan_hash: plan.plan_hash.clone(),
            created_objects,
        };
        let advanced = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: sequence + 2,
            previous_record_hash: Some(hash_journal_record(&committed).unwrap()),
            actor: "windows_bootstrap".into(),
            transition_id: transition_id.into(),
            record_type: JournalRecordType::StateAdvanced,
            precondition_hash: action_postcondition_hash,
            postcondition_hash: Some(control_state_hash(resulting_state).unwrap()),
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        journal.extend([intent, committed, advanced]);
    }

    #[test]
    fn confirmation_binds_exact_plan_and_display() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let display = PlanDisplay::from(&plan);
        let confirmation = create_confirmation(&plan, &display, 42).unwrap();
        validate_confirmation(&plan, &display, &confirmation).unwrap();

        let mut altered = display.clone();
        altered.windows_target_size_bytes += 1;
        assert!(matches!(
            create_confirmation(&plan, &altered, 42),
            Err(IntegrityError::ConfirmationDisplayMismatch)
        ));
        assert!(matches!(
            validate_confirmation(&plan, &altered, &confirmation),
            Err(IntegrityError::ConfirmationDisplayMismatch)
        ));

        let forged = Confirmation {
            schema_version: CONTRACT_SCHEMA_VERSION,
            plan_hash: plan.plan_hash.clone(),
            display_digest: canonical_sha256(&altered).unwrap(),
            confirmed_at_unix_ms: 42,
            authorization: "explicit_user_confirmation".into(),
        };
        assert!(matches!(
            validate_confirmation(&plan, &altered, &forged),
            Err(IntegrityError::ConfirmationDisplayMismatch)
        ));
    }

    #[test]
    fn plan_body_tampering_is_detected() {
        let (inventory, requirements) = fixture();
        let mut plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        plan.body.created_partitions[1].size_bytes -= 1;
        assert!(matches!(
            validate_plan_hash(&plan),
            Err(IntegrityError::PlanHashMismatch)
        ));
    }

    #[test]
    fn journal_chain_and_handoff_are_hash_bound() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let mut journal = vec![];
        let esp_path = plan
            .body
            .rollback_objects
            .iter()
            .find(|object| object.kind == RollbackObjectKind::EspPath)
            .unwrap()
            .clone();
        append_transition(
            &mut journal,
            &plan,
            "stage_installer_loader",
            "windows.installer_loader_files_staged",
            vec![esp_path],
        );
        append_transition(
            &mut journal,
            &plan,
            "create_installer_entry",
            "windows.installer_loader_staged",
            vec![RollbackObject {
                kind: RollbackObjectKind::BootEntry,
                stable_id: "uefi:Boot0007".into(),
            }],
        );
        append_transition(
            &mut journal,
            &plan,
            "reboot_to_installer",
            "windows.reboot_to_installer_pending",
            vec![],
        );
        validate_journal_chain(&journal).unwrap();
        assert_eq!(
            journaled_rollback_objects(&plan, &journal).unwrap().len(),
            2
        );
        let handoff = create_handoff(
            &plan,
            &journal,
            "windows.reboot_to_installer_pending",
            "installer",
            "nonce-1",
            &hash("e"),
            PartitionFingerprintPhase::WindowsHandoff,
        )
        .unwrap();
        validate_handoff(
            &handoff,
            &plan,
            &journal,
            "windows.reboot_to_installer_pending",
            "installer",
            &hash("e"),
            PartitionFingerprintPhase::WindowsHandoff,
        )
        .unwrap();
        let mut altered_evidence = handoff.clone();
        altered_evidence.staging_evidence_hash = hash("f");
        assert!(matches!(
            validate_handoff(
                &altered_evidence,
                &plan,
                &journal,
                "windows.reboot_to_installer_pending",
                "installer",
                &hash("e"),
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            Err(IntegrityError::InvalidHandoff)
        ));
        validate_observed_partition_fingerprint(
            &handoff,
            &plan.body.partition_fingerprints.windows_handoff,
        )
        .unwrap();
        assert!(
            validate_observed_partition_fingerprint(
                &handoff,
                &plan.body.partition_fingerprints.source
            )
            .is_err()
        );

        assert!(matches!(
            create_handoff(
                &plan,
                &journal[..journal.len() - 1],
                "windows.reboot_to_installer_pending",
                "installer",
                "nonce-1",
                &hash("e"),
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            Err(IntegrityError::InvalidHandoff)
        ));
    }

    #[test]
    fn journal_rejects_invalid_phase_or_mismatched_transition() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let committed = JournalRecord {
            schema_version: 1,
            sequence: 0,
            previous_record_hash: None,
            actor: "windows_bootstrap".into(),
            transition_id: "reserve_windows_space".into(),
            record_type: JournalRecordType::ActionCommitted,
            precondition_hash: hash("1"),
            postcondition_hash: Some(hash("2")),
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        assert!(matches!(
            validate_journal_record(&committed, None),
            Err(IntegrityError::InvalidJournalChain)
        ));

        let mut intent = committed.clone();
        intent.record_type = JournalRecordType::ActionIntent;
        intent.postcondition_hash = None;
        validate_journal_record(&intent, None).unwrap();
        let mut mismatched = committed;
        mismatched.sequence = 1;
        mismatched.previous_record_hash = Some(hash_journal_record(&intent).unwrap());
        mismatched.transition_id = "format_xbootldr".into();
        assert!(matches!(
            validate_journal_record(&mismatched, Some(&intent)),
            Err(IntegrityError::InvalidJournalChain)
        ));
    }

    #[test]
    fn handoff_rejects_unowned_rollback_identity() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let mut journal = vec![];
        append_transition(
            &mut journal,
            &plan,
            "stage_installer_loader",
            "windows.installer_loader_files_staged",
            vec![RollbackObject {
                kind: RollbackObjectKind::EspPath,
                stable_id: r"esp:foreign;path:\EFI\JStack".into(),
            }],
        );
        assert!(matches!(
            create_handoff(
                &plan,
                &journal,
                "windows.installer_loader_files_staged",
                "installer",
                "nonce-1",
                &hash("e"),
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            Err(IntegrityError::InvalidHandoff)
        ));
    }

    #[test]
    fn failure_records_bind_evidence_and_advance_only_through_state_advanced() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let residual = plan.body.rollback_objects[0].clone();
        let intent = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: 0,
            previous_record_hash: None,
            actor: "windows_bootstrap".into(),
            transition_id: "shrink_windows".into(),
            record_type: JournalRecordType::ActionIntent,
            precondition_hash: hash("1"),
            postcondition_hash: None,
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        let evidence = create_failure_evidence(
            &intent,
            "jstack-no-usb-dual-boot-v1",
            "recovery.rollback_required",
            FailureClass::ExecutorFailed,
            hash("9"),
            vec![residual.clone()],
        )
        .unwrap();
        let failed = create_action_failed_record(&intent, &evidence).unwrap();
        let advanced = create_failure_state_advanced_record(&intent, &failed, &evidence).unwrap();

        validate_journal_chain(&[intent.clone(), failed.clone(), advanced.clone()]).unwrap();
        assert_eq!(failed.created_objects, vec![residual.clone()]);
        assert_eq!(
            failed.postcondition_hash,
            Some(canonical_sha256(&evidence).unwrap())
        );
        assert_eq!(
            advanced.postcondition_hash,
            Some(control_state_hash("recovery.rollback_required").unwrap())
        );
        assert_eq!(
            journaled_rollback_objects(&plan, &[intent.clone(), failed.clone(), advanced.clone()],)
                .unwrap(),
            vec![residual]
        );
        assert!(matches!(
            create_handoff(
                &plan,
                &[intent.clone(), failed.clone(), advanced.clone()],
                "recovery.rollback_required",
                "installer",
                "nonce-failure",
                &hash("e"),
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            Err(IntegrityError::InvalidHandoff)
        ));

        let mut forged = evidence.clone();
        forged.failure_state = "terminal.completed".into();
        assert!(matches!(
            create_failure_state_advanced_record(&intent, &failed, &forged),
            Err(IntegrityError::InvalidFailureEvidence)
        ));

        let mut committed = failed.clone();
        committed.record_type = JournalRecordType::ActionCommitted;
        assert!(matches!(
            validate_journal_record(&failed, Some(&committed)),
            Err(IntegrityError::InvalidJournalChain)
        ));
    }

    #[test]
    fn direct_state_advances_require_hash_continuity() {
        let (inventory, requirements) = fixture();
        let plan =
            crate::planner::create_install_plan_unverified(&inventory, &requirements).unwrap();
        let first = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: 0,
            previous_record_hash: None,
            actor: "windows_bootstrap".into(),
            transition_id: "acquire_release_manifest".into(),
            record_type: JournalRecordType::StateAdvanced,
            precondition_hash: control_state_hash("windows.preflight_complete").unwrap(),
            postcondition_hash: Some(control_state_hash("windows.release_manifest_ready").unwrap()),
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        validate_journal_record(&first, None).unwrap();
        let second = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: 1,
            previous_record_hash: Some(hash_journal_record(&first).unwrap()),
            actor: "windows_bootstrap".into(),
            transition_id: "verify_release_manifest".into(),
            record_type: JournalRecordType::StateAdvanced,
            precondition_hash: first.postcondition_hash.clone().unwrap(),
            postcondition_hash: Some(control_state_hash("windows.release_verified").unwrap()),
            plan_hash: plan.plan_hash.clone(),
            created_objects: vec![],
        };
        validate_journal_chain(&[first.clone(), second.clone()]).unwrap();
        assert!(matches!(
            create_handoff(
                &plan,
                &[first.clone(), second.clone()],
                "windows.release_verified",
                "installer",
                "nonce-direct",
                &hash("e"),
                PartitionFingerprintPhase::WindowsHandoff,
            ),
            Err(IntegrityError::InvalidHandoff)
        ));

        let mut discontinuous = second;
        discontinuous.precondition_hash = hash("f");
        assert!(matches!(
            validate_journal_record(&discontinuous, Some(&first)),
            Err(IntegrityError::InvalidJournalChain)
        ));
    }

    #[test]
    fn persisted_contract_examples_are_semantically_valid() {
        let plan: InstallPlan =
            serde_json::from_str(include_str!("../generated/example-plan.json")).unwrap();
        let display: PlanDisplay =
            serde_json::from_str(include_str!("../generated/example-plan-display.json")).unwrap();
        let confirmation: Confirmation =
            serde_json::from_str(include_str!("../generated/example-confirmation.json")).unwrap();
        let journal: Vec<JournalRecord> =
            serde_json::from_str(include_str!("../generated/example-journal-chain.json")).unwrap();
        let failure_evidence: FailureEvidence =
            serde_json::from_str(include_str!("../generated/example-failure-evidence.json"))
                .unwrap();
        let failure_journal: Vec<JournalRecord> = serde_json::from_str(include_str!(
            "../generated/example-failure-journal-chain.json"
        ))
        .unwrap();
        let handoff: Handoff =
            serde_json::from_str(include_str!("../generated/example-handoff.json")).unwrap();
        let staging_evidence: serde_json::Value =
            serde_json::from_str(include_str!("../../staging/fixtures/staging-evidence.json"))
                .unwrap();
        let staging_evidence_hash = canonical_sha256(&staging_evidence).unwrap();

        validate_plan_hash(&plan).unwrap();
        validate_confirmation(&plan, &display, &confirmation).unwrap();
        validate_journal_chain(&journal).unwrap();
        validate_journal_chain(&failure_journal).unwrap();
        validate_failure_evidence(&failure_evidence, &failure_journal[0]).unwrap();
        assert_eq!(
            create_action_failed_record(&failure_journal[0], &failure_evidence).unwrap(),
            failure_journal[1]
        );
        assert_eq!(
            create_failure_state_advanced_record(
                &failure_journal[0],
                &failure_journal[1],
                &failure_evidence,
            )
            .unwrap(),
            failure_journal[2]
        );
        validate_handoff(
            &handoff,
            &plan,
            &journal,
            "windows.reboot_to_installer_pending",
            "installer",
            &staging_evidence_hash,
            PartitionFingerprintPhase::WindowsHandoff,
        )
        .unwrap();

        assert_eq!(handoff.staging_evidence_hash, staging_evidence_hash);
    }
}
