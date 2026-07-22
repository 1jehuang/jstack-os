//! Pure, graph-bound interpretation of the durable mutation journal.
//!
//! This module performs no I/O and exposes no effect executor. It converts a
//! validated hash chain into one deterministic restart disposition while
//! independently enforcing graph adjacency, actor ownership, mutation class,
//! and exact success/failure control-state targets.

use jstack_installer_core::{
    CONTRACT_SCHEMA_VERSION, FailureEvidence, Hash256, IntegrityError, JournalRecord,
    JournalRecordType, control_state_hash, create_action_failed_record, hash_journal_record,
    validate_failure_evidence, validate_journal_chain, validate_journal_record,
};
use thiserror::Error;

use crate::{GraphModel, StateId, TransitionId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalDisposition {
    Quiescent {
        state: StateId,
    },
    ActionPending {
        state: StateId,
        transition: TransitionId,
    },
    CommitAdvancePending {
        state: StateId,
        transition: TransitionId,
    },
    FailureAdvancePending {
        state: StateId,
        transition: TransitionId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectOutcome {
    Success,
    Failure,
}

impl JournalDisposition {
    pub fn state(self) -> StateId {
        match self {
            Self::Quiescent { state }
            | Self::ActionPending { state, .. }
            | Self::CommitAdvancePending { state, .. }
            | Self::FailureAdvancePending { state, .. } => state,
        }
    }
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("journal hash chain or phase ordering is invalid: {0}")]
    InvalidChain(#[from] IntegrityError),
    #[error("journal is bound to a different confirmed plan")]
    PlanMismatch,
    #[error("journal names unknown transition {0}")]
    UnknownTransition(String),
    #[error("journal transition {transition} is not adjacent to state {state}")]
    NonAdjacent { state: String, transition: String },
    #[error("journal actor does not own transition {0}")]
    WrongActor(String),
    #[error("journal phase is incompatible with transition {0}")]
    WrongTransitionClass(String),
    #[error("journal success/failure state hash does not match transition {0}")]
    WrongStateHash(String),
    #[error("failed transition {0} has no graph failure edge")]
    MissingFailureTarget(String),
    #[error("journal disposition is not eligible for this state advancement")]
    WrongDisposition,
    #[error("failure evidence does not match the executable graph")]
    FailureEvidenceGraphMismatch,
    #[error("journal failure records and supplied failure evidence are not an exact set")]
    FailureEvidenceSetMismatch,
}

/// Derive one deterministic restart disposition from a complete journal.
///
/// Empty journals resolve to the graph's initial state. Every non-empty chain
/// is first validated by core, then folded against the exact typed graph. Only
/// `StateAdvanced` changes the derived control state.
pub fn derive_disposition(
    graph: &GraphModel,
    expected_plan_hash: &Hash256,
    records: &[JournalRecord],
    failure_evidence: &[FailureEvidence],
) -> Result<JournalDisposition, ReplayError> {
    if records.is_empty() {
        if !failure_evidence.is_empty() {
            return Err(ReplayError::FailureEvidenceSetMismatch);
        }
        return Ok(JournalDisposition::Quiescent {
            state: graph.initial_state(),
        });
    }
    validate_journal_chain(records)?;
    if records
        .iter()
        .any(|record| &record.plan_hash != expected_plan_hash)
    {
        return Err(ReplayError::PlanMismatch);
    }

    let mut state = graph.initial_state();
    let mut pending: Option<(TransitionId, JournalRecordType)> = None;
    let mut consumed_failure_evidence = 0usize;
    for (index, record) in records.iter().enumerate() {
        let transition_id = graph
            .transition_id(&record.transition_id)
            .ok_or_else(|| ReplayError::UnknownTransition(record.transition_id.clone()))?;
        let transition = graph.transition(transition_id);
        if record.actor != transition.def.actor {
            return Err(ReplayError::WrongActor(record.transition_id.clone()));
        }

        match record.record_type {
            JournalRecordType::ActionIntent => {
                require_adjacent(graph, state, transition_id)?;
                if !graph.is_mutating(transition_id) {
                    return Err(ReplayError::WrongTransitionClass(
                        record.transition_id.clone(),
                    ));
                }
                pending = Some((transition_id, JournalRecordType::ActionIntent));
            }
            JournalRecordType::ActionCommitted => {
                require_pending(
                    pending,
                    transition_id,
                    JournalRecordType::ActionIntent,
                    record,
                )?;
                pending = Some((transition_id, JournalRecordType::ActionCommitted));
            }
            JournalRecordType::ActionFailed => {
                require_pending(
                    pending,
                    transition_id,
                    JournalRecordType::ActionIntent,
                    record,
                )?;
                if transition.failure_to.is_none() {
                    return Err(ReplayError::MissingFailureTarget(
                        record.transition_id.clone(),
                    ));
                }
                let action_intent = records
                    .get(
                        index
                            .checked_sub(1)
                            .ok_or(ReplayError::FailureEvidenceSetMismatch)?,
                    )
                    .ok_or(ReplayError::FailureEvidenceSetMismatch)?;
                let intent_hash = hash_journal_record(action_intent)?;
                let mut matching = failure_evidence
                    .iter()
                    .filter(|evidence| evidence.action_intent_record_hash == intent_hash);
                let evidence = matching
                    .next()
                    .ok_or(ReplayError::FailureEvidenceSetMismatch)?;
                if matching.next().is_some() {
                    return Err(ReplayError::FailureEvidenceSetMismatch);
                }
                validate_failure_evidence_against_graph(graph, action_intent, evidence)?;
                if create_action_failed_record(action_intent, evidence)? != *record {
                    return Err(ReplayError::FailureEvidenceSetMismatch);
                }
                consumed_failure_evidence += 1;
                pending = Some((transition_id, JournalRecordType::ActionFailed));
            }
            JournalRecordType::StateAdvanced => {
                let target = match pending {
                    Some((pending_id, JournalRecordType::ActionCommitted))
                        if pending_id == transition_id =>
                    {
                        transition.to
                    }
                    Some((pending_id, JournalRecordType::ActionFailed))
                        if pending_id == transition_id =>
                    {
                        transition.failure_to.ok_or_else(|| {
                            ReplayError::MissingFailureTarget(record.transition_id.clone())
                        })?
                    }
                    None => {
                        require_adjacent(graph, state, transition_id)?;
                        if graph.is_mutating(transition_id) {
                            return Err(ReplayError::WrongTransitionClass(
                                record.transition_id.clone(),
                            ));
                        }
                        if record.precondition_hash != control_state_hash(&graph.state(state).id)? {
                            return Err(ReplayError::WrongStateHash(record.transition_id.clone()));
                        }
                        let success_hash = control_state_hash(&graph.state(transition.to).id)?;
                        if record.postcondition_hash.as_ref() == Some(&success_hash) {
                            transition.to
                        } else if let Some(failure) = transition.failure_to {
                            let failure_hash = control_state_hash(&graph.state(failure).id)?;
                            if record.postcondition_hash.as_ref() == Some(&failure_hash) {
                                failure
                            } else {
                                return Err(ReplayError::WrongStateHash(
                                    record.transition_id.clone(),
                                ));
                            }
                        } else {
                            return Err(ReplayError::WrongStateHash(record.transition_id.clone()));
                        }
                    }
                    _ => {
                        return Err(ReplayError::WrongTransitionClass(
                            record.transition_id.clone(),
                        ));
                    }
                };
                if record.postcondition_hash.as_ref()
                    != Some(&control_state_hash(&graph.state(target).id)?)
                {
                    return Err(ReplayError::WrongStateHash(record.transition_id.clone()));
                }
                state = target;
                pending = None;
            }
        }

        // A pending phase cannot be silently bypassed by the next record. Core
        // rejects that phase ordering, while this assertion documents the
        // fold's one-triad invariant and catches future enum extensions.
        if index + 1 < records.len()
            && pending.is_some()
            && records[index + 1].transition_id != record.transition_id
        {
            return Err(ReplayError::WrongTransitionClass(
                record.transition_id.clone(),
            ));
        }
    }

    if consumed_failure_evidence != failure_evidence.len() {
        return Err(ReplayError::FailureEvidenceSetMismatch);
    }

    Ok(match pending {
        None => JournalDisposition::Quiescent { state },
        Some((transition, JournalRecordType::ActionIntent)) => {
            JournalDisposition::ActionPending { state, transition }
        }
        Some((transition, JournalRecordType::ActionCommitted)) => {
            JournalDisposition::CommitAdvancePending { state, transition }
        }
        Some((transition, JournalRecordType::ActionFailed)) => {
            JournalDisposition::FailureAdvancePending { state, transition }
        }
        Some((_, JournalRecordType::StateAdvanced)) => unreachable!("state advances are quiescent"),
    })
}

/// Create the only legal durable record for a non-mutating graph transition.
pub fn create_direct_state_advanced(
    graph: &GraphModel,
    expected_plan_hash: &Hash256,
    records: &[JournalRecord],
    failure_evidence: &[FailureEvidence],
    transition_id: TransitionId,
    outcome: DirectOutcome,
) -> Result<JournalRecord, ReplayError> {
    let state = match derive_disposition(graph, expected_plan_hash, records, failure_evidence)? {
        JournalDisposition::Quiescent { state } => state,
        _ => return Err(ReplayError::WrongDisposition),
    };
    require_adjacent(graph, state, transition_id)?;
    if graph.is_mutating(transition_id) {
        return Err(ReplayError::WrongTransitionClass(
            graph.transition(transition_id).def.id.clone(),
        ));
    }
    let transition = graph.transition(transition_id);
    let target = match outcome {
        DirectOutcome::Success => transition.to,
        DirectOutcome::Failure => transition
            .failure_to
            .ok_or_else(|| ReplayError::MissingFailureTarget(transition.def.id.clone()))?,
    };
    let previous = records.last();
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: previous.map_or(0, |record| record.sequence + 1),
        previous_record_hash: previous.map(hash_journal_record).transpose()?,
        actor: transition.def.actor.clone(),
        transition_id: transition.def.id.clone(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: control_state_hash(&graph.state(state).id)?,
        postcondition_hash: Some(control_state_hash(&graph.state(target).id)?),
        plan_hash: expected_plan_hash.clone(),
        created_objects: Vec::new(),
    };
    validate_journal_record(&record, previous)?;
    Ok(record)
}

/// Finish a durable success or failure action outcome with its sole legal
/// StateAdvanced record. The pending outcome is derived from the journal head,
/// never selected by the caller.
pub fn create_pending_state_advanced(
    graph: &GraphModel,
    expected_plan_hash: &Hash256,
    records: &[JournalRecord],
    failure_evidence: &[FailureEvidence],
) -> Result<JournalRecord, ReplayError> {
    let (transition_id, target) =
        match derive_disposition(graph, expected_plan_hash, records, failure_evidence)? {
            JournalDisposition::CommitAdvancePending { transition, .. } => {
                (transition, graph.transition(transition).to)
            }
            JournalDisposition::FailureAdvancePending { transition, .. } => (
                transition,
                graph.transition(transition).failure_to.ok_or_else(|| {
                    ReplayError::MissingFailureTarget(graph.transition(transition).def.id.clone())
                })?,
            ),
            _ => return Err(ReplayError::WrongDisposition),
        };
    let previous = records.last().ok_or(ReplayError::WrongDisposition)?;
    let transition = graph.transition(transition_id);
    let record = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: previous
            .sequence
            .checked_add(1)
            .ok_or(ReplayError::WrongDisposition)?,
        previous_record_hash: Some(hash_journal_record(previous)?),
        actor: transition.def.actor.clone(),
        transition_id: transition.def.id.clone(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: previous
            .postcondition_hash
            .clone()
            .ok_or(ReplayError::WrongDisposition)?,
        postcondition_hash: Some(control_state_hash(&graph.state(target).id)?),
        plan_hash: expected_plan_hash.clone(),
        created_objects: Vec::new(),
    };
    validate_journal_record(&record, Some(previous))?;
    Ok(record)
}

/// Validate the graph-specific portion of a durable failure proof.
///
/// Platform code must separately recompute `no_committed_effect_hash` before
/// this evidence may be appended. This function proves only identity, actor,
/// transition class, and the exact graph failure target.
pub fn validate_failure_evidence_against_graph(
    graph: &GraphModel,
    action_intent: &JournalRecord,
    evidence: &FailureEvidence,
) -> Result<TransitionId, ReplayError> {
    validate_failure_evidence(evidence, action_intent)?;
    let transition_id = graph
        .transition_id(&evidence.transition_id)
        .ok_or_else(|| ReplayError::UnknownTransition(evidence.transition_id.clone()))?;
    let transition = graph.transition(transition_id);
    let failure_state = transition
        .failure_to
        .map(|state| graph.state(state).id.as_str());
    if !graph.is_mutating(transition_id)
        || evidence.graph_model_id != graph.model_id()
        || evidence.actor != transition.def.actor
        || failure_state != Some(evidence.failure_state.as_str())
    {
        return Err(ReplayError::FailureEvidenceGraphMismatch);
    }
    Ok(transition_id)
}

fn require_adjacent(
    graph: &GraphModel,
    state: StateId,
    transition_id: TransitionId,
) -> Result<(), ReplayError> {
    let transition = graph.transition(transition_id);
    if transition.from != state {
        return Err(ReplayError::NonAdjacent {
            state: graph.state(state).id.clone(),
            transition: transition.def.id.clone(),
        });
    }
    Ok(())
}

fn require_pending(
    pending: Option<(TransitionId, JournalRecordType)>,
    transition_id: TransitionId,
    expected: JournalRecordType,
    record: &JournalRecord,
) -> Result<(), ReplayError> {
    if pending != Some((transition_id, expected)) {
        return Err(ReplayError::WrongTransitionClass(
            record.transition_id.clone(),
        ));
    }
    Ok(())
}
