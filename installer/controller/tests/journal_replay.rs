use jstack_installer_controller::{
    DirectOutcome, JournalDisposition, ReplayError, create_direct_state_advanced,
    create_pending_state_advanced, derive_disposition, load_verified,
    validate_failure_evidence_against_graph,
};
use jstack_installer_core::{
    CONTRACT_SCHEMA_VERSION, FailureClass, Hash256, JournalRecord, JournalRecordType,
    canonical_sha256, control_state_hash, create_action_failed_record, create_failure_evidence,
    create_failure_state_advanced_record, hash_journal_record,
};
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const GENERATED_FAILURE_EVIDENCE: &str =
    include_str!("../../core/generated/example-failure-evidence.json");
const GENERATED_FAILURE_JOURNAL: &str =
    include_str!("../../core/generated/example-failure-journal-chain.json");

fn hash(byte: &str) -> Hash256 {
    Hash256::parse(byte.repeat(64)).unwrap()
}

fn graph() -> jstack_installer_controller::GraphModel {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).unwrap()
}

fn intent(
    previous: Option<&JournalRecord>,
    plan_hash: &Hash256,
    transition_id: &str,
    actor: &str,
) -> JournalRecord {
    JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: previous.map_or(0, |record| record.sequence + 1),
        previous_record_hash: previous.map(|record| hash_journal_record(record).unwrap()),
        actor: actor.into(),
        transition_id: transition_id.into(),
        record_type: JournalRecordType::ActionIntent,
        precondition_hash: hash("1"),
        postcondition_hash: None,
        plan_hash: plan_hash.clone(),
        created_objects: vec![],
    }
}

fn committed(intent: &JournalRecord) -> JournalRecord {
    JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: intent.sequence + 1,
        previous_record_hash: Some(hash_journal_record(intent).unwrap()),
        actor: intent.actor.clone(),
        transition_id: intent.transition_id.clone(),
        record_type: JournalRecordType::ActionCommitted,
        precondition_hash: intent.precondition_hash.clone(),
        postcondition_hash: Some(hash("2")),
        plan_hash: intent.plan_hash.clone(),
        created_objects: vec![],
    }
}

fn advanced(previous: &JournalRecord, state: &str) -> JournalRecord {
    JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: previous.sequence + 1,
        previous_record_hash: Some(hash_journal_record(previous).unwrap()),
        actor: previous.actor.clone(),
        transition_id: previous.transition_id.clone(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: previous.postcondition_hash.clone().unwrap(),
        postcondition_hash: Some(control_state_hash(state).unwrap()),
        plan_hash: previous.plan_hash.clone(),
        created_objects: vec![],
    }
}

fn begin_preflight_success(plan_hash: &Hash256) -> Vec<JournalRecord> {
    let intent = intent(None, plan_hash, "begin_preflight", "windows_bootstrap");
    let committed = committed(&intent);
    let advanced = advanced(&committed, "windows.staging_reconciled");
    vec![intent, committed, advanced]
}

fn direct_advance(
    previous: &JournalRecord,
    transition_id: &str,
    actor: &str,
    target: &str,
) -> JournalRecord {
    JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: previous.sequence + 1,
        previous_record_hash: Some(hash_journal_record(previous).unwrap()),
        actor: actor.into(),
        transition_id: transition_id.into(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: previous.postcondition_hash.clone().unwrap(),
        postcondition_hash: Some(control_state_hash(target).unwrap()),
        plan_hash: previous.plan_hash.clone(),
        created_objects: vec![],
    }
}

#[test]
fn restart_disposition_is_total_at_every_durable_phase() {
    let graph = graph();
    let plan_hash = hash("a");
    let records = begin_preflight_success(&plan_hash);
    let initial = graph.state(graph.initial_state()).id.clone();

    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[], &[]).unwrap(),
        JournalDisposition::Quiescent { state } if graph.state(state).id == initial
    ));
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &records[..1], &[]).unwrap(),
        JournalDisposition::ActionPending { state, transition }
            if graph.state(state).id == "windows.bootstrap_started"
                && graph.transition(transition).def.id == "begin_preflight"
    ));
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &records[..2], &[]).unwrap(),
        JournalDisposition::CommitAdvancePending { state, transition }
            if graph.state(state).id == "windows.bootstrap_started"
                && graph.transition(transition).def.id == "begin_preflight"
    ));
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &records, &[]).unwrap(),
        JournalDisposition::Quiescent { state }
            if graph.state(state).id == "windows.staging_reconciled"
    ));
}

#[test]
fn generated_failure_contract_replays_from_the_graph_initial_state() {
    let graph = graph();
    let evidence = serde_json::from_str(GENERATED_FAILURE_EVIDENCE).unwrap();
    let records: Vec<JournalRecord> = serde_json::from_str(GENERATED_FAILURE_JOURNAL).unwrap();
    let plan_hash = records[0].plan_hash.clone();

    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &records, &[evidence]).unwrap(),
        JournalDisposition::Quiescent { state }
            if graph.state(state).id == "terminal.manual_recovery"
    ));
}

#[test]
fn action_failed_requires_the_exact_graph_failure_advance() {
    let graph = graph();
    let plan_hash = hash("a");
    let intent = intent(None, &plan_hash, "begin_preflight", "windows_bootstrap");
    let evidence = create_failure_evidence(
        &intent,
        graph.model_id(),
        "terminal.manual_recovery",
        FailureClass::InjectedFault,
        hash("8"),
        vec![],
    )
    .unwrap();
    let failed = create_action_failed_record(&intent, &evidence).unwrap();
    assert_eq!(
        validate_failure_evidence_against_graph(&graph, &intent, &evidence).unwrap(),
        graph.transition_id("begin_preflight").unwrap()
    );
    let advanced = create_failure_state_advanced_record(&intent, &failed, &evidence).unwrap();
    assert_eq!(
        create_pending_state_advanced(
            &graph,
            &plan_hash,
            &[intent.clone(), failed.clone()],
            std::slice::from_ref(&evidence),
        )
        .unwrap(),
        advanced
    );

    assert!(matches!(
        derive_disposition(
            &graph,
            &plan_hash,
            &[intent.clone(), failed.clone()],
            std::slice::from_ref(&evidence),
        )
        .unwrap(),
        JournalDisposition::FailureAdvancePending { state, transition }
            if graph.state(state).id == "windows.bootstrap_started"
                && graph.transition(transition).def.id == "begin_preflight"
    ));
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[intent.clone(), failed.clone()], &[],),
        Err(ReplayError::FailureEvidenceSetMismatch)
    ));
    assert!(matches!(
        derive_disposition(
            &graph,
            &plan_hash,
            &[intent.clone(), failed.clone()],
            &[evidence.clone(), evidence.clone()],
        ),
        Err(ReplayError::FailureEvidenceSetMismatch)
    ));
    assert!(matches!(
        derive_disposition(
            &graph,
            &plan_hash,
            &[intent.clone(), failed.clone(), advanced.clone()],
            std::slice::from_ref(&evidence),
        )
        .unwrap(),
        JournalDisposition::Quiescent { state }
            if graph.state(state).id == "terminal.manual_recovery"
    ));

    let mut wrong_target = advanced;
    wrong_target.postcondition_hash =
        Some(control_state_hash("windows.staging_reconciled").unwrap());
    assert!(matches!(
        derive_disposition(
            &graph,
            &plan_hash,
            &[intent.clone(), failed.clone(), wrong_target],
            std::slice::from_ref(&evidence),
        ),
        Err(ReplayError::WrongStateHash(_))
    ));

    let mut wrong_graph = evidence.clone();
    wrong_graph.graph_model_id = "invented-model".into();
    assert!(matches!(
        validate_failure_evidence_against_graph(&graph, &intent, &wrong_graph),
        Err(ReplayError::FailureEvidenceGraphMismatch)
    ));
    assert!(matches!(
        derive_disposition(
            &graph,
            &plan_hash,
            &[intent.clone(), failed],
            std::slice::from_ref(&wrong_graph),
        ),
        Err(ReplayError::FailureEvidenceGraphMismatch)
    ));

    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[], std::slice::from_ref(&evidence)),
        Err(ReplayError::FailureEvidenceSetMismatch)
    ));
}

#[test]
fn direct_non_mutating_success_and_failure_edges_are_durable() {
    let graph = graph();
    let plan_hash = hash("a");
    let prefix = begin_preflight_success(&plan_hash);
    let success = direct_advance(
        prefix.last().unwrap(),
        "acquire_release_manifest",
        "windows_bootstrap",
        "windows.release_manifest_verified",
    );
    assert_eq!(
        create_direct_state_advanced(
            &graph,
            &plan_hash,
            &prefix,
            &[],
            graph.transition_id("acquire_release_manifest").unwrap(),
            DirectOutcome::Success,
        )
        .unwrap(),
        success
    );
    let mut success_chain = prefix.clone();
    success_chain.push(success);
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &success_chain, &[]).unwrap(),
        JournalDisposition::Quiescent { state }
            if graph.state(state).id == "windows.release_manifest_verified"
    ));

    let failure = direct_advance(
        prefix.last().unwrap(),
        "acquire_release_manifest",
        "windows_bootstrap",
        "windows.release_acquisition_failed",
    );
    assert_eq!(
        create_direct_state_advanced(
            &graph,
            &plan_hash,
            &prefix,
            &[],
            graph.transition_id("acquire_release_manifest").unwrap(),
            DirectOutcome::Failure,
        )
        .unwrap(),
        failure
    );
    let mut failure_chain = prefix;
    failure_chain.push(failure);
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &failure_chain, &[]).unwrap(),
        JournalDisposition::Quiescent { state }
            if graph.state(state).id == "windows.release_acquisition_failed"
    ));
}

#[test]
fn replay_rejects_skips_wrong_actors_direct_mutations_and_plan_drift() {
    let graph = graph();
    let plan_hash = hash("a");

    let skipped = intent(
        None,
        &plan_hash,
        "reserve_windows_space",
        "windows_bootstrap",
    );
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[skipped], &[]),
        Err(ReplayError::NonAdjacent { .. })
    ));

    let wrong_actor = intent(None, &plan_hash, "begin_preflight", "linux_installer");
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[wrong_actor], &[]),
        Err(ReplayError::WrongActor(_))
    ));

    let direct_mutation = JournalRecord {
        schema_version: CONTRACT_SCHEMA_VERSION,
        sequence: 0,
        previous_record_hash: None,
        actor: "windows_bootstrap".into(),
        transition_id: "begin_preflight".into(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: control_state_hash("windows.bootstrap_started").unwrap(),
        postcondition_hash: Some(control_state_hash("windows.staging_reconciled").unwrap()),
        plan_hash: plan_hash.clone(),
        created_objects: vec![],
    };
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[direct_mutation], &[]),
        Err(ReplayError::WrongTransitionClass(_))
    ));

    let records = begin_preflight_success(&plan_hash);
    assert!(matches!(
        derive_disposition(&graph, &hash("b"), &records, &[]),
        Err(ReplayError::PlanMismatch)
    ));
}

#[test]
fn replay_rejects_unknown_transition_and_non_graph_state_hashes() {
    let graph = graph();
    let plan_hash = hash("a");
    let mut unknown = intent(None, &plan_hash, "begin_preflight", "windows_bootstrap");
    unknown.transition_id = "invented_transition".into();
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &[unknown], &[]),
        Err(ReplayError::UnknownTransition(_))
    ));

    let mut records = begin_preflight_success(&plan_hash);
    records[2].postcondition_hash = Some(canonical_sha256(&"invented.state").unwrap());
    assert!(matches!(
        derive_disposition(&graph, &plan_hash, &records, &[]),
        Err(ReplayError::WrongStateHash(_))
    ));
}
