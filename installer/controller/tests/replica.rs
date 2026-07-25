use jstack_installer_controller::replica;
use jstack_installer_controller::{GraphModel, load_verified};
use jstack_installer_core::{
    Confirmation, Handoff, Hash256, InstallPlan, JournalRecord, JournalRecordType, PlanDisplay,
    canonical_sha256, control_state_hash, hash_journal_record,
};
use sha2::{Digest, Sha256};

use jstack_installer_controller::replica::{
    ReplicaError, ReplicaId, accept_authenticated_handoff, authenticate_confirmation_object,
    authenticate_handoff_object, authenticate_journal_replica, empty_nonce_ledger,
    journal_identity, reconcile_authenticated_replicas, restore_nonce_ledger,
    validate_authentication_authority, verify_authenticated_confirmation,
    verify_authenticated_handoff,
};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const PLAN: &str = include_str!("../../core/generated/example-plan.json");
const DISPLAY: &str = include_str!("../../core/generated/example-plan-display.json");
const CONFIRMATION: &str = include_str!("../../core/generated/example-confirmation.json");
const JOURNAL: &str = include_str!("../../core/generated/example-journal-chain.json");
const HANDOFF: &str = include_str!("../../core/generated/example-handoff.json");

fn graph() -> GraphModel {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).unwrap()
}

fn authority() -> replica::AuthenticationAuthority {
    validate_authentication_authority(b"replica-test-authority-key-material-v1").unwrap()
}

fn plan() -> InstallPlan {
    serde_json::from_str(PLAN).unwrap()
}

fn fixture_journal() -> Vec<JournalRecord> {
    serde_json::from_str(JOURNAL).unwrap()
}

fn fixture_handoff() -> Handoff {
    serde_json::from_str(HANDOFF).unwrap()
}

fn hash(byte: char) -> Hash256 {
    Hash256::parse(byte.to_string().repeat(64)).unwrap()
}

fn direct_advance(
    previous: Option<&JournalRecord>,
    plan_hash: &Hash256,
    actor: &str,
    transition_id: &str,
    target_state: &str,
) -> JournalRecord {
    JournalRecord {
        schema_version: 1,
        sequence: previous.map_or(0, |record| record.sequence + 1),
        previous_record_hash: previous.map(|record| hash_journal_record(record).unwrap()),
        actor: actor.into(),
        transition_id: transition_id.into(),
        record_type: JournalRecordType::StateAdvanced,
        precondition_hash: previous
            .and_then(|record| record.postcondition_hash.clone())
            .unwrap_or_else(|| hash('1')),
        postcondition_hash: Some(control_state_hash(target_state).unwrap()),
        plan_hash: plan_hash.clone(),
        created_objects: vec![],
    }
}

#[test]
fn happy_reconciliation_authenticates_exact_identity_confirmation_and_handoff() {
    let graph = graph();
    let authority = authority();
    let plan = plan();
    let release_hash = plan.body.release_manifest_hash.clone();
    let journal = fixture_journal();

    let identity = journal_identity(&graph, &plan.plan_hash, &release_hash, &journal).unwrap();
    assert_eq!(identity.graph_model_id(), graph.model_id());
    assert_eq!(identity.graph_digest(), graph.digest());
    assert_eq!(identity.plan_hash(), &plan.plan_hash);
    assert_eq!(identity.release_manifest_hash(), &release_hash);
    assert_eq!(identity.journal_len(), journal.len() as u64);
    assert_eq!(
        identity.journal_head_hash(),
        &hash_journal_record(journal.last().unwrap()).unwrap()
    );
    assert_eq!(
        identity,
        journal_identity(&graph, &plan.plan_hash, &release_hash, &journal).unwrap()
    );

    let windows = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan.plan_hash,
        &release_hash,
        journal.clone(),
    )
    .unwrap();
    let xbootldr = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::Xbootldr,
        &plan.plan_hash,
        &release_hash,
        journal.clone(),
    )
    .unwrap();
    let repeated_windows = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan.plan_hash,
        &release_hash,
        journal.clone(),
    )
    .unwrap();
    assert_eq!(windows.authentication(), repeated_windows.authentication());

    let reconciled = reconcile_authenticated_replicas(
        &authority,
        &graph,
        &plan.plan_hash,
        &release_hash,
        &[xbootldr, windows],
    )
    .unwrap();
    assert_eq!(reconciled.identity(), &identity);
    assert_eq!(reconciled.journal(), journal);
    assert_eq!(
        reconciled.replicas(),
        &[ReplicaId::WindowsSystemVolume, ReplicaId::Xbootldr]
    );

    let displayed: PlanDisplay = serde_json::from_str(DISPLAY).unwrap();
    let confirmation: Confirmation = serde_json::from_str(CONFIRMATION).unwrap();
    let authenticated_confirmation = authenticate_confirmation_object(
        &authority,
        &graph,
        reconciled.identity(),
        &plan,
        &displayed,
        confirmation,
    )
    .unwrap();
    verify_authenticated_confirmation(
        &authority,
        &graph,
        reconciled.identity(),
        &plan,
        &displayed,
        &authenticated_confirmation,
    )
    .unwrap();
    assert_eq!(
        authenticated_confirmation.authentication().purpose(),
        "confirmation"
    );

    let handoff = authenticate_handoff_object(
        &authority,
        &graph,
        &reconciled,
        fixture_handoff(),
        "linux_installer",
        "installer-handoff-v1",
    )
    .unwrap();
    verify_authenticated_handoff(&authority, &graph, &reconciled, &handoff).unwrap();
    assert_eq!(handoff.actor(), "windows_bootstrap");
    assert_eq!(handoff.next_actor(), "linux_installer");
    assert_eq!(handoff.transition_id(), "reboot_to_installer");
    assert_eq!(handoff.authentication().purpose(), "handoff");

    let mut ledger = empty_nonce_ledger();
    accept_authenticated_handoff(&authority, &graph, &reconciled, &handoff, &mut ledger).unwrap();
    assert!(ledger.contains("fixture-nonce-1").unwrap());
    let serialized = serde_json::to_vec(&ledger.snapshot()).unwrap();
    let snapshot = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(restore_nonce_ledger(&snapshot).unwrap(), ledger);
}

#[test]
fn reconciliation_rejects_authenticated_forks() {
    let graph = graph();
    let authority = authority();
    let plan_hash = hash('a');
    let release_hash = hash('b');
    let first_journal = vec![direct_advance(
        None,
        &plan_hash,
        "windows_bootstrap",
        "cancel_before_mutation",
        "terminal.cancelled",
    )];
    let second_journal = vec![direct_advance(
        None,
        &plan_hash,
        "windows_bootstrap",
        "reject_preflight",
        "terminal.unsupported",
    )];
    let first = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan_hash,
        &release_hash,
        first_journal,
    )
    .unwrap();
    let second = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::Xbootldr,
        &plan_hash,
        &release_hash,
        second_journal,
    )
    .unwrap();

    assert_eq!(
        reconcile_authenticated_replicas(
            &authority,
            &graph,
            &plan_hash,
            &release_hash,
            &[first, second]
        ),
        Err(ReplicaError::Fork)
    );
}

#[test]
fn reconciliation_rejects_stale_and_mixed_identities() {
    let graph = graph();
    let authority = authority();
    let plan_hash = hash('a');
    let release_hash = hash('b');
    let other_release_hash = hash('c');
    let first_record = direct_advance(
        None,
        &plan_hash,
        "windows_bootstrap",
        "cancel_before_mutation",
        "terminal.cancelled",
    );
    let stale_journal = vec![first_record.clone()];
    let mut current_journal = stale_journal.clone();
    current_journal.push(direct_advance(
        Some(&first_record),
        &plan_hash,
        "windows_bootstrap",
        "show_exact_plan",
        "windows.awaiting_confirmation",
    ));

    let stale = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan_hash,
        &release_hash,
        stale_journal.clone(),
    )
    .unwrap();
    let current = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::Xbootldr,
        &plan_hash,
        &release_hash,
        current_journal,
    )
    .unwrap();
    assert_eq!(
        reconcile_authenticated_replicas(
            &authority,
            &graph,
            &plan_hash,
            &release_hash,
            &[stale, current]
        ),
        Err(ReplicaError::StaleReplica)
    );

    let expected = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan_hash,
        &release_hash,
        stale_journal.clone(),
    )
    .unwrap();
    let mixed = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::Xbootldr,
        &plan_hash,
        &other_release_hash,
        stale_journal,
    )
    .unwrap();
    assert_eq!(
        reconcile_authenticated_replicas(
            &authority,
            &graph,
            &plan_hash,
            &release_hash,
            &[expected, mixed]
        ),
        Err(ReplicaError::MixedIdentity)
    );
}

#[test]
fn reconciliation_rejects_one_replica_and_duplicate_locations() {
    let graph = graph();
    let authority = authority();
    let plan_hash = hash('a');
    let release_hash = hash('b');
    let journal = vec![direct_advance(
        None,
        &plan_hash,
        "windows_bootstrap",
        "cancel_before_mutation",
        "terminal.cancelled",
    )];
    let replica = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan_hash,
        &release_hash,
        journal.clone(),
    )
    .unwrap();
    assert_eq!(
        reconcile_authenticated_replicas(
            &authority,
            &graph,
            &plan_hash,
            &release_hash,
            std::slice::from_ref(&replica)
        ),
        Err(ReplicaError::ReplicaCount { actual: 1 })
    );

    let duplicate = authenticate_journal_replica(
        &authority,
        &graph,
        ReplicaId::WindowsSystemVolume,
        &plan_hash,
        &release_hash,
        journal,
    )
    .unwrap();
    assert_eq!(
        reconcile_authenticated_replicas(
            &authority,
            &graph,
            &plan_hash,
            &release_hash,
            &[replica, duplicate]
        ),
        Err(ReplicaError::DuplicateReplica)
    );
}

#[test]
fn graph_aware_handoff_rejects_bad_actor_change() {
    let graph = graph();
    let authority = authority();
    let plan = plan();
    let release_hash = plan.body.release_manifest_hash.clone();
    let journal = fixture_journal();
    let replicas = [
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::WindowsSystemVolume,
            &plan.plan_hash,
            &release_hash,
            journal.clone(),
        )
        .unwrap(),
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::Xbootldr,
            &plan.plan_hash,
            &release_hash,
            journal,
        )
        .unwrap(),
    ];
    let reconciled = reconcile_authenticated_replicas(
        &authority,
        &graph,
        &plan.plan_hash,
        &release_hash,
        &replicas,
    )
    .unwrap();

    assert_eq!(
        authenticate_handoff_object(
            &authority,
            &graph,
            &reconciled,
            fixture_handoff(),
            "windows_finalizer",
            "installer-handoff-v1",
        ),
        Err(ReplicaError::IllegalActorChange)
    );
    assert_eq!(
        authenticate_handoff_object(
            &authority,
            &graph,
            &reconciled,
            fixture_handoff(),
            "linux_installer",
            "windows-finalizer-v1",
        ),
        Err(ReplicaError::IllegalActorChange)
    );
}

#[test]
fn durable_nonce_ledger_rejects_replay_after_restore() {
    let graph = graph();
    let authority = authority();
    let plan = plan();
    let release_hash = plan.body.release_manifest_hash.clone();
    let journal = fixture_journal();
    let replicas = [
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::WindowsSystemVolume,
            &plan.plan_hash,
            &release_hash,
            journal.clone(),
        )
        .unwrap(),
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::Xbootldr,
            &plan.plan_hash,
            &release_hash,
            journal,
        )
        .unwrap(),
    ];
    let reconciled = reconcile_authenticated_replicas(
        &authority,
        &graph,
        &plan.plan_hash,
        &release_hash,
        &replicas,
    )
    .unwrap();
    let handoff = authenticate_handoff_object(
        &authority,
        &graph,
        &reconciled,
        fixture_handoff(),
        "linux_installer",
        "installer-handoff-v1",
    )
    .unwrap();
    let mut ledger = empty_nonce_ledger();
    accept_authenticated_handoff(&authority, &graph, &reconciled, &handoff, &mut ledger).unwrap();

    let mut restored = restore_nonce_ledger(&ledger.snapshot()).unwrap();
    assert_eq!(
        accept_authenticated_handoff(&authority, &graph, &reconciled, &handoff, &mut restored),
        Err(ReplicaError::NonceReplay)
    );
}

#[test]
fn authentication_is_authority_bound() {
    let graph = graph();
    let authority = authority();
    let other_authority =
        validate_authentication_authority(b"different-replica-authority-key-v1!!").unwrap();
    let plan_hash = hash('a');
    let release_hash = hash('b');
    let journal = vec![direct_advance(
        None,
        &plan_hash,
        "windows_bootstrap",
        "cancel_before_mutation",
        "terminal.cancelled",
    )];
    let replicas = [
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::WindowsSystemVolume,
            &plan_hash,
            &release_hash,
            journal.clone(),
        )
        .unwrap(),
        authenticate_journal_replica(
            &authority,
            &graph,
            ReplicaId::Xbootldr,
            &plan_hash,
            &release_hash,
            journal,
        )
        .unwrap(),
    ];

    assert_eq!(
        reconcile_authenticated_replicas(
            &other_authority,
            &graph,
            &plan_hash,
            &release_hash,
            &replicas
        ),
        Err(ReplicaError::AuthenticationFailed)
    );
    assert_ne!(authority.key_id(), other_authority.key_id());
    assert_ne!(
        canonical_sha256(&"a").unwrap(),
        canonical_sha256(&"b").unwrap()
    );
}
