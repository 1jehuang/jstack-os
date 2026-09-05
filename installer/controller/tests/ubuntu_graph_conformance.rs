//! Conformance and identity tests for the pinned Ubuntu whole-disk graph.

use jstack_installer_controller::{
    ActionRisk, GraphLoadError, GraphModel, TerminalOutcome, UBUNTU_WHOLE_DISK_GRAPH_SHA256,
    UBUNTU_WHOLE_DISK_MODEL_ID, load_verified,
};
use jstack_installer_core::Hash256;
use sha2::{Digest, Sha256};

const UBUNTU_GRAPH: &[u8] = include_bytes!("../../model/ubuntu-whole-disk-state-graph.json");
const WINDOWS_GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");

fn digest(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

fn graph() -> GraphModel {
    GraphModel::load_verified_ubuntu_whole_disk(UBUNTU_GRAPH).unwrap()
}

#[test]
fn pinned_identity_digest_and_model_separation_hold() {
    let model = graph();
    assert_eq!(model.model_id(), UBUNTU_WHOLE_DISK_MODEL_ID);
    assert_eq!(model.digest().as_str(), UBUNTU_WHOLE_DISK_GRAPH_SHA256);

    let mut tampered = UBUNTU_GRAPH.to_vec();
    tampered.push(b'\n');
    assert!(matches!(
        GraphModel::load_verified_ubuntu_whole_disk(&tampered),
        Err(GraphLoadError::DigestMismatch { .. })
    ));
    assert!(matches!(
        GraphModel::load_verified_ubuntu_whole_disk(WINDOWS_GRAPH),
        Err(GraphLoadError::DigestMismatch { .. })
    ));
    assert!(matches!(
        load_verified(UBUNTU_GRAPH, &digest(UBUNTU_GRAPH)),
        Err(GraphLoadError::Identity(_))
    ));
}

#[test]
fn topology_ids_actor_and_refusal_terminal_are_exact() {
    let model = graph();
    let states: Vec<_> = model
        .state_ids()
        .map(|id| model.state(id).id.as_str())
        .collect();
    assert_eq!(
        states,
        [
            "discovered",
            "artifact_prepared",
            "authorized",
            "deploying",
            "verified",
            "complete",
            "refused",
            "manual_recovery",
        ]
    );
    assert_eq!(model.state(model.initial_state()).id, "discovered");
    assert_eq!(
        model
            .state(model.state_id("complete").unwrap())
            .terminal_outcome,
        Some(TerminalOutcome::Success)
    );
    assert_eq!(
        model
            .state(model.state_id("refused").unwrap())
            .terminal_outcome,
        Some(TerminalOutcome::SafeAbort)
    );
    assert_eq!(
        model
            .state(model.state_id("manual_recovery").unwrap())
            .terminal_outcome,
        Some(TerminalOutcome::ManualRecovery)
    );
    assert_eq!(model.actors(), &["ubuntu_host_controller"]);
    assert!(
        model
            .state_ids()
            .all(|id| model.state(id).actor == "ubuntu_host_controller")
    );
    assert!(
        model
            .transition_ids()
            .all(|id| model.transition(id).def.actor == "ubuntu_host_controller")
    );
}

#[test]
fn mutations_have_durable_intent_commit_and_failure_edges() {
    let model = graph();
    let mut mutating = Vec::new();
    for id in model.transition_ids() {
        if model.is_mutating(id) {
            let transition = model.transition(id);
            mutating.push(transition.def.id.as_str());
            assert!(transition.def.journal.intent_before_actions);
            assert!(transition.def.journal.commit_after_postconditions);
            let expected_failure = if transition.def.id == "deploy_chunk" {
                "manual_recovery"
            } else {
                "refused"
            };
            assert_eq!(
                transition
                    .failure_to
                    .map(|state| model.state(state).id.as_str()),
                Some(expected_failure)
            );
            assert!(!transition.def.preconditions.is_empty());
            assert!(!transition.def.postconditions.is_empty());
        }
    }
    assert_eq!(mutating, ["prepare_artifact", "deploy_chunk"]);

    let prepare = model.transition(model.transition_id("prepare_artifact").unwrap());
    assert_eq!(prepare.def.actions, ["inspect_scope", "stage_artifact"]);
    assert_eq!(
        model
            .action(model.action_id("stage_artifact").unwrap())
            .risk,
        ActionRisk::StagingMutation
    );
}

#[test]
fn chunk_loop_and_full_target_finalization_are_required() {
    let model = graph();
    let deploying = model.state_id("deploying").unwrap();
    let chunk = model.transition(model.transition_id("deploy_chunk").unwrap());
    assert_eq!((chunk.from, chunk.to), (deploying, deploying));
    assert_eq!(chunk.def.event, "chunk");
    assert_eq!(chunk.def.actions, ["write_chunk", "verify_chunk"]);
    let write = model.action(model.action_id("write_chunk").unwrap());
    assert_eq!(write.risk, ActionRisk::DiskMutation);
    assert_eq!(
        write.parameters.as_ref().unwrap()["binding"],
        serde_json::json!([
            "target_identity",
            "offset_bytes",
            "length_bytes",
            "chunk_digest"
        ])
    );
    assert!(
        chunk
            .def
            .postconditions
            .iter()
            .any(|item| item == "target_chunk_digest_readback_verified")
    );
    assert!(
        !chunk.def.postconditions.iter().any(|item| {
            item == "chunk_commit_durable" || item == "deployment_cursor_monotonic"
        })
    );
    assert_eq!(
        chunk.failure_to.map(|state| model.state(state).id.as_str()),
        Some("manual_recovery")
    );

    let finish = model.transition(model.transition_id("finish_deployment").unwrap());
    assert_eq!(finish.def.actions, ["verify_target"]);
    assert!(
        finish
            .def
            .guards
            .iter()
            .any(|guard| guard == "all_chunks_verified")
    );
    let complete = model.transition(model.transition_id("complete_install").unwrap());
    assert_eq!(complete.def.actions, ["commit_complete"]);
    assert!(
        complete
            .def
            .guards
            .iter()
            .any(|guard| guard == "target_full_hash_verified")
    );
    assert_eq!(model.state(complete.from).id, "verified");
    assert_eq!(model.state(complete.to).id, "complete");
}

#[test]
fn exact_transition_and_action_catalogs_are_pinned() {
    let model = graph();
    let actions: Vec<_> = model
        .action_ids()
        .map(|id| model.action(id).id.as_str())
        .collect();
    assert_eq!(
        actions,
        [
            "inspect_scope",
            "stage_artifact",
            "record_authorization",
            "write_chunk",
            "verify_chunk",
            "verify_target",
            "commit_complete",
            "record_refusal",
        ]
    );
    let transitions: Vec<_> = model
        .transition_ids()
        .map(|id| model.transition(id).def.id.as_str())
        .collect();
    assert_eq!(
        transitions,
        [
            "prepare_artifact",
            "authorize_plan",
            "begin_deployment",
            "deploy_chunk",
            "finish_deployment",
            "complete_install",
            "refuse_from_discovered",
            "refuse_from_artifact_prepared",
            "refuse_from_authorized",
            "refuse_from_deploying",
            "refuse_from_verified",
        ]
    );
}
