use crate::GraphModel;

const GRAPH: &[u8] = include_bytes!("../../../model/ubuntu-whole-disk-state-graph.json");
const ACTOR: &str = "ubuntu_host_controller";
const PLATFORM: &str = "ubuntu_host";

/// Resolve an execution phase from the pinned graph and fail closed unless its
/// executable metadata is exactly the contract the production adapter enforces.
pub fn require_phase(
    from: &str,
    event: &str,
    actions: &[&str],
    guards: &[&str],
    intent_before_actions: bool,
    commit_after_postconditions: bool,
) -> Result<String, String> {
    let graph = GraphModel::load_verified_ubuntu_whole_disk(GRAPH)
        .map_err(|e| format!("Ubuntu graph verification failed: {e}"))?;
    if graph
        .actor_platforms(ACTOR)
        .is_none_or(|p| !p.contains(PLATFORM))
    {
        return Err("Ubuntu graph actor/platform authority is absent".into());
    }
    let state = graph.state_id(from).ok_or("unknown durable graph state")?;
    let candidates = graph.candidates(state, event);
    if candidates.len() != 1 {
        return Err("graph phase is missing or ambiguous".into());
    }
    let transition = graph.transition(candidates[0]);
    let actual_actions: Vec<&str> = transition
        .actions
        .iter()
        .map(|id| graph.action(*id).id.as_str())
        .collect();
    let actual_guards: Vec<&str> = transition
        .guards
        .iter()
        .map(|id| graph.guard(*id).id.as_str())
        .collect();
    if transition.def.actor != ACTOR
        || actual_actions != actions
        || actual_guards != guards
        || transition.def.journal.intent_before_actions != intent_before_actions
        || transition.def.journal.commit_after_postconditions != commit_after_postconditions
        || transition.def.preconditions.is_empty()
        || transition.def.postconditions.is_empty()
    {
        return Err("graph phase metadata does not match enforced adapter contract".into());
    }
    Ok(transition.def.to.clone())
}

pub fn require_prepare() -> Result<(), String> {
    require_phase(
        "discovered",
        "prepare",
        &["inspect_scope", "stage_artifact"],
        &["scope_supported"],
        true,
        true,
    )
    .map(|_| ())
}
pub fn require_authorize() -> Result<(), String> {
    require_phase(
        "artifact_prepared",
        "authorize",
        &["record_authorization"],
        &["artifact_staged_and_verified"],
        false,
        false,
    )
    .map(|_| ())
}
pub fn require_begin() -> Result<(), String> {
    require_phase(
        "authorized",
        "deploy",
        &[],
        &["artifact_staged_and_verified", "plan_authorized"],
        false,
        false,
    )
    .map(|_| ())
}
pub fn require_chunk() -> Result<(), String> {
    require_phase(
        "deploying",
        "chunk",
        &["write_chunk", "verify_chunk"],
        &[
            "artifact_staged_and_verified",
            "plan_authorized",
            "next_chunk_bound",
        ],
        true,
        true,
    )
    .map(|_| ())
}
pub fn require_verify() -> Result<(), String> {
    require_phase(
        "deploying",
        "verify",
        &["verify_target"],
        &[
            "artifact_staged_and_verified",
            "plan_authorized",
            "all_chunks_verified",
        ],
        false,
        false,
    )
    .map(|_| ())
}
pub fn require_complete() -> Result<(), String> {
    require_phase(
        "verified",
        "complete",
        &["commit_complete"],
        &["plan_authorized", "target_full_hash_verified"],
        false,
        false,
    )
    .map(|_| ())
}
