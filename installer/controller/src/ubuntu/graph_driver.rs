use crate::{ActionRisk, Authorization, GraphModel};
use std::collections::BTreeMap;

const GRAPH: &[u8] = include_bytes!("../../../model/ubuntu-whole-disk-state-graph.json");
const ACTOR: &str = "ubuntu_host_controller";
const PLATFORM: &str = "ubuntu_host";

// Explicit adapter vocabulary. Adding graph predicates requires implementing
// observations, not accepting unknown names as satisfied.
const OBSERVATIONS: &[&str] = &[
    "action_intent_durable",
    "all_chunks_verified",
    "all_planned_chunks_have_verified_commits",
    "ambiguous_or_unsafe_target_state_observed",
    "artifact_durable_on_recovery_host",
    "artifact_source_verified",
    "artifact_staged_and_verified",
    "automatic_target_writes_stopped",
    "chunk_not_committed_or_exact_preimage_observed",
    "chunk_offset_and_digest_match_cursor",
    "completion_precondition_failed",
    "confirmed_plan",
    "deployment_cursor_initialized",
    "exact_plan_authorization_recorded",
    "exact_plan_displayed",
    "full_target_digest_readback_verified",
    "next_chunk_bound",
    "no_target_chunk_committed",
    "no_target_write_authorized",
    "no_target_write_performed",
    "plan_authorized",
    "recovery_host_bootable",
    "refusal_reason_observed",
    "release_policy",
    "scope_supported",
    "stable_target_identity_observed",
    "staged_artifact_digest_verified",
    "success_not_recorded",
    "success_terminal_committed",
    "target_chunk_digest_readback_verified",
    "target_chunk_flushed",
    "target_full_hash_verified",
    "target_identity_matches_authorized_plan",
    "target_outside_recovery_host",
];

/// Facts collected by the platform adapter from actual checks. Missing and false
/// observations both fail closed. A later failed check revokes an earlier fact.
/// This is not a cryptographic attestation and never substitutes for disk I/O.
#[derive(Default, Debug)]
pub struct Evidence {
    observations: BTreeMap<String, bool>,
}
impl Evidence {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn observe(&mut self, id: &str, holds: bool) -> Result<(), String> {
        if !OBSERVATIONS.contains(&id) {
            return Err(format!("unimplemented Ubuntu observation: {id}"));
        }
        self.observations.insert(id.into(), holds);
        Ok(())
    }
    fn require(&self, id: &str) -> Result<(), String> {
        if !OBSERVATIONS.contains(&id) {
            return Err(format!("unimplemented Ubuntu condition: {id}"));
        }
        if self.observations.get(id) != Some(&true) {
            return Err(format!("Ubuntu graph condition not observed: {id}"));
        }
        Ok(())
    }
}

/// A single graph-selected transition. Not Clone: completion consumes the
/// permit. The adapter must journal intent before asking to execute a mutation,
/// and must collect independent post-effect evidence before finishing.
#[derive(Debug)]
pub struct TransitionPermit {
    transition_id: String,
    from: String,
    to: String,
    actions: Vec<(String, ActionRisk)>,
    next_action: usize,
    postconditions: Vec<String>,
    intent_required: bool,
}
impl TransitionPermit {
    pub fn transition_id(&self) -> &str {
        &self.transition_id
    }
    pub fn from_state(&self) -> &str {
        &self.from
    }
    pub fn to_state(&self) -> &str {
        &self.to
    }
    /// Call immediately before the named effect, in the graph's exact order.
    pub fn require_action(&mut self, action: &str, evidence: &Evidence) -> Result<(), String> {
        let (expected, risk) = self
            .actions
            .get(self.next_action)
            .ok_or("all transition actions already consumed")?;
        if expected != action {
            return Err(format!("graph requires action {expected}, not {action}"));
        }
        if matches!(risk, ActionRisk::StagingMutation | ActionRisk::DiskMutation) {
            if !self.intent_required {
                return Err("mutation lacks intent protocol".into());
            }
            evidence.require("action_intent_durable")?;
        }
        self.next_action += 1;
        Ok(())
    }
    /// Called after effects and independent verification, before publishing the
    /// transition commit/state advance. Returns the graph destination to persist.
    pub fn finish(self, evidence: &Evidence) -> Result<String, String> {
        if self.next_action != self.actions.len() {
            return Err("graph transition has unexecuted actions".into());
        }
        for id in &self.postconditions {
            evidence.require(id)?;
        }
        Ok(self.to)
    }
}

/// Select using the *replayed durable state*, never a hardcoded predecessor.
/// Every guard, authorization and precondition is dispatched to a known fact.
pub fn begin_transition(
    from: &str,
    event: &str,
    evidence: &Evidence,
) -> Result<TransitionPermit, String> {
    let graph = GraphModel::load_verified_ubuntu_whole_disk(GRAPH)
        .map_err(|e| format!("Ubuntu graph verification failed: {e}"))?;
    let state = graph.state_id(from).ok_or("unknown durable graph state")?;
    let candidates = graph.candidates(state, event);
    if candidates.len() != 1 {
        return Err("graph phase is missing or ambiguous".into());
    }
    let t = graph.transition(candidates[0]);
    if t.def.actor != ACTOR
        || graph.state(state).actor != ACTOR
        || graph
            .actor_platforms(ACTOR)
            .is_none_or(|p| !p.contains(PLATFORM))
    {
        return Err("Ubuntu graph actor/platform authority is absent".into());
    }
    for id in &t.guards {
        let guard = graph.guard(*id);
        if guard.platform != PLATFORM {
            return Err("guard platform mismatch".into());
        }
        evidence.require(&guard.id)?;
    }
    for authorization in &t.def.authorization {
        let id = match authorization {
            Authorization::ReleasePolicy => "release_policy",
            Authorization::ConfirmedPlan => "confirmed_plan",
            Authorization::RollbackAuthorized => {
                return Err("Ubuntu rollback authority is unsupported".into());
            }
        };
        evidence.require(id)?;
    }
    for id in &t.def.preconditions {
        evidence.require(id)?;
    }
    let mut actions = Vec::new();
    for id in &t.actions {
        let action = graph.action(*id);
        if action.platform != PLATFORM {
            return Err("action platform mismatch".into());
        }
        actions.push((action.id.clone(), action.risk));
    }
    // No alias can substitute another action with weaker risk metadata.
    let expected: &[&str] = match t.def.id.as_str() {
        "prepare_artifact" => &["inspect_scope", "stage_artifact"],
        "authorize_plan" => &["record_authorization"],
        "begin_deployment" => &[],
        "deploy_chunk" => &["write_chunk", "verify_chunk"],
        "finish_deployment" => &["verify_target"],
        "complete_install" => &["commit_complete"],
        "refuse_from_discovered"
        | "refuse_from_artifact_prepared"
        | "refuse_from_authorized"
        | "refuse_from_deploying"
        | "refuse_from_verified" => &["record_refusal"],
        _ => return Err("unimplemented Ubuntu transition".into()),
    };
    if actions
        .iter()
        .map(|(id, _)| id.as_str())
        .collect::<Vec<_>>()
        != expected
    {
        return Err("Ubuntu transition/action binding mismatch".into());
    }
    for (_, risk) in &actions {
        if matches!(risk, ActionRisk::StagingMutation | ActionRisk::DiskMutation)
            && (!t.def.journal.intent_before_actions || !t.def.journal.commit_after_postconditions)
        {
            return Err("mutation lacks durable intent/postcondition commit".into());
        }
    }
    Ok(TransitionPermit {
        transition_id: t.def.id.clone(),
        from: from.into(),
        to: t.def.to.clone(),
        actions,
        next_action: 0,
        postconditions: t.def.postconditions.clone(),
        intent_required: t.def.journal.intent_before_actions,
    })
}

// Temporary metadata compatibility only. Production must use evidence permits.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn all_observed() -> Evidence {
        let mut evidence = Evidence::new();
        for id in OBSERVATIONS {
            evidence.observe(id, true).unwrap();
        }
        evidence
    }

    #[test]
    fn every_guard_authorization_and_precondition_is_enforced() {
        let graph = GraphModel::load_verified_ubuntu_whole_disk(GRAPH).unwrap();
        for id in graph.transition_ids() {
            let t = graph.transition(id);
            let mut required = t.def.guards.clone();
            required.extend(t.def.preconditions.clone());
            required.extend(t.def.authorization.iter().map(|a| match a {
                Authorization::ReleasePolicy => "release_policy".into(),
                Authorization::ConfirmedPlan => "confirmed_plan".into(),
                Authorization::RollbackAuthorized => panic!("unexpected rollback"),
            }));
            assert!(begin_transition(&t.def.from, &t.def.event, &all_observed()).is_ok());
            for predicate in required {
                let mut evidence = all_observed();
                evidence.observations.remove(&predicate);
                let error = begin_transition(&t.def.from, &t.def.event, &evidence).unwrap_err();
                assert!(error.contains(&predicate), "{}: {error}", t.def.id);
                evidence.observe(&predicate, false).unwrap();
                assert!(begin_transition(&t.def.from, &t.def.event, &evidence).is_err());
            }
        }
    }

    #[test]
    fn every_postcondition_and_action_is_required_before_state_advance() {
        let graph = GraphModel::load_verified_ubuntu_whole_disk(GRAPH).unwrap();
        for id in graph.transition_ids() {
            let t = graph.transition(id);
            for missing in &t.def.postconditions {
                let mut permit =
                    begin_transition(&t.def.from, &t.def.event, &all_observed()).unwrap();
                for action in &t.def.actions {
                    permit.require_action(action, &all_observed()).unwrap();
                }
                let mut post = all_observed();
                post.observations.remove(missing);
                assert!(permit.finish(&post).unwrap_err().contains(missing));
            }
            let mut permit = begin_transition(&t.def.from, &t.def.event, &all_observed()).unwrap();
            for action in &t.def.actions {
                permit.require_action(action, &all_observed()).unwrap();
            }
            assert_eq!(permit.finish(&all_observed()).unwrap(), t.def.to);
            if !t.def.actions.is_empty() {
                let permit = begin_transition(&t.def.from, &t.def.event, &all_observed()).unwrap();
                assert!(permit.finish(&all_observed()).is_err());
            }
        }
    }

    #[test]
    fn mutation_requires_intent_and_exact_action_order_without_aliases() {
        let mut permit = begin_transition("deploying", "chunk", &all_observed()).unwrap();
        assert!(
            permit
                .require_action("verify_chunk", &all_observed())
                .is_err()
        );
        assert!(
            permit
                .require_action("stage_artifact", &all_observed())
                .is_err()
        );
        assert!(
            permit
                .require_action("write_chunk", &Evidence::new())
                .is_err()
        );
        permit
            .require_action("write_chunk", &all_observed())
            .unwrap();
        assert!(
            permit
                .require_action("write_chunk", &all_observed())
                .is_err()
        );
        permit
            .require_action("verify_chunk", &all_observed())
            .unwrap();
        assert!(
            permit
                .require_action("verify_chunk", &all_observed())
                .is_err()
        );
        assert_eq!(permit.finish(&all_observed()).unwrap(), "deploying");
    }

    #[test]
    fn terminal_states_and_unknown_conditions_never_authorize_writes() {
        for state in [
            "complete",
            "refused",
            "manual_recovery",
            "authorized",
            "unknown",
        ] {
            assert!(begin_transition(state, "chunk", &all_observed()).is_err());
        }
        assert!(
            Evidence::new()
                .observe("assume_everything_safe", true)
                .is_err()
        );
        assert!(begin_transition("discovered", "prepare", &Evidence::new()).is_err());
    }
}
