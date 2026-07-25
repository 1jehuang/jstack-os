//! PH-02 deterministic runtime selection.
//!
//! Every transition in the executable graph must be reachable exactly once
//! through `authorize_transition`, using only the transition's own source
//! state, event, verified guard witnesses, actor, and graph-declared
//! authorizations. The suite is exhaustive over the whole graph rather than
//! sampling a few interesting edges, so a future graph edit that introduces a
//! nondeterministic or unauthorizable transition fails here.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use jstack_installer_controller::authority::{
    ActorCapability, CapabilityAuthority, ConfirmationCapabilities, GuardCapability,
    GuardWitnessValidator, PresentedAuthorization, TransitionAuthorizationError,
    authorize_transition,
};
use jstack_installer_controller::{
    Authorization, GraphModel, GuardDef, GuardId, SelectionError, TransitionId, load_verified,
};
use jstack_installer_core::{
    Architecture, Confirmation, Hash256, InstallPlan, PlanDisplay, ReleaseChannel,
    ReleaseTrustPolicy, ReleaseVerificationMode, SignedReleaseManifest, TrustedReleaseKey,
    VerifiedReleaseManifest, verify_release_manifest,
};
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const MANIFEST: &[u8] = include_bytes!("../../core/fixtures/signed-release-manifest.json");
const PLAN: &str = include_str!("../../core/generated/example-plan.json");
const DISPLAY: &str = include_str!("../../core/generated/example-plan-display.json");
const CONFIRMATION: &str = include_str!("../../core/generated/example-confirmation.json");
const NOW: u64 = 1_800_000_000;

fn hash(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

fn graph() -> GraphModel {
    load_verified(GRAPH, &hash(GRAPH)).unwrap()
}

/// The signed fixture release is bound to the exact executable graph, so a
/// real `ReleasePolicyCapability` can be issued without any platform adapter.
fn release() -> VerifiedReleaseManifest {
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
    let pending = verify_release_manifest(MANIFEST, &policy, ReleaseVerificationMode::Acquire)
        .expect("fixture release manifest verifies against the compiled policy");
    let persisted = pending.required_acceptance().clone();
    pending.accept_after_persist(&persisted).unwrap()
}

fn confirmation(authority: &CapabilityAuthority<'_>) -> ConfirmationCapabilities {
    let plan: InstallPlan = serde_json::from_str(PLAN).unwrap();
    let displayed: PlanDisplay = serde_json::from_str(DISPLAY).unwrap();
    let confirmation: Confirmation = serde_json::from_str(CONFIRMATION).unwrap();
    authority
        .issue_confirmation(&plan, &displayed, &confirmation)
        .unwrap()
}

/// A validator standing in for a platform observation. It certifies only the
/// exact guard it was asked about, and refuses guards outside the actor's
/// declared platforms so guard authority stays actor-bound.
struct ObservedGuard;

impl GuardWitnessValidator<str> for ObservedGuard {
    type Error = String;

    fn validate(
        &self,
        graph: &GraphModel,
        actor: &str,
        guard: &GuardDef,
        evidence: &str,
    ) -> Result<Hash256, Self::Error> {
        let platforms = graph
            .actor_platforms(actor)
            .ok_or_else(|| format!("unknown actor {actor}"))?;
        if !platforms.contains(&guard.platform) {
            return Err(format!("actor {actor} cannot observe {}", guard.id));
        }
        if evidence != guard.id {
            return Err(format!("evidence does not observe {}", guard.id));
        }
        Ok(hash(
            format!("{actor}\0{}\0{evidence}", guard.id).as_bytes(),
        ))
    }
}

struct Fixture {
    graph: GraphModel,
}

impl Fixture {
    fn new() -> Self {
        Self { graph: graph() }
    }

    fn authority(&self) -> CapabilityAuthority<'_> {
        CapabilityAuthority::new(&self.graph)
    }
}

fn issue_guards(
    authority: &CapabilityAuthority<'_>,
    actor: &ActorCapability,
    guards: &[&str],
) -> Vec<GuardCapability> {
    guards
        .iter()
        .map(|guard| {
            authority
                .issue_guard(actor, guard, *guard, &ObservedGuard)
                .unwrap_or_else(|error| panic!("guard {guard} could not be witnessed: {error}"))
        })
        .collect()
}

/// Every transition is authorized exactly once from its own source state and
/// event, and the selected transition is always the intended one.
#[test]
fn every_transition_is_authorizable_exactly_once_from_its_own_source_and_event() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;
    let authority = fixture.authority();
    let release_capability = authority.issue_release_policy(&release()).unwrap();
    let confirmation = confirmation(&authority);
    let rollback = authority
        .issue_rollback(confirmation.user_confirmation())
        .unwrap();

    let actors: BTreeMap<&str, ActorCapability> = graph
        .actors()
        .iter()
        .map(|actor| {
            (
                actor.as_str(),
                authority.issue_actor(actor).expect("graph actor"),
            )
        })
        .collect();

    let mut authorized = BTreeSet::new();
    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        let actor = &actors[transition.def.actor.as_str()];
        let guard_ids: Vec<&str> = transition
            .guards
            .iter()
            .map(|guard| graph.guard(*guard).id.as_str())
            .collect();
        let guards = issue_guards(&authority, actor, &guard_ids);
        let guard_refs: Vec<&GuardCapability> = guards.iter().collect();

        let mut presented = Vec::new();
        for authorization in &transition.def.authorization {
            presented.push(match authorization {
                Authorization::ReleasePolicy => PresentedAuthorization::from(&release_capability),
                Authorization::ConfirmedPlan => {
                    PresentedAuthorization::from(confirmation.confirmed_plan())
                }
                Authorization::RollbackAuthorized => PresentedAuthorization::from(&rollback),
            });
        }

        let from = graph.state_id(&transition.def.from).unwrap();
        let selected = authorize_transition(
            graph,
            from,
            &transition.def.event,
            actor,
            &presented,
            &guard_refs,
        )
        .unwrap_or_else(|error| {
            panic!(
                "transition {} is not authorizable: {error}",
                transition.def.id
            )
        });
        assert_eq!(
            selected.transition_id(),
            id,
            "transition {} selected a different edge",
            transition.def.id
        );
        assert_eq!(selected.graph_digest(), graph.digest());
        assert!(
            authorized.insert(id),
            "transition {} was authorized twice",
            transition.def.id
        );
    }

    assert_eq!(
        authorized.len(),
        graph.transition_count(),
        "every graph transition must be covered"
    );
}

/// No transition can be selected by presenting the guard set of a different
/// transition that shares its source state and event. This is the only
/// (state, event) pair in the graph with more than one candidate, so it is the
/// only place runtime nondeterminism could appear.
#[test]
fn shared_candidate_pairs_never_admit_two_transitions_under_one_verdict() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;

    let mut shared: BTreeMap<(String, String), Vec<TransitionId>> = BTreeMap::new();
    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        shared
            .entry((transition.def.from.clone(), transition.def.event.clone()))
            .or_default()
            .push(id);
    }
    let contested: Vec<_> = shared
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .collect();
    assert_eq!(
        contested.len(),
        1,
        "graph gained or lost a contested (state, event) pair; re-derive this proof"
    );

    for ((state, event), ids) in contested {
        let from = graph.state_id(&state).unwrap();
        // The union of all candidate guard sets is an inconsistent oracle. It
        // must be rejected as ambiguous rather than resolved arbitrarily.
        let union: BTreeSet<GuardId> = ids
            .iter()
            .flat_map(|id| graph.transition(*id).guards.iter().copied())
            .collect();
        assert!(matches!(
            graph.select_enabled(from, &event, &union),
            Err(SelectionError::Ambiguous(_))
        ));

        // Each candidate's own guard set selects exactly that candidate.
        for id in &ids {
            let own: BTreeSet<GuardId> = graph.transition(*id).guards.iter().copied().collect();
            assert_eq!(graph.select_enabled(from, &event, &own).unwrap(), *id);
        }

        // Dropping any single guard from a candidate disables it entirely
        // instead of falling through to a sibling.
        for id in &ids {
            let own: BTreeSet<GuardId> = graph.transition(*id).guards.iter().copied().collect();
            for guard in &own {
                let mut weakened = own.clone();
                weakened.remove(guard);
                assert_eq!(
                    graph.select_enabled(from, &event, &weakened),
                    Err(SelectionError::NoneEnabled),
                    "dropping {} from {} still selected an edge",
                    graph.guard(*guard).id,
                    graph.transition(*id).def.id
                );
            }
        }
    }
}

/// For every transition, the actors that the graph did not name are rejected
/// even when the guard set and authorizations are exactly correct.
#[test]
fn no_transition_accepts_an_actor_the_graph_did_not_name() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;
    let authority = fixture.authority();
    let release_capability = authority.issue_release_policy(&release()).unwrap();
    let confirmation = confirmation(&authority);
    let rollback = authority
        .issue_rollback(confirmation.user_confirmation())
        .unwrap();

    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        let expected_actor = transition.def.actor.as_str();
        let witness_actor = authority.issue_actor(expected_actor).unwrap();
        let guard_ids: Vec<&str> = transition
            .guards
            .iter()
            .map(|guard| graph.guard(*guard).id.as_str())
            .collect();
        // Witnesses stay bound to the correct actor so the failure below is
        // attributable to the actor identity, not to guard provenance.
        let guards = issue_guards(&authority, &witness_actor, &guard_ids);
        let guard_refs: Vec<&GuardCapability> = guards.iter().collect();
        let from = graph.state_id(&transition.def.from).unwrap();

        for other in graph
            .actors()
            .iter()
            .filter(|a| a.as_str() != expected_actor)
        {
            let wrong = authority.issue_actor(other).unwrap();
            let mut presented = Vec::new();
            for authorization in &transition.def.authorization {
                presented.push(match authorization {
                    Authorization::ReleasePolicy => {
                        PresentedAuthorization::from(&release_capability)
                    }
                    Authorization::ConfirmedPlan => {
                        PresentedAuthorization::from(confirmation.confirmed_plan())
                    }
                    Authorization::RollbackAuthorized => PresentedAuthorization::from(&rollback),
                });
            }
            let error = authorize_transition(
                graph,
                from,
                &transition.def.event,
                &wrong,
                &presented,
                &guard_refs,
            )
            .expect_err("a foreign actor must never authorize a transition");
            assert!(
                matches!(
                    error,
                    TransitionAuthorizationError::WrongActor { .. }
                        | TransitionAuthorizationError::GuardActorMismatch { .. }
                ),
                "transition {} rejected actor {other} for the wrong reason: {error}",
                transition.def.id
            );
        }
    }
}

/// For every transition, omitting any graph-declared authorization, or adding
/// one the graph did not declare, fails closed.
#[test]
fn no_transition_accepts_a_wrong_authorization_set() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;
    let authority = fixture.authority();
    let release_capability = authority.issue_release_policy(&release()).unwrap();
    let confirmation = confirmation(&authority);
    let rollback = authority
        .issue_rollback(confirmation.user_confirmation())
        .unwrap();

    let present = |authorization: Authorization| match authorization {
        Authorization::ReleasePolicy => PresentedAuthorization::from(&release_capability),
        Authorization::ConfirmedPlan => PresentedAuthorization::from(confirmation.confirmed_plan()),
        Authorization::RollbackAuthorized => PresentedAuthorization::from(&rollback),
    };
    let all = [
        Authorization::ReleasePolicy,
        Authorization::ConfirmedPlan,
        Authorization::RollbackAuthorized,
    ];

    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        let actor = authority.issue_actor(&transition.def.actor).unwrap();
        let guard_ids: Vec<&str> = transition
            .guards
            .iter()
            .map(|guard| graph.guard(*guard).id.as_str())
            .collect();
        let guards = issue_guards(&authority, &actor, &guard_ids);
        let guard_refs: Vec<&GuardCapability> = guards.iter().collect();
        let from = graph.state_id(&transition.def.from).unwrap();
        let required = &transition.def.authorization;

        // Every strict subset of the required set is rejected.
        for omitted in required {
            let presented: Vec<_> = required
                .iter()
                .filter(|authorization| *authorization != omitted)
                .map(|authorization| present(*authorization))
                .collect();
            assert_eq!(
                authorize_transition(
                    graph,
                    from,
                    &transition.def.event,
                    &actor,
                    &presented,
                    &guard_refs,
                )
                .unwrap_err(),
                TransitionAuthorizationError::AuthorizationSetMismatch,
                "transition {} accepted a missing authorization",
                transition.def.id
            );
        }

        // Every undeclared extra authorization is rejected.
        for extra in all.iter().filter(|a| !required.contains(a)) {
            let mut presented: Vec<_> = required
                .iter()
                .map(|authorization| present(*authorization))
                .collect();
            presented.push(present(*extra));
            assert_eq!(
                authorize_transition(
                    graph,
                    from,
                    &transition.def.event,
                    &actor,
                    &presented,
                    &guard_refs,
                )
                .unwrap_err(),
                TransitionAuthorizationError::AuthorizationSetMismatch,
                "transition {} accepted an extra {extra:?} authorization",
                transition.def.id
            );
        }

        // A duplicated required authorization is rejected rather than counted
        // twice toward the required set.
        if let Some(first) = required.first() {
            let mut presented: Vec<_> = required
                .iter()
                .map(|authorization| present(*authorization))
                .collect();
            presented.push(present(*first));
            assert_eq!(
                authorize_transition(
                    graph,
                    from,
                    &transition.def.event,
                    &actor,
                    &presented,
                    &guard_refs,
                )
                .unwrap_err(),
                TransitionAuthorizationError::DuplicateAuthorization(*first),
                "transition {} accepted a duplicated authorization",
                transition.def.id
            );
        }
    }
}

/// For every guarded transition, dropping any one guard witness fails closed
/// through the graph selector rather than authorizing a weaker edge.
#[test]
fn no_guarded_transition_is_authorizable_with_a_missing_witness() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;
    let authority = fixture.authority();
    let release_capability = authority.issue_release_policy(&release()).unwrap();
    let confirmation = confirmation(&authority);
    let rollback = authority
        .issue_rollback(confirmation.user_confirmation())
        .unwrap();

    let mut guarded = 0_usize;
    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        if transition.guards.is_empty() {
            continue;
        }
        guarded += 1;
        let actor = authority.issue_actor(&transition.def.actor).unwrap();
        let guard_ids: Vec<&str> = transition
            .guards
            .iter()
            .map(|guard| graph.guard(*guard).id.as_str())
            .collect();
        let guards = issue_guards(&authority, &actor, &guard_ids);
        let from = graph.state_id(&transition.def.from).unwrap();

        for dropped in 0..guards.len() {
            let guard_refs: Vec<&GuardCapability> = guards
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != dropped)
                .map(|(_, guard)| guard)
                .collect();
            let mut presented = Vec::new();
            for authorization in &transition.def.authorization {
                presented.push(match authorization {
                    Authorization::ReleasePolicy => {
                        PresentedAuthorization::from(&release_capability)
                    }
                    Authorization::ConfirmedPlan => {
                        PresentedAuthorization::from(confirmation.confirmed_plan())
                    }
                    Authorization::RollbackAuthorized => PresentedAuthorization::from(&rollback),
                });
            }
            let error = authorize_transition(
                graph,
                from,
                &transition.def.event,
                &actor,
                &presented,
                &guard_refs,
            )
            .expect_err("a missing guard witness must never authorize a transition");
            assert!(
                matches!(
                    error,
                    TransitionAuthorizationError::Selection(SelectionError::NoneEnabled)
                        | TransitionAuthorizationError::GuardSetMismatch
                ),
                "transition {} tolerated a missing guard: {error}",
                transition.def.id
            );
        }
    }
    assert!(guarded > 0, "the graph must contain guarded transitions");
}

/// A guard witness is only issuable by an actor whose declared platforms cover
/// that guard, so no actor can manufacture another platform's observation.
#[test]
fn guard_witnesses_cannot_be_issued_outside_actor_platform_authority() {
    let fixture = Fixture::new();
    let graph = &fixture.graph;
    let authority = fixture.authority();

    let mut rejected = 0_usize;
    for guard in graph.guard_ids() {
        let definition = graph.guard(guard);
        for actor in graph.actors() {
            let capability = authority.issue_actor(actor).unwrap();
            let platforms = graph.actor_platforms(actor).unwrap();
            let result = authority.issue_guard(
                &capability,
                &definition.id,
                definition.id.as_str(),
                &ObservedGuard,
            );
            if platforms.contains(&definition.platform) {
                assert!(
                    result.is_ok(),
                    "actor {actor} should observe {}",
                    definition.id
                );
            } else {
                assert!(
                    result.is_err(),
                    "actor {actor} must not observe {}",
                    definition.id
                );
                rejected += 1;
            }
        }
    }
    assert!(
        rejected > 0,
        "the graph must constrain at least one guard to a subset of actors"
    );
}
