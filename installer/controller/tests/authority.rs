use jstack_installer_core::{Confirmation, Hash256, InstallPlan, PlanDisplay};
use sha2::{Digest, Sha256};

use jstack_installer_controller::{GraphModel, GuardDef, SelectionError, load_verified};

use jstack_installer_controller::authority::{
    ActorCapability, CapabilityAuthority, CapabilityIssueError, ConfirmationCapabilities,
    GuardCapability, GuardWitnessValidator, PresentedAuthorization, TransitionAuthorizationError,
    authorize_transition,
};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const PLAN: &str = include_str!("../../core/generated/example-plan.json");
const DISPLAY: &str = include_str!("../../core/generated/example-plan-display.json");
const CONFIRMATION: &str = include_str!("../../core/generated/example-confirmation.json");

const RESERVE_GUARDS: &[&str] = &[
    "confirmed_plan_current",
    "plan_fingerprint_current",
    "windows_ntfs_supported",
    "finalizer_registered",
];

const AMBIGUOUS_PREPARE_GUARDS: &[&str] = &[
    "confirmed_plan_current",
    "plan_fingerprint_current",
    "bitlocker_enabled",
    "bitlocker_recovery_key_confirmed",
    "bitlocker_disabled",
];

fn hash(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

fn graph() -> GraphModel {
    load_verified(GRAPH, &hash(GRAPH)).unwrap()
}

fn confirmation_capabilities(authority: &CapabilityAuthority<'_>) -> ConfirmationCapabilities {
    let plan: InstallPlan = serde_json::from_str(PLAN).unwrap();
    let displayed: PlanDisplay = serde_json::from_str(DISPLAY).unwrap();
    let confirmation: Confirmation = serde_json::from_str(CONFIRMATION).unwrap();
    authority
        .issue_confirmation(&plan, &displayed, &confirmation)
        .unwrap()
}

struct ExactGuardValidator;

impl GuardWitnessValidator<str> for ExactGuardValidator {
    type Error = &'static str;

    fn validate(
        &self,
        graph: &GraphModel,
        actor: &str,
        guard: &GuardDef,
        evidence: &str,
    ) -> Result<Hash256, Self::Error> {
        if graph.actor_platforms(actor).is_none() || evidence != guard.id {
            return Err("guard evidence does not match the observed guard");
        }
        Ok(hash(
            format!("{actor}\0{}\0{evidence}", guard.id).as_bytes(),
        ))
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
                .issue_guard(actor, guard, *guard, &ExactGuardValidator)
                .unwrap()
        })
        .collect()
}

fn guard_refs(guards: &[GuardCapability]) -> Vec<&GuardCapability> {
    guards.iter().collect()
}

#[test]
fn missing_authorization_fails_closed_after_exact_selection() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let actor = authority.issue_actor("windows_bootstrap").unwrap();
    let guards = issue_guards(&authority, &actor, RESERVE_GUARDS);
    let from = graph.state_id("windows.bitlocker_prepared").unwrap();

    assert_eq!(
        authorize_transition(
            &graph,
            from,
            "shrink_windows",
            &actor,
            &[],
            &guard_refs(&guards),
        )
        .unwrap_err(),
        TransitionAuthorizationError::AuthorizationSetMismatch
    );
}

#[test]
fn wrong_actor_fails_closed_even_with_exact_guards_and_authorization() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let transition_actor = authority.issue_actor("windows_bootstrap").unwrap();
    let wrong_actor = authority.issue_actor("linux_installer").unwrap();
    let guards = issue_guards(&authority, &transition_actor, RESERVE_GUARDS);
    let confirmation = confirmation_capabilities(&authority);
    let authorizations = [PresentedAuthorization::from(confirmation.confirmed_plan())];
    let from = graph.state_id("windows.bitlocker_prepared").unwrap();

    assert_eq!(
        authorize_transition(
            &graph,
            from,
            "shrink_windows",
            &wrong_actor,
            &authorizations,
            &guard_refs(&guards),
        )
        .unwrap_err(),
        TransitionAuthorizationError::WrongActor {
            expected: "windows_bootstrap".into(),
            actual: "linux_installer".into(),
        }
    );
}

#[test]
fn wrong_extra_guard_fails_closed_instead_of_authorizing_a_subset_match() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let actor = authority.issue_actor("windows_bootstrap").unwrap();
    let mut guard_names = RESERVE_GUARDS.to_vec();
    guard_names.push("release_manifest_valid");
    let guards = issue_guards(&authority, &actor, &guard_names);
    let confirmation = confirmation_capabilities(&authority);
    let authorizations = [PresentedAuthorization::from(confirmation.confirmed_plan())];
    let from = graph.state_id("windows.bitlocker_prepared").unwrap();

    assert_eq!(
        authorize_transition(
            &graph,
            from,
            "shrink_windows",
            &actor,
            &authorizations,
            &guard_refs(&guards),
        )
        .unwrap_err(),
        TransitionAuthorizationError::GuardSetMismatch
    );
}

#[test]
fn zero_candidates_fail_closed_through_graph_selection() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let actor = authority.issue_actor("windows_bootstrap").unwrap();

    assert_eq!(
        authorize_transition(
            &graph,
            graph.initial_state(),
            "not_a_graph_event",
            &actor,
            &[],
            &[],
        )
        .unwrap_err(),
        TransitionAuthorizationError::Selection(SelectionError::NoneEnabled)
    );
}

#[test]
fn ambiguous_candidates_fail_closed_through_graph_selection() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let actor = authority.issue_actor("windows_bootstrap").unwrap();
    let guards = issue_guards(&authority, &actor, AMBIGUOUS_PREPARE_GUARDS);
    let confirmation = confirmation_capabilities(&authority);
    let authorizations = [PresentedAuthorization::from(confirmation.confirmed_plan())];
    let from = graph.state_id("windows.plan_confirmed").unwrap();

    assert!(matches!(
        authorize_transition(
            &graph,
            from,
            "prepare_security",
            &actor,
            &authorizations,
            &guard_refs(&guards),
        ),
        Err(TransitionAuthorizationError::Selection(
            SelectionError::Ambiguous(candidates)
        )) if candidates.len() == 2
    ));
}

#[test]
fn exact_actor_authorization_and_verified_guards_select_one_transition() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let actor = authority.issue_actor("windows_bootstrap").unwrap();
    let guards = issue_guards(&authority, &actor, RESERVE_GUARDS);
    let confirmation = confirmation_capabilities(&authority);
    let authorizations = [PresentedAuthorization::from(confirmation.confirmed_plan())];
    let from = graph.state_id("windows.bitlocker_prepared").unwrap();

    let authorized = authorize_transition(
        &graph,
        from,
        "shrink_windows",
        &actor,
        &authorizations,
        &guard_refs(&guards),
    )
    .unwrap();

    assert_eq!(
        authorized.transition_id(),
        graph.transition_id("reserve_windows_space").unwrap()
    );
    assert_eq!(authorized.graph_digest(), graph.digest());
}

#[test]
fn issuance_rejects_failed_confirmation_and_failed_guard_validator() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let plan: InstallPlan = serde_json::from_str(PLAN).unwrap();
    let displayed: PlanDisplay = serde_json::from_str(DISPLAY).unwrap();
    let mut confirmation: Confirmation = serde_json::from_str(CONFIRMATION).unwrap();
    confirmation.authorization = "forged".into();
    assert!(matches!(
        authority.issue_confirmation(&plan, &displayed, &confirmation),
        Err(CapabilityIssueError::InvalidConfirmation(_))
    ));

    let actor = authority.issue_actor("windows_bootstrap").unwrap();
    assert!(matches!(
        authority.issue_guard(
            &actor,
            "confirmed_plan_current",
            "different_guard",
            &ExactGuardValidator,
        ),
        Err(CapabilityIssueError::GuardWitnessRejected(_))
    ));
}

#[test]
fn rollback_capability_is_derived_only_from_validated_confirmation() {
    let graph = graph();
    let authority = CapabilityAuthority::new(&graph);
    let confirmation = confirmation_capabilities(&authority);
    let rollback = authority
        .issue_rollback(confirmation.user_confirmation())
        .unwrap();

    assert_eq!(
        rollback.plan_hash(),
        confirmation.confirmed_plan().plan_hash()
    );
}
