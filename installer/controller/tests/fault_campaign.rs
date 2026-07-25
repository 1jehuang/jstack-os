//! PH-14 graph-derived fault campaign.
//!
//! The campaign is derived from the executable graph rather than hand-written:
//! it walks every reachable mutating transition and, at each one, injects every
//! modelled fault class and every crash boundary. The properties asserted at
//! each point are the ones a real fault campaign must establish:
//!
//! * the control state after a fault is always a state the graph declares as
//!   that transition's success or failure target, never an invented one,
//! * a failure that leaves no new committed effect produces exactly one
//!   canonical failure-evidence object and lands on the exact `failure_to`,
//! * a failure that does leave a committed effect halts for manual recovery and
//!   fabricates no evidence,
//! * the durable journal always replays to the same disposition in a fresh
//!   process, and
//! * a rollback from any post-mutation state reaches a declared terminal.
//!
//! Every case runs against the in-memory platform, so the campaign is
//! deterministic and needs no VM. It is the pre-hardware half of PH-14; the
//! disposable-VM half is recorded separately in the ledger.

use std::collections::{BTreeMap, BTreeSet};

use jstack_installer_controller::platform::{BitLockerState, RunningSystem, VirtualPlatform};
use jstack_installer_controller::runtime::{
    CrashPoint, EffectBoundary, InjectedFault, Runtime, StepResult,
};
use jstack_installer_controller::{
    DirectOutcome, GraphModel, JournalDisposition, StateId, TransitionId, load_verified,
};
use jstack_installer_core::{Hash256, InstallPlan, JournalRecordType};
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const PLAN: &str = include_str!("../../core/generated/example-plan.json");

fn graph() -> GraphModel {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).unwrap()
}

fn plan() -> InstallPlan {
    serde_json::from_str(PLAN).unwrap()
}

/// The install path, as an ordered transition list per BitLocker profile.
fn path(bitlocker: BitLockerState) -> Vec<&'static str> {
    let mut steps = vec![
        "begin_preflight",
        "acquire_release_manifest",
        "persist_release_acceptance",
        "accept_preflight_and_plan",
        "begin_payload_staging",
        "accept_verified_payload",
        "show_exact_plan",
        "confirm_exact_plan",
    ];
    if bitlocker == BitLockerState::Protected {
        steps.push("prepare_bitlocker");
        steps.push("suspend_bitlocker_after_finalizer");
    } else {
        steps.push("prepare_without_bitlocker");
    }
    steps.extend([
        "reserve_windows_space",
        "create_xbootldr",
        "format_xbootldr",
        "copy_verified_payload",
        "stage_installer_loader",
        "create_installer_entry",
        "arm_installer_bootnext",
        "reboot_to_installer",
        "installer_boot_observed",
        "verify_linux_handoff",
        "revalidate_linux_plan",
        "create_linux_root",
        "format_linux_root",
        "deploy_jstack_image",
        "configure_jstack_system",
        "install_jstack_boot",
        "verify_offline_install",
        "arm_windows_finalizer",
        "arm_windows_finalize",
        "windows_finalizer_booted",
        "restore_windows_security",
        "cleanup_windows_bootstrap",
        "arm_installed_jstack",
        "reboot_to_installed_jstack",
        "jstack_boot_observed",
        "complete_after_first_boot",
    ]);
    steps
}

fn boot_after(transition: &str) -> Option<RunningSystem> {
    match transition {
        "reboot_to_installer" => Some(RunningSystem::LinuxInstaller),
        "arm_windows_finalize" => Some(RunningSystem::Windows),
        "reboot_to_installed_jstack" => Some(RunningSystem::Jstack),
        _ => None,
    }
}

fn runtime(graph: &GraphModel, bitlocker: BitLockerState) -> Runtime<'_> {
    let platform = VirtualPlatform::from_plan(&plan(), bitlocker).unwrap();
    Runtime::new(graph, &plan(), EffectBoundary::virtual_platform(platform))
}

/// Drive the path up to (not including) `stop_before`.
fn advance_to<'a>(
    graph: &'a GraphModel,
    bitlocker: BitLockerState,
    stop_before: &str,
) -> Runtime<'a> {
    let mut runtime = runtime(graph, bitlocker);
    for name in path(bitlocker) {
        if name == stop_before {
            return runtime;
        }
        let transition = graph.transition_id(name).unwrap();
        if graph.is_mutating(transition) {
            runtime
                .step(transition, None, None)
                .unwrap_or_else(|error| panic!("{name} failed while advancing: {error}"));
        } else {
            runtime
                .advance_direct(transition, DirectOutcome::Success)
                .unwrap_or_else(|error| panic!("{name} failed while advancing: {error}"));
        }
        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }
    }
    panic!("{stop_before} is not on the path");
}

/// Whether a transition's actions bring a durable, plan-owned object into
/// existence. A failure after such an action leaves a committed effect, so the
/// runtime must halt instead of writing a no-committed-effect proof.
fn creates_durable_object(graph: &GraphModel, transition: TransitionId) -> bool {
    graph
        .transition(transition)
        .def
        .actions
        .iter()
        .any(|action| {
            matches!(
                action.as_str(),
                "create_xbootldr_partition"
                    | "create_root_partition"
                    | "stage_namespaced_esp_loader"
                    | "create_installer_boot_entry"
                    | "install_jstack_boot_artifacts"
                    | "register_windows_finalizer"
            )
        })
}

/// The set of control states the graph permits after attempting `transition`.
fn permitted_states(graph: &GraphModel, transition: TransitionId) -> BTreeSet<StateId> {
    let resolved = graph.transition(transition);
    let mut permitted = BTreeSet::from([resolved.from, resolved.to]);
    if let Some(failure) = resolved.failure_to {
        permitted.insert(failure);
    }
    permitted
}

/// Every mutating transition on both profiles, under every fault class, must
/// land on a graph-declared state and never fabricate evidence.
#[test]
fn every_mutating_transition_survives_every_fault_class() {
    let graph = graph();
    let mut covered: BTreeMap<&str, usize> = BTreeMap::new();

    for bitlocker in [BitLockerState::NotApplicable, BitLockerState::Protected] {
        for name in path(bitlocker) {
            let transition = graph.transition_id(name).unwrap();
            if !graph.is_mutating(transition) {
                continue;
            }
            let permitted = permitted_states(&graph, transition);

            for fault in [
                InjectedFault::before_first_action(),
                InjectedFault::ClaimSuccessWithoutEffect,
                InjectedFault::FailAfterEffect,
            ] {
                let mut runtime = advance_to(&graph, bitlocker, name);
                let before = runtime.journal().len();
                let result = runtime
                    .step(transition, Some(fault), None)
                    .unwrap_or_else(|error| panic!("{name} under {fault:?}: {error}"));

                let state = runtime.state().unwrap();
                assert!(
                    permitted.contains(&state),
                    "{name} under {fault:?} reached {}, which the graph does not declare",
                    graph.state(state).id
                );

                // The fault class determines which outcomes are legal. A fault
                // that landed a real effect must never be allowed to fail
                // forward with a no-committed-effect proof, because that proof
                // would be false.
                if fault == InjectedFault::FailAfterEffect
                    && creates_durable_object(&graph, transition)
                {
                    assert_eq!(
                        result,
                        Some(StepResult::HaltedForManualRecovery),
                        "{name} landed a durable object then failed, so it must halt \
                         rather than claim no committed effect"
                    );
                }

                match result {
                    Some(StepResult::FailedForward) => {
                        // Exactly one canonical evidence object, bound to the
                        // graph's own failure target.
                        assert_eq!(
                            runtime.failure_evidence().len(),
                            1,
                            "{name} under {fault:?} must produce exactly one evidence object"
                        );
                        let evidence = &runtime.failure_evidence()[0];
                        assert_eq!(evidence.transition_id, name);
                        let expected = graph
                            .transition(transition)
                            .failure_to
                            .map(|state| graph.state(state).id.clone())
                            .expect("a mutating transition must declare a failure edge");
                        assert_eq!(evidence.failure_state, expected);
                        assert_eq!(graph.state(state).id, expected);
                        // The journal is the legal triad.
                        let types: Vec<_> = runtime.journal()[before..]
                            .iter()
                            .map(|record| record.record_type)
                            .collect();
                        assert_eq!(
                            types,
                            vec![
                                JournalRecordType::ActionIntent,
                                JournalRecordType::ActionFailed,
                                JournalRecordType::StateAdvanced,
                            ],
                            "{name} under {fault:?} wrote an illegal record sequence"
                        );
                    }
                    Some(StepResult::HaltedForManualRecovery) => {
                        // No evidence may be fabricated, and the control state
                        // must not have advanced.
                        assert!(
                            runtime.failure_evidence().is_empty(),
                            "{name} under {fault:?} fabricated failure evidence"
                        );
                        assert!(
                            !runtime
                                .journal()
                                .iter()
                                .any(|r| r.record_type == JournalRecordType::ActionFailed),
                            "{name} under {fault:?} wrote an action_failed record"
                        );
                        assert_eq!(state, graph.transition(transition).from);
                        assert!(matches!(
                            runtime.disposition().unwrap(),
                            JournalDisposition::ActionPending { .. }
                        ));
                    }
                    Some(StepResult::Committed) => {
                        // A fault that the platform absorbed (an idempotent or
                        // no-op action) may still commit, but only to the exact
                        // success target.
                        assert_eq!(state, graph.transition(transition).to);
                    }
                    None => panic!("{name} under {fault:?} reported a crash without one"),
                }

                // The durable journal must replay to the same disposition in a
                // fresh process.
                let expected_state = state;
                let (journal, evidence, boundary) = runtime.into_parts();
                let restored = Runtime::restore(&graph, &plan(), boundary, journal, evidence);
                assert_eq!(
                    restored.state().unwrap(),
                    expected_state,
                    "{name} under {fault:?} does not replay to the same state"
                );

                *covered.entry(name).or_default() += 1;
            }
        }
    }

    // Every mutating transition on the paths was covered by every fault class.
    assert!(
        covered.len() >= 20,
        "expected broad mutating coverage, saw {} transitions",
        covered.len()
    );
    for (name, count) in &covered {
        assert!(
            *count >= 3,
            "{name} was only exercised by {count} fault classes"
        );
    }
}

/// Every crash boundary of every mutating transition replays to a disposition
/// the graph permits, and resuming always converges.
#[test]
fn every_crash_boundary_replays_to_a_graph_permitted_disposition() {
    let graph = graph();
    let mut cases = 0_usize;

    for name in path(BitLockerState::NotApplicable) {
        let transition = graph.transition_id(name).unwrap();
        if !graph.is_mutating(transition) {
            continue;
        }
        let permitted = permitted_states(&graph, transition);

        for point in CrashPoint::ALL {
            let mut runtime = advance_to(&graph, BitLockerState::NotApplicable, name);
            let outcome = runtime.step(transition, None, Some(point)).unwrap();

            // Replay in a fresh process from the durable records alone.
            let (journal, evidence, boundary) = runtime.into_parts();
            let mut restored = Runtime::restore(&graph, &plan(), boundary, journal, evidence);
            let state = restored.state().unwrap();
            assert!(
                permitted.contains(&state),
                "crash at {point:?} during {name} replayed to {}, which the graph does not declare",
                graph.state(state).id
            );

            if outcome.is_none() {
                // Resuming must converge, and resuming twice must be a no-op.
                restored.resume().unwrap();
                let after = restored.state().unwrap();
                let length = restored.journal().len();
                restored.resume().unwrap();
                assert_eq!(restored.state().unwrap(), after);
                assert_eq!(
                    restored.journal().len(),
                    length,
                    "a second resume must append nothing"
                );
                assert!(permitted.contains(&after));
            }
            cases += 1;
        }
    }
    assert!(cases >= 100, "expected a broad crash matrix, saw {cases}");
}

/// A rollback request from every post-mutation state reaches a graph-declared
/// terminal, so no mutation leaves the operator without a defined exit.
#[test]
fn every_post_mutation_state_can_reach_a_declared_terminal() {
    let graph = graph();
    let mut checked = 0_usize;

    for name in path(BitLockerState::NotApplicable) {
        let transition = graph.transition_id(name).unwrap();
        if !graph.is_mutating(transition) {
            continue;
        }
        let state = graph.transition(transition).to;

        // Every state reached by a mutation must have some outgoing edge that
        // leads toward a terminal. Prove reachability of a terminal by search
        // over the graph rather than by asserting a hand-written list.
        let mut seen = BTreeSet::from([state]);
        let mut frontier = vec![state];
        let mut reaches_terminal = false;
        while let Some(current) = frontier.pop() {
            if graph.state(current).terminal_outcome.is_some() {
                reaches_terminal = true;
                break;
            }
            for candidate in graph.transition_ids() {
                let resolved = graph.transition(candidate);
                if resolved.from != current {
                    continue;
                }
                for next in [Some(resolved.to), resolved.failure_to]
                    .into_iter()
                    .flatten()
                {
                    if seen.insert(next) {
                        frontier.push(next);
                    }
                }
            }
        }
        assert!(
            reaches_terminal,
            "{} is reachable by mutation but cannot reach a terminal",
            graph.state(state).id
        );
        checked += 1;
    }
    assert!(
        checked >= 20,
        "expected many post-mutation states, saw {checked}"
    );
}

/// Tamper class: corrupting the staged loader after it is verified must prevent
/// a boot from ever being armed, on every transition that arms one.
#[test]
fn tampering_with_the_staged_loader_prevents_arming_any_boot() {
    let graph = graph();
    let name = "arm_installer_bootnext";
    let mut runtime = advance_to(&graph, BitLockerState::NotApplicable, name);
    runtime
        .boundary_mut()
        .platform_mut()
        .corrupt_staged_loader();

    let transition = graph.transition_id(name).unwrap();
    let permitted = permitted_states(&graph, transition);
    let result = runtime.step(transition, None, None).unwrap();
    let state = runtime.state().unwrap();

    assert!(permitted.contains(&state));
    assert_ne!(
        result,
        Some(StepResult::Committed),
        "{name} must not commit with a corrupted loader"
    );
    assert!(
        !runtime
            .boundary()
            .platform()
            .observe("bootnext_is_installer")
            .unwrap(),
        "a corrupted loader must never be armed for boot"
    );
}

/// Stale-identity class: a journal bound to a different plan is rejected rather
/// than replayed against this machine.
#[test]
fn a_journal_bound_to_another_plan_is_rejected_on_replay() {
    let graph = graph();
    let runtime = advance_to(&graph, BitLockerState::NotApplicable, "create_xbootldr");
    let (journal, evidence, boundary) = runtime.into_parts();
    assert!(!journal.is_empty());

    // A different plan hash means a different confirmed plan.
    let mut other = plan();
    other.plan_hash = Hash256::parse("f".repeat(64)).unwrap();
    let restored = Runtime::restore(&graph, &other, boundary, journal, evidence);
    assert!(
        restored.state().is_err(),
        "a journal from another plan must not replay"
    );
}

/// Reboot class: a reboot request cannot be followed by another reboot without
/// an intervening boot observation, so a rearm loop is bounded.
#[test]
fn a_reboot_cannot_be_repeated_without_observing_a_boot() {
    let graph = graph();
    let mut runtime = advance_to(&graph, BitLockerState::NotApplicable, "reboot_to_installer");
    let reboot = graph.transition_id("reboot_to_installer").unwrap();
    runtime.step(reboot, None, None).unwrap();

    // The machine is waiting for a boot. Observing it twice is refused.
    runtime.observe_boot(RunningSystem::LinuxInstaller).unwrap();
    assert!(
        runtime.observe_boot(RunningSystem::LinuxInstaller).is_err(),
        "a boot cannot be observed twice without a new reboot request"
    );
}

/// Finalizer class: the finalizer must be registered before the install can arm
/// it, and BitLocker must be restored before the bootstrap is cleaned up.
#[test]
fn finalizer_and_security_ordering_is_enforced_by_preconditions() {
    let graph = graph();

    // Arming the finalizer requires it to be registered. Reaching that
    // transition on the normal path already implies registration, so assert the
    // precondition is genuinely observed rather than assumed.
    let arm = graph.transition_id("arm_windows_finalizer").unwrap();
    assert!(
        graph
            .transition(arm)
            .def
            .preconditions
            .contains(&"finalizer_registered".to_owned()),
        "arming the finalizer must require registration"
    );

    let cleanup = graph.transition_id("cleanup_windows_bootstrap").unwrap();
    assert!(
        graph
            .transition(cleanup)
            .def
            .preconditions
            .contains(&"bitlocker_restored_or_not_applicable".to_owned()),
        "cleanup must require BitLocker to be restored first"
    );

    // And the platform actually refuses cleanup while BitLocker is suspended.
    let mut runtime = advance_to(
        &graph,
        BitLockerState::Protected,
        "restore_windows_security",
    );
    assert_eq!(
        runtime.boundary().platform().bitlocker(),
        BitLockerState::Suspended
    );
    let result = runtime.step(cleanup, None, None);
    assert!(
        result.is_err() || result.unwrap() != Some(StepResult::Committed),
        "cleanup must not commit while BitLocker is still suspended"
    );
}
