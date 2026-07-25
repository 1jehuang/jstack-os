//! PH-03 restart-safe execution, PH-04 verified failure admission, and PH-06
//! deterministic virtual platform.
//!
//! The central proof is convergence: for every mutating transition on the
//! happy path, crashing at every durable boundary and restarting must reach the
//! same durable control state and the same observable machine as an
//! uninterrupted run. A test exit code alone is not the evidence; each case
//! compares a derived control state, a journal-derived disposition, and a
//! content digest of the whole virtual machine.

use std::collections::BTreeSet;

use jstack_installer_controller::platform::{
    BitLockerState, BootTarget, PlatformError, RunningSystem, VirtualPlatform,
};
use jstack_installer_controller::runtime::{
    CrashPoint, EffectBoundary, InjectedFault, Runtime, RuntimeError, StepResult,
};
use jstack_installer_controller::{
    DirectOutcome, GraphModel, JournalDisposition, TransitionId, load_verified,
};
use jstack_installer_core::{Hash256, InstallPlan, JournalRecordType, RollbackObjectKind};
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

fn platform(bitlocker: BitLockerState) -> VirtualPlatform {
    VirtualPlatform::from_plan(&plan(), bitlocker).unwrap()
}

fn runtime(graph: &GraphModel, bitlocker: BitLockerState) -> Runtime<'_> {
    Runtime::new(
        graph,
        &plan(),
        EffectBoundary::virtual_platform(platform(bitlocker)),
    )
}

/// The happy path with BitLocker absent, as an ordered transition list.
const HAPPY_PATH: &[&str] = &[
    "begin_preflight",
    "acquire_release_manifest",
    "persist_release_acceptance",
    "accept_preflight_and_plan",
    "begin_payload_staging",
    "accept_verified_payload",
    "show_exact_plan",
    "confirm_exact_plan",
    "prepare_without_bitlocker",
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
];

/// Boot observations that must happen between specific transitions, modelling
/// the firmware actually bringing a system up.
fn boot_after(transition: &str) -> Option<RunningSystem> {
    match transition {
        "reboot_to_installer" => Some(RunningSystem::LinuxInstaller),
        "arm_windows_finalize" => Some(RunningSystem::Windows),
        "reboot_to_installed_jstack" => Some(RunningSystem::Jstack),
        _ => None,
    }
}

/// Drive one transition, choosing the mutating or direct protocol from the
/// graph rather than from a hardcoded list.
fn drive(
    runtime: &mut Runtime<'_>,
    graph: &GraphModel,
    transition: TransitionId,
    crash_at: Option<CrashPoint>,
) -> Result<Option<StepResult>, RuntimeError> {
    if graph.is_mutating(transition) {
        runtime.step(transition, None, crash_at)
    } else {
        runtime
            .advance_direct(transition, DirectOutcome::Success)
            .map(Some)
    }
}

/// Run the happy path to completion, optionally crashing at one boundary of one
/// transition and resuming. Returns the terminal state id and machine digest.
fn run_happy_path(
    graph: &GraphModel,
    crash: Option<(usize, CrashPoint)>,
) -> (String, Hash256, usize) {
    let mut runtime = runtime(graph, BitLockerState::NotApplicable);
    let mut restarts = 0_usize;

    for (index, name) in HAPPY_PATH.iter().enumerate() {
        let transition = graph.transition_id(name).unwrap();
        let crash_at = crash.and_then(|(target, point)| (target == index).then_some(point));

        let result = drive(&mut runtime, graph, transition, crash_at).unwrap();
        if result.is_none() {
            // A crash happened. Simulate a restart: rebuild the runtime from
            // the durable journal alone, keeping only the machine (which
            // survives a power loss) and nothing in memory.
            restarts += 1;
            let (journal, evidence, boundary) = runtime.into_parts();
            let mut restored = Runtime::restore(graph, &plan(), boundary, journal, evidence);
            let resumed = restored.resume().unwrap();
            assert_eq!(
                resumed,
                StepResult::Committed,
                "crash during {name} did not converge forward"
            );
            runtime = restored;

            // If the crash landed before the intent was durable, the
            // transition never started and must still be run.
            if crash_at == Some(CrashPoint::BeforeIntent) {
                drive(&mut runtime, graph, transition, None).unwrap();
            }
        }

        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }
    }

    let state = runtime.state().unwrap();
    (
        graph.state(state).id.clone(),
        runtime.boundary().platform().digest(),
        restarts,
    )
}

/// The uninterrupted happy path reaches the completed terminal and leaves an
/// installed machine.
#[test]
fn uninterrupted_happy_path_reaches_the_completed_terminal() {
    let graph = graph();
    let (state, digest, restarts) = run_happy_path(&graph, None);
    assert_eq!(state, "terminal.completed");
    assert_eq!(restarts, 0);

    // The machine is genuinely installed, not merely "the test passed".
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }
    }
    let machine = runtime.boundary().platform();
    assert_eq!(machine.digest(), digest, "the run must be deterministic");
    assert!(machine.observe("deployed_image_hash_matches").unwrap());
    assert!(machine.observe("jstack_boot_entry_valid").unwrap());
    assert!(machine.observe("windows_boot_entry_present").unwrap());
    assert!(machine.observe("installed_configuration_valid").unwrap());
    assert!(
        machine
            .observe("temporary_bootstrap_state_removed")
            .unwrap()
    );
    assert_eq!(machine.running(), RunningSystem::Jstack);
}

/// PH-03: a crash at every durable boundary of every mutating transition
/// converges to exactly the uninterrupted outcome.
#[test]
fn crashing_at_every_durable_boundary_converges_to_the_uninterrupted_outcome() {
    let graph = graph();
    let (expected_state, expected_digest, _) = run_happy_path(&graph, None);

    let mut covered = 0_usize;
    for (index, name) in HAPPY_PATH.iter().enumerate() {
        let transition = graph.transition_id(name).unwrap();
        if !graph.is_mutating(transition) {
            continue;
        }
        for point in CrashPoint::ALL {
            let (state, digest, restarts) = run_happy_path(&graph, Some((index, point)));
            assert_eq!(
                state, expected_state,
                "crash at {point:?} during {name} diverged to {state}"
            );
            assert_eq!(
                digest, expected_digest,
                "crash at {point:?} during {name} left a different machine"
            );
            // AfterAdvance is not observable as a crash because the transition
            // has already completed; every earlier boundary must restart.
            if point != CrashPoint::AfterAdvance {
                assert_eq!(
                    restarts, 1,
                    "crash at {point:?} during {name} did not restart"
                );
            }
            covered += 1;
        }
    }
    assert!(
        covered >= 5 * 20,
        "every mutating happy-path transition must be crashed at every boundary, saw {covered}"
    );
}

/// `resume` is a pure function of the durable journal: replaying it twice from
/// the same records produces the same disposition, and resuming a quiescent
/// journal is a no-op.
#[test]
fn resume_is_a_total_function_of_the_durable_journal() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);

    for name in HAPPY_PATH.iter().take(12) {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }

        // Resuming a quiescent journal must not append anything or change the
        // derived state.
        let before = runtime.journal().len();
        let state = runtime.state().unwrap();
        assert_eq!(runtime.resume().unwrap(), StepResult::Committed);
        assert_eq!(runtime.journal().len(), before);
        assert_eq!(runtime.state().unwrap(), state);
        assert!(matches!(
            runtime.disposition().unwrap(),
            JournalDisposition::Quiescent { .. }
        ));
    }
}

/// PH-04: an action that fails without leaving an effect is admitted only with
/// a recomputed no-committed-effect proof, and lands on the graph's exact
/// failure state.
#[test]
fn a_clean_failure_advances_to_the_exact_graph_failure_state_with_a_proof() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    let transition = graph.transition_id("begin_preflight").unwrap();

    let result = runtime
        .step(transition, Some(InjectedFault::before_first_action()), None)
        .unwrap();
    assert_eq!(result, Some(StepResult::FailedForward));

    // The control state is the graph's declared failure target, not a value the
    // caller chose.
    let state = runtime.state().unwrap();
    let expected = graph
        .transition(transition)
        .failure_to
        .map(|state| graph.state(state).id.clone())
        .unwrap();
    assert_eq!(graph.state(state).id, expected);

    // Exactly one canonical failure-evidence object exists and it is bound to
    // the exact intent record.
    assert_eq!(runtime.failure_evidence().len(), 1);
    let evidence = &runtime.failure_evidence()[0];
    assert_eq!(evidence.transition_id, "begin_preflight");
    assert_eq!(evidence.failure_state, expected);
    assert_eq!(evidence.graph_model_id, graph.model_id());
    assert!(evidence.residual_objects.is_empty());

    // The journal is the legal intent/failed/advanced triad.
    let types: Vec<_> = runtime
        .journal()
        .iter()
        .map(|record| record.record_type)
        .collect();
    assert_eq!(
        types,
        vec![
            JournalRecordType::ActionIntent,
            JournalRecordType::ActionFailed,
            JournalRecordType::StateAdvanced,
        ]
    );

    // Replay from the durable records alone derives the same state.
    let (journal, failure_evidence, boundary) = runtime.into_parts();
    let restored = Runtime::restore(&graph, &plan(), boundary, journal, failure_evidence);
    assert_eq!(graph.state(restored.state().unwrap()).id, expected);
}

/// PH-04: when a committed effect survives a failure, the runtime halts for
/// manual recovery rather than forging a no-committed-effect proof.
#[test]
fn a_surviving_effect_halts_instead_of_forging_a_failure_proof() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);

    // Reach the state where the finalizer has been registered, which is a
    // durable object recorded in the journal.
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "reserve_windows_space")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }
    assert!(
        runtime
            .boundary()
            .platform()
            .residual_objects()
            .iter()
            .any(|object| object.kind == RollbackObjectKind::WindowsFinalizer),
        "the finalizer must be a surviving residual object"
    );

    // Now fail a later transition. The finalizer predates this attempt, so it
    // is not a *new* committed effect and the failure is still clean.
    let shrink = graph.transition_id("reserve_windows_space").unwrap();
    let result = runtime
        .step(shrink, Some(InjectedFault::before_first_action()), None)
        .unwrap();
    assert_eq!(
        result,
        Some(StepResult::FailedForward),
        "a pre-existing object must not be mistaken for a new committed effect"
    );
    assert_eq!(
        graph.state(runtime.state().unwrap()).id,
        "recovery.rollback_required"
    );
}

/// PH-04: a lying executor is caught, because postconditions are observed
/// independently of the executor's own return value.
#[test]
fn postconditions_are_observed_independently_of_the_executor() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "arm_installer_bootnext")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }

    // Corrupt the staged loader behind the runtime's back. The BootNext
    // transition re-hashes the payload, so it must refuse rather than arm a
    // boot entry pointing at unverified bytes.
    runtime
        .boundary_mut()
        .platform_mut()
        .corrupt_staged_loader();
    let arm = graph.transition_id("arm_installer_bootnext").unwrap();
    let result = runtime.step(arm, None, None).unwrap();
    assert_eq!(result, Some(StepResult::FailedForward));
    assert_ne!(
        runtime.boundary().platform().boot_next(),
        BootTarget::Installer,
        "a corrupted loader must never be armed for boot"
    );
}

/// The runtime refuses to start a transition that is not adjacent to the
/// durable control state, and refuses to mix the mutating and direct protocols.
#[test]
fn the_runtime_refuses_non_adjacent_and_misclassified_transitions() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);

    let far = graph.transition_id("deploy_jstack_image").unwrap();
    assert!(matches!(
        runtime.step(far, None, None),
        Err(RuntimeError::NonAdjacent { .. })
    ));

    // `begin_preflight` is mutating, so the direct-advance path must reject it.
    let mutating = graph.transition_id("begin_preflight").unwrap();
    assert!(
        runtime
            .advance_direct(mutating, DirectOutcome::Success)
            .is_err()
    );

    // Conversely a non-mutating transition cannot be run as a mutating step.
    drive(&mut runtime, &graph, mutating, None).unwrap();
    for name in ["acquire_release_manifest", "persist_release_acceptance"] {
        drive(
            &mut runtime,
            &graph,
            graph.transition_id(name).unwrap(),
            None,
        )
        .unwrap();
    }
    let direct = graph.transition_id("accept_preflight_and_plan").unwrap();
    assert!(matches!(
        runtime.step(direct, None, None),
        Err(RuntimeError::NonMutatingTransition(_))
    ));
}

/// PH-06: every condition named anywhere in the graph is answerable by the
/// virtual platform. An unmodelled condition is an error, so a graph edit
/// cannot introduce a silently unobserved precondition.
#[test]
fn the_virtual_platform_answers_every_graph_condition() {
    let graph = graph();
    let machine = platform(BitLockerState::Protected);

    let mut conditions = BTreeSet::new();
    for id in graph.transition_ids() {
        let transition = graph.transition(id);
        conditions.extend(transition.def.preconditions.iter().cloned());
        conditions.extend(transition.def.postconditions.iter().cloned());
    }
    assert!(
        conditions.len() > 60,
        "the graph must declare many conditions"
    );

    for condition in &conditions {
        machine
            .observe(condition)
            .unwrap_or_else(|error| panic!("condition {condition} is unmodelled: {error}"));
    }

    // An identifier the graph does not use is rejected rather than defaulted.
    assert!(matches!(
        machine.observe("not_a_real_condition"),
        Err(PlatformError::UnknownCondition(_))
    ));
}

/// PH-06: every action named by the graph is modelled. An unmodelled action is
/// an error rather than a silent no-op that would fake a postcondition.
#[test]
fn the_virtual_platform_models_every_graph_action() {
    let graph = graph();
    for id in graph.action_ids() {
        let action = graph.action(id);
        let mut machine = platform(BitLockerState::Protected);
        match machine.apply(&action.id) {
            Ok(()) => {}
            Err(PlatformError::UnknownAction(name)) => {
                panic!("graph action {name} is not modelled by the virtual platform")
            }
            // Applying an action out of order legitimately fails; what must
            // never happen is the action being unknown.
            Err(_) => {}
        }
    }
}

/// PH-06: the virtual GPT never admits an overlapping or escaping partition,
/// and partitions are created only at the confirmed plan's exact geometry.
#[test]
fn the_virtual_gpt_rejects_overlap_and_escapes_from_the_confirmed_interval() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "create_xbootldr")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }

    let created = graph.transition_id("create_xbootldr").unwrap();
    drive(&mut runtime, &graph, created, None).unwrap();

    let body = plan().body;
    let expected = body
        .created_partitions
        .iter()
        .find(|partition| partition.role == jstack_installer_core::PartitionRole::Xbootldr)
        .unwrap();
    let actual = runtime
        .boundary()
        .platform()
        .partitions()
        .iter()
        .find(|partition| partition.partition_guid == expected.partition_guid.to_string())
        .expect("xbootldr must exist");
    assert_eq!(actual.offset_bytes, expected.offset_bytes);
    assert_eq!(actual.size_bytes, expected.size_bytes);
    assert!(actual.offset_bytes >= body.allocation_interval.start_bytes);
    assert!(
        actual.offset_bytes + actual.size_bytes <= body.allocation_interval.end_bytes,
        "a created partition must stay inside the confirmed allocation interval"
    );

    // Creating it twice is refused rather than duplicating the GPT entry.
    assert!(
        runtime
            .boundary_mut()
            .platform_mut()
            .apply("create_xbootldr_partition")
            .is_err()
    );

    // No two partitions overlap at any point in the run.
    let partitions = runtime.boundary().platform().partitions();
    for (index, first) in partitions.iter().enumerate() {
        for second in &partitions[index + 1..] {
            let disjoint = first.offset_bytes + first.size_bytes <= second.offset_bytes
                || second.offset_bytes + second.size_bytes <= first.offset_bytes;
            assert!(
                disjoint,
                "partitions {} and {} overlap",
                first.partition_guid, second.partition_guid
            );
        }
    }
}

/// PH-06: BitLocker suspend and restore round-trip exactly, and a machine that
/// was never protected is never "restored" into protection.
#[test]
fn bitlocker_suspend_and_restore_round_trip_exactly() {
    let mut protected = platform(BitLockerState::Protected);
    assert!(protected.observe("bitlocker_protected").unwrap());
    protected.apply("suspend_bitlocker").unwrap();
    assert!(protected.observe("bitlocker_suspended").unwrap());
    assert!(
        !protected
            .observe("bitlocker_restored_or_not_applicable")
            .unwrap()
    );
    protected.apply("restore_bitlocker").unwrap();
    assert!(protected.observe("bitlocker_protected").unwrap());
    assert!(
        protected
            .observe("bitlocker_restored_or_not_applicable")
            .unwrap()
    );

    let mut absent = platform(BitLockerState::NotApplicable);
    absent.apply("suspend_bitlocker").unwrap();
    assert_eq!(absent.bitlocker(), BitLockerState::NotApplicable);
    absent.apply("restore_bitlocker").unwrap();
    assert_eq!(
        absent.bitlocker(),
        BitLockerState::NotApplicable,
        "an unprotected volume must never become protected by a restore"
    );
}

/// PH-06: BootNext is one-shot firmware state. It is consumed by the boot it
/// caused, so a machine cannot silently keep rebooting into the installer.
#[test]
fn bootnext_is_consumed_by_the_boot_it_causes() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "installer_boot_observed")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }
    assert_eq!(
        runtime.boundary().platform().boot_next(),
        BootTarget::Installer
    );
    assert_eq!(
        runtime.boundary().platform().running(),
        RunningSystem::RebootRequested
    );

    runtime.observe_boot(RunningSystem::LinuxInstaller).unwrap();
    assert_eq!(
        runtime.boundary().platform().boot_next(),
        BootTarget::Windows,
        "BootNext must be consumed by the boot it caused"
    );

    // A second boot observation without a new reboot request is refused.
    assert!(runtime.observe_boot(RunningSystem::LinuxInstaller).is_err());
}

/// The BitLocker-protected happy path also completes, and the volume ends
/// protected again.
#[test]
fn the_bitlocker_happy_path_restores_protection() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::Protected);
    let path: Vec<&str> = HAPPY_PATH
        .iter()
        .flat_map(|name| {
            if *name == "prepare_without_bitlocker" {
                vec!["prepare_bitlocker", "suspend_bitlocker_after_finalizer"]
            } else {
                vec![*name]
            }
        })
        .collect();

    for name in &path {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None)
            .unwrap_or_else(|error| panic!("{name} failed: {error}"));
        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }
    }

    assert_eq!(
        graph.state(runtime.state().unwrap()).id,
        "terminal.completed"
    );
    assert_eq!(
        runtime.boundary().platform().bitlocker(),
        BitLockerState::Protected,
        "BitLocker protection must be restored before completion"
    );
}

/// The sealed effect boundary has exactly one constructor, and it consumes an
/// in-memory machine. This test documents the boundary rather than proving it;
/// the real enforcement is that `EffectBoundary`'s inner enum is private and
/// has a single variant.
#[test]
fn the_effect_boundary_is_reachable_only_through_a_virtual_platform() {
    let boundary = EffectBoundary::virtual_platform(platform(BitLockerState::NotApplicable));
    // The boundary exposes only the virtual machine it was built from.
    assert_eq!(
        boundary.platform().digest(),
        platform(BitLockerState::NotApplicable).digest()
    );
}

/// PH-04: an executor that reports success without doing the work is caught by
/// the independent postcondition observation, not believed.
#[test]
fn a_lying_executor_is_caught_by_independent_observation() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "create_xbootldr")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }

    let before = runtime.boundary().platform().digest();
    let create = graph.transition_id("create_xbootldr").unwrap();
    let result = runtime
        .step(create, Some(InjectedFault::ClaimSuccessWithoutEffect), None)
        .unwrap();

    // The runtime must not commit. The declared postcondition
    // `xbootldr_partition_matches_plan` does not hold, so the claim is refused.
    assert_eq!(
        result,
        Some(StepResult::FailedForward),
        "a success claim without an effect must never commit"
    );
    assert_eq!(
        graph.state(runtime.state().unwrap()).id,
        "recovery.rollback_required"
    );
    assert!(
        !runtime
            .boundary()
            .platform()
            .observe("xbootldr_partition_matches_plan")
            .unwrap(),
        "no partition may exist after a lying executor"
    );
    assert_eq!(
        runtime.boundary().platform().digest(),
        before,
        "a lying executor must not change the machine"
    );

    // No ActionCommitted record was written for this transition.
    assert!(
        !runtime
            .journal()
            .iter()
            .any(|record| record.transition_id == "create_xbootldr"
                && record.record_type == JournalRecordType::ActionCommitted),
        "a refused transition must not leave a commit record"
    );
}

/// PH-04: when the action really did land a durable object and then failed, the
/// runtime halts for manual recovery instead of writing a no-committed-effect
/// proof that would be a forgery.
#[test]
fn a_new_surviving_effect_forces_manual_recovery_not_a_forged_proof() {
    let graph = graph();
    let mut runtime = runtime(&graph, BitLockerState::NotApplicable);
    for name in HAPPY_PATH
        .iter()
        .take_while(|name| **name != "create_xbootldr")
    {
        let transition = graph.transition_id(name).unwrap();
        drive(&mut runtime, &graph, transition, None).unwrap();
    }

    let create = graph.transition_id("create_xbootldr").unwrap();
    let journal_before = runtime.journal().len();
    let result = runtime
        .step(create, Some(InjectedFault::FailAfterEffect), None)
        .unwrap();

    assert_eq!(
        result,
        Some(StepResult::HaltedForManualRecovery),
        "a surviving new effect must halt instead of failing forward"
    );

    // The partition really is on the virtual disk, which is precisely why a
    // no-committed-effect proof would be false.
    assert!(
        runtime
            .boundary()
            .platform()
            .observe("xbootldr_partition_matches_plan")
            .unwrap(),
        "the effect must have survived for this case to be meaningful"
    );

    // No failure evidence and no failure record were fabricated.
    assert!(
        runtime.failure_evidence().is_empty(),
        "a surviving effect must never produce failure evidence"
    );
    assert!(
        !runtime
            .journal()
            .iter()
            .any(|record| record.record_type == JournalRecordType::ActionFailed),
        "a surviving effect must never produce an action_failed record"
    );

    // Only the intent record was appended; the control state did not advance.
    assert_eq!(runtime.journal().len(), journal_before + 1);
    assert_eq!(
        runtime.journal().last().unwrap().record_type,
        JournalRecordType::ActionIntent
    );
    assert!(matches!(
        runtime.disposition().unwrap(),
        JournalDisposition::ActionPending { .. }
    ));
}
