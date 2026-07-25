//! PH-15 repetition and freshness, at the virtual level.
//!
//! The ledger requires ten fresh runs per supported profile. On real hardware
//! that means ten fresh qcow2 overlays; here it means ten runs each built from a
//! brand-new [`VirtualPlatform`] with no state carried over, which establishes
//! the property the VM campaign will later confirm: **the install is
//! deterministic and independent of run history.**
//!
//! Two things are proven that a single run cannot:
//!
//! * **Determinism.** Ten fresh runs of the same profile produce byte-identical
//!   machine digests, journal lengths, and terminal states. A run that depended
//!   on uninitialized state, iteration order, or a clock would diverge.
//! * **Isolation.** Runs do not influence each other. Interleaving profiles,
//!   and running a failing case between successful ones, changes nothing about
//!   the successful outcomes.
//!
//! These are exactly the invariants that make a ten-overlay VM campaign
//! meaningful rather than ten repetitions of the same accident.

use std::collections::BTreeSet;

use jstack_installer_controller::platform::{BitLockerState, RunningSystem, VirtualPlatform};
use jstack_installer_controller::runtime::{EffectBoundary, InjectedFault, Runtime, StepResult};
use jstack_installer_controller::{DirectOutcome, GraphModel, load_verified};
use jstack_installer_core::{Hash256, InstallPlan};
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const PLAN: &str = include_str!("../../core/generated/example-plan.json");

/// The ledger's repetition count for a supported profile.
const REQUIRED_FRESH_RUNS: usize = 10;

fn graph() -> GraphModel {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).unwrap()
}

fn plan() -> InstallPlan {
    serde_json::from_str(PLAN).unwrap()
}

/// The supported security profiles this suite repeats over.
fn profiles() -> [BitLockerState; 2] {
    [BitLockerState::NotApplicable, BitLockerState::Protected]
}

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

/// The observable outcome of one complete run.
#[derive(Debug, Eq, PartialEq)]
struct RunOutcome {
    terminal_state: String,
    machine_digest: Hash256,
    journal_records: usize,
    bitlocker: BitLockerState,
}

/// Execute one run from a brand-new virtual machine. Nothing is shared with any
/// previous run: the platform, the runtime, and the journal are all fresh.
fn fresh_run(graph: &GraphModel, bitlocker: BitLockerState) -> RunOutcome {
    let platform = VirtualPlatform::from_plan(&plan(), bitlocker).unwrap();
    let mut runtime = Runtime::new(graph, &plan(), EffectBoundary::virtual_platform(platform));

    for name in path(bitlocker) {
        let transition = graph.transition_id(name).unwrap();
        if graph.is_mutating(transition) {
            let result = runtime
                .step(transition, None, None)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                result,
                Some(StepResult::Committed),
                "{name} did not commit on a fresh run"
            );
        } else {
            runtime
                .advance_direct(transition, DirectOutcome::Success)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        }
        if let Some(system) = boot_after(name) {
            runtime.observe_boot(system).unwrap();
        }
    }

    let state = runtime.state().unwrap();
    RunOutcome {
        terminal_state: graph.state(state).id.clone(),
        machine_digest: runtime.boundary().platform().digest(),
        journal_records: runtime.journal().len(),
        bitlocker: runtime.boundary().platform().bitlocker(),
    }
}

/// Ten fresh runs per supported profile all reach the same outcome, byte for
/// byte. This is the pre-hardware form of the ledger's repetition requirement.
#[test]
fn ten_fresh_runs_per_profile_are_byte_identical() {
    let graph = graph();

    for bitlocker in profiles() {
        let first = fresh_run(&graph, bitlocker);
        assert_eq!(first.terminal_state, "terminal.completed");

        for run in 1..REQUIRED_FRESH_RUNS {
            let outcome = fresh_run(&graph, bitlocker);
            assert_eq!(
                outcome, first,
                "run {run} of profile {bitlocker:?} diverged from the first run"
            );
        }
    }
}

/// The two profiles reach genuinely different machines, so the determinism above
/// is not an artifact of the profile being ignored.
#[test]
fn the_two_profiles_produce_different_machines() {
    let graph = graph();
    let without = fresh_run(&graph, BitLockerState::NotApplicable);
    let with = fresh_run(&graph, BitLockerState::Protected);

    assert_eq!(without.terminal_state, with.terminal_state);
    assert_ne!(
        without.machine_digest, with.machine_digest,
        "the BitLocker profile must be reflected in the final machine"
    );
    assert_eq!(without.bitlocker, BitLockerState::NotApplicable);
    assert_eq!(
        with.bitlocker,
        BitLockerState::Protected,
        "a protected volume must end protected again"
    );
    // The BitLocker path runs two extra transitions, so its journal is longer.
    assert!(with.journal_records > without.journal_records);
}

/// Interleaving profiles changes nothing. A run that leaked state into a shared
/// location would show up here as a digest that depends on execution order.
#[test]
fn interleaving_profiles_does_not_affect_any_outcome() {
    let graph = graph();
    let baseline: Vec<RunOutcome> = profiles()
        .into_iter()
        .map(|bitlocker| fresh_run(&graph, bitlocker))
        .collect();

    // Run them alternating, several times over.
    for _ in 0..3 {
        for (index, bitlocker) in profiles().into_iter().enumerate() {
            let outcome = fresh_run(&graph, bitlocker);
            assert_eq!(
                outcome, baseline[index],
                "interleaved run of {bitlocker:?} diverged"
            );
        }
    }
}

/// A failing run between two successful ones does not contaminate them. This is
/// the property that makes a fault campaign and a happy-path campaign safe to
/// run in the same session.
#[test]
fn a_failed_run_does_not_contaminate_later_runs() {
    let graph = graph();
    let before = fresh_run(&graph, BitLockerState::NotApplicable);

    // A run that fails partway, on a fresh machine of its own.
    {
        let platform = VirtualPlatform::from_plan(&plan(), BitLockerState::NotApplicable).unwrap();
        let mut runtime = Runtime::new(&graph, &plan(), EffectBoundary::virtual_platform(platform));
        let failing = graph.transition_id("begin_preflight").unwrap();
        let result = runtime
            .step(failing, Some(InjectedFault::before_first_action()), None)
            .unwrap();
        assert_eq!(result, Some(StepResult::FailedForward));
        assert_eq!(
            graph.state(runtime.state().unwrap()).id,
            "terminal.manual_recovery"
        );
    }

    let after = fresh_run(&graph, BitLockerState::NotApplicable);
    assert_eq!(after, before, "a failed run contaminated a later fresh run");
}

/// A fresh platform is genuinely fresh: no condition that should start false is
/// already true, across every profile.
#[test]
fn a_fresh_platform_starts_from_a_clean_state() {
    let _graph = graph();

    // Conditions that must never hold on an untouched machine.
    let must_start_false = [
        "staging_store_reconciled",
        "release_candidate_verified",
        "acceptance_record_committed",
        "quarantine_chunks_complete_and_synced",
        "promoted_artifacts_reopened_and_verified",
        "finalizer_registered",
        "windows_finalizer_armed",
        "installer_boot_entry_present",
        "jstack_boot_entry_valid",
        "bootnext_is_installer",
        "bootnext_is_jstack",
        "reboot_requested",
        "installer_rearm_attempt_recorded",
        "jstack_rearm_attempt_recorded",
        "xbootldr_partition_matches_plan",
        "root_partition_matches_plan",
        "deployed_image_hash_matches",
        "installed_configuration_valid",
        "temporary_bootstrap_state_present",
        "recovery_metadata_retained",
        "rollback_mode_recorded",
        "rollback_terminal_durable",
    ];

    for bitlocker in profiles() {
        let machine = VirtualPlatform::from_plan(&plan(), bitlocker).unwrap();
        for condition in must_start_false {
            assert!(
                !machine.observe(condition).unwrap(),
                "{condition} must not hold on a fresh {bitlocker:?} machine"
            );
        }
        // And the things that must start true.
        assert!(
            machine
                .observe("windows_partition_at_original_size")
                .unwrap()
        );
        assert!(machine.observe("finalizer_not_registered").unwrap());
        assert!(machine.observe("installer_boot_entry_absent").unwrap());
        assert!(machine.observe("jstack_boot_entries_absent").unwrap());
        assert!(machine.observe("windows_boot_entry_present").unwrap());
        assert_eq!(machine.running(), RunningSystem::Windows);
        // No JStack partition exists yet.
        assert!(machine.observe("jstack_partitions_absent").unwrap());
    }
}

/// Two freshly built platforms for the same profile are identical, and for
/// different profiles are not. A fresh machine must be a pure function of the
/// plan and profile.
#[test]
fn a_fresh_platform_is_a_pure_function_of_the_plan_and_profile() {
    let mut digests = BTreeSet::new();
    for bitlocker in profiles() {
        let first = VirtualPlatform::from_plan(&plan(), bitlocker)
            .unwrap()
            .digest();
        let second = VirtualPlatform::from_plan(&plan(), bitlocker)
            .unwrap()
            .digest();
        assert_eq!(
            first, second,
            "two fresh {bitlocker:?} machines must be identical"
        );
        digests.insert(first);
    }
    assert_eq!(
        digests.len(),
        profiles().len(),
        "each profile must yield a distinct fresh machine"
    );
}
