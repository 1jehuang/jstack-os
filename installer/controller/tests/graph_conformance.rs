//! Conformance, adversarial, and drift tests for the verified graph loader
//! and the pure trace simulator.

use std::collections::BTreeSet;

use jstack_installer_controller::{
    ActionRisk, GraphLoadError, GraphModel, MutationObservation, SelectionError, SimulationError,
    StepOutcome, TerminalOutcome, apply_step, load_verified, parse_trace, reconcile_interruption,
    simulate_steps, simulate_to_terminal,
};
use jstack_installer_core::Hash256;
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");

const TRACES: &[(&str, &str)] = &[
    (
        "acceptance-corruption-manual-recovery",
        include_str!("../../traces/acceptance-corruption-manual-recovery.json"),
    ),
    (
        "bootnext-rearm-exhausted",
        include_str!("../../traces/bootnext-rearm-exhausted.json"),
    ),
    (
        "bootnext-rearm",
        include_str!("../../traces/bootnext-rearm.json"),
    ),
    (
        "cancel-before-mutation",
        include_str!("../../traces/cancel-before-mutation.json"),
    ),
    (
        "deploy-power-loss-reconcile",
        include_str!("../../traces/deploy-power-loss-reconcile.json"),
    ),
    (
        "finalizer-security-failure",
        include_str!("../../traces/finalizer-security-failure.json"),
    ),
    (
        "first-boot-validation-failure",
        include_str!("../../traces/first-boot-validation-failure.json"),
    ),
    (
        "happy-path-bitlocker",
        include_str!("../../traces/happy-path-bitlocker.json"),
    ),
    (
        "happy-path-no-bitlocker",
        include_str!("../../traces/happy-path-no-bitlocker.json"),
    ),
    (
        "invalid-linux-handoff",
        include_str!("../../traces/invalid-linux-handoff.json"),
    ),
    (
        "jstack-boot-rearm",
        include_str!("../../traces/jstack-boot-rearm.json"),
    ),
    (
        "payload-corruption-retry",
        include_str!("../../traces/payload-corruption-retry.json"),
    ),
    (
        "post-shrink-failure-rollback",
        include_str!("../../traces/post-shrink-failure-rollback.json"),
    ),
    (
        "preflight-rejection",
        include_str!("../../traces/preflight-rejection.json"),
    ),
    (
        "release-acquisition-failure-cancel",
        include_str!("../../traces/release-acquisition-failure-cancel.json"),
    ),
    (
        "shrink-interruption-divergence",
        include_str!("../../traces/shrink-interruption-divergence.json"),
    ),
    (
        "shrink-interruption-retry",
        include_str!("../../traces/shrink-interruption-retry.json"),
    ),
];

fn graph_digest(bytes: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(bytes).into())
}

fn load_real() -> GraphModel {
    load_verified(GRAPH, &graph_digest(GRAPH)).unwrap()
}

/// Mutate the real graph JSON, recompute its digest, and try to load it.
fn load_mutated(mutate: impl FnOnce(&mut serde_json::Value)) -> Result<GraphModel, GraphLoadError> {
    let mut value: serde_json::Value = serde_json::from_slice(GRAPH).unwrap();
    mutate(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap();
    load_verified(&bytes, &graph_digest(&bytes))
}

#[test]
fn real_graph_loads_with_exact_identity_and_counts() {
    let model = load_real();
    assert_eq!(model.model_id(), "jstack-no-usb-dual-boot-v1");
    assert_eq!(model.digest(), &graph_digest(GRAPH));
    assert_eq!(model.state_count(), 55);
    assert_eq!(model.transition_count(), 92);
    assert_eq!(model.guard_count(), 44);
    assert_eq!(model.action_count(), 41);
    assert_eq!(
        model.state(model.initial_state()).id,
        "windows.bootstrap_started"
    );
    assert_eq!(model.actors().len(), 6);
    assert!(model.scope()["unsupported"].as_array().unwrap().len() >= 5);
}

#[test]
fn wrong_digest_and_tampered_bytes_are_rejected() {
    let wrong = Hash256::parse("0".repeat(64)).unwrap();
    assert!(matches!(
        load_verified(GRAPH, &wrong),
        Err(GraphLoadError::DigestMismatch { .. })
    ));
    // Whitespace-only tampering changes the digest and must fail closed too.
    let mut tampered = GRAPH.to_vec();
    tampered.push(b'\n');
    assert!(matches!(
        load_verified(&tampered, &graph_digest(GRAPH)),
        Err(GraphLoadError::DigestMismatch { .. })
    ));
}

#[test]
fn wrong_model_id_and_schema_version_are_rejected() {
    assert!(matches!(
        load_mutated(|value| value["model_id"] = "jstack-installer-v1".into()),
        Err(GraphLoadError::Identity(_))
    ));
    assert!(matches!(
        load_mutated(|value| value["schema_version"] = 2.into()),
        Err(GraphLoadError::UnsupportedSchemaVersion(2))
    ));
}

#[test]
fn unknown_fields_are_rejected_at_every_level() {
    for mutate in [
        (|value: &mut serde_json::Value| {
            value["unexpected"] = true.into();
        }) as fn(&mut serde_json::Value),
        |value| value["transitions"][0]["unexpected"] = true.into(),
        |value| value["states"][0]["unexpected"] = true.into(),
        |value| value["guards"][0]["unexpected"] = true.into(),
        |value| value["actions"][0]["unexpected"] = true.into(),
        |value| value["invariants"][0]["unexpected"] = true.into(),
        |value| value["transitions"][0]["journal"]["unexpected"] = true.into(),
        |value| {
            // First transition with a handoff object.
            let transitions = value["transitions"].as_array_mut().unwrap();
            let handoff = transitions
                .iter_mut()
                .find(|transition| transition.get("handoff").is_some())
                .unwrap();
            handoff["handoff"]["unexpected"] = true.into();
        },
    ] {
        assert!(matches!(
            load_mutated(mutate),
            Err(GraphLoadError::Parse(_))
        ));
    }
}

type Mutator = fn(&mut serde_json::Value);

#[test]
fn duplicate_ids_and_bad_references_are_rejected() {
    let cases: [(Mutator, &str); 7] = [
        (
            |value| {
                let duplicate = value["states"][0].clone();
                value["states"].as_array_mut().unwrap().push(duplicate);
            },
            "duplicate state",
        ),
        (
            |value| {
                let duplicate = value["transitions"][0].clone();
                value["transitions"].as_array_mut().unwrap().push(duplicate);
            },
            "duplicate transition",
        ),
        (
            |value| value["initial_state"] = "windows.does_not_exist".into(),
            "unknown initial state",
        ),
        (
            |value| value["transitions"][0]["from"] = "windows.does_not_exist".into(),
            "unknown source",
        ),
        (
            |value| {
                value["transitions"][0]["guards"]
                    .as_array_mut()
                    .unwrap()
                    .push("guard.does_not_exist".into());
            },
            "unknown guard",
        ),
        (
            |value| {
                value["transitions"][0]["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push("action.does_not_exist".into());
            },
            "unknown action",
        ),
        (
            |value| value["states"][0]["actor"] = "actor.does_not_exist".into(),
            "unknown actor",
        ),
    ];
    for (mutate, label) in cases {
        assert!(
            matches!(load_mutated(mutate), Err(GraphLoadError::Invalid(_))),
            "{label} must be rejected"
        );
    }
}

#[test]
fn actor_platform_authority_is_enforced() {
    // linux_installer must not execute a Windows-only storage action.
    let error = load_mutated(|value| {
        let transitions = value["transitions"].as_array_mut().unwrap();
        let deploy = transitions
            .iter_mut()
            .find(|transition| transition["id"] == "deploy_jstack_image")
            .unwrap();
        deploy["actions"] = serde_json::json!(["shrink_windows_ntfs"]);
    });
    match error {
        Err(GraphLoadError::Invalid(message)) => {
            assert!(message.contains("cannot execute"), "{message}");
        }
        other => panic!("expected platform authority rejection, got {other:?}"),
    }
}

#[test]
fn runtime_critical_mutation_invariants_are_enforced() {
    // Two mutating actions in one transition.
    assert!(matches!(
        load_mutated(|value| {
            let transitions = value["transitions"].as_array_mut().unwrap();
            let shrink = transitions
                .iter_mut()
                .find(|transition| transition["id"] == "reserve_windows_space")
                .unwrap();
            shrink["actions"]
                .as_array_mut()
                .unwrap()
                .push("create_xbootldr_partition".into());
        }),
        Err(GraphLoadError::Invalid(message)) if message.contains("multiple mutations")
    ));
    // A mutating transition without a failure route.
    assert!(matches!(
        load_mutated(|value| {
            let transitions = value["transitions"].as_array_mut().unwrap();
            let shrink = transitions
                .iter_mut()
                .find(|transition| transition["id"] == "reserve_windows_space")
                .unwrap();
            shrink.as_object_mut().unwrap().remove("failure_to");
        }),
        Err(GraphLoadError::Invalid(message)) if message.contains("failure_to")
    ));
    // A mutating transition without the journal protocol.
    assert!(matches!(
        load_mutated(|value| {
            let transitions = value["transitions"].as_array_mut().unwrap();
            let shrink = transitions
                .iter_mut()
                .find(|transition| transition["id"] == "reserve_windows_space")
                .unwrap();
            shrink["journal"]["intent_before_actions"] = false.into();
        }),
        Err(GraphLoadError::Invalid(message)) if message.contains("journal protocol")
    ));
    // A reboot transition without at least two journal replicas.
    assert!(matches!(
        load_mutated(|value| {
            let transitions = value["transitions"].as_array_mut().unwrap();
            let reboot = transitions
                .iter_mut()
                .find(|transition| transition["id"] == "reboot_to_installer")
                .unwrap();
            reboot["handoff"]["journal_replicas"] = serde_json::json!(["xbootldr"]);
        }),
        Err(GraphLoadError::Invalid(message)) if message.contains("journal replicas")
    ));
    // Terminal states must have no outgoing transitions.
    assert!(matches!(
        load_mutated(|value| {
            value["transitions"][0]["from"] = "terminal.completed".into();
        }),
        Err(GraphLoadError::Invalid(_))
    ));
}

#[test]
fn one_guard_verdict_cannot_enable_two_candidates() {
    // The real graph's only shared (state, event) pair stays deterministic
    // because bitlocker_enabled and bitlocker_disabled cannot hold together.
    let model = load_real();
    let confirmed = model.state_id("windows.plan_confirmed").unwrap();
    let candidates = model.candidates(confirmed, "prepare_security");
    assert_eq!(candidates.len(), 2);

    let satisfied: BTreeSet<_> = [
        "bitlocker_disabled",
        "confirmed_plan_current",
        "plan_fingerprint_current",
    ]
    .iter()
    .map(|guard| model.guard_id(guard).unwrap())
    .collect();
    let selected = model
        .select_enabled(confirmed, "prepare_security", &satisfied)
        .unwrap();
    assert_eq!(
        model.transition(selected).def.id,
        "prepare_without_bitlocker"
    );

    // An inconsistent oracle that satisfies every guard is rejected, not
    // resolved arbitrarily.
    let all: BTreeSet<_> = model.guard_ids().collect();
    assert!(matches!(
        model.select_enabled(confirmed, "prepare_security", &all),
        Err(SelectionError::Ambiguous(_))
    ));
    assert_eq!(
        model.select_enabled(confirmed, "prepare_security", &BTreeSet::new()),
        Err(SelectionError::NoneEnabled)
    );

    // A graph where one candidate's guards are a subset of another's is
    // rejected at load time.
    assert!(matches!(
        load_mutated(|value| {
            let transitions = value["transitions"].as_array_mut().unwrap();
            let with_bitlocker = transitions
                .iter_mut()
                .find(|transition| transition["id"] == "prepare_bitlocker")
                .unwrap();
            with_bitlocker["guards"] = serde_json::json!([
                "bitlocker_disabled",
                "confirmed_plan_current",
                "plan_fingerprint_current",
                "bitlocker_recovery_key_confirmed"
            ]);
        }),
        Err(GraphLoadError::Invalid(message)) if message.contains("enable together")
    ));
}

#[test]
fn all_seventeen_traces_reach_their_expected_terminals() {
    let model = load_real();
    let mut outcomes = BTreeSet::new();
    assert_eq!(TRACES.len(), 17);
    for (name, body) in TRACES {
        let trace = parse_trace(body.as_bytes()).unwrap();
        let outcome = simulate_to_terminal(&model, &trace)
            .unwrap_or_else(|error| panic!("trace {name}: {error}"));
        outcomes.insert(format!("{outcome:?}"));
    }
    // Every terminal outcome class is exercised by at least one trace.
    for expected in [
        TerminalOutcome::Success,
        TerminalOutcome::SafeAbort,
        TerminalOutcome::Unsupported,
        TerminalOutcome::RolledBack,
        TerminalOutcome::ManualRecovery,
    ] {
        assert!(outcomes.contains(&format!("{expected:?}")), "{expected:?}");
    }
}

#[test]
fn trace_edge_coverage_is_exposed_not_assumed() {
    // The stored traces do not exercise every edge. This test pins the exact
    // uncovered sets so silently growing gaps are surfaced as drift.
    let model = load_real();
    let mut success_covered = BTreeSet::new();
    let mut failure_covered = BTreeSet::new();
    for (_, body) in TRACES {
        let trace = parse_trace(body.as_bytes()).unwrap();
        for step in &trace.steps {
            match step.outcome() {
                StepOutcome::Success | StepOutcome::InterruptedPostcondition => {
                    success_covered.insert(step.transition().to_owned());
                }
                StepOutcome::Failure | StepOutcome::InterruptedDivergent => {
                    failure_covered.insert(step.transition().to_owned());
                }
                StepOutcome::InterruptedPrecondition => {}
            }
        }
    }
    let mut success_uncovered = BTreeSet::new();
    let mut failure_uncovered = BTreeSet::new();
    for id in model.transition_ids() {
        let transition = model.transition(id);
        if !success_covered.contains(&transition.def.id) {
            success_uncovered.insert(transition.def.id.clone());
        }
        if transition.failure_to.is_some() && !failure_covered.contains(&transition.def.id) {
            failure_uncovered.insert(transition.def.id.clone());
        }
    }
    assert_eq!(success_uncovered.len(), 25, "{success_uncovered:?}");
    assert_eq!(failure_uncovered.len(), 36, "{failure_uncovered:?}");
    // Every uncovered success edge is a rollback request or explicit
    // rejection edge; the primary forward path is fully covered.
    for id in &success_uncovered {
        assert!(
            id.starts_with("request_rollback_from_")
                || id.starts_with("reject_")
                || id.starts_with("cancel_")
                || id.starts_with("exhaust_"),
            "unexpected uncovered forward edge: {id}"
        );
    }
}

#[test]
fn every_success_and_failure_edge_simulates_deterministically() {
    // Independent of the stored traces, apply_step must resolve every legal
    // edge of every transition without panicking or leaving the state space.
    let model = load_real();
    let mut mutating = 0;
    for id in model.transition_ids() {
        let transition = model.transition(id);
        assert_eq!(
            apply_step(&model, id, &StepOutcome::Success).unwrap(),
            transition.to
        );
        match transition.failure_to {
            Some(failure) => {
                assert_eq!(
                    apply_step(&model, id, &StepOutcome::Failure).unwrap(),
                    failure
                );
            }
            None => assert!(apply_step(&model, id, &StepOutcome::Failure).is_err()),
        }
        if model.is_mutating(id) {
            mutating += 1;
            assert_eq!(
                reconcile_interruption(&model, id, MutationObservation::Precondition).unwrap(),
                transition.from
            );
            assert_eq!(
                reconcile_interruption(&model, id, MutationObservation::Postcondition).unwrap(),
                transition.to
            );
            assert_eq!(
                reconcile_interruption(&model, id, MutationObservation::Divergent).unwrap(),
                transition.failure_to.unwrap()
            );
        } else {
            assert!(reconcile_interruption(&model, id, MutationObservation::Divergent).is_err());
        }
    }
    // Drift pin against the semantic validator's mutation classification.
    assert_eq!(mutating, 38);
}

#[test]
fn simulator_rejects_source_mismatch_unknown_transitions_and_bad_interruptions() {
    let model = load_real();
    let trace = parse_trace(
        br#"{"id":"bad","description":"x","expected_terminal":"terminal.completed",
             "steps":["acquire_release_manifest"]}"#,
    )
    .unwrap();
    assert!(matches!(
        simulate_steps(&model, &trace),
        Err(SimulationError::SourceMismatch { .. })
    ));

    let trace = parse_trace(
        br#"{"id":"bad","description":"x","expected_terminal":"terminal.completed",
             "steps":["does_not_exist"]}"#,
    )
    .unwrap();
    assert!(matches!(
        simulate_steps(&model, &trace),
        Err(SimulationError::UnknownTransition { .. })
    ));

    // begin_preflight mutates (staging), but show/confirm steps do not;
    // interrupting a non-mutating transition is rejected.
    let trace = parse_trace(
        br#"{"id":"bad","description":"x","expected_terminal":"terminal.completed",
             "steps":[{"transition":"begin_preflight","outcome":"success"},
                      {"transition":"acquire_release_manifest",
                       "outcome":"interrupted_divergent"}]}"#,
    )
    .unwrap();
    assert!(matches!(
        simulate_steps(&model, &trace),
        Err(SimulationError::InterruptedNonMutating { .. })
    ));

    // A trace declaring the wrong terminal is rejected even when it replays.
    let mut wrong: serde_json::Value = serde_json::from_str(
        TRACES
            .iter()
            .find(|(name, _)| *name == "preflight-rejection")
            .unwrap()
            .1,
    )
    .unwrap();
    wrong["expected_terminal"] = "terminal.completed".into();
    let wrong = parse_trace(&serde_json::to_vec(&wrong).unwrap()).unwrap();
    assert!(matches!(
        simulate_to_terminal(&model, &wrong),
        Err(SimulationError::TerminalMismatch { .. })
    ));
}

#[test]
fn traces_with_unknown_fields_are_rejected() {
    assert!(
        parse_trace(
            br#"{"id":"bad","description":"x","expected_terminal":"terminal.completed",
             "steps":[], "unexpected": true}"#,
        )
        .is_err()
    );
    assert!(
        parse_trace(
            br#"{"id":"bad","description":"x","expected_terminal":"terminal.completed",
             "steps":[{"transition":"begin_preflight","proof":"p1"}]}"#,
        )
        .is_err()
    );
}

#[test]
fn destination_transition_contracts_still_match_the_loaded_graph() {
    // Cross-check the compiled core destination contracts against the typed
    // model, so loader drift from core is caught here too.
    let model = load_real();
    for (id, from, to, actor) in [
        (
            "copy_verified_payload",
            "windows.xbootldr_ready",
            "windows.payload_staged",
            "windows_bootstrap",
        ),
        (
            "stage_installer_loader",
            "windows.payload_staged",
            "windows.installer_loader_files_staged",
            "windows_bootstrap",
        ),
        (
            "deploy_jstack_image",
            "linux.root_filesystem_ready",
            "linux.image_deployed",
            "linux_installer",
        ),
        (
            "install_jstack_boot",
            "linux.system_configured",
            "linux.bootloader_ready",
            "linux_installer",
        ),
    ] {
        let transition = model.transition(model.transition_id(id).unwrap());
        assert_eq!(model.state(transition.from).id, from);
        assert_eq!(model.state(transition.to).id, to);
        assert_eq!(transition.def.actor, actor);
        assert!(model.is_mutating(model.transition_id(id).unwrap()));
        assert!(transition.def.journal.intent_before_actions);
        assert!(transition.def.journal.commit_after_postconditions);
    }
}

#[test]
fn mutating_actions_carry_explicit_policies_and_risks() {
    let model = load_real();
    let mut risky = 0;
    for id in model.action_ids() {
        let action = model.action(id);
        let is_mutating = matches!(
            action.risk,
            ActionRisk::StagingMutation
                | ActionRisk::FilesystemMutation
                | ActionRisk::SecurityMutation
                | ActionRisk::DiskMutation
                | ActionRisk::BootMutation
                | ActionRisk::Reboot
        );
        if is_mutating {
            risky += 1;
            assert!(action.idempotency.is_some(), "{}", action.id);
            assert!(action.recovery.is_some(), "{}", action.id);
        }
    }
    assert!(
        risky >= 29,
        "expected the closed mutating action set, got {risky}"
    );
}
