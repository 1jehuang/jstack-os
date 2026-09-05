//! Tests for guest dispatch.
//!
//! Dispatch is the bridge between an authorised graph action and an adapter that
//! can genuinely repartition a machine. It is the most dangerous code in the
//! tree by consequence, so these tests are written against the properties that
//! keep it safe rather than only the ones that make it work.
//!
//! The central property is that dispatch produces bytes and nothing else. There
//! is no host it can reach, no process it can spawn, and no device it can name,
//! so a defect here cannot damage the machine running it.

use std::collections::BTreeMap;

use jstack_installer_controller::authority::CapabilityAuthority;
use jstack_installer_controller::dispatch::{DispatchError, dispatch};
use jstack_installer_controller::graph::{ActionRisk, MUTATING_RISKS};
use jstack_installer_controller::{GraphModel, load_verified};
use jstack_installer_core::Hash256;
use sha2::{Digest, Sha256};

const GRAPH: &[u8] = include_bytes!("../../model/installer-state-graph.json");
const PLAN: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

fn graph() -> GraphModel {
    let digest = Hash256::from_bytes(Sha256::digest(GRAPH).into());
    load_verified(GRAPH, &digest).unwrap()
}

/// Find one mutating action and the actor the graph says owns its platform.
fn a_mutating_action(model: &GraphModel) -> (String, String) {
    for action in model.action_ids() {
        let definition = model.action(action);
        if !MUTATING_RISKS.contains(&definition.risk) {
            continue;
        }
        for actor in model.actors().iter() {
            if let Some(platforms) = model.actor_platforms(actor) {
                if platforms.contains(&definition.platform) {
                    return (definition.id.clone(), actor.clone());
                }
            }
        }
    }
    panic!("the graph declares no mutating action with an owning actor");
}

#[test]
fn an_authorised_mutating_action_becomes_a_bound_request() {
    let model = graph();
    let (action, actor) = a_mutating_action(&model);
    let authority = CapabilityAuthority::new(&model);
    let capability = authority.issue_actor(&actor).unwrap();

    let request = dispatch(&model, &capability, &action, PLAN, BTreeMap::new()).unwrap();

    assert_eq!(request.action, action);
    assert_eq!(request.plan_hash, PLAN);
    assert_eq!(request.capability.plan_hash, PLAN);
    assert_eq!(request.capability.action, action);
    assert_eq!(request.graph_digest, model.digest().as_str());
}

#[test]
fn a_non_mutating_action_is_refused() {
    // A request only ever needs to exist for something that changes a machine.
    let model = graph();
    let authority = CapabilityAuthority::new(&model);
    let (_, actor) = a_mutating_action(&model);
    let capability = authority.issue_actor(&actor).unwrap();

    let benign = model
        .action_ids()
        .find(|id| !MUTATING_RISKS.contains(&model.action(*id).risk))
        .map(|id| model.action(id).id.clone())
        .expect("the graph declares a non-mutating action");

    let error = dispatch(&model, &capability, &benign, PLAN, BTreeMap::new()).unwrap_err();
    assert!(matches!(error, DispatchError::NotMutating { .. }));
}

#[test]
fn an_unknown_action_is_refused() {
    let model = graph();
    let (_, actor) = a_mutating_action(&model);
    let authority = CapabilityAuthority::new(&model);
    let capability = authority.issue_actor(&actor).unwrap();

    let error = dispatch(
        &model,
        &capability,
        "format_everything",
        PLAN,
        BTreeMap::new(),
    )
    .unwrap_err();
    assert!(matches!(error, DispatchError::UnknownAction(_)));
}

#[test]
fn an_actor_cannot_drive_another_platforms_action() {
    // A Windows capability must never dispatch a Linux mutation, or the platform
    // separation the graph models would be decorative.
    //
    // The action must be chosen deliberately rather than taken from
    // `a_mutating_action`, which returns whichever comes first and may well be a
    // `shared` action that every actor legitimately owns. Written that way the
    // test passed against a build with the platform check deleted, which is the
    // definition of a test without teeth. It now searches for an action whose
    // platform at least one actor does *not* own.
    let model = graph();
    let mut selected: Option<(String, String, String)> = None;
    'search: for id in model.action_ids() {
        let definition = model.action(id);
        if !MUTATING_RISKS.contains(&definition.risk) {
            continue;
        }
        for candidate in model.actors().iter() {
            let owns = model
                .actor_platforms(candidate)
                .is_some_and(|platforms| platforms.contains(&definition.platform));
            if !owns {
                selected = Some((
                    definition.id.clone(),
                    definition.platform.clone(),
                    candidate.clone(),
                ));
                break 'search;
            }
        }
    }
    let (action, platform, foreign_actor) =
        selected.expect("the graph must separate at least one actor from one platform");
    let owner = foreign_actor;

    let foreign = owner;
    assert!(
        model
            .actor_platforms(&foreign)
            .is_some_and(|platforms| !platforms.contains(&platform)),
        "the chosen actor must genuinely not own the action's platform"
    );

    let authority = CapabilityAuthority::new(&model);
    let capability = authority.issue_actor(&foreign).unwrap();
    let error = dispatch(&model, &capability, &action, PLAN, BTreeMap::new()).unwrap_err();
    assert!(matches!(error, DispatchError::ActorNotAuthorised { .. }));
}

#[test]
fn a_request_must_be_bound_to_a_plan() {
    // An unbound request could be replayed against any plan, which is exactly
    // what the adapters' plan check exists to prevent.
    let model = graph();
    let (action, actor) = a_mutating_action(&model);
    let authority = CapabilityAuthority::new(&model);
    let capability = authority.issue_actor(&actor).unwrap();

    let error = dispatch(&model, &capability, &action, "", BTreeMap::new()).unwrap_err();
    assert_eq!(error, DispatchError::UnboundPlan);
}

#[test]
fn the_request_carries_no_path_device_or_credential() {
    // An adapter must locate its target by GUID from the confirmed plan. A path
    // or device name in the request would be a second, unverified way to name a
    // target, and the weaker one would win.
    let model = graph();
    let (action, actor) = a_mutating_action(&model);
    let authority = CapabilityAuthority::new(&model);
    let capability = authority.issue_actor(&actor).unwrap();
    let request = dispatch(&model, &capability, &action, PLAN, BTreeMap::new()).unwrap();

    let rendered = serde_json::to_string(&request).unwrap();
    for forbidden in ["/dev/", "\\\\.\\", "C:\\", "password", "token"] {
        assert!(
            !rendered.contains(forbidden),
            "a guest request must not carry {forbidden:?}"
        );
    }
}

#[test]
fn dispatch_cannot_reach_the_machine_it_runs_on() {
    // The seal that protects the host is that no production effect boundary
    // exists. Dispatch must not become the exception, so its source is checked
    // for the primitives that would make it one.
    let source = include_str!("../src/dispatch.rs");
    for forbidden in [
        "std::process",
        "Command",
        "std::fs",
        "File::",
        "unsafe",
        "libc",
    ] {
        assert!(
            !source.contains(forbidden),
            "dispatch must not reference {forbidden:?}: it renders bytes and nothing else"
        );
    }
}

#[test]
fn every_mutating_risk_is_dispatchable_and_no_other_is() {
    // Derived from the graph rather than a hand-written list, so an action added
    // later is covered without anyone remembering to update this test.
    let model = graph();
    let authority = CapabilityAuthority::new(&model);

    for id in model.action_ids() {
        let definition = model.action(id);
        let Some(actor) = model
            .actors()
            .iter()
            .find(|actor| {
                model
                    .actor_platforms(actor)
                    .is_some_and(|platforms| platforms.contains(&definition.platform))
            })
            .cloned()
        else {
            continue;
        };
        let capability = authority.issue_actor(&actor).unwrap();
        let outcome = dispatch(&model, &capability, &definition.id, PLAN, BTreeMap::new());

        if MUTATING_RISKS.contains(&definition.risk) {
            assert!(
                outcome.is_ok(),
                "mutating action {} must be dispatchable",
                definition.id
            );
        } else {
            assert!(
                matches!(outcome, Err(DispatchError::NotMutating { .. })),
                "non-mutating action {} must be refused",
                definition.id
            );
        }
    }
}

#[test]
fn a_reboot_is_treated_as_mutating() {
    // A reboot commits everything staged before it, so it is not a benign action
    // even though it writes no bytes itself.
    assert!(MUTATING_RISKS.contains(&ActionRisk::Reboot));
}
