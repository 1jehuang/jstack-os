//! PH-08/PH-09 dispatch: turn an authorised graph action into a guest request.
//!
//! The controller and the mutation adapters both exist, and nothing connects
//! them. [`EffectBoundary`] has exactly one constructor, binding it to an
//! in-memory [`VirtualPlatform`], so no path leads from the graph to a real
//! machine. That seal is the safety property this module must not break.
//!
//! So dispatch does not execute anything. It renders a *request document*: the
//! action, the plan it is bound to, the targets the confirmed plan named, and
//! the capability that authorises it. Something outside this crate carries that
//! document to an adapter running inside a disposable VM. The distinction is the
//! whole point:
//!
//! * This module has no process spawn, no path, no device, and no syscall. It is
//!   a pure function from an authorised action to bytes, so it cannot mutate the
//!   machine it runs on even by mistake.
//! * A request is inert on its own. The adapter still demands a matching
//!   disposable-VM attestation, which this module cannot mint, and re-derives its
//!   targets from the plan rather than trusting the request.
//! * Two independent parties must therefore agree before anything mutates: the
//!   controller issues the capability, and the harness mints the attestation.
//!   Neither alone is sufficient.
//!
//! Non-mutating actions are refused rather than dispatched, because a request is
//! only ever needed for an action that changes a machine, and a narrower surface
//! is easier to prove.

use serde::Serialize;

use crate::authority::ActorCapability;
use crate::graph::{ActionRisk, GraphModel, MUTATING_RISKS};

/// Why an action could not be dispatched to a guest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchError {
    /// The graph does not declare this action at all.
    UnknownAction(String),
    /// The action exists but changes nothing, so it needs no guest request.
    NotMutating { action: String, risk: ActionRisk },
    /// The capability was issued for an actor that cannot run this action.
    ActorNotAuthorised { action: String, actor: String },
    /// A request must be bound to the confirmed plan it derives from.
    UnboundPlan,
    /// The action names a target the caller did not supply from the plan.
    MissingTarget(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAction(action) => {
                write!(formatter, "the graph declares no action {action:?}")
            }
            Self::NotMutating { action, risk } => write!(
                formatter,
                "action {action:?} has risk {risk:?} and mutates nothing, so it needs no guest request"
            ),
            Self::ActorNotAuthorised { action, actor } => write!(
                formatter,
                "actor {actor:?} is not authorised to run {action:?}"
            ),
            Self::UnboundPlan => {
                write!(formatter, "a guest request must be bound to a plan hash")
            }
            Self::MissingTarget(name) => {
                write!(formatter, "the plan supplied no {name:?} for this action")
            }
        }
    }
}

impl std::error::Error for DispatchError {}

/// One action, authorised and bound, ready to be carried to a guest.
///
/// Serialised as the request document an adapter reads. It deliberately carries
/// no path, no host identifier, and no credential: an adapter that receives this
/// still cannot locate anything except by GUID from the confirmed plan.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct GuestRequest {
    pub action: String,
    pub plan_hash: String,
    pub actor: String,
    pub graph_digest: String,
    pub risk: ActionRisk,
    pub capability: RequestCapability,
    pub targets: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The controller's authorisation, in the exact shape the adapters check.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct RequestCapability {
    pub action: String,
    pub plan_hash: String,
    pub actor: String,
}

/// Render one authorised mutating action as a guest request.
///
/// Takes an [`ActorCapability`] rather than an action name alone, so a caller
/// cannot dispatch without having gone through the capability authority first.
pub fn dispatch(
    graph: &GraphModel,
    actor: &ActorCapability,
    action: &str,
    plan_hash: &str,
    targets: std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<GuestRequest, DispatchError> {
    if plan_hash.is_empty() {
        return Err(DispatchError::UnboundPlan);
    }

    let definition = graph
        .action_id(action)
        .map(|id| graph.action(id))
        .ok_or_else(|| DispatchError::UnknownAction(action.to_owned()))?;

    // Only a mutating action needs to reach a guest. Refusing the rest keeps the
    // surface small enough to enumerate.
    if !MUTATING_RISKS.contains(&definition.risk) {
        return Err(DispatchError::NotMutating {
            action: action.to_owned(),
            risk: definition.risk,
        });
    }

    // The capability names an actor; the graph says which platform the action
    // runs on and which platforms that actor owns. Membership is the check, so a
    // capability for one platform can never drive an action on another.
    let owned = graph
        .actor_platforms(actor.actor())
        .ok_or_else(|| DispatchError::ActorNotAuthorised {
            action: action.to_owned(),
            actor: actor.actor().to_owned(),
        })?;
    if !owned.contains(&definition.platform) {
        return Err(DispatchError::ActorNotAuthorised {
            action: action.to_owned(),
            actor: actor.actor().to_owned(),
        });
    }

    Ok(GuestRequest {
        action: action.to_owned(),
        plan_hash: plan_hash.to_owned(),
        actor: actor.actor().to_owned(),
        graph_digest: graph.digest().as_str().to_owned(),
        risk: definition.risk,
        capability: RequestCapability {
            action: action.to_owned(),
            plan_hash: plan_hash.to_owned(),
            actor: actor.actor().to_owned(),
        },
        targets,
    })
}
