//! Controller-side capability issuance and deterministic transition authorization.
//!
//! Capability fields and constructors are private. The types in this module are
//! deliberately neither `Clone` nor `Deserialize`: callers can only obtain them
//! after the corresponding validator succeeds. This module is pure controller
//! logic and exposes no platform, filesystem, firmware, or storage mutation API.

use std::collections::BTreeSet;
use std::fmt::Display;

use jstack_installer_core::{
    Confirmation, Hash256, InstallPlan, IntegrityError, PlanDisplay, VerifiedReleaseManifest,
    validate_confirmation,
};
use thiserror::Error;

use crate::{Authorization, GraphModel, GuardDef, GuardId, SelectionError, StateId, TransitionId};

/// A validator for one actor's observation of a graph guard.
///
/// Platform-specific code owns the observation mechanism. Returning a digest
/// certifies the exact evidence that was validated; the authority binds that
/// digest, guard, actor, and graph into a non-forgeable [`GuardCapability`].
pub trait GuardWitnessValidator<E: ?Sized> {
    type Error: Display;

    fn validate(
        &self,
        graph: &GraphModel,
        actor: &str,
        guard: &GuardDef,
        evidence: &E,
    ) -> Result<Hash256, Self::Error>;
}

/// A validator for durable staging evidence bound to an accepted release.
///
/// The staging crate can implement this trait without making the controller
/// depend on a filesystem or platform adapter.
pub trait StagingEvidenceValidator<E: ?Sized> {
    type Error: Display;

    fn validate(
        &self,
        graph: &GraphModel,
        release_manifest_digest: &Hash256,
        evidence: &E,
    ) -> Result<Hash256, Self::Error>;
}

#[derive(Debug, Error)]
pub enum CapabilityIssueError {
    #[error("release proof is bound to a different executable graph")]
    ReleaseGraphMismatch,
    #[error("plan is bound to model {actual}, expected {expected}")]
    PlanGraphMismatch { expected: String, actual: String },
    #[error("capability is bound to a different executable graph")]
    ForeignCapability,
    #[error("unknown graph actor {0}")]
    UnknownActor(String),
    #[error("unknown graph guard {0}")]
    UnknownGuard(String),
    #[error("actor {actor} cannot validate guard {guard}")]
    GuardOutsideActorAuthority { actor: String, guard: String },
    #[error("core validation rejected confirmation: {0}")]
    InvalidConfirmation(#[from] IntegrityError),
    #[error("guard witness validation failed: {0}")]
    GuardWitnessRejected(String),
    #[error("staging evidence validation failed: {0}")]
    StagingEvidenceRejected(String),
}

/// Authority tied to one already verified executable graph.
#[derive(Debug)]
pub struct CapabilityAuthority<'graph> {
    graph: &'graph GraphModel,
}

impl<'graph> CapabilityAuthority<'graph> {
    pub fn new(graph: &'graph GraphModel) -> Self {
        Self { graph }
    }

    pub fn graph(&self) -> &'graph GraphModel {
        self.graph
    }

    /// Issue release-policy authority only from a core-verified and durably
    /// accepted release manifest whose state-graph digest is exact.
    pub fn issue_release_policy(
        &self,
        release: &VerifiedReleaseManifest,
    ) -> Result<ReleasePolicyCapability, CapabilityIssueError> {
        if release.acceptance().state_model_sha256 != *self.graph.digest()
            || release.acceptance().manifest_digest != *release.manifest_digest()
        {
            return Err(CapabilityIssueError::ReleaseGraphMismatch);
        }
        Ok(ReleasePolicyCapability {
            graph_digest: self.graph.digest().clone(),
            release_manifest_digest: release.manifest_digest().clone(),
        })
    }

    /// Validate the canonical plan and explicit confirmation together, issuing
    /// both the graph authorization and the separate user-confirmation proof.
    pub fn issue_confirmation(
        &self,
        plan: &InstallPlan,
        displayed: &PlanDisplay,
        confirmation: &Confirmation,
    ) -> Result<ConfirmationCapabilities, CapabilityIssueError> {
        if plan.body.state_model_id != self.graph.model_id() {
            return Err(CapabilityIssueError::PlanGraphMismatch {
                expected: self.graph.model_id().to_owned(),
                actual: plan.body.state_model_id.clone(),
            });
        }
        validate_confirmation(plan, displayed, confirmation)?;

        Ok(ConfirmationCapabilities {
            confirmed_plan: ConfirmedPlanCapability {
                graph_digest: self.graph.digest().clone(),
                plan_hash: plan.plan_hash.clone(),
            },
            user_confirmation: UserConfirmationCapability {
                graph_digest: self.graph.digest().clone(),
                plan_hash: plan.plan_hash.clone(),
                display_digest: confirmation.display_digest.clone(),
                confirmed_at_unix_ms: confirmation.confirmed_at_unix_ms,
            },
        })
    }

    /// Rollback authority is derived only from a successfully validated user
    /// confirmation for this graph and remains bound to that confirmed plan.
    pub fn issue_rollback(
        &self,
        confirmation: &UserConfirmationCapability,
    ) -> Result<RollbackCapability, CapabilityIssueError> {
        self.require_graph(&confirmation.graph_digest)?;
        Ok(RollbackCapability {
            graph_digest: self.graph.digest().clone(),
            plan_hash: confirmation.plan_hash.clone(),
        })
    }

    /// Issue an actor capability only for an actor declared by this graph.
    pub fn issue_actor(&self, actor: &str) -> Result<ActorCapability, CapabilityIssueError> {
        if self.graph.actor_platforms(actor).is_none() {
            return Err(CapabilityIssueError::UnknownActor(actor.to_owned()));
        }
        Ok(ActorCapability {
            graph_digest: self.graph.digest().clone(),
            actor: actor.to_owned(),
        })
    }

    /// Issue one guard witness after checking graph identity, actor platform
    /// authority, and the supplied evidence with the caller's validator.
    pub fn issue_guard<E: ?Sized, V: GuardWitnessValidator<E>>(
        &self,
        actor: &ActorCapability,
        guard: &str,
        evidence: &E,
        validator: &V,
    ) -> Result<GuardCapability, CapabilityIssueError> {
        self.require_graph(&actor.graph_digest)?;
        let guard_id = self
            .graph
            .guard_id(guard)
            .ok_or_else(|| CapabilityIssueError::UnknownGuard(guard.to_owned()))?;
        let guard_def = self.graph.guard(guard_id);
        let actor_platforms = self
            .graph
            .actor_platforms(&actor.actor)
            .ok_or_else(|| CapabilityIssueError::UnknownActor(actor.actor.clone()))?;
        if !actor_platforms.contains(&guard_def.platform) {
            return Err(CapabilityIssueError::GuardOutsideActorAuthority {
                actor: actor.actor.clone(),
                guard: guard.to_owned(),
            });
        }
        let witness_digest = validator
            .validate(self.graph, &actor.actor, guard_def, evidence)
            .map_err(|error| CapabilityIssueError::GuardWitnessRejected(error.to_string()))?;

        Ok(GuardCapability {
            graph_digest: self.graph.digest().clone(),
            actor: actor.actor.clone(),
            guard: guard_id,
            witness_digest,
        })
    }

    /// Issue staging authority only after release binding and durable staging
    /// evidence validation both succeed.
    pub fn issue_staging<E: ?Sized, V: StagingEvidenceValidator<E>>(
        &self,
        release: &ReleasePolicyCapability,
        evidence: &E,
        validator: &V,
    ) -> Result<StagingCapability, CapabilityIssueError> {
        self.require_graph(&release.graph_digest)?;
        let evidence_digest = validator
            .validate(self.graph, &release.release_manifest_digest, evidence)
            .map_err(|error| CapabilityIssueError::StagingEvidenceRejected(error.to_string()))?;
        Ok(StagingCapability {
            graph_digest: self.graph.digest().clone(),
            release_manifest_digest: release.release_manifest_digest.clone(),
            evidence_digest,
        })
    }

    fn require_graph(&self, digest: &Hash256) -> Result<(), CapabilityIssueError> {
        if digest == self.graph.digest() {
            Ok(())
        } else {
            Err(CapabilityIssueError::ForeignCapability)
        }
    }
}

#[derive(Debug)]
pub struct ReleasePolicyCapability {
    graph_digest: Hash256,
    release_manifest_digest: Hash256,
}

impl ReleasePolicyCapability {
    pub fn release_manifest_digest(&self) -> &Hash256 {
        &self.release_manifest_digest
    }
}

#[derive(Debug)]
pub struct ConfirmedPlanCapability {
    graph_digest: Hash256,
    plan_hash: Hash256,
}

impl ConfirmedPlanCapability {
    pub fn plan_hash(&self) -> &Hash256 {
        &self.plan_hash
    }
}

#[derive(Debug)]
pub struct UserConfirmationCapability {
    graph_digest: Hash256,
    plan_hash: Hash256,
    display_digest: Hash256,
    confirmed_at_unix_ms: u64,
}

impl UserConfirmationCapability {
    pub fn plan_hash(&self) -> &Hash256 {
        &self.plan_hash
    }

    pub fn display_digest(&self) -> &Hash256 {
        &self.display_digest
    }

    pub fn confirmed_at_unix_ms(&self) -> u64 {
        self.confirmed_at_unix_ms
    }
}

#[derive(Debug)]
pub struct RollbackCapability {
    graph_digest: Hash256,
    plan_hash: Hash256,
}

impl RollbackCapability {
    pub fn plan_hash(&self) -> &Hash256 {
        &self.plan_hash
    }
}

#[derive(Debug)]
pub struct StagingCapability {
    graph_digest: Hash256,
    release_manifest_digest: Hash256,
    evidence_digest: Hash256,
}

impl StagingCapability {
    /// The executable graph this staging authority is bound to. Callers must
    /// reject a capability that was issued against a different graph.
    pub fn graph_digest(&self) -> &Hash256 {
        &self.graph_digest
    }

    pub fn release_manifest_digest(&self) -> &Hash256 {
        &self.release_manifest_digest
    }

    pub fn evidence_digest(&self) -> &Hash256 {
        &self.evidence_digest
    }
}

#[derive(Debug)]
pub struct ActorCapability {
    graph_digest: Hash256,
    actor: String,
}

impl ActorCapability {
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

#[derive(Debug)]
pub struct GuardCapability {
    graph_digest: Hash256,
    actor: String,
    guard: GuardId,
    witness_digest: Hash256,
}

impl GuardCapability {
    pub fn guard_id(&self) -> GuardId {
        self.guard
    }

    pub fn witness_digest(&self) -> &Hash256 {
        &self.witness_digest
    }
}

/// The two distinct capabilities produced by explicit confirmation validation.
#[derive(Debug)]
pub struct ConfirmationCapabilities {
    confirmed_plan: ConfirmedPlanCapability,
    user_confirmation: UserConfirmationCapability,
}

impl ConfirmationCapabilities {
    pub fn confirmed_plan(&self) -> &ConfirmedPlanCapability {
        &self.confirmed_plan
    }

    pub fn user_confirmation(&self) -> &UserConfirmationCapability {
        &self.user_confirmation
    }
}

/// A borrowed graph authorization capability presented for one transition.
pub enum PresentedAuthorization<'capability> {
    ReleasePolicy(&'capability ReleasePolicyCapability),
    ConfirmedPlan(&'capability ConfirmedPlanCapability),
    Rollback(&'capability RollbackCapability),
}

impl PresentedAuthorization<'_> {
    fn kind(&self) -> Authorization {
        match self {
            Self::ReleasePolicy(_) => Authorization::ReleasePolicy,
            Self::ConfirmedPlan(_) => Authorization::ConfirmedPlan,
            Self::Rollback(_) => Authorization::RollbackAuthorized,
        }
    }

    fn graph_digest(&self) -> &Hash256 {
        match self {
            Self::ReleasePolicy(capability) => &capability.graph_digest,
            Self::ConfirmedPlan(capability) => &capability.graph_digest,
            Self::Rollback(capability) => &capability.graph_digest,
        }
    }
}

impl<'capability> From<&'capability ReleasePolicyCapability>
    for PresentedAuthorization<'capability>
{
    fn from(value: &'capability ReleasePolicyCapability) -> Self {
        Self::ReleasePolicy(value)
    }
}

impl<'capability> From<&'capability ConfirmedPlanCapability>
    for PresentedAuthorization<'capability>
{
    fn from(value: &'capability ConfirmedPlanCapability) -> Self {
        Self::ConfirmedPlan(value)
    }
}

impl<'capability> From<&'capability RollbackCapability> for PresentedAuthorization<'capability> {
    fn from(value: &'capability RollbackCapability) -> Self {
        Self::Rollback(value)
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum TransitionAuthorizationError {
    #[error("presented {0} capability is bound to a different graph")]
    ForeignCapability(&'static str),
    #[error("guard witness {0} was presented more than once")]
    DuplicateGuardWitness(String),
    #[error("graph transition contains duplicate guard declarations")]
    DuplicateGraphGuard,
    #[error("graph transition contains duplicate authorization declarations")]
    DuplicateGraphAuthorization,
    #[error("transition selection failed: {0}")]
    Selection(#[from] SelectionError),
    #[error("transition requires actor {expected}, but actor {actual} was presented")]
    WrongActor { expected: String, actual: String },
    #[error("guard witness {guard} was validated for actor {witness_actor}, not {actor}")]
    GuardActorMismatch {
        guard: String,
        actor: String,
        witness_actor: String,
    },
    #[error("presented guard witnesses are not the exact selected transition guard set")]
    GuardSetMismatch,
    #[error("authorization {0:?} was presented more than once")]
    DuplicateAuthorization(Authorization),
    #[error("presented authorizations are not the exact selected transition authorization set")]
    AuthorizationSetMismatch,
}

/// A selected transition capability. It authorizes controller progression only;
/// it does not expose or perform any platform effect.
#[derive(Debug)]
pub struct AuthorizedTransition {
    graph_digest: Hash256,
    transition: TransitionId,
}

impl AuthorizedTransition {
    pub fn transition_id(&self) -> TransitionId {
        self.transition
    }

    pub fn graph_digest(&self) -> &Hash256 {
        &self.graph_digest
    }
}

/// Select and authorize exactly one graph transition.
///
/// Candidate resolution is delegated to [`GraphModel::select_enabled`], so zero
/// and multiple candidates fail closed in the graph's deterministic selector.
/// Only after unique selection does this function require the exact actor, the
/// exact selected guard-witness set, and every graph-declared authorization with
/// no duplicates or extras.
pub fn authorize_transition(
    graph: &GraphModel,
    from: StateId,
    event: &str,
    actor: &ActorCapability,
    authorizations: &[PresentedAuthorization<'_>],
    guard_witnesses: &[&GuardCapability],
) -> Result<AuthorizedTransition, TransitionAuthorizationError> {
    let mut satisfied = BTreeSet::new();
    for witness in guard_witnesses {
        if witness.graph_digest != *graph.digest() {
            return Err(TransitionAuthorizationError::ForeignCapability("guard"));
        }
        if !satisfied.insert(witness.guard) {
            return Err(TransitionAuthorizationError::DuplicateGuardWitness(
                graph.guard(witness.guard).id.clone(),
            ));
        }
    }

    let transition_id = graph.select_enabled(from, event, &satisfied)?;
    let transition = graph.transition(transition_id);

    if actor.graph_digest != *graph.digest() {
        return Err(TransitionAuthorizationError::ForeignCapability("actor"));
    }
    if actor.actor != transition.def.actor {
        return Err(TransitionAuthorizationError::WrongActor {
            expected: transition.def.actor.clone(),
            actual: actor.actor.clone(),
        });
    }

    let required_guards = transition.guards.iter().copied().collect::<BTreeSet<_>>();
    if required_guards.len() != transition.guards.len() {
        return Err(TransitionAuthorizationError::DuplicateGraphGuard);
    }
    for witness in guard_witnesses {
        if witness.actor != actor.actor {
            return Err(TransitionAuthorizationError::GuardActorMismatch {
                guard: graph.guard(witness.guard).id.clone(),
                actor: actor.actor.clone(),
                witness_actor: witness.actor.clone(),
            });
        }
    }
    if satisfied != required_guards {
        return Err(TransitionAuthorizationError::GuardSetMismatch);
    }

    let mut required_authorizations = Vec::new();
    for authorization in &transition.def.authorization {
        if required_authorizations.contains(authorization) {
            return Err(TransitionAuthorizationError::DuplicateGraphAuthorization);
        }
        required_authorizations.push(*authorization);
    }
    let mut presented_authorizations = Vec::new();
    for authorization in authorizations {
        if authorization.graph_digest() != graph.digest() {
            return Err(TransitionAuthorizationError::ForeignCapability(
                "authorization",
            ));
        }
        let kind = authorization.kind();
        if presented_authorizations.contains(&kind) {
            return Err(TransitionAuthorizationError::DuplicateAuthorization(kind));
        }
        presented_authorizations.push(kind);
    }
    if presented_authorizations.len() != required_authorizations.len()
        || presented_authorizations
            .iter()
            .any(|authorization| !required_authorizations.contains(authorization))
    {
        return Err(TransitionAuthorizationError::AuthorizationSetMismatch);
    }

    Ok(AuthorizedTransition {
        graph_digest: graph.digest().clone(),
        transition: transition_id,
    })
}
