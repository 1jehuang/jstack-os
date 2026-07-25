//! Pure authenticated replica and cross-actor handoff model.
//!
//! This module deliberately models durable state in memory. It contains no
//! filesystem, process, firmware, boot, or platform mutation API. Authority and
//! authentication token constructors are private; callers obtain them only
//! through the validating functions below.

use std::collections::BTreeSet;
use std::fmt;

use jstack_installer_core::{
    CONTRACT_SCHEMA_VERSION, Confirmation, Handoff, Hash256, InstallPlan, JournalRecord,
    JournalRecordType, PlanDisplay, canonical_sha256, control_state_hash, hash_journal_record,
    validate_confirmation, validate_journal_chain,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::GraphModel;

const AUTHORITY_DOMAIN: &str = "jstack.replica.authority.v1";
const REPLICA_DOMAIN: &str = "jstack.replica.journal.v1";
const CONFIRMATION_DOMAIN: &str = "jstack.replica.confirmation.v1";
const HANDOFF_DOMAIN: &str = "jstack.replica.handoff.v1";
const NONCE_DOMAIN: &str = "jstack.replica.handoff-nonce.v1";
const REQUIRED_REPLICAS: usize = 2;

/// The two durable locations required by the v1 cross-OS graph handoffs.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaId {
    WindowsSystemVolume,
    Xbootldr,
}

impl ReplicaId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowsSystemVolume => "windows_system_volume",
            Self::Xbootldr => "xbootldr",
        }
    }
}

/// Canonical identity shared by authenticated replicas for one exact journal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalIdentity {
    graph_model_id: String,
    graph_digest: Hash256,
    plan_hash: Hash256,
    release_manifest_hash: Hash256,
    journal_head_hash: Hash256,
    journal_len: u64,
}

impl JournalIdentity {
    pub fn graph_model_id(&self) -> &str {
        &self.graph_model_id
    }

    pub fn graph_digest(&self) -> &Hash256 {
        &self.graph_digest
    }

    pub fn plan_hash(&self) -> &Hash256 {
        &self.plan_hash
    }

    pub fn release_manifest_hash(&self) -> &Hash256 {
        &self.release_manifest_hash
    }

    pub fn journal_head_hash(&self) -> &Hash256 {
        &self.journal_head_hash
    }

    pub fn journal_len(&self) -> u64 {
        self.journal_len
    }

    fn matches_context(
        &self,
        graph: &GraphModel,
        plan_hash: &Hash256,
        release_manifest_hash: &Hash256,
    ) -> bool {
        self.graph_model_id == graph.model_id()
            && self.graph_digest == *graph.digest()
            && self.plan_hash == *plan_hash
            && self.release_manifest_hash == *release_manifest_hash
    }
}

/// In-memory authentication authority. Secret material is never serialized.
///
/// The constructor is private. Use [`validate_authentication_authority`].
pub struct AuthenticationAuthority {
    key_id: Hash256,
    secret: Hash256,
}

impl AuthenticationAuthority {
    fn new(key_id: Hash256, secret: Hash256) -> Self {
        Self { key_id, secret }
    }

    pub fn key_id(&self) -> &Hash256 {
        &self.key_id
    }
}

impl fmt::Debug for AuthenticationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationAuthority")
            .field("key_id", &self.key_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthenticationPurpose {
    JournalReplica,
    Confirmation,
    Handoff,
}

/// Opaque deterministic authentication token.
///
/// This type intentionally implements `Serialize` but not `Deserialize`, so
/// untrusted serialized input cannot directly become an authority-bearing
/// token. Its constructor and fields are private.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticationToken {
    purpose: AuthenticationPurpose,
    key_id: Hash256,
    tag: Hash256,
}

impl AuthenticationToken {
    fn new(purpose: AuthenticationPurpose, key_id: Hash256, tag: Hash256) -> Self {
        Self {
            purpose,
            key_id,
            tag,
        }
    }

    pub fn key_id(&self) -> &Hash256 {
        &self.key_id
    }

    pub fn tag(&self) -> &Hash256 {
        &self.tag
    }

    pub fn purpose(&self) -> &'static str {
        match self.purpose {
            AuthenticationPurpose::JournalReplica => "journal_replica",
            AuthenticationPurpose::Confirmation => "confirmation",
            AuthenticationPurpose::Handoff => "handoff",
        }
    }
}

/// One exact journal replica authenticated by an in-memory authority.
///
/// Its constructor is private. Use [`authenticate_journal_replica`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedJournalReplica {
    replica_id: ReplicaId,
    identity: JournalIdentity,
    journal: Vec<JournalRecord>,
    authentication: AuthenticationToken,
}

impl AuthenticatedJournalReplica {
    fn new(
        replica_id: ReplicaId,
        identity: JournalIdentity,
        journal: Vec<JournalRecord>,
        authentication: AuthenticationToken,
    ) -> Self {
        Self {
            replica_id,
            identity,
            journal,
            authentication,
        }
    }

    pub fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }

    pub fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub fn journal(&self) -> &[JournalRecord] {
        &self.journal
    }

    pub fn authentication(&self) -> &AuthenticationToken {
        &self.authentication
    }
}

/// Exact state obtained only after two distinct replicas authenticate and agree.
///
/// Its constructor is private. Use [`reconcile_authenticated_replicas`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledJournal {
    identity: JournalIdentity,
    journal: Vec<JournalRecord>,
    replicas: [ReplicaId; REQUIRED_REPLICAS],
}

impl ReconciledJournal {
    fn new(
        identity: JournalIdentity,
        journal: Vec<JournalRecord>,
        replicas: [ReplicaId; REQUIRED_REPLICAS],
    ) -> Self {
        Self {
            identity,
            journal,
            replicas,
        }
    }

    pub fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub fn journal(&self) -> &[JournalRecord] {
        &self.journal
    }

    pub fn replicas(&self) -> &[ReplicaId; REQUIRED_REPLICAS] {
        &self.replicas
    }
}

/// Authenticated user confirmation bound to the exact run identity.
///
/// Its constructor is private. Use [`authenticate_confirmation_object`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedConfirmation {
    identity: JournalIdentity,
    confirmation: Confirmation,
    authentication: AuthenticationToken,
}

impl AuthenticatedConfirmation {
    fn new(
        identity: JournalIdentity,
        confirmation: Confirmation,
        authentication: AuthenticationToken,
    ) -> Self {
        Self {
            identity,
            confirmation,
            authentication,
        }
    }

    pub fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub fn confirmation(&self) -> &Confirmation {
        &self.confirmation
    }

    pub fn authentication(&self) -> &AuthenticationToken {
        &self.authentication
    }
}

/// Authenticated graph-approved handoff claim.
///
/// Its constructor is private. Use [`authenticate_handoff_object`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedHandoff {
    identity: JournalIdentity,
    handoff: Handoff,
    transition_id: String,
    actor: String,
    next_actor: String,
    resume_token: String,
    authentication: AuthenticationToken,
}

impl AuthenticatedHandoff {
    fn new(
        identity: JournalIdentity,
        handoff: Handoff,
        transition_id: String,
        actor: String,
        next_actor: String,
        resume_token: String,
        authentication: AuthenticationToken,
    ) -> Self {
        Self {
            identity,
            handoff,
            transition_id,
            actor,
            next_actor,
            resume_token,
            authentication,
        }
    }

    pub fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub fn handoff(&self) -> &Handoff {
        &self.handoff
    }

    pub fn transition_id(&self) -> &str {
        &self.transition_id
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn next_actor(&self) -> &str {
        &self.next_actor
    }

    pub fn resume_token(&self) -> &str {
        &self.resume_token
    }

    pub fn authentication(&self) -> &AuthenticationToken {
        &self.authentication
    }
}

/// Serializable state for the durable-model nonce ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceLedgerSnapshot {
    schema_version: u32,
    consumed_nonce_hashes: Vec<Hash256>,
}

impl NonceLedgerSnapshot {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn consumed_nonce_hashes(&self) -> &[Hash256] {
        &self.consumed_nonce_hashes
    }
}

/// In-memory model of durably recorded, single-use handoff nonces.
///
/// Its constructors are private. Use [`empty_nonce_ledger`] or
/// [`restore_nonce_ledger`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableNonceLedger {
    consumed_nonce_hashes: BTreeSet<Hash256>,
}

impl DurableNonceLedger {
    fn new(consumed_nonce_hashes: BTreeSet<Hash256>) -> Self {
        Self {
            consumed_nonce_hashes,
        }
    }

    pub fn snapshot(&self) -> NonceLedgerSnapshot {
        NonceLedgerSnapshot {
            schema_version: CONTRACT_SCHEMA_VERSION,
            consumed_nonce_hashes: self.consumed_nonce_hashes.iter().cloned().collect(),
        }
    }

    pub fn contains(&self, nonce: &str) -> Result<bool, ReplicaError> {
        Ok(self.consumed_nonce_hashes.contains(&nonce_hash(nonce)?))
    }

    fn consume(&mut self, nonce: &str) -> Result<(), ReplicaError> {
        let hash = nonce_hash(nonce)?;
        if !self.consumed_nonce_hashes.insert(hash) {
            return Err(ReplicaError::NonceReplay);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ReplicaError {
    #[error("authentication key material must contain at least 32 nonzero bytes")]
    InvalidAuthorityKey,
    #[error("canonical SHA-256 hashing failed")]
    CanonicalHash,
    #[error("journal is invalid")]
    InvalidJournal,
    #[error("journal plan identity does not match the expected plan")]
    JournalPlanMismatch,
    #[error("journal is too long to represent")]
    JournalTooLong,
    #[error("exactly two replicas are required, got {actual}")]
    ReplicaCount { actual: usize },
    #[error("the two replicas must use distinct durable locations")]
    DuplicateReplica,
    #[error("replica authentication failed")]
    AuthenticationFailed,
    #[error("replica graph, plan, or release identities are mixed")]
    MixedIdentity,
    #[error("one authenticated replica is a stale prefix of the other")]
    StaleReplica,
    #[error("authenticated replica histories fork")]
    Fork,
    #[error("confirmation validation failed")]
    InvalidConfirmation,
    #[error("handoff transition is unknown")]
    UnknownHandoffTransition,
    #[error("handoff requests an actor change not declared by the graph")]
    IllegalActorChange,
    #[error("handoff is not bound to the reconciled graph, journal, plan, or release")]
    InvalidHandoff,
    #[error("handoff nonce must not be empty")]
    InvalidNonce,
    #[error("handoff nonce was already consumed")]
    NonceReplay,
    #[error("nonce ledger snapshot is invalid")]
    InvalidNonceLedger,
}

#[derive(Serialize)]
struct AuthorityKeyId<'a> {
    domain: &'static str,
    secret: &'a Hash256,
}

#[derive(Serialize)]
struct MacMaterial<'a> {
    domain: &'static str,
    purpose: AuthenticationPurpose,
    key_id: &'a Hash256,
    secret: &'a Hash256,
    payload_hash: &'a Hash256,
}

#[derive(Serialize)]
struct ReplicaPayload<'a> {
    domain: &'static str,
    replica_id: ReplicaId,
    identity: &'a JournalIdentity,
    journal: &'a [JournalRecord],
}

#[derive(Serialize)]
struct ConfirmationPayload<'a> {
    domain: &'static str,
    identity: &'a JournalIdentity,
    confirmation: &'a Confirmation,
}

#[derive(Serialize)]
struct HandoffPayload<'a> {
    domain: &'static str,
    identity: &'a JournalIdentity,
    handoff: &'a Handoff,
    transition_id: &'a str,
    actor: &'a str,
    next_actor: &'a str,
    resume_token: &'a str,
}

#[derive(Serialize)]
struct NonceMaterial<'a> {
    domain: &'static str,
    nonce: &'a str,
}

/// Validate key material and issue an opaque in-memory authentication authority.
pub fn validate_authentication_authority(
    key_material: &[u8],
) -> Result<AuthenticationAuthority, ReplicaError> {
    if key_material.len() < 32 || key_material.iter().all(|byte| *byte == 0) {
        return Err(ReplicaError::InvalidAuthorityKey);
    }
    let secret = Hash256::from_bytes(Sha256::digest(key_material).into());
    let key_id = hash_canonical(&AuthorityKeyId {
        domain: AUTHORITY_DOMAIN,
        secret: &secret,
    })?;
    Ok(AuthenticationAuthority::new(key_id, secret))
}

/// Validate a journal and derive its exact graph/plan/release/head identity.
pub fn journal_identity(
    graph: &GraphModel,
    plan_hash: &Hash256,
    release_manifest_hash: &Hash256,
    journal: &[JournalRecord],
) -> Result<JournalIdentity, ReplicaError> {
    let head = validate_journal_chain(journal).map_err(|_| ReplicaError::InvalidJournal)?;
    if head.plan_hash != *plan_hash {
        return Err(ReplicaError::JournalPlanMismatch);
    }
    let journal_len = u64::try_from(journal.len()).map_err(|_| ReplicaError::JournalTooLong)?;
    Ok(JournalIdentity {
        graph_model_id: graph.model_id().to_owned(),
        graph_digest: graph.digest().clone(),
        plan_hash: plan_hash.clone(),
        release_manifest_hash: release_manifest_hash.clone(),
        journal_head_hash: hash_journal_record(head).map_err(|_| ReplicaError::CanonicalHash)?,
        journal_len,
    })
}

/// Authenticate one validated journal at one of the two v1 durable locations.
pub fn authenticate_journal_replica(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    replica_id: ReplicaId,
    plan_hash: &Hash256,
    release_manifest_hash: &Hash256,
    journal: Vec<JournalRecord>,
) -> Result<AuthenticatedJournalReplica, ReplicaError> {
    let identity = journal_identity(graph, plan_hash, release_manifest_hash, &journal)?;
    let authentication = authenticate_payload(
        authority,
        AuthenticationPurpose::JournalReplica,
        &ReplicaPayload {
            domain: REPLICA_DOMAIN,
            replica_id,
            identity: &identity,
            journal: &journal,
        },
    )?;
    Ok(AuthenticatedJournalReplica::new(
        replica_id,
        identity,
        journal,
        authentication,
    ))
}

/// Reconcile exactly two distinct authenticated replicas.
///
/// The replicas must have the expected graph, plan, and release identity and
/// byte-for-byte equal journal records. A strict-prefix disagreement is stale;
/// any other disagreement is a fork.
pub fn reconcile_authenticated_replicas(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    plan_hash: &Hash256,
    release_manifest_hash: &Hash256,
    replicas: &[AuthenticatedJournalReplica],
) -> Result<ReconciledJournal, ReplicaError> {
    if replicas.len() != REQUIRED_REPLICAS {
        return Err(ReplicaError::ReplicaCount {
            actual: replicas.len(),
        });
    }
    let first = &replicas[0];
    let second = &replicas[1];
    if first.replica_id == second.replica_id {
        return Err(ReplicaError::DuplicateReplica);
    }

    verify_replica(authority, graph, first)?;
    verify_replica(authority, graph, second)?;

    if !first
        .identity
        .matches_context(graph, plan_hash, release_manifest_hash)
        || !second
            .identity
            .matches_context(graph, plan_hash, release_manifest_hash)
    {
        return Err(ReplicaError::MixedIdentity);
    }

    if first.journal != second.journal {
        if is_strict_prefix(&first.journal, &second.journal)
            || is_strict_prefix(&second.journal, &first.journal)
        {
            return Err(ReplicaError::StaleReplica);
        }
        return Err(ReplicaError::Fork);
    }
    if first.identity != second.identity {
        return Err(ReplicaError::MixedIdentity);
    }

    let mut replica_ids = [first.replica_id, second.replica_id];
    replica_ids.sort();
    Ok(ReconciledJournal::new(
        first.identity.clone(),
        first.journal.clone(),
        replica_ids,
    ))
}

/// Authenticate a confirmation only after the core confirmation validator and
/// the graph/plan/release identity checks all succeed.
pub fn authenticate_confirmation_object(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    identity: &JournalIdentity,
    plan: &InstallPlan,
    displayed: &PlanDisplay,
    confirmation: Confirmation,
) -> Result<AuthenticatedConfirmation, ReplicaError> {
    validate_confirmation_binding(graph, identity, plan, displayed, &confirmation)?;
    let authentication = authenticate_payload(
        authority,
        AuthenticationPurpose::Confirmation,
        &ConfirmationPayload {
            domain: CONFIRMATION_DOMAIN,
            identity,
            confirmation: &confirmation,
        },
    )?;
    Ok(AuthenticatedConfirmation::new(
        identity.clone(),
        confirmation,
        authentication,
    ))
}

/// Revalidate an authenticated confirmation against the current exact identity.
pub fn verify_authenticated_confirmation(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    identity: &JournalIdentity,
    plan: &InstallPlan,
    displayed: &PlanDisplay,
    authenticated: &AuthenticatedConfirmation,
) -> Result<(), ReplicaError> {
    if authenticated.identity != *identity {
        return Err(ReplicaError::MixedIdentity);
    }
    validate_confirmation_binding(
        graph,
        identity,
        plan,
        displayed,
        &authenticated.confirmation,
    )?;
    verify_payload(
        authority,
        AuthenticationPurpose::Confirmation,
        &ConfirmationPayload {
            domain: CONFIRMATION_DOMAIN,
            identity: &authenticated.identity,
            confirmation: &authenticated.confirmation,
        },
        &authenticated.authentication,
    )
}

/// Authenticate a handoff only when its actor change and resume token are the
/// exact values declared by the journal head's transition in `GraphModel`.
pub fn authenticate_handoff_object(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    reconciled: &ReconciledJournal,
    handoff: Handoff,
    requested_next_actor: &str,
    requested_resume_token: &str,
) -> Result<AuthenticatedHandoff, ReplicaError> {
    let head = reconciled
        .journal
        .last()
        .ok_or(ReplicaError::InvalidJournal)?;
    validate_handoff_binding(
        graph,
        reconciled,
        &handoff,
        &head.transition_id,
        &head.actor,
        requested_next_actor,
        requested_resume_token,
    )?;
    let authentication = authenticate_payload(
        authority,
        AuthenticationPurpose::Handoff,
        &HandoffPayload {
            domain: HANDOFF_DOMAIN,
            identity: &reconciled.identity,
            handoff: &handoff,
            transition_id: &head.transition_id,
            actor: &head.actor,
            next_actor: requested_next_actor,
            resume_token: requested_resume_token,
        },
    )?;
    Ok(AuthenticatedHandoff::new(
        reconciled.identity.clone(),
        handoff,
        head.transition_id.clone(),
        head.actor.clone(),
        requested_next_actor.to_owned(),
        requested_resume_token.to_owned(),
        authentication,
    ))
}

/// Verify an authenticated graph-aware handoff without consuming its nonce.
pub fn verify_authenticated_handoff(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    reconciled: &ReconciledJournal,
    authenticated: &AuthenticatedHandoff,
) -> Result<(), ReplicaError> {
    if authenticated.identity != reconciled.identity {
        return Err(ReplicaError::MixedIdentity);
    }
    validate_handoff_binding(
        graph,
        reconciled,
        &authenticated.handoff,
        &authenticated.transition_id,
        &authenticated.actor,
        &authenticated.next_actor,
        &authenticated.resume_token,
    )?;
    verify_payload(
        authority,
        AuthenticationPurpose::Handoff,
        &HandoffPayload {
            domain: HANDOFF_DOMAIN,
            identity: &authenticated.identity,
            handoff: &authenticated.handoff,
            transition_id: &authenticated.transition_id,
            actor: &authenticated.actor,
            next_actor: &authenticated.next_actor,
            resume_token: &authenticated.resume_token,
        },
        &authenticated.authentication,
    )
}

/// Verify a handoff and atomically consume its nonce in the durable model.
pub fn accept_authenticated_handoff(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    reconciled: &ReconciledJournal,
    authenticated: &AuthenticatedHandoff,
    nonce_ledger: &mut DurableNonceLedger,
) -> Result<(), ReplicaError> {
    verify_authenticated_handoff(authority, graph, reconciled, authenticated)?;
    nonce_ledger.consume(&authenticated.handoff.nonce)
}

/// Create an empty durable-model nonce ledger.
pub fn empty_nonce_ledger() -> DurableNonceLedger {
    DurableNonceLedger::new(BTreeSet::new())
}

/// Restore a nonce ledger from deterministic serialized state, rejecting
/// unsupported schema versions, duplicates, and non-canonical ordering.
pub fn restore_nonce_ledger(
    snapshot: &NonceLedgerSnapshot,
) -> Result<DurableNonceLedger, ReplicaError> {
    if snapshot.schema_version != CONTRACT_SCHEMA_VERSION
        || !snapshot
            .consumed_nonce_hashes
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(ReplicaError::InvalidNonceLedger);
    }
    Ok(DurableNonceLedger::new(
        snapshot.consumed_nonce_hashes.iter().cloned().collect(),
    ))
}

fn validate_confirmation_binding(
    graph: &GraphModel,
    identity: &JournalIdentity,
    plan: &InstallPlan,
    displayed: &PlanDisplay,
    confirmation: &Confirmation,
) -> Result<(), ReplicaError> {
    validate_confirmation(plan, displayed, confirmation)
        .map_err(|_| ReplicaError::InvalidConfirmation)?;
    if !identity.matches_context(graph, &plan.plan_hash, &plan.body.release_manifest_hash) {
        return Err(ReplicaError::MixedIdentity);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_handoff_binding(
    graph: &GraphModel,
    reconciled: &ReconciledJournal,
    handoff: &Handoff,
    transition_id: &str,
    actor: &str,
    next_actor: &str,
    resume_token: &str,
) -> Result<(), ReplicaError> {
    let transition_id = graph
        .transition_id(transition_id)
        .ok_or(ReplicaError::UnknownHandoffTransition)?;
    let transition = graph.transition(transition_id);
    let handoff_spec = transition
        .def
        .handoff
        .as_ref()
        .ok_or(ReplicaError::IllegalActorChange)?;
    let target_state = graph.state(transition.to);
    let head = reconciled
        .journal
        .last()
        .ok_or(ReplicaError::InvalidJournal)?;

    if transition.def.actor != actor
        || graph.state(transition.from).actor != actor
        || head.actor != actor
        || handoff_spec.next_actor != next_actor
        || next_actor == actor
        || handoff_spec.resume_token != resume_token
        || !graph
            .actors()
            .iter()
            .any(|candidate| candidate == next_actor)
    {
        return Err(ReplicaError::IllegalActorChange);
    }

    let expected_replicas = handoff_spec
        .journal_replicas
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual_replicas = reconciled
        .replicas
        .iter()
        .map(|replica| replica.as_str())
        .collect::<BTreeSet<_>>();
    let expected_state_hash =
        control_state_hash(&handoff.control_state).map_err(|_| ReplicaError::CanonicalHash)?;

    if handoff.schema_version != CONTRACT_SCHEMA_VERSION
        || !transition.def.journal.advance_before_handoff
        || expected_replicas.len() != REQUIRED_REPLICAS
        || expected_replicas != actual_replicas
        || handoff.graph_model_id != reconciled.identity.graph_model_id
        || handoff.plan_hash != reconciled.identity.plan_hash
        || handoff.release_manifest_hash != reconciled.identity.release_manifest_hash
        || handoff.journal_head_hash != reconciled.identity.journal_head_hash
        || handoff.control_state != target_state.id
        || head.record_type != JournalRecordType::StateAdvanced
        || head.transition_id != transition.def.id
        || head.postcondition_hash.as_ref() != Some(&expected_state_hash)
    {
        return Err(ReplicaError::InvalidHandoff);
    }
    if handoff.nonce.is_empty() {
        return Err(ReplicaError::InvalidNonce);
    }
    Ok(())
}

fn verify_replica(
    authority: &AuthenticationAuthority,
    graph: &GraphModel,
    replica: &AuthenticatedJournalReplica,
) -> Result<(), ReplicaError> {
    verify_payload(
        authority,
        AuthenticationPurpose::JournalReplica,
        &ReplicaPayload {
            domain: REPLICA_DOMAIN,
            replica_id: replica.replica_id,
            identity: &replica.identity,
            journal: &replica.journal,
        },
        &replica.authentication,
    )?;
    let observed = journal_identity(
        graph,
        &replica.identity.plan_hash,
        &replica.identity.release_manifest_hash,
        &replica.journal,
    )?;
    if observed != replica.identity {
        return Err(ReplicaError::AuthenticationFailed);
    }
    Ok(())
}

fn authenticate_payload<T: Serialize>(
    authority: &AuthenticationAuthority,
    purpose: AuthenticationPurpose,
    payload: &T,
) -> Result<AuthenticationToken, ReplicaError> {
    let payload_hash = hash_canonical(payload)?;
    let tag = hash_canonical(&MacMaterial {
        domain: AUTHORITY_DOMAIN,
        purpose,
        key_id: &authority.key_id,
        secret: &authority.secret,
        payload_hash: &payload_hash,
    })?;
    Ok(AuthenticationToken::new(
        purpose,
        authority.key_id.clone(),
        tag,
    ))
}

fn verify_payload<T: Serialize>(
    authority: &AuthenticationAuthority,
    purpose: AuthenticationPurpose,
    payload: &T,
    token: &AuthenticationToken,
) -> Result<(), ReplicaError> {
    let expected = authenticate_payload(authority, purpose, payload)?;
    if token != &expected {
        return Err(ReplicaError::AuthenticationFailed);
    }
    Ok(())
}

fn hash_canonical<T: Serialize>(value: &T) -> Result<Hash256, ReplicaError> {
    canonical_sha256(value).map_err(|_| ReplicaError::CanonicalHash)
}

fn nonce_hash(nonce: &str) -> Result<Hash256, ReplicaError> {
    if nonce.is_empty() {
        return Err(ReplicaError::InvalidNonce);
    }
    hash_canonical(&NonceMaterial {
        domain: NONCE_DOMAIN,
        nonce,
    })
}

fn is_strict_prefix(first: &[JournalRecord], second: &[JournalRecord]) -> bool {
    first.len() < second.len() && second.starts_with(first)
}
