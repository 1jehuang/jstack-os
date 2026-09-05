//! Verified, typed, strictly parsed executable state graph.
//!
//! Loading succeeds only for the exact pinned model identity and expected
//! content digest, with unknown fields rejected at every level, all catalog
//! references resolved, and the runtime-critical structural invariants the
//! controller depends on re-asserted in Rust.

use std::collections::{BTreeMap, BTreeSet};

use jstack_installer_core::Hash256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Identity of the separately executable Ubuntu whole-disk deployment graph.
pub const UBUNTU_WHOLE_DISK_MODEL_ID: &str = "jstack-ubuntu-whole-disk-v1";

/// SHA-256 of `model/ubuntu-whole-disk-state-graph.json`.
pub const UBUNTU_WHOLE_DISK_GRAPH_SHA256: &str =
    "3c7cfc18ade7eb3810bd5e2fa68e5969ee82ef4adaf2d3785477d0ed50e922f4";

/// Action risks that make a transition mutating and therefore subject to the
/// intent/commit journal protocol. Mirrors the semantic validator.
pub const MUTATING_RISKS: [ActionRisk; 6] = [
    ActionRisk::StagingMutation,
    ActionRisk::FilesystemMutation,
    ActionRisk::SecurityMutation,
    ActionRisk::DiskMutation,
    ActionRisk::BootMutation,
    ActionRisk::Reboot,
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StateId(pub(crate) u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransitionId(pub(crate) u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GuardId(pub(crate) u16);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionId(pub(crate) u16);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StateKind {
    Checkpoint,
    Terminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Success,
    SafeAbort,
    Unsupported,
    RolledBack,
    ManualRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    ReadOnly,
    ExternalIo,
    UserAuthorization,
    StagingMutation,
    FilesystemMutation,
    SecurityMutation,
    DiskMutation,
    BootMutation,
    Reboot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionIdempotency {
    Idempotent,
    ContentAddressed,
    ReconcileRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionRecovery {
    Retry,
    Reconcile,
    Compensate,
    ReconcileThenCompensate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Authorization {
    ReleasePolicy,
    ConfirmedPlan,
    RollbackAuthorized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JournalRequirements {
    pub intent_before_actions: bool,
    pub commit_after_postconditions: bool,
    #[serde(default)]
    pub advance_before_handoff: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HandoffSpec {
    pub next_actor: String,
    pub resume_token: String,
    pub journal_replicas: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardEvidenceDeclaration {
    pub claim: String,
    pub content_address: String,
    pub identity_fields: Vec<String>,
    pub witness_roles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDef {
    pub id: String,
    pub kind: StateKind,
    pub actor: String,
    pub phase: String,
    pub ui_view: String,
    pub description: String,
    #[serde(default)]
    pub terminal_outcome: Option<TerminalOutcome>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardDef {
    pub id: String,
    pub platform: String,
    pub description: String,
    #[serde(default)]
    pub evidence: Option<GuardEvidenceDeclaration>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDef {
    pub id: String,
    pub platform: String,
    pub risk: ActionRisk,
    pub description: String,
    #[serde(default)]
    pub idempotency: Option<ActionIdempotency>,
    #[serde(default)]
    pub recovery: Option<ActionRecovery>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantDef {
    pub id: String,
    pub description: String,
    pub enforced_by: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionDef {
    pub id: String,
    pub from: String,
    pub to: String,
    pub event: String,
    pub actor: String,
    pub guards: Vec<String>,
    pub actions: Vec<String>,
    pub authorization: Vec<Authorization>,
    pub journal: JournalRequirements,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub description: String,
    #[serde(default)]
    pub failure_to: Option<String>,
    #[serde(default)]
    pub handoff: Option<HandoffSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    schema_version: u32,
    model_id: String,
    initial_state: String,
    scope: serde_json::Value,
    actors: Vec<String>,
    actor_platforms: BTreeMap<String, Vec<String>>,
    guards: Vec<GuardDef>,
    actions: Vec<ActionDef>,
    invariants: Vec<InvariantDef>,
    states: Vec<StateDef>,
    transitions: Vec<TransitionDef>,
}

#[derive(Debug, Error)]
pub enum GraphLoadError {
    #[error("state graph is not valid strict JSON: {0}")]
    Parse(String),
    #[error("state graph identity is invalid: {0}")]
    Identity(#[from] jstack_installer_core::StateGraphIdentityError),
    #[error("state graph digest {} does not match expected {}", actual.as_str(), expected.as_str())]
    DigestMismatch { expected: Hash256, actual: Hash256 },
    #[error("state graph schema_version {0} is unsupported")]
    UnsupportedSchemaVersion(u32),
    #[error("state graph is semantically invalid: {0}")]
    Invalid(String),
}

/// The verified, interned executable state graph.
#[derive(Debug)]
pub struct GraphModel {
    model_id: String,
    digest: Hash256,
    initial_state: StateId,
    scope: serde_json::Value,
    actors: Vec<String>,
    actor_platforms: BTreeMap<String, BTreeSet<String>>,
    states: Vec<StateDef>,
    guards: Vec<GuardDef>,
    actions: Vec<ActionDef>,
    invariants: Vec<InvariantDef>,
    transitions: Vec<ResolvedTransition>,
    state_index: BTreeMap<String, StateId>,
    guard_index: BTreeMap<String, GuardId>,
    action_index: BTreeMap<String, ActionId>,
    transition_index: BTreeMap<String, TransitionId>,
    candidates: BTreeMap<(StateId, String), Vec<TransitionId>>,
}

/// A transition with every catalog reference resolved to a typed id.
#[derive(Clone, Debug)]
pub struct ResolvedTransition {
    pub def: TransitionDef,
    pub from: StateId,
    pub to: StateId,
    pub failure_to: Option<StateId>,
    pub guards: Vec<GuardId>,
    pub actions: Vec<ActionId>,
}

/// Load and verify the executable graph from its exact bytes.
///
/// The bytes must hash to `expected_sha256`, carry the pinned executable
/// `model_id`, parse with unknown fields rejected everywhere, and satisfy the
/// runtime-critical structural invariants.
pub fn load_verified(
    bytes: &[u8],
    expected_sha256: &Hash256,
) -> Result<GraphModel, GraphLoadError> {
    let actual = Hash256::from_bytes(Sha256::digest(bytes).into());
    if &actual != expected_sha256 {
        return Err(GraphLoadError::DigestMismatch {
            expected: expected_sha256.clone(),
            actual,
        });
    }
    jstack_installer_core::executable_state_model_id(bytes)?;
    let raw: RawModel =
        serde_json::from_slice(bytes).map_err(|error| GraphLoadError::Parse(error.to_string()))?;
    if raw.schema_version != 1 {
        return Err(GraphLoadError::UnsupportedSchemaVersion(raw.schema_version));
    }
    GraphModel::build(raw, actual)
}

/// Load the exact pinned Ubuntu whole-disk graph.
///
/// This is intentionally additive to [`load_verified`]. The existing loader
/// remains bound to the Windows no-USB model through core's executable model
/// identity check. Ubuntu has a distinct graph and pin, and therefore cannot
/// weaken or substitute for that identity.
pub fn load_verified_ubuntu_whole_disk(bytes: &[u8]) -> Result<GraphModel, GraphLoadError> {
    GraphModel::load_verified_ubuntu_whole_disk(bytes)
}

impl GraphModel {
    /// Load only the repository-pinned Ubuntu whole-disk graph.
    ///
    /// This is deliberately separate from [`load_verified`], whose identity
    /// remains pinned by installer-core to the Windows dual-boot model.
    pub fn load_verified_ubuntu_whole_disk(bytes: &[u8]) -> Result<Self, GraphLoadError> {
        let expected = Hash256::parse(UBUNTU_WHOLE_DISK_GRAPH_SHA256)
            .expect("the compiled-in Ubuntu graph digest is valid");
        let actual = Hash256::from_bytes(Sha256::digest(bytes).into());
        if actual != expected {
            return Err(GraphLoadError::DigestMismatch { expected, actual });
        }

        let raw: RawModel = serde_json::from_slice(bytes)
            .map_err(|error| GraphLoadError::Parse(error.to_string()))?;
        if raw.model_id != UBUNTU_WHOLE_DISK_MODEL_ID {
            return Err(GraphLoadError::Identity(
                jstack_installer_core::StateGraphIdentityError::UnexpectedModelId {
                    expected: UBUNTU_WHOLE_DISK_MODEL_ID,
                    actual: raw.model_id,
                },
            ));
        }
        if raw.schema_version != 1 {
            return Err(GraphLoadError::UnsupportedSchemaVersion(raw.schema_version));
        }
        Self::build(raw, actual)
    }

    fn build(raw: RawModel, digest: Hash256) -> Result<Self, GraphLoadError> {
        let invalid = |message: String| GraphLoadError::Invalid(message);

        let state_index = intern("state", raw.states.iter().map(|item| item.id.as_str()))
            .map(|index| {
                index
                    .into_iter()
                    .map(|(id, position)| (id, StateId(position)))
                    .collect::<BTreeMap<_, _>>()
            })
            .map_err(invalid)?;
        let guard_index = intern("guard", raw.guards.iter().map(|item| item.id.as_str()))
            .map(|index| {
                index
                    .into_iter()
                    .map(|(id, position)| (id, GuardId(position)))
                    .collect::<BTreeMap<_, _>>()
            })
            .map_err(invalid)?;
        let action_index = intern("action", raw.actions.iter().map(|item| item.id.as_str()))
            .map(|index| {
                index
                    .into_iter()
                    .map(|(id, position)| (id, ActionId(position)))
                    .collect::<BTreeMap<_, _>>()
            })
            .map_err(invalid)?;
        let transition_index = intern(
            "transition",
            raw.transitions.iter().map(|item| item.id.as_str()),
        )
        .map(|index| {
            index
                .into_iter()
                .map(|(id, position)| (id, TransitionId(position)))
                .collect::<BTreeMap<_, _>>()
        })
        .map_err(invalid)?;
        intern(
            "invariant",
            raw.invariants.iter().map(|item| item.id.as_str()),
        )
        .map_err(invalid)?;

        let actors: BTreeSet<&str> = raw.actors.iter().map(String::as_str).collect();
        if actors.len() != raw.actors.len() {
            return Err(invalid("duplicate actor".into()));
        }
        let actor_platforms: BTreeMap<String, BTreeSet<String>> = raw
            .actor_platforms
            .iter()
            .map(|(actor, platforms)| (actor.clone(), platforms.iter().cloned().collect()))
            .collect();
        if actor_platforms
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != actors
        {
            return Err(invalid(
                "actor_platforms does not exactly cover actors".into(),
            ));
        }

        let initial_state = *state_index
            .get(&raw.initial_state)
            .ok_or_else(|| invalid(format!("unknown initial state {}", raw.initial_state)))?;

        for state in &raw.states {
            if !actors.contains(state.actor.as_str()) {
                return Err(invalid(format!(
                    "state {} references unknown actor {}",
                    state.id, state.actor
                )));
            }
            match (state.kind, state.terminal_outcome) {
                (StateKind::Terminal, None) => {
                    return Err(invalid(format!(
                        "terminal state {} lacks terminal_outcome",
                        state.id
                    )));
                }
                (StateKind::Checkpoint, Some(_)) => {
                    return Err(invalid(format!(
                        "nonterminal state {} declares terminal_outcome",
                        state.id
                    )));
                }
                _ => {}
            }
        }

        let mut transitions = Vec::with_capacity(raw.transitions.len());
        let mut candidates: BTreeMap<(StateId, String), Vec<TransitionId>> = BTreeMap::new();
        let mut outgoing: BTreeMap<StateId, usize> = BTreeMap::new();
        for (position, def) in raw.transitions.iter().enumerate() {
            let context = |message: String| invalid(format!("transition {}: {message}", def.id));
            let from = *state_index
                .get(&def.from)
                .ok_or_else(|| context(format!("unknown source {}", def.from)))?;
            let to = *state_index
                .get(&def.to)
                .ok_or_else(|| context(format!("unknown target {}", def.to)))?;
            let failure_to = def
                .failure_to
                .as_ref()
                .map(|target| {
                    state_index
                        .get(target)
                        .copied()
                        .ok_or_else(|| context(format!("unknown failure target {target}")))
                })
                .transpose()?;
            if !actors.contains(def.actor.as_str()) {
                return Err(context(format!("unknown actor {}", def.actor)));
            }
            let allowed_platforms = actor_platforms
                .get(&def.actor)
                .ok_or_else(|| context(format!("actor {} lacks platform authority", def.actor)))?;
            let guards = def
                .guards
                .iter()
                .map(|guard| {
                    let id = guard_index
                        .get(guard)
                        .copied()
                        .ok_or_else(|| context(format!("unknown guard {guard}")))?;
                    let platform = &raw.guards[id.0 as usize].platform;
                    if !allowed_platforms.contains(platform) {
                        return Err(context(format!(
                            "actor {} cannot evaluate {guard} on platform {platform}",
                            def.actor
                        )));
                    }
                    Ok(id)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let actions = def
                .actions
                .iter()
                .map(|action| {
                    let id = action_index
                        .get(action)
                        .copied()
                        .ok_or_else(|| context(format!("unknown action {action}")))?;
                    let platform = &raw.actions[id.0 as usize].platform;
                    if !allowed_platforms.contains(platform) {
                        return Err(context(format!(
                            "actor {} cannot execute {action} on platform {platform}",
                            def.actor
                        )));
                    }
                    Ok(id)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mutating_actions = actions
                .iter()
                .filter(|action| MUTATING_RISKS.contains(&raw.actions[action.0 as usize].risk))
                .count();
            if mutating_actions > 1 {
                return Err(context("combines multiple mutations".into()));
            }
            if mutating_actions == 1 {
                if !def.journal.intent_before_actions || !def.journal.commit_after_postconditions {
                    return Err(context("mutating transition lacks journal protocol".into()));
                }
                if failure_to.is_none() {
                    return Err(context("mutating transition lacks failure_to".into()));
                }
                if def.preconditions.is_empty() || def.postconditions.is_empty() {
                    return Err(context(
                        "mutating transition lacks preconditions or postconditions".into(),
                    ));
                }
                for action in &actions {
                    let action_def = &raw.actions[action.0 as usize];
                    if MUTATING_RISKS.contains(&action_def.risk)
                        && (action_def.idempotency.is_none() || action_def.recovery.is_none())
                    {
                        return Err(context(format!(
                            "mutating action {} lacks idempotency or recovery policy",
                            action_def.id
                        )));
                    }
                }
            }
            let requests_reboot = def.actions.iter().any(|action| action == "request_reboot");
            match (&def.handoff, requests_reboot) {
                (Some(handoff), true) => {
                    let replicas: BTreeSet<&String> = handoff.journal_replicas.iter().collect();
                    if replicas.len() < 2 {
                        return Err(context(
                            "reboot handoff needs at least two journal replicas".into(),
                        ));
                    }
                    if !actors.contains(handoff.next_actor.as_str()) {
                        return Err(context(format!(
                            "handoff next actor {} is unknown",
                            handoff.next_actor
                        )));
                    }
                    if !def.journal.advance_before_handoff {
                        return Err(context(
                            "reboot transition must advance durable state before handoff".into(),
                        ));
                    }
                }
                (None, true) => return Err(context("reboot transition lacks handoff".into())),
                (Some(_), false) => {
                    return Err(context("handoff declared without a reboot action".into()));
                }
                (None, false) => {}
            }

            candidates
                .entry((from, def.event.clone()))
                .or_default()
                .push(TransitionId(position as u16));
            *outgoing.entry(from).or_default() += 1;
            transitions.push(ResolvedTransition {
                def: def.clone(),
                from,
                to,
                failure_to,
                guards,
                actions,
            });
        }

        for (position, state) in raw.states.iter().enumerate() {
            let count = outgoing
                .get(&StateId(position as u16))
                .copied()
                .unwrap_or(0);
            match state.kind {
                StateKind::Terminal if count != 0 => {
                    return Err(invalid(format!(
                        "terminal state {} has outgoing transitions",
                        state.id
                    )));
                }
                StateKind::Checkpoint if count == 0 => {
                    return Err(invalid(format!(
                        "nonterminal state {} has no outgoing transition",
                        state.id
                    )));
                }
                _ => {}
            }
        }

        // Static determinism: two candidates for one (state, event) must have
        // guard sets where neither is a subset of the other; otherwise one
        // consistent guard verdict could enable both simultaneously.
        for ((state, event), ids) in &candidates {
            for (index, first) in ids.iter().enumerate() {
                for second in &ids[index + 1..] {
                    let first_guards: BTreeSet<GuardId> = transitions[first.0 as usize]
                        .guards
                        .iter()
                        .copied()
                        .collect();
                    let second_guards: BTreeSet<GuardId> = transitions[second.0 as usize]
                        .guards
                        .iter()
                        .copied()
                        .collect();
                    if first_guards.is_subset(&second_guards)
                        || second_guards.is_subset(&first_guards)
                    {
                        return Err(invalid(format!(
                            "state {} event {event} has candidates {} and {} that one guard \
                             verdict can enable together",
                            raw.states[state.0 as usize].id,
                            transitions[first.0 as usize].def.id,
                            transitions[second.0 as usize].def.id,
                        )));
                    }
                }
            }
        }

        Ok(Self {
            model_id: raw.model_id,
            digest,
            initial_state,
            scope: raw.scope,
            actors: raw.actors,
            actor_platforms,
            states: raw.states,
            guards: raw.guards,
            actions: raw.actions,
            invariants: raw.invariants,
            transitions,
            state_index,
            guard_index,
            action_index,
            transition_index,
            candidates,
        })
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn digest(&self) -> &Hash256 {
        &self.digest
    }

    pub fn scope(&self) -> &serde_json::Value {
        &self.scope
    }

    pub fn initial_state(&self) -> StateId {
        self.initial_state
    }

    pub fn actors(&self) -> &[String] {
        &self.actors
    }

    pub fn actor_platforms(&self, actor: &str) -> Option<&BTreeSet<String>> {
        self.actor_platforms.get(actor)
    }

    pub fn state(&self, id: StateId) -> &StateDef {
        &self.states[id.0 as usize]
    }

    pub fn guard(&self, id: GuardId) -> &GuardDef {
        &self.guards[id.0 as usize]
    }

    pub fn action(&self, id: ActionId) -> &ActionDef {
        &self.actions[id.0 as usize]
    }

    pub fn transition(&self, id: TransitionId) -> &ResolvedTransition {
        &self.transitions[id.0 as usize]
    }

    pub fn invariants(&self) -> &[InvariantDef] {
        &self.invariants
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn state_ids(&self) -> impl Iterator<Item = StateId> + '_ {
        (0..self.states.len()).map(|position| StateId(position as u16))
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    pub fn state_id(&self, id: &str) -> Option<StateId> {
        self.state_index.get(id).copied()
    }

    pub fn guard_id(&self, id: &str) -> Option<GuardId> {
        self.guard_index.get(id).copied()
    }

    pub fn action_id(&self, id: &str) -> Option<ActionId> {
        self.action_index.get(id).copied()
    }

    pub fn transition_id(&self, id: &str) -> Option<TransitionId> {
        self.transition_index.get(id).copied()
    }

    pub fn transition_ids(&self) -> impl Iterator<Item = TransitionId> + '_ {
        (0..self.transitions.len()).map(|position| TransitionId(position as u16))
    }

    pub fn guard_ids(&self) -> impl Iterator<Item = GuardId> + '_ {
        (0..self.guards.len()).map(|position| GuardId(position as u16))
    }

    pub fn action_ids(&self) -> impl Iterator<Item = ActionId> + '_ {
        (0..self.actions.len()).map(|position| ActionId(position as u16))
    }

    /// Transitions leaving `from` on `event`, in declaration order.
    pub fn candidates(&self, from: StateId, event: &str) -> &[TransitionId] {
        self.candidates
            .get(&(from, event.to_owned()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether a transition contains a mutating action.
    pub fn is_mutating(&self, id: TransitionId) -> bool {
        self.transitions[id.0 as usize]
            .actions
            .iter()
            .any(|action| MUTATING_RISKS.contains(&self.actions[action.0 as usize].risk))
    }

    /// Select the unique enabled candidate for `(from, event)` given one
    /// consistent set of satisfied guards, failing closed on zero or several.
    pub fn select_enabled(
        &self,
        from: StateId,
        event: &str,
        satisfied: &BTreeSet<GuardId>,
    ) -> Result<TransitionId, SelectionError> {
        let mut enabled = self
            .candidates(from, event)
            .iter()
            .copied()
            .filter(|id| {
                self.transitions[id.0 as usize]
                    .guards
                    .iter()
                    .all(|guard| satisfied.contains(guard))
            })
            .collect::<Vec<_>>();
        match enabled.len() {
            1 => Ok(enabled.remove(0)),
            0 => Err(SelectionError::NoneEnabled),
            _ => Err(SelectionError::Ambiguous(enabled)),
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum SelectionError {
    #[error("no candidate transition is enabled")]
    NoneEnabled,
    #[error("multiple candidate transitions are enabled simultaneously")]
    Ambiguous(Vec<TransitionId>),
}

fn intern<'a>(
    kind: &str,
    ids: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, u16>, String> {
    let mut index = BTreeMap::new();
    for (position, id) in ids.enumerate() {
        if id.is_empty() {
            return Err(format!("{kind} at position {position} has an empty id"));
        }
        let position =
            u16::try_from(position).map_err(|_| format!("too many {kind} definitions"))?;
        if index.insert(id.to_owned(), position).is_some() {
            return Err(format!("duplicate {kind} id: {id}"));
        }
    }
    Ok(index)
}
