//! PH-03 restart-safe controller execution and PH-04 verified failure admission.
//!
//! The runtime executes graph transitions through a *sealed* effect boundary.
//! [`EffectBoundary`] is a private-constructor wrapper: the only way to obtain
//! one is [`EffectBoundary::virtual_platform`], which binds it to an in-memory
//! [`VirtualPlatform`]. There is no production constructor, so a caller cannot
//! reach a real disk, firmware variable, or filesystem through this module.
//!
//! The execution protocol is exactly the one in `ARCHITECTURE.md`:
//!
//! 1. validate the source state and observe all preconditions,
//! 2. append and flush `action_intent`,
//! 3. execute the action,
//! 4. observe postconditions independently,
//! 5. append and flush `action_committed`,
//! 6. append `state_advanced` and advance the durable control state.
//!
//! Every step boundary is a *durable boundary*. [`Runtime::resume`] derives its
//! disposition purely from the journal, so a crash at any boundary converges to
//! the same control state as an uninterrupted run, or to the transition's exact
//! graph failure state with a recomputed no-committed-effect proof.

use jstack_installer_core::{
    CONTRACT_SCHEMA_VERSION, FailureClass, FailureEvidence, Hash256, InstallPlan, JournalRecord,
    JournalRecordType, canonical_sha256, control_state_hash, create_action_failed_record,
    create_failure_evidence, hash_journal_record, validate_journal_record,
};
use thiserror::Error;

use crate::platform::{PlatformError, RunningSystem, VirtualPlatform};
use crate::{
    DirectOutcome, GraphModel, JournalDisposition, ReplayError, StateId, TransitionId,
    create_direct_state_advanced, create_pending_state_advanced, derive_disposition,
};

/// A sealed boundary between the controller and platform effects.
///
/// The inner enum is private and has exactly one variant. Adding a production
/// variant would require editing this file, which is the point: the type system
/// records that no production mutation path exists yet.
#[derive(Debug)]
pub struct EffectBoundary {
    inner: BoundaryKind,
}

#[derive(Debug)]
enum BoundaryKind {
    /// A fully in-memory machine. No syscall, path, or device is reachable.
    Virtual(VirtualPlatform),
}

impl EffectBoundary {
    /// The only constructor. It consumes an in-memory platform, so an
    /// `EffectBoundary` can never denote real hardware.
    pub fn virtual_platform(platform: VirtualPlatform) -> Self {
        Self {
            inner: BoundaryKind::Virtual(platform),
        }
    }

    pub fn platform(&self) -> &VirtualPlatform {
        match &self.inner {
            BoundaryKind::Virtual(platform) => platform,
        }
    }

    pub fn platform_mut(&mut self) -> &mut VirtualPlatform {
        match &mut self.inner {
            BoundaryKind::Virtual(platform) => platform,
        }
    }

    fn observe_all(&self, conditions: &[String]) -> Result<(), PlatformError> {
        self.platform().require_all(conditions)
    }

    fn apply(&mut self, action: &str) -> Result<(), PlatformError> {
        self.platform_mut().apply(action)
    }
}

/// How a single execution attempt ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepResult {
    /// The transition committed and the control state advanced.
    Committed,
    /// The action failed with a verified no-committed-effect proof, and the
    /// control state advanced to the transition's exact graph failure state.
    FailedForward,
    /// Effects survived a failure, so automatic mutation stopped for manual
    /// recovery rather than forging a failure proof.
    HaltedForManualRecovery,
}

/// Where a simulated crash interrupts the protocol. Every variant is a durable
/// boundary in the six-step sequence above.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CrashPoint {
    /// Before anything is written. The journal is untouched.
    BeforeIntent,
    /// After `action_intent` is durable, before the action runs.
    AfterIntent,
    /// After the action ran, before `action_committed` is durable.
    AfterEffect,
    /// After `action_committed` is durable, before `state_advanced`.
    AfterCommit,
    /// After `state_advanced` is durable. The transition is complete.
    AfterAdvance,
}

impl CrashPoint {
    pub const ALL: [Self; 5] = [
        Self::BeforeIntent,
        Self::AfterIntent,
        Self::AfterEffect,
        Self::AfterCommit,
        Self::AfterAdvance,
    ];
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("journal replay rejected the durable state: {0}")]
    Replay(#[from] ReplayError),
    #[error("journal record could not be constructed: {0}")]
    Integrity(#[from] jstack_installer_core::IntegrityError),
    #[error("virtual platform rejected the step: {0}")]
    Platform(#[from] PlatformError),
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] jstack_installer_core::canonical::CanonicalError),
    #[error("transition {transition} is not adjacent to durable state {state}")]
    NonAdjacent { state: String, transition: String },
    #[error("transition {0} is mutating and cannot be run as a direct advance")]
    MutatingTransition(String),
    #[error("transition {0} is non-mutating and cannot be run as a mutating step")]
    NonMutatingTransition(String),
    #[error("the durable journal is mid-transition; resume before starting {0}")]
    NotQuiescent(String),
    #[error("transition {0} declares no graph failure edge, so it cannot fail forward")]
    NoFailureEdge(String),
}

/// A restart-safe execution engine over one confirmed plan and one sealed
/// effect boundary.
///
/// The runtime owns no durable storage of its own. The journal is passed in and
/// out explicitly so a test, a crash campaign, or a real durable log can supply
/// it, and so `resume` is provably a pure function of the journal.
#[derive(Debug)]
pub struct Runtime<'graph> {
    graph: &'graph GraphModel,
    plan_hash: Hash256,
    journal: Vec<JournalRecord>,
    failure_evidence: Vec<FailureEvidence>,
    boundary: EffectBoundary,
}

impl<'graph> Runtime<'graph> {
    pub fn new(graph: &'graph GraphModel, plan: &InstallPlan, boundary: EffectBoundary) -> Self {
        Self {
            graph,
            plan_hash: plan.plan_hash.clone(),
            journal: Vec::new(),
            failure_evidence: Vec::new(),
            boundary,
        }
    }

    /// Rebuild a runtime from a durable journal after a restart. Nothing is
    /// carried over from the previous process except the records themselves.
    pub fn restore(
        graph: &'graph GraphModel,
        plan: &InstallPlan,
        boundary: EffectBoundary,
        journal: Vec<JournalRecord>,
        failure_evidence: Vec<FailureEvidence>,
    ) -> Self {
        Self {
            graph,
            plan_hash: plan.plan_hash.clone(),
            journal,
            failure_evidence,
            boundary,
        }
    }

    pub fn journal(&self) -> &[JournalRecord] {
        &self.journal
    }

    pub fn failure_evidence(&self) -> &[FailureEvidence] {
        &self.failure_evidence
    }

    pub fn boundary(&self) -> &EffectBoundary {
        &self.boundary
    }

    pub fn boundary_mut(&mut self) -> &mut EffectBoundary {
        &mut self.boundary
    }

    pub fn into_parts(self) -> (Vec<JournalRecord>, Vec<FailureEvidence>, EffectBoundary) {
        (self.journal, self.failure_evidence, self.boundary)
    }

    /// The disposition derived purely from the durable journal.
    pub fn disposition(&self) -> Result<JournalDisposition, RuntimeError> {
        Ok(derive_disposition(
            self.graph,
            &self.plan_hash,
            &self.journal,
            &self.failure_evidence,
        )?)
    }

    /// The durable control state.
    pub fn state(&self) -> Result<StateId, RuntimeError> {
        Ok(self.disposition()?.state())
    }

    /// Run one non-mutating transition as a single durable `state_advanced`.
    ///
    /// Non-mutating transitions may still carry read-only or external-I/O
    /// actions (inventory collection, manifest verification, handoff checks).
    /// Those run through the same sealed boundary; they simply need no
    /// intent/commit triad because they cannot leave a partial durable effect.
    pub fn advance_direct(
        &mut self,
        transition: TransitionId,
        outcome: DirectOutcome,
    ) -> Result<StepResult, RuntimeError> {
        if self.graph.is_mutating(transition) {
            return Err(RuntimeError::MutatingTransition(
                self.graph.transition(transition).def.id.clone(),
            ));
        }
        if outcome == DirectOutcome::Success {
            let definition = self.graph.transition(transition).def.clone();
            self.boundary.observe_all(&definition.preconditions)?;
            self.execute_actions(&definition.actions, None)?;
            self.boundary
                .observe_all(&definition.postconditions)
                .map_err(|error| match error {
                    PlatformError::PreconditionFailed(condition) => {
                        PlatformError::PostconditionFailed(condition, definition.id.clone())
                    }
                    other => other,
                })?;
        }
        let record = create_direct_state_advanced(
            self.graph,
            &self.plan_hash,
            &self.journal,
            &self.failure_evidence,
            transition,
            outcome,
        )?;
        self.journal.push(record);
        Ok(match outcome {
            DirectOutcome::Success => StepResult::Committed,
            DirectOutcome::Failure => StepResult::FailedForward,
        })
    }

    /// Execute one mutating transition through the full six-step protocol.
    ///
    /// `crash_at` interrupts execution at a durable boundary and returns
    /// immediately, leaving exactly the records that a real power loss at that
    /// point would have left behind.
    pub fn step(
        &mut self,
        transition: TransitionId,
        fault: Option<InjectedFault>,
        crash_at: Option<CrashPoint>,
    ) -> Result<Option<StepResult>, RuntimeError> {
        let state = match self.disposition()? {
            JournalDisposition::Quiescent { state } => state,
            _ => {
                return Err(RuntimeError::NotQuiescent(
                    self.graph.transition(transition).def.id.clone(),
                ));
            }
        };
        self.require_adjacent(state, transition)?;
        if !self.graph.is_mutating(transition) {
            return Err(RuntimeError::NonMutatingTransition(
                self.graph.transition(transition).def.id.clone(),
            ));
        }

        // Step 1: observe every declared precondition through the boundary.
        let definition = self.graph.transition(transition).def.clone();
        self.boundary.observe_all(&definition.preconditions)?;

        if crash_at == Some(CrashPoint::BeforeIntent) {
            return Ok(None);
        }

        // Step 2: durable intent.
        let intent = self.create_intent(state, transition)?;
        self.journal.push(intent);

        if crash_at == Some(CrashPoint::AfterIntent) {
            return Ok(None);
        }

        // Step 3: execute, honoring an injected fault.
        let outcome = self.execute_actions(&definition.actions, fault);

        if crash_at == Some(CrashPoint::AfterEffect) {
            return Ok(None);
        }

        // Step 4: observe postconditions independently of the executor's own
        // return value. An executor that lies about success is caught here.
        let postconditions_hold = outcome.is_ok()
            && self
                .boundary
                .observe_all(&definition.postconditions)
                .is_ok();

        if !postconditions_hold {
            return self.admit_failure(transition, crash_at);
        }

        // Step 5: durable commit.
        let commit = self.create_commit(transition)?;
        self.journal.push(commit);

        if crash_at == Some(CrashPoint::AfterCommit) {
            return Ok(None);
        }

        // Step 6: durable advance.
        self.advance_pending()?;
        Ok(Some(StepResult::Committed))
    }

    /// PH-04: admit a failure only with a recomputed no-committed-effect proof.
    ///
    /// The proof is derived from the platform's own residual-object observation
    /// rather than supplied by the caller, and the failure target is read from
    /// the graph rather than chosen. If effects survived, the runtime halts for
    /// manual recovery instead of forging a proof.
    fn admit_failure(
        &mut self,
        transition: TransitionId,
        crash_at: Option<CrashPoint>,
    ) -> Result<Option<StepResult>, RuntimeError> {
        let residual = self.boundary.platform().residual_objects();
        let before = self.residual_before_intent()?;
        // Any object created by this attempt and still present is a committed
        // effect. Objects that predate the attempt are not.
        let new_effects: Vec<_> = residual
            .iter()
            .filter(|object| !before.contains(object))
            .cloned()
            .collect();
        if !new_effects.is_empty() {
            return Ok(Some(StepResult::HaltedForManualRecovery));
        }

        let failure_state = self
            .graph
            .transition(transition)
            .failure_to
            .map(|state| self.graph.state(state).id.clone())
            .ok_or_else(|| {
                RuntimeError::NoFailureEdge(self.graph.transition(transition).def.id.clone())
            })?;

        let intent = self
            .journal
            .last()
            .cloned()
            .ok_or_else(|| RuntimeError::NotQuiescent(failure_state.clone()))?;
        // The proof is a digest over the observed machine plus the exact intent
        // record. It is recomputed here, never accepted from a caller.
        let no_committed_effect_hash = canonical_sha256(&(
            "jstack.no-committed-effect.v1",
            self.boundary.platform().digest(),
            hash_journal_record(&intent)?,
        ))?;
        let evidence = create_failure_evidence(
            &intent,
            self.graph.model_id(),
            failure_state,
            FailureClass::ExecutorFailed,
            no_committed_effect_hash,
            Vec::new(),
        )?;
        let record = create_action_failed_record(&intent, &evidence)?;
        self.failure_evidence.push(evidence);
        self.journal.push(record);

        if crash_at == Some(CrashPoint::AfterCommit) {
            return Ok(None);
        }

        self.advance_pending()?;
        Ok(Some(StepResult::FailedForward))
    }

    /// Residual objects that already existed when the current attempt started.
    /// Derived from the journal, not remembered in memory, so it survives a
    /// restart.
    fn residual_before_intent(
        &self,
    ) -> Result<Vec<jstack_installer_core::RollbackObject>, RuntimeError> {
        let mut objects = Vec::new();
        for record in &self.journal {
            if record.record_type == JournalRecordType::ActionCommitted {
                for object in &record.created_objects {
                    if !objects.contains(object) {
                        objects.push(object.clone());
                    }
                }
            }
        }
        Ok(objects)
    }

    /// Resume after a restart. This is a pure function of the durable journal:
    /// it re-derives the disposition and finishes whatever the crash
    /// interrupted, with no in-memory carryover.
    pub fn resume(&mut self) -> Result<StepResult, RuntimeError> {
        match self.disposition()? {
            JournalDisposition::Quiescent { .. } => Ok(StepResult::Committed),
            JournalDisposition::ActionPending { transition, .. } => {
                // The intent is durable but the outcome is unknown. Observe the
                // machine: if postconditions already hold, the effect survived
                // the crash and the missing commit is synthesized. Otherwise the
                // idempotent action is retried, and only a genuine failure with
                // no surviving effect is admitted.
                let definition = self.graph.transition(transition).def.clone();
                if self
                    .boundary
                    .observe_all(&definition.postconditions)
                    .is_err()
                {
                    if self.boundary.observe_all(&definition.preconditions).is_ok() {
                        let _ = self.execute_actions(&definition.actions, None);
                    }
                    if self
                        .boundary
                        .observe_all(&definition.postconditions)
                        .is_err()
                    {
                        return Ok(self
                            .admit_failure(transition, None)?
                            .unwrap_or(StepResult::HaltedForManualRecovery));
                    }
                }
                let commit = self.create_commit(transition)?;
                self.journal.push(commit);
                self.advance_pending()?;
                Ok(StepResult::Committed)
            }
            JournalDisposition::CommitAdvancePending { .. } => {
                self.advance_pending()?;
                Ok(StepResult::Committed)
            }
            JournalDisposition::FailureAdvancePending { .. } => {
                self.advance_pending()?;
                Ok(StepResult::FailedForward)
            }
        }
    }

    /// Complete a reboot by observing which system actually came up.
    pub fn observe_boot(&mut self, system: RunningSystem) -> Result<(), RuntimeError> {
        self.boundary.platform_mut().observe_boot(system)?;
        Ok(())
    }

    fn execute_actions(
        &mut self,
        actions: &[String],
        fault: Option<InjectedFault>,
    ) -> Result<(), PlatformError> {
        if fault == Some(InjectedFault::ClaimSuccessWithoutEffect) {
            // The executor returns success having done nothing. The runtime
            // must not believe it.
            return Ok(());
        }
        for (index, action) in actions.iter().enumerate() {
            if fault
                == Some(InjectedFault::StopBefore {
                    action_index: index,
                })
            {
                return Err(PlatformError::IllegalAction {
                    action: action.clone(),
                    reason: "an injected fault stopped execution".to_owned(),
                });
            }
            self.boundary.apply(action)?;
        }
        if fault == Some(InjectedFault::FailAfterEffect) {
            return Err(PlatformError::IllegalAction {
                action: actions.last().cloned().unwrap_or_default(),
                reason: "an injected fault failed after the effect landed".to_owned(),
            });
        }
        Ok(())
    }

    fn create_intent(
        &self,
        state: StateId,
        transition: TransitionId,
    ) -> Result<JournalRecord, RuntimeError> {
        let definition = &self.graph.transition(transition).def;
        let previous = self.journal.last();
        let record = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: previous.map_or(0, |record| record.sequence + 1),
            previous_record_hash: previous.map(hash_journal_record).transpose()?,
            actor: definition.actor.clone(),
            transition_id: definition.id.clone(),
            record_type: JournalRecordType::ActionIntent,
            precondition_hash: control_state_hash(&self.graph.state(state).id)?,
            postcondition_hash: None,
            plan_hash: self.plan_hash.clone(),
            created_objects: Vec::new(),
        };
        validate_journal_record(&record, previous)?;
        Ok(record)
    }

    fn create_commit(&self, transition: TransitionId) -> Result<JournalRecord, RuntimeError> {
        let definition = &self.graph.transition(transition).def;
        let previous = self
            .journal
            .last()
            .ok_or_else(|| RuntimeError::NotQuiescent(definition.id.clone()))?;
        // The commit's postcondition hash binds the observed machine, so a
        // commit cannot be replayed against a different machine state.
        let observed = canonical_sha256(&(
            "jstack.observed-postconditions.v1",
            self.boundary.platform().digest(),
            definition.id.as_str(),
        ))?;
        let record = JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: previous.sequence + 1,
            previous_record_hash: Some(hash_journal_record(previous)?),
            actor: definition.actor.clone(),
            transition_id: definition.id.clone(),
            record_type: JournalRecordType::ActionCommitted,
            precondition_hash: previous.precondition_hash.clone(),
            postcondition_hash: Some(observed),
            plan_hash: self.plan_hash.clone(),
            created_objects: self.created_objects(transition),
        };
        validate_journal_record(&record, Some(previous))?;
        Ok(record)
    }

    /// Objects this transition brought into existence, recorded so that a later
    /// failure can distinguish a surviving committed effect from a clean abort.
    fn created_objects(
        &self,
        transition: TransitionId,
    ) -> Vec<jstack_installer_core::RollbackObject> {
        let definition = &self.graph.transition(transition).def;
        let creates = definition.actions.iter().any(|action| {
            matches!(
                action.as_str(),
                "create_xbootldr_partition"
                    | "create_root_partition"
                    | "stage_namespaced_esp_loader"
                    | "create_installer_boot_entry"
                    | "install_jstack_boot_artifacts"
                    | "register_windows_finalizer"
            )
        });
        if !creates {
            return Vec::new();
        }
        self.boundary.platform().residual_objects()
    }

    fn advance_pending(&mut self) -> Result<(), RuntimeError> {
        let record = create_pending_state_advanced(
            self.graph,
            &self.plan_hash,
            &self.journal,
            &self.failure_evidence,
        )?;
        self.journal.push(record);
        Ok(())
    }

    fn require_adjacent(
        &self,
        state: StateId,
        transition: TransitionId,
    ) -> Result<(), RuntimeError> {
        let resolved = self.graph.transition(transition);
        if resolved.from != state {
            return Err(RuntimeError::NonAdjacent {
                state: self.graph.state(state).id.clone(),
                transition: resolved.def.id.clone(),
            });
        }
        Ok(())
    }
}

/// A deterministic fault injected into one execution attempt.
///
/// These model the three ways a real executor misbehaves: it stops early, it
/// claims success without doing the work, or it does part of the work and then
/// fails leaving a durable object behind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InjectedFault {
    /// Stop immediately before the action at this index runs, reporting an
    /// error. Nothing after that index executes.
    StopBefore { action_index: usize },
    /// Execute nothing but report success. This is a lying executor: only an
    /// independent postcondition observation can catch it.
    ClaimSuccessWithoutEffect,
    /// Execute every action, then report an error anyway. The effects are real
    /// and durable, so a failure proof would be a forgery.
    FailAfterEffect,
}

impl InjectedFault {
    pub fn before_first_action() -> Self {
        Self::StopBefore { action_index: 0 }
    }
}
