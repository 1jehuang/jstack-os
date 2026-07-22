//! Pure control-state simulator over the verified graph.
//!
//! This mirrors the Python `simulate_trace` semantics exactly: success takes
//! the transition target, failure takes `failure_to`, and interruption of a
//! mutating transition reconciles from an independently observed disk state.
//! No side effects and no platform access exist here.

use thiserror::Error;

use crate::graph::{GraphModel, StateId, StateKind, TerminalOutcome, TransitionId};
use crate::trace::{StepOutcome, Trace};

/// An independently observed reconciliation result for a pending mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationObservation {
    /// Preconditions still hold: the mutation did not take effect.
    Precondition,
    /// Postconditions hold: the mutation completed before the interruption.
    Postcondition,
    /// Neither holds: automatic mutation must stop on the failure route.
    Divergent,
}

#[derive(Debug, Error, PartialEq)]
pub enum SimulationError {
    #[error("step {step}: unknown transition {transition}")]
    UnknownTransition { step: usize, transition: String },
    #[error("step {step}: transition {transition} starts at {expected}, not {actual}")]
    SourceMismatch {
        step: usize,
        transition: String,
        expected: String,
        actual: String,
    },
    #[error("step {step}: cannot interrupt non-mutating transition {transition}")]
    InterruptedNonMutating { step: usize, transition: String },
    #[error("step {step}: transition {transition} has no failure route")]
    MissingFailureRoute { step: usize, transition: String },
    #[error("trace ended in nonterminal state {state}")]
    NonterminalEnd { state: String },
    #[error("trace reached {actual}, expected {expected}")]
    TerminalMismatch { expected: String, actual: String },
}

/// The pure state-advance rule shared by the simulator and, later, the
/// journal-backed controller.
pub fn apply_step(
    model: &GraphModel,
    transition: TransitionId,
    outcome: &StepOutcome,
) -> Result<StateId, ApplyError> {
    let resolved = model.transition(transition);
    match outcome {
        StepOutcome::Success => Ok(resolved.to),
        StepOutcome::Failure => resolved.failure_to.ok_or(ApplyError::MissingFailureRoute),
        StepOutcome::InterruptedPrecondition => {
            reconcile_interruption(model, transition, MutationObservation::Precondition)
        }
        StepOutcome::InterruptedPostcondition => {
            reconcile_interruption(model, transition, MutationObservation::Postcondition)
        }
        StepOutcome::InterruptedDivergent => {
            reconcile_interruption(model, transition, MutationObservation::Divergent)
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum ApplyError {
    #[error("transition has no failure route")]
    MissingFailureRoute,
    #[error("cannot reconcile a non-mutating transition")]
    NonMutating,
}

/// Resolve an interrupted mutation from an independent observation, exactly
/// like the semantic validator's `reconcile_interruption`.
pub fn reconcile_interruption(
    model: &GraphModel,
    transition: TransitionId,
    observed: MutationObservation,
) -> Result<StateId, ApplyError> {
    if !model.is_mutating(transition) {
        return Err(ApplyError::NonMutating);
    }
    let resolved = model.transition(transition);
    match observed {
        MutationObservation::Precondition => Ok(resolved.from),
        MutationObservation::Postcondition => Ok(resolved.to),
        MutationObservation::Divergent => {
            resolved.failure_to.ok_or(ApplyError::MissingFailureRoute)
        }
    }
}

/// Replay a trace from the initial state and return the reached state.
pub fn simulate_steps(model: &GraphModel, trace: &Trace) -> Result<StateId, SimulationError> {
    let mut current = model.initial_state();
    for (step, raw) in trace.steps.iter().enumerate() {
        let transition_name = raw.transition();
        let transition = model.transition_id(transition_name).ok_or_else(|| {
            SimulationError::UnknownTransition {
                step,
                transition: transition_name.to_owned(),
            }
        })?;
        let resolved = model.transition(transition);
        if resolved.from != current {
            return Err(SimulationError::SourceMismatch {
                step,
                transition: transition_name.to_owned(),
                expected: model.state(current).id.clone(),
                actual: model.state(resolved.from).id.clone(),
            });
        }
        let outcome = raw.outcome();
        if matches!(
            outcome,
            StepOutcome::InterruptedPrecondition
                | StepOutcome::InterruptedPostcondition
                | StepOutcome::InterruptedDivergent
        ) && !model.is_mutating(transition)
        {
            return Err(SimulationError::InterruptedNonMutating {
                step,
                transition: transition_name.to_owned(),
            });
        }
        current = apply_step(model, transition, &outcome).map_err(|error| match error {
            ApplyError::MissingFailureRoute => SimulationError::MissingFailureRoute {
                step,
                transition: transition_name.to_owned(),
            },
            ApplyError::NonMutating => SimulationError::InterruptedNonMutating {
                step,
                transition: transition_name.to_owned(),
            },
        })?;
    }
    Ok(current)
}

/// Replay a trace and require it to end in its declared expected terminal.
pub fn simulate_to_terminal(
    model: &GraphModel,
    trace: &Trace,
) -> Result<TerminalOutcome, SimulationError> {
    let reached = simulate_steps(model, trace)?;
    let state = model.state(reached);
    if state.kind != StateKind::Terminal {
        return Err(SimulationError::NonterminalEnd {
            state: state.id.clone(),
        });
    }
    if state.id != trace.expected_terminal {
        return Err(SimulationError::TerminalMismatch {
            expected: trace.expected_terminal.clone(),
            actual: state.id.clone(),
        });
    }
    Ok(state
        .terminal_outcome
        .expect("verified terminal states always declare an outcome"))
}
