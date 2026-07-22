//! Strictly parsed executable trace scenarios.

use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    #[default]
    Success,
    Failure,
    InterruptedPrecondition,
    InterruptedPostcondition,
    InterruptedDivergent,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredStep {
    pub transition: String,
    #[serde(default)]
    pub outcome: StepOutcome,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum TraceStep {
    Simple(String),
    Structured(StructuredStep),
}

impl TraceStep {
    pub fn transition(&self) -> &str {
        match self {
            Self::Simple(transition) => transition,
            Self::Structured(step) => &step.transition,
        }
    }

    pub fn outcome(&self) -> StepOutcome {
        match self {
            Self::Simple(_) => StepOutcome::Success,
            Self::Structured(step) => step.outcome.clone(),
        }
    }
}

/// One abstract scenario trace, exactly as stored under `installer/traces/`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub id: String,
    pub description: String,
    pub expected_terminal: String,
    pub steps: Vec<TraceStep>,
}

#[derive(Debug, Error)]
pub enum TraceParseError {
    #[error("trace is not valid strict JSON: {0}")]
    Parse(String),
}

pub fn parse_trace(bytes: &[u8]) -> Result<Trace, TraceParseError> {
    serde_json::from_slice(bytes).map_err(|error| TraceParseError::Parse(error.to_string()))
}
