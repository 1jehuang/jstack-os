use serde::Deserialize;
use thiserror::Error;

pub const EXECUTABLE_STATE_MODEL_ID: &str = "jstack-no-usb-dual-boot-v1";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StateGraphIdentityError {
    #[error("state graph is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("state graph model_id must be a nonempty string")]
    MissingModelId,
    #[error("state graph model_id {actual:?} does not match executable model {expected:?}")]
    UnexpectedModelId {
        expected: &'static str,
        actual: String,
    },
}

#[derive(Deserialize)]
struct StateGraphHeader {
    model_id: String,
}

pub fn executable_state_model_id(state_graph: &[u8]) -> Result<String, StateGraphIdentityError> {
    let header: StateGraphHeader = serde_json::from_slice(state_graph)
        .map_err(|error| StateGraphIdentityError::InvalidJson(error.to_string()))?;
    if header.model_id.is_empty() {
        return Err(StateGraphIdentityError::MissingModelId);
    }
    if header.model_id != EXECUTABLE_STATE_MODEL_ID {
        return Err(StateGraphIdentityError::UnexpectedModelId {
            expected: EXECUTABLE_STATE_MODEL_ID,
            actual: header.model_id,
        });
    }
    Ok(header.model_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_graph_model_id_is_exact() {
        let graph = include_bytes!("../../model/installer-state-graph.json");
        assert_eq!(
            executable_state_model_id(graph).unwrap(),
            EXECUTABLE_STATE_MODEL_ID
        );
    }

    #[test]
    fn generator_binding_rejects_model_id_drift() {
        let error =
            executable_state_model_id(br#"{"model_id":"jstack-installer-v1"}"#).unwrap_err();
        assert_eq!(
            error,
            StateGraphIdentityError::UnexpectedModelId {
                expected: EXECUTABLE_STATE_MODEL_ID,
                actual: "jstack-installer-v1".to_owned(),
            }
        );
    }
}
