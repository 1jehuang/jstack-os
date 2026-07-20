use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::Hash256;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to serialize canonical JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("floating-point values are forbidden in canonical installer data")]
    FloatingPoint,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<Hash256, CanonicalError> {
    let bytes = canonical_json(value)?;
    let digest = Sha256::digest(bytes);
    Ok(Hash256::from_bytes(digest.into()))
}

fn reject_floats(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Number(number) if number.is_f64() => Err(CanonicalError::FloatingPoint),
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn canonical_json_is_compact_and_key_sorted() {
        let value = BTreeMap::from([("z", 1_u64), ("a", 2_u64)]);
        assert_eq!(canonical_json(&value).unwrap(), br#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canonical_json_rejects_floats() {
        assert!(matches!(
            canonical_json(&1.5_f64),
            Err(CanonicalError::FloatingPoint)
        ));
    }
}
