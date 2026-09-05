use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub const PLAN_SCHEMA: &str = "ubuntu-whole-disk-plan-v1";
pub const GRAPH_ID: &str = "jstack-ubuntu-whole-disk-v1";
pub const GRAPH_SHA256: &str = "3c7cfc18ade7eb3810bd5e2fa68e5969ee82ef4adaf2d3785477d0ed50e922f4";
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableDiskIdentity {
    pub stable_serial: String,
    pub stable_wwn: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryIdentity {
    pub filesystem_uuid: String,
    pub backing_serial: String,
    pub backing_wwn: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactChunk {
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub sha256: String,
    pub size_bytes: u64,
    pub relative_store_path: PathBuf,
    pub chunks: Vec<ArtifactChunk>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub chunk_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBody {
    pub model_id: String,
    pub graph_digest: String,
    pub created_at_unix_ms: u64,
    pub target: StableDiskIdentity,
    pub recovery: RecoveryIdentity,
    pub artifact: ArtifactManifest,
    pub deployment: Deployment,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub exact_phrase: String,
    pub confirmed_plan_hash: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UbuntuPlan {
    pub schema_version: String,
    pub plan_hash: String,
    pub body: PlanBody,
    pub confirmation: Confirmation,
}

impl UbuntuPlan {
    pub fn body_digest(&self) -> Result<String, serde_json::Error> {
        Ok(hex(&Sha256::digest(serde_json::to_vec(&self.body)?)))
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != PLAN_SCHEMA
            || self.body.model_id != GRAPH_ID
            || self.body.graph_digest != GRAPH_SHA256
        {
            return Err("plan graph/schema identity is not pinned".into());
        }
        let t = &self.body.target;
        let r = &self.body.recovery;
        let a = &self.body.artifact;
        if t.stable_serial.trim().is_empty()
            || r.filesystem_uuid.trim().is_empty()
            || r.backing_serial.trim().is_empty()
        {
            return Err("stable target and recovery identities must be complete".into());
        }
        if t.stable_serial == r.backing_serial
            || (t.stable_wwn.is_some() && t.stable_wwn == r.backing_wwn)
        {
            return Err("target and recovery disk are not separate".into());
        }
        if t.size_bytes == 0
            || t.logical_sector_bytes == 0
            || a.size_bytes == 0
            || a.size_bytes != t.size_bytes
            || self.body.deployment.chunk_bytes == 0
        {
            return Err("invalid target or artifact geometry".into());
        }
        if !is_hash(&a.sha256) || a.chunks.is_empty() {
            return Err("artifact digest manifest is malformed".into());
        }
        let mut next = 0;
        for chunk in &a.chunks {
            if chunk.offset != next
                || chunk.length == 0
                || chunk.length > self.body.deployment.chunk_bytes
                || !is_hash(&chunk.sha256)
            {
                return Err("chunk manifest is not contiguous and valid".into());
            }
            next = next.checked_add(chunk.length).ok_or("chunk overflow")?;
        }
        if next != a.size_bytes {
            return Err("chunk manifest does not cover artifact".into());
        }
        if a.relative_store_path.is_absolute()
            || a.relative_store_path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("artifact store path must be a simple relative path".into());
        }
        let digest = self.body_digest().map_err(|e| e.to_string())?;
        if self.plan_hash != digest
            || self.confirmation.confirmed_plan_hash != digest
            || self.confirmation.exact_phrase != format!("ERASE {}", t.stable_serial)
        {
            return Err("exact plan authorization does not match".into());
        }
        Ok(())
    }
    pub fn artifact_path(&self, state_dir: &Path) -> PathBuf {
        state_dir.join(&self.body.artifact.relative_store_path)
    }
}
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
pub fn is_hash(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
