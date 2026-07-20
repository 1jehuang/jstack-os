use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical::{CanonicalError, canonical_json};
use crate::model::{Architecture, CONTRACT_SCHEMA_VERSION, Hash256, ReleaseRequirements};

pub const RELEASE_SIGNATURE_DOMAIN: &[u8] = b"JSTACK-RELEASE-MANIFEST-V1\0";
pub const RELEASE_PRODUCT: &str = "jstack-os";
pub const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const CONTRACT_MAX_SIGNATURES: usize = 16;
const CONTRACT_MAX_CHUNKS_PER_ARTIFACT: usize = 4_096;

const REQUIRED_ARTIFACT_ROLES: [ArtifactRole; 4] = [
    ArtifactRole::EspLoader,
    ArtifactRole::InstallerUki,
    ArtifactRole::OfflineSystemImage,
    ArtifactRole::RecoveryUki,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Beta,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    EspLoader,
    InstallerUki,
    OfflineSystemImage,
    RecoveryUki,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseManifest {
    pub signed: ReleaseManifestBody,
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestBody {
    pub schema_version: u32,
    pub product: String,
    pub release_id: String,
    pub release_version: String,
    pub release_sequence: u64,
    pub channel: ReleaseChannel,
    pub architecture: Architecture,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub state_model_id: String,
    pub state_model_sha256: Hash256,
    pub installer_protocol_min: u32,
    pub installer_protocol_max: u32,
    pub planner: PlannerRequirements,
    pub artifacts: Vec<ArtifactDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerRequirements {
    pub alignment_bytes: u64,
    pub xbootldr_size_bytes: u64,
    pub minimum_root_size_bytes: u64,
    pub safety_margin_bytes: u64,
    pub minimum_total_allocation_bytes: u64,
    pub esp_loader_required_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub role: ArtifactRole,
    pub size_bytes: u64,
    pub sha256: Hash256,
    pub chunk_size_bytes: u32,
    pub chunk_sha256: Vec<Hash256>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    pub key_id: Hash256,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAcceptanceState {
    pub schema_version: u32,
    pub channel: ReleaseChannel,
    pub state_model_sha256: Hash256,
    pub highest_sequence: u64,
    pub manifest_digest: Hash256,
    pub issued_at_unix_secs: u64,
    pub trusted_time_unix_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedReleaseKey {
    pub public_key: [u8; 32],
    pub channels: Vec<ReleaseChannel>,
}

impl TrustedReleaseKey {
    pub fn key_id(&self) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(self.public_key).into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseTrustPolicy {
    pub channel: ReleaseChannel,
    pub architecture: Architecture,
    pub state_model_id: String,
    pub state_model_sha256: Hash256,
    pub installer_protocol_version: u32,
    pub now_unix_secs: u64,
    pub maximum_future_skew_secs: u64,
    pub maximum_manifest_lifetime_secs: u64,
    pub maximum_manifest_bytes: usize,
    pub maximum_signatures: usize,
    pub maximum_artifacts: usize,
    pub maximum_chunks_per_artifact: usize,
    pub maximum_artifact_bytes: u64,
    pub maximum_chunk_size_bytes: u32,
    pub signature_threshold: usize,
    pub trusted_keys: Vec<TrustedReleaseKey>,
    pub previous_acceptance: Option<ReleaseAcceptanceState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseVerificationMode {
    Acquire,
    Resume { pinned_manifest_digest: Hash256 },
}

#[derive(Debug)]
pub struct PendingReleaseManifest {
    body: ReleaseManifestBody,
    manifest_digest: Hash256,
    expected_previous_acceptance: Option<ReleaseAcceptanceState>,
    required_acceptance: ReleaseAcceptanceState,
}

impl PendingReleaseManifest {
    pub fn required_acceptance(&self) -> &ReleaseAcceptanceState {
        &self.required_acceptance
    }

    pub fn expected_previous_acceptance(&self) -> Option<&ReleaseAcceptanceState> {
        self.expected_previous_acceptance.as_ref()
    }

    pub fn accept_after_persist(
        self,
        persisted_readback: &ReleaseAcceptanceState,
    ) -> Result<VerifiedReleaseManifest, ReleaseError> {
        if persisted_readback != &self.required_acceptance {
            return Err(ReleaseError::AcceptanceNotPersisted);
        }
        Ok(VerifiedReleaseManifest {
            body: self.body,
            manifest_digest: self.manifest_digest,
            acceptance: self.required_acceptance,
        })
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedReleaseManifest {
    body: ReleaseManifestBody,
    manifest_digest: Hash256,
    acceptance: ReleaseAcceptanceState,
}

impl VerifiedReleaseManifest {
    pub fn manifest_digest(&self) -> &Hash256 {
        &self.manifest_digest
    }

    pub fn acceptance(&self) -> &ReleaseAcceptanceState {
        &self.acceptance
    }

    fn release_requirements(&self) -> ReleaseRequirements {
        ReleaseRequirements {
            schema_version: CONTRACT_SCHEMA_VERSION,
            release_id: self.body.release_id.clone(),
            release_manifest_hash: self.manifest_digest.clone(),
            state_model_id: self.body.state_model_id.clone(),
            alignment_bytes: self.body.planner.alignment_bytes,
            xbootldr_size_bytes: self.body.planner.xbootldr_size_bytes,
            minimum_root_size_bytes: self.body.planner.minimum_root_size_bytes,
            safety_margin_bytes: self.body.planner.safety_margin_bytes,
            minimum_total_allocation_bytes: self.body.planner.minimum_total_allocation_bytes,
            esp_loader_required_bytes: self.body.planner.esp_loader_required_bytes,
        }
    }

    pub fn verified_release_requirements(&self) -> VerifiedReleaseRequirements {
        VerifiedReleaseRequirements(self.release_requirements())
    }

    pub fn artifact_descriptor(
        &self,
        role: ArtifactRole,
    ) -> Result<&ArtifactDescriptor, ReleaseError> {
        self.body
            .artifacts
            .iter()
            .find(|artifact| artifact.role == role)
            .ok_or(ReleaseError::MissingArtifactRole(role))
    }

    pub fn verify_artifact<R: Read>(
        &self,
        role: ArtifactRole,
        reader: &mut R,
    ) -> Result<VerifiedArtifact, ReleaseError> {
        let descriptor = self.artifact_descriptor(role)?;
        verify_artifact_stream(descriptor, reader, &mut std::io::sink())?;
        Ok(self.verified_artifact(descriptor))
    }

    pub fn copy_verified_artifact<R: Read, W: Write>(
        &self,
        role: ArtifactRole,
        reader: &mut R,
        destination: &mut W,
    ) -> Result<VerifiedArtifact, ReleaseError> {
        let descriptor = self.artifact_descriptor(role)?;
        verify_artifact_stream(descriptor, reader, destination)?;
        Ok(self.verified_artifact(descriptor))
    }

    fn verified_artifact(&self, descriptor: &ArtifactDescriptor) -> VerifiedArtifact {
        VerifiedArtifact {
            role: descriptor.role,
            size_bytes: descriptor.size_bytes,
            sha256: descriptor.sha256.clone(),
            manifest_digest: self.manifest_digest.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedReleaseRequirements(ReleaseRequirements);

impl VerifiedReleaseRequirements {
    pub(crate) fn as_requirements(&self) -> &ReleaseRequirements {
        &self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    role: ArtifactRole,
    size_bytes: u64,
    sha256: Hash256,
    manifest_digest: Hash256,
}

impl VerifiedArtifact {
    pub fn role(&self) -> ArtifactRole {
        self.role
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn sha256(&self) -> &Hash256 {
        &self.sha256
    }

    pub fn manifest_digest(&self) -> &Hash256 {
        &self.manifest_digest
    }
}

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("release manifest exceeds the configured byte limit")]
    ManifestTooLarge,
    #[error("release manifest JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("release manifest cannot be canonically serialized: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("release manifest bytes are not the unique canonical encoding")]
    NonCanonicalEnvelope,
    #[error("release trust policy is invalid: {0}")]
    InvalidPolicy(&'static str),
    #[error("release manifest contract is invalid: {0}")]
    InvalidManifest(&'static str),
    #[error("release manifest does not match immutable local policy: {0}")]
    BindingMismatch(&'static str),
    #[error("release manifest signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("release manifest contains a duplicate signature key id")]
    DuplicateSignatureKey,
    #[error(
        "release manifest has only {valid} valid trusted signatures, below threshold {required}"
    )]
    SignatureThreshold { valid: usize, required: usize },
    #[error("trusted clock moved behind the persisted time floor")]
    ClockRollback,
    #[error("release manifest is not yet valid")]
    IssuedInFuture,
    #[error("release manifest has expired")]
    Expired,
    #[error("release sequence is below the persisted acceptance floor")]
    Downgrade,
    #[error("a different manifest reused an already accepted release sequence")]
    Equivocation,
    #[error("resume is not bound to the persisted and pinned manifest")]
    InvalidResume,
    #[error("release acceptance state was not durably persisted and read back")]
    AcceptanceNotPersisted,
    #[error("release manifest is missing required artifact role {0:?}")]
    MissingArtifactRole(ArtifactRole),
    #[error("artifact {0:?} ended before its signed size")]
    ArtifactTruncated(ArtifactRole),
    #[error("artifact {0:?} contains bytes after its signed size")]
    ArtifactTrailingBytes(ArtifactRole),
    #[error("artifact {role:?} chunk {index} failed SHA-256 verification")]
    ArtifactChunkMismatch { role: ArtifactRole, index: usize },
    #[error("artifact {0:?} failed whole-file SHA-256 verification")]
    ArtifactDigestMismatch(ArtifactRole),
    #[error("artifact {role:?} read failed: {message}")]
    ArtifactIo { role: ArtifactRole, message: String },
}

pub fn verify_release_manifest(
    raw_envelope: &[u8],
    policy: &ReleaseTrustPolicy,
    mode: ReleaseVerificationMode,
) -> Result<PendingReleaseManifest, ReleaseError> {
    validate_policy(policy)?;
    if raw_envelope.len() > policy.maximum_manifest_bytes {
        return Err(ReleaseError::ManifestTooLarge);
    }

    let envelope: SignedReleaseManifest = serde_json::from_slice(raw_envelope)?;
    if canonical_json(&envelope)? != raw_envelope {
        return Err(ReleaseError::NonCanonicalEnvelope);
    }
    validate_body(&envelope.signed, policy)?;
    if envelope.signatures.len() > policy.maximum_signatures {
        return Err(ReleaseError::InvalidManifest(
            "signature count exceeds policy",
        ));
    }
    validate_signature_order(&envelope.signatures)?;

    let signed_bytes = signed_message(&envelope.signed)?;
    let manifest_digest = Hash256::from_bytes(Sha256::digest(&signed_bytes).into());
    verify_signatures(&envelope.signatures, &signed_bytes, policy)?;
    let required_acceptance = validate_ratchet(&envelope.signed, &manifest_digest, policy, mode)?;

    Ok(PendingReleaseManifest {
        body: envelope.signed,
        manifest_digest,
        expected_previous_acceptance: policy.previous_acceptance.clone(),
        required_acceptance,
    })
}

pub fn signed_message(body: &ReleaseManifestBody) -> Result<Vec<u8>, ReleaseError> {
    let canonical_body = canonical_json(body)?;
    let body_len = u64::try_from(canonical_body.len())
        .map_err(|_| ReleaseError::InvalidManifest("canonical body length overflow"))?;
    let mut message = Vec::with_capacity(
        RELEASE_SIGNATURE_DOMAIN.len() + std::mem::size_of::<u64>() + canonical_body.len(),
    );
    message.extend_from_slice(RELEASE_SIGNATURE_DOMAIN);
    message.extend_from_slice(&body_len.to_be_bytes());
    message.extend_from_slice(&canonical_body);
    Ok(message)
}

fn validate_policy(policy: &ReleaseTrustPolicy) -> Result<(), ReleaseError> {
    if policy.maximum_manifest_bytes == 0
        || policy.maximum_signatures == 0
        || policy.maximum_signatures > CONTRACT_MAX_SIGNATURES
        || policy.maximum_artifacts < REQUIRED_ARTIFACT_ROLES.len()
        || policy.maximum_chunks_per_artifact == 0
        || policy.maximum_chunks_per_artifact > CONTRACT_MAX_CHUNKS_PER_ARTIFACT
        || policy.maximum_artifact_bytes == 0
        || policy.maximum_chunk_size_bytes == 0
        || policy.maximum_manifest_lifetime_secs == 0
    {
        return Err(ReleaseError::InvalidPolicy(
            "resource limits must be positive",
        ));
    }
    if policy.signature_threshold == 0 {
        return Err(ReleaseError::InvalidPolicy(
            "signature threshold must be positive",
        ));
    }
    if policy.now_unix_secs > MAX_SAFE_JSON_INTEGER
        || policy.maximum_future_skew_secs > MAX_SAFE_JSON_INTEGER
        || policy.maximum_manifest_lifetime_secs > MAX_SAFE_JSON_INTEGER
        || policy.maximum_artifact_bytes > MAX_SAFE_JSON_INTEGER
    {
        return Err(ReleaseError::InvalidPolicy(
            "policy integer exceeds the interoperable safe bound",
        ));
    }
    validate_token(&policy.state_model_id, 128)
        .map_err(|_| ReleaseError::InvalidPolicy("state model id is invalid"))?;

    let mut keys = BTreeSet::new();
    let mut eligible = 0_usize;
    for key in &policy.trusted_keys {
        VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| ReleaseError::InvalidPolicy("trusted Ed25519 key is invalid"))?;
        if !keys.insert(key.key_id()) {
            return Err(ReleaseError::InvalidPolicy(
                "trusted key ids must be unique",
            ));
        }
        let channels: BTreeSet<_> = key.channels.iter().copied().collect();
        if channels.len() != key.channels.len() {
            return Err(ReleaseError::InvalidPolicy(
                "trusted key channels must be unique",
            ));
        }
        if channels.contains(&policy.channel) {
            eligible += 1;
        }
    }
    if policy.signature_threshold > eligible {
        return Err(ReleaseError::InvalidPolicy(
            "signature threshold exceeds eligible trusted keys",
        ));
    }
    if let Some(previous) = &policy.previous_acceptance {
        if previous.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ReleaseError::InvalidPolicy(
                "persisted acceptance schema version is unsupported",
            ));
        }
        if previous.channel != policy.channel
            || previous.state_model_sha256 != policy.state_model_sha256
        {
            return Err(ReleaseError::InvalidPolicy(
                "persisted acceptance belongs to another trust domain",
            ));
        }
        if previous.highest_sequence == 0
            || previous.highest_sequence > MAX_SAFE_JSON_INTEGER
            || previous.issued_at_unix_secs > MAX_SAFE_JSON_INTEGER
            || previous.trusted_time_unix_secs > MAX_SAFE_JSON_INTEGER
        {
            return Err(ReleaseError::InvalidPolicy(
                "persisted acceptance is outside safe integer bounds",
            ));
        }
        if policy.now_unix_secs < previous.trusted_time_unix_secs {
            return Err(ReleaseError::ClockRollback);
        }
    }
    Ok(())
}

fn validate_body(
    body: &ReleaseManifestBody,
    policy: &ReleaseTrustPolicy,
) -> Result<(), ReleaseError> {
    if body.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(ReleaseError::InvalidManifest("unsupported schema version"));
    }
    if body.product != RELEASE_PRODUCT {
        return Err(ReleaseError::BindingMismatch("product"));
    }
    validate_token(&body.release_id, 128)?;
    validate_token(&body.release_version, 64)?;
    validate_token(&body.state_model_id, 128)?;
    if body.release_sequence == 0 || body.release_sequence > MAX_SAFE_JSON_INTEGER {
        return Err(ReleaseError::InvalidManifest(
            "release sequence is out of bounds",
        ));
    }
    if body.issued_at_unix_secs > MAX_SAFE_JSON_INTEGER
        || body.expires_at_unix_secs > MAX_SAFE_JSON_INTEGER
        || body.expires_at_unix_secs <= body.issued_at_unix_secs
    {
        return Err(ReleaseError::InvalidManifest(
            "manifest validity interval is invalid",
        ));
    }
    let lifetime = body.expires_at_unix_secs - body.issued_at_unix_secs;
    if lifetime > policy.maximum_manifest_lifetime_secs {
        return Err(ReleaseError::InvalidManifest(
            "manifest lifetime exceeds policy",
        ));
    }
    if body.channel != policy.channel {
        return Err(ReleaseError::BindingMismatch("channel"));
    }
    if body.architecture != policy.architecture {
        return Err(ReleaseError::BindingMismatch("architecture"));
    }
    if body.state_model_id != policy.state_model_id
        || body.state_model_sha256 != policy.state_model_sha256
    {
        return Err(ReleaseError::BindingMismatch("state model"));
    }
    if body.installer_protocol_min == 0
        || body.installer_protocol_min > body.installer_protocol_max
        || policy.installer_protocol_version < body.installer_protocol_min
        || policy.installer_protocol_version > body.installer_protocol_max
    {
        return Err(ReleaseError::BindingMismatch("installer protocol"));
    }
    validate_planner(&body.planner)?;
    validate_artifacts(&body.artifacts, policy)
}

fn validate_token(value: &str, maximum_length: usize) -> Result<(), ReleaseError> {
    if value.is_empty()
        || value.len() > maximum_length
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(ReleaseError::InvalidManifest("identifier token is invalid"));
    }
    Ok(())
}

fn validate_planner(planner: &PlannerRequirements) -> Result<(), ReleaseError> {
    let positive = [
        planner.alignment_bytes,
        planner.xbootldr_size_bytes,
        planner.minimum_root_size_bytes,
        planner.minimum_total_allocation_bytes,
        planner.esp_loader_required_bytes,
    ];
    if positive
        .iter()
        .any(|value| *value == 0 || *value > MAX_SAFE_JSON_INTEGER)
        || planner.safety_margin_bytes > MAX_SAFE_JSON_INTEGER
    {
        return Err(ReleaseError::InvalidManifest(
            "planner requirements are out of bounds",
        ));
    }
    if !planner.alignment_bytes.is_power_of_two() {
        return Err(ReleaseError::InvalidManifest(
            "planner alignment must be a power of two",
        ));
    }
    Ok(())
}

fn validate_artifacts(
    artifacts: &[ArtifactDescriptor],
    policy: &ReleaseTrustPolicy,
) -> Result<(), ReleaseError> {
    if artifacts.len() != REQUIRED_ARTIFACT_ROLES.len()
        || artifacts.len() > policy.maximum_artifacts
    {
        return Err(ReleaseError::InvalidManifest(
            "artifact role set is incomplete or contains extras",
        ));
    }

    let mut previous = None;
    for artifact in artifacts {
        if previous.is_some_and(|role| role >= artifact.role) {
            return Err(ReleaseError::InvalidManifest(
                "artifacts must be strictly sorted by unique role",
            ));
        }
        previous = Some(artifact.role);
        if artifact.size_bytes == 0
            || artifact.size_bytes > policy.maximum_artifact_bytes
            || artifact.size_bytes > MAX_SAFE_JSON_INTEGER
        {
            return Err(ReleaseError::InvalidManifest(
                "artifact size is out of bounds",
            ));
        }
        if artifact.chunk_size_bytes == 0
            || artifact.chunk_size_bytes > policy.maximum_chunk_size_bytes
        {
            return Err(ReleaseError::InvalidManifest(
                "artifact chunk size is out of bounds",
            ));
        }
        let chunk_size = u64::from(artifact.chunk_size_bytes);
        let expected_chunks = artifact.size_bytes.div_ceil(chunk_size);
        let expected_chunks = usize::try_from(expected_chunks)
            .map_err(|_| ReleaseError::InvalidManifest("artifact chunk count overflow"))?;
        if expected_chunks == 0
            || expected_chunks > policy.maximum_chunks_per_artifact
            || artifact.chunk_sha256.len() != expected_chunks
        {
            return Err(ReleaseError::InvalidManifest(
                "artifact chunk table is inconsistent",
            ));
        }
    }

    if artifacts
        .iter()
        .map(|artifact| artifact.role)
        .ne(REQUIRED_ARTIFACT_ROLES)
    {
        return Err(ReleaseError::InvalidManifest(
            "artifact role set is incomplete or contains extras",
        ));
    }
    Ok(())
}

fn validate_signature_order(signatures: &[ManifestSignature]) -> Result<(), ReleaseError> {
    let mut previous: Option<&Hash256> = None;
    for signature in signatures {
        if previous.is_some_and(|key_id| key_id >= &signature.key_id) {
            return Err(ReleaseError::DuplicateSignatureKey);
        }
        previous = Some(&signature.key_id);
        if signature.signature_hex.len() != 128
            || !signature
                .signature_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReleaseError::InvalidSignatureEncoding);
        }
    }
    Ok(())
}

fn verify_signatures(
    signatures: &[ManifestSignature],
    message: &[u8],
    policy: &ReleaseTrustPolicy,
) -> Result<(), ReleaseError> {
    let trusted: BTreeMap<_, _> = policy
        .trusted_keys
        .iter()
        .filter(|key| key.channels.contains(&policy.channel))
        .map(|key| (key.key_id(), key))
        .collect();
    let mut valid = 0_usize;
    for candidate in signatures {
        let Some(trusted_key) = trusted.get(&candidate.key_id) else {
            continue;
        };
        let signature_bytes = decode_hex::<64>(&candidate.signature_hex)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = VerifyingKey::from_bytes(&trusted_key.public_key)
            .map_err(|_| ReleaseError::InvalidPolicy("trusted Ed25519 key is invalid"))?;
        if verifying_key.verify_strict(message, &signature).is_ok() {
            valid += 1;
        }
    }
    if valid < policy.signature_threshold {
        return Err(ReleaseError::SignatureThreshold {
            valid,
            required: policy.signature_threshold,
        });
    }
    Ok(())
}

fn validate_ratchet(
    body: &ReleaseManifestBody,
    manifest_digest: &Hash256,
    policy: &ReleaseTrustPolicy,
    mode: ReleaseVerificationMode,
) -> Result<ReleaseAcceptanceState, ReleaseError> {
    let previous = policy.previous_acceptance.as_ref();
    match mode {
        ReleaseVerificationMode::Acquire => {
            let latest_acceptable_issue = policy
                .now_unix_secs
                .checked_add(policy.maximum_future_skew_secs)
                .ok_or(ReleaseError::InvalidPolicy("clock skew addition overflow"))?;
            if body.issued_at_unix_secs > latest_acceptable_issue {
                return Err(ReleaseError::IssuedInFuture);
            }
            if policy.now_unix_secs >= body.expires_at_unix_secs {
                return Err(ReleaseError::Expired);
            }
            if let Some(previous) = previous {
                if body.release_sequence < previous.highest_sequence {
                    return Err(ReleaseError::Downgrade);
                }
                if body.release_sequence == previous.highest_sequence
                    && (manifest_digest != &previous.manifest_digest
                        || body.issued_at_unix_secs != previous.issued_at_unix_secs)
                {
                    return Err(ReleaseError::Equivocation);
                }
            }
        }
        ReleaseVerificationMode::Resume {
            pinned_manifest_digest,
        } => {
            let Some(previous) = previous else {
                return Err(ReleaseError::InvalidResume);
            };
            if manifest_digest != &pinned_manifest_digest
                || manifest_digest != &previous.manifest_digest
                || body.release_sequence != previous.highest_sequence
                || body.issued_at_unix_secs != previous.issued_at_unix_secs
            {
                return Err(ReleaseError::InvalidResume);
            }
        }
    }

    Ok(ReleaseAcceptanceState {
        schema_version: CONTRACT_SCHEMA_VERSION,
        channel: policy.channel,
        state_model_sha256: policy.state_model_sha256.clone(),
        highest_sequence: body.release_sequence,
        manifest_digest: manifest_digest.clone(),
        issued_at_unix_secs: body.issued_at_unix_secs,
        trusted_time_unix_secs: policy.now_unix_secs,
    })
}

fn verify_artifact_stream<R: Read, W: Write>(
    descriptor: &ArtifactDescriptor,
    reader: &mut R,
    destination: &mut W,
) -> Result<(), ReleaseError> {
    let mut whole = Sha256::new();
    let mut remaining_total = descriptor.size_bytes;
    let mut buffer = [0_u8; 64 * 1024];

    for (index, expected_chunk) in descriptor.chunk_sha256.iter().enumerate() {
        let mut chunk = Sha256::new();
        let mut remaining_chunk = remaining_total.min(u64::from(descriptor.chunk_size_bytes));
        while remaining_chunk > 0 {
            let wanted = remaining_chunk.min(buffer.len() as u64) as usize;
            let read =
                reader
                    .read(&mut buffer[..wanted])
                    .map_err(|error| ReleaseError::ArtifactIo {
                        role: descriptor.role,
                        message: error.to_string(),
                    })?;
            if read == 0 {
                return Err(ReleaseError::ArtifactTruncated(descriptor.role));
            }
            destination
                .write_all(&buffer[..read])
                .map_err(|error| ReleaseError::ArtifactIo {
                    role: descriptor.role,
                    message: error.to_string(),
                })?;
            chunk.update(&buffer[..read]);
            whole.update(&buffer[..read]);
            remaining_chunk -= read as u64;
            remaining_total -= read as u64;
        }
        if Hash256::from_bytes(chunk.finalize().into()) != *expected_chunk {
            return Err(ReleaseError::ArtifactChunkMismatch {
                role: descriptor.role,
                index,
            });
        }
    }

    if remaining_total != 0 {
        return Err(ReleaseError::ArtifactTruncated(descriptor.role));
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| ReleaseError::ArtifactIo {
            role: descriptor.role,
            message: error.to_string(),
        })?
        != 0
    {
        return Err(ReleaseError::ArtifactTrailingBytes(descriptor.role));
    }
    if Hash256::from_bytes(whole.finalize().into()) != descriptor.sha256 {
        return Err(ReleaseError::ArtifactDigestMismatch(descriptor.role));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ReleaseError> {
    if value.len() != N * 2 {
        return Err(ReleaseError::InvalidSignatureEncoding);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, ReleaseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ReleaseError::InvalidSignatureEncoding),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn hash(bytes: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(bytes).into())
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[(byte >> 4) as usize] as char);
            output.push(DIGITS[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn artifact(role: ArtifactRole, bytes: &[u8], chunk_size: u32) -> ArtifactDescriptor {
        ArtifactDescriptor {
            role,
            size_bytes: bytes.len() as u64,
            sha256: hash(bytes),
            chunk_size_bytes: chunk_size,
            chunk_sha256: bytes.chunks(chunk_size as usize).map(hash).collect(),
        }
    }

    fn body() -> ReleaseManifestBody {
        ReleaseManifestBody {
            schema_version: CONTRACT_SCHEMA_VERSION,
            product: RELEASE_PRODUCT.to_owned(),
            release_id: "jstack-2026.07.20".to_owned(),
            release_version: "2026.07.20".to_owned(),
            release_sequence: 42,
            channel: ReleaseChannel::Stable,
            architecture: Architecture::X86_64,
            issued_at_unix_secs: NOW - 60,
            expires_at_unix_secs: NOW + 3_600,
            state_model_id: "jstack-installer-v1".to_owned(),
            state_model_sha256: hash(b"state-model"),
            installer_protocol_min: 1,
            installer_protocol_max: 1,
            planner: PlannerRequirements {
                alignment_bytes: 1_048_576,
                xbootldr_size_bytes: 4_294_967_296,
                minimum_root_size_bytes: 34_359_738_368,
                safety_margin_bytes: 2_147_483_648,
                minimum_total_allocation_bytes: 42_949_672_960,
                esp_loader_required_bytes: 16_777_216,
            },
            artifacts: vec![
                artifact(ArtifactRole::EspLoader, b"loader", 3),
                artifact(ArtifactRole::InstallerUki, b"installer-uki", 4),
                artifact(ArtifactRole::OfflineSystemImage, b"system-image", 5),
                artifact(ArtifactRole::RecoveryUki, b"recovery-uki", 6),
            ],
        }
    }

    fn signing_keys() -> [SigningKey; 3] {
        [
            SigningKey::from_bytes(&[1_u8; 32]),
            SigningKey::from_bytes(&[2_u8; 32]),
            SigningKey::from_bytes(&[3_u8; 32]),
        ]
    }

    fn envelope(body: ReleaseManifestBody, keys: &[SigningKey]) -> Vec<u8> {
        let message = signed_message(&body).unwrap();
        let mut signatures: Vec<_> = keys
            .iter()
            .map(|key| ManifestSignature {
                key_id: hash(key.verifying_key().as_bytes()),
                signature_hex: hex(&key.sign(&message).to_bytes()),
            })
            .collect();
        signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        canonical_json(&SignedReleaseManifest {
            signed: body,
            signatures,
        })
        .unwrap()
    }

    fn policy(keys: &[SigningKey]) -> ReleaseTrustPolicy {
        ReleaseTrustPolicy {
            channel: ReleaseChannel::Stable,
            architecture: Architecture::X86_64,
            state_model_id: "jstack-installer-v1".to_owned(),
            state_model_sha256: hash(b"state-model"),
            installer_protocol_version: 1,
            now_unix_secs: NOW,
            maximum_future_skew_secs: 300,
            maximum_manifest_lifetime_secs: 86_400,
            maximum_manifest_bytes: 1_048_576,
            maximum_signatures: 16,
            maximum_artifacts: 4,
            maximum_chunks_per_artifact: 4_096,
            maximum_artifact_bytes: 8 * 1024 * 1024 * 1024,
            maximum_chunk_size_bytes: 1024 * 1024 * 1024,
            signature_threshold: 2,
            trusted_keys: keys
                .iter()
                .map(|key| TrustedReleaseKey {
                    public_key: key.verifying_key().to_bytes(),
                    channels: vec![ReleaseChannel::Stable],
                })
                .collect(),
            previous_acceptance: None,
        }
    }

    fn verify(keys: &[SigningKey]) -> PendingReleaseManifest {
        verify_release_manifest(
            &envelope(body(), keys),
            &policy(keys),
            ReleaseVerificationMode::Acquire,
        )
        .unwrap()
    }

    #[test]
    fn canonical_threshold_manifest_requires_persisted_acceptance_before_use() {
        let keys = signing_keys();
        let pending = verify(&keys);
        let wrong = ReleaseAcceptanceState {
            manifest_digest: hash(b"wrong"),
            ..pending.required_acceptance().clone()
        };
        assert!(matches!(
            pending.accept_after_persist(&wrong),
            Err(ReleaseError::AcceptanceNotPersisted)
        ));

        let pending = verify(&keys);
        let persisted = pending.required_acceptance().clone();
        let verified = pending.accept_after_persist(&persisted).unwrap();
        assert_eq!(
            verified.release_requirements().release_manifest_hash,
            *verified.manifest_digest()
        );
    }

    #[test]
    fn envelope_must_be_byte_canonical_and_strictly_typed() {
        let keys = signing_keys();
        let canonical = envelope(body(), &keys);
        let mut whitespace = canonical.clone();
        whitespace.insert(1, b' ');
        assert!(matches!(
            verify_release_manifest(
                &whitespace,
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::NonCanonicalEnvelope)
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["signed"]["unexpected"] = serde_json::json!(true);
        assert!(matches!(
            verify_release_manifest(
                &serde_json::to_vec(&value).unwrap(),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidJson(_))
        ));
    }

    #[test]
    fn threshold_counts_only_distinct_locally_trusted_channel_keys() {
        let keys = signing_keys();
        let raw = envelope(body(), &keys[..1]);
        assert!(matches!(
            verify_release_manifest(&raw, &policy(&keys), ReleaseVerificationMode::Acquire),
            Err(ReleaseError::SignatureThreshold {
                valid: 1,
                required: 2
            })
        ));

        let mut parsed: SignedReleaseManifest =
            serde_json::from_slice(&envelope(body(), &keys)).unwrap();
        parsed.signatures.insert(1, parsed.signatures[0].clone());
        assert!(matches!(
            verify_release_manifest(
                &canonical_json(&parsed).unwrap(),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::DuplicateSignatureKey)
        ));

        let foreign = SigningKey::from_bytes(&[9_u8; 32]);
        let raw = envelope(body(), &[keys[0].clone(), keys[1].clone(), foreign]);
        assert!(
            verify_release_manifest(&raw, &policy(&keys), ReleaseVerificationMode::Acquire).is_ok()
        );
    }

    #[test]
    fn ratchet_rejects_downgrade_and_equal_sequence_equivocation() {
        let keys = signing_keys();
        let first = verify(&keys);
        let accepted = first.required_acceptance().clone();

        let mut downgrade = body();
        downgrade.release_sequence -= 1;
        let mut downgrade_policy = policy(&keys);
        downgrade_policy.previous_acceptance = Some(accepted.clone());
        assert!(matches!(
            verify_release_manifest(
                &envelope(downgrade, &keys),
                &downgrade_policy,
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::Downgrade)
        ));

        let mut equivocation = body();
        equivocation.release_version = "2026.07.20-hotfix".to_owned();
        assert!(matches!(
            verify_release_manifest(
                &envelope(equivocation, &keys),
                &downgrade_policy,
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::Equivocation)
        ));
    }

    #[test]
    fn expired_manifest_is_allowed_only_for_exact_persisted_resume() {
        let keys = signing_keys();
        let first = verify(&keys);
        let accepted = first.required_acceptance().clone();
        let mut resume_policy = policy(&keys);
        resume_policy.now_unix_secs = NOW + 7_200;
        resume_policy.previous_acceptance = Some(accepted.clone());
        assert!(matches!(
            verify_release_manifest(
                &envelope(body(), &keys),
                &resume_policy,
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::Expired)
        ));
        assert!(
            verify_release_manifest(
                &envelope(body(), &keys),
                &resume_policy,
                ReleaseVerificationMode::Resume {
                    pinned_manifest_digest: accepted.manifest_digest
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn policy_bindings_and_clock_floor_fail_closed() {
        let keys = signing_keys();
        let raw = envelope(body(), &keys);
        let mut wrong_graph = policy(&keys);
        wrong_graph.state_model_sha256 = hash(b"other");
        assert!(matches!(
            verify_release_manifest(&raw, &wrong_graph, ReleaseVerificationMode::Acquire),
            Err(ReleaseError::BindingMismatch("state model"))
        ));

        let pending = verify(&keys);
        let mut rollback_clock = policy(&keys);
        let mut accepted = pending.required_acceptance().clone();
        accepted.trusted_time_unix_secs = NOW + 1;
        rollback_clock.previous_acceptance = Some(accepted);
        assert!(matches!(
            verify_release_manifest(&raw, &rollback_clock, ReleaseVerificationMode::Acquire),
            Err(ReleaseError::ClockRollback)
        ));

        let mut zero_floor = policy(&keys);
        let mut malformed_acceptance = pending.required_acceptance().clone();
        malformed_acceptance.highest_sequence = 0;
        zero_floor.previous_acceptance = Some(malformed_acceptance);
        assert!(matches!(
            verify_release_manifest(&raw, &zero_floor, ReleaseVerificationMode::Acquire),
            Err(ReleaseError::InvalidPolicy(
                "persisted acceptance is outside safe integer bounds"
            ))
        ));
    }

    struct ShortReader<R> {
        inner: R,
        maximum: usize,
    }

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.maximum);
            self.inner.read(&mut buffer[..limit])
        }
    }

    #[test]
    fn artifact_verification_is_independent_of_io_read_boundaries() {
        let keys = signing_keys();
        let pending = verify(&keys);
        let persisted = pending.required_acceptance().clone();
        let verified = pending.accept_after_persist(&persisted).unwrap();
        let bytes = b"system-image";
        for maximum in 1..=bytes.len() {
            let mut reader = ShortReader {
                inner: Cursor::new(bytes),
                maximum,
            };
            assert_eq!(
                verified
                    .verify_artifact(ArtifactRole::OfflineSystemImage, &mut reader)
                    .unwrap()
                    .size_bytes(),
                bytes.len() as u64
            );
        }
    }

    #[test]
    fn artifact_verification_rejects_truncation_trailing_and_hash_changes() {
        let keys = signing_keys();
        let pending = verify(&keys);
        let persisted = pending.required_acceptance().clone();
        let verified = pending.accept_after_persist(&persisted).unwrap();

        let mut truncated = Cursor::new(b"system-imag");
        assert!(matches!(
            verified.verify_artifact(ArtifactRole::OfflineSystemImage, &mut truncated),
            Err(ReleaseError::ArtifactTruncated(
                ArtifactRole::OfflineSystemImage
            ))
        ));
        let mut trailing = Cursor::new(b"system-image!");
        assert!(matches!(
            verified.verify_artifact(ArtifactRole::OfflineSystemImage, &mut trailing),
            Err(ReleaseError::ArtifactTrailingBytes(
                ArtifactRole::OfflineSystemImage
            ))
        ));
        let mut changed = Cursor::new(b"system-Image");
        assert!(matches!(
            verified.verify_artifact(ArtifactRole::OfflineSystemImage, &mut changed),
            Err(ReleaseError::ArtifactChunkMismatch {
                role: ArtifactRole::OfflineSystemImage,
                ..
            })
        ));
    }

    #[test]
    fn accepted_release_capability_is_the_public_planner_input() {
        let keys = signing_keys();
        let pending = verify(&keys);
        let persisted = pending.required_acceptance().clone();
        let verified = pending.accept_after_persist(&persisted).unwrap();
        let inventory: crate::Inventory =
            serde_json::from_str(include_str!("../fixtures/windows-11-basic-gpt.json")).unwrap();
        let plan =
            crate::create_install_plan(&inventory, &verified.verified_release_requirements())
                .unwrap();
        assert_eq!(plan.body.release_manifest_hash, *verified.manifest_digest());
    }

    #[test]
    fn signed_manifest_rejects_missing_roles_and_inconsistent_chunks() {
        let keys = signing_keys();
        let mut missing = body();
        missing.artifacts.pop();
        assert!(matches!(
            verify_release_manifest(
                &envelope(missing, &keys),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidManifest(
                "artifact role set is incomplete or contains extras"
            ))
        ));

        let mut inconsistent = body();
        inconsistent.artifacts[2].chunk_sha256.pop();
        assert!(matches!(
            verify_release_manifest(
                &envelope(inconsistent, &keys),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidManifest(
                "artifact chunk table is inconsistent"
            ))
        ));
    }

    #[test]
    fn corrupted_trusted_signature_and_excess_signature_count_fail_closed() {
        let keys = signing_keys();
        let mut parsed: SignedReleaseManifest =
            serde_json::from_slice(&envelope(body(), &keys[..2])).unwrap();
        parsed.signatures[0].signature_hex = "00".repeat(64);
        assert!(matches!(
            verify_release_manifest(
                &canonical_json(&parsed).unwrap(),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::SignatureThreshold {
                valid: 1,
                required: 2
            })
        ));

        let mut limited = policy(&keys);
        limited.maximum_signatures = 2;
        assert!(matches!(
            verify_release_manifest(
                &envelope(body(), &keys),
                &limited,
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidManifest(
                "signature count exceeds policy"
            ))
        ));
    }

    #[test]
    fn future_issue_lifetime_and_acceptance_trust_domain_fail_closed() {
        let keys = signing_keys();
        let mut future = body();
        future.issued_at_unix_secs = NOW + 301;
        future.expires_at_unix_secs = NOW + 601;
        assert!(matches!(
            verify_release_manifest(
                &envelope(future, &keys),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::IssuedInFuture)
        ));

        let mut long_lived = body();
        long_lived.expires_at_unix_secs = long_lived.issued_at_unix_secs + 86_401;
        assert!(matches!(
            verify_release_manifest(
                &envelope(long_lived, &keys),
                &policy(&keys),
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidManifest(
                "manifest lifetime exceeds policy"
            ))
        ));

        let pending = verify(&keys);
        let mut foreign = pending.required_acceptance().clone();
        foreign.channel = ReleaseChannel::Beta;
        let mut foreign_policy = policy(&keys);
        foreign_policy.previous_acceptance = Some(foreign);
        assert!(matches!(
            verify_release_manifest(
                &envelope(body(), &keys),
                &foreign_policy,
                ReleaseVerificationMode::Acquire
            ),
            Err(ReleaseError::InvalidPolicy(
                "persisted acceptance belongs to another trust domain"
            ))
        ));
    }

    #[test]
    fn whole_artifact_digest_is_checked_independently_of_chunk_hashes() {
        let keys = signing_keys();
        let mut inconsistent = body();
        inconsistent.artifacts[2].sha256 = hash(b"different-whole-digest");
        let pending = verify_release_manifest(
            &envelope(inconsistent, &keys),
            &policy(&keys),
            ReleaseVerificationMode::Acquire,
        )
        .unwrap();
        let persisted = pending.required_acceptance().clone();
        let verified = pending.accept_after_persist(&persisted).unwrap();
        let mut bytes = Cursor::new(b"system-image");
        assert!(matches!(
            verified.verify_artifact(ArtifactRole::OfflineSystemImage, &mut bytes),
            Err(ReleaseError::ArtifactDigestMismatch(
                ArtifactRole::OfflineSystemImage
            ))
        ));
    }
}
