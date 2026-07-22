use std::env;
use std::io::{self, Write};

use ed25519_dalek::{Signer, SigningKey};
use jstack_installer_core::{
    Architecture, ArtifactDescriptor, ArtifactRole, CONTRACT_SCHEMA_VERSION, Hash256,
    ManifestSignature, PlannerRequirements, RELEASE_PRODUCT, ReleaseAcceptanceState,
    ReleaseChannel, ReleaseManifestBody, SignedReleaseManifest, canonical_json,
    executable_state_model_id, signed_message,
};
use sha2::{Digest, Sha256};

const ISSUED_AT: u64 = 1_800_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 86_400;
const STATE_MODEL_BYTES: &[u8] = include_bytes!("../../../model/installer-state-graph.json");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = env::args().nth(1).unwrap_or_else(|| "manifest".to_owned());
    let body = release_body()?;
    let message = signed_message(&body)?;
    let manifest_digest = hash(&message);

    let output = match mode.as_str() {
        "manifest" => canonical_json(&signed_envelope(body, &message))?,
        "acceptance" => canonical_json(&ReleaseAcceptanceState {
            schema_version: CONTRACT_SCHEMA_VERSION,
            channel: ReleaseChannel::Stable,
            state_model_sha256: hash(STATE_MODEL_BYTES),
            highest_sequence: 1,
            manifest_digest,
            issued_at_unix_secs: ISSUED_AT,
            trusted_time_unix_secs: ISSUED_AT,
        })?,
        _ => return Err(format!("unsupported mode {mode:?}; use manifest or acceptance").into()),
    };
    io::stdout().write_all(&output)?;
    Ok(())
}

fn release_body() -> Result<ReleaseManifestBody, Box<dyn std::error::Error>> {
    Ok(ReleaseManifestBody {
        schema_version: CONTRACT_SCHEMA_VERSION,
        product: RELEASE_PRODUCT.to_owned(),
        release_id: "jstack-fixture-1".to_owned(),
        release_version: "1.0.0".to_owned(),
        release_sequence: 1,
        channel: ReleaseChannel::Stable,
        architecture: Architecture::X86_64,
        issued_at_unix_secs: ISSUED_AT,
        expires_at_unix_secs: EXPIRES_AT,
        state_model_id: executable_state_model_id(STATE_MODEL_BYTES)?,
        state_model_sha256: hash(STATE_MODEL_BYTES),
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
            artifact(ArtifactRole::EspLoader, b"jstack-esp-loader-fixture\n", 8),
            artifact(
                ArtifactRole::InstallerUki,
                b"jstack-installer-uki-fixture\n",
                9,
            ),
            artifact(
                ArtifactRole::OfflineSystemImage,
                b"jstack-offline-system-image-fixture\n",
                11,
            ),
            artifact(
                ArtifactRole::RecoveryUki,
                b"jstack-recovery-uki-fixture\n",
                10,
            ),
        ],
    })
}

fn signed_envelope(body: ReleaseManifestBody, message: &[u8]) -> SignedReleaseManifest {
    let keys = [
        SigningKey::from_bytes(&[1_u8; 32]),
        SigningKey::from_bytes(&[2_u8; 32]),
    ];
    let mut signatures: Vec<_> = keys
        .iter()
        .map(|key| ManifestSignature {
            key_id: hash(key.verifying_key().as_bytes()),
            signature_hex: hex(&key.sign(message).to_bytes()),
        })
        .collect();
    signatures.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    SignedReleaseManifest {
        signed: body,
        signatures,
    }
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
