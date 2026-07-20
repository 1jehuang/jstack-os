use std::{env, fs, process::ExitCode};

use jstack_installer_core::{
    Architecture, Hash256, Inventory, PlanDisplay, ReleaseChannel, ReleaseTrustPolicy,
    ReleaseVerificationMode, TrustedReleaseKey, create_install_plan, verify_release_manifest,
};
use sha2::{Digest, Sha256};

const FIXTURE_NOW: u64 = 1_800_000_000;
const STATE_MODEL_BYTES: &[u8] = include_bytes!("../../../model/installer-state-graph.json");
const FIXTURE_PUBLIC_KEYS: [[u8; 32]; 2] = [
    [
        0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d,
        0x72, 0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f,
        0x6f, 0x5c,
    ],
    [
        0x81, 0x39, 0x77, 0x0e, 0xa8, 0x7d, 0x17, 0x5f, 0x56, 0xa3, 0x54, 0x66, 0xc3, 0x4c, 0x7e,
        0xcc, 0xcb, 0x8d, 0x8a, 0x91, 0xb4, 0xee, 0x37, 0xa2, 0x5d, 0xf6, 0x0f, 0x5b, 0x8f, 0xc9,
        0xb3, 0x94,
    ],
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (display_only, inventory_path, manifest_path) = match args.as_slice() {
        [_, inventory, manifest] => (false, inventory.as_str(), manifest.as_str()),
        [_, flag, inventory, manifest] if flag == "--display" => {
            (true, inventory.as_str(), manifest.as_str())
        }
        _ => {
            eprintln!(
                "usage: jstack-plan [--display] <inventory.json> <canonical-signed-release-manifest.json>"
            );
            return ExitCode::from(2);
        }
    };
    match run(inventory_path, manifest_path, display_only) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jstack-plan: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(
    inventory_path: &str,
    manifest_path: &str,
    display_only: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let inventory: Inventory = serde_json::from_slice(&fs::read(inventory_path)?)?;
    let manifest = fs::read(manifest_path)?;
    let policy = fixture_trust_policy();
    let pending = verify_release_manifest(&manifest, &policy, ReleaseVerificationMode::Acquire)?;
    let persisted_readback = pending.required_acceptance().clone();
    let verified = pending.accept_after_persist(&persisted_readback)?;
    let requirements = verified.verified_release_requirements();
    let plan = create_install_plan(&inventory, &requirements)?;
    if display_only {
        Ok(serde_json::to_string_pretty(&PlanDisplay::from(&plan))?)
    } else {
        Ok(serde_json::to_string_pretty(&plan)?)
    }
}

fn fixture_trust_policy() -> ReleaseTrustPolicy {
    ReleaseTrustPolicy {
        channel: ReleaseChannel::Stable,
        architecture: Architecture::X86_64,
        state_model_id: "jstack-installer-v1".to_owned(),
        state_model_sha256: Hash256::from_bytes(Sha256::digest(STATE_MODEL_BYTES).into()),
        installer_protocol_version: 1,
        now_unix_secs: FIXTURE_NOW,
        maximum_future_skew_secs: 300,
        maximum_manifest_lifetime_secs: 86_400,
        maximum_manifest_bytes: 1_048_576,
        maximum_signatures: 16,
        maximum_artifacts: 4,
        maximum_chunks_per_artifact: 4_096,
        maximum_artifact_bytes: 8 * 1024 * 1024 * 1024,
        maximum_chunk_size_bytes: 1024 * 1024 * 1024,
        signature_threshold: 2,
        trusted_keys: FIXTURE_PUBLIC_KEYS
            .into_iter()
            .map(|public_key| TrustedReleaseKey {
                public_key,
                channels: vec![ReleaseChannel::Stable],
            })
            .collect(),
        previous_acceptance: None,
    }
}
