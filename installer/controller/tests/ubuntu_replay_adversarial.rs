//! Independent malformed-history checks through public journal/status APIs.
//! Synthetic evidence only, not a replacement for cold-restart VM acceptance.
#![cfg(target_os = "linux")]
use jstack_installer_controller::ubuntu::*;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
fn hx(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    UbuntuPlan,
) {
    let d = tempdir().unwrap();
    std::fs::create_dir(d.path().join("artifacts")).unwrap();
    let data = b"abcdefgh";
    let art = d.path().join("artifacts/image.raw");
    std::fs::write(&art, data).unwrap();
    let chunks = vec![
        ArtifactChunk {
            offset: 0,
            length: 4,
            sha256: hx(&data[..4]),
        },
        ArtifactChunk {
            offset: 4,
            length: 4,
            sha256: hx(&data[4..]),
        },
    ];
    let body = PlanBody {
        model_id: GRAPH_ID.into(),
        graph_digest: GRAPH_SHA256.into(),
        created_at_unix_ms: 1,
        target: StableDiskIdentity {
            stable_serial: "TARGET".into(),
            stable_wwn: None,
            size_bytes: 8,
            logical_sector_bytes: 512,
        },
        recovery: RecoveryIdentity {
            filesystem_uuid: "uuid".into(),
            backing_serial: "HOST".into(),
            backing_wwn: None,
        },
        artifact: ArtifactManifest {
            sha256: hx(data),
            size_bytes: 8,
            relative_store_path: "artifacts/image.raw".into(),
            chunks,
        },
        deployment: Deployment { chunk_bytes: 4 },
    };
    let hash = hex(&Sha256::digest(serde_json::to_vec(&body).unwrap()));
    let p = UbuntuPlan {
        schema_version: PLAN_SCHEMA.into(),
        plan_hash: hash.clone(),
        body,
        confirmation: Confirmation {
            exact_phrase: "ERASE TARGET".into(),
            confirmed_plan_hash: hash.clone(),
        },
    };
    let pp = d.path().join("plan.json");
    std::fs::write(&pp, serde_json::to_vec(&p).unwrap()).unwrap();
    let journal = Journal::open(d.path(), &hash).unwrap();
    journal
        .append(Event::StageIntent {
            artifact_sha256: hx(data),
            size_bytes: data.len() as u64,
        })
        .unwrap();
    journal
        .append(Event::StageCommit {
            artifact_sha256: hx(data),
            size_bytes: data.len() as u64,
        })
        .unwrap();
    journal.append(Event::Authorized).unwrap();
    let target = d.path().join("target.raw");
    std::fs::write(&target, [0; 8]).unwrap();
    (d, pp, target, p)
}

fn refuses(events: Vec<Event>) {
    let (d, path, target, plan) = fixture();
    assert_eq!(status(&path).unwrap().state, "authorized");
    let j = Journal::open(d.path(), &plan.plan_hash).unwrap();
    for event in events {
        j.append(event).unwrap();
    }
    let before = std::fs::read(&target).unwrap();
    assert!(
        status(&path).is_err(),
        "invalid durable history must be rejected"
    );
    assert_eq!(std::fs::read(&target).unwrap(), before);
}
#[test]
fn rejects_advance_without_commit() {
    refuses(vec![Event::Advance { next_offset: 4 }]);
}
#[test]
fn rejects_verified_before_chunks() {
    refuses(vec![Event::Verified]);
}
#[test]
fn rejects_complete_before_verified() {
    refuses(vec![Event::Complete]);
}
#[test]
fn rejects_repeated_authorization() {
    refuses(vec![Event::Authorized]);
}
#[test]
fn rejects_transition_after_manual_recovery() {
    refuses(vec![
        Event::Intent {
            seq: 0,
            offset: 0,
            length: 4,
            sha256: hx(b"abcd"),
        },
        Event::ManualRecovery {
            reason: "test refusal".into(),
        },
        Event::Verified,
    ]);
}
#[test]
fn rejects_commit_without_intent() {
    refuses(vec![Event::Commit {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: hx(b"abcd"),
    }]);
}
#[test]
fn rejects_wrong_chunk_digest() {
    refuses(vec![Event::Intent {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: hx(b"xxxx"),
    }]);
}
#[test]
fn rejects_advance_with_only_pending_intent() {
    refuses(vec![
        Event::Intent {
            seq: 0,
            offset: 0,
            length: 4,
            sha256: hx(b"abcd"),
        },
        Event::Advance { next_offset: 4 },
    ]);
}

#[test]
fn valid_authorized_history_is_read_only() {
    let (d, path, target, plan) = fixture();
    let wal = d
        .path()
        .join("journal")
        .join(format!("{}.wal", plan.plan_hash));
    let before = std::fs::read(&wal).unwrap();
    assert_eq!(status(&path).unwrap().state, "authorized");
    assert_eq!(std::fs::read(wal).unwrap(), before);
    assert_eq!(std::fs::read(target).unwrap(), vec![0; 8]);
}

#[test]
fn rejects_restarted_staging_after_authorization() {
    refuses(vec![Event::StageIntent {
        artifact_sha256: hx(b"abcdefgh"),
        size_bytes: 8,
    }]);
}

#[test]
fn status_does_not_truncate_torn_journal_tail() {
    use std::io::Write;
    let (d, path, _, plan) = fixture();
    let wal = d
        .path()
        .join("journal")
        .join(format!("{}.wal", plan.plan_hash));
    assert_eq!(status(&path).unwrap().state, "authorized");
    let mut f = std::fs::OpenOptions::new().append(true).open(&wal).unwrap();
    f.write_all(b"JUB").unwrap();
    f.sync_all().unwrap();
    let before = std::fs::read(&wal).unwrap();
    assert!(status(&path).is_err());
    assert_eq!(std::fs::read(&wal).unwrap(), before);
}

#[test]
fn status_rejects_hardlinked_journal() {
    let (d, path, _, plan) = fixture();
    let wal = d
        .path()
        .join("journal")
        .join(format!("{}.wal", plan.plan_hash));
    assert_eq!(status(&path).unwrap().state, "authorized");
    std::fs::hard_link(&wal, d.path().join("journal-alias")).unwrap();
    assert!(status(&path).is_err());
}

#[test]
fn status_rejects_symlinked_journal() {
    let (d, path, _, plan) = fixture();
    let wal = d
        .path()
        .join("journal")
        .join(format!("{}.wal", plan.plan_hash));
    assert_eq!(status(&path).unwrap().state, "authorized");
    let moved = d.path().join("moved-journal");
    std::fs::rename(&wal, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &wal).unwrap();
    assert!(status(&path).is_err());
}
