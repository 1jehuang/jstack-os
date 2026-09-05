#![cfg(target_os = "linux")]
use jstack_installer_controller::ubuntu::*;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
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
            artifact_sha256: p.body.artifact.sha256.clone(),
            size_bytes: 8,
        })
        .unwrap();
    journal
        .append(Event::StageCommit {
            artifact_sha256: p.body.artifact.sha256.clone(),
            size_bytes: 8,
        })
        .unwrap();
    journal.append(Event::Authorized).unwrap();
    journal.append(Event::DeploymentStarted).unwrap();
    let target = d.path().join("target.raw");
    std::fs::write(&target, [0; 8]).unwrap();
    (d, pp, target, p)
}
#[test]
fn deploy_verifies_and_completed_resume_never_repairs() {
    let (_d, p, t, _) = fixture();
    deploy_files(&p, &t, false).unwrap();
    assert_eq!(std::fs::read(&t).unwrap(), b"abcdefgh");
    OpenOptions::new()
        .write(true)
        .open(&t)
        .unwrap()
        .write_all(b"X")
        .unwrap();
    deploy_files(&p, &t, false).unwrap();
    assert_eq!(std::fs::read(&t).unwrap()[0], b'X');
    assert_eq!(status(&p).unwrap().state, "complete")
}
#[test]
fn dangling_intent_is_reconciled_only_for_bound_range() {
    let (d, p, t, plan) = fixture();
    let j = Journal::open(d.path(), &plan.plan_hash).unwrap();
    let c = &plan.body.artifact.chunks[0];
    j.append(Event::Intent {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: c.sha256.clone(),
    })
    .unwrap();
    deploy_files(&p, &t, false).unwrap();
    assert_eq!(std::fs::read(t).unwrap(), b"abcdefgh")
}
#[test]
fn corrupt_committed_chunk_is_never_overwritten() {
    let (d, p, t, plan) = fixture();
    let j = Journal::open(d.path(), &plan.plan_hash).unwrap();
    let c = &plan.body.artifact.chunks[0];
    j.append(Event::Intent {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: c.sha256.clone(),
    })
    .unwrap();
    j.append(Event::Commit {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: c.sha256.clone(),
    })
    .unwrap();
    j.append(Event::Advance { next_offset: 4 }).unwrap();
    let e = deploy_files(&p, &t, false).unwrap_err();
    assert!(e.contains("committed target chunk mismatch"));
    assert_eq!(std::fs::read(t).unwrap(), vec![0; 8])
}
#[test]
fn plan_drift_and_committed_journal_corruption_stop() {
    let (d, p, _t, plan) = fixture();
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    v["body"]["target"]["size_bytes"] = 9.into();
    std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    assert!(read_plan(&p).is_err());
    let wal = d
        .path()
        .join("journal")
        .join(format!("{}.wal", plan.plan_hash));
    let mut f = OpenOptions::new().write(true).open(wal).unwrap();
    f.seek(SeekFrom::Start(15)).unwrap();
    f.write_all(b"X").unwrap();
    f.sync_all().unwrap();
    assert!(
        Journal::open_existing(d.path(), &plan.plan_hash)
            .unwrap()
            .read_strict()
            .is_err()
    )
}

fn assert_replay_rejects(event: Event) {
    let (d, p, _, plan) = fixture();
    Journal::open(d.path(), &plan.plan_hash)
        .unwrap()
        .append(event)
        .unwrap();
    assert!(status(&p).is_err());
}

#[test]
fn replay_rejects_advance_verify_complete_and_manual_recovery_out_of_order() {
    assert_replay_rejects(Event::Advance { next_offset: 4 });
    assert_replay_rejects(Event::Verified);
    assert_replay_rejects(Event::Complete);
    assert_replay_rejects(Event::Authorized);
}

#[test]
fn commit_before_advance_resume_appends_only_advance() {
    let (d, p, t, plan) = fixture();
    let j = Journal::open(d.path(), &plan.plan_hash).unwrap();
    let c = &plan.body.artifact.chunks[0];
    std::fs::write(&t, b"abcd\0\0\0\0").unwrap();
    j.append(Event::Intent {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: c.sha256.clone(),
    })
    .unwrap();
    j.append(Event::Commit {
        seq: 0,
        offset: 0,
        length: 4,
        sha256: c.sha256.clone(),
    })
    .unwrap();
    deploy_files(&p, &t, false).unwrap();
    let records = j.read().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(r.event, Event::Intent { seq: 0, .. }))
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(r.event, Event::Commit { seq: 0, .. }))
            .count(),
        1
    );
}

#[test]
fn replay_rejects_records_after_complete_terminal() {
    let (d, p, t, plan) = fixture();
    deploy_files(&p, &t, false).unwrap();
    Journal::open(d.path(), &plan.plan_hash)
        .unwrap()
        .append(Event::Verified)
        .unwrap();
    assert!(status(&p).is_err());
}
