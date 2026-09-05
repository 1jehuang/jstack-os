use super::{Event, Journal, UbuntuPlan, hex};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub state: &'static str,
    pub next_offset: u64,
}
pub fn read_plan(path: &Path) -> Result<(UbuntuPlan, PathBuf), String> {
    let supplied = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if supplied.file_type().is_symlink() {
        return Err("plan path must not be a symlink".into());
    }
    let canonical = path.canonicalize().map_err(|e| e.to_string())?;
    let meta = std::fs::symlink_metadata(&canonical).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err("plan must be a regular single-link file".into());
    }
    let p: UbuntuPlan =
        serde_json::from_reader(File::open(&canonical).map_err(err)?).map_err(err)?;
    p.validate()?;
    Ok((p, canonical))
}
pub fn status(plan_path: &Path) -> Result<Status, String> {
    let (p, cp) = read_plan(plan_path)?;
    let root = cp.parent().ok_or("plan has no parent")?;
    let records = Journal::open_existing(root, &p.plan_hash)?.read_strict()?;
    replay(&p, &records)
}
fn replay(p: &UbuntuPlan, records: &[super::Record]) -> Result<Status, String> {
    Ok(replay_state(p, records)?.status)
}

type ChunkTuple = (u64, u64, u64, String);
struct ReplayState {
    status: Status,
    pending_intent: Option<ChunkTuple>,
    committed_unadvanced: Option<ChunkTuple>,
}

fn replay_state(p: &UbuntuPlan, records: &[super::Record]) -> Result<ReplayState, String> {
    let mut next = 0;
    let mut state = "discovered";
    let mut pending: Option<ChunkTuple> = None;
    let mut committed: Option<ChunkTuple> = None;
    let mut staging = false;
    let mut terminal = false;
    for r in records {
        if terminal {
            return Err("journal contains a record after a terminal state".into());
        }
        match &r.event {
            Event::StageIntent {
                artifact_sha256,
                size_bytes,
            } => {
                if state != "discovered"
                    || staging
                    || artifact_sha256 != &p.body.artifact.sha256
                    || *size_bytes != p.body.artifact.size_bytes
                {
                    return Err(
                        "artifact staging intent is duplicate, out of order, or unbound".into(),
                    );
                }
                staging = true;
            }
            Event::StageCommit {
                artifact_sha256,
                size_bytes,
            } => {
                if state != "discovered"
                    || !staging
                    || artifact_sha256 != &p.body.artifact.sha256
                    || *size_bytes != p.body.artifact.size_bytes
                {
                    return Err("artifact staging commit has no exact intent".into());
                }
                staging = false;
                state = "artifact_prepared";
            }
            Event::Authorized => {
                if state != "artifact_prepared"
                    || staging
                    || pending.is_some()
                    || committed.is_some()
                {
                    return Err("authorization is duplicate or out of order".into());
                }
                state = "authorized";
            }
            Event::Intent {
                seq,
                offset,
                length,
                sha256,
            } => {
                if state != "authorized" && state != "deploying"
                    || pending.is_some()
                    || committed.is_some()
                    || *offset != next
                    || p.body
                        .artifact
                        .chunks
                        .get(*seq as usize)
                        .map(|c| (c.offset, c.length, c.sha256.as_str()))
                        != Some((*offset, *length, sha256))
                {
                    return Err("journal intent violates plan/cursor".into());
                }
                pending = Some((*seq, *offset, *length, sha256.clone()));
                state = "deploying"
            }
            Event::Commit {
                seq,
                offset,
                length,
                sha256,
            } => {
                let exact = (*seq, *offset, *length, sha256.clone());
                if pending.take() != Some(exact.clone()) || committed.is_some() {
                    return Err("commit has no exact intent".into());
                }
                committed = Some(exact);
            }
            Event::Advance { next_offset } => {
                let Some((_, offset, length, _)) = committed.take() else {
                    return Err("cursor advance has no immediately committed chunk".into());
                };
                if offset != next || offset.checked_add(length) != Some(*next_offset) {
                    return Err("cursor advance is not a committed chunk".into());
                }
                next = *next_offset
            }
            Event::Verified => {
                if state != "deploying"
                    || pending.is_some()
                    || committed.is_some()
                    || next != p.body.artifact.size_bytes
                {
                    return Err("target verified before all chunks advanced".into());
                }
                state = "verified"
            }
            Event::Complete => {
                if state != "verified" {
                    return Err("completion lacks full verification".into());
                }
                state = "complete";
                terminal = true;
            }
            Event::ManualRecovery { .. } => {
                if state != "deploying" && state != "verified" {
                    return Err("manual recovery recorded before target mutation".into());
                }
                state = "manual_recovery";
                terminal = true;
            }
        }
    }
    Ok(ReplayState {
        status: Status {
            state,
            next_offset: next,
        },
        pending_intent: pending,
        committed_unadvanced: committed,
    })
}
pub fn deploy_files(
    plan_path: &Path,
    target_path: &Path,
    production_checks: bool,
) -> Result<(), String> {
    let (p, cp) = read_plan(plan_path)?;
    let root = cp.parent().ok_or("plan has no parent")?;
    let lock_name = hex(&Sha256::digest(
        format!(
            "{}:{:?}",
            p.body.target.stable_serial, p.body.target.stable_wwn
        )
        .as_bytes(),
    ));
    let lock_path = if production_checks {
        PathBuf::from("/run/lock").join(format!("jstack-ubuntu-{lock_name}.lock"))
    } else {
        root.join("target.lock")
    };
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(err)?;
    fs4::FileExt::try_lock(&lock)
        .map_err(|_| "target transaction already has a writer".to_string())?;
    if production_checks {
        super::verify_unused_target(target_path, root)?;
        super::verify_recovery_identity(root, &p.body.recovery)?;
        let resolved = super::resolve_unique(&p.body.target)?;
        if resolved.canonicalize().map_err(err)? != target_path.canonicalize().map_err(err)? {
            return Err("resolved device differs from plan identity".into());
        }
    }
    let journal = Journal::open(root, &p.plan_hash)?;
    let records = journal.read()?;
    let initial = replay_state(&p, &records)?;
    let artifact_path = p.artifact_path(root);
    secure_regular(&artifact_path)?;
    let mut source = File::open(&artifact_path).map_err(err)?;
    if hash_range(&source, 0, p.body.artifact.size_bytes)? != p.body.artifact.sha256 {
        return Err("retained artifact no longer matches the authorized plan".into());
    }
    if initial.status.state == "complete" {
        marker(&format!("JSTK_UBUNTU_COMPLETE plan={}", p.plan_hash));
        return Ok(());
    }
    if initial.status.state == "manual_recovery" {
        return Err("transaction requires manual recovery".into());
    }
    if initial.status.state == "authorized" {
        super::require_begin()?;
    }
    let mut target = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target_path)
        .map_err(err)?;
    let records = journal.read()?;
    let mut replayed = replay_state(&p, &records)?;
    let mut s = replayed.status.clone();
    // Validate every durable commit before considering a pending intent.
    for r in &records {
        if let Event::Commit {
            offset,
            length,
            sha256,
            ..
        } = &r.event
        {
            if hash_range(&target, *offset, *length)? != *sha256 {
                return Err("committed target chunk mismatch; manual recovery required".into());
            }
        }
    }
    if let Some((_, offset, length, _)) = replayed.committed_unadvanced.take() {
        journal.append(Event::Advance {
            next_offset: offset + length,
        })?;
        marker(&format!(
            "JSTK_UBUNTU_ADVANCE next_offset={}",
            offset + length
        ));
        s.next_offset = offset + length;
    }
    if let Some((seq, offset, length, digest)) = replayed.pending_intent.take() {
        super::require_chunk()?;
        write_or_admit(
            &journal,
            &mut source,
            &mut target,
            seq,
            offset,
            length,
            &digest,
        )?;
        journal.append(Event::Advance {
            next_offset: offset + length,
        })?;
        marker(&format!(
            "JSTK_UBUNTU_ADVANCE next_offset={}",
            offset + length
        ));
        s.next_offset = offset + length
    }
    for (seq, c) in p
        .body
        .artifact
        .chunks
        .iter()
        .enumerate()
        .skip_while(|(_, c)| c.offset < s.next_offset)
    {
        super::require_chunk()?;
        if production_checks {
            super::verify_unused_target(target_path, root)?
        }
        journal.append(Event::Intent {
            seq: seq as u64,
            offset: c.offset,
            length: c.length,
            sha256: c.sha256.clone(),
        })?;
        marker(&format!(
            "JSTK_UBUNTU_INTENT seq={seq} offset={} length={}",
            c.offset, c.length
        ));
        write_or_admit(
            &journal,
            &mut source,
            &mut target,
            seq as u64,
            c.offset,
            c.length,
            &c.sha256,
        )?;
        journal.append(Event::Advance {
            next_offset: c.offset + c.length,
        })?;
        marker(&format!(
            "JSTK_UBUNTU_ADVANCE next_offset={}",
            c.offset + c.length
        ));
    }
    super::require_verify()?;
    if hash_range(&target, 0, p.body.artifact.size_bytes)? != p.body.artifact.sha256 {
        journal.append(Event::ManualRecovery {
            reason: "full target digest mismatch".into(),
        })?;
        return Err("full target digest mismatch".into());
    }
    journal.append(Event::Verified)?;
    super::require_complete()?;
    journal.append(Event::Complete)?;
    marker(&format!("JSTK_UBUNTU_COMPLETE plan={}", p.plan_hash));
    Ok(())
}
fn write_or_admit(
    j: &Journal,
    src: &mut File,
    dst: &mut File,
    seq: u64,
    off: u64,
    len: u64,
    digest: &str,
) -> Result<(), String> {
    let mut b = vec![0; len as usize];
    src.read_exact_at(&mut b, off).map_err(err)?;
    if hex(&Sha256::digest(&b)) != digest {
        return Err("staged source chunk mismatch".into());
    }
    if hash_range(dst, off, len)? != digest {
        marker(&format!(
            "JSTK_UBUNTU_WRITE_BEGIN seq={seq} offset={off} length={len}"
        ));
        dst.write_all_at(&b, off).map_err(err)?;
        dst.sync_data().map_err(err)?;
        marker(&format!(
            "JSTK_UBUNTU_WRITE_END seq={seq} offset={off} length={len}"
        ));
    }
    if hash_range(dst, off, len)? != digest {
        return Err("target readback mismatch".into());
    }
    marker(&format!(
        "JSTK_UBUNTU_READBACK_OK seq={seq} offset={off} length={len}"
    ));
    j.append(Event::Commit {
        seq,
        offset: off,
        length: len,
        sha256: digest.into(),
    })?;
    marker(&format!(
        "JSTK_UBUNTU_COMMIT seq={seq} offset={off} length={len}"
    ));
    Ok(())
}
fn hash_range(f: &File, off: u64, len: u64) -> Result<String, String> {
    let mut h = Sha256::new();
    let mut b = vec![0; 1024 * 1024];
    let mut done = 0;
    while done < len {
        let n = ((len - done) as usize).min(b.len());
        f.read_exact_at(&mut b[..n], off + done).map_err(err)?;
        h.update(&b[..n]);
        done += n as u64
    }
    Ok(hex(&h.finalize()))
}
fn secure_regular(p: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(p).map_err(err)?;
    if !m.file_type().is_file() || m.nlink() != 1 {
        return Err("unsafe artifact file".into());
    }
    Ok(())
}
pub fn marker(s: &str) {
    println!("{s}");
    let _ = std::io::stdout().flush();
}
fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
