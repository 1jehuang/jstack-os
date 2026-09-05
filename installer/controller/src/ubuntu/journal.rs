use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::model::hex;
const MAGIC: &[u8; 8] = b"JUBWAL1\0";
const COMMIT: &[u8; 8] = b"JUBCMT1\0";
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Event {
    StageIntent {
        artifact_sha256: String,
        size_bytes: u64,
    },
    StageCommit {
        artifact_sha256: String,
        size_bytes: u64,
    },
    Authorized,
    DeploymentStarted,
    Intent {
        seq: u64,
        offset: u64,
        length: u64,
        sha256: String,
    },
    Commit {
        seq: u64,
        offset: u64,
        length: u64,
        sha256: String,
    },
    Advance {
        next_offset: u64,
    },
    Verified,
    Complete,
    ManualRecovery {
        reason: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub sequence: u64,
    pub plan_hash: String,
    pub previous_hash: Option<String>,
    pub event: Event,
}
impl Record {
    pub fn hash(&self) -> Result<String, String> {
        serde_json::to_vec(self)
            .map(|b| hex(&Sha256::digest(b)))
            .map_err(|e| e.to_string())
    }
}
pub struct Journal {
    path: PathBuf,
    plan_hash: String,
}
impl Journal {
    pub fn open_existing(root: &Path, plan_hash: &str) -> Result<Self, String> {
        let path = root.join("journal").join(format!("{plan_hash}.wal"));
        validate_directory(root)?;
        validate_directory(&root.join("journal"))?;
        validate_regular(&path)?;
        Ok(Self {
            path,
            plan_hash: plan_hash.into(),
        })
    }
    pub fn open(root: &Path, plan_hash: &str) -> Result<Self, String> {
        let dir = root.join("journal");
        validate_directory(root)?;
        if !dir.exists() {
            std::fs::create_dir(&dir).map_err(err)?;
        }
        validate_directory(&dir)?;
        sync_dir(&dir)?;
        let path = dir.join(format!("{plan_hash}.wal"));
        if path.exists() {
            validate_regular(&path)?;
        }
        let f = nofollow_options()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(err)?;
        validate_regular(&path)?;
        f.sync_all().map_err(err)?;
        sync_dir(&dir)?;
        Ok(Self {
            path,
            plan_hash: plan_hash.into(),
        })
    }
    pub fn read(&self) -> Result<Vec<Record>, String> {
        let mut f = OpenOptions::new()
            .custom_flags(O_NOFOLLOW)
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(err)?;
        fs4::FileExt::lock(&f).map_err(err)?;
        let r = parse(&mut f, true, &self.plan_hash);
        let _ = fs4::FileExt::unlock(&f);
        r
    }
    pub fn read_strict(&self) -> Result<Vec<Record>, String> {
        let mut f = OpenOptions::new()
            .custom_flags(O_NOFOLLOW)
            .read(true)
            .open(&self.path)
            .map_err(err)?;
        fs4::FileExt::lock_shared(&f).map_err(err)?;
        let result = parse(&mut f, false, &self.plan_hash);
        let _ = fs4::FileExt::unlock(&f);
        result
    }
    pub fn append(&self, event: Event) -> Result<Record, String> {
        let mut f = OpenOptions::new()
            .custom_flags(O_NOFOLLOW)
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(err)?;
        fs4::FileExt::lock(&f).map_err(err)?;
        let records = parse(&mut f, true, &self.plan_hash)?;
        let record = Record {
            sequence: records.len() as u64,
            plan_hash: self.plan_hash.clone(),
            previous_hash: records.last().map(Record::hash).transpose()?,
            event,
        };
        let body = serde_json::to_vec(&record).map_err(err)?;
        f.seek(SeekFrom::End(0)).map_err(err)?;
        f.write_all(MAGIC)
            .and_then(|_| f.write_all(&(body.len() as u32).to_le_bytes()))
            .and_then(|_| f.write_all(&body))
            .and_then(|_| f.write_all(&Sha256::digest(&body)))
            .map_err(err)?;
        f.sync_data().map_err(err)?;
        f.write_all(COMMIT)
            .and_then(|_| f.sync_all())
            .map_err(err)?;
        let _ = fs4::FileExt::unlock(&f);
        Ok(record)
    }
}
const O_NOFOLLOW: i32 = 0o400000;
fn nofollow_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.custom_flags(O_NOFOLLOW);
    o
}
fn validate_directory(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(err)?;
    if !m.file_type().is_dir() || m.file_type().is_symlink() {
        return Err("unsafe journal directory".into());
    }
    Ok(())
}
fn validate_regular(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(err)?;
    if !m.file_type().is_file() || m.file_type().is_symlink() || m.nlink() != 1 {
        return Err("unsafe journal file".into());
    }
    Ok(())
}
fn parse(f: &mut File, truncate: bool, plan: &str) -> Result<Vec<Record>, String> {
    let len = f.metadata().map_err(err)?.len();
    f.seek(SeekFrom::Start(0)).map_err(err)?;
    let mut out = vec![];
    let mut pos = 0;
    while pos < len {
        let start = pos;
        let mut magic = [0; 8];
        if f.read_exact(&mut magic).is_err() {
            return torn(f, start, truncate, out);
        }
        pos += 8;
        if &magic != MAGIC {
            return Err("journal chain corruption".into());
        }
        let mut lb = [0; 4];
        if f.read_exact(&mut lb).is_err() {
            return torn(f, start, truncate, out);
        }
        pos += 4;
        let n = u32::from_le_bytes(lb) as usize;
        if n > 1024 * 1024 {
            return Err("journal record too large".into());
        }
        let mut body = vec![0; n];
        let mut digest = [0; 32];
        let mut commit = [0; 8];
        if f.read_exact(&mut body)
            .and_then(|_| f.read_exact(&mut digest))
            .and_then(|_| f.read_exact(&mut commit))
            .is_err()
        {
            return torn(f, start, truncate, out);
        }
        pos += n as u64 + 40;
        if digest[..] != Sha256::digest(&body)[..] || &commit != COMMIT {
            return Err("journal committed frame corruption".into());
        }
        let r: Record = serde_json::from_slice(&body).map_err(err)?;
        if r.plan_hash != plan
            || r.sequence != out.len() as u64
            || r.previous_hash != out.last().map(Record::hash).transpose()?
        {
            return Err("journal stale plan or hash-chain corruption".into());
        }
        out.push(r)
    }
    Ok(out)
}
fn torn(f: &mut File, at: u64, truncate: bool, out: Vec<Record>) -> Result<Vec<Record>, String> {
    if !truncate {
        return Err("torn journal tail".into());
    }
    f.set_len(at).and_then(|_| f.sync_all()).map_err(err)?;
    Ok(out)
}
fn sync_dir(p: &Path) -> Result<(), String> {
    File::open(p).and_then(|f| f.sync_all()).map_err(err)
}
fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
