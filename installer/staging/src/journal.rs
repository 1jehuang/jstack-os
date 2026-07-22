use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use jstack_installer_core::{
    Hash256, JournalRecord, canonical_json, hash_journal_record, validate_journal_record,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    ensure_private_directory, ensure_regular_file_io, set_nofollow_flags, sync_directory,
    validate_trusted_root,
};

const JOURNAL_MAGIC: &[u8; 8] = b"JJRNLV2\0";
const JOURNAL_COMMIT: &[u8; 8] = b"JJCMIT1\0";
const HEADER_BYTES: usize = JOURNAL_MAGIC.len() + 2 * std::mem::size_of::<u32>();
const TRAILER_BYTES: usize = 32 + JOURNAL_COMMIT.len();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLimits {
    pub maximum_log_bytes: u64,
    pub maximum_record_bytes: u32,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            maximum_log_bytes: 16 * 1024 * 1024,
            maximum_record_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalFaultPoint {
    AfterLock,
    AfterFrameWrite,
    AfterFrameSync,
    AfterCommitWrite,
    AfterCommitSync,
    BeforeReadback,
}

pub trait JournalFaultInjector {
    fn should_fail(&mut self, point: JournalFaultPoint) -> bool;
}

#[derive(Default)]
pub struct NoJournalFaults;

impl JournalFaultInjector for NoJournalFaults {
    fn should_fail(&mut self, _point: JournalFaultPoint) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal root or entry is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("durable mutation journal is corrupt")]
    Corrupt,
    #[error("journal record does not match the bound plan or prior durable head")]
    ChainMismatch,
    #[error("durable mutation journal exceeds its configured byte limit")]
    LogFull,
    #[error("journal record exceeds its configured byte limit")]
    RecordTooLarge,
    #[error("injected mutation journal crash at {0:?}")]
    Injected(JournalFaultPoint),
    #[error("journal filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("journal JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("journal JSON cannot be canonicalized: {0}")]
    Canonical(#[from] jstack_installer_core::canonical::CanonicalError),
    #[error("journal record is semantically invalid: {0}")]
    Integrity(#[from] jstack_installer_core::integrity::IntegrityError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalReconcileReport {
    pub records: Vec<JournalRecord>,
    pub truncated_tail_bytes: u64,
}

pub struct DurableJournal<I = NoJournalFaults> {
    root: PathBuf,
    path: PathBuf,
    plan_hash: Hash256,
    limits: JournalLimits,
    injector: I,
}

impl DurableJournal<NoJournalFaults> {
    pub fn open(root: impl AsRef<Path>, plan_hash: &Hash256) -> Result<Self, JournalError> {
        Self::open_with(root, plan_hash, JournalLimits::default(), NoJournalFaults)
    }
}

impl<I: JournalFaultInjector> DurableJournal<I> {
    pub fn open_with(
        root: impl AsRef<Path>,
        plan_hash: &Hash256,
        limits: JournalLimits,
        injector: I,
    ) -> Result<Self, JournalError> {
        if limits.maximum_record_bytes == 0
            || limits.maximum_log_bytes < (HEADER_BYTES + TRAILER_BYTES + 2) as u64
        {
            return Err(JournalError::LogFull);
        }
        let root = root.as_ref();
        validate_trusted_root(root).map_err(map_staging_error)?;
        ensure_private_directory(root, "journal").map_err(map_staging_error)?;
        let path = root
            .join("journal")
            .join(format!("{}.wal", plan_hash.as_str()));
        let journal = Self {
            root: root.to_path_buf(),
            path,
            plan_hash: plan_hash.clone(),
            limits,
            injector,
        };
        let file = journal.open_file()?;
        file.sync_all()?;
        sync_directory(
            journal
                .path
                .parent()
                .ok_or_else(|| JournalError::UnsafePath(journal.path.clone()))?,
        )?;
        Ok(journal)
    }

    pub fn read_all(&mut self) -> Result<Vec<JournalRecord>, JournalError> {
        Ok(self.reconcile()?.records)
    }

    pub fn reconcile(&mut self) -> Result<JournalReconcileReport, JournalError> {
        let mut file = self.open_file()?;
        FileExt::lock(&file)?;
        let result = self.parse_locked(&mut file, true);
        let unlock = FileExt::unlock(&file);
        match (result, unlock) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    pub fn append(&mut self, record: &JournalRecord) -> Result<Hash256, JournalError> {
        if record.plan_hash != self.plan_hash {
            return Err(JournalError::ChainMismatch);
        }
        let body = canonical_json(record)?;
        let body_length = u32::try_from(body.len()).map_err(|_| JournalError::RecordTooLarge)?;
        if body_length > self.limits.maximum_record_bytes {
            return Err(JournalError::RecordTooLarge);
        }
        let mut file = self.open_file()?;
        FileExt::lock(&file)?;
        let result = self.append_locked(&mut file, record, &body, body_length);
        let unlock = FileExt::unlock(&file);
        match (result, unlock) {
            (Ok(hash), Ok(())) => Ok(hash),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn append_locked(
        &mut self,
        file: &mut File,
        record: &JournalRecord,
        body: &[u8],
        body_length: u32,
    ) -> Result<Hash256, JournalError> {
        self.hit(JournalFaultPoint::AfterLock)?;
        let report = self.parse_locked(file, true)?;
        if report.records.last() == Some(record) {
            return Ok(hash_journal_record(record)?);
        }
        let previous = report.records.last();
        validate_journal_record(record, previous).map_err(|_| JournalError::ChainMismatch)?;
        if record.plan_hash != self.plan_hash {
            return Err(JournalError::ChainMismatch);
        }

        let frame_bytes = HEADER_BYTES
            .checked_add(body.len())
            .and_then(|bytes| bytes.checked_add(TRAILER_BYTES))
            .ok_or(JournalError::LogFull)?;
        let current_length = file.metadata()?.len();
        if current_length
            .checked_add(frame_bytes as u64)
            .is_none_or(|length| length > self.limits.maximum_log_bytes)
        {
            return Err(JournalError::LogFull);
        }

        file.seek(SeekFrom::End(0))?;
        file.write_all(JOURNAL_MAGIC)?;
        file.write_all(&body_length.to_le_bytes())?;
        file.write_all(&(!body_length).to_le_bytes())?;
        file.write_all(body)?;
        file.write_all(&Sha256::digest(body))?;
        self.hit(JournalFaultPoint::AfterFrameWrite)?;
        file.sync_data()?;
        self.hit(JournalFaultPoint::AfterFrameSync)?;
        file.write_all(JOURNAL_COMMIT)?;
        self.hit(JournalFaultPoint::AfterCommitWrite)?;
        file.sync_all()?;
        self.hit(JournalFaultPoint::AfterCommitSync)?;
        self.hit(JournalFaultPoint::BeforeReadback)?;

        let readback = self.parse_locked(file, false)?;
        if readback.records.last() != Some(record) {
            return Err(JournalError::Corrupt);
        }
        Ok(hash_journal_record(record)?)
    }

    fn parse_locked(
        &self,
        file: &mut File,
        truncate_torn_tail: bool,
    ) -> Result<JournalReconcileReport, JournalError> {
        let file_length = file.metadata()?.len();
        if file_length > self.limits.maximum_log_bytes {
            return Err(JournalError::LogFull);
        }
        file.seek(SeekFrom::Start(0))?;
        let mut records = Vec::new();
        let mut offset = 0_u64;
        while offset < file_length {
            let remaining = file_length - offset;
            if remaining < HEADER_BYTES as u64 {
                return self.finish_torn_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            let mut magic = [0_u8; 8];
            file.read_exact(&mut magic)?;
            if &magic != JOURNAL_MAGIC {
                return self.finish_invalid_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            let mut length_bytes = [0_u8; 4];
            file.read_exact(&mut length_bytes)?;
            let body_length = u32::from_le_bytes(length_bytes);
            let mut inverse_length_bytes = [0_u8; 4];
            file.read_exact(&mut inverse_length_bytes)?;
            let inverse_body_length = u32::from_le_bytes(inverse_length_bytes);
            if inverse_body_length != !body_length {
                return self.finish_invalid_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            if body_length == 0 || body_length > self.limits.maximum_record_bytes {
                return self.finish_invalid_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            let frame_length = (HEADER_BYTES as u64)
                .checked_add(u64::from(body_length))
                .and_then(|length| length.checked_add(TRAILER_BYTES as u64))
                .ok_or(JournalError::Corrupt)?;
            if frame_length > remaining {
                return self.finish_invalid_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            let capacity =
                usize::try_from(body_length).map_err(|_| JournalError::RecordTooLarge)?;
            let mut body = vec![0_u8; capacity];
            file.read_exact(&mut body)?;
            let mut expected_digest = [0_u8; 32];
            file.read_exact(&mut expected_digest)?;
            let mut commit = [0_u8; 8];
            file.read_exact(&mut commit)?;
            if commit != *JOURNAL_COMMIT {
                return self.finish_invalid_tail(
                    file,
                    records,
                    offset,
                    file_length,
                    truncate_torn_tail,
                );
            }
            if Sha256::digest(&body).as_slice() != expected_digest {
                return Err(JournalError::Corrupt);
            }
            let record: JournalRecord = serde_json::from_slice(&body)?;
            if canonical_json(&record)? != body
                || record.plan_hash != self.plan_hash
                || validate_journal_record(&record, records.last()).is_err()
            {
                return Err(JournalError::Corrupt);
            }
            records.push(record);
            offset = offset
                .checked_add(frame_length)
                .ok_or(JournalError::Corrupt)?;
        }
        Ok(JournalReconcileReport {
            records,
            truncated_tail_bytes: 0,
        })
    }

    fn finish_invalid_tail(
        &self,
        file: &mut File,
        records: Vec<JournalRecord>,
        durable_length: u64,
        file_length: u64,
        truncate: bool,
    ) -> Result<JournalReconcileReport, JournalError> {
        if !truncate {
            return Err(JournalError::Corrupt);
        }
        file.seek(SeekFrom::Start(durable_length))?;
        let tail_length =
            usize::try_from(file_length - durable_length).map_err(|_| JournalError::Corrupt)?;
        let mut tail = vec![0_u8; tail_length];
        file.read_exact(&mut tail)?;
        if tail
            .windows(JOURNAL_COMMIT.len())
            .any(|window| window == JOURNAL_COMMIT)
        {
            return Err(JournalError::Corrupt);
        }
        self.finish_torn_tail(file, records, durable_length, file_length, truncate)
    }

    fn finish_torn_tail(
        &self,
        file: &mut File,
        records: Vec<JournalRecord>,
        durable_length: u64,
        file_length: u64,
        truncate: bool,
    ) -> Result<JournalReconcileReport, JournalError> {
        if !truncate {
            return Err(JournalError::Corrupt);
        }
        file.set_len(durable_length)?;
        file.sync_all()?;
        Ok(JournalReconcileReport {
            records,
            truncated_tail_bytes: file_length - durable_length,
        })
    }

    fn open_file(&self) -> Result<File, JournalError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        set_nofollow_flags(&mut options, true);
        let file = options.open(&self.path)?;
        ensure_regular_file_io(&file, &self.path)
            .map_err(|_| JournalError::UnsafePath(self.path.clone()))?;
        ensure_single_link(&file, &self.path)?;
        Ok(file)
    }

    fn hit(&mut self, point: JournalFaultPoint) -> Result<(), JournalError> {
        if self.injector.should_fail(point) {
            Err(JournalError::Injected(point))
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(unix)]
fn ensure_single_link(file: &File, path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::MetadataExt;

    if file.metadata()?.nlink() != 1 {
        return Err(JournalError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_single_link(_file: &File, _path: &Path) -> Result<(), JournalError> {
    Ok(())
}

fn map_staging_error(error: super::StagingError) -> JournalError {
    match error {
        super::StagingError::UnsafePath(path) | super::StagingError::UnexpectedEntry(path) => {
            JournalError::UnsafePath(path)
        }
        super::StagingError::Io(error) => JournalError::Io(error),
        _ => JournalError::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jstack_installer_core::{
        CONTRACT_SCHEMA_VERSION, JournalRecordType, RollbackObject, hash_journal_record,
    };
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone)]
    struct FailOnce {
        point: JournalFaultPoint,
        fired: bool,
    }

    impl JournalFaultInjector for FailOnce {
        fn should_fail(&mut self, point: JournalFaultPoint) -> bool {
            if !self.fired && point == self.point {
                self.fired = true;
                true
            } else {
                false
            }
        }
    }

    fn hash(byte: &str) -> Hash256 {
        Hash256::parse(byte.repeat(64)).unwrap()
    }

    fn record(previous: Option<&JournalRecord>, plan_hash: &Hash256) -> JournalRecord {
        JournalRecord {
            schema_version: CONTRACT_SCHEMA_VERSION,
            sequence: previous.map_or(0, |record| record.sequence + 1),
            previous_record_hash: previous.map(|record| hash_journal_record(record).unwrap()),
            actor: "windows_bootstrap".into(),
            transition_id: "copy_verified_payload".into(),
            record_type: match previous.map(|record| record.record_type) {
                None => JournalRecordType::ActionIntent,
                Some(JournalRecordType::ActionIntent) => JournalRecordType::ActionCommitted,
                Some(JournalRecordType::ActionCommitted | JournalRecordType::ActionFailed) => {
                    JournalRecordType::StateAdvanced
                }
                Some(JournalRecordType::StateAdvanced) => JournalRecordType::ActionIntent,
            },
            precondition_hash: previous
                .and_then(|record| record.postcondition_hash.clone())
                .unwrap_or_else(|| hash("1")),
            postcondition_hash: match previous.map(|record| record.record_type) {
                None | Some(JournalRecordType::StateAdvanced) => None,
                Some(_) => Some(hash("2")),
            },
            plan_hash: plan_hash.clone(),
            created_objects: Vec::<RollbackObject>::new(),
        }
    }

    #[test]
    fn appends_canonical_monotonic_records_and_is_idempotent() {
        let temporary = TempDir::new().unwrap();
        let plan_hash = hash("a");
        let mut journal = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
        let intent = record(None, &plan_hash);
        let committed = record(Some(&intent), &plan_hash);
        journal.append(&intent).unwrap();
        journal.append(&intent).unwrap();
        journal.append(&committed).unwrap();
        assert_eq!(journal.read_all().unwrap(), vec![intent, committed]);
    }

    #[test]
    fn every_fault_point_reconciles_to_a_valid_prefix_and_retry_is_safe() {
        let points = [
            JournalFaultPoint::AfterLock,
            JournalFaultPoint::AfterFrameWrite,
            JournalFaultPoint::AfterFrameSync,
            JournalFaultPoint::AfterCommitWrite,
            JournalFaultPoint::AfterCommitSync,
            JournalFaultPoint::BeforeReadback,
        ];
        for point in points {
            let temporary = TempDir::new().unwrap();
            let plan_hash = hash("b");
            let intent = record(None, &plan_hash);
            let mut crashing = DurableJournal::open_with(
                temporary.path(),
                &plan_hash,
                JournalLimits::default(),
                FailOnce {
                    point,
                    fired: false,
                },
            )
            .unwrap();
            assert!(matches!(
                crashing.append(&intent),
                Err(JournalError::Injected(actual)) if actual == point
            ));
            drop(crashing);
            let mut recovered = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
            let prefix = recovered.read_all().unwrap();
            assert!(prefix.is_empty() || prefix == vec![intent.clone()]);
            recovered.append(&intent).unwrap();
            assert_eq!(recovered.read_all().unwrap(), vec![intent.clone()]);
        }
    }

    #[test]
    fn torn_tail_is_truncated_but_committed_corruption_hard_stops() {
        let temporary = TempDir::new().unwrap();
        let plan_hash = hash("c");
        let mut journal = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
        let intent = record(None, &plan_hash);
        journal.append(&intent).unwrap();
        let durable_length = fs::metadata(journal.path()).unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(journal.path())
            .unwrap()
            .write_all(&JOURNAL_MAGIC[..3])
            .unwrap();
        let report = journal.reconcile().unwrap();
        assert_eq!(report.records, vec![intent]);
        assert_eq!(fs::metadata(journal.path()).unwrap().len(), durable_length);

        let mut bytes = fs::read(journal.path()).unwrap();
        bytes[HEADER_BYTES] ^= 1;
        fs::write(journal.path(), bytes).unwrap();
        assert!(matches!(journal.read_all(), Err(JournalError::Corrupt)));
    }

    #[test]
    fn committed_header_length_corruption_is_never_misclassified_as_a_torn_tail() {
        let temporary = TempDir::new().unwrap();
        let plan_hash = hash("9");
        let intent = record(None, &plan_hash);

        for range in [8..12, 12..16] {
            let mut journal = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
            journal.append(&intent).unwrap();
            let original = fs::read(journal.path()).unwrap();
            let mut corrupted = original.clone();
            corrupted[range.start] ^= 1;
            fs::write(journal.path(), corrupted).unwrap();

            assert!(matches!(journal.reconcile(), Err(JournalError::Corrupt)));
            assert_eq!(fs::read(journal.path()).unwrap().len(), original.len());

            fs::remove_file(journal.path()).unwrap();
        }
    }

    #[test]
    fn complete_but_invalid_uncommitted_headers_are_truncated_as_torn_tails() {
        let temporary = TempDir::new().unwrap();
        let plan_hash = hash("8");
        let mut journal = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
        let intent = record(None, &plan_hash);
        journal.append(&intent).unwrap();
        let durable_length = fs::metadata(journal.path()).unwrap().len();

        for tail in [
            [
                JOURNAL_MAGIC.as_slice(),
                &0_u32.to_le_bytes(),
                &u32::MAX.to_le_bytes(),
            ]
            .concat(),
            [
                JOURNAL_MAGIC.as_slice(),
                &1_u32.to_le_bytes(),
                &0_u32.to_le_bytes(),
            ]
            .concat(),
            [b"BROKEN!!".as_slice(), &0_u64.to_le_bytes()].concat(),
        ] {
            OpenOptions::new()
                .append(true)
                .open(journal.path())
                .unwrap()
                .write_all(&tail)
                .unwrap();
            let report = journal.reconcile().unwrap();
            assert_eq!(report.records, vec![intent.clone()]);
            assert_eq!(report.truncated_tail_bytes, tail.len() as u64);
            assert_eq!(fs::metadata(journal.path()).unwrap().len(), durable_length);
        }
    }

    #[test]
    fn rejects_forks_wrong_plans_limits_and_symlink_entries() {
        let temporary = TempDir::new().unwrap();
        let plan_hash = hash("d");
        let mut journal = DurableJournal::open(temporary.path(), &plan_hash).unwrap();
        let intent = record(None, &plan_hash);
        journal.append(&intent).unwrap();

        let mut fork = intent.clone();
        fork.precondition_hash = hash("e");
        assert!(matches!(
            journal.append(&fork),
            Err(JournalError::ChainMismatch)
        ));
        let wrong = record(None, &hash("f"));
        assert!(matches!(
            journal.append(&wrong),
            Err(JournalError::ChainMismatch)
        ));

        let mut tiny = DurableJournal::open_with(
            temporary.path(),
            &plan_hash,
            JournalLimits {
                maximum_log_bytes: 128,
                maximum_record_bytes: 32,
            },
            NoJournalFaults,
        )
        .unwrap();
        assert!(matches!(
            tiny.append(&intent),
            Err(JournalError::RecordTooLarge)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let other = TempDir::new().unwrap();
            let symlink_root = TempDir::new().unwrap();
            fs::create_dir(symlink_root.path().join("journal")).unwrap();
            let path = symlink_root
                .path()
                .join("journal")
                .join(format!("{}.wal", plan_hash.as_str()));
            symlink(other.path().join("target"), &path).unwrap();
            assert!(DurableJournal::open(symlink_root.path(), &plan_hash).is_err());

            fs::hard_link(
                journal.path(),
                temporary.path().join("journal-hardlink-alias"),
            )
            .unwrap();
            assert!(matches!(
                journal.read_all(),
                Err(JournalError::UnsafePath(_))
            ));
        }
    }
}
