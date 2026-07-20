#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use fs4::FileExt;
use jstack_installer_core::canonical::CanonicalError;
use jstack_installer_core::{
    ArtifactDescriptor, ArtifactRole, Hash256, PendingReleaseManifest, ReleaseAcceptanceState,
    ReleaseChannel, ReleaseError, VerifiedReleaseManifest, canonical_json, canonical_sha256,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ACCEPTANCE_MAGIC: &[u8; 8] = b"JSACTV1\0";
const ACCEPTANCE_COMMIT: &[u8; 8] = b"JSCMIT1\0";
const ACCEPTANCE_HEADER_BYTES: usize = ACCEPTANCE_MAGIC.len() + std::mem::size_of::<u32>();
const ACCEPTANCE_TRAILER_BYTES: usize = 32 + ACCEPTANCE_COMMIT.len();
const MAX_ACCEPTANCE_RECORD_BYTES: usize = 4 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const REQUIRED_ARTIFACT_ROLES: [ArtifactRole; 4] = [
    ArtifactRole::EspLoader,
    ArtifactRole::InstallerUki,
    ArtifactRole::OfflineSystemImage,
    ArtifactRole::RecoveryUki,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub maximum_acceptance_log_bytes: u64,
    pub maximum_evidence_bytes: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            maximum_acceptance_log_bytes: 8 * 1024 * 1024,
            maximum_evidence_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FaultPoint {
    AcceptanceAfterLock,
    AcceptanceAfterRecordWrite,
    AcceptanceAfterRecordSync,
    AcceptanceAfterCommitWrite,
    AcceptanceAfterCommitSync,
    AcceptanceBeforeReadback,
    ArtifactAfterQuarantineOpen,
    ArtifactAfterChunkWrite,
    ArtifactAfterChunkSync,
    ArtifactAfterFullVerify,
    ArtifactAfterFileSync,
    ArtifactAfterPromote,
    ArtifactAfterPromotionSync,
    ArtifactAfterQuarantineRemove,
    EvidenceAfterWrite,
    EvidenceAfterFileSync,
    EvidenceAfterPromote,
    EvidenceAfterPromotionSync,
}

pub trait FaultInjector {
    fn should_fail(&mut self, point: FaultPoint) -> bool;
}

#[derive(Default)]
pub struct NoFaultInjector;

impl FaultInjector for NoFaultInjector {
    fn should_fail(&mut self, _point: FaultPoint) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum StagingError {
    #[error("staging root must be an existing absolute directory")]
    InvalidRoot,
    #[error("staging path contains a symlink, reparse point, or non-directory component: {0}")]
    UnsafePath(PathBuf),
    #[error("staging store contains an unexpected entry: {0}")]
    UnexpectedEntry(PathBuf),
    #[error("durable acceptance log is corrupt")]
    AcceptanceCorrupt,
    #[error("durable acceptance state changed since release verification")]
    AcceptanceChanged,
    #[error("durable acceptance log exceeds its configured byte limit")]
    AcceptanceLogFull,
    #[error("artifact source offset {actual} does not match durable resume offset {expected}")]
    ResumeOffsetMismatch { expected: u64, actual: u64 },
    #[error("quarantined artifact {role:?} chunk {index} is corrupt")]
    QuarantineChunkMismatch { role: ArtifactRole, index: usize },
    #[error("existing promoted artifact {0:?} is corrupt")]
    ExistingArtifactInvalid(ArtifactRole),
    #[error("required staged artifact is missing: {0:?}")]
    MissingArtifact(ArtifactRole),
    #[error("durable staging evidence is invalid")]
    InvalidStagingEvidence,
    #[error("durable staging evidence exceeds its configured byte limit")]
    EvidenceTooLarge,
    #[error("injected staging crash at {0:?}")]
    Injected(FaultPoint),
    #[error("filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("staging JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("staging JSON cannot be canonicalized: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("release verification failed: {0}")]
    Release(#[from] ReleaseError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedArtifactEvidence {
    pub role: ArtifactRole,
    pub size_bytes: u64,
    pub sha256: Hash256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingEvidence {
    pub schema_version: u32,
    pub manifest_digest: Hash256,
    pub acceptance_state_hash: Hash256,
    pub artifacts: Vec<StagedArtifactEvidence>,
}

#[derive(Debug)]
pub struct DurableStagingEvidence {
    evidence: StagingEvidence,
    evidence_hash: Hash256,
}

impl DurableStagingEvidence {
    pub fn evidence(&self) -> &StagingEvidence {
        &self.evidence
    }

    pub fn evidence_hash(&self) -> &Hash256 {
        &self.evidence_hash
    }
}

#[derive(Debug)]
pub enum StageProgress {
    Incomplete { next_offset: u64 },
    Complete(StagedArtifact),
}

#[derive(Debug)]
pub struct StagedArtifact {
    file: File,
    descriptor: ArtifactDescriptor,
    manifest_digest: Hash256,
}

impl StagedArtifact {
    pub fn role(&self) -> ArtifactRole {
        self.descriptor.role
    }

    pub fn size_bytes(&self) -> u64 {
        self.descriptor.size_bytes
    }

    pub fn sha256(&self) -> &Hash256 {
        &self.descriptor.sha256
    }

    pub fn manifest_digest(&self) -> &Hash256 {
        &self.manifest_digest
    }

    pub fn verify_integrity(
        &mut self,
        release: &VerifiedReleaseManifest,
    ) -> Result<(), StagingError> {
        if release.manifest_digest() != &self.manifest_digest
            || release.artifact_descriptor(self.descriptor.role)? != &self.descriptor
        {
            return Err(StagingError::InvalidStagingEvidence);
        }
        self.file.seek(SeekFrom::Start(0))?;
        release.verify_artifact(self.descriptor.role, &mut self.file)?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}

pub struct StagingStore<I = NoFaultInjector> {
    root: PathBuf,
    limits: StoreLimits,
    injector: I,
}

impl StagingStore<NoFaultInjector> {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StagingError> {
        Self::open_with(root, StoreLimits::default(), NoFaultInjector)
    }

    pub fn open_with_limits(
        root: impl AsRef<Path>,
        limits: StoreLimits,
    ) -> Result<Self, StagingError> {
        Self::open_with(root, limits, NoFaultInjector)
    }
}

impl<I: FaultInjector> StagingStore<I> {
    pub fn open_with(
        root: impl AsRef<Path>,
        limits: StoreLimits,
        injector: I,
    ) -> Result<Self, StagingError> {
        if limits.maximum_acceptance_log_bytes < 4096 || limits.maximum_evidence_bytes < 1024 {
            return Err(StagingError::AcceptanceLogFull);
        }
        let root = root.as_ref();
        validate_trusted_root(root)?;
        for child in ["acceptance", "quarantine", "artifacts", "evidence"] {
            ensure_private_directory(root, child)?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            limits,
            injector,
        })
    }

    pub fn read_acceptance(
        &mut self,
        channel: ReleaseChannel,
        state_model_sha256: &Hash256,
    ) -> Result<Option<ReleaseAcceptanceState>, StagingError> {
        let _lock = self.lock_store()?;
        self.read_acceptance_locked(channel, state_model_sha256)
    }

    pub fn persist_acceptance(
        &mut self,
        pending: PendingReleaseManifest,
    ) -> Result<VerifiedReleaseManifest, StagingError> {
        let _lock = self.lock_store()?;
        self.hit(FaultPoint::AcceptanceAfterLock)?;

        let required = pending.required_acceptance().clone();
        let current =
            self.read_acceptance_locked(required.channel, &required.state_model_sha256)?;
        if current.as_ref() != pending.expected_previous_acceptance() {
            return Err(StagingError::AcceptanceChanged);
        }
        if current.as_ref() != Some(&required) {
            self.append_acceptance_locked(&required)?;
        }
        self.hit(FaultPoint::AcceptanceBeforeReadback)?;
        let readback = self
            .read_acceptance_locked(required.channel, &required.state_model_sha256)?
            .ok_or(StagingError::AcceptanceCorrupt)?;
        if readback != required {
            return Err(StagingError::AcceptanceCorrupt);
        }
        Ok(pending.accept_after_persist(&readback)?)
    }

    pub fn artifact_resume_offset(
        &mut self,
        release: &VerifiedReleaseManifest,
        role: ArtifactRole,
    ) -> Result<u64, StagingError> {
        let _lock = self.lock_store()?;
        if self.open_staged_locked(release, role)?.is_some() {
            return Ok(release.artifact_descriptor(role)?.size_bytes);
        }
        let descriptor = release.artifact_descriptor(role)?.clone();
        let path = self.quarantine_path(release.manifest_digest(), &descriptor);
        let mut file = open_quarantine(&path)?;
        self.reconcile_quarantine_prefix(&mut file, &descriptor)
    }

    pub fn stage_artifact<R: Read>(
        &mut self,
        release: &VerifiedReleaseManifest,
        role: ArtifactRole,
        source_offset: u64,
        source: &mut R,
    ) -> Result<StageProgress, StagingError> {
        let _lock = self.lock_store()?;
        if let Some(staged) = self.open_staged_locked(release, role)? {
            return Ok(StageProgress::Complete(staged));
        }

        let descriptor = release.artifact_descriptor(role)?.clone();
        let quarantine_path = self.quarantine_path(release.manifest_digest(), &descriptor);
        let mut file = open_quarantine(&quarantine_path)?;
        self.hit(FaultPoint::ArtifactAfterQuarantineOpen)?;
        let expected_offset = self.reconcile_quarantine_prefix(&mut file, &descriptor)?;
        if source_offset != expected_offset {
            return Err(StagingError::ResumeOffsetMismatch {
                expected: expected_offset,
                actual: source_offset,
            });
        }
        file.seek(SeekFrom::Start(expected_offset))?;

        let mut offset = expected_offset;
        let chunk_size = u64::from(descriptor.chunk_size_bytes);
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        while offset < descriptor.size_bytes {
            let chunk_index = usize::try_from(offset / chunk_size)
                .map_err(|_| StagingError::AcceptanceCorrupt)?;
            let chunk_start = offset;
            let chunk_length = (descriptor.size_bytes - offset).min(chunk_size);
            let mut remaining = chunk_length;
            let mut digest = Sha256::new();
            while remaining > 0 {
                let wanted = remaining.min(buffer.len() as u64) as usize;
                let read = source.read(&mut buffer[..wanted])?;
                if read == 0 {
                    file.set_len(chunk_start)?;
                    file.sync_all()?;
                    return Ok(StageProgress::Incomplete {
                        next_offset: chunk_start,
                    });
                }
                file.write_all(&buffer[..read])?;
                digest.update(&buffer[..read]);
                remaining -= read as u64;
                offset += read as u64;
                self.hit(FaultPoint::ArtifactAfterChunkWrite)?;
            }
            if Hash256::from_bytes(digest.finalize().into()) != descriptor.chunk_sha256[chunk_index]
            {
                file.set_len(chunk_start)?;
                file.sync_all()?;
                return Err(StagingError::QuarantineChunkMismatch {
                    role,
                    index: chunk_index,
                });
            }
            file.sync_data()?;
            self.hit(FaultPoint::ArtifactAfterChunkSync)?;
        }

        let mut trailing = [0_u8; 1];
        if source.read(&mut trailing)? != 0 {
            return Err(StagingError::Release(ReleaseError::ArtifactTrailingBytes(
                role,
            )));
        }
        file.seek(SeekFrom::Start(0))?;
        release.verify_artifact(role, &mut file)?;
        self.hit(FaultPoint::ArtifactAfterFullVerify)?;
        file.sync_all()?;
        self.hit(FaultPoint::ArtifactAfterFileSync)?;

        let final_path = self.artifact_path(&descriptor.sha256);
        match fs::hard_link(&quarantine_path, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut existing = open_regular_read(&final_path)?;
                if release.verify_artifact(role, &mut existing).is_err() {
                    return Err(StagingError::ExistingArtifactInvalid(role));
                }
            }
            Err(error) => return Err(error.into()),
        }
        self.hit(FaultPoint::ArtifactAfterPromote)?;
        let promoted = open_regular_read(&final_path)?;
        promoted.sync_all()?;
        sync_directory(final_path.parent().ok_or(StagingError::InvalidRoot)?)?;
        self.hit(FaultPoint::ArtifactAfterPromotionSync)?;

        remove_file_if_present(&quarantine_path)?;
        sync_directory(quarantine_path.parent().ok_or(StagingError::InvalidRoot)?)?;
        self.hit(FaultPoint::ArtifactAfterQuarantineRemove)?;
        let staged = self
            .open_staged_locked(release, role)?
            .ok_or(StagingError::MissingArtifact(role))?;
        Ok(StageProgress::Complete(staged))
    }

    pub fn open_staged_artifact(
        &mut self,
        release: &VerifiedReleaseManifest,
        role: ArtifactRole,
    ) -> Result<StagedArtifact, StagingError> {
        let _lock = self.lock_store()?;
        self.open_staged_locked(release, role)?
            .ok_or(StagingError::MissingArtifact(role))
    }

    pub fn persist_staging_evidence(
        &mut self,
        release: &VerifiedReleaseManifest,
    ) -> Result<DurableStagingEvidence, StagingError> {
        let _lock = self.lock_store()?;
        let evidence = self.build_evidence_locked(release)?;
        let bytes = canonical_json(&evidence)?;
        if bytes.len() as u64 > self.limits.maximum_evidence_bytes {
            return Err(StagingError::EvidenceTooLarge);
        }
        let evidence_hash = canonical_sha256(&evidence)?;
        let final_path = self.evidence_path(&evidence_hash);
        match self.read_evidence_locked(release, &evidence_hash) {
            Ok(existing) => return Ok(existing),
            Err(StagingError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let temporary_path = self
            .root
            .join("evidence")
            .join(format!("{}.part", evidence_hash.as_str()));
        let temporary = match create_new_regular(&temporary_path) {
            Ok(mut temporary) => {
                temporary.write_all(&bytes)?;
                temporary
            }
            Err(StagingError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut existing = open_regular_read(&temporary_path)?;
                let existing_bytes =
                    read_bounded_evidence(&mut existing, self.limits.maximum_evidence_bytes)?;
                drop(existing);
                if existing_bytes != bytes {
                    remove_file_if_present(&temporary_path)?;
                    let mut replacement = create_new_regular(&temporary_path)?;
                    replacement.write_all(&bytes)?;
                    replacement
                } else {
                    open_regular_write(&temporary_path)?
                }
            }
            Err(error) => return Err(error),
        };
        self.hit(FaultPoint::EvidenceAfterWrite)?;
        temporary.sync_all()?;
        self.hit(FaultPoint::EvidenceAfterFileSync)?;
        match fs::hard_link(&temporary_path, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        self.hit(FaultPoint::EvidenceAfterPromote)?;
        let promoted = open_regular_read(&final_path)?;
        promoted.sync_all()?;
        sync_directory(final_path.parent().ok_or(StagingError::InvalidRoot)?)?;
        self.hit(FaultPoint::EvidenceAfterPromotionSync)?;
        remove_file_if_present(&temporary_path)?;
        self.read_evidence_locked(release, &evidence_hash)
    }

    pub fn read_staging_evidence(
        &mut self,
        release: &VerifiedReleaseManifest,
        evidence_hash: &Hash256,
    ) -> Result<DurableStagingEvidence, StagingError> {
        let _lock = self.lock_store()?;
        self.read_evidence_locked(release, evidence_hash)
    }

    pub fn reconcile(&mut self) -> Result<ReconcileReport, StagingError> {
        let _lock = self.lock_store()?;
        let mut removed_entries = 0_usize;
        let mut resumable_artifacts = 0_usize;
        for entry in fs::read_dir(self.root.join("quarantine"))? {
            let entry = entry?;
            let path = entry.path();
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => {
                    remove_untrusted_cache_entry(&path)?;
                    removed_entries += 1;
                    continue;
                }
            };
            if valid_quarantine_name(&name) {
                ensure_regular_path(&path)?;
                resumable_artifacts += 1;
            } else {
                remove_untrusted_cache_entry(&path)?;
                removed_entries += 1;
            }
        }
        for directory in ["artifacts", "evidence"] {
            for entry in fs::read_dir(self.root.join(directory))? {
                let entry = entry?;
                let path = entry.path();
                let name = match entry.file_name().into_string() {
                    Ok(name) => name,
                    Err(_) => {
                        remove_untrusted_cache_entry(&path)?;
                        removed_entries += 1;
                        continue;
                    }
                };
                let valid = match directory {
                    "artifacts" => valid_artifact_name(&name),
                    "evidence" => valid_evidence_name(&name),
                    _ => false,
                };
                if valid {
                    ensure_regular_path(&path)?;
                } else {
                    remove_untrusted_cache_entry(&path)?;
                    removed_entries += 1;
                }
            }
        }
        Ok(ReconcileReport {
            removed_entries,
            resumable_artifacts,
        })
    }

    fn hit(&mut self, point: FaultPoint) -> Result<(), StagingError> {
        if self.injector.should_fail(point) {
            Err(StagingError::Injected(point))
        } else {
            Ok(())
        }
    }

    fn lock_store(&self) -> Result<File, StagingError> {
        let path = self.root.join(".staging.lock");
        let file = open_lock_file(&path)?;
        FileExt::lock(&file)?;
        Ok(file)
    }

    fn read_acceptance_locked(
        &self,
        channel: ReleaseChannel,
        state_model_sha256: &Hash256,
    ) -> Result<Option<ReleaseAcceptanceState>, StagingError> {
        let path = self.acceptance_log_path(channel, state_model_sha256);
        let mut file = open_acceptance_log(&path)?;
        let states = parse_acceptance_log(
            &mut file,
            channel,
            state_model_sha256,
            self.limits.maximum_acceptance_log_bytes,
        )?;
        Ok(states.last().cloned())
    }

    fn append_acceptance_locked(
        &mut self,
        state: &ReleaseAcceptanceState,
    ) -> Result<(), StagingError> {
        let body = canonical_json(state)?;
        if body.len() > MAX_ACCEPTANCE_RECORD_BYTES {
            return Err(StagingError::AcceptanceCorrupt);
        }
        let path = self.acceptance_log_path(state.channel, &state.state_model_sha256);
        let mut file = open_acceptance_log(&path)?;
        let existing = parse_acceptance_log(
            &mut file,
            state.channel,
            &state.state_model_sha256,
            self.limits.maximum_acceptance_log_bytes,
        )?;
        validate_acceptance_append(existing.last(), state)?;

        let frame_bytes = ACCEPTANCE_HEADER_BYTES
            .checked_add(body.len())
            .and_then(|value| value.checked_add(ACCEPTANCE_TRAILER_BYTES))
            .ok_or(StagingError::AcceptanceLogFull)?;
        let next_len = file
            .metadata()?
            .len()
            .checked_add(frame_bytes as u64)
            .ok_or(StagingError::AcceptanceLogFull)?;
        if next_len > self.limits.maximum_acceptance_log_bytes {
            return Err(StagingError::AcceptanceLogFull);
        }

        file.seek(SeekFrom::End(0))?;
        file.write_all(ACCEPTANCE_MAGIC)?;
        file.write_all(&(body.len() as u32).to_be_bytes())?;
        file.write_all(&body)?;
        file.write_all(&Sha256::digest(&body))?;
        self.hit(FaultPoint::AcceptanceAfterRecordWrite)?;
        file.sync_all()?;
        self.hit(FaultPoint::AcceptanceAfterRecordSync)?;
        file.write_all(ACCEPTANCE_COMMIT)?;
        self.hit(FaultPoint::AcceptanceAfterCommitWrite)?;
        file.sync_all()?;
        self.hit(FaultPoint::AcceptanceAfterCommitSync)?;
        Ok(())
    }

    fn open_staged_locked(
        &self,
        release: &VerifiedReleaseManifest,
        role: ArtifactRole,
    ) -> Result<Option<StagedArtifact>, StagingError> {
        let descriptor = release.artifact_descriptor(role)?.clone();
        let path = self.artifact_path(&descriptor.sha256);
        let mut file = match open_regular_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if release.verify_artifact(role, &mut file).is_err() {
            return Err(StagingError::ExistingArtifactInvalid(role));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Some(StagedArtifact {
            file,
            descriptor,
            manifest_digest: release.manifest_digest().clone(),
        }))
    }

    fn reconcile_quarantine_prefix(
        &self,
        file: &mut File,
        descriptor: &ArtifactDescriptor,
    ) -> Result<u64, StagingError> {
        let length = file.metadata()?.len();
        if length > descriptor.size_bytes {
            return Err(StagingError::ExistingArtifactInvalid(descriptor.role));
        }
        file.seek(SeekFrom::Start(0))?;
        let chunk_size = u64::from(descriptor.chunk_size_bytes);
        let mut offset = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        for (index, expected) in descriptor.chunk_sha256.iter().enumerate() {
            let chunk_length = (descriptor.size_bytes - offset).min(chunk_size);
            if length - offset < chunk_length {
                file.set_len(offset)?;
                file.sync_all()?;
                return Ok(offset);
            }
            let mut remaining = chunk_length;
            let mut digest = Sha256::new();
            while remaining > 0 {
                let wanted = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..wanted])?;
                digest.update(&buffer[..wanted]);
                remaining -= wanted as u64;
            }
            if Hash256::from_bytes(digest.finalize().into()) != *expected {
                file.set_len(offset)?;
                file.sync_all()?;
                return Err(StagingError::QuarantineChunkMismatch {
                    role: descriptor.role,
                    index,
                });
            }
            offset += chunk_length;
        }
        Ok(offset)
    }

    fn build_evidence_locked(
        &self,
        release: &VerifiedReleaseManifest,
    ) -> Result<StagingEvidence, StagingError> {
        let mut artifacts = Vec::with_capacity(REQUIRED_ARTIFACT_ROLES.len());
        for role in REQUIRED_ARTIFACT_ROLES {
            let staged = self
                .open_staged_locked(release, role)?
                .ok_or(StagingError::MissingArtifact(role))?;
            artifacts.push(StagedArtifactEvidence {
                role,
                size_bytes: staged.size_bytes(),
                sha256: staged.sha256().clone(),
            });
        }
        Ok(StagingEvidence {
            schema_version: 1,
            manifest_digest: release.manifest_digest().clone(),
            acceptance_state_hash: canonical_sha256(release.acceptance())?,
            artifacts,
        })
    }

    fn read_evidence_locked(
        &self,
        release: &VerifiedReleaseManifest,
        evidence_hash: &Hash256,
    ) -> Result<DurableStagingEvidence, StagingError> {
        let path = self.evidence_path(evidence_hash);
        let mut file = open_regular_read(&path)?;
        let bytes = read_bounded_evidence(&mut file, self.limits.maximum_evidence_bytes)?;
        let evidence: StagingEvidence = serde_json::from_slice(&bytes)?;
        if canonical_json(&evidence)? != bytes
            || canonical_sha256(&evidence)? != *evidence_hash
            || evidence != self.build_evidence_locked(release)?
        {
            return Err(StagingError::InvalidStagingEvidence);
        }
        Ok(DurableStagingEvidence {
            evidence,
            evidence_hash: evidence_hash.clone(),
        })
    }

    fn acceptance_log_path(
        &self,
        channel: ReleaseChannel,
        state_model_sha256: &Hash256,
    ) -> PathBuf {
        self.root.join("acceptance").join(format!(
            "{}-{}.log",
            channel_token(channel),
            state_model_sha256.as_str()
        ))
    }

    fn quarantine_path(
        &self,
        manifest_digest: &Hash256,
        descriptor: &ArtifactDescriptor,
    ) -> PathBuf {
        self.root.join("quarantine").join(format!(
            "{}-{}-{}.part",
            manifest_digest.as_str(),
            role_token(descriptor.role),
            descriptor.sha256.as_str()
        ))
    }

    fn artifact_path(&self, digest: &Hash256) -> PathBuf {
        self.root
            .join("artifacts")
            .join(format!("{}.blob", digest.as_str()))
    }

    fn evidence_path(&self, digest: &Hash256) -> PathBuf {
        self.root
            .join("evidence")
            .join(format!("{}.json", digest.as_str()))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub removed_entries: usize,
    pub resumable_artifacts: usize,
}

fn parse_acceptance_log(
    file: &mut File,
    channel: ReleaseChannel,
    state_model_sha256: &Hash256,
    maximum_bytes: u64,
) -> Result<Vec<ReleaseAcceptanceState>, StagingError> {
    let length = file.metadata()?.len();
    if length > maximum_bytes {
        return Err(StagingError::AcceptanceLogFull);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    let mut states = Vec::new();
    let mut offset = 0_usize;
    let mut durable_end = 0_usize;
    while offset < bytes.len() {
        if bytes.len() - offset < ACCEPTANCE_HEADER_BYTES {
            break;
        }
        if &bytes[offset..offset + ACCEPTANCE_MAGIC.len()] != ACCEPTANCE_MAGIC {
            return Err(StagingError::AcceptanceCorrupt);
        }
        let length_start = offset + ACCEPTANCE_MAGIC.len();
        let body_length = u32::from_be_bytes(
            bytes[length_start..length_start + 4]
                .try_into()
                .map_err(|_| StagingError::AcceptanceCorrupt)?,
        ) as usize;
        if body_length == 0 || body_length > MAX_ACCEPTANCE_RECORD_BYTES {
            return Err(StagingError::AcceptanceCorrupt);
        }
        let frame_length = ACCEPTANCE_HEADER_BYTES
            .checked_add(body_length)
            .and_then(|value| value.checked_add(ACCEPTANCE_TRAILER_BYTES))
            .ok_or(StagingError::AcceptanceCorrupt)?;
        if bytes.len() - offset < frame_length {
            break;
        }
        let body_start = offset + ACCEPTANCE_HEADER_BYTES;
        let body_end = body_start + body_length;
        let checksum_end = body_end + 32;
        let commit_end = checksum_end + ACCEPTANCE_COMMIT.len();
        if &bytes[checksum_end..commit_end] != ACCEPTANCE_COMMIT {
            return Err(StagingError::AcceptanceCorrupt);
        }
        if Sha256::digest(&bytes[body_start..body_end]).as_slice() != &bytes[body_end..checksum_end]
        {
            return Err(StagingError::AcceptanceCorrupt);
        }
        let state: ReleaseAcceptanceState = serde_json::from_slice(&bytes[body_start..body_end])?;
        if canonical_json(&state)? != bytes[body_start..body_end]
            || state.schema_version != 1
            || state.channel != channel
            || state.state_model_sha256 != *state_model_sha256
            || state.highest_sequence == 0
        {
            return Err(StagingError::AcceptanceCorrupt);
        }
        validate_acceptance_append(states.last(), &state)?;
        states.push(state);
        offset = commit_end;
        durable_end = offset;
    }
    if durable_end != bytes.len() {
        file.set_len(durable_end as u64)?;
        file.sync_all()?;
    }
    Ok(states)
}

fn validate_acceptance_append(
    previous: Option<&ReleaseAcceptanceState>,
    next: &ReleaseAcceptanceState,
) -> Result<(), StagingError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if next.channel != previous.channel
        || next.state_model_sha256 != previous.state_model_sha256
        || next.highest_sequence < previous.highest_sequence
        || next.issued_at_unix_secs < previous.issued_at_unix_secs
        || next.trusted_time_unix_secs < previous.trusted_time_unix_secs
        || (next.highest_sequence == previous.highest_sequence
            && (next.manifest_digest != previous.manifest_digest
                || next.issued_at_unix_secs != previous.issued_at_unix_secs))
    {
        return Err(StagingError::AcceptanceCorrupt);
    }
    Ok(())
}

fn validate_trusted_root(root: &Path) -> Result<(), StagingError> {
    if !root.is_absolute() {
        return Err(StagingError::InvalidRoot);
    }
    let mut current = PathBuf::new();
    for component in root.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(part) => current.push(part),
            Component::CurDir | Component::ParentDir => return Err(StagingError::InvalidRoot),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            if current == root && error.kind() == io::ErrorKind::NotFound {
                StagingError::InvalidRoot
            } else {
                StagingError::Io(error)
            }
        })?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(StagingError::UnsafePath(current));
        }
        if !metadata.is_dir() {
            return Err(StagingError::InvalidRoot);
        }
        if current == root {
            if !directory_is_private(&metadata) {
                return Err(StagingError::UnsafePath(current));
            }
        } else if !ancestor_directory_is_trusted(&metadata) {
            return Err(StagingError::UnsafePath(current));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn directory_is_private(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    unix_directory_is_private(
        metadata.permissions().mode(),
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    )
}

#[cfg(not(unix))]
fn directory_is_private(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn unix_directory_is_private(mode: u32, owner_uid: u32, expected_uid: u32) -> bool {
    mode & 0o022 == 0 && owner_uid == expected_uid
}

#[cfg(unix)]
fn ancestor_directory_is_trusted(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    unix_ancestor_is_trusted(
        metadata.permissions().mode(),
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
    )
}

#[cfg(not(unix))]
fn ancestor_directory_is_trusted(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn unix_ancestor_is_trusted(mode: u32, owner_uid: u32, expected_uid: u32) -> bool {
    let owner_is_trusted = owner_uid == expected_uid || owner_uid == 0;
    if !owner_is_trusted {
        return false;
    }
    if mode & 0o022 == 0 {
        return true;
    }
    owner_uid == 0 && mode & 0o1000 != 0
}

fn ensure_private_directory(root: &Path, child: &str) -> Result<(), StagingError> {
    let path = root.join(child);
    match fs::create_dir(&path) {
        Ok(()) => {
            set_private_directory_permissions(&path)?;
            sync_directory(root)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || is_reparse_point(&metadata)
        || !directory_is_private(&metadata)
    {
        return Err(StagingError::UnsafePath(path));
    }
    Ok(())
}

fn open_acceptance_log(path: &Path) -> Result<File, StagingError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_nofollow_flags(&mut options, true);
    let file = options.open(path)?;
    ensure_regular_file(&file, path)?;
    file.sync_all()?;
    sync_directory(path.parent().ok_or(StagingError::InvalidRoot)?)?;
    Ok(file)
}

fn open_lock_file(path: &Path) -> Result<File, StagingError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_nofollow_flags(&mut options, true);
    let file = options.open(path)?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

fn open_quarantine(path: &Path) -> Result<File, StagingError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_nofollow_flags(&mut options, true);
    let file = options.open(path)?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

fn create_new_regular(path: &Path) -> Result<File, StagingError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    set_nofollow_flags(&mut options, true);
    let file = options.open(path)?;
    ensure_regular_file(&file, path)?;
    Ok(file)
}

fn open_regular_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    set_nofollow_flags(&mut options, false);
    let file = options.open(path)?;
    ensure_regular_file_io(&file, path)?;
    Ok(file)
}

fn open_regular_write(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    set_nofollow_flags(&mut options, true);
    let file = options.open(path)?;
    ensure_regular_file_io(&file, path)?;
    Ok(file)
}

fn ensure_regular_path(path: &Path) -> Result<(), StagingError> {
    let file = open_regular_read(path)?;
    ensure_regular_file(&file, path)
}

fn ensure_regular_file(file: &File, path: &Path) -> Result<(), StagingError> {
    ensure_regular_file_io(file, path).map_err(|_| StagingError::UnsafePath(path.to_path_buf()))
}

fn ensure_regular_file_io(file: &File, _path: &Path) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staging entry is not a regular no-follow file",
        ));
    }
    Ok(())
}

fn read_bounded_evidence(file: &mut File, maximum_bytes: u64) -> Result<Vec<u8>, StagingError> {
    let length = file.metadata()?.len();
    if length > maximum_bytes {
        return Err(StagingError::EvidenceTooLarge);
    }
    let capacity = usize::try_from(length).map_err(|_| StagingError::EvidenceTooLarge)?;
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or(StagingError::EvidenceTooLarge)?;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(StagingError::EvidenceTooLarge);
    }
    Ok(bytes)
}

fn remove_file_if_present(path: &Path) -> Result<(), StagingError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_untrusted_cache_entry(path: &Path) -> Result<(), StagingError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        return Err(StagingError::UnexpectedEntry(path.to_path_buf()));
    }
    remove_file_if_present(path)
}

fn channel_token(channel: ReleaseChannel) -> &'static str {
    match channel {
        ReleaseChannel::Stable => "stable",
        ReleaseChannel::Beta => "beta",
    }
}

fn role_token(role: ArtifactRole) -> &'static str {
    match role {
        ArtifactRole::EspLoader => "esp-loader",
        ArtifactRole::InstallerUki => "installer-uki",
        ArtifactRole::OfflineSystemImage => "offline-system-image",
        ArtifactRole::RecoveryUki => "recovery-uki",
    }
}

fn valid_quarantine_name(name: &str) -> bool {
    let Some(base) = name.strip_suffix(".part") else {
        return false;
    };
    REQUIRED_ARTIFACT_ROLES.iter().any(|role| {
        let marker = format!("-{}-", role_token(*role));
        let Some((manifest, artifact)) = base.split_once(&marker) else {
            return false;
        };
        valid_hash(manifest) && valid_hash(artifact)
    })
}

fn valid_artifact_name(name: &str) -> bool {
    name.strip_suffix(".blob").is_some_and(valid_hash)
}

fn valid_evidence_name(name: &str) -> bool {
    if let Some(hash) = name.strip_suffix(".json") {
        valid_hash(hash)
    } else if let Some(hash) = name.strip_suffix(".part") {
        valid_hash(hash)
    } else {
        false
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn set_nofollow_flags(options: &mut OpenOptions, durable: bool) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut flags = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    if durable {
        flags |= libc::O_DSYNC;
    }
    options.custom_flags(flags);
}

#[cfg(windows)]
fn set_nofollow_flags(options: &mut OpenOptions, durable: bool) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    };
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if durable {
        flags |= FILE_FLAG_WRITE_THROUGH;
    }
    options.custom_flags(flags);
}

#[cfg(not(any(unix, windows)))]
fn set_nofollow_flags(_options: &mut OpenOptions, _durable: bool) {}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

impl fmt::Debug for StagingStore<NoFaultInjector> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagingStore")
            .field("root", &self.root)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ed25519_dalek::SigningKey;
    use jstack_installer_core::{
        Architecture, ReleaseTrustPolicy, ReleaseVerificationMode, SignedReleaseManifest,
        TrustedReleaseKey, verify_release_manifest,
    };
    use tempfile::TempDir;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const MANIFEST: &[u8] = include_bytes!("../../core/fixtures/signed-release-manifest.json");

    #[derive(Clone)]
    struct FailOnce {
        point: FaultPoint,
        fired: bool,
    }

    impl FailOnce {
        fn at(point: FaultPoint) -> Self {
            Self {
                point,
                fired: false,
            }
        }
    }

    impl FaultInjector for FailOnce {
        fn should_fail(&mut self, point: FaultPoint) -> bool {
            if !self.fired && point == self.point {
                self.fired = true;
                true
            } else {
                false
            }
        }
    }

    fn envelope() -> SignedReleaseManifest {
        serde_json::from_slice(MANIFEST).unwrap()
    }

    fn policy(
        previous_acceptance: Option<ReleaseAcceptanceState>,
        now_unix_secs: u64,
    ) -> ReleaseTrustPolicy {
        let manifest = envelope();
        let trusted_keys = [[1_u8; 32], [2_u8; 32]]
            .into_iter()
            .map(|seed| TrustedReleaseKey {
                public_key: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                channels: vec![ReleaseChannel::Stable],
            })
            .collect();
        ReleaseTrustPolicy {
            channel: ReleaseChannel::Stable,
            architecture: Architecture::X86_64,
            state_model_id: manifest.signed.state_model_id,
            state_model_sha256: manifest.signed.state_model_sha256,
            installer_protocol_version: 1,
            now_unix_secs,
            maximum_future_skew_secs: 300,
            maximum_manifest_lifetime_secs: 86_400,
            maximum_manifest_bytes: 1024 * 1024,
            maximum_signatures: 16,
            maximum_artifacts: 4,
            maximum_chunks_per_artifact: 4096,
            maximum_artifact_bytes: 1024 * 1024,
            maximum_chunk_size_bytes: 1024 * 1024,
            signature_threshold: 2,
            trusted_keys,
            previous_acceptance,
        }
    }

    fn pending(
        previous_acceptance: Option<ReleaseAcceptanceState>,
        now_unix_secs: u64,
    ) -> PendingReleaseManifest {
        verify_release_manifest(
            MANIFEST,
            &policy(previous_acceptance, now_unix_secs),
            ReleaseVerificationMode::Acquire,
        )
        .unwrap()
    }

    fn accepted_release<I: FaultInjector>(store: &mut StagingStore<I>) -> VerifiedReleaseManifest {
        let manifest = envelope();
        let previous = store
            .read_acceptance(ReleaseChannel::Stable, &manifest.signed.state_model_sha256)
            .unwrap();
        let pending = pending(previous, NOW);
        store.persist_acceptance(pending).unwrap()
    }

    fn artifact_bytes(role: ArtifactRole) -> &'static [u8] {
        match role {
            ArtifactRole::EspLoader => b"jstack-esp-loader-fixture\n",
            ArtifactRole::InstallerUki => b"jstack-installer-uki-fixture\n",
            ArtifactRole::OfflineSystemImage => b"jstack-offline-system-image-fixture\n",
            ArtifactRole::RecoveryUki => b"jstack-recovery-uki-fixture\n",
        }
    }

    fn stage_all<I: FaultInjector>(store: &mut StagingStore<I>, release: &VerifiedReleaseManifest) {
        for role in REQUIRED_ARTIFACT_ROLES {
            let mut source = Cursor::new(artifact_bytes(role));
            assert!(matches!(
                store.stage_artifact(release, role, 0, &mut source).unwrap(),
                StageProgress::Complete(_)
            ));
        }
    }

    #[test]
    fn acceptance_log_is_monotonic_cas_and_requires_exact_readback() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let first_pending = pending(None, NOW);
        let required = first_pending.required_acceptance().clone();
        let release = store.persist_acceptance(first_pending).unwrap();
        assert_eq!(release.acceptance(), &required);
        assert_eq!(
            store
                .read_acceptance(required.channel, &required.state_model_sha256)
                .unwrap(),
            Some(required.clone())
        );

        assert!(matches!(
            store.persist_acceptance(pending(None, NOW)),
            Err(StagingError::AcceptanceChanged)
        ));

        let second = pending(Some(required.clone()), NOW + 1);
        let advanced = second.required_acceptance().clone();
        assert_eq!(advanced.highest_sequence, required.highest_sequence);
        assert!(advanced.trusted_time_unix_secs > required.trusted_time_unix_secs);
        store.persist_acceptance(second).unwrap();
        assert_eq!(
            store
                .read_acceptance(required.channel, &required.state_model_sha256)
                .unwrap(),
            Some(advanced)
        );
    }

    #[test]
    fn acceptance_log_rejects_backdated_higher_sequence() {
        let previous = pending(None, NOW).required_acceptance().clone();
        let mut backdated = previous.clone();
        backdated.highest_sequence += 1;
        backdated.issued_at_unix_secs -= 1;
        backdated.trusted_time_unix_secs += 1;

        assert!(matches!(
            validate_acceptance_append(Some(&previous), &backdated),
            Err(StagingError::AcceptanceCorrupt)
        ));
    }

    #[test]
    fn every_acceptance_kill_point_recovers_without_rollback() {
        let points = [
            FaultPoint::AcceptanceAfterLock,
            FaultPoint::AcceptanceAfterRecordWrite,
            FaultPoint::AcceptanceAfterRecordSync,
            FaultPoint::AcceptanceAfterCommitWrite,
            FaultPoint::AcceptanceAfterCommitSync,
            FaultPoint::AcceptanceBeforeReadback,
        ];
        for point in points {
            let temporary = TempDir::new().unwrap();
            let mut crashing = StagingStore::open_with(
                temporary.path(),
                StoreLimits::default(),
                FailOnce::at(point),
            )
            .unwrap();
            assert!(matches!(
                crashing.persist_acceptance(pending(None, NOW)),
                Err(StagingError::Injected(actual)) if actual == point
            ));
            drop(crashing);

            let mut recovered = StagingStore::open(temporary.path()).unwrap();
            let body = envelope().signed;
            let previous = recovered
                .read_acceptance(ReleaseChannel::Stable, &body.state_model_sha256)
                .unwrap();
            let next = pending(previous, NOW);
            recovered.persist_acceptance(next).unwrap();
            assert!(
                recovered
                    .read_acceptance(ReleaseChannel::Stable, &body.state_model_sha256)
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn torn_uncommitted_acceptance_tail_is_truncated_but_committed_corruption_hard_stops() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        let state = release.acceptance().clone();
        let log = store.acceptance_log_path(state.channel, &state.state_model_sha256);

        {
            let mut file = OpenOptions::new().append(true).open(&log).unwrap();
            file.write_all(&ACCEPTANCE_MAGIC[..3]).unwrap();
            file.sync_all().unwrap();
        }
        assert_eq!(
            store
                .read_acceptance(state.channel, &state.state_model_sha256)
                .unwrap(),
            Some(state.clone())
        );

        let mut bytes = fs::read(&log).unwrap();
        let body_start = ACCEPTANCE_HEADER_BYTES;
        bytes[body_start] ^= 1;
        fs::write(&log, bytes).unwrap();
        assert!(matches!(
            store.read_acceptance(state.channel, &state.state_model_sha256),
            Err(StagingError::AcceptanceCorrupt)
        ));
    }

    #[test]
    fn artifact_resume_preserves_only_complete_verified_chunks() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        let role = ArtifactRole::OfflineSystemImage;
        let bytes = artifact_bytes(role);
        let chunk_size = release.artifact_descriptor(role).unwrap().chunk_size_bytes as usize;
        let split = chunk_size + 3;
        let mut first = Cursor::new(&bytes[..split]);
        assert!(matches!(
            store.stage_artifact(&release, role, 0, &mut first).unwrap(),
            StageProgress::Incomplete { next_offset } if next_offset == chunk_size as u64
        ));
        assert_eq!(
            store.artifact_resume_offset(&release, role).unwrap(),
            chunk_size as u64
        );
        let mut second = Cursor::new(&bytes[chunk_size..]);
        let mut staged = match store
            .stage_artifact(&release, role, chunk_size as u64, &mut second)
            .unwrap()
        {
            StageProgress::Complete(staged) => staged,
            StageProgress::Incomplete { .. } => panic!("artifact should be complete"),
        };
        staged.verify_integrity(&release).unwrap();
        staged.file.seek(SeekFrom::Start(0)).unwrap();
        let mut copied = Vec::new();
        staged.file.read_to_end(&mut copied).unwrap();
        assert_eq!(copied, bytes);
    }

    #[test]
    fn artifact_offset_hash_and_promoted_tampering_fail_closed() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        let role = ArtifactRole::EspLoader;
        let bytes = artifact_bytes(role);
        assert!(matches!(
            store.stage_artifact(&release, role, 1, &mut Cursor::new(bytes)),
            Err(StagingError::ResumeOffsetMismatch {
                expected: 0,
                actual: 1
            })
        ));

        let mut corrupt = bytes.to_vec();
        corrupt[0] ^= 1;
        assert!(matches!(
            store.stage_artifact(&release, role, 0, &mut Cursor::new(corrupt)),
            Err(StagingError::QuarantineChunkMismatch { role: actual, index: 0 })
                if actual == role
        ));
        let mut valid = Cursor::new(bytes);
        assert!(matches!(
            store.stage_artifact(&release, role, 0, &mut valid).unwrap(),
            StageProgress::Complete(_)
        ));
        let descriptor = release.artifact_descriptor(role).unwrap();
        fs::write(store.artifact_path(&descriptor.sha256), b"tampered").unwrap();
        assert!(matches!(
            store.open_staged_artifact(&release, role),
            Err(StagingError::ExistingArtifactInvalid(actual)) if actual == role
        ));
    }

    #[test]
    fn every_artifact_kill_point_is_retryable_or_already_durable() {
        let points = [
            FaultPoint::ArtifactAfterQuarantineOpen,
            FaultPoint::ArtifactAfterChunkWrite,
            FaultPoint::ArtifactAfterChunkSync,
            FaultPoint::ArtifactAfterFullVerify,
            FaultPoint::ArtifactAfterFileSync,
            FaultPoint::ArtifactAfterPromote,
            FaultPoint::ArtifactAfterPromotionSync,
            FaultPoint::ArtifactAfterQuarantineRemove,
        ];
        for point in points {
            let temporary = TempDir::new().unwrap();
            let release = {
                let mut setup = StagingStore::open(temporary.path()).unwrap();
                accepted_release(&mut setup)
            };
            let role = ArtifactRole::RecoveryUki;
            let mut crashing = StagingStore::open_with(
                temporary.path(),
                StoreLimits::default(),
                FailOnce::at(point),
            )
            .unwrap();
            assert!(matches!(
                crashing.stage_artifact(
                    &release,
                    role,
                    0,
                    &mut Cursor::new(artifact_bytes(role))
                ),
                Err(StagingError::Injected(actual)) if actual == point
            ));
            drop(crashing);

            let mut recovered = StagingStore::open(temporary.path()).unwrap();
            let offset = recovered.artifact_resume_offset(&release, role).unwrap();
            let bytes = artifact_bytes(role);
            let start = usize::try_from(offset).unwrap();
            let progress = recovered
                .stage_artifact(&release, role, offset, &mut Cursor::new(&bytes[start..]))
                .unwrap();
            assert!(matches!(progress, StageProgress::Complete(_)));
        }
    }

    #[test]
    fn durable_evidence_binds_acceptance_manifest_and_exact_staged_set() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        stage_all(&mut store, &release);
        let durable = store.persist_staging_evidence(&release).unwrap();
        assert_eq!(
            durable.evidence().manifest_digest,
            *release.manifest_digest()
        );
        assert_eq!(durable.evidence().artifacts.len(), 4);
        assert_eq!(
            store
                .read_staging_evidence(&release, durable.evidence_hash())
                .unwrap()
                .evidence(),
            durable.evidence()
        );

        let path = store.evidence_path(durable.evidence_hash());
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(
            store
                .read_staging_evidence(&release, durable.evidence_hash())
                .is_err()
        );
    }

    #[test]
    fn every_evidence_kill_point_is_retryable_and_corrupt_part_is_replaced() {
        let points = [
            FaultPoint::EvidenceAfterWrite,
            FaultPoint::EvidenceAfterFileSync,
            FaultPoint::EvidenceAfterPromote,
            FaultPoint::EvidenceAfterPromotionSync,
        ];
        for point in points {
            let temporary = TempDir::new().unwrap();
            let release = {
                let mut setup = StagingStore::open(temporary.path()).unwrap();
                let release = accepted_release(&mut setup);
                stage_all(&mut setup, &release);
                release
            };
            let mut crashing = StagingStore::open_with(
                temporary.path(),
                StoreLimits::default(),
                FailOnce::at(point),
            )
            .unwrap();
            assert!(matches!(
                crashing.persist_staging_evidence(&release),
                Err(StagingError::Injected(actual)) if actual == point
            ));
            drop(crashing);

            let mut recovered = StagingStore::open(temporary.path()).unwrap();
            let durable = recovered.persist_staging_evidence(&release).unwrap();
            assert_eq!(
                recovered
                    .read_staging_evidence(&release, durable.evidence_hash())
                    .unwrap()
                    .evidence(),
                durable.evidence()
            );
        }

        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        stage_all(&mut store, &release);
        let evidence = store.build_evidence_locked(&release).unwrap();
        let hash = canonical_sha256(&evidence).unwrap();
        fs::write(
            temporary
                .path()
                .join("evidence")
                .join(format!("{}.part", hash.as_str())),
            b"corrupt",
        )
        .unwrap();
        assert_eq!(
            store
                .persist_staging_evidence(&release)
                .unwrap()
                .evidence_hash(),
            &hash
        );
    }

    #[test]
    fn evidence_reads_are_bounded_before_allocation() {
        let temporary = TempDir::new().unwrap();
        let limits = StoreLimits {
            maximum_evidence_bytes: 1024,
            ..StoreLimits::default()
        };
        let mut store = StagingStore::open_with_limits(temporary.path(), limits).unwrap();
        let release = accepted_release(&mut store);
        stage_all(&mut store, &release);
        let evidence_hash =
            canonical_sha256(&store.build_evidence_locked(&release).unwrap()).unwrap();
        let oversized = vec![b'x'; 1025];

        let part = temporary
            .path()
            .join("evidence")
            .join(format!("{}.part", evidence_hash.as_str()));
        fs::write(&part, &oversized).unwrap();
        assert!(matches!(
            store.persist_staging_evidence(&release),
            Err(StagingError::EvidenceTooLarge)
        ));

        fs::remove_file(part).unwrap();
        fs::write(store.evidence_path(&evidence_hash), oversized).unwrap();
        assert!(matches!(
            store.read_staging_evidence(&release, &evidence_hash),
            Err(StagingError::EvidenceTooLarge)
        ));
    }

    #[test]
    fn reconciliation_removes_untrusted_cache_names_and_preserves_resumable_parts() {
        let temporary = TempDir::new().unwrap();
        let mut store = StagingStore::open(temporary.path()).unwrap();
        let release = accepted_release(&mut store);
        let role = ArtifactRole::InstallerUki;
        let bytes = artifact_bytes(role);
        let chunk = release.artifact_descriptor(role).unwrap().chunk_size_bytes as usize;
        let mut partial = Cursor::new(&bytes[..chunk]);
        assert!(matches!(
            store
                .stage_artifact(&release, role, 0, &mut partial)
                .unwrap(),
            StageProgress::Incomplete { .. }
        ));
        fs::write(temporary.path().join("quarantine").join("junk"), b"x").unwrap();
        fs::write(temporary.path().join("artifacts").join("WRONG.blob"), b"x").unwrap();
        let report = store.reconcile().unwrap();
        assert_eq!(report.removed_entries, 2);
        assert_eq!(report.resumable_artifacts, 1);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_components_and_artifact_entries_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().unwrap();
        let target = TempDir::new().unwrap();
        symlink(target.path(), root.path().join("quarantine")).unwrap();
        assert!(matches!(
            StagingStore::open(root.path()),
            Err(StagingError::UnsafePath(_))
        ));

        let root = TempDir::new().unwrap();
        let mut store = StagingStore::open(root.path()).unwrap();
        let release = accepted_release(&mut store);
        let descriptor = release
            .artifact_descriptor(ArtifactRole::EspLoader)
            .unwrap();
        symlink(
            target.path().join("target"),
            store.artifact_path(&descriptor.sha256),
        )
        .unwrap();
        assert!(
            store
                .open_staged_artifact(&release, ArtifactRole::EspLoader)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_writable_staging_root_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            StagingStore::open(root.path()),
            Err(StagingError::UnsafePath(_))
        ));

        let root = TempDir::new().unwrap();
        StagingStore::open(root.path()).unwrap();
        fs::set_permissions(
            root.path().join("artifacts"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(matches!(
            StagingStore::open(root.path()),
            Err(StagingError::UnsafePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_requires_the_effective_owner() {
        assert!(unix_directory_is_private(0o700, 1000, 1000));
        assert!(!unix_directory_is_private(0o700, 1001, 1000));
        assert!(!unix_directory_is_private(0o720, 1000, 1000));
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_chain_rejects_rename_capability_but_allows_root_sticky_directories() {
        use std::os::unix::fs::PermissionsExt;

        assert!(unix_ancestor_is_trusted(0o755, 0, 1000));
        assert!(unix_ancestor_is_trusted(0o700, 1000, 1000));
        assert!(unix_ancestor_is_trusted(0o1777, 0, 1000));
        assert!(!unix_ancestor_is_trusted(0o777, 0, 1000));
        assert!(!unix_ancestor_is_trusted(0o755, 1001, 1000));

        let ancestor = TempDir::new().unwrap();
        let root = ancestor.path().join("store");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(ancestor.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            StagingStore::open(&root),
            Err(StagingError::UnsafePath(path)) if path == ancestor.path()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_removes_non_utf8_cache_names() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = TempDir::new().unwrap();
        let mut store = StagingStore::open(root.path()).unwrap();
        let hostile = root
            .path()
            .join("artifacts")
            .join(OsString::from_vec(vec![b'x', 0xff]));
        fs::write(&hostile, b"junk").unwrap();
        assert_eq!(store.reconcile().unwrap().removed_entries, 1);
        assert!(!hostile.exists());
    }
}
