use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use jstack_installer_core::{
    DestinationCommitEvidence, DestinationEvidenceError, DestinationIntentEvidence,
    DestinationPlacement, DestinationTransition, Hash256, InstallPlan, JournalRecord,
    JournalRecordType, VerifiedArtifactBytes, VerifiedReleaseManifest, canonical_sha256,
    create_destination_action_committed_record, create_destination_action_intent_record,
    create_destination_commit, create_destination_intent, create_destination_state_advanced_record,
};
use thiserror::Error;

use crate::journal::{DurableJournal, JournalError, JournalFaultInjector};
use crate::{
    StagedArtifact, StagingError, create_new_regular, ensure_private_directory,
    ensure_regular_file_io, open_lock_file, open_regular_read, remove_file_if_present,
    sync_directory, validate_trusted_root,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationFaultPoint {
    AfterIntentDurable,
    AfterTemporaryVerified(usize),
    AfterAllTemporariesVerified,
    AfterFinalReachable(usize),
    AfterFinalDirectoriesSynced,
    BeforeCommitDurable,
    AfterCommitDurable,
    AfterStateAdvancedDurable,
}

pub trait DestinationFaultInjector {
    fn should_fail(&mut self, point: DestinationFaultPoint) -> bool;

    fn maximum_written_bytes(&mut self, _artifact_index: usize) -> Option<u64> {
        None
    }
}

#[derive(Default)]
pub struct NoDestinationFaults;

impl DestinationFaultInjector for NoDestinationFaults {
    fn should_fail(&mut self, _point: DestinationFaultPoint) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum DestinationTransactionError {
    #[error("VM destination transaction is supported only on Unix file-backed test hosts")]
    UnsupportedHost,
    #[error(
        "destination transaction input is not exactly bound to its release, plan, and staging evidence"
    )]
    InvalidBinding,
    #[error("destination transaction encountered an incompatible durable journal phase")]
    JournalPhase,
    #[error("destination path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("destination already exists or has a case-colliding name: {0}")]
    AlreadyExists(PathBuf),
    #[error("destination transaction observed a hard-linked file: {0}")]
    HardLinked(PathBuf),
    #[error("injected destination transaction crash at {0:?}")]
    Injected(DestinationFaultPoint),
    #[error("destination filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("staging operation failed: {0}")]
    Staging(#[from] StagingError),
    #[error("release verification failed: {0}")]
    Release(#[from] jstack_installer_core::ReleaseError),
    #[error("destination evidence failed: {0}")]
    Evidence(#[from] DestinationEvidenceError),
    #[error("durable journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("destination evidence cannot be canonicalized: {0}")]
    Canonical(#[from] jstack_installer_core::canonical::CanonicalError),
}

#[derive(Debug)]
pub struct CommittedDestinationTransaction {
    evidence: DestinationCommitEvidence,
    journal_record: JournalRecord,
    state_advanced_record: JournalRecord,
}

impl CommittedDestinationTransaction {
    pub fn evidence(&self) -> &DestinationCommitEvidence {
        &self.evidence
    }

    pub fn journal_record(&self) -> &JournalRecord {
        &self.journal_record
    }

    pub fn state_advanced_record(&self) -> &JournalRecord {
        &self.state_advanced_record
    }
}

struct RecoveredCommit {
    evidence: DestinationCommitEvidence,
    action_intent_record: JournalRecord,
    action_committed_record: JournalRecord,
}

pub struct VmFileTransaction<I = NoDestinationFaults> {
    injector: I,
}

impl Default for VmFileTransaction<NoDestinationFaults> {
    fn default() -> Self {
        Self {
            injector: NoDestinationFaults,
        }
    }
}

impl<I: DestinationFaultInjector> VmFileTransaction<I> {
    pub fn with_injector(injector: I) -> Self {
        Self { injector }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute<J: JournalFaultInjector>(
        &mut self,
        journal: &mut DurableJournal<J>,
        release: &VerifiedReleaseManifest,
        plan: &InstallPlan,
        staging_evidence_hash: &Hash256,
        observed_partition_fingerprint: &Hash256,
        transition: DestinationTransition,
        mut staged: Vec<StagedArtifact>,
    ) -> Result<CommittedDestinationTransaction, DestinationTransactionError> {
        if !cfg!(unix) {
            return Err(DestinationTransactionError::UnsupportedHost);
        }
        let intent = create_destination_intent(release, plan, staging_evidence_hash, transition)?;
        if &intent.partition_fingerprint != observed_partition_fingerprint
            || staged.len() != intent.artifacts.len()
            || !staged
                .iter()
                .zip(&intent.artifacts)
                .all(|(source, expected)| {
                    source.role() == expected.artifact.role
                        && source.size_bytes() == expected.artifact.size_bytes
                        && source.sha256() == &expected.artifact.sha256
                        && source.manifest_digest() == &expected.artifact.manifest_digest
                })
        {
            return Err(DestinationTransactionError::InvalidBinding);
        }

        validate_trusted_root(journal.root()).map_err(map_staging_path_error)?;
        ensure_private_directory(journal.root(), "transaction-locks")?;
        let lock_path = journal
            .root()
            .join("transaction-locks")
            .join(format!("{}.lock", plan.plan_hash.as_str()));
        let lock = open_lock_file(&lock_path)?;
        FileExt::lock(&lock)?;
        let result = self.execute_locked(journal, release, plan, transition, &intent, &mut staged);
        let unlock = FileExt::unlock(&lock);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn execute_locked<J: JournalFaultInjector>(
        &mut self,
        journal: &mut DurableJournal<J>,
        release: &VerifiedReleaseManifest,
        plan: &InstallPlan,
        transition: DestinationTransition,
        intent: &DestinationIntentEvidence,
        staged: &mut [StagedArtifact],
    ) -> Result<CommittedDestinationTransaction, DestinationTransactionError> {
        let paths = prepare_paths(journal.root(), plan, transition, intent)?;
        let records = journal.read_all()?;
        let previous = records.last();
        let (action_intent, recovering) = match previous {
            Some(head)
                if head.record_type == JournalRecordType::ActionIntent
                    && head.actor == intent.actor
                    && head.transition_id == intent.transition_id
                    && head.plan_hash == intent.plan_hash
                    && head.precondition_hash == canonical_sha256(intent)? =>
            {
                (head.clone(), true)
            }
            Some(head)
                if head.record_type == JournalRecordType::ActionCommitted
                    && head.actor == intent.actor
                    && head.transition_id == intent.transition_id
                    && head.plan_hash == intent.plan_hash =>
            {
                let action_intent = records
                    .iter()
                    .rev()
                    .nth(1)
                    .ok_or(DestinationTransactionError::JournalPhase)?;
                let recovered = Self::recover_committed(
                    release,
                    plan,
                    transition,
                    intent,
                    action_intent,
                    head,
                    &paths,
                )?;
                return self
                    .finish_state_advance(journal, release, plan, transition, intent, recovered);
            }
            Some(head)
                if head.record_type == JournalRecordType::StateAdvanced
                    && head.actor == intent.actor
                    && head.transition_id == intent.transition_id
                    && head.plan_hash == intent.plan_hash =>
            {
                return Self::recover_advanced(
                    release, plan, transition, intent, &records, head, &paths,
                );
            }
            Some(head) if head.record_type != JournalRecordType::StateAdvanced => {
                return Err(DestinationTransactionError::JournalPhase);
            }
            head => {
                // Only an absent closed destination set may become owned by this intent.
                reject_existing_outputs(&paths)?;
                let action_intent = create_destination_action_intent_record(
                    head,
                    intent,
                    release,
                    plan,
                    &intent.staging_evidence_hash,
                    transition,
                )?;
                journal.append(&action_intent)?;
                self.hit(DestinationFaultPoint::AfterIntentDurable)?;
                (action_intent, false)
            }
        };

        if recovering {
            cleanup_owned_outputs(&paths)?;
        }

        let mut temporary_verified = Vec::with_capacity(staged.len());
        for (index, ((source, expected), paths)) in staged
            .iter_mut()
            .zip(&intent.artifacts)
            .zip(&paths)
            .enumerate()
        {
            ensure_single_link(&source.file, &paths.temporary)?;
            let mut temporary = create_new_regular(&paths.temporary)?;
            ensure_single_link(&temporary, &paths.temporary)?;
            let write_limit = self.injector.maximum_written_bytes(index);
            let source_verified = copy_same_stream_verified(
                source,
                &mut temporary,
                release,
                expected.artifact.role,
                write_limit,
            )?;
            temporary.sync_all()?;
            drop(temporary);
            let destination_verified =
                verify_regular_file(&paths.temporary, release, expected.artifact.role)?;
            if source_verified != destination_verified {
                return Err(DestinationTransactionError::InvalidBinding);
            }
            temporary_verified.push(destination_verified);
            self.hit(DestinationFaultPoint::AfterTemporaryVerified(index))?;
        }
        self.hit(DestinationFaultPoint::AfterAllTemporariesVerified)?;

        for (index, paths) in paths.iter().enumerate() {
            reject_case_collision(&paths.final_path)?;
            match fs::symlink_metadata(&paths.final_path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(DestinationTransactionError::AlreadyExists(
                        paths.final_path.clone(),
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            fs::rename(&paths.temporary, &paths.final_path)?;
            self.hit(DestinationFaultPoint::AfterFinalReachable(index))?;
            sync_directory(paths.final_path.parent().ok_or_else(|| {
                DestinationTransactionError::UnsafePath(paths.final_path.clone())
            })?)?;
        }
        self.hit(DestinationFaultPoint::AfterFinalDirectoriesSynced)?;

        let final_verified = paths
            .iter()
            .zip(&intent.artifacts)
            .map(|(paths, expected)| {
                verify_regular_file(&paths.final_path, release, expected.artifact.role)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if final_verified != temporary_verified {
            return Err(DestinationTransactionError::InvalidBinding);
        }
        let commit = create_destination_commit(
            intent,
            &action_intent,
            &final_verified,
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
        )?;
        let committed_record = create_destination_action_committed_record(
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
            intent,
            &action_intent,
            &commit,
        )?;
        self.hit(DestinationFaultPoint::BeforeCommitDurable)?;
        journal.append(&committed_record)?;
        self.hit(DestinationFaultPoint::AfterCommitDurable)?;
        self.finish_state_advance(
            journal,
            release,
            plan,
            transition,
            intent,
            RecoveredCommit {
                evidence: commit,
                action_intent_record: action_intent,
                action_committed_record: committed_record,
            },
        )
    }

    fn recover_committed(
        release: &VerifiedReleaseManifest,
        plan: &InstallPlan,
        transition: DestinationTransition,
        intent: &DestinationIntentEvidence,
        action_intent: &JournalRecord,
        committed_record: &JournalRecord,
        paths: &[DestinationPaths],
    ) -> Result<RecoveredCommit, DestinationTransactionError> {
        if action_intent.record_type != JournalRecordType::ActionIntent {
            return Err(DestinationTransactionError::JournalPhase);
        }
        let verified = paths
            .iter()
            .zip(&intent.artifacts)
            .map(|(paths, expected)| {
                verify_regular_file(&paths.final_path, release, expected.artifact.role)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commit = create_destination_commit(
            intent,
            action_intent,
            &verified,
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
        )?;
        if committed_record.postcondition_hash.as_ref() != Some(&canonical_sha256(&commit)?) {
            return Err(DestinationTransactionError::InvalidBinding);
        }
        let expected = create_destination_action_committed_record(
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
            intent,
            action_intent,
            &commit,
        )?;
        if &expected != committed_record {
            return Err(DestinationTransactionError::InvalidBinding);
        }
        Ok(RecoveredCommit {
            evidence: commit,
            action_intent_record: action_intent.clone(),
            action_committed_record: committed_record.clone(),
        })
    }

    fn finish_state_advance<J: JournalFaultInjector>(
        &mut self,
        journal: &mut DurableJournal<J>,
        release: &VerifiedReleaseManifest,
        plan: &InstallPlan,
        transition: DestinationTransition,
        intent: &DestinationIntentEvidence,
        recovered: RecoveredCommit,
    ) -> Result<CommittedDestinationTransaction, DestinationTransactionError> {
        let state_advanced = create_destination_state_advanced_record(
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
            intent,
            &recovered.action_intent_record,
            &recovered.evidence,
            &recovered.action_committed_record,
        )?;
        journal.append(&state_advanced)?;
        self.hit(DestinationFaultPoint::AfterStateAdvancedDurable)?;
        Ok(CommittedDestinationTransaction {
            evidence: recovered.evidence,
            journal_record: recovered.action_committed_record,
            state_advanced_record: state_advanced,
        })
    }

    fn recover_advanced(
        release: &VerifiedReleaseManifest,
        plan: &InstallPlan,
        transition: DestinationTransition,
        intent: &DestinationIntentEvidence,
        records: &[JournalRecord],
        state_advanced: &JournalRecord,
        paths: &[DestinationPaths],
    ) -> Result<CommittedDestinationTransaction, DestinationTransactionError> {
        let committed = records
            .iter()
            .rev()
            .nth(1)
            .ok_or(DestinationTransactionError::JournalPhase)?;
        let action_intent = records
            .iter()
            .rev()
            .nth(2)
            .ok_or(DestinationTransactionError::JournalPhase)?;
        let recovered = Self::recover_committed(
            release,
            plan,
            transition,
            intent,
            action_intent,
            committed,
            paths,
        )?;
        let expected = create_destination_state_advanced_record(
            release,
            plan,
            &intent.staging_evidence_hash,
            transition,
            intent,
            &recovered.action_intent_record,
            &recovered.evidence,
            &recovered.action_committed_record,
        )?;
        if &expected != state_advanced {
            return Err(DestinationTransactionError::InvalidBinding);
        }
        Ok(CommittedDestinationTransaction {
            evidence: recovered.evidence,
            journal_record: recovered.action_committed_record,
            state_advanced_record: state_advanced.clone(),
        })
    }

    fn hit(&mut self, point: DestinationFaultPoint) -> Result<(), DestinationTransactionError> {
        if self.injector.should_fail(point) {
            Err(DestinationTransactionError::Injected(point))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct DestinationPaths {
    temporary: PathBuf,
    final_path: PathBuf,
}

fn prepare_paths(
    staging_root: &Path,
    plan: &InstallPlan,
    transition: DestinationTransition,
    intent: &DestinationIntentEvidence,
) -> Result<Vec<DestinationPaths>, DestinationTransactionError> {
    ensure_private_directory(staging_root, "vm-destinations")?;
    let destinations = staging_root.join("vm-destinations");
    let plan_component = plan.plan_hash.as_str();
    ensure_private_directory(&destinations, plan_component)?;
    prepare_paths_from_existing_root(destinations.join(plan_component), plan, transition, intent)
}

fn prepare_paths_from_existing_root(
    plan_root: PathBuf,
    plan: &InstallPlan,
    transition: DestinationTransition,
    intent: &DestinationIntentEvidence,
) -> Result<Vec<DestinationPaths>, DestinationTransactionError> {
    if transition.transition_id() != intent.transition_id {
        return Err(DestinationTransactionError::InvalidBinding);
    }
    validate_trusted_root(&plan_root).map_err(map_staging_path_error)?;
    intent
        .artifacts
        .iter()
        .map(|item| {
            let components = placement_components(&item.destination, plan);
            let (file_name, directories) = components
                .split_last()
                .ok_or_else(|| DestinationTransactionError::UnsafePath(plan_root.clone()))?;
            let mut parent = plan_root.clone();
            for directory in directories {
                ensure_private_directory(&parent, directory)?;
                parent.push(directory);
            }
            let final_path = parent.join(file_name);
            let temporary = parent.join(format!(
                ".jstack-txn-{}-{}.part",
                plan.plan_hash.as_str(),
                placement_token(item.destination.placement)
            ));
            Ok(DestinationPaths {
                temporary,
                final_path,
            })
        })
        .collect()
}

fn placement_components(
    destination: &jstack_installer_core::DestinationIdentity,
    plan: &InstallPlan,
) -> Vec<String> {
    let partition = destination.partition_guid.to_string();
    match destination.placement {
        DestinationPlacement::XbootldrInstallerUki => vec![
            "xbootldr".into(),
            partition.clone(),
            "EFI".into(),
            "Linux".into(),
            "jstack-installer.efi".into(),
        ],
        DestinationPlacement::XbootldrOfflineSystemImage => vec![
            "xbootldr".into(),
            partition,
            "jstack".into(),
            "offline-system.img".into(),
        ],
        DestinationPlacement::XbootldrRecoveryUki => vec![
            "xbootldr".into(),
            partition.clone(),
            "EFI".into(),
            "Linux".into(),
            "jstack-recovery.efi".into(),
        ],
        DestinationPlacement::EspBootstrapLoader => vec![
            "esp".into(),
            partition,
            "EFI".into(),
            "JStack".into(),
            "Installations".into(),
            plan.body.install_id.to_string(),
            "jstack-bootstrap.efi".into(),
        ],
        DestinationPlacement::RootImageDeployment => {
            vec![
                "root".into(),
                partition,
                "images".into(),
                "jstack-root.raw".into(),
            ]
        }
        DestinationPlacement::InstalledInstallerUki => vec![
            "xbootldr".into(),
            partition.clone(),
            "EFI".into(),
            "Linux".into(),
            "jstack-installed-installer.efi".into(),
        ],
        DestinationPlacement::InstalledRecoveryUki => vec![
            "xbootldr".into(),
            partition.clone(),
            "EFI".into(),
            "Linux".into(),
            "jstack-installed-recovery.efi".into(),
        ],
    }
}

fn placement_token(placement: DestinationPlacement) -> &'static str {
    match placement {
        DestinationPlacement::XbootldrInstallerUki => "xbootldr-installer",
        DestinationPlacement::XbootldrOfflineSystemImage => "xbootldr-image",
        DestinationPlacement::XbootldrRecoveryUki => "xbootldr-recovery",
        DestinationPlacement::EspBootstrapLoader => "esp-loader",
        DestinationPlacement::RootImageDeployment => "root-image",
        DestinationPlacement::InstalledInstallerUki => "installed-installer",
        DestinationPlacement::InstalledRecoveryUki => "installed-recovery",
    }
}

fn copy_same_stream_verified(
    source: &mut StagedArtifact,
    destination: &mut File,
    release: &VerifiedReleaseManifest,
    role: jstack_installer_core::ArtifactRole,
    mut write_limit: Option<u64>,
) -> Result<VerifiedArtifactBytes, DestinationTransactionError> {
    source.file.seek(SeekFrom::Start(0))?;
    let mut verifier = release.artifact_stream_verifier(role)?;
    let mut buffer = [0_u8; 64 * 1024];
    while verifier.bytes_seen() < verifier.expected_size_bytes() {
        let remaining = verifier.expected_size_bytes() - verifier.bytes_seen();
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = source.file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(jstack_installer_core::ReleaseError::ArtifactTruncated(role).into());
        }
        let accepted = write_limit
            .map(|remaining| remaining.min(read as u64) as usize)
            .unwrap_or(read);
        if accepted != 0 {
            destination.write_all(&buffer[..accepted])?;
            verifier.update(&buffer[..accepted])?;
        }
        if let Some(remaining) = write_limit.as_mut() {
            *remaining -= accepted as u64;
            if accepted < read
                || (*remaining == 0 && verifier.bytes_seen() < verifier.expected_size_bytes())
            {
                return Err(io::Error::from_raw_os_error(28).into());
            }
        }
    }
    let mut trailing = [0_u8; 1];
    if source.file.read(&mut trailing)? != 0 {
        return Err(jstack_installer_core::ReleaseError::ArtifactTrailingBytes(role).into());
    }
    verifier.finish().map_err(Into::into)
}

fn verify_regular_file(
    path: &Path,
    release: &VerifiedReleaseManifest,
    role: jstack_installer_core::ArtifactRole,
) -> Result<VerifiedArtifactBytes, DestinationTransactionError> {
    let mut file = open_regular_read(path)?;
    ensure_single_link(&file, path)?;
    let mut verifier = release.artifact_stream_verifier(role)?;
    let mut buffer = [0_u8; 64 * 1024];
    while verifier.bytes_seen() < verifier.expected_size_bytes() {
        let remaining = verifier.expected_size_bytes() - verifier.bytes_seen();
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(jstack_installer_core::ReleaseError::ArtifactTruncated(role).into());
        }
        verifier.update(&buffer[..read])?;
    }
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(jstack_installer_core::ReleaseError::ArtifactTrailingBytes(role).into());
    }
    verifier.finish().map_err(Into::into)
}

fn reject_existing_outputs(paths: &[DestinationPaths]) -> Result<(), DestinationTransactionError> {
    for paths in paths {
        reject_case_collision(&paths.temporary)?;
        reject_case_collision(&paths.final_path)?;
        for path in [&paths.temporary, &paths.final_path] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(DestinationTransactionError::AlreadyExists(path.clone())),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn cleanup_owned_outputs(paths: &[DestinationPaths]) -> Result<(), DestinationTransactionError> {
    for paths in paths {
        for path in [&paths.temporary, &paths.final_path] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    let file = open_regular_read(path)?;
                    ensure_regular_file_io(&file, path)?;
                    ensure_single_link(&file, path)?;
                    drop(file);
                    remove_file_if_present(path)?;
                    sync_directory(
                        path.parent()
                            .ok_or_else(|| DestinationTransactionError::UnsafePath(path.clone()))?,
                    )?;
                }
                Ok(_) => return Err(DestinationTransactionError::UnsafePath(path.clone())),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn reject_case_collision(path: &Path) -> Result<(), DestinationTransactionError> {
    let parent = path
        .parent()
        .ok_or_else(|| DestinationTransactionError::UnsafePath(path.to_path_buf()))?;
    let expected = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| DestinationTransactionError::UnsafePath(path.to_path_buf()))?;
    let expected_folded = expected.to_ascii_lowercase();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(DestinationTransactionError::UnsafePath(entry.path()));
        };
        if name != expected && name.to_ascii_lowercase() == expected_folded {
            return Err(DestinationTransactionError::AlreadyExists(entry.path()));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_single_link(file: &File, path: &Path) -> Result<(), DestinationTransactionError> {
    use std::os::unix::fs::MetadataExt;
    if file.metadata()?.nlink() != 1 {
        return Err(DestinationTransactionError::HardLinked(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_single_link(_file: &File, _path: &Path) -> Result<(), DestinationTransactionError> {
    Err(DestinationTransactionError::UnsupportedHost)
}

fn map_staging_path_error(error: StagingError) -> DestinationTransactionError {
    match error {
        StagingError::UnsafePath(path) | StagingError::UnexpectedEntry(path) => {
            DestinationTransactionError::UnsafePath(path)
        }
        StagingError::Io(error) => DestinationTransactionError::Io(error),
        other => DestinationTransactionError::Staging(other),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Cursor;

    use ed25519_dalek::SigningKey;
    use jstack_installer_core::{
        Architecture, ArtifactRole, Inventory, ReleaseChannel, ReleaseTrustPolicy,
        ReleaseVerificationMode, SignedReleaseManifest, TrustedReleaseKey, create_install_plan,
        verify_release_manifest,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{StageProgress, StagingStore};

    const NOW: u64 = 1_800_000_000;
    const MANIFEST: &[u8] = include_bytes!("../../core/fixtures/signed-release-manifest.json");
    const INVENTORY: &[u8] = include_bytes!("../../core/fixtures/windows-11-basic-gpt.json");
    const ESP_LOADER: &[u8] = b"jstack-esp-loader-fixture\n";
    const INSTALLER_UKI: &[u8] = b"jstack-installer-uki-fixture\n";
    const OFFLINE_IMAGE: &[u8] = b"jstack-offline-system-image-fixture\n";
    const RECOVERY_UKI: &[u8] = b"jstack-recovery-uki-fixture\n";

    struct Fixture {
        temporary: TempDir,
        store: StagingStore,
        release: VerifiedReleaseManifest,
        plan: InstallPlan,
        staging_hash: Hash256,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = TempDir::new().unwrap();
            let mut store = StagingStore::open(temporary.path()).unwrap();
            let envelope: SignedReleaseManifest = serde_json::from_slice(MANIFEST).unwrap();
            let trusted_keys = [[1_u8; 32], [2_u8; 32]]
                .into_iter()
                .map(|seed| TrustedReleaseKey {
                    public_key: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
                    channels: vec![ReleaseChannel::Stable],
                })
                .collect();
            let policy = ReleaseTrustPolicy {
                channel: ReleaseChannel::Stable,
                architecture: Architecture::X86_64,
                state_model_id: envelope.signed.state_model_id.clone(),
                state_model_sha256: envelope.signed.state_model_sha256.clone(),
                installer_protocol_version: 1,
                now_unix_secs: NOW,
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
                previous_acceptance: None,
            };
            let pending =
                verify_release_manifest(MANIFEST, &policy, ReleaseVerificationMode::Acquire)
                    .unwrap();
            let release = store.persist_acceptance(pending).unwrap();
            let inventory: Inventory = serde_json::from_slice(INVENTORY).unwrap();
            let plan =
                create_install_plan(&inventory, &release.verified_release_requirements()).unwrap();
            for (role, bytes) in [
                (ArtifactRole::EspLoader, ESP_LOADER),
                (ArtifactRole::InstallerUki, INSTALLER_UKI),
                (ArtifactRole::OfflineSystemImage, OFFLINE_IMAGE),
                (ArtifactRole::RecoveryUki, RECOVERY_UKI),
            ] {
                assert!(matches!(
                    store
                        .stage_artifact(&release, role, 0, &mut Cursor::new(bytes))
                        .unwrap(),
                    StageProgress::Complete(_)
                ));
            }
            let staging_hash = store
                .persist_staging_evidence(&release)
                .unwrap()
                .evidence_hash()
                .clone();
            Self {
                temporary,
                store,
                release,
                plan,
                staging_hash,
            }
        }

        fn sources(&mut self, transition: DestinationTransition) -> Vec<StagedArtifact> {
            let intent = create_destination_intent(
                &self.release,
                &self.plan,
                &self.staging_hash,
                transition,
            )
            .unwrap();
            intent
                .artifacts
                .iter()
                .map(|item| {
                    self.store
                        .open_staged_artifact(&self.release, item.artifact.role)
                        .unwrap()
                })
                .collect()
        }

        fn observed(&self, transition: DestinationTransition) -> Hash256 {
            self.plan
                .body
                .partition_fingerprints
                .for_phase(transition.partition_phase())
                .clone()
        }

        fn journal(&self) -> DurableJournal {
            DurableJournal::open(self.temporary.path(), &self.plan.plan_hash).unwrap()
        }
    }

    #[derive(Clone, Copy)]
    struct FailAt(DestinationFaultPoint);

    impl DestinationFaultInjector for FailAt {
        fn should_fail(&mut self, point: DestinationFaultPoint) -> bool {
            point == self.0
        }
    }

    struct EnospcAt {
        artifact_index: usize,
        after_bytes: u64,
    }

    impl DestinationFaultInjector for EnospcAt {
        fn should_fail(&mut self, _point: DestinationFaultPoint) -> bool {
            false
        }

        fn maximum_written_bytes(&mut self, artifact_index: usize) -> Option<u64> {
            (artifact_index == self.artifact_index).then_some(self.after_bytes)
        }
    }

    #[test]
    fn exact_multi_artifact_copy_commits_once_and_replays_idempotently() {
        let mut fixture = Fixture::new();
        let transition = DestinationTransition::CopyVerifiedPayload;
        let observed = fixture.observed(transition);
        let mut journal = fixture.journal();
        let sources = fixture.sources(transition);
        let first = VmFileTransaction::default()
            .execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            )
            .unwrap();
        assert_eq!(first.evidence().artifacts.len(), 3);
        assert_eq!(journal.read_all().unwrap().len(), 3);

        let sources = fixture.sources(transition);
        let second = VmFileTransaction::default()
            .execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            )
            .unwrap();
        assert_eq!(first.evidence(), second.evidence());
        assert_eq!(journal.read_all().unwrap().len(), 3);
    }

    #[test]
    fn every_single_artifact_fault_boundary_retries_to_one_valid_commit() {
        let points = [
            DestinationFaultPoint::AfterIntentDurable,
            DestinationFaultPoint::AfterTemporaryVerified(0),
            DestinationFaultPoint::AfterAllTemporariesVerified,
            DestinationFaultPoint::AfterFinalReachable(0),
            DestinationFaultPoint::AfterFinalDirectoriesSynced,
            DestinationFaultPoint::BeforeCommitDurable,
            DestinationFaultPoint::AfterCommitDurable,
            DestinationFaultPoint::AfterStateAdvancedDurable,
        ];
        for point in points {
            let mut fixture = Fixture::new();
            let transition = DestinationTransition::DeployJstackImage;
            let observed = fixture.observed(transition);
            let mut journal = fixture.journal();
            let sources = fixture.sources(transition);
            assert!(matches!(
                VmFileTransaction::with_injector(FailAt(point)).execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                ),
                Err(DestinationTransactionError::Injected(actual)) if actual == point
            ));
            let sources = fixture.sources(transition);
            VmFileTransaction::default()
                .execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                )
                .unwrap();
            let records = journal.read_all().unwrap();
            assert_eq!(records.len(), 3, "fault point {point:?}");
            assert_eq!(records[0].record_type, JournalRecordType::ActionIntent);
            assert_eq!(records[1].record_type, JournalRecordType::ActionCommitted);
            assert_eq!(records[2].record_type, JournalRecordType::StateAdvanced);
        }
    }

    #[test]
    fn mid_stream_enospc_leaves_only_a_reconcilable_temporary() {
        let mut fixture = Fixture::new();
        let transition = DestinationTransition::DeployJstackImage;
        let observed = fixture.observed(transition);
        let intent = create_destination_intent(
            &fixture.release,
            &fixture.plan,
            &fixture.staging_hash,
            transition,
        )
        .unwrap();
        let paths =
            prepare_paths(fixture.temporary.path(), &fixture.plan, transition, &intent).unwrap();
        let mut journal = fixture.journal();
        let sources = fixture.sources(transition);
        assert!(matches!(
            VmFileTransaction::with_injector(EnospcAt {
                artifact_index: 0,
                after_bytes: 1,
            })
            .execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::Io(error)) if error.raw_os_error() == Some(28)
        ));
        assert_eq!(journal.read_all().unwrap().len(), 1);
        assert_eq!(fs::metadata(&paths[0].temporary).unwrap().len(), 1);
        assert!(!paths[0].final_path.exists());

        let sources = fixture.sources(transition);
        VmFileTransaction::default()
            .execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            )
            .unwrap();
        assert!(!paths[0].temporary.exists());
        assert!(paths[0].final_path.is_file());
        assert_eq!(journal.read_all().unwrap().len(), 3);
    }

    #[test]
    fn per_plan_lock_blocks_a_concurrent_transaction() {
        use std::thread;
        use std::time::Duration;

        let mut fixture = Fixture::new();
        let transition = DestinationTransition::DeployJstackImage;
        let observed = fixture.observed(transition);
        let sources = fixture.sources(transition);
        let mut journal = fixture.journal();
        ensure_private_directory(fixture.temporary.path(), "transaction-locks").unwrap();
        let lock_path = fixture
            .temporary
            .path()
            .join("transaction-locks")
            .join(format!("{}.lock", fixture.plan.plan_hash.as_str()));
        let lock = open_lock_file(&lock_path).unwrap();
        FileExt::lock(&lock).unwrap();
        let root = fixture.temporary.path().to_path_buf();
        let plan_hash = fixture.plan.plan_hash.clone();

        thread::scope(|scope| {
            let handle = scope.spawn(move || {
                VmFileTransaction::default().execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                )
            });
            thread::sleep(Duration::from_millis(100));
            assert!(!handle.is_finished());
            FileExt::unlock(&lock).unwrap();
            handle.join().unwrap().unwrap();
        });
        let mut reopened = DurableJournal::open(root, &plan_hash).unwrap();
        assert_eq!(reopened.read_all().unwrap().len(), 3);
    }

    #[test]
    fn every_multi_artifact_copy_boundary_retries_without_partial_batch_commit() {
        let points = [
            DestinationFaultPoint::AfterTemporaryVerified(0),
            DestinationFaultPoint::AfterTemporaryVerified(1),
            DestinationFaultPoint::AfterTemporaryVerified(2),
            DestinationFaultPoint::AfterAllTemporariesVerified,
            DestinationFaultPoint::AfterFinalReachable(0),
            DestinationFaultPoint::AfterFinalReachable(1),
            DestinationFaultPoint::AfterFinalReachable(2),
            DestinationFaultPoint::AfterFinalDirectoriesSynced,
            DestinationFaultPoint::BeforeCommitDurable,
            DestinationFaultPoint::AfterCommitDurable,
            DestinationFaultPoint::AfterStateAdvancedDurable,
        ];
        for point in points {
            let mut fixture = Fixture::new();
            let transition = DestinationTransition::CopyVerifiedPayload;
            let observed = fixture.observed(transition);
            let mut journal = fixture.journal();
            let sources = fixture.sources(transition);
            assert!(matches!(
                VmFileTransaction::with_injector(FailAt(point)).execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                ),
                Err(DestinationTransactionError::Injected(actual)) if actual == point
            ));
            let sources = fixture.sources(transition);
            let committed = VmFileTransaction::default()
                .execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                )
                .unwrap();
            assert_eq!(committed.evidence().artifacts.len(), 3, "{point:?}");
            let records = journal.read_all().unwrap();
            assert_eq!(records.len(), 3, "{point:?}");
            assert_eq!(records[0].record_type, JournalRecordType::ActionIntent);
            assert_eq!(records[1].record_type, JournalRecordType::ActionCommitted);
            assert_eq!(records[2].record_type, JournalRecordType::StateAdvanced);
        }
    }

    #[test]
    fn committed_destination_tamper_fails_closed_on_recovery() {
        let mut fixture = Fixture::new();
        let transition = DestinationTransition::DeployJstackImage;
        let observed = fixture.observed(transition);
        let intent = create_destination_intent(
            &fixture.release,
            &fixture.plan,
            &fixture.staging_hash,
            transition,
        )
        .unwrap();
        let paths =
            prepare_paths(fixture.temporary.path(), &fixture.plan, transition, &intent).unwrap();
        let mut journal = fixture.journal();
        let sources = fixture.sources(transition);
        VmFileTransaction::default()
            .execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            )
            .unwrap();
        fs::write(&paths[0].final_path, b"tampered").unwrap();
        let sources = fixture.sources(transition);
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::Release(_))
        ));
        assert_eq!(journal.read_all().unwrap().len(), 3);
    }

    #[test]
    fn regular_existing_output_and_hardlinks_fail_closed() {
        use std::fs::hard_link;

        let mut fixture = Fixture::new();
        let transition = DestinationTransition::DeployJstackImage;
        let observed = fixture.observed(transition);
        let intent = create_destination_intent(
            &fixture.release,
            &fixture.plan,
            &fixture.staging_hash,
            transition,
        )
        .unwrap();
        let paths =
            prepare_paths(fixture.temporary.path(), &fixture.plan, transition, &intent).unwrap();
        fs::write(&paths[0].final_path, b"foreign").unwrap();
        let sources = fixture.sources(transition);
        let mut journal = fixture.journal();
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::AlreadyExists(_))
        ));
        assert!(journal.read_all().unwrap().is_empty());

        let mut fixture = Fixture::new();
        let observed = fixture.observed(transition);
        let sources = fixture.sources(transition);
        let artifact_path = fixture
            .temporary
            .path()
            .join("artifacts")
            .join(format!("{}.blob", sources[0].sha256().as_str()));
        hard_link(
            &artifact_path,
            fixture.temporary.path().join("source-alias"),
        )
        .unwrap();
        let mut journal = fixture.journal();
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::HardLinked(_))
        ));
        assert_eq!(journal.read_all().unwrap().len(), 1);

        let mut fixture = Fixture::new();
        let observed = fixture.observed(transition);
        let intent = create_destination_intent(
            &fixture.release,
            &fixture.plan,
            &fixture.staging_hash,
            transition,
        )
        .unwrap();
        let paths =
            prepare_paths(fixture.temporary.path(), &fixture.plan, transition, &intent).unwrap();
        let mut journal = fixture.journal();
        let sources = fixture.sources(transition);
        assert!(
            VmFileTransaction::with_injector(FailAt(DestinationFaultPoint::AfterFinalReachable(0)))
                .execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                )
                .is_err()
        );
        hard_link(
            &paths[0].final_path,
            fixture.temporary.path().join("destination-alias"),
        )
        .unwrap();
        let sources = fixture.sources(transition);
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::HardLinked(_))
        ));
        assert_eq!(journal.read_all().unwrap().len(), 1);
    }

    #[test]
    fn wrong_order_and_wrong_fingerprint_fail_before_journal_intent() {
        let mut fixture = Fixture::new();
        let transition = DestinationTransition::CopyVerifiedPayload;
        let mut sources = fixture.sources(transition);
        sources.swap(0, 1);
        let mut journal = fixture.journal();
        let observed = fixture.observed(transition);
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::InvalidBinding)
        ));
        assert!(journal.read_all().unwrap().is_empty());

        let sources = fixture.sources(transition);
        let wrong = Hash256::parse("f".repeat(64)).unwrap();
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &wrong,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::InvalidBinding)
        ));
        assert!(journal.read_all().unwrap().is_empty());
    }

    #[test]
    fn staged_source_tamper_is_detected_on_the_copied_stream() {
        let mut fixture = Fixture::new();
        let transition = DestinationTransition::DeployJstackImage;
        let sources = fixture.sources(transition);
        let artifact_path = fixture
            .temporary
            .path()
            .join("artifacts")
            .join(format!("{}.blob", sources[0].sha256().as_str()));
        fs::write(&artifact_path, vec![0_u8; sources[0].size_bytes() as usize]).unwrap();
        let observed = fixture.observed(transition);
        let mut journal = fixture.journal();
        assert!(matches!(
            VmFileTransaction::default().execute(
                &mut journal,
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                &observed,
                transition,
                sources,
            ),
            Err(DestinationTransactionError::Release(_))
        ));
        assert_eq!(journal.read_all().unwrap().len(), 1);
    }

    #[test]
    fn preexisting_symlink_and_case_collision_are_never_claimed_by_an_intent() {
        use std::os::unix::fs::symlink;

        for case_collision in [false, true] {
            let mut fixture = Fixture::new();
            let transition = DestinationTransition::DeployJstackImage;
            let intent = create_destination_intent(
                &fixture.release,
                &fixture.plan,
                &fixture.staging_hash,
                transition,
            )
            .unwrap();
            let paths = prepare_paths(fixture.temporary.path(), &fixture.plan, transition, &intent)
                .unwrap();
            if case_collision {
                let colliding = paths[0]
                    .final_path
                    .parent()
                    .unwrap()
                    .join("JSTACK-ROOT.RAW");
                fs::write(colliding, b"foreign").unwrap();
            } else {
                symlink("foreign", &paths[0].final_path).unwrap();
            }
            let sources = fixture.sources(transition);
            let observed = fixture.observed(transition);
            let mut journal = fixture.journal();
            assert!(matches!(
                VmFileTransaction::default().execute(
                    &mut journal,
                    &fixture.release,
                    &fixture.plan,
                    &fixture.staging_hash,
                    &observed,
                    transition,
                    sources,
                ),
                Err(DestinationTransactionError::AlreadyExists(_))
            ));
            assert!(journal.read_all().unwrap().is_empty());
        }
    }
}
