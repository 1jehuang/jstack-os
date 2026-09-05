#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("error: Ubuntu whole-disk installer is supported only on Linux");
    std::process::exit(1)
}
#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = linux::run() {
        eprintln!("error: {e}");
        std::process::exit(1)
    }
}
#[cfg(target_os = "linux")]
mod linux {
    use jstack_installer_controller::GraphModel;
    use jstack_installer_controller::ubuntu::*;
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};
    const GRAPH: &[u8] = include_bytes!("../../../model/ubuntu-whole-disk-state-graph.json");
    #[derive(serde::Serialize, serde::Deserialize)]
    struct InitEvidence {
        schema: String,
        target: StableDiskIdentity,
        recovery: RecoveryIdentity,
    }
    fn facts(ids: &[&str]) -> Result<Evidence, String> {
        let mut e = Evidence::new();
        for id in ids {
            e.observe(id, true)?
        }
        Ok(e)
    }
    pub fn run() -> Result<(), String> {
        GraphModel::load_verified_ubuntu_whole_disk(GRAPH)
            .map_err(|e| format!("embedded graph invalid: {e}"))?;
        let a: Vec<String> = std::env::args().skip(1).collect();
        match a.first().map(String::as_str) {
            Some("inspect") => {
                let (d, s) = disk_state(&a)?;
                inspect(&d, &s)?;
                println!("INSPECT_OK");
                Ok(())
            }
            Some("init") => {
                let (d, s) = disk_state(&a)?;
                init(&d, &s)
            }
            Some("prepare") => prepare(&a),
            Some("deploy") | Some("resume") => {
                let p = flag(&a, "--plan")?;
                let (plan, canonical_plan) = read_plan(Path::new(&p))?;
                let target = resolve_unique(&plan.body.target)?;
                let durable_executable = canonical_plan
                    .parent()
                    .ok_or("plan has no state directory")?
                    .join("jstack-ubuntu-installer")
                    .canonicalize()
                    .map_err(err)?;
                marker(&format!(
                    "JSTK_UBUNTU_RECOVERY command='{} resume --plan {}'",
                    durable_executable.display(),
                    canonical_plan.display()
                ));
                deploy_files(Path::new(&p), &target, true)
            }
            Some("status") => {
                let s = status(Path::new(&flag(&a, "--plan")?))?;
                println!("STATE={}", s.state);
                println!("NEXT_OFFSET={}", s.next_offset);
                Ok(())
            }
            _ => Err(
                "usage: jstack-ubuntu-installer inspect|init|prepare|deploy|resume|status ..."
                    .into(),
            ),
        }
    }
    fn disk_state(a: &[String]) -> Result<(PathBuf, PathBuf), String> {
        Ok((flag(a, "--disk")?.into(), flag(a, "--state-dir")?.into()))
    }
    fn flag(a: &[String], n: &str) -> Result<String, String> {
        a.iter()
            .position(|x| x == n)
            .and_then(|i| a.get(i + 1))
            .cloned()
            .ok_or_else(|| format!("missing {n}"))
    }
    fn inspect(d: &Path, s: &Path) -> Result<(), String> {
        verify_host_scope(s)?;
        verify_unused_target(d, s)?;
        if s.exists() {
            return validate_init(d, s);
        }
        let parent = nearest(s)?;
        safe_parent(&parent)?;
        Ok(())
    }
    fn nearest(p: &Path) -> Result<PathBuf, String> {
        let mut x = p.to_path_buf();
        while !x.exists() {
            x = x.parent().ok_or("no existing state parent")?.to_path_buf()
        }
        x.canonicalize().map_err(err)
    }
    fn safe_parent(p: &Path) -> Result<(), String> {
        let m = std::fs::symlink_metadata(p).map_err(err)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("state parent must be root-owned and not group/world writable".into());
        }
        Ok(())
    }
    fn verify_host_scope(state: &Path) -> Result<(), String> {
        let os = std::fs::read_to_string("/etc/os-release").map_err(err)?;
        if !os.lines().any(|l| l == "ID=ubuntu" || l == "ID=\"ubuntu\"") {
            return Err("recovery host must be Ubuntu".into());
        }
        if !Path::new("/sys/firmware/efi").is_dir() {
            return Err("recovery host must be booted via UEFI".into());
        }
        let parent = nearest(state)?;
        let out = Command::new("findmnt")
            .args(["-n", "-o", "FSTYPE", "--target"])
            .arg(parent)
            .output()
            .map_err(err)?;
        let fs = String::from_utf8(out.stdout).map_err(err)?;
        if !out.status.success() || matches!(fs.trim(), "tmpfs" | "ramfs" | "overlay") {
            return Err("recovery state must be on persistent storage".into());
        }
        let boot = Command::new("findmnt")
            .args(["-n", "--target", "/boot"])
            .status()
            .map_err(err)?;
        if !boot.success() {
            return Err("recovery host boot filesystem is unavailable".into());
        }
        Ok(())
    }
    fn init(d: &Path, s: &Path) -> Result<(), String> {
        verify_host_scope(s)?;
        verify_unused_target(d, s)?;
        if s.exists() {
            return validate_init(d, s);
        }
        let parent = s.parent().ok_or("state root needs parent")?;
        safe_parent(&nearest(parent)?)?;
        std::fs::create_dir(s).map_err(err)?;
        std::fs::set_permissions(s, std::fs::Permissions::from_mode(0o700)).map_err(err)?;
        std::fs::create_dir(s.join("artifact-build")).map_err(err)?;
        std::fs::set_permissions(
            s.join("artifact-build"),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(err)?;
        let target = observe_target(d)?.identity;
        let (filesystem_uuid, backing_serial, backing_wwn) = recovery(s)?;
        let evidence = InitEvidence {
            schema: "jstack-ubuntu-state-v1".into(),
            target,
            recovery: RecoveryIdentity {
                filesystem_uuid,
                backing_serial,
                backing_wwn,
            },
        };
        durable_write(
            &s.join("initialized.json"),
            &serde_json::to_vec(&evidence).map_err(err)?,
        )?;
        sync_dir(s)?;
        Ok(())
    }
    fn validate_init(d: &Path, s: &Path) -> Result<(), String> {
        let m = std::fs::symlink_metadata(s).map_err(err)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o077 != 0 {
            return Err("unsafe initialized state root".into());
        }
        let evidence: InitEvidence =
            serde_json::from_reader(File::open(s.join("initialized.json")).map_err(err)?)
                .map_err(err)?;
        if evidence.schema != "jstack-ubuntu-state-v1"
            || observe_target(d)?.identity != evidence.target
        {
            return Err("initialized state identity mismatch".into());
        }
        verify_recovery_identity(s, &evidence.recovery)
    }
    fn prepare(a: &[String]) -> Result<(), String> {
        let (d, s) = disk_state(a)?;
        verify_host_scope(&s)?;
        let src = PathBuf::from(flag(a, "--artifact-source")?);
        secure_input_file(&src, "artifact source")?;
        verify_unused_target(&d, &s)?;
        if !s.join("initialized.json").is_file() {
            return Err("state directory was not initialized".into());
        }
        let target = observe_target(&d)?.identity;
        let (uuid, backing_serial, backing_wwn) = recovery(&s)?;
        if target.stable_serial == backing_serial {
            return Err("recovery host and target are same disk".into());
        }
        let chunk_bytes = DEFAULT_CHUNK_SIZE;
        let (full, chunks, size) = hash_image(&src, chunk_bytes)?;
        if size != target.size_bytes {
            return Err(format!(
                "artifact size {size} must equal target size {}",
                target.size_bytes
            ));
        }
        let rel = PathBuf::from(format!("artifacts/{full}.raw"));
        let exe = std::env::current_exe().map_err(err)?;
        let durable_exe = s.join("jstack-ubuntu-installer");
        if durable_exe.exists() {
            secure_input_file(&durable_exe, "persisted installer")?;
            if hash_image(&exe, 1024 * 1024)?.0 != hash_image(&durable_exe, 1024 * 1024)?.0 {
                return Err("persisted installer differs from running executable".into());
            }
        } else {
            copy_file(&exe, &durable_exe)?;
            std::fs::set_permissions(&durable_exe, std::fs::Permissions::from_mode(0o700))
                .map_err(err)?
        }
        durable_write(&s.join("ubuntu-whole-disk-state-graph.json"), GRAPH)?;
        let body = PlanBody {
            model_id: GRAPH_ID.into(),
            graph_digest: GRAPH_SHA256.into(),
            created_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(err)?
                .as_millis() as u64,
            target,
            recovery: RecoveryIdentity {
                filesystem_uuid: uuid,
                backing_serial,
                backing_wwn,
            },
            artifact: ArtifactManifest {
                sha256: full.clone(),
                size_bytes: size,
                relative_store_path: rel.clone(),
                chunks,
            },
            deployment: Deployment { chunk_bytes },
        };
        let hash = hex(&Sha256::digest(serde_json::to_vec(&body).map_err(err)?));
        let phrase = format!("ERASE {}", body.target.stable_serial);
        let plan = UbuntuPlan {
            schema_version: PLAN_SCHEMA.into(),
            plan_hash: hash.clone(),
            body,
            confirmation: Confirmation {
                exact_phrase: phrase.clone(),
                confirmed_plan_hash: hash.clone(),
            },
        };
        plan.validate()?;
        let journal = Journal::open(&s, &hash)?;
        let existing = journal.read()?;
        let pre = facts(&[
            "scope_supported",
            "release_policy",
            "recovery_host_bootable",
            "target_outside_recovery_host",
            "artifact_source_verified",
        ])?;
        let mut prepare_permit = begin_transition("discovered", "prepare", &pre)?;
        prepare_permit.require_action("inspect_scope", &Evidence::new())?;
        if existing.is_empty() {
            journal.append(Event::StageIntent {
                artifact_sha256: full.clone(),
                size_bytes: size,
            })?;
        }
        let intent = facts(&["action_intent_durable"])?;
        prepare_permit.require_action("stage_artifact", &intent)?;
        let dst = s.join(&rel);
        if !dst.parent().unwrap().exists() {
            std::fs::create_dir(dst.parent().unwrap()).map_err(err)?;
        }
        if !dst.exists() {
            sparse_copy(&src, &dst, chunk_bytes)?;
        }
        if hash_image(&dst, chunk_bytes)?.0 != full {
            return Err("promoted artifact verification failed".into());
        }
        let post = facts(&[
            "artifact_durable_on_recovery_host",
            "staged_artifact_digest_verified",
        ])?;
        if prepare_permit.finish(&post)? != "artifact_prepared" {
            return Err("graph prepare destination mismatch".into());
        }
        if journal
            .read()?
            .iter()
            .all(|r| !matches!(r.event, Event::StageCommit { .. }))
        {
            journal.append(Event::StageCommit {
                artifact_sha256: full.clone(),
                size_bytes: size,
            })?;
        }
        eprintln!(
            "Exact destructive plan:\n{}",
            serde_json::to_string_pretty(&plan).map_err(err)?
        );
        if !a.iter().any(|x| x == "--yes") {
            eprintln!("Type exactly '{phrase}' to authorize the plan:");
            let mut answer = String::new();
            BufReader::new(File::open("/dev/tty").map_err(err)?)
                .read_line(&mut answer)
                .map_err(err)?;
            if answer.trim_end() != phrase {
                return Err("exact destructive confirmation did not match".into());
            }
        }
        let pp = s.join(format!("plan-{hash}.json"));
        durable_write(&pp, &serde_json::to_vec_pretty(&plan).map_err(err)?)?;
        let pre = facts(&[
            "artifact_staged_and_verified",
            "stable_target_identity_observed",
            "exact_plan_displayed",
        ])?;
        let mut permit = begin_transition("artifact_prepared", "authorize", &pre)?;
        permit.require_action("record_authorization", &Evidence::new())?;
        if journal
            .read()?
            .iter()
            .all(|r| !matches!(r.event, Event::Authorized))
        {
            journal.append(Event::Authorized)?;
        }
        let post = facts(&["exact_plan_authorization_recorded"])?;
        if permit.finish(&post)? != "authorized" {
            return Err("graph authorization destination mismatch".into());
        }
        marker(&format!("JSTK_UBUNTU_AUTHORIZED plan={hash}"));
        println!("PLAN_PATH={}", pp.canonicalize().map_err(err)?.display());
        Ok(())
    }
    fn recovery(s: &Path) -> Result<(String, String, Option<String>), String> {
        let o = Command::new("findmnt")
            .args(["-n", "-o", "UUID,SOURCE", "--target"])
            .arg(s)
            .output()
            .map_err(err)?;
        if !o.status.success() {
            return Err("cannot identify recovery filesystem".into());
        }
        let text = String::from_utf8(o.stdout).map_err(err)?;
        let mut x = text.split_whitespace();
        let uuid = x
            .next()
            .ok_or("recovery filesystem UUID missing")?
            .to_string();
        let source = x.next().ok_or("recovery source missing")?;
        let ds = devices()?;
        let source = Path::new(source).canonicalize().map_err(err)?;
        let part = ds
            .iter()
            .find(|d| d.path.canonicalize().ok().as_ref() == Some(&source))
            .ok_or("recovery source not in lsblk")?;
        let disk = if part.dev_type == "disk" {
            part
        } else {
            let pk = part
                .pkname
                .as_ref()
                .ok_or("recovery backing disk missing")?;
            ds.iter()
                .find(|d| {
                    d.dev_type == "disk"
                        && (d.path.file_name().and_then(|x| x.to_str()) == Some(pk)
                            || d.path.to_string_lossy() == *pk)
                })
                .ok_or("recovery backing disk missing")?
        };
        if disk.identity.stable_serial.is_empty() {
            return Err("recovery backing stable serial missing".into());
        }
        Ok((
            uuid,
            disk.identity.stable_serial.clone(),
            disk.identity.stable_wwn.clone(),
        ))
    }
    fn hash_image(p: &Path, chunk: u64) -> Result<(String, Vec<ArtifactChunk>, u64), String> {
        let mut f = File::open(p).map_err(err)?;
        let size = f.metadata().map_err(err)?.len();
        let mut all = Sha256::new();
        let mut out = vec![];
        let mut off = 0;
        while off < size {
            let n = (size - off).min(chunk) as usize;
            let mut b = vec![0; n];
            f.read_exact(&mut b).map_err(err)?;
            all.update(&b);
            out.push(ArtifactChunk {
                offset: off,
                length: n as u64,
                sha256: hex(&Sha256::digest(&b)),
            });
            off += n as u64
        }
        Ok((hex(&all.finalize()), out, size))
    }
    fn secure_input_file(p: &Path, what: &str) -> Result<(), String> {
        let m = std::fs::symlink_metadata(p).map_err(err)?;
        if !m.file_type().is_file()
            || m.file_type().is_symlink()
            || m.nlink() != 1
            || m.uid() != 0
            || m.mode() & 0o022 != 0
        {
            return Err(format!(
                "{what} must be a regular single-link non-symlink file"
            ));
        }
        Ok(())
    }
    fn sparse_copy(src: &Path, dst: &Path, chunk: u64) -> Result<(), String> {
        let mut i = File::open(src).map_err(err)?;
        let size = i.metadata().map_err(err)?.len();
        let mut o = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(dst)
            .map_err(err)?;
        let mut off = 0;
        while off < size {
            let n = (size - off).min(chunk) as usize;
            let mut b = vec![0; n];
            i.read_exact(&mut b).map_err(err)?;
            if b.iter().any(|x| *x != 0) {
                o.seek(SeekFrom::Start(off))
                    .and_then(|_| o.write_all(&b))
                    .map_err(err)?
            }
            off += n as u64
        }
        o.set_len(size).and_then(|_| o.sync_all()).map_err(err)?;
        sync_dir(dst.parent().unwrap())?;
        Ok(())
    }
    fn copy_file(a: &Path, b: &Path) -> Result<(), String> {
        let data = std::fs::read(a).map_err(err)?;
        durable_write(b, &data)
    }
    fn durable_write(p: &Path, b: &[u8]) -> Result<(), String> {
        let tmp = p.with_extension("tmp");
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(err)?;
        f.write_all(b).and_then(|_| f.sync_all()).map_err(err)?;
        std::fs::rename(&tmp, p).map_err(err)?;
        sync_dir(p.parent().unwrap())?;
        Ok(())
    }
    fn sync_dir(p: &Path) -> Result<(), String> {
        File::open(p).and_then(|f| f.sync_all()).map_err(err)
    }
    fn err<E: std::fmt::Display>(e: E) -> String {
        e.to_string()
    }
}
