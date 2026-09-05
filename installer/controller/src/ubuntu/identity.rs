use super::model::{RecoveryIdentity, StableDiskIdentity};
use serde::Deserialize;
use std::fs::File;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub struct ObservedDevice {
    pub path: PathBuf,
    pub identity: StableDiskIdentity,
    pub dev_type: String,
    pub mountpoints: Vec<String>,
    pub pkname: Option<String>,
}
#[derive(Deserialize)]
struct Listing {
    blockdevices: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    path: String,
    serial: Option<String>,
    wwn: Option<String>,
    size: u64,
    #[serde(rename = "log-sec")]
    log_sec: u64,
    #[serde(rename = "type")]
    kind: String,
    pkname: Option<String>,
    mountpoints: Option<Vec<Option<String>>>,
    children: Option<Vec<Entry>>,
}
fn flatten(e: Entry, out: &mut Vec<ObservedDevice>) {
    out.push(ObservedDevice {
        path: e.path.into(),
        identity: StableDiskIdentity {
            stable_serial: e.serial.unwrap_or_default(),
            stable_wwn: e.wwn.filter(|s| !s.is_empty()),
            size_bytes: e.size,
            logical_sector_bytes: e.log_sec,
        },
        dev_type: e.kind,
        mountpoints: e
            .mountpoints
            .unwrap_or_default()
            .into_iter()
            .flatten()
            .collect(),
        pkname: e.pkname,
    });
    for c in e.children.unwrap_or_default() {
        flatten(c, out)
    }
}
pub fn devices() -> Result<Vec<ObservedDevice>, String> {
    let o = Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "--paths",
            "--output",
            "PATH,SERIAL,WWN,SIZE,LOG-SEC,TYPE,PKNAME,MOUNTPOINTS",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err("lsblk failed".into());
    }
    let l: Listing = serde_json::from_slice(&o.stdout).map_err(|e| format!("lsblk JSON: {e}"))?;
    let mut v = vec![];
    for e in l.blockdevices {
        flatten(e, &mut v)
    }
    Ok(v)
}
pub fn observe_target(path: &Path) -> Result<ObservedDevice, String> {
    let canonical = path.canonicalize().map_err(|e| e.to_string())?;
    let mut m = devices()?
        .into_iter()
        .filter(|d| d.path.canonicalize().ok().as_ref() == Some(&canonical))
        .collect::<Vec<_>>();
    if m.len() != 1 {
        return Err("target path does not resolve uniquely".into());
    }
    let d = m.remove(0);
    if d.dev_type != "disk" || d.identity.stable_serial.is_empty() {
        return Err("target must be a whole disk with stable serial".into());
    }
    let duplicates = devices()?
        .into_iter()
        .filter(|x| {
            x.dev_type == "disk"
                && (x.identity.stable_serial == d.identity.stable_serial
                    || (d.identity.stable_wwn.is_some()
                        && x.identity.stable_wwn == d.identity.stable_wwn))
        })
        .count();
    if duplicates != 1 {
        return Err("target stable serial/WWN is ambiguous".into());
    }
    Ok(d)
}
pub fn resolve_unique(id: &StableDiskIdentity) -> Result<PathBuf, String> {
    let all = devices()?;
    let matches = all
        .iter()
        .filter(|d| {
            d.dev_type == "disk"
                && (d.identity.stable_serial == id.stable_serial
                    || (id.stable_wwn.is_some() && d.identity.stable_wwn == id.stable_wwn))
        })
        .count();
    if matches != 1 {
        return Err("stable target identity is missing or ambiguous".into());
    }
    let m = all
        .into_iter()
        .filter(|d| d.dev_type == "disk" && d.identity == *id)
        .collect::<Vec<_>>();
    if m.len() != 1 {
        return Err("stable target identity is missing or ambiguous".into());
    }
    Ok(m[0].path.clone())
}
pub fn verify_unused_target(path: &Path, state_dir: &Path) -> Result<(), String> {
    let target = observe_target(path)?;
    let all = devices()?;
    let target_name = target
        .path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or("invalid target name")?;
    let on_target =
        |d: &ObservedDevice| d.path == target.path || d.pkname.as_deref() == Some(target_name);
    if all
        .iter()
        .any(|d| on_target(d) && !d.mountpoints.is_empty())
    {
        return Err("target ancestry is mounted".into());
    }
    let swaps =
        std::fs::read_to_string("/proc/swaps").map_err(|e| format!("cannot inspect swaps: {e}"))?;
    if swaps
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next())
        .any(|s| {
            all.iter()
                .find(|d| d.path == Path::new(s))
                .is_some_and(&on_target)
        })
    {
        return Err("target is swap".into());
    }
    let state = state_dir
        .parent()
        .unwrap_or(Path::new("/"))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let out = Command::new("findmnt")
        .args(["-n", "-o", "SOURCE", "--target"])
        .arg(&state)
        .output()
        .map_err(|e| e.to_string())?;
    let source = String::from_utf8_lossy(&out.stdout);
    let state_source = Path::new(source.trim())
        .canonicalize()
        .map_err(|_| "state filesystem source is not a resolvable block device")?;
    if all
        .iter()
        .find(|d| d.path.canonicalize().ok().as_ref() == Some(&state_source))
        .is_some_and(on_target)
    {
        return Err("state is on target".into());
    }
    Ok(())
}

pub fn verify_recovery_identity(
    state_dir: &Path,
    expected: &RecoveryIdentity,
) -> Result<(), String> {
    let out = Command::new("findmnt")
        .args(["-n", "-o", "UUID,SOURCE", "--target"])
        .arg(state_dir)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("cannot inspect recovery filesystem".into());
    }
    let text = String::from_utf8(out.stdout).map_err(|e| e.to_string())?;
    let mut fields = text.split_whitespace();
    if fields.next() != Some(expected.filesystem_uuid.as_str()) {
        return Err("recovery filesystem UUID changed".into());
    }
    let source = Path::new(fields.next().ok_or("recovery source missing")?)
        .canonicalize()
        .map_err(|_| "recovery source is not a block device")?;
    let all = devices()?;
    let part = all
        .iter()
        .find(|d| d.path.canonicalize().ok().as_ref() == Some(&source))
        .ok_or("recovery source missing from topology")?;
    let disk = if part.dev_type == "disk" {
        part
    } else {
        let parent = part
            .pkname
            .as_deref()
            .ok_or("recovery backing disk missing")?;
        all.iter()
            .find(|d| {
                d.dev_type == "disk"
                    && (d.path.file_name().and_then(|x| x.to_str()) == Some(parent)
                        || d.path.to_string_lossy() == parent)
            })
            .ok_or("recovery backing disk missing")?
    };
    if disk.identity.stable_serial != expected.backing_serial
        || disk.identity.stable_wwn != expected.backing_wwn
    {
        return Err("recovery backing identity changed".into());
    }
    Ok(())
}

pub fn verify_open_target(
    file: &File,
    path: &Path,
    expected: &StableDiskIdentity,
) -> Result<(), String> {
    let descriptor = file.metadata().map_err(|e| e.to_string())?;
    let named = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !descriptor.file_type().is_block_device()
        || !named.file_type().is_block_device()
        || descriptor.rdev() != named.rdev()
    {
        return Err("open target descriptor is not the freshly resolved whole block device".into());
    }
    if observe_target(path)?.identity != *expected {
        return Err("open target stable identity changed".into());
    }
    Ok(())
}
