use super::model::StableDiskIdentity;
use serde::Deserialize;
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
    Ok(d)
}
pub fn resolve_unique(id: &StableDiskIdentity) -> Result<PathBuf, String> {
    let m = devices()?
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
    if !target.mountpoints.is_empty() {
        return Err("target ancestry is mounted".into());
    }
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    if swaps
        .lines()
        .skip(1)
        .any(|l| l.split_whitespace().next() == Some(target.path.to_string_lossy().as_ref()))
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
    if source.trim() == target.path.to_string_lossy() {
        return Err("state is on target".into());
    }
    Ok(())
}
