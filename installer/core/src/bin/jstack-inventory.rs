#![deny(unsafe_code)]

use std::{env, fs, process::ExitCode};

use jstack_installer_core::{WindowsStorageSnapshot, normalize_windows_snapshot};

const COLLECTOR: &str = include_str!("../../assets/collect-windows-inventory.ps1");

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let result = match args.as_slice() {
        [_] => collect_snapshot().and_then(normalize),
        [_, flag, path] if flag == "--from-snapshot" => fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| parse_snapshot(&bytes))
            .and_then(normalize),
        _ => Err("usage: jstack-inventory [--from-snapshot <snapshot.json>]".to_owned()),
    };
    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jstack-inventory: {error}");
            ExitCode::from(1)
        }
    }
}

fn parse_snapshot(bytes: &[u8]) -> Result<WindowsStorageSnapshot, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid snapshot JSON: {error}"))
}

fn normalize(snapshot: WindowsStorageSnapshot) -> Result<String, String> {
    let inventory = normalize_windows_snapshot(&snapshot).map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&inventory).map_err(|error| error.to_string())
}

#[cfg(target_os = "windows")]
fn collect_snapshot() -> Result<WindowsStorageSnapshot, String> {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::PathBuf,
        process::Command,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    #[allow(unsafe_code)]
    fn trusted_system_directory() -> Result<PathBuf, String> {
        const BUFFER_CAPACITY: u32 = 32768;
        let mut buffer = vec![0_u16; BUFFER_CAPACITY as usize];
        // SAFETY: the buffer is valid for `buffer.len()` writable UTF-16 code
        // units. The API returns the number of initialized units, excluding the
        // terminator on success. No pointer escapes this call.
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), BUFFER_CAPACITY) };
        if length == 0 {
            return Err(format!(
                "could not discover the Windows system directory: {}",
                std::io::Error::last_os_error()
            ));
        }
        let length = usize::try_from(length).map_err(|error| error.to_string())?;
        if length >= buffer.len() {
            return Err("Windows system directory exceeded the trusted buffer".to_owned());
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
    }

    fn trusted_system_drive(system_directory: &std::path::Path) -> Result<String, String> {
        let encoded: Vec<u16> = system_directory.as_os_str().encode_wide().collect();
        let Some(letter) = encoded
            .first()
            .and_then(|value| u8::try_from(*value).ok())
            .filter(u8::is_ascii_alphabetic)
        else {
            return Err("Windows system directory is not on a drive-letter volume".to_owned());
        };
        if encoded.get(1) != Some(&u16::from(b':')) {
            return Err("Windows system directory is not on a drive-letter volume".to_owned());
        }
        Ok(format!("{}:", char::from(letter).to_ascii_uppercase()))
    }

    let system_directory = trusted_system_directory()?;
    let system_drive = trusted_system_drive(&system_directory)?;
    let powershell = system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let module_root = system_directory
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("Modules");

    let output = Command::new(&powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            COLLECTOR,
        ])
        .env("JSTACK_WINDOWS_MODULE_ROOT", &module_root)
        .env("JSTACK_SYSTEM_DRIVE", &system_drive)
        .output()
        .map_err(|error| format!("could not start Windows PowerShell: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("Windows collector exited with {}", output.status)
        } else {
            format!("Windows collector failed: {stderr}")
        });
    }
    parse_snapshot(&output.stdout)
}

#[cfg(not(target_os = "windows"))]
fn collect_snapshot() -> Result<WindowsStorageSnapshot, String> {
    let _ = COLLECTOR;
    Err(
        "live collection is available only on Windows; use --from-snapshot for validation"
            .to_owned(),
    )
}
