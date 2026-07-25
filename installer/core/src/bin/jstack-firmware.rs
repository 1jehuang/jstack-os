//! PH-08 live Windows firmware boot adapter binary.
//!
//! All decision logic lives in `jstack_installer_core::windows_firmware`, which
//! is pure and forbids `unsafe`. This binary supplies only the two Win32 calls
//! that cannot be expressed safely, and it is the sole place in the installer
//! where `unsafe` appears.
//!
//! The mutation path requires a [`FirmwareMutationCapability`], whose only
//! constructor validates a matching disposable-VM attestation pair. On a real
//! user machine those environment variables are absent, so `arm` exits with an
//! error before touching firmware.
//!
//! Usage:
//!
//! ```text
//! jstack-firmware read BootNext
//! jstack-firmware entries
//! jstack-firmware arm <boot-number>
//! ```

// This binary is the single `unsafe` boundary in the installer. The crate root
// cannot forbid it here because the Win32 firmware API has no safe wrapper.
#![deny(unsafe_op_in_unsafe_fn)]

use std::env;
use std::process::ExitCode;

use jstack_installer_core::{
    FirmwareError, FirmwareMutationCapability, FirmwareVariables, arm_boot_next, is_readable,
    read_boot_next,
};

/// Environment variables minted by the VM harness for exactly one run.
const ATTESTATION: &str = "JSTACK_DISPOSABLE_VM";
const ATTESTATION_EXPECTED: &str = "JSTACK_DISPOSABLE_VM_EXPECTED";

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let mut variables = platform::variables()?;

    match arguments.first().map(String::as_str) {
        Some("read") => {
            let name = arguments
                .get(1)
                .ok_or_else(|| "read requires a variable name".to_owned())?;
            if !is_readable(name) {
                return Err(format!("{name} is not an allowed boot variable"));
            }
            let (bytes, attributes) = variables.read(name).map_err(|error| error.to_string())?;
            Ok(format!(
                "{{\"name\":\"{name}\",\"attributes\":{attributes},\"bytes\":{}}}",
                bytes.len()
            ))
        }
        Some("boot-next") => {
            let observed = read_boot_next(&variables).map_err(|error| error.to_string())?;
            Ok(match observed {
                Some(number) => format!("{{\"boot_next\":{number}}}"),
                None => "{\"boot_next\":null}".to_owned(),
            })
        }
        Some("arm") => {
            let raw = arguments
                .get(1)
                .ok_or_else(|| "arm requires a boot number".to_owned())?;
            let boot_number: u16 = raw
                .parse()
                .map_err(|_| format!("boot number {raw} is not a u16"))?;

            // The capability gate. Without a matching attestation pair this
            // returns an error and no firmware variable is written.
            let presented = env::var(ATTESTATION).unwrap_or_default();
            let expected = env::var(ATTESTATION_EXPECTED).unwrap_or_default();
            let capability =
                FirmwareMutationCapability::from_disposable_vm_attestation(&presented, &expected)
                    .map_err(|error| error.to_string())?;

            let armed = arm_boot_next(&mut variables, &capability, boot_number)
                .map_err(|error| error.to_string())?;
            Ok(format!("{{\"armed_boot_next\":{armed}}}"))
        }
        _ => Err("usage: jstack-firmware read <name> | boot-next | arm <boot-number>".to_owned()),
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use jstack_installer_core::{
        BOOT_NEXT_BYTES, EFI_GLOBAL_VARIABLE_GUID, is_writable, require_attributes,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
    };

    const MAXIMUM_VARIABLE_BYTES: u32 = 8192;

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    #[derive(Debug, Default)]
    pub struct LiveFirmwareVariables;

    impl FirmwareVariables for LiveFirmwareVariables {
        fn read(&self, name: &str) -> Result<(Vec<u8>, u32), FirmwareError> {
            if !is_readable(name) {
                return Err(FirmwareError::ForbiddenVariable(name.to_owned()));
            }
            let name_wide = wide(name);
            let guid_wide = wide(EFI_GLOBAL_VARIABLE_GUID);
            let mut buffer = vec![0_u8; MAXIMUM_VARIABLE_BYTES as usize];
            let mut attributes: u32 = 0;
            // SAFETY: both wide strings are NUL-terminated and live for the
            // duration of the call. `buffer` is valid for MAXIMUM_VARIABLE_BYTES
            // writable bytes and `attributes` is a valid writable u32. The API
            // retains no pointer past return.
            let written = unsafe {
                GetFirmwareEnvironmentVariableExW(
                    name_wide.as_ptr(),
                    guid_wide.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    MAXIMUM_VARIABLE_BYTES,
                    &mut attributes,
                )
            };
            if written == 0 {
                return Err(FirmwareError::Os(format!(
                    "reading firmware variable {name} failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let written = usize::try_from(written).map_err(|error| {
                FirmwareError::Os(format!("firmware variable length overflowed: {error}"))
            })?;
            if written > buffer.len() {
                return Err(FirmwareError::Os(format!(
                    "firmware variable {name} exceeded the trusted buffer"
                )));
            }
            buffer.truncate(written);
            Ok((buffer, attributes))
        }

        fn write(
            &mut self,
            name: &str,
            value: &[u8],
            attributes: u32,
        ) -> Result<(), FirmwareError> {
            // Defence in depth: the live writer itself refuses anything but
            // BootNext, so no future caller can reorder BootOrder or replace a
            // Secure Boot key.
            if !is_writable(name) {
                return Err(FirmwareError::ForbiddenVariable(name.to_owned()));
            }
            if value.len() != BOOT_NEXT_BYTES {
                return Err(FirmwareError::MalformedBootNext(value.len()));
            }
            require_attributes(attributes)?;
            let name_wide = wide(name);
            let guid_wide = wide(EFI_GLOBAL_VARIABLE_GUID);
            let length = u32::try_from(value.len()).map_err(|error| {
                FirmwareError::Os(format!("firmware value length overflowed: {error}"))
            })?;
            // SAFETY: both wide strings are NUL-terminated and live for the
            // duration of the call. `value` is valid for `length` readable bytes.
            // The API retains no pointer past return.
            let result = unsafe {
                SetFirmwareEnvironmentVariableExW(
                    name_wide.as_ptr(),
                    guid_wide.as_ptr(),
                    value.as_ptr().cast(),
                    length,
                    attributes,
                )
            };
            if result == 0 {
                return Err(FirmwareError::Os(format!(
                    "writing firmware variable {name} failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(())
        }
    }

    pub fn variables() -> Result<LiveFirmwareVariables, String> {
        Ok(LiveFirmwareVariables)
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::*;

    /// Off Windows there is no firmware environment API. This stub exists so the
    /// binary compiles and its argument handling can be reviewed on Linux; every
    /// operation fails closed.
    #[derive(Debug, Default)]
    pub struct UnsupportedFirmwareVariables;

    impl FirmwareVariables for UnsupportedFirmwareVariables {
        fn read(&self, _name: &str) -> Result<(Vec<u8>, u32), FirmwareError> {
            Err(FirmwareError::UnsupportedHost)
        }

        fn write(
            &mut self,
            _name: &str,
            _value: &[u8],
            _attributes: u32,
        ) -> Result<(), FirmwareError> {
            Err(FirmwareError::UnsupportedHost)
        }
    }

    pub fn variables() -> Result<UnsupportedFirmwareVariables, String> {
        Ok(UnsupportedFirmwareVariables)
    }
}
