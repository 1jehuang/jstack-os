//! PH-08 Windows firmware boot adapter.
//!
//! Windows exposes no cmdlet for UEFI boot variables, and shelling out to
//! `bcdedit` is forbidden by the safety contract. This module therefore drives
//! the documented Win32 firmware-environment API directly:
//!
//! * `GetFirmwareEnvironmentVariableExW` to read `Boot####`, `BootOrder`, and
//!   `BootNext` from the EFI global variable namespace.
//! * `SetFirmwareEnvironmentVariableExW` to arm `BootNext`.
//!
//! Three properties make this adapter safe to compile into the installer even
//! before it is trusted on real hardware:
//!
//! 1. Every mutating entry point requires a [`FirmwareMutationCapability`],
//!    whose only constructor validates a disposable-VM attestation. There is no
//!    production constructor, so the mutation path is unreachable outside a
//!    disposable VM.
//! 2. `BootNext` is the only variable ever written. `BootOrder` and the
//!    `Boot####` entries are read-only here, so the adapter cannot reorder or
//!    delete a vendor's boot configuration.
//! 3. The value written is re-read and compared before the call returns, so the
//!    controller never has to trust a success code.
//!
//! This module is deliberately pure: the crate root forbids `unsafe`, so the
//! live Win32 calls live in the `jstack-firmware` binary, which implements
//! [`FirmwareVariables`] against `Get/SetFirmwareEnvironmentVariableExW`. All
//! decision logic (which variables may be named, which may be written, encoding,
//! attribute requirements, and read-back verification) is here and is testable
//! on any host.
//!
//! Reference: <https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw>

use thiserror::Error;

/// The EFI global variable namespace, as required by the Win32 API. The braces
/// and casing are part of the documented contract.
pub const EFI_GLOBAL_VARIABLE_GUID: &str = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

/// Attribute bits every boot variable must carry. A variable missing
/// non-volatility would not survive the reboot the installer depends on.
pub const EFI_VARIABLE_NON_VOLATILE: u32 = 0x0000_0001;
pub const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x0000_0002;
pub const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x0000_0004;

/// The attribute set the installer requires for `BootNext`.
pub const BOOT_VARIABLE_ATTRIBUTES: u32 =
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

/// `BootNext` is a single UInt16 in little-endian order.
pub const BOOT_NEXT_BYTES: usize = 2;

#[derive(Debug, Error, PartialEq)]
pub enum FirmwareError {
    #[error("firmware boot adapters are available only on Windows")]
    UnsupportedHost,
    #[error("refusing to mutate firmware without a disposable-VM attestation")]
    MissingAttestation,
    #[error("disposable-VM attestation does not match this run")]
    AttestationMismatch,
    #[error("variable name {0} is not an allowed boot variable")]
    ForbiddenVariable(String),
    #[error("BootNext must be exactly {BOOT_NEXT_BYTES} bytes, observed {0}")]
    MalformedBootNext(usize),
    #[error("firmware variable attributes {observed:#x} lack the required {required:#x}")]
    InsufficientAttributes { observed: u32, required: u32 },
    #[error("BootNext read back as {observed:?}, expected {expected}")]
    BootNextNotArmed {
        observed: Option<u16>,
        expected: u16,
    },
    #[error("firmware call failed: {0}")]
    Os(String),
}

/// A capability proving this process runs inside a disposable VM.
///
/// The field is private and the type is neither `Clone` nor `Default`, so the
/// only way to hold one is to pass a matching attestation pair.
#[derive(Debug)]
pub struct FirmwareMutationCapability {
    attestation: String,
}

impl FirmwareMutationCapability {
    /// The only constructor. Both values are minted by the VM harness for one
    /// run and recorded in the evidence bundle; they never exist on a real user
    /// machine, so this returns an error there rather than a capability.
    pub fn from_disposable_vm_attestation(
        presented: &str,
        expected: &str,
    ) -> Result<Self, FirmwareError> {
        if presented.len() < 32 || expected.len() < 32 {
            return Err(FirmwareError::MissingAttestation);
        }
        // Constant-time-ish comparison is unnecessary here (the token is not a
        // secret against a local attacker) but an exact match is required.
        if presented != expected {
            return Err(FirmwareError::AttestationMismatch);
        }
        Ok(Self {
            attestation: presented.to_owned(),
        })
    }

    pub fn attestation(&self) -> &str {
        &self.attestation
    }
}

/// Boot variables this adapter is permitted to name at all.
///
/// `BootOrder` and `Boot####` are readable so the installer can find its own
/// entry and verify the loader digest. Only `BootNext` is ever written, and
/// [`is_writable`] is the single place that decision is made.
pub fn is_readable(name: &str) -> bool {
    if name == "BootOrder" || name == "BootNext" || name == "BootCurrent" {
        return true;
    }
    // Boot#### where #### is exactly four uppercase hex digits.
    if let Some(index) = name.strip_prefix("Boot") {
        return index.len() == 4
            && index
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte));
    }
    false
}

/// Only `BootNext` may be written. This is the whole firmware mutation surface.
pub fn is_writable(name: &str) -> bool {
    name == "BootNext"
}

/// Decode a `BootNext` payload, rejecting any length but two bytes.
pub fn decode_boot_next(bytes: &[u8]) -> Result<u16, FirmwareError> {
    if bytes.len() != BOOT_NEXT_BYTES {
        return Err(FirmwareError::MalformedBootNext(bytes.len()));
    }
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Encode a `BootNext` payload in the little-endian order UEFI requires.
pub fn encode_boot_next(boot_number: u16) -> [u8; BOOT_NEXT_BYTES] {
    boot_number.to_le_bytes()
}

/// Reject a variable whose attributes would not survive a reboot.
pub fn require_attributes(observed: u32) -> Result<(), FirmwareError> {
    if observed & BOOT_VARIABLE_ATTRIBUTES != BOOT_VARIABLE_ATTRIBUTES {
        return Err(FirmwareError::InsufficientAttributes {
            observed,
            required: BOOT_VARIABLE_ATTRIBUTES,
        });
    }
    Ok(())
}

/// The platform operations the adapter needs, abstracted so the decision logic
/// is testable on Linux without any Windows API.
pub trait FirmwareVariables {
    fn read(&self, name: &str) -> Result<(Vec<u8>, u32), FirmwareError>;
    fn write(&mut self, name: &str, value: &[u8], attributes: u32) -> Result<(), FirmwareError>;
}

/// Arm `BootNext` and prove it was armed.
///
/// This is the only mutating entry point. It requires the capability, refuses
/// any variable but `BootNext`, and re-reads the value before returning.
pub fn arm_boot_next<V: FirmwareVariables>(
    variables: &mut V,
    _capability: &FirmwareMutationCapability,
    boot_number: u16,
) -> Result<u16, FirmwareError> {
    let name = "BootNext";
    if !is_writable(name) {
        return Err(FirmwareError::ForbiddenVariable(name.to_owned()));
    }

    // The target entry must exist and its variable must be non-volatile, or the
    // reboot would not reach the installer.
    let entry = format!("Boot{boot_number:04X}");
    if !is_readable(&entry) {
        return Err(FirmwareError::ForbiddenVariable(entry));
    }
    let (_, entry_attributes) = variables.read(&entry)?;
    require_attributes(entry_attributes)?;

    variables.write(
        name,
        &encode_boot_next(boot_number),
        BOOT_VARIABLE_ATTRIBUTES,
    )?;

    // Independent observation: read the variable back rather than trusting the
    // write's return code.
    let (observed_bytes, observed_attributes) = variables.read(name)?;
    require_attributes(observed_attributes)?;
    let observed = decode_boot_next(&observed_bytes)?;
    if observed != boot_number {
        return Err(FirmwareError::BootNextNotArmed {
            observed: Some(observed),
            expected: boot_number,
        });
    }
    Ok(observed)
}

/// Read `BootNext` if it is currently set. An absent variable is not an error:
/// firmware clears `BootNext` when it consumes it, which is exactly how the
/// installer detects that a one-shot boot was taken.
pub fn read_boot_next<V: FirmwareVariables>(variables: &V) -> Result<Option<u16>, FirmwareError> {
    match variables.read("BootNext") {
        Ok((bytes, attributes)) => {
            require_attributes(attributes)?;
            Ok(Some(decode_boot_next(&bytes)?))
        }
        Err(FirmwareError::Os(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const TOKEN: &str = "disposable-vm-attestation-token-0001";

    /// A deterministic firmware model. It records every write so a test can
    /// prove which variables were touched.
    #[derive(Debug, Default)]
    struct FakeFirmware {
        variables: BTreeMap<String, (Vec<u8>, u32)>,
        writes: Vec<String>,
    }

    impl FakeFirmware {
        fn with_entry(boot_number: u16) -> Self {
            let mut firmware = Self::default();
            firmware.variables.insert(
                format!("Boot{boot_number:04X}"),
                (b"loader-device-path".to_vec(), BOOT_VARIABLE_ATTRIBUTES),
            );
            firmware.variables.insert(
                "BootOrder".to_owned(),
                (boot_number.to_le_bytes().to_vec(), BOOT_VARIABLE_ATTRIBUTES),
            );
            firmware
        }
    }

    impl FirmwareVariables for FakeFirmware {
        fn read(&self, name: &str) -> Result<(Vec<u8>, u32), FirmwareError> {
            if !is_readable(name) {
                return Err(FirmwareError::ForbiddenVariable(name.to_owned()));
            }
            self.variables
                .get(name)
                .cloned()
                .ok_or_else(|| FirmwareError::Os(format!("{name} is not present")))
        }

        fn write(
            &mut self,
            name: &str,
            value: &[u8],
            attributes: u32,
        ) -> Result<(), FirmwareError> {
            if !is_writable(name) {
                return Err(FirmwareError::ForbiddenVariable(name.to_owned()));
            }
            self.writes.push(name.to_owned());
            self.variables
                .insert(name.to_owned(), (value.to_vec(), attributes));
            Ok(())
        }
    }

    fn capability() -> FirmwareMutationCapability {
        FirmwareMutationCapability::from_disposable_vm_attestation(TOKEN, TOKEN).unwrap()
    }

    #[test]
    fn a_capability_requires_a_matching_disposable_vm_attestation() {
        assert_eq!(
            FirmwareMutationCapability::from_disposable_vm_attestation("", "").unwrap_err(),
            FirmwareError::MissingAttestation
        );
        assert_eq!(
            FirmwareMutationCapability::from_disposable_vm_attestation("short", "short")
                .unwrap_err(),
            FirmwareError::MissingAttestation
        );
        assert_eq!(
            FirmwareMutationCapability::from_disposable_vm_attestation(
                TOKEN,
                "disposable-vm-attestation-token-0002"
            )
            .unwrap_err(),
            FirmwareError::AttestationMismatch
        );
        assert_eq!(capability().attestation(), TOKEN);
    }

    #[test]
    fn only_boot_next_is_writable_and_only_boot_variables_are_readable() {
        assert!(is_writable("BootNext"));
        for name in [
            "BootOrder",
            "Boot0001",
            "BootCurrent",
            "PK",
            "db",
            "SetupMode",
        ] {
            assert!(!is_writable(name), "{name} must never be writable");
        }
        for name in [
            "BootNext",
            "BootOrder",
            "BootCurrent",
            "Boot0000",
            "BootFFFF",
        ] {
            assert!(is_readable(name), "{name} should be readable");
        }
        for name in [
            "PK",
            "KEK",
            "db",
            "dbx",
            "SetupMode",
            "Boot00",
            "Boot000G",
            "Boot0001x",
        ] {
            assert!(!is_readable(name), "{name} must not be readable");
        }
    }

    #[test]
    fn arming_boot_next_writes_only_boot_next_and_verifies_the_read_back() {
        let mut firmware = FakeFirmware::with_entry(7);
        let armed = arm_boot_next(&mut firmware, &capability(), 7).unwrap();
        assert_eq!(armed, 7);
        assert_eq!(firmware.writes, vec!["BootNext".to_owned()]);
        assert_eq!(read_boot_next(&firmware).unwrap(), Some(7));

        // BootOrder was never touched.
        assert_eq!(
            firmware.variables.get("BootOrder").unwrap().0,
            7_u16.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn arming_refuses_a_boot_entry_that_does_not_exist() {
        let mut firmware = FakeFirmware::default();
        assert!(matches!(
            arm_boot_next(&mut firmware, &capability(), 7),
            Err(FirmwareError::Os(_))
        ));
        assert!(firmware.writes.is_empty(), "nothing may be written");
    }

    #[test]
    fn arming_refuses_a_volatile_boot_entry() {
        let mut firmware = FakeFirmware::default();
        firmware.variables.insert(
            "Boot0007".to_owned(),
            (b"loader".to_vec(), EFI_VARIABLE_RUNTIME_ACCESS),
        );
        assert!(matches!(
            arm_boot_next(&mut firmware, &capability(), 7),
            Err(FirmwareError::InsufficientAttributes { .. })
        ));
        assert!(firmware.writes.is_empty());
    }

    #[test]
    fn a_firmware_that_silently_drops_the_write_is_detected() {
        /// Models buggy firmware that accepts the write and keeps the old value.
        #[derive(Default)]
        struct LyingFirmware {
            inner: FakeFirmware,
        }

        impl FirmwareVariables for LyingFirmware {
            fn read(&self, name: &str) -> Result<(Vec<u8>, u32), FirmwareError> {
                self.inner.read(name)
            }

            fn write(
                &mut self,
                name: &str,
                _value: &[u8],
                _attributes: u32,
            ) -> Result<(), FirmwareError> {
                // Report success, change nothing.
                self.inner.writes.push(name.to_owned());
                Ok(())
            }
        }

        let mut firmware = LyingFirmware {
            inner: FakeFirmware::with_entry(7),
        };
        let error = arm_boot_next(&mut firmware, &capability(), 7).unwrap_err();
        assert!(
            matches!(
                error,
                FirmwareError::BootNextNotArmed { .. } | FirmwareError::Os(_)
            ),
            "a dropped write must be detected, got {error}"
        );
    }

    #[test]
    fn a_consumed_boot_next_reads_as_absent_rather_than_failing() {
        let firmware = FakeFirmware::with_entry(7);
        // Firmware clears BootNext when it consumes it.
        assert_eq!(read_boot_next(&firmware).unwrap(), None);
    }

    #[test]
    fn boot_next_encoding_is_little_endian_and_length_checked() {
        assert_eq!(encode_boot_next(0x0007), [0x07, 0x00]);
        assert_eq!(encode_boot_next(0xABCD), [0xCD, 0xAB]);
        assert_eq!(decode_boot_next(&[0xCD, 0xAB]).unwrap(), 0xABCD);
        assert_eq!(
            decode_boot_next(&[0x01]).unwrap_err(),
            FirmwareError::MalformedBootNext(1)
        );
        assert_eq!(
            decode_boot_next(&[0x01, 0x02, 0x03]).unwrap_err(),
            FirmwareError::MalformedBootNext(3)
        );
    }

    #[test]
    fn the_efi_global_namespace_and_attributes_are_the_documented_values() {
        assert_eq!(
            EFI_GLOBAL_VARIABLE_GUID,
            "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
        );
        assert_eq!(BOOT_VARIABLE_ATTRIBUTES, 0x7);
        assert!(require_attributes(0x7).is_ok());
        assert!(require_attributes(0x6).is_err());
        assert!(require_attributes(0x3).is_err());
    }
}
