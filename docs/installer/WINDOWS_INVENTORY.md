# Windows read-only inventory adapter

## Boundary

`jstack-inventory` is the first Windows platform adapter. Its live mode is compiled
only for Windows and launches the embedded `collect-windows-inventory.ps1` script.
The script observes Windows storage state and emits a versioned
`WindowsStorageSnapshot`. The shared Rust core then normalizes that snapshot into
the existing `Inventory` contract.

Neither layer exposes a disk, volume, partition, BitLocker, BCD, firmware, file,
or registry mutation operation. The shared Rust library forbids unsafe code. The
Windows launcher denies unsafe code everywhere except one documented call to
`GetSystemDirectoryW`, whose wrapper owns and bounds the writable UTF-16 buffer.
Live collection is unavailable on non-Windows targets, while `--from-snapshot`
permits reproducible validation on Linux and Windows.

```text
Windows read-only cmdlets
        ↓
WindowsStorageSnapshot (strict JSON Schema)
        ↓
normalize_windows_snapshot (pure Rust)
        ↓
Inventory (schema-valid, conservatively untrusted)
```

## System-disk identity

The collector reads `%SystemDrive%`, enumerates all disks and partitions, and
sorts both by their Windows numeric identifiers. Unrelated MBR or RAW media may
have no GPT identifiers and remain eligible only as negative evidence during
system-disk selection. The normalizer applies strict GPT identity and geometry
validation to the selected Windows disk, then selects only a
partition that simultaneously:

1. has the `%SystemDrive%` drive letter,
2. is reported by Windows as the boot partition, and
3. belongs to exactly one observed disk.

Zero matches are rejected. Multiple matches are rejected. Exactly one partition
must also carry Windows `IsSystem` evidence, use the ESP type GUID, and reside on
the selected Windows disk. This rejects split boot-chain layouts where Windows is
on one disk but the active firmware ESP is on another. The selected disk must
be GPT and the selected Windows partition must use the Microsoft Basic Data type
GUID. Additional Basic Data partitions are classified as `other`, never guessed
to be Windows. Duplicate disk or partition numbers are rejected globally.
Invalid or nil selected-disk GUIDs, inconsistent selected-disk volume geometry,
another observed disk carrying the selected disk GUID, resize bounds that exclude
the current Windows size, missing volume health for a drive-letter partition,
missing ESP or recovery volume metadata, and missing BitLocker status are
rejected.

## Observation mapping

| Contract value | Read-only source |
| --- | --- |
| Disk size, GUID, partition style, sector sizes, health | `Get-Disk` |
| Partition GUID, type GUID, offset, size, boot/system flags | `Get-Partition` |
| Filesystem, volume ID, free space, volume health | `Get-Volume` |
| Windows supported shrink range | `Get-PartitionSupportedSize` |
| Protection and recovery-protector presence | `Get-BitLockerVolume` |
| UEFI/Secure Boot observation | `Confirm-SecureBootUEFI` |
| Pending servicing reboot indicators | read-only registry queries |
| Battery, AC, and charge observations | `Get-CimInstance Win32_Battery` |

The live launcher asks the native `GetSystemDirectoryW` API for the running OS
system directory, derives both Windows PowerShell and its module tree from that
result, and never consults `PATH`, `SystemRoot`, `SystemDrive`, or a fixed drive.
It passes the verified module root and system drive directly to the child process.
The collector constrains `PSModulePath` to that tree for dependency resolution
and calls its cmdlets with module-qualified names. The exact command set is
statically allowlisted. New commands fail
`make check` until reviewed. A separate denylist rejects known storage, firmware,
BCD, BitLocker, reboot, and mount mutation primitives. Suppressed observation
errors are forbidden. A failed storage, registry, servicing, or power observation
aborts collection instead of becoming positive readiness evidence. When
PowerShell is available, the gate also parses the script and executes the exact
embedded script. Its semantic command AST must contain every required
module-qualified call and no non-allowlisted command. The exact script then runs
against deterministic command mocks, validates the raw snapshot schema, passes
through the Rust CLI, and validates the resulting inventory schema.

## Fail-closed attestations

A disk scan cannot prove release trust or that a person possesses recovery
material. The normalizer therefore never fabricates those facts:

- enabled Secure Boot becomes `enabled_untrusted`, not `enabled_trusted`;
- `bitlocker_recovery_material_confirmed` is always `false`;
- `firmware_variables_writable` is always `false`; reading Secure Boot state does
  not prove that a later firmware write will succeed;
- unavailable Secure Boot status is treated as untrusted;
- unhealthy storage, pending servicing, unsafe laptop power, and missing
  elevation remain false readiness values.

Consequently, an observed inventory is not automatically planner-ready. A future
signed release verifier and explicit user recovery-material confirmation step
must add independently validated evidence before planning can pass. This keeps
read-only discovery separate from authorization to mutate.

## Commands

```sh
cd installer/core
cargo run --offline --bin jstack-inventory -- \
  --from-snapshot fixtures/windows-storage-snapshot.json
make collector
make check
```

On Windows, an elevated invocation with no arguments performs live observation:

```powershell
jstack-inventory.exe
```

## Primary references

- Microsoft `GetSystemDirectoryW`: <https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw>
- Microsoft `Get-Disk`: <https://learn.microsoft.com/powershell/module/storage/get-disk>
- Microsoft `Get-Partition`: <https://learn.microsoft.com/powershell/module/storage/get-partition>
- Microsoft `Get-Volume`: <https://learn.microsoft.com/powershell/module/storage/get-volume>
- Microsoft `Get-PartitionSupportedSize`: <https://learn.microsoft.com/powershell/module/storage/get-partitionsupportedsize>
- Microsoft `Get-BitLockerVolume`: <https://learn.microsoft.com/powershell/module/bitlocker/get-bitlockervolume>
- Microsoft `Confirm-SecureBootUEFI`: <https://learn.microsoft.com/powershell/module/secureboot/confirm-securebootuefi>
