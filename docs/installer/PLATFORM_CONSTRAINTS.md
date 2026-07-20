# Windows and firmware platform constraints

This document records the evidence behind the v1 boundary. It is an input to the
state graph, not permission to broaden that boundary. A platform not explicitly
supported is rejected before any persistent mutation.

## Supported envelope

| Area | v1 requirement | Enforcement |
| --- | --- | --- |
| Host | Windows 10 or Windows 11 on x86-64 | `supported_windows` |
| Firmware | The running Windows installation booted with UEFI and firmware variables are writable | `uefi_boot` |
| Disk | One unambiguous GPT basic system disk | `gpt_basic_disk`, `single_system_disk` |
| Windows volume | NTFS with a supported shrink range and healthy state | `windows_ntfs_supported`, `storage_health_acceptable` |
| Installation | Dual boot into newly freed contiguous space | `planned_interval_current` |
| Security | Valid Secure Boot chain or Secure Boot disabled; recoverable BitLocker state | `boot_chain_trusted`, BitLocker guards |
| Reboot ownership | No pending Windows update, repair, or other servicing reboot | `windows_servicing_idle` |
| Power | AC power or a conservative battery threshold | `power_safe` |

Dynamic disks, Storage Spaces, RAID-backed system disks, BIOS/MBR, native VHD
boot, Windows-to-Go, destructive replacement, and ambiguous multi-disk layouts
remain unsupported.

## Partition contract

1. Windows identifies the system disk and queries the Windows partition's
   supported shrink bounds.
2. The planner selects one aligned interval that meets the minimum allocation
   and safety margin.
3. Windows shrinks NTFS and its partition using Windows Storage APIs.
4. JStack creates exactly one XBOOTLDR partition and one Btrfs root partition
   inside that interval.
5. The existing ESP, MSR, Windows recovery partition, Windows volume start
   offset, and all unrelated partitions remain unchanged.
6. The ESP receives only namespaced signed JStack loader files. Large UKIs and
   payload chunks live on XBOOTLDR.
7. Rollback deletes only journaled JStack objects. Windows expands NTFS only
   after the complete planned interval is contiguous and its identity matches.

The XBOOTLDR GPT type is the Boot Loader Specification type
`bc13c2ff-59e6-4262-a352-b275fd6f7172`. It must be on the same disk as the ESP,
and v1 permits at most one XBOOTLDR on that disk. Payload files larger than the
FAT32 single-file limit must be content-addressed chunks.

## Windows API implications

- `Get-PartitionSupportedSize` provides the minimum and maximum sizes supported
  for a partition. The planner must stay inside this reported range.
- `Resize-Partition` resizes both the partition and underlying filesystem. It is
  the only permitted NTFS shrink and expansion mechanism in v1.
- `Suspend-BitLocker` is modeled with explicit `RebootCount 0`, which requires
  an explicit resume. Before suspension, JStack records the original protection
  state and installs a boot-start dispatcher. That dispatcher accepts finalizer
  behavior only with a signed Linux completion token; otherwise it performs the
  bounded installer rearm or rollback that restores protection.
- Writing UEFI variables requires an elevated process with the system
  environment privilege and works only on UEFI systems. Inability to write or
  verify the one-time boot target is a safe rejection or rollback condition.
- Installer handoffs use Restart rather than shutdown. Fast Startup therefore
  must not be treated as evidence that a full firmware handoff occurred.

## Races explicitly rejected

- Windows Update, component servicing, a feature update, or repair owns a
  pending reboot.
- NTFS is dirty, storage repair is pending, or disk health is unacceptable.
- Disk GUID, partition GUID, offset, size, type, or volume identity changes
  after confirmation.
- Firmware resumes Windows instead of the requested installer target more than
  the bounded rearm policy allows.
- Secure Boot state or accepted trust changes between staging and BootNext.
- BitLocker protection state differs from the journaled state.

## Primary references

- Microsoft `Get-PartitionSupportedSize`: <https://learn.microsoft.com/en-us/powershell/module/storage/get-partitionsupportedsize?view=windowsserver2025-ps>
- Microsoft `Resize-Partition`: <https://learn.microsoft.com/en-us/powershell/module/storage/resize-partition?view=windowsserver2025-ps>
- Microsoft `Suspend-BitLocker`: <https://learn.microsoft.com/en-us/powershell/module/bitlocker/suspend-bitlocker?view=windowsserver2025-ps>
- Microsoft UEFI variable API: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexa>
- Microsoft UEFI/GPT layout guidance: <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions?view=windows-11>
- Microsoft `powercfg` reference: <https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options>
- UAPI Boot Loader Specification: <https://uapi-group.org/specifications/specs/boot_loader_specification/>

## Current validation limits

The development host is UEFI-capable and has QEMU plus OVMF, but its current
system disk contains only GPT, ESP, and Btrfs partitions. It has no live Windows
NTFS installation to use for destructive hardware testing. Milestone 1 therefore
validates the state model, schemas, reachability, traces, and interruption rules
only. Windows API, BitLocker, Secure Boot, and real partition behavior require
disposable Windows 10 and 11 UEFI virtual machines in later milestones.
