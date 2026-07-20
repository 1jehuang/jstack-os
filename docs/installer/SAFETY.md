# Installer safety and threat model

## Safety invariants

1. **Confirmed plan only**: no disk, boot, filesystem, or BitLocker mutation
   occurs unless the exact current plan hash equals the explicitly confirmed
   plan hash.
2. **Stable identity**: disk and partition GUIDs, offsets, sizes, GPT type
   GUIDs, and Windows volume identity are revalidated before every mutation.
3. **Windows owns NTFS resizing**: Linux never shrinks or expands the Windows
   filesystem. The Windows Storage API performs both operations.
4. **Bounded writes**: Linux may create or format partitions only inside the
   confirmed unallocated interval produced by Windows.
5. **Windows boot remains**: the original Windows boot entry, ESP files, MSR,
   recovery partition, and Windows volume are never deleted or overwritten.
6. **Namespaced ESP changes**: JStack writes only under its dedicated ESP
   directory and records every created path for rollback.
7. **Trust before boot mutation**: BootNext is armed only after loader, UKI,
   manifest, and payload signatures or hashes validate.
8. **Recovery key before suspension**: BitLocker is suspended only after the
   user confirms that a recovery key is available and the finalizer is
   registered.
9. **Journal before action**: every mutating action has a durable intent record,
   observable preconditions and postconditions, and a reconciliation policy.
10. **Stop on ambiguity**: when observed disk state matches neither the action's
    precondition nor postcondition, automatic mutation stops.
11. **Success is end-to-end**: installation is not complete until Windows has
    booted once for security restoration and JStack first-boot verification
    passes.
12. **No destructive v1 mode**: replace-disk and unattended erase modes are not
    reachable in the v1 graph.
13. **Actor authority**: an actor may execute only actions authorized for its
    current platform. Linux never performs a Windows-only storage action.
14. **Servicing owns no reboot**: a pending Windows update, feature update,
    repair, or other reboot owner rejects preflight.
15. **One mutation per transition**: every destructive action has its own named
    checkpoint, intent, postcondition, and failure route.

## Threat boundaries

### Untrusted until verified

- Network responses and release mirrors
- Cached installer payloads
- Windows environment variables and command-line input
- Disk numbers, drive letters, and enumeration order
- UEFI variable contents
- Any journal copy that lacks a valid signature and sequence chain

### Privileged trusted computing base

- Signed Windows bootstrap and finalizer
- Shared state-model/runtime library
- Signed loader and installer UKI
- RAM installer
- Release signing keys and channel manifest

## Unsupported v1 layouts

- Legacy BIOS or MBR system disk
- Windows dynamic disks
- Storage Spaces or firmware/software RAID system volumes
- Ambiguous multi-disk boot layouts
- Native VHD boot or Windows-to-Go
- Unsupported NTFS shrink minimum
- Existing disk corruption or failing health checks
- Missing BitLocker recovery material when protection is enabled
- Secure Boot without a validated JStack trust chain
- Insufficient ESP space for the namespaced loader
- Insufficient shrinkable space for XBOOTLDR plus JStack root

## Rollback boundary

Before the confirmed plan is recorded, cancellation is a no-op. After the first
mutation, cancellation becomes a rollback request. Rollback boots Windows,
removes only graph-recorded JStack partitions and files, expands NTFS through
the Windows Storage API when safe, restores BitLocker, and then records a
`rolled_back` terminal.

Any partition identity mismatch, write outside the planned interval, missing
Windows boot entry, or divergent GPT state enters `manual_recovery_required`
without further automatic writes.

## Required fault injection

Tests must interrupt every mutating transition at these points:

- Before the intent record
- After intent flush but before mutation
- During mutation
- After mutation but before observation
- After postcondition observation but before commit record
- After commit record but before control-state advancement

Each interruption must deterministically retry, advance, roll back, or stop for
manual recovery. Silent best-effort continuation is forbidden.

Milestone 1 exercises these points as abstract precondition, postcondition, and
divergent observations for every mutating transition. Later VM tests must inject
the same failures while real platform adapters are running.
