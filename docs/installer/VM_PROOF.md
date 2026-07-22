# Windows VM proof contract

This document defines the evidence required before the JStack no-USB installer may
be described as working on Windows. Architecture, cross-compilation, mocks, and a
single successful VM run are necessary but insufficient.

## Claim boundary

The VM campaign can establish this claim:

> For the declared Windows 10 and Windows 11 x86-64 UEFI/GPT VM profiles, the
> pinned installer and release either complete a verified dual-boot installation
> or reach a defined recovery outcome without claiming success or mutating outside
> the confirmed plan.

The campaign cannot establish universal compatibility with physical firmware,
storage drivers, vendor recovery layouts, TPM implementations, or reset behavior.
Those remain a separate supported-hardware release gate.

## Supported VM envelope

Each profile is immutable and evidence-addressed. The initial profile records are
blocked until their declared host-acquisition, base-image, installer, graph, and
release hashes are resolved into new content-addressed profiles:

- Windows 11 Enterprise Evaluation 25H2, en-US, x86-64
- Windows 10 Pro 22H2, en-US, x86-64, selected from official Home/Pro
  multi-edition media
- QEMU/KVM with an explicit version and machine type
- OVMF UEFI with separate immutable code and per-run variable-store files
- Secure Boot enabled and disabled variants
- swtpm TPM 2.0 enabled and absent variants where the Windows release permits it
- one sparse qcow2 GPT basic system disk, never a host block device
- emulated storage and network devices with inbox Windows drivers for the base
  profile; separate driver profiles may be added only with pinned signed media
- one Windows system volume, one ESP on the same disk, standard MSR and recovery
  partitions, and no pre-existing JStack partitions
- BitLocker disabled and enabled variants

Unsupported layouts must be rejected, not silently added to this envelope.

## Definition of an end-to-end pass

A happy-path run passes only when all of the following are independently observed:

1. The VM starts from a read-only base image and fresh per-run qcow2 overlay,
   OVMF variable store, TPM state, journal roots, and evidence directory.
2. Windows boots and reports the expected release, architecture, UEFI mode, GPT
   disk identity, Secure Boot state, TPM state, BitLocker state, and system disk.
3. The signed Windows bootstrap verifies its own release inputs, collects live
   inventory, computes the shared plan, and displays the exact confirmed plan.
4. The bootstrap accepts the release durably, stages all artifacts, and verifies
   exact size, logical chunks, whole digest, EOF, and staging evidence.
5. Every mutation is authorized by the current graph state, confirmed plan,
   current disk fingerprint, signed release capability, and durable intent.
6. Windows performs NTFS resize and Windows-only security operations. No Linux
   component writes to the Windows filesystem or resizes NTFS.
7. XBOOTLDR, ESP loader, installer boot entry, finalizer, and one-time BootNext
   are installed through destination-specific transactions and verified at their
   privileged point of use.
8. The signed RAM installer boots, verifies the handoff, re-inventories the disk,
   creates and formats only the planned JStack root interval, deploys the exact
   image, installs boot artifacts, and hands control back to Windows.
9. Windows boots successfully after Linux deployment, verifies the committed
   disk plan, restores BitLocker when applicable, removes temporary bootstrap
   state, and arms JStack exactly once.
10. JStack boots successfully and verifies root, boot artifacts, networking,
    Niri session prerequisites, recovery service, and the Windows boot entry.
11. The durable journal reaches `terminal.completed`; all replicas, handoffs,
    plan hashes, release hashes, graph digest, disk identity, and evidence hashes
    agree; no unplanned disk interval or ESP path changed.
12. A subsequent cold boot can select both Windows and JStack successfully.

A test harness exit code alone is never success evidence.

## Mandatory failure campaigns

Every production mutating transition must be interrupted at each applicable
boundary:

- before intent persistence
- after intent flush and before mutation
- during mutation before an externally visible effect
- during mutation after a partial effect
- after mutation and before independent observation
- after observation and before commit persistence
- after commit and before durable state advancement
- before and after each reboot or firmware handoff

Each boundary is exercised with abrupt QEMU process termination, not only an
in-process injected error. The next boot must deterministically retry, advance,
roll back, or enter manual recovery according to the graph.

The campaign also includes:

- ENOSPC for staging, journal, ESP/XBOOTLDR, destination temporary objects, and
  root deployment
- Windows sharing violations and locked files
- symlink and reparse-point substitution
- artifact, staging-evidence, handoff, journal, GPT, ESP, and destination tamper
- stale disk, partition, plan, release, graph, and boot-entry identities
- torn, duplicated, reordered, equivocated, oversized, and corrupted records
- invalid signatures, expired releases, rollback attempts, and clock rollback
- missing or insufficient BitLocker recovery confirmation
- Secure Boot valid, invalid, and incomplete trust chains
- BootNext failure, one bounded rearm, exhausted rearm, and firmware-variable
  write failure
- cancellation before mutation and rollback requests from every post-mutation
  checkpoint
- failed Windows resume, failed finalizer, failed JStack first boot, repeated
  recovery boots, and rollback interruption

## Repetition and freshness

A release candidate requires:

- at least ten fresh-overlay happy-path runs for each supported OS/security
  profile
- every modeled failure edge and every production mutation interruption boundary
  exercised at least once per applicable platform
- a fresh base-image reconstruction run to detect hidden snapshot dependencies
- a complete rerun after any change to runtime, adapters, graph, release policy,
  boot artifacts, VM harness, firmware, or evidence verifier

A statistical pass rate does not waive any deterministic failure.

## Evidence record

Every run emits an immutable canonical record containing at least:

- run ID, scenario ID, start and finish timestamps, and final outcome
- source commit and clean tree digest
- state-model bytes and digest
- release manifest, acceptance state, and staging-evidence digests
- Windows ISO source URL, Microsoft hash-document digest, and verified ISO hash
- QEMU, KVM, OVMF, swtpm, machine type, CPU, memory, device, and command-line data
- base image, overlay, OVMF variable store, and TPM-state identity
- initial and final Windows inventory, GPT, ESP, firmware, BitLocker, and boot data
- ordered journal records, handoffs, observed preconditions and postconditions
- fault trigger, exact boundary, process exit cause, and recovery observations
- Windows and JStack boot attestations and final dual-boot verification
- hashes and paths of logs, screenshots, serial output, guest output, and disk
  inspection reports
- a unique digest for every complete campaign-run evidence bundle and the
  externally approved canonical campaign-index digest

The evidence verifier fails closed on missing, duplicate, unknown, oversized, or
noncanonical data. The approved release-policy, resolved-profile, official-media,
and campaign-index SHA-256 trust roots are supplied independently of the bundle
and must match its artifacts. A bundle may never select or redefine its own trust
roots. A summary dashboard is derived from these records and is not a source of
truth.

## Host real-drive interlock

VM tooling must make host-drive attachment structurally impossible:

- all VM disks are regular files below `$JCODE_SCRATCH_DIR/jstack-windows-vm`
- every disk is created by the harness and verified as qcow2 before use
- `/dev/*`, `/sys/*`, `/proc/*`, physical-volume, partition, host-device, and
  passthrough disk sources are rejected
- symlinked disk paths, device nodes, mounted block devices inside the workspace,
  and paths escaping the workspace are rejected
- QEMU runs as the unprivileged user with no `sudo`; libvirt, if used, is
  `qemu:///session`, never the system daemon
- generated QEMU arguments use fixed device templates and do not accept arbitrary
  user-supplied drive or blockdev fragments
- fault tests may kill or corrupt only the per-run process and files whose
  canonical paths are inside the run directory

The safety interlock is tested adversarially before any installer mutation code is
connected to a VM.

## Milestone gate

Each implementation milestone follows the same gate:

1. update graph, contracts, and this proof contract when behavior changes
2. implement behind capabilities that remain unreachable from real-drive builds
3. add deterministic, adversarial, and interruption tests
4. run exact Rust 1.85.0 selected by `installer/rust-toolchain.toml`, schemas,
   generated docs, static analysis, Linux tests, and Windows-target `cargo check`
5. validate in a clean isolated worktree
6. obtain an independent read-only P0/P1 review
7. fix every reproduced blocker and repeat the gate
8. commit only after `SAFE TO COMMIT: yes`

Real-drive enablement is a separate decision after all VM gates and the physical
hardware campaign pass.
