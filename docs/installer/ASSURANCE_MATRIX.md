# Installer assurance matrix

This document separates properties that are already demonstrated from properties
that still require production adapters, disposable virtual machines, or physical
hardware. Passing a lower level never substitutes for a higher-level platform
observation.

## Assurance levels

| Level | Meaning |
| --- | --- |
| A0 | Architecture or state-model requirement only. No runtime adapter exists. |
| A1 | Pure implementation checked by schemas, deterministic vectors, and unit or property tests. |
| A2 | Runtime contract checked with adversarial mocks and deterministic crash, tamper, or reconciliation injection. |
| A3 | `cargo check` passes for all supported Rust targets on the minimum toolchain, and platform-specific command surfaces pass static allowlist checks. |
| A4 | Production adapter passes destructive tests in a disposable Windows or Linux UEFI VM, including forced power loss and disk-full behavior. |
| A5 | Signed release candidate passes the supported physical-hardware matrix. |

A property is production-ready only when it reaches the highest level named in
its row. Real-drive mutation remains unreachable while any required A4 or A5 gate
is open.

## Current Milestone 5 baseline

The executable graph models 55 states, 92 transitions, 41 actions, 44 guards, 20
invariants, and 17 scenario traces. Its 31 non-read-only actions include staging,
disk, filesystem, boot, security, reboot, external-I/O, and explicit user
authorization effects.

The complete `make check` gate passes under Rust 1.85. It currently includes 49
state-model tests, 62 core tests, 34 staging tests, 86 VM tests, strict Clippy,
schema and canonical fixture validation, independent Ed25519 and artifact vectors,
the PowerShell collector audit and mocked execution, Linux builds, and
`cargo check --target x86_64-pc-windows-msvc` for every Rust crate. This is a
compile check, not an MSVC-linked Windows build.

| Area | Current level | Evidence demonstrated now | Required production level | Open boundary |
| --- | --- | --- | --- | --- |
| State graph structure and authorization | A2 | Every modeled mutation requires intent-before-action, postcondition-before-commit, a failure edge, allowed actor authority, and deterministic abstract interruption reconciliation. Adversarial tests reject authorization, risk, guard, handoff, success-gate, and multi-mutation weakening. | A2 plus runtime conformance | The production runtime must consume graph IDs and must not implement a parallel workflow. |
| Typed controller and restart replay | A2 | The Rust controller loads the exact digest-pinned 55-state/92-transition graph, replays all 17 abstract traces, exercises every success and failure edge, and folds durable journals from the initial state. It rejects wrong actors, skipped states, direct mutation advances, plan drift, invented state hashes, wrong success/failure targets, and missing, duplicate, extra, or mismatched failure evidence. Durable failure records bind strict failure evidence and only a following state advance changes control state. | A4 with a virtual executor, typed guard capabilities, graph-aware handoff validation, and replicated journal integration | No executor or production adapter exists. Platform code must still recompute no-committed-effect proofs, issue authorization capabilities, and durably append records through the controller boundary. Generic handoff rejects direct and failure-derived advances. |
| Release trust and canonical envelope | A3 | Threshold Ed25519 verification, byte-canonical signed bodies, immutable policy, expiry/resource bounds, equivocation rejection, and acceptance-state anti-rollback pass Rust and independent Python vectors. | A4 for durable platform integration, A5 for release signing operations | Provision production roots and protect the rollback floor with the chosen platform mechanism. |
| Read-only Windows inventory | A3 | Raw and normalized schemas, strict deserialization, fail-closed normalization, stable identity rules, a 25-command read-only PowerShell allowlist, mocked collector execution, and Windows-target `cargo check` pass. | A4 | Capture real Windows 10 and 11 results across the supported and rejected layout matrix. |
| Pure partition planner | A3 | Deterministic plan, confirmation display, signed requirement binding, stable disk fingerprints, ambiguous-layout rejection, and generated shrink-boundary cases pass. | A4 when bound to live observation and mutation | Reobserve the actual disk immediately before each production action and prove the adapter executes only the returned plan. |
| Acceptance write-ahead log | A3 | Monotonic compare-and-swap, exact readback, torn-tail recovery, committed-corruption hard stop, and every modeled write/flush/commit fault point pass. | A4, then A5 rollback hardening | Prove NTFS ACL, sharing, flush, and local-filesystem behavior in Windows; prove Linux directory durability; add the production rollback anchor. |
| Artifact quarantine and promotion | A3 | Bounded reads, closed role-derived names, chunk resume, exact size/chunk/whole/EOF verification, no-clobber promotion, tamper rejection, and every write/sync/promote fault point pass. | A4 | Exercise production Windows and Linux filesystems under power loss, disk full, sharing violations, reparse/symlink attacks, and post-verification replacement attempts. |
| Staging evidence and handoff digest | A3 | Canonical evidence binds the accepted manifest, acceptance-state hash, exactly four required roles, sizes, and digests; interrupted evidence publication is reconciled. | A4 when consumed by both platform runtimes | The Windows-to-Linux and Linux-to-Windows production handoffs must verify this digest together with the journal sequence and plan identity. |
| Confirmation, journal, and cross-OS handoff objects | A3 for the private file-backed mutation journal; A1 for cross-OS replication | Deterministic schemas and generated examples bind plan, staging evidence, state-model digest, actor, sequence, and prior record. The journal grammar supports intent followed by committed or failed, then state advanced; failure evidence binds the failed intent, exact graph identity, failure state, no-committed-effect proof hash, and rollback residuals. The Unix-host VM simulator persists canonical framed records, rejects forks and malformed committed frames, truncates only torn uncommitted tails, and revalidates committed outputs on replay. | A4 | Implement durable authenticated journal replicas on the selected Windows and Linux filesystems, integrate verified failure-proof production with the graph controller, and prove cross-OS reconciliation. |
| Same-stream privileged destination transactions | A3 for the bounded VM simulator; production adapters remain A0 | A closed Unix-host regular-file simulator consumes retained staged handles for exact graph-derived artifact batches, verifies signed chunks, whole digest, size, and same-handle EOF while copying, flushes non-selectable temporaries, publishes only after the whole batch verifies, reopens final files, and binds canonical intent/commit evidence to release, staging, plan, transition, actor, partition identity, phase, and fingerprint. It then durably advances to the transition's exact graph target. Multi-artifact crash retry, state-advance replay, ENOSPC, locking, source/final tamper, symlink, case collision, and hardlink tests pass. It accepts no caller-selected root or host block device. | A4 | Implement and destructively test actual FAT32 XBOOTLDR/ESP and Linux deployment adapters, descriptor-relative path traversal, Windows reparse/ACL and directory/volume flush semantics, disk-full/short-write behavior, production graph-controller integration, and cross-OS journal replication. |
| Windows storage, BitLocker, finalizer, and reboot adapters | A0 | Required actions, guards, identities, failure routes, and rollback states exist in the graph. No production mutation command is reachable. | A4, with selected A5 checks | Implement and test NTFS shrink/expand, partition creation, BitLocker suspend/restore, finalizer registration, and reboot ownership. |
| Linux RAM installer and root deployment | A0 | Required bounded-write, re-inventory, deployment, boot-artifact, verification, and rollback contracts exist in the graph. | A4 | Implement image deployment, Btrfs creation, installed-system configuration, and crash-safe reconciliation against temporary disk images and disposable VMs. |
| UEFI, ESP, XBOOTLDR, and BootNext adapters | A0 | Namespacing, point-of-use trust, one-time rearm limits, and Windows boot preservation are modeled. | A4 and A5 | Implement loader placement and firmware entry operations; test OVMF first, then firmware-specific behavior and Secure Boot chains on hardware. |
| End-to-end completion and rollback | A0 | The graph cannot reach success before Windows finalization and JStack first-boot verification; modeled mutation failures can reach a safe terminal. | A4 and A5 | Run the complete signed installer through success, cancellation, rollback, tamper, disk-full, sharing, and power-cut campaigns. |

## Work possible without a Windows machine

The repository can be advanced to the Windows-VM entry gate on Linux:

1. Implement a graph-driven runtime that accepts only typed capabilities issued
   after the corresponding guards and evidence have been verified.
2. Implement a deterministic virtual platform with GPT, partitions, filesystems,
   firmware variables, boot targets, BitLocker state, journal replicas, and
   independently observable preconditions and postconditions.
3. Generate a test campaign for every mutating transition at every documented
   interruption phase, plus divergent observations, replay, cancellation,
   rollback, disk-full, sharing, and tamper outcomes.
4. Implement destination-specific same-stream transactions against bounded
   temporary files and sparse disk images before connecting them to production
   Windows or Linux APIs.
5. Implement and cross-compile the Windows adapters while keeping their capability
   constructors unavailable outside tests and disposable-VM builds.
6. Implement the Linux RAM-installer adapters against temporary disk images.
7. Add QEMU/OVMF boot tests once a loader, installer UKI, and image-level boot
   adapter exist. QEMU provides no meaningful end-to-end evidence before those
   artifacts and adapters are implemented.

Completing these steps can remove nearly all control-flow, serialization,
cryptographic, planner, crash-recovery, and adapter-contract uncertainty. It
cannot demonstrate that the real Windows Storage API, NTFS, BitLocker, or a
particular UEFI implementation obeys those contracts.

## Disposable VM gates

Before enabling any real-drive mutation, disposable Windows 10 and 11 UEFI VMs
must cover at least:

- BitLocker on and off, including recovery-material confirmation and restoration
- Secure Boot on and off with a complete valid or invalid trust chain
- supported single-disk layouts and rejected multi-disk, dynamic, pooled, RAID,
  MBR, unhealthy, dirty, pending-reboot, low-space, and low-ESP cases
- power loss at every intent, action, observation, commit, promotion, handoff,
  firmware, reboot, finalizer, and rollback boundary
- disk-full, sharing-violation, ACL, reparse-point, symlink, stale-identity,
  post-verification tamper, and corrupted-journal cases
- successful Windows resume, JStack first boot, rollback, repeated recovery, and
  actual bootability after snapshots are restored

Linux VM tests must additionally prove local-filesystem and directory-sync
semantics, Btrfs deployment, image verification, boot-artifact installation, and
bounded writes to the confirmed interval.

## Physical-hardware gates

A small supported-device matrix remains necessary for firmware variable behavior,
BootNext reliability, Secure Boot key chains, vendor recovery layouts, BitLocker
and TPM integration, storage-driver behavior, unexpected reset behavior, and
actual Windows/JStack bootability. Hardware testing is evidence for the declared
support envelope, not permission to silently accept an untested layout.

## Guarantee claim

The intended production claim is not that installation always succeeds. The
claim is:

> The installer mutates only the explicitly confirmed, freshly revalidated plan;
> commits progress only after independently observed postconditions; and otherwise
> retries, rolls back, or stops for manual recovery without claiming success.

That claim becomes supportable only after every row reaches its required level.
