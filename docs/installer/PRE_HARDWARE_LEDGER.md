# Pre-hardware completion ledger

This ledger is the source of truth for work that can be completed before a
physical Windows laptop is available. It complements `ASSURANCE_MATRIX.md` and
`VM_PROOF.md`; it does not lower either document's gates.

## Completion boundary

Pre-hardware completion means that the declared Windows 10 and Windows 11 VM
profiles either complete a verified dual-boot installation or reach a defined
recovery outcome without mutating outside the confirmed plan. It does **not**
claim compatibility with physical firmware, storage controllers, TPMs, recovery
layouts, or reset behavior.

The following restrictions remain unconditional throughout this work:

1. VM disks are harness-created regular files below
   `$JCODE_SCRATCH_DIR/jstack-windows-vm`.
2. Host block devices, host firmware variables, system libvirt, passthrough disk
   arguments, arbitrary QEMU fragments, and caller-selected mutation roots are
   rejected.
3. Production mutation constructors remain unavailable. Platform effects are
   exposed only to sealed virtual or disposable-VM adapters.
4. Every mutation is graph-authorized, plan-bound, identity-revalidated,
   preceded by durable intent, and followed by independent observation before
   commit.
5. A test exit code is never sufficient evidence. Guest, disk, firmware,
   journal, and boot observations must agree.

## Verified baseline

Implementation baseline commit: `eed4d6b301ed890d3db5f902fa514fea9ead4a6a`. PH-01 and
PH-05 controller logic landed afterward and is exposed from the controller
crate root; `installer/make check` passes on that tree.
This ledger was introduced by `1cdab4c1f5ab1acb2bc9ec4af7fa62a82866859f`.
Neither commit is the future PH-18 release candidate: that gate records and
validates the exact immutable tree that contains all completed work.

| Capability | Current evidence | State |
| --- | --- | --- |
| Executable model | 55 states, 92 transitions, 41 actions, 44 guards, 20 invariants, and 17 traces validated by `installer/tools/validate_state_graph.py` using `state_model.py` | complete foundation |
| Typed graph and replay | Digest-pinned Rust graph loader, all abstract traces, every success/failure edge, and graph-bound durable replay in `installer/controller` | complete foundation |
| Release and planning | Canonical threshold-signed release, acceptance ratchet, strict inventory, deterministic plan, confirmation, and identity bindings in `installer/core` | complete foundation |
| Durable staging | Acceptance WAL, resumable quarantine, evidence publication, and private regular-file transaction simulator in `installer/staging` | complete foundation |
| VM safety harness | File-only QEMU plan, workspace confinement, QMP/FD audit, immutable profiles, and strict evidence verifier in `installer/vm` | complete foundation |
| Exact toolchain | Rust and Cargo 1.85.0 plus installed Linux and `x86_64-pc-windows-msvc` targets | available |
| Virtualization | QEMU 11.0.2, KVM access, OVMF secure/nonsecure code, swtpm 0.10.1, PowerShell 7.5.4 | available |
| Official Windows 10 media | 6,140,975,104 bytes, SHA-256 `a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e`; matches the page-sourced Microsoft hash recorded in the profile, but no archival Microsoft publication artifact is retained | acquired; publication provenance is non-archival |
| Official Windows 11 media | 7,092,807,680 bytes, SHA-256 `a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9`; matches the Microsoft publication record | acquired and authenticated |
| Local capacity | 8 logical CPUs, 15 GiB RAM, KVM, and approximately 74 GiB free at the baseline audit; obsolete detached review worktrees provide reclaimable scratch capacity | usable only while at least 64 GiB remains free before a new base-image build |

## Pre-hardware requirement ledger

A row is complete only when its named observation exists on a frozen tree. Unit
coverage cannot substitute for a VM observation, and a VM observation cannot
substitute for a physical-hardware observation.

| ID | Requirement | Existing evidence | Pre-hardware exit criterion | Status |
| --- | --- | --- | --- | --- |
| PH-01 | Typed capability issuance | `installer/controller/src/authority.rs` issues private-field, non-`Clone`, non-`Deserialize` release-policy, confirmed-plan, user-confirmation, rollback, staging, actor, and guard capabilities only from successful validators, and `tests/authority.rs` proves fail-closed behavior for missing, wrong-actor, extra, ambiguous, and rejected-validator cases | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-02 | Deterministic runtime selection | `installer/controller/tests/selection_totality.rs` authorizes all 92 transitions exactly once from their own source state and event through `authorize_transition`, and exhaustively rejects every foreign actor, missing/extra/duplicated authorization, missing guard witness, and out-of-platform guard issuance; the single contested `(state, event)` pair is proven ambiguous under a union oracle and disabled under any weakened guard set | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-03 | Restart-safe controller execution | `installer/controller/src/runtime.rs` executes the six-step intent/effect/observe/commit/advance protocol through `EffectBoundary`, whose only constructor consumes an in-memory `VirtualPlatform`; `tests/runtime_convergence.rs` crashes every mutating happy-path transition at all five durable boundaries and proves each restart converges to the identical control state and identical whole-machine digest as the uninterrupted run, for both the BitLocker and no-BitLocker profiles | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-04 | Verified failure admission | The runtime recomputes the no-committed-effect proof from the platform's own residual-object observation and reads the failure target from the graph; `tests/runtime_convergence.rs` proves a clean failure lands on the exact graph failure state with one canonical evidence object, a lying executor that claims success without an effect is refused by independent postcondition observation, and a genuinely surviving new effect halts for manual recovery with no `action_failed` record. Removing either check was mutation-tested and fails the suite | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-05 | Replicated cross-OS state | `installer/controller/src/replica.rs` requires two authenticated replicas, binds journal identity to graph/plan/release/journal head, authenticates confirmation and handoff objects, enforces a durable single-use nonce ledger, and rejects illegal actor changes; `tests/replica.rs` covers forks, stale and mixed identities, duplicate locations, cross-authority tokens, and replay after restore | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-06 | Deterministic virtual platform | `installer/controller/src/platform.rs` models GPT geometry, filesystems, ESP namespace, firmware boot entries and one-shot BootNext, BitLocker, the finalizer, power state, rearm budgets, staging, and journal replicas with no I/O, path, device, or unsafe code; `tests/runtime_convergence.rs` proves every graph condition is answerable and every graph action is modelled (unknown identifiers are errors, never silent defaults), partitions are created only at the confirmed plan's exact geometry inside the approved interval, the GPT never overlaps, BitLocker round-trips exactly, and BootNext is consumed by the boot it causes | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-07 | FAT32 and Btrfs image transactions | `installer/vm/images.py` builds real FAT32 and Btrfs volumes in sparse regular files inside the workspace using unprivileged `mkfs.fat`/mtools and `mkfs.btrfs`, with no mount, block device, or privilege; every payload is verified by reading the bytes back out of the image. `installer/vm/tests/test_images.py` (31 cases) covers short write, silent corruption, injected and genuine ENOSPC, a crash at every protocol boundary for both filesystems, FAT32 case folding, existing-destination refusal, partial-batch isolation, symlink and hard-link rejection, workspace confinement, post-deploy tamper detection, `btrfs check` and superblock-checksum agreement, and replay idempotence. Skipping either read-back check or the case-collision check was mutation-tested and fails the suite | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-08 | Disposable-VM Windows adapters | `installer/core/assets/windows-mutation-adapters.ps1` implements storage shrink/expand, plan-bound partition creation, BitLocker suspend/restore, and finalizer register/unregister; each adapter refuses to run without a matching `JSTACK_DISPOSABLE_VM` attestation and an action-bound controller capability, resolves targets only by GPT GUID from the confirmed plan, and re-observes its own postcondition. `installer/core/src/windows_firmware.rs` holds all firmware decision logic with no `unsafe` and restricts the entire write surface to `BootNext`; `src/bin/jstack-firmware.rs` is the sole `unsafe` boundary and calls only `Get/SetFirmwareEnvironmentVariableExW`. `tools/validate_windows_adapters.py` statically bounds the surface (allowlist, module-qualified mutation cmdlets, forbidden-primitive scan, gate-before-dispatch ordering, exact `is_writable` body, SAFETY-comment coverage) and both it and the 9 firmware unit tests were mutation-tested against unqualified cmdlets, an injected `Clear-Disk`, a reordered gate, a widened write surface, and a dropped read-back check. Compiles for `x86_64-pc-windows-msvc` | implemented; **no live Windows execution yet** (requires PH-12 base images) |
| PH-09 | Linux RAM-installer adapters | `installer/vm/linux_installer.py` re-inventories the GPT with `sgdisk`, recomputes the handoff fingerprint and refuses any drift before writing, creates only the confirmed plan's exact partition geometry and GUIDs (refusing non-creatable roles and type GUIDs so an ESP/MSR/recovery partition can never be created), formats and deploys Btrfs through the PH-07 verified transactions, installs boot artifacts, independently re-verifies the installation, and rolls back only plan-owned partitions. Every mutating adapter requires a matching disposable-VM attestation, and every target must be a sparse regular file inside the workspace: `/dev` paths, symlinks, hard links, and outside-workspace paths are refused, and a static test asserts the module body names no device path, `losetup`, `mount(`, `kpartx`, `partprobe`, or `sudo`. `installer/vm/tests/test_linux_installer.py` (28 cases) covers drift, wrong disk GUID, occupied interval, exact geometry, idempotent retry after a crash, overlap refusal, mismatched-existing refusal, rollback preservation of unowned and OEM partitions, tamper and absence detection, and an ordered end-to-end Linux-side install. Skipping the drift check, the ownership filter, the overlap check, or the type-GUID allowlist was mutation-tested and fails the suite | implemented; **no live VM boot yet** (requires PH-12 base images) |
| PH-10 | Bootable signed test artifacts | `installer/vm/artifacts.py` builds the closed role set with the same tools a release uses: the distribution systemd-boot binary as the ESP loader (copied byte-identically), real installer and recovery UKIs via `ukify`, a content-addressed system image, BLS type-1 boot entries, and canonical Windows/Linux handoff payloads, all signed with `sbsign` under a per-run throwaway key and bound by one canonical manifest that the manifest builder refuses to emit unless every PE role is signed and the role set is complete. `installer/vm/tests/test_artifacts.py` (26 cases) proves UKI byte-reproducibility, that cmdline and initrd changes alter the identity, entry and handoff canonicality, cross-build agreement, and that a flipped byte inside a signed PE, a foreign trust root, an unsigned PE, and a tampered unsigned image are all rejected. Four cases invoke `sbverify` directly rather than through the module helper, so the module's own verification is never the oracle; replacing signing with a file copy fails 17 cases | implemented; **artifacts are test-key signed, not a release** |
| PH-11 | Resolved immutable profiles | Media records, QEMU/OVMF/swtpm acquisition evidence, and profile schemas exist | Windows 10 and 11 profiles contain exact installed-build, base-image, firmware, executable, release, graph, installer, and boot-artifact identities | open |
| PH-12 | Reproducible base images | Official ISOs and unattended answer media exist | Freshly built UEFI/GPT qcow2 bases match declared Windows edition/build/layout and are independently inspected before sealing read-only | open |
| PH-13 | End-to-end happy paths | `VM_PROOF.md` defines twelve independent observations | Each claimed Secure Boot/TPM/BitLocker profile completes Windows → installer → Windows → JStack and cold-boots both OSes with a terminal journal | open |
| PH-14 | Graph-derived fault campaigns | Model and evidence schema define mutation classes and eight interruption phases | Every applicable mutation and failure edge is exercised with process termination plus ENOSPC, sharing, tamper, stale identity, firmware, reboot, finalizer, rollback, and recovery cases | open |
| PH-15 | Repetition and freshness | Fresh-run isolation is enforced by the harness | Ten fresh-overlay happy paths pass per supported OS and security-profile combination, a base is reconstructed, and all required campaigns rerun after relevant changes | open |
| PH-16 | Canonical evidence and support matrix | `installer/vm/evidence/verify.py` (2,856 lines) is the fail-closed verifier: canonical-byte serialization, unique keys, no floats or non-finite numbers, exact field sets, artifact path normalization with symlink/hard-link/escape rejection, size and digest checks before any semantic claim, immutable profile list, and Ed25519 release trust. All four trust roots (`--trusted-release-policy-sha256`, `--trusted-profile-sha256`, `--trusted-media-sha256`, `--trusted-campaign-index-sha256`) are **required CLI arguments**, so a bundle can never nominate its own trust root. 36 verifier tests pass | verifier complete; **no real run bundles yet** (requires PH-13) |
| PH-17 | Runnable packaging and recovery UX | `installer/controller/src/bin/jstack-installer.rs` provides `confirm` (renders the disk GUID, plan hash, before/after sizes, exact byte interval, every created and preserved partition GUID, and all rollback objects, refusing a mismatched display or a plan whose hash disagrees with its body), `confirmed` (validates a recorded confirmation), `run` (drives the full graph to `terminal.completed` through the sealed virtual boundary, 83 durable journal records, for both BitLocker profiles), `explain`, and `states` (actionable operator guidance derived from the graph, including an explicit "Do not retry" for `terminal.manual_recovery`). `tests/installer_cli.rs` (10 cases) runs the real binary and asserts the CLI offers no `--device`, `--disk`, or `--production` target, names no device path, and constructs exactly one kind of effect boundary | implemented; **virtual execution only** |
| PH-18 | Frozen-tree assurance | Milestone gate is documented and previously exercised | Exact Rust 1.85 Linux/Windows-target/VM/media/evidence gates and static host-device audit pass on immutable trees; independent P0/P1 reviewers report no blockers before each commit | open |

## Physical-only residual ledger

These rows must remain open after pre-hardware completion. A QEMU result must not
be used to close them.

| ID | Required physical observation |
| --- | --- |
| HW-01 | Firmware Boot#### creation, BootNext reliability, bounded rearm, and reset behavior on each declared device |
| HW-02 | Secure Boot chain and key-enrollment behavior of each vendor firmware |
| HW-03 | TPM-backed BitLocker suspend, recovery, restoration, and PCR behavior across real reboots |
| HW-04 | NVMe/storage-driver resize, flush, discard, power-loss, and sharing semantics |
| HW-05 | OEM ESP, MSR, recovery, diagnostics, and vendor partition preservation |
| HW-06 | Real AC/battery readiness, unexpected reset, firmware update, and pending-servicing interactions |
| HW-07 | Actual Windows and JStack bootability, networking, graphics/session prerequisites, and recovery UX |
| HW-08 | Signed release-candidate repetition on a small explicitly supported hardware matrix using sacrificial storage |

## Environment actions

The local host is the current VM execution target because the configured SSH
desktop was unreachable during the baseline audit. `mkfs.fat`, `mtools`,
`sgdisk`, `guestfish`, and `ukify` are installed from signed Arch repositories.
The host has 74 GiB free and the existing VM workspace uses 13 GiB. Large
artifacts remain under `$JCODE_SCRATCH_DIR`; obsolete detached validation
worktrees may be removed only after confirming they contain no uncommitted
evidence.

## Definition of done

Pre-hardware work is complete only when PH-01 through PH-18 are closed with
content-addressed evidence, the final tree is independently reviewed and
committed, production mutation remains unreachable, and HW-01 through HW-08 are
still explicitly reported as open.
