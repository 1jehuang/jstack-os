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
| PH-11 | Resolved immutable profiles | Media records and profile schemas are complete and validated (23 profile tests). Both profiles remain `status: blocked-required-inputs` because `installed_build`, base-image, and firmware-variable digests are marked `required-unresolved` and can only be resolved by actually building a base image | **blocked on PH-12** |
| PH-12 | Reproducible base images | Tooling is in place (QEMU 11.0.2, KVM, OVMF secure/nonsecure, swtpm, and a validated file-only launcher) | **blocked on two host preconditions.** (1) The official Windows 10 and 11 ISOs recorded in the media records are no longer present under `$JCODE_SCRATCH_DIR`; they need re-acquiring (about 13 GB total) and their recorded SHA-256 values re-verified. The Microsoft Evaluation Center download requires an interactive registration form, so this is not scriptable. (2) `lab.py check-host` requires 6 GiB available memory and the host currently has 3.2 GiB free. Neither is a code defect |
| PH-13 | End-to-end happy paths | The full install path is proven end to end against the deterministic virtual platform for both BitLocker profiles (`runtime_convergence.rs`, and the `jstack-installer run` CLI reaching `terminal.completed` with 83 durable journal records). A virtual result is explicitly **not** accepted as evidence for this row | **blocked on PH-12**; requires real guest, disk, firmware, journal, and cold-boot observations |
| PH-14 | Graph-derived fault campaigns | `installer/controller/tests/fault_campaign.rs` derives its cases from the graph, not a hand-written list: every mutating transition on both BitLocker profiles is exercised under every fault class (stop-before-action, success-claimed-without-effect, fail-after-effect) and every crash boundary, asserting each outcome lands on a graph-declared state, that a clean failure yields exactly one canonical evidence object on the exact `failure_to` with the legal intent/failed/advanced triad, that a fault which landed a durable object halts for manual recovery and fabricates nothing, that every case replays to the same disposition in a fresh runtime, and that a second resume appends nothing. Plus tamper (a corrupted loader can never be armed), stale identity (a journal from another plan is rejected), reboot (a boot cannot be observed twice), finalizer/security ordering, and a graph search proving every post-mutation state can reach a declared terminal. **This campaign found and fixed a real bug**: firmware boot entries were absent from the plan's rollback-object list, so a failure after creating one would have falsely claimed no committed effect. ENOSPC, short-write, and sharing classes are covered by the PH-07 image suite | virtual campaign complete; **disposable-VM campaign still open** (requires PH-12) |
| PH-15 | Repetition and freshness | Fresh-run isolation is enforced and tested by the harness (run ids, exclusive mutable state, overlay and hard-link rejection). The virtual campaigns are deterministic and rerun on every `make check` | **blocked on PH-12** for the ten-fresh-overlay VM requirement |
| PH-16 | Canonical evidence and support matrix | `installer/vm/evidence/verify.py` (2,856 lines) is the fail-closed verifier: canonical-byte serialization, unique keys, no floats or non-finite numbers, exact field sets, artifact path normalization with symlink/hard-link/escape rejection, size and digest checks before any semantic claim, immutable profile list, and Ed25519 release trust. All four trust roots (`--trusted-release-policy-sha256`, `--trusted-profile-sha256`, `--trusted-media-sha256`, `--trusted-campaign-index-sha256`) are **required CLI arguments**, so a bundle can never nominate its own trust root. 36 verifier tests pass | verifier complete; **no real run bundles yet** (requires PH-13) |
| PH-17 | Runnable packaging and recovery UX | `installer/controller/src/bin/jstack-installer.rs` provides `confirm` (renders the disk GUID, plan hash, before/after sizes, exact byte interval, every created and preserved partition GUID, and all rollback objects, refusing a mismatched display or a plan whose hash disagrees with its body), `confirmed` (validates a recorded confirmation), `run` (drives the full graph to `terminal.completed` through the sealed virtual boundary, 83 durable journal records, for both BitLocker profiles), `explain`, and `states` (actionable operator guidance derived from the graph, including an explicit "Do not retry" for `terminal.manual_recovery`). `tests/installer_cli.rs` (10 cases) runs the real binary and asserts the CLI offers no `--device`, `--disk`, or `--production` target, names no device path, and constructs exactly one kind of effect boundary | implemented; **virtual execution only** |
| PH-18 | Frozen-tree assurance | Every commit in this work ran the full `installer/make check` gate on its own tree: exact Rust and Cargo 1.85.0, `cargo fmt --check`, `clippy -D warnings`, `cargo check --target x86_64-pc-windows-msvc`, the state-graph validator, the core/staging/controller suites, the static Windows collector and mutation-adapter surface validators, and 171 VM tests. A static host-device audit is enforced continuously by the harness and by tests asserting no `/dev` path, mount, loop device, `libvirt`, passthrough argument, or privileged call is reachable | **cannot close**: the release-candidate gate must run on the immutable tree that contains all completed work, which requires PH-12 through PH-15 first |

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

## Current status

Eleven rows are implemented and mutation-tested: PH-01 through PH-10, PH-14
(virtual half), PH-16, and PH-17. Five remain blocked, and none of the five is
blocked by a code defect:

| Row | Blocker |
| --- | --- |
| PH-11 | Depends on PH-12: profile digests can only be resolved by building a base image |
| PH-12 | Windows 10/11 ISOs are absent from scratch and must be re-acquired through an interactive Microsoft form; the host is also below the 6 GiB available-memory gate |
| PH-13 | Depends on PH-12 |
| PH-15 | Depends on PH-12 for the ten-fresh-overlay requirement |
| PH-18 | Must run on the immutable tree that contains PH-12 through PH-15 |

To unblock, in order:

1. Re-acquire both ISOs and verify them against the recorded SHA-256 values in
   `installer/vm/profiles/*.media.json`.
2. Free memory until `python3 installer/vm/lab.py check-host` passes, and confirm
   at least 64 GiB free before a base-image build.
3. Build and independently inspect the base images, resolving the
   `required-unresolved` profile fields (PH-12, then PH-11).
4. Run the end-to-end and repetition campaigns (PH-13, PH-15).
5. Freeze the tree and run the release-candidate gate (PH-18).

## Verification discipline

Every row above records the exact file and test names that establish it. Each
key invariant was additionally *mutation-tested*: the check was deliberately
broken, a specific named test was confirmed to fail, and the check was restored.
This is recorded because a passing suite proves nothing about a check that never
had teeth. One such mutation exposed a real defect, described in the PH-14 row.

## Definition of done

Pre-hardware work is complete only when PH-01 through PH-18 are closed with
content-addressed evidence, the final tree is independently reviewed and
committed, production mutation remains unreachable, and HW-01 through HW-08 are
still explicitly reported as open.

HW-01 through HW-08 remain open and unchanged. No result in this document was
produced on physical hardware, and no QEMU or virtual-platform result may be
used to close any of them.
