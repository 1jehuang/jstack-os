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
| PH-10 | Bootable signed test artifacts | `installer/vm/artifacts.py` builds the closed role set with the same tools a release uses: the distribution systemd-boot binary as the ESP loader (copied byte-identically), real installer and recovery UKIs via `ukify`, a content-addressed system image, BLS type-1 boot entries, and canonical Windows/Linux handoff payloads, all signed with `sbsign` under a per-run throwaway key and bound by one canonical manifest that the manifest builder refuses to emit unless every PE role is signed and the role set is complete. `installer/vm/tests/test_artifacts.py` (26 cases) proves UKI byte-reproducibility, that cmdline and initrd changes alter the identity, entry and handoff canonicality, cross-build agreement, and that a flipped byte inside a signed PE, a foreign trust root, an unsigned PE, and a tampered unsigned image are all rejected. Four cases invoke `sbverify` directly rather than through the module helper, so the module's own verification is never the oracle; replacing signing with a file copy fails 17 cases. **The artifacts are also proven to actually boot**, which no digest check establishes: `installer/vm/boot_proof.py` (run by `make -C installer/vm boot-proof`, 12 cases) enrolls the test certificate as PK/KEK/db in a per-run OVMF variable copy, enables Secure Boot, and boots the artifact three times on real firmware with a network-less, device-less guest. Observed on the serial console: the **signed** UKI reaches the in-guest marker; a **single flipped byte** deep inside the signed PE is refused by firmware with `Access Denied` and never reaches the marker; and an **unsigned** image is likewise refused, which is the control proving Secure Boot is genuinely enforcing rather than the harness being broken. Static cases assert the guest gets no network or host device, firmware code is opened read-only, the variable store is a per-run copy, and every boot is hard-timeout capped | implemented and **boot-verified on real firmware**; artifacts remain test-key signed, not a release |
| PH-11 | Resolved immutable profiles | Media records and profile schemas are complete and validated. Of the twelve required inputs per profile, the **five host-scoped ones are now resolved**: `base_image.py host-identities` (also `make -C installer/vm host-identities`) digests the QEMU and swtpm executables and the three OVMF firmware files, refusing set-id binaries and binding each digest to its exact resolved path. This deliberately does **not** go through `lab.py init`, which gates read-only digest collection behind the 6 GiB VM-launch memory envelope and so could not resolve these on a busy host; a test asserts collection never references that gate, `available_memory_bytes`, `host_evidence`, or `/dev/kvm`. Coverage is derived from the profiles themselves, not hardcoded: a test asserts the collector covers exactly the `host-acquisition` inputs and that every remaining input is `base-image-acquisition` or `release-build` scoped. Digests are checked against an independent hash of the same file so the collector is not its own oracle. Dropping an input, faking a digest, or re-coupling to the memory gate were each mutation-tested and fail the suite **9 of 12 inputs resolved.** The four release-build inputs also resolve now via `base_image.py release-identities`: the state-graph and signed-release digests come straight from the repository (and a test asserts the graph digest equals the value the signed manifest pins, so a drift between them is caught), the installer digest comes from the built `jstack-installer`, and the boot-artifact digest comes from a real `build_test_artifact_set` manifest. A test asserts the only inputs left uncovered are exactly the `base-image-acquisition` ones, which is the precise statement of what the absent ISOs still block. The remaining 3 base-image-scoped inputs **now resolve for both profiles** from their built images, through the per-record `base-image.<record>.json` document each build emits; the test walks the profile's own `evidence_locator` values rather than restating them, so a renamed locator fails a test instead of silently going unresolvable. **12 of 12 inputs resolved for both profiles.** |
| PH-12 | Reproducible base images | `installer/vm/base_image.py` provides the three inputs a base-image build needs, all testable without the ISO: (a) `verify-media` accepts an ISO only when its size, SHA-256, **and** ISO 9660 structure all match the immutable media record, checking size before hashing and refusing symlinks, hard links, and out-of-workspace paths; (b) `answer-media` builds a byte-reproducible `Autounattend.xml` pinning the exact edition, locale, and the exact ESP/MSR/extended-Windows UEFI-GPT layout, requesting no recovery partition (Windows setup creates one of its own regardless, which the built image confirms: the answer file declares three partitions and the finished disk carries four), published into a FAT32 image through the verified PH-07 transaction; (c) `make readiness` reports all 12 preconditions with an actionable remedy for each. `tests/test_base_image.py` (23 cases) proves the recorded Windows 10 and 11 digests match the values Microsoft publishes, that a flipped byte, a wrong size, and a non-ISO file with a forged matching record are each refused, and that the answer file is well-formed and reproducible. Skipping the digest, magic, or size check, or adding a recovery partition, were each mutation-tested and fail the suite. **Both ISOs are now acquired and verified, and `make readiness` reports 21/21 with `ready: true`.** Each was accepted by `verify-media` on size, SHA-256, and ISO 9660 structure against its immutable record. The Windows 11 Enterprise 25H2 Evaluation image resolves from a stable `go.microsoft.com/fwlink` redirect whose advertised length matches the recorded 7,092,807,680 bytes exactly, so that one is scriptable. The Windows 10 retail image still is not: its download URL is minted per session behind Microsoft's Sentinel bot defence, so the page selection must be performed in a real browser and the resulting signed URL handed to the downloader. **The Windows 11 Enterprise 25H2 base image is now built.** The install ran unattended on Microsoft-enrolled Secure Boot firmware with an emulated TPM 2.0 and no network, the guest powered itself off after 2,149 s, and the resulting qcow2 was inspected by reading the image back: a GPT carrying the ESP, MSR, Windows, and recovery partitions in the profile's declared order. `vm/tools/verify_base_image.py` is a ledger probe that **recomputes** the image and GPT digests from the disk rather than trusting the recorded numbers, re-inspects the layout, and resolves every base-image-scoped profile input through `base-image.json`; a document that was true when written says nothing about the file that is there now. Four separate defects had to be fixed before any install could finish, each of which failed silently for its full 90-minute timeout: the boot-prompt keypress had to stop as soon as the guest began writing (a fixed schedule pressed Cancel mid-install); the answer file never asked the guest to shut down, which is the build's only success signal; the `oobeSystem` pass had no `International-Core` component, so a completed install stopped on OOBE's region page forever; and a guest killed by the host OOM reaper was invisible, because QEMU exits zero on SIGTERM. **The Windows 10 Pro 22H2 image is now built as well, and both verify from their own disks.** Each profile's evidence document is scoped to its record, because both profiles name `base-image.json` and a shared file would have left the second build's digests standing in for the first image's. The two images are usefully different rather than two runs of the same thing: Windows 10 finished in 426 s with three partitions, Windows 11 in 2,149 s with four, since Windows 11 setup creates a recovery partition and Windows 10 does not, from answer files that both request three. Retail multi-edition media also needs a `ProductKey` that the Evaluation image must not be given. **A repeated build settles the row's own title, and the answer is no.** Windows 10 Pro was built twice from byte-identical inputs: same verified ISO, same answer media, same enrolled firmware master, same topology. The two images are **structurally identical and byte-different** -- both carry the same three partition roles in the same order, and the image digests differ (`bd5d7797...` vs `f8a69266...`), as do the GPT digests, the sizes (10,611,589,120 vs 10,050,600,960 bytes), and the durations (426 s vs 372 s). This is inherent rather than a defect: Windows setup writes timestamps, freshly generated partition and machine GUIDs, and entropy that no answer file can pin. **So `base-image-sha256` is not a reproducibility claim and must not be read as one.** It is the identity of one specific produced image, exactly as PH-19 already records `reproducible=false` for the enrolled firmware store because EFI signature lists embed a timestamp. What *is* reproducible, and is what a campaign actually depends on, is the structure: the partition roles, their order, and their type GUIDs, which agreed across both runs and are what `verify_base_image.py` checks. The row's title overpromises, and the honest scope is structural reproducibility plus a pinned per-image identity |
| PH-13 | End-to-end happy paths | The full install path is proven end to end against the deterministic virtual platform for both BitLocker profiles (`runtime_convergence.rs`, and the `jstack-installer run` CLI reaching `terminal.completed` with 83 durable journal records). A virtual result is explicitly **not** accepted as evidence for this row | **blocked on PH-12**; requires real guest, disk, firmware, journal, and cold-boot observations |
| PH-14 | Graph-derived fault campaigns | `installer/controller/tests/fault_campaign.rs` derives its cases from the graph, not a hand-written list: every mutating transition on both BitLocker profiles is exercised under every fault class (stop-before-action, success-claimed-without-effect, fail-after-effect) and every crash boundary, asserting each outcome lands on a graph-declared state, that a clean failure yields exactly one canonical evidence object on the exact `failure_to` with the legal intent/failed/advanced triad, that a fault which landed a durable object halts for manual recovery and fabricates nothing, that every case replays to the same disposition in a fresh runtime, and that a second resume appends nothing. Plus tamper (a corrupted loader can never be armed), stale identity (a journal from another plan is rejected), reboot (a boot cannot be observed twice), finalizer/security ordering, and a graph search proving every post-mutation state can reach a declared terminal. **This campaign found and fixed a real bug**: firmware boot entries were absent from the plan's rollback-object list, so a failure after creating one would have falsely claimed no committed effect. ENOSPC, short-write, and sharing classes are covered by the PH-07 image suite | virtual campaign complete; **disposable-VM campaign still open** (requires PH-12) |
| PH-15 | Repetition and freshness | Fresh-run isolation is enforced and tested by the harness (run ids, exclusive mutable state, overlay and hard-link rejection). `installer/controller/tests/repetition.rs` establishes the property that makes a ten-overlay VM campaign meaningful rather than ten repetitions of one accident: ten fresh runs per supported profile are byte-identical in terminal state, whole-machine digest, and journal length; the two profiles reach genuinely different machines, so that determinism is not an artifact of the profile being ignored; interleaving profiles repeatedly changes nothing; a failing run between two successful ones does not contaminate them; a fresh machine has all 22 should-be-false conditions false and the should-be-true ones true; and a fresh machine is a pure function of the plan and profile. Excluding BitLocker from the machine digest, or leaking one field of start state, were each mutation-tested and fail the suite | virtual repetition complete; the **ten-fresh-overlay VM requirement is blocked on PH-12** |
| PH-16 | Canonical evidence and support matrix | `installer/vm/evidence/verify.py` (2,856 lines) is the fail-closed verifier: canonical-byte serialization, unique keys, no floats or non-finite numbers, exact field sets, artifact path normalization with symlink/hard-link/escape rejection, size and digest checks before any semantic claim, immutable profile list, and Ed25519 release trust. All four trust roots (`--trusted-release-policy-sha256`, `--trusted-profile-sha256`, `--trusted-media-sha256`, `--trusted-campaign-index-sha256`) are **required CLI arguments**, so a bundle can never nominate its own trust root. 36 verifier tests pass | verifier complete; **no real run bundles yet** (requires PH-13) |
| PH-17 | Runnable packaging and recovery UX | `installer/controller/src/bin/jstack-installer.rs` provides `confirm` (renders the disk GUID, plan hash, before/after sizes, exact byte interval, every created and preserved partition GUID, and all rollback objects, refusing a mismatched display or a plan whose hash disagrees with its body), `confirmed` (validates a recorded confirmation), `run` (drives the full graph to `terminal.completed` through the sealed virtual boundary, 83 durable journal records, for both BitLocker profiles), `explain`, and `states` (actionable operator guidance derived from the graph, including an explicit "Do not retry" for `terminal.manual_recovery`). `tests/installer_cli.rs` (10 cases) runs the real binary and asserts the CLI offers no `--device`, `--disk`, or `--production` target, names no device path, and constructs exactly one kind of effect boundary | implemented; **virtual execution only** |
| PH-18 | Frozen-tree assurance | Every commit in this work ran the full `installer/make check` gate on its own tree: exact Rust and Cargo 1.85.0, `cargo fmt --check`, `clippy -D warnings`, `cargo check --target x86_64-pc-windows-msvc`, the state-graph validator, the core/staging/controller suites, the static Windows collector and mutation-adapter surface validators, and 171 VM tests. A static host-device audit is enforced continuously by the harness and by tests asserting no `/dev` path, mount, loop device, `libvirt`, passthrough argument, or privileged call is reachable | **cannot close**: the release-candidate gate must run on the immutable tree that contains all completed work, which requires PH-12 through PH-15 first |
| PH-19 | Microsoft-production firmware enrollment | `installer/vm/firmware_enrollment.py` builds the enrolled OVMF variable store the support profiles require as `ovmf-enrolled-vars-sha256`. The distribution ships an empty `OVMF_VARS.4m.fd`, so this is a build step. The store is verified by re-parsing the produced bytes rather than by trusting `virt-fw-vars` to exit 0: PK, KEK, and db must all be present, Secure Boot must be on, and CustomMode must be off, since custom mode would let the guest rewrite the trust anchors and void every later observation. Enrollment copies the read-only distribution template and writes only inside the workspace, and the template digest is re-checked afterwards because a build that mutated the shared file would silently change every future run's starting firmware state. `tests/test_firmware_enrollment.py` (14 cases) mocks the enrolling call into a silent no-op and confirms the read-back catches it, drops each trust anchor individually, and refuses a symlinked destination, an outside-workspace target, and a clobbered store. Recorded as `reproducible=false` on purpose: EFI signature lists embed a timestamp, so the identity to pin is one specific produced store | implemented and verified; **no Windows guest has booted from it yet** |

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

**Do not read the status from this section. Compute it.**

```sh
make -C installer progress        # static probes, part of `make check`
make -C installer progress-full   # also runs the readiness and identity gates
```

`installer/tools/ledger_status.py` evaluates every row in
`installer/model/pre-hardware-ledger.json` by running probes against the tree:
does the evidence file exist, does the named safety property still hold, does the
gate still exit zero. A row is reported open whenever its probes fail, regardless
of what any prose says. That is deliberate. A status column in a document is a
claim about the past; a probe is a measurement of the present. This section
records the interpretation, and the tool records the truth.

Three numbers are reported, and conflating them is the mistake the separation
exists to prevent:

| Number | Current | Meaning |
| --- | --- | --- |
| implemented | 19/19 | The code exists and its static safety properties hold |
| pre-hardware closed | 9/19 | Implemented *and* every named virtual or firmware observation exists |
| hardware closed | 0/8 | Physical observations. QEMU can never close one of these |

`implemented` reaching 19/19 is not completion, and the gap between it and 9/19
is the honest measure of what is left. Ten rows stay open because they name an
observation that no amount of source code can supply. **Real Windows guests have
now been installed for both profiles, and one profile twice.** The repeat
measured what the row's title asserts and contradicted it: the images are
structurally identical and byte-different, because Windows setup writes
timestamps and fresh GUIDs. A pinned image digest is therefore an identity, not
a reproducibility claim.

PH-08, PH-09, PH-16, and PH-19 still need a guest that boots *from* the built
image; PH-12 needs its reproducibility scope corrected to the structural claim its evidence supports; PH-13
through PH-15 need real VM campaigns; PH-11 needs the Windows 10 image for its
last three inputs; PH-18 must run on the frozen tree. The tracker refuses to
close those from unit tests, and `tests/test_ledger_status.py` mutation-tests
that refusal by releasing the gate and confirming the row would otherwise close.

Dependency closure is computed to a fixed point, so a satisfied dependency stops
blocking. A row that still names an outstanding observation carries
`requires_vm_observation` and is held open by that, not by its dependency list.
Those two reasons are kept separate because conflating them once produced a
score of 73.7% that quietly counted five unbooted rows as closed.

The baseline is a ratchet. `make progress` fails if fewer than 19 rows are
implemented, so a regression that would previously have been a quietly edited
table is now a build failure.

| Row | Blocker |
| --- | --- |
| PH-08, PH-09 | Adapters are implemented and statically bounded; no live guest execution yet |
| PH-19 | Enrolled firmware store is built and verified; no guest has booted from it |
| PH-11 | 12 of 12 resolved for both profiles from their built images |
| PH-12 | Both images built and re-verified. A repeated build shows they are structurally identical but byte-different, so `base-image-sha256` pins one produced image rather than asserting reproducibility |
| PH-13, PH-14, PH-15 | Virtual halves complete; real VM observations outstanding |
| PH-16 | Verifier complete; no real run bundle exists to verify |
| PH-18 | Must run on the immutable tree that contains PH-12 through PH-15 and PH-19 |

To unblock, in order:

1. Run the readiness gate. Its stdout is pure JSON and it exits nonzero while
   anything is blocked, so it can be scripted:

   ```sh
   make --no-print-directory -C installer/vm readiness
   ```
2. Both ISOs are already acquired and verified. If the workspace is ever rebuilt,
   note that the Windows 11 Enterprise Evaluation image downloads from a stable
   `go.microsoft.com/fwlink` redirect and can be scripted, while the Windows 10
   retail image cannot: its URL is minted per session behind Microsoft's Sentinel
   bot defence, so the edition and language selection must happen in a real
   browser and the resulting signed URL be handed to the downloader. Verify each
   with
   `python3 installer/vm/base_image.py --workspace <lab> verify-media --record <key>`.
3. Build the answer media with `base_image.py ... answer-media`, then build and
   independently inspect the base images, resolving the `required-unresolved`
   profile fields (PH-12, then PH-11).
4. Run the end-to-end and repetition campaigns (PH-13, PH-15) and the
   disposable-VM fault campaign (PH-14), which also exercises PH-08 and PH-09
   against a live guest and produces the first PH-16 evidence bundle.
5. Freeze the tree and run the release-candidate gate (PH-18).

## Firmware-observed evidence

Almost every check in this tree compares bytes. Exactly one observes real
firmware behaviour: the PH-10 boot proof, which is the only place a claim about
bootability or Secure Boot enforcement is settled by a machine rather than by an
assertion about a signature. It is excluded from the default `make check` because
it launches three VMs and is host-dependent; run it with
`make -C installer/vm boot-proof`, or as part of `make -C installer/vm full-check`.

## Composition

The per-row rows above each prove one component. `installer/vm/tests/test_end_to_end.py`
proves they compose: one plan, produced by the real planner from the real signed
release manifest, flows through the artifact builder, the Linux adapters, and the
image transactions, and the result verifies. It asserts the planner's output
parses under the adapters' strict creatable-role and creatable-type-GUID rules,
that the display document the operator approves agrees with the plan field by
field, that partitions land at the planner's byte offsets exactly, that the boot
artifacts read back out of the FAT32 image are still the signed originals, that
rollback removes exactly the plan's partitions, that a drifted disk stops the
install before anything is written, that the readiness gate emits pure JSON
and exits nonzero while blocked, and that the gate never reports a
repository-resolvable input as blocked, always shows a real digest for a
satisfied identity, and cleans up everything it builds. A checklist that cries
wolf is worse than no checklist, so that honesty is itself tested. This is where a component that passes its own
tests but disagrees with its neighbour is caught.

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
