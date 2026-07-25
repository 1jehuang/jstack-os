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
| PH-03 | Restart-safe controller execution | Durable journal replay derives all current dispositions | `step`, `resume`, and `reconcile` execute graph actions through a sealed virtual effect boundary and converge after every durable boundary | open |
| PH-04 | Verified failure admission | Strict `FailureEvidence` and `ActionFailed` records exist | Each mutating action class recomputes a no-committed-effect proof or recovers forward; callers cannot choose a failure target | open |
| PH-05 | Replicated cross-OS state | `installer/controller/src/replica.rs` requires two authenticated replicas, binds journal identity to graph/plan/release/journal head, authenticates confirmation and handoff objects, enforces a durable single-use nonce ledger, and rejects illegal actor changes; `tests/replica.rs` covers forks, stale and mixed identities, duplicate locations, cross-authority tokens, and replay after restore | implemented; awaiting PH-18 frozen-tree confirmation |
| PH-06 | Deterministic virtual platform | Graph actions and guards define required state | Private state models GPT, filesystems, firmware, boot targets, BitLocker, power, replicas, and independently observable pre/postconditions for all applicable actions | open |
| PH-07 | FAT32 and Btrfs image transactions | Same-stream private regular-file simulator proves the core protocol | Descriptor-confined transactions write only plan-derived ESP/XBOOTLDR/Btrfs locations in sparse images and pass short-write, ENOSPC, crash, case, link, tamper, and replay tests | open |
| PH-08 | Disposable-VM Windows adapters | Read-only collector and Windows-target compile checks pass | Storage shrink/expand, partition creation, BitLocker suspend/restore, finalizer, BootNext, and reboot adapters run only in disposable VMs and consume controller capabilities | open |
| PH-09 | Linux RAM-installer adapters | Graph, planner, release, and handoff contracts exist | Signed RAM installer re-inventories, creates only the confirmed interval, formats/deploys/verifies Btrfs, installs boot artifacts, reconciles crashes, and rolls back | open |
| PH-10 | Bootable signed test artifacts | Artifact roles and signed test manifest exist | Reproducible loader, installer UKI, minimal JStack image, boot entries, and Windows/Linux handoff payloads form one verified test trust chain | open |
| PH-11 | Resolved immutable profiles | Media records, QEMU/OVMF/swtpm acquisition evidence, and profile schemas exist | Windows 10 and 11 profiles contain exact installed-build, base-image, firmware, executable, release, graph, installer, and boot-artifact identities | open |
| PH-12 | Reproducible base images | Official ISOs and unattended answer media exist | Freshly built UEFI/GPT qcow2 bases match declared Windows edition/build/layout and are independently inspected before sealing read-only | open |
| PH-13 | End-to-end happy paths | `VM_PROOF.md` defines twelve independent observations | Each claimed Secure Boot/TPM/BitLocker profile completes Windows → installer → Windows → JStack and cold-boots both OSes with a terminal journal | open |
| PH-14 | Graph-derived fault campaigns | Model and evidence schema define mutation classes and eight interruption phases | Every applicable mutation and failure edge is exercised with process termination plus ENOSPC, sharing, tamper, stale identity, firmware, reboot, finalizer, rollback, and recovery cases | open |
| PH-15 | Repetition and freshness | Fresh-run isolation is enforced by the harness | Ten fresh-overlay happy paths pass per supported OS and security-profile combination, a base is reconstructed, and all required campaigns rerun after relevant changes | open |
| PH-16 | Canonical evidence and support matrix | Strict evidence schema/verifier rejects malformed and self-selected trust roots | Every run and campaign has an immutable verified bundle and approved index; published support claims equal exact observed profile coverage | open |
| PH-17 | Runnable packaging and recovery UX | Core CLIs and deterministic fixtures exist | A pre-hardware installer CLI presents exact confirmation, runs only virtual/disposable capabilities, explains recovery states, and builds a deterministic signed test bundle | open |
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
