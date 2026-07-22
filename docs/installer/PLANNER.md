# Shared partition planner

## Role

The planner is a pure function:

```text
Inventory × VerifiedReleaseManifest.verified_release_requirements() → InstallPlan | PlanError
```

It has no platform APIs and cannot mutate storage. Windows and the RAM installer
consume the same Rust library, contract schemas, canonical serializer, and hash
rules. Platform adapters collect inventory and execute graph actions, but they
cannot independently choose offsets, sizes, GUIDs, or rollback targets.
`ReleaseRequirements` is available to a platform adapter only after the shared
release verifier has validated the canonical Ed25519 quorum, compatibility
bindings, time policy, and anti-rollback ratchet, and the exact acceptance state
has been atomically persisted and read back.

## Planning algorithm

1. Validate schema versions and all v1 readiness facts. Require planner inputs
   derived from the already accepted signed manifest.
2. Validate one basic GPT system disk, one FAT32 ESP, one NTFS Windows partition,
   stable GUID uniqueness, sector alignment, bounds, and non-overlap.
3. Confirm BitLocker recovery material when protection is active and reject an
   untrusted Secure Boot chain, pending servicing reboot, unhealthy storage, or
   unsafe power.
4. Validate release alignment against both logical and physical sector sizes and
   verify measured ESP free capacity for the namespaced signed loader.
5. Compute the required allocation as the greater of the release minimum and
   `XBOOTLDR + minimum root + safety margin`.
6. Select a Windows target size inside the Windows-supported shrink range and
   align it down. The allocation interval is exactly the tail removed from the
   existing Windows partition. Pre-existing free space is not silently adopted.
7. Place one aligned XBOOTLDR at the interval start, one aligned Btrfs root after
   it, and retain the safety margin at the interval end.
8. Hash a reconstructable GPT-only projection containing disk geometry and each
   partition's GUID, type GUID, offset, and size. Transient names, filesystem
   metadata, and volume IDs are deliberately excluded.
9. Derive deterministic RFC 9562 UUIDv8 install and partition identifiers from
   the source GPT fingerprint, release hash, disk GUID, state model, and role.
10. Produce exact before and after layouts. Every original partition retains its
   GUID, type, offset, filesystem identity, and size except the explicitly
   resized Windows partition.
11. Compute four expected GPT fingerprints: source, Windows-reserved, Windows
    handoff with XBOOTLDR, and fully installed with root. A receiver recomputes
    the current fingerprint and must match the handoff's explicit phase.
12. Record a plan-bound allowlist for both created partition GUIDs, an
    install-instance ESP path, and an install-instance Windows finalizer task.
    Firmware Boot#### IDs cannot be predicted and enter the rollback set only
    when an `action_committed` journal record names the actual created ID.
13. Canonically hash the plan body. Confirmation separately hashes the exact
    display report shown to the user.

## Integrity objects

- `source_inventory_hash` binds all collected facts, including readiness and ESP
  capacity.
- `partition_fingerprints` binds the exact expected GPT projection at each
  mutation phase. These values are reconstructable from fresh inventory.
- `plan_hash` binds every offset, size, GUID, filesystem, and rollback object.
- `Confirmation` accepts only the canonical `PlanDisplay` projection of that
  plan, then binds its exact digest. A display carrying the right plan hash but
  altered sizes is rejected.
- `JournalRecord` binds sequence, previous-record hash, transition, actor,
  precondition, postcondition, and plan. Validation also enforces the phase
  grammar `intent → (committed | failed) → state advanced`, plus hash-contiguous
  direct state advances for non-mutating transitions. It keeps each transition's
  actor and identity stable through its outcome. Failure records bind strict
  canonical `FailureEvidence`, including an independently recomputable
  no-committed-effect proof and any residual rollback objects.
- `journaled_rollback_objects` returns only identities durably recorded by
  committed actions or proven failure residuals, checked against the plan
  allowlist. Rollback must never delete every prospective plan object blindly.
- `Handoff` requires the complete journal chain to end in `state_advanced`, binds
  `control_state` to that record's postcondition hash, and binds graph state,
  journal head, release, plan, disk, fingerprint phase, intended target, and
  nonce. Generic core handoff rejects graph-unvalidated direct state advances.

## Current validation

- Rust tests including 86 generated shrink-boundary cases, adversarial release
  verification, and adversarial Windows snapshot normalization.
  Windows snapshot normalization.
- Strict Clippy with warnings denied.
- Linux tests and Windows MSVC compile checking.
- Draft 2020-12 schemas and validated contract documents, including the canonical
  signed release and durable acceptance state.
- Deterministic generated plan, user display, confirmation, full journal chain,
  handoff, and observed-inventory fixtures.
- Exact read-only PowerShell command allowlisting plus an end-to-end mocked
  Windows collection and Rust normalization run.
- Deterministic Rust release fixtures plus independent Python Ed25519, framing,
  acceptance, whole-file, and logical-chunk known-answer vectors.

## Not implemented yet

- Windows storage mutation execution and readiness-evidence merging.
- Signatures or MACs over journals, confirmations, and handoffs.
- Production trust-root provisioning, atomic platform persistence, no-follow
  staging, and release publishing infrastructure.
- Linux execution adapters or real VM power-loss injection.
- Upgrade, reinstall, multi-disk, or replace-disk planning.

Those remain unreachable platform capabilities, not silent fallbacks.
