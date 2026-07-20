# Shared installer core

This Rust crate is the side-effect-free implementation shared by the future
Windows bootstrap and RAM installer. It parses versioned contracts, rejects
unsupported inventories, computes the only permitted v1 dual-boot plan, and
binds plans, confirmations, journal records, and handoffs with canonical hashes.
It never opens or writes a disk.

## Commands

```sh
cd installer/core
make check
cargo run --offline --bin jstack-plan -- \
  fixtures/windows-11-basic-gpt.json fixtures/release-requirements.json
cargo run --offline --bin jstack-plan -- --display \
  fixtures/windows-11-basic-gpt.json fixtures/release-requirements.json
```

`make check` runs Rust formatting, unit and generated-boundary tests, strict
Clippy, an `x86_64-pc-windows-msvc` compile check, deterministic fixture
regeneration, and Draft 2020-12 schema validation.

## Canonical JSON v1

Hash-bound installer values use compact UTF-8 JSON with lexicographically sorted
object keys, no insignificant whitespace, and integers only. Floating-point
values are rejected. Both supported platforms run this same Rust crate, avoiding
cross-language number and escaping differences. SHA-256 is lowercase hex.

## Safety rules implemented now

- One system disk, one ESP, and one Windows NTFS partition are required.
- Disk partitions must be non-overlapping, sector aligned, in bounds, and have
  unique GUIDs.
- Windows resize bounds must include the current size.
- Secure Boot, servicing, power, storage health, UEFI variables, and BitLocker
  readiness must pass.
- The ESP must be FAT32 with enough measured free capacity for the signed loader.
- The planner uses only the interval newly released by shrinking Windows.
- XBOOTLDR and Btrfs root are aligned and deterministic UUIDv8 identifiers are
  derived from inventory and release hashes.
- Existing Windows partition offsets, types, GUIDs, MSR, recovery partitions,
  and unrelated partitions are preserved exactly.
- Four reconstructable GPT fingerprints cover the source, post-shrink,
  Windows-to-Linux handoff, and fully installed layouts.
- Planned rollback objects are install-instance allowlist entries, never disk
  numbers or drive letters. The deletion set contains only actual identities
  recorded by committed journal actions.
- User confirmation is bound to both the plan hash and exact displayed report.
- Journal records enforce intent, commit, and state-advance ordering. Cross-OS
  handoff requires a fully validated chain ending in a state hash that matches
  the handoff control state.

See `docs/installer/PLANNER.md` for the algorithm and remaining validation work.
