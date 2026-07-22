# JStack no-USB installer

This directory contains the cross-platform installer specification and, over
time, the Windows bootstrap, RAM installer, shared planner, and release tools.

The state graph is the source of truth. UI screens, journal records, runtime
commands, recovery behavior, documentation, and tests must refer to state,
transition, guard, action, and invariant IDs from the graph rather than invent
parallel workflows.

## Milestone 1 commands

The checks require Python 3.11 or newer, `python-jsonschema`, Python
`cryptography` for the independent Ed25519 known-answer vectors, and PowerShell
(`pwsh` or `powershell`) for collector AST validation and mocked execution.
Rust commands below are selected by `rust-toolchain.toml` and fail unless both
`rustc` and `cargo` are exactly 1.85.0. Command-line `CARGO=/path/to/cargo` and
`RUSTC=/path/to/rustc` overrides remain supported, but both selected tools must
still report exactly 1.85.0.

```sh
cd installer
make check
make docs
```

## Layout

- `model/installer-state-graph.json`: executable control-state model
- `model/schema.json`: structural schema for the model
- `model/trace-schema.json`: structural schema for executable traces
- `core/`: cross-platform Rust contracts, canonical signed-release verification,
  pure planner, integrity binding, and read-only Windows inventory and planning
  CLIs
- `staging/`: crash-safe acceptance WAL, resumable digest-addressed quarantine,
  durable staging evidence, and same-stream point-of-use verification
- `controller/`: verified typed state-graph loader, pure trace simulator, and
  graph-bound durable-journal replay core. It derives restart disposition at
  every journal phase, rejects non-adjacent or wrong-actor records, and binds
  success/failure advances to exact graph states. It contains no platform
  adapters and no reachable production mutation API.
- `traces/`: success, rejection, interruption, and rollback scenarios
- `tools/validate_state_graph.py`: structural and safety validator
- `tools/render_state_graph.py`: generated Mermaid and transition tables
- `tests/`: validator and trace tests

The architecture, safety contract, platform evidence, and milestone review live
under `docs/installer/`.

The planner design and current implementation boundary are documented in
`docs/installer/PLANNER.md`.

The Windows storage observation mapping and fail-closed attestation boundary are
documented in `docs/installer/WINDOWS_INVENTORY.md`.

The immutable trust policy, canonical Ed25519 message, anti-rollback ratchet,
closed artifact role set, and cross-OS revalidation boundary are documented in
`docs/installer/RELEASE_TRUST.md`.

The trusted staging root, crash protocol, point-of-use rule, and remaining VM
and TPM production gates are documented in `docs/installer/STAGING.md`.

The current proof boundary, platform-independent work, disposable VM campaign,
and physical-hardware gates are tracked in
`docs/installer/ASSURANCE_MATRIX.md`.

The end-to-end Windows acceptance criteria, evidence requirements, fault
campaign, and host real-drive interlock are defined in
`docs/installer/VM_PROOF.md`. The file-only QEMU/KVM harness lives in `vm/`.

## v1 scope

- Windows 10 or 11, x86-64
- UEFI boot with a GPT basic disk
- One Windows system disk
- NTFS Windows system volume
- Safe dual boot only
- Existing Windows ESP retained
- A new XBOOTLDR partition for JStack UKIs and the offline payload
- Btrfs JStack root partition
- Secure Boot only when the complete loader and UKI trust chain validates

Dynamic disks, Storage Spaces, firmware RAID, MBR/legacy BIOS, destructive
replace-disk installation, and ambiguous multi-disk layouts are rejected in
v1 rather than guessed.
