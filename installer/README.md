# JStack no-USB installer

This directory contains the cross-platform installer specification and, over
time, the Windows bootstrap, RAM installer, shared planner, and release tools.

The state graph is the source of truth. UI screens, journal records, runtime
commands, recovery behavior, documentation, and tests must refer to state,
transition, guard, action, and invariant IDs from the graph rather than invent
parallel workflows.

## Milestone 1 commands

The checks require Python 3.11 or newer and `python-jsonschema`.

```sh
cd installer
make check
make docs
```

## Layout

- `model/installer-state-graph.json`: executable control-state model
- `model/schema.json`: structural schema for the model
- `model/trace-schema.json`: structural schema for executable traces
- `core/`: cross-platform Rust contracts, pure planner, integrity binding, and
  read-only Windows inventory and planning CLIs
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
