# Milestone 2 review

## Result

The shared installer core now provides a side-effect-free Rust planner, strict
versioned contracts, deterministic canonical hashing, exact user confirmation,
append-only journal validation, and cross-OS handoff binding. It compiles for
Linux and `x86_64-pc-windows-msvc` but contains no storage execution APIs.

## Independent review resolution

A read-only review found four commit-blocking issues:

1. The handoff carried only the pre-mutation partition fingerprint, which could
   never match the valid post-shrink and post-XBOOTLDR disk.
2. A handoff could be created from an isolated intent or action-commit record
   before durable state advancement.
3. Prospective ESP, boot-entry, and finalizer descriptors could be mistaken for
   resources actually created by this installation and deleted during rollback.
4. The journal JSON Schema accepted postcondition nullability combinations that
   the Rust runtime rejected.

All four are resolved and covered by regression checks:

- The plan carries source, Windows-reserved, Windows-handoff, and installed GPT
  fingerprints. The projection uses only reconstructable disk and GPT fields.
- Handoff creation and validation consume the complete journal chain, require a
  `state_advanced` head, and bind its postcondition to the exact control state.
- The plan has a deterministic install ID. ESP paths and finalizer tasks are
  namespaced by it. Actual UEFI Boot#### IDs are accepted only from committed
  boot-creation transitions. `journaled_rollback_objects` derives the deletion
  set exclusively from committed, allowlisted identities.
- Conditional Draft 2020-12 rules now match runtime intent, commit, and
  state-advance shapes. Negative schema counterexamples run on every check.
- A deceptive confirmation display with the correct plan hash but altered sizes
  is also rejected by exact projection comparison.

The independent geometry pass found no separate arithmetic, alignment, bounds,
or partition-preservation escape.

## Validation boundary

Milestone 2 does not make this safe to run on a real Windows disk. Signatures,
Windows Storage API adapters, Linux execution adapters, and disposable UEFI VM
power-loss testing remain mandatory before any real mutation path is enabled.
