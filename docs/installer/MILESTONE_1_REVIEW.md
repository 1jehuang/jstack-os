# Milestone 1 review

## Result

The installer workflow is now a versioned labeled transition system rather than
a UI flowchart. The checked-in graph is the source of truth for 52 states, 86
transitions, actor authority, guards, actions, terminal outcomes, and recovery
routes.

The standard check performs:

- Draft 2020-12 JSON Schema validation for the graph and every trace.
- Semantic identity, reference, reachability, and dominator checks.
- Actor-to-platform authority checks for every action.
- Confirmation and journaling checks for every mutation.
- Rollback identity checks for every rollback mutation.
- Proof that every mutation failure target can reach rollback or manual recovery.
- Replay of 15 checked-in traces covering all five terminal outcomes.
- Exhaustive abstract reconciliation at every documented power-loss phase for
  all 34 mutating transitions.
- Deterministic documentation regeneration.

## Independent review resolution

An independent read-only review generated adversarial model mutations rather
than accepting the passing suite. It found that failure edges were excluded from
success dominators, action risk labels could be weakened to bypass mutation
checks, handoff actors were not pinned, required first-boot security guards could
be removed, and several transitions bundled multiple destructive actions.

Those findings are resolved as follows:

- Dominators include normal and failure edges.
- Safety-critical action IDs have validator-pinned risk classes.
- Expected actors are pinned for every reboot handoff.
- Required BitLocker and first-boot gates have dedicated semantic checks.
- Every destructive transition contains exactly one mutating action.
- The old compound rollback is six named, independently journaled checkpoints.
- The review's counterexamples are permanent regression tests.
- Guard facts and actions both enforce actor-platform authority.

The hardened suite contains 21 unit tests. No observed independent-review
critical finding remains unresolved. Real Windows VM fault injection is still a
later milestone and is not implied by this result.

## Assumptions deliberately not hidden

- Production Authenticode, Secure Boot, and release signing infrastructure does
  not exist yet.
- A disposable Windows UEFI VM matrix is required before storage code is allowed
  to mutate a real Windows installation.
- Firmware behavior is not uniform. BootNext rearm is bounded and repeated
  failure must roll back rather than loop forever.
- The graph specifies observable preconditions and postconditions. Milestone 2
  must define their typed runtime representation and exact comparison rules.
- The graph permits dual boot only. Replace-disk installation is not an
  unimplemented branch; it is explicitly unreachable in v1.
- The current tests model interruption reconciliation. They do not yet kill real
  Windows or Linux VMs during storage operations.

## Milestone 2 interface decisions

The shared core must consume and emit immutable, canonically serialized objects:

1. `Inventory`: firmware, security, power, disk, partition, volume, and boot
   facts with stable identities.
2. `ReleaseManifest`: version, channel, expiry, graph compatibility, artifact
   hashes, sizes, signatures, and signing-key identifiers.
3. `InstallPlan`: source inventory hash, exact before/after layout, allocation
   interval, resource GUIDs, rollback objects, and plan hash.
4. `Confirmation`: plan hash, display digest, timestamp, and user authorization.
5. `JournalRecord`: sequence, previous-record hash, actor, transition, intent or
   commit type, precondition hash, postcondition hash, and signature or MAC.
6. `Handoff`: graph version, current state, journal head, manifest hash, plan
   hash, disk identity, intended boot target, and nonce.

Canonical serialization and hash rules must be identical on Windows and Linux.
The planner must be a pure function. Platform adapters may collect facts or
execute actions, but they may not make independent partition decisions.

## Exit decision

Milestone 1 is suitable to commit as the architecture baseline after the full
check passes and an independent reviewer has no unresolved critical finding.
It is not yet a usable installer and must not be presented as safe for a real
Windows disk.
