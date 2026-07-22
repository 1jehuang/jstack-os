# Canonical VM run evidence

This directory defines the machine-checkable bundle contract for Windows/JStack VM installer runs. `schema.json` is the strict Draft 2020-12 structural schema. `verify.py` is the authoritative fail-closed verifier for canonical bytes, local artifacts, Ed25519 release trust, and cross-record invariants that JSON Schema cannot express. Ed25519 verification uses Python `cryptography` and fails closed if it is unavailable.

## Bundle and canonical serialization

A bundle is a directory containing `evidence.json` and regular files below `artifacts/`. The manifest is canonical only when its bytes are exactly:

```python
json.dumps(value, ensure_ascii=False, allow_nan=False,
           separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
```

Object keys must be unique. Floating-point and non-finite numbers, a BOM, invalid UTF-8, alternate whitespace or key order, and trailing bytes are forbidden. All objects use exact field sets. IDs, UUIDs, and SHA-256 values use canonical lowercase forms. Timestamps are real, second-precision RFC 3339 UTC values.

Artifact paths are byte-normalized POSIX paths rooted at `artifacts/`. Absolute paths, `.`, `..`, duplicate separators, backslashes, symlinked bundle or artifact components, hard links, special files, missing files, and bundle escape are rejected. Every artifact has a unique logical ID, role, path, and content digest. The verifier checks actual size and SHA-256 before accepting semantic claims. Limits are 2 MiB for `evidence.json`, 64 MiB per non-ISO artifact, 8 GiB for the Windows ISO, 256 MiB aggregate excluding the ISO, and 10,000 records per collection.

Run:

```sh
python installer/vm/evidence/verify.py /path/to/bundle \
  --trusted-release-policy-sha256 "$POLICY_SHA256" \
  --trusted-profile-sha256 "$RESOLVED_PROFILE_SHA256" \
  --trusted-media-sha256 "$OFFICIAL_MEDIA_SHA256" \
  --trusted-campaign-index-sha256 "$CAMPAIGN_INDEX_SHA256"
```

## Immutable profiles and identity

The supported profile list is immutable in `verify.py` and `schema.json` and mirrors the approved VM support-profile scenario matrices: four Windows 10 Pro 22H2 scenarios and three Windows 11 Enterprise Evaluation 25H2 scenarios. Each record binds the support-profile ID, scenario ID, edition, release, UEFI/GPT requirement, Secure Boot state, TPM state, and BitLocker state. A bundle must contain all seven records in canonical order and may not redefine one.

Content identity propagates eleven digests through the root, evidence journal, and boot witnesses: the raw state graph, canonical signed release message, durable release acceptance, staging evidence, canonical plan hash, disk identity, release policy, resolved profile, official media record, durable journal, and handoff. The release-policy, resolved-profile, official-media, and campaign-index artifact digests must also match independently supplied trust roots. They cannot be selected by the bundle itself. The verifier parses those artifacts rather than trusting their role labels. It verifies the externally anchored release-policy threshold against distinct trusted Ed25519 keys, binds the signed release to the exact graph ID and bytes, and then binds acceptance, staging, plan confirmation, durable journal, handoff, resolved profile, media, and ISO into one chain. Plan, display, confirmation, journal, and handoff objects are validated against the authoritative checked-in core schemas. The displayed plan digest is recomputed, core journal records must repeat complete intent, commit, and state-advance phases owned by graph actors and states, and handoff control state, boot target, partition fingerprint, and journal head must match the runtime handoff point. VM identity separately binds a canonical VM ID, machine/SMBIOS UUID, and disk serial.

## Platform, disk, and boot evidence

Initial and final snapshots contain independently hashed observations for:

- UEFI, Secure Boot, and firmware setup mode;
- TPM presence, version, and readiness;
- BitLocker enablement, protection, and recovery-key confirmation;
- disk serial, size, sector size, and GPT partitioning;
- primary and backup GPT validity plus concrete partition GUIDs; and
- FAT32 ESP contents, including Windows and JStack EFI loader presence.

For completed and recovered-forward outcomes, the final GPT must preserve every initial partition and add a deployment partition, and a valid final JStack loader must coexist with the Windows loader. `terminal.rolled_back` is distinct: its final firmware, TPM, BitLocker, disk, GPT, and ESP observations must restore the initial semantic state exactly, with no added JStack partition or loader. Snapshot artifacts must remain distinct even when their restored semantic values match.

The VM journal has unique IDs and transitions, contiguous sequences from zero, strictly increasing timestamps, canonical observations for each state, and one feasible state-machine path. Completed runs must follow the full happy path. Recovery runs must enter recovery once from a feasible prefix and end at the outcome claimed by `run.final_outcome`; rollback ends at `terminal.rolled_back`, never the generic recovered-forward outcome.

Successful runs require five ordered, distinct, concrete boot witnesses: Windows before installation, Windows after deployment, JStack first boot, a later cold Windows boot, and a later cold JStack boot. Ordering is also bound to journal and observation boundaries: pre-install must follow the initial snapshot and precede `mutation.started`; post-deploy must follow the final mutation observation; JStack first boot must follow `handoff.committed`; both cold boots must follow `terminal.completed`. Each witness binds a unique boot ID, boot-volume UUID, expected EFI loader path, VM/content identity, timestamp, and dedicated hashed artifact. Evidence artifacts and boot IDs may not be reused.

## Faults and campaign coverage

An injected fault record is all-or-nothing. It includes the mandatory class, trigger, exact interruption boundary, graph-derived production mutation transition, canonical checkpoint, a distinct hashed serial or guest boundary observation, process exit cause, recovery outcome, and distinct hashed recovery logs. Its recovery outcome must agree with the run journal and final outcome. The current injected run must appear exactly once in matching mandatory-fault campaign coverage.

Campaign input identity is one canonical digest over runtime, adapters, graph, release policy, boot artifacts, VM harness, and evidence verifier hashes. Every campaign run must use that digest. Coverage requires, for every immutable profile:

- at least ten distinct passing fresh-overlay happy-path runs;
- every production transition whose referenced action has a `staging_mutation`, `filesystem_mutation`, `security_mutation`, `disk_mutation`, `boot_mutation`, or `reboot` risk in the parsed state model, in exact graph order, at all eight interruption boundaries with abrupt QEMU termination;
- every immutable modeled failure edge;
- every mandatory fault class, including rollback request and interruption at all post-mutation checkpoints; and
- a distinct passing fresh base-image reconstruction.

Every campaign row carries a unique content address for a complete canonical per-run bundle embedded in the independently trusted campaign index. Each bundle repeats the run and input identity, pins the evidence verifier and checked-in trace schema, and contains a trace that is schema-validated and simulated against the signed graph. Interruption and failure-edge rows must actually execute the claimed interrupted transition or concrete failure edge. Rollback bundles additionally bind equal initial/restored state digests, restored Windows security, and an empty retained-JStack-object set. The verifier hashes the actual canonical bundle bytes and compares that digest with the row, so formatted digests, row-local `passed` flags, or an externally trusted index containing mismatched bundle identities cannot certify coverage.

Coverage arrays are exact sets rather than counters. Missing or extra products, self-declared mutation gaps, unknown profiles, duplicate logical keys, deterministic failures, stale inputs, and reuse of a run ID across any campaign section invalidate the bundle. A dashboard may summarize a verified bundle but is never evidence itself.
