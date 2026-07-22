# Durable release staging

Milestone 5 implements the durable boundary between a verified release candidate and every privileged installer consumer. It does not enable partition, boot, or deployment adapters.

## Trusted root

The store root must already exist as an absolute directory. On Unix the root and managed child directories must be owned by the installer's effective UID and must not be group- or world-writable. Every ancestor must be owned by that UID or root and must not grant rename capability to other users; root-owned sticky directories such as `/tmp` are the only writable-ancestor exception. Every existing component is rejected if it is a symlink. Windows opens files with `FILE_FLAG_OPEN_REPARSE_POINT` and rejects reparse points. The production bootstrap must create the root on a local ACL-protected NTFS volume. Linux must use a local filesystem with durable file and directory synchronization. FAT, exFAT, network filesystems, reparse-rooted paths, and attacker-writable roots are unsupported.

The local administrator and kernel remain part of the trusted computing base. Protecting the anti-rollback floor from an already privileged local attacker requires a later TPM NV monotonic anchor. Until that exists, real mutation adapters remain unreachable.

## Acceptance write-ahead log

Each channel and state-model digest has one append-only log. A record contains a versioned magic value, big-endian canonical-body length and its bitwise inverse, canonical `ReleaseAcceptanceState`, SHA-256 checksum, and commit marker. The redundant header lets recovery distinguish a torn uncommitted header from committed header corruption without erasing the anti-rollback floor.

1. Lock the store.
2. Parse every committed record and enforce monotonic sequence, issue time, trusted time, channel, and state-model binding.
3. Require the current record to equal the verifier's expected previous acceptance.
4. Append body and checksum, then flush.
5. Append the commit marker, then flush again.
6. Reopen and parse the final log.
7. Unlock planner and artifact capabilities only when readback exactly equals the required acceptance.

An uncommitted torn tail is truncated to the last committed boundary. Any malformed committed record is a hard stop and is never deleted or reset automatically.

## Artifact quarantine and promotion

Quarantine and durable names are derived only from closed artifact roles and lowercase signed digests. Existing entries are opened no-follow and must be regular files.

Downloads resume only after complete logical chunks have been hashed and flushed. A partial or mismatched chunk is truncated to its start. After all chunks arrive, the same quarantine handle is rewound, checked for exact size, every chunk digest, whole digest, and EOF, then flushed. Promotion uses a no-clobber hard link into the digest store. An existing destination is accepted only after full verification. The promoted file and containing directory are synchronized where the platform exposes that primitive, then reopened and verified.

Staging evidence is canonical, content-addressed, and binds:

- accepted manifest digest
- canonical acceptance-state hash
- exactly four required artifact roles
- each role's size and digest

Evidence files and interrupted `.part` files are read through a fixed byte cap before JSON parsing or allocation. Oversized evidence fails closed.

Cross-OS handoffs bind the staging-evidence hash.

## VM-only destination transaction simulator

The staging crate now contains a Unix-host, regular-file-only transaction simulator. It derives a closed destination namespace from the confirmed plan, graph transition, partition GUID, and artifact placement. It accepts only the exact ordered `StagedArtifact` set required by that transition. For each artifact it copies from the retained staged file handle into an exclusively created non-selectable `.part` file, hashes the exact copied stream against signed chunk and whole-artifact digests, probes EOF on the same source handle, flushes and reopens the temporary, then verifies it again. A multi-artifact transition makes no final name reachable until every temporary verifies.

The simulator also persists a canonical, framed mutation journal under the private staging root. Each frame protects its bounded body length with an inverse-length field before the canonical body, SHA-256 digest, and commit marker, so header corruption cannot be mistaken for an uncommitted torn tail. An `action_intent` record is durable before artifact bytes are written. Final files are renamed only after every temporary verifies and are reopened and reverified before `action_committed` is appended. A `state_advanced` record is then appended with the exact target state declared by the executable graph. Torn uncommitted journal tails are truncated to the last committed frame; malformed committed frames are a hard stop. Retry either removes only the transaction-owned regular single-link outputs recorded by the pending intent, completes a missing state advance after revalidating an already committed destination set, or validates and returns an already completed three-record chain with identical commit evidence.

This is an A2/A3 contract test surface, not a production adapter. It runs only against private regular files beneath the staging root on Unix. It cannot receive a caller-selected destination root or a block/special device, and it returns `UnsupportedHost` at runtime on non-Unix systems. Its Windows target build proves only conditional compilation. It does **not** write FAT32 ESP/XBOOTLDR volumes, create or deploy Btrfs filesystems, call Windows storage APIs, modify firmware variables, or make any real-drive mutation reachable.

Before this design can back production mutation, Windows must implement and prove reparse-point and ACL checks plus durable directory/volume flushing such as `FlushFileBuffers`; FAT32 rename, case-folding, disk-full, and power-loss behavior must be observed in disposable VMs; Linux must use descriptor-relative no-follow traversal and prove destination filesystem synchronization; and both sides must integrate the proven three-phase journal contract with authenticated cross-OS replicas and the production graph controller.

## Point-of-use rule

A prior hash result is not authority to reopen and copy a path. `StagedArtifact` retains an open file and is not serializable or cloneable. The staging and core crates intentionally expose no generic `Write` copy API because such an API cannot enforce that bytes written before final verification remain uncommitted. Only the closed VM transaction simulator can currently consume the handle. No production platform adapter can consume staged bytes yet.

Every future XBOOTLDR copy, ESP placement, and Linux deployment adapter must hash the exact source stream while writing to an exclusively created temporary destination, flush it, and make it reachable from boot or deployment state only after verification succeeds. An error or crash must leave only a journal-reconcilable temporary object that cannot be selected as a boot or deployment target. These destination transactions and their power-loss tests are mandatory before real mutation paths become reachable.

## Crash reconciliation

Deterministic fault tests cover every boundary after acceptance lock, record write, record flush, commit write, commit flush, quarantine open, chunk write, chunk flush, full verification, promotion, promotion sync, cleanup, evidence write, evidence flush, and evidence promotion. The VM destination simulator additionally covers intent durability, each temporary verification, batch verification, each final rename, directory synchronization, commit append, state-advance append, replay before and after state advancement, multi-artifact retry, deterministic mid-stream ENOSPC, per-plan lock serialization, same-stream source tamper, committed-destination tamper, symlink, case collision, and hardlink rejection. Recovery yields one of three results: the old committed state, the new committed state, or a verified resumable prefix. It never treats an uncommitted record or unverified artifact as durable.

## Production gates still required

Before real mutation is enabled, Windows and Linux VM tests must inject power loss, disk-full, sharing violations, and post-verification tampering against the production adapters and filesystem choices. Windows must prove local NTFS and trusted ACL setup. Linux must prove directory-sync semantics. TPM-backed rollback protection is a separate hardening milestone.
