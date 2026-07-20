# Signed release trust contract

Milestone 4 adds the side-effect-free release verifier shared by the signed
Windows bootstrap and RAM installer. It authenticates planner requirements and
payload bytes before either platform may consume them. It does not download,
stage, promote, boot, or write an artifact.

## Immutable local policy

The release envelope cannot choose its verification algorithm, threshold, trust
roots, channel, architecture, installer protocol, or state-model identity. Those
values are compiled into each trusted bootstrap and installer build. The local
policy contains:

- a fixed Ed25519 key set and threshold;
- per-key channel authorization;
- the selected channel and `x86_64` architecture;
- the exact state-model ID and SHA-256 of its distributed bytes;
- the supported installer protocol version;
- maximum manifest lifetime and future-clock skew;
- manifest, artifact, chunk-size, and chunk-count resource limits; and
- the last durably accepted release sequence, body digest, issue time, and
  trusted time floor.

A key ID is SHA-256 over the raw 32-byte Ed25519 public key. Signature quorum is
counted by distinct locally trusted key IDs authorized for the selected channel.
Duplicate signature IDs are rejected. Unknown IDs are strictly encoded and
sorted but do not count. Ignoring rather than rejecting an unknown ID allows an
overlap release to carry signatures for both old and new bootstrap trust stores.
A new authenticated bootstrap is still required to add or remove roots. Metadata
alone cannot revoke a root embedded in an old bootstrap.

## Canonical signed body

The envelope is exactly:

```text
{"signed": ReleaseManifestBody, "signatures": [ManifestSignature, ...]}
```

The received UTF-8 bytes must equal the shared Rust canonical serializer output:
compact JSON, lexicographically sorted object keys, no insignificant whitespace,
no floating point, no unknown fields, and all integers at or below
`2^53 - 1` where the contract uses `u64`. Identifiers use a field-bounded lowercase
ASCII token grammar. Artifact and signature arrays are strictly sorted and
unique.

The Ed25519 message is:

```text
"JSTACK-RELEASE-MANIFEST-V1\0"
|| u64be(canonical_body_length)
|| canonical_json(release_body)
```

The release manifest digest is SHA-256 of that entire domain-separated message,
not of the envelope or a mirror response. This digest becomes
`ReleaseRequirements.release_manifest_hash`, the plan binding, the journal
binding, and the handoff binding.

The signed body binds product, release ID and version, globally monotonic release
sequence, channel, architecture, issue and expiry times, exact state-model ID and
digest, installer protocol range, every planner sizing input, and a closed v1
artifact role set. A manifest cannot supply a filesystem or firmware destination.
Platform adapters map roles to compiled destinations.

## Anti-rollback acceptance

For a new acquisition:

- a sequence below the durable floor is a downgrade;
- an equal sequence is accepted only for the identical body digest and issue
  time;
- an equal sequence with a different body is equivocation and hard-stops; and
- a different accepted body must have a strictly greater sequence.

The verifier returns `PendingReleaseManifest` plus the exact next
`ReleaseAcceptanceState`. Planner requirements and artifact verification remain
unavailable until the adapter atomically persists that state and supplies an
identical read-back to `accept_after_persist`. The staging crate implements this
as a locked append-only WAL with a canonical body checksum, separately flushed
commit marker, monotonic compare-and-swap check, and exact reopened read-back.
Production adapters must use that durable interface rather than inventing a
second acceptance format.

`Acquire` enforces expiry, maximum lifetime, future skew, and the persisted time
floor. `Resume` may use an expired manifest only when its digest, sequence, and
issue time exactly match both the persisted acceptance and the install's pinned
digest. This permits an already accepted offline installation to survive a
network outage or expiry without permitting a new expired release.

A recovery rollback is published as a new higher-sequence signed release. Release
sequence allocation is global within a channel.

## Artifact verification

V1 requires exactly these sorted roles:

1. `esp_loader`
2. `installer_uki`
3. `offline_system_image`
4. `recovery_uki`

Each descriptor binds an exact byte length, whole-file SHA-256, fixed logical
chunk size, and one SHA-256 per logical chunk. The chunk count must equal
`ceil(size / chunk_size)`. Verification is independent of operating-system read
boundaries and rejects truncation, trailing bytes, changed chunks, inconsistent
whole hashes, overflow, missing roles, extra roles, and duplicate roles.

`VerifiedArtifact` is produced only through an accepted manifest and carries the
manifest digest. The staging crate writes no-follow, reparse-safe quarantine
files, flushes complete logical chunks, verifies the complete file, promotes it
without clobber under its digest, and reverifies the exact byte stream at each
privileged copy or deployment use. Manifest data never selects a privileged
destination path. The complete protocol and trusted-root assumptions are in
`STAGING.md`.

## Cross-OS and boot-chain boundary

The Windows bootstrap and RAM installer call this same Rust verifier with the
same trust roots and compatibility bindings. The raw canonical signed manifest,
accepted digest, and acceptance state cross the handoff. Linux must independently
verify the manifest and rehash artifact bytes at the privileged point of use. A
hash copied from Windows is not sufficient evidence by itself.

The handoff also binds the canonical durable staging-evidence hash. That evidence
commits to the accepted manifest, canonical acceptance-state hash, and exact
promoted artifact set. Linux rejects a missing or different evidence hash and
still reopens and rehashes the artifact source.

Authenticode verification of the Windows bootstrap and Secure Boot verification
of the ESP loader and installer UKI are separate mandatory platform gates. Real
storage mutation and real boot transitions remain unreachable until those gates,
production adapter integration, and Windows/Linux VM fault injection are
implemented. No-follow staging and atomic acceptance persistence are covered by
the shared implementation and deterministic fault harness.

## Deterministic validation

`jstack-release-fixture` is the only fixture producer. It uses the shared Rust
canonicalizer and fixed test-only signing keys. `validate_release_vectors.py`
independently checks the raw canonical bytes, domain and length framing, Ed25519
known-answer signatures, manifest digest, acceptance binding, exact role set,
whole hashes, and logical chunk hashes using Python's independent cryptography
implementation. The fixed private seeds exist only in test fixture generation and
must never be production trust roots.
