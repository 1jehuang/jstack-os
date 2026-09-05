# Ubuntu recovery contract

This is the acceptance contract for the graph-controlled Ubuntu whole-disk
installer. It is not evidence that the implementation has passed these checks.
The implementation and its final frozen-tree evidence must identify each row.

## Supported recovery boundary

A supported install preserves an independently bootable Ubuntu host on a
separate persistent disk. The complete offline installation image, executable,
pinned graph, exact confirmed plan, and durable journal remain on that host.
The target is a different, uniquely identifiable whole disk. Target replacement
is intentionally destructive and does not promise restoration of its old OS.

The currently authorized hardware envelope is UEFI with Secure Boot observably
disabled and a target with 512-byte logical sectors. Missing, unreadable,
ambiguous, or enabled Secure Boot state and every other logical sector size are
pre-write refusals. The local artifact boot chain is not signed.

A RAM-only environment on the disk being erased is not a recovery environment.
Same-disk conversion without retained durable bootable recovery, volatile state,
ambiguous storage ancestry, and unsupported partition-only installation must be
refused before target mutation. A future implementation supporting those cases
needs its own explicit contract and real interruption tests.

## Image trust and graph enforcement

The Ubuntu graph's `release_policy` authorization means an explicitly approved
local image policy, not a vendor-signed release claim. The adapter must verify a
protected, root-controlled, regular single-link source, its complete digest
manifest, and approval of that exact image in the displayed plan. Downloaded
inputs and locally built packages do not acquire a release signature merely
because the final image is hashed. The operator trusts the local build inputs.

Loading the pinned graph alone does not authorize an effect. Execution must
select a transition from the replayed durable state, satisfy every known guard,
authorization and precondition using actual observations, execute only the
ordered graph actions, and satisfy postconditions before publishing the graph's
destination. Missing, false or unimplemented observations fail closed. A
mutating action also requires observed durable intent before its effect.

## Required properties and observations

| ID | Required property | Acceptance observation |
|---|---|---|
| UR-01 | The default public entrypoint cannot bypass the Ubuntu controller. An internal image builder cannot receive a physical target. | Public CLI unsupported/legacy-bypass cases fail without target writes. Builder accepts only an exclusively created regular image and its own loop mapping. |
| UR-02 | Ubuntu uses an explicit pinned executable graph without weakening Windows graph identity or virtual-only runtime gates. | Model confusion, altered digest, missing failure/journal edges, wrong actor, and illegal transitions are rejected. Existing Windows gates continue to pass. |
| UR-03 | All network-dependent package and source builds finish before target writes. | A complete bootable image is staged first. Disconnect networking during deployment and resume, and still complete installation. Source/build failure leaves the target unchanged. |
| UR-04 | Durable plan and confirmation bind graph identity, exact artifact and chunk digest manifest, target hardware identity/geometry, and recovery storage identity. | Tampering or substituting any bound object causes refusal with no new target writes. No credential is persisted in plan or journal. |
| UR-05 | Recovery storage and boot remain separate from the target and survive a cold reboot. | Mounted/swap/root/ESP/state/artifact ancestry overlap is refused. Cold boot reaches the preserved host with executable and state available without the source checkout. |
| UR-06 | Device identity is stable across enumeration changes, but not guessed when serial/WWN is missing or ambiguous. | Renumber the same device and resume safely. Substitute a different same-size device or duplicate its identity and refuse. Mount IDs and transient sysfs paths are observations, not durable identity. |
| UR-07 | Only one deployment writer can own a target and its transaction. | Concurrent deploy/resume attempts, including different path aliases, cannot interleave target writes. |
| UR-08 | Artifact promotion and journal updates use durable, authenticated-by-integrity publication under protected directories. | Torn-tail, stale-plan, symlink/hardlink, corruption, and interrupted publication cases either recover the last valid prefix or stop without target writes. |
| UR-09 | Each graph-authorized chunk has durable intent before effect, fixed range/digest, flushed target write, independent readback, and durable commit afterward. | Interrupt before intent, after intent, during write, after effect, after commit, and before state advance. The journal and independently inspected target agree. |
| UR-10 | Resume reconciles only the confirmed transaction, not a fresh format or blind restart of the shell installer. | Cold resume validates committed chunks and either admits a matching pending write or rewrites only its authorized range. Corrupt committed data and refuse rather than silently overwrite it. |
| UR-11 | Completion requires independent whole-target verification and graph completion. A completed transaction never repairs later OS changes automatically. | Fresh target boots under UEFI with expected policy. Repeating resume after completion performs no target writes. No pending or failed state is reported as completed. |
| UR-12 | Boot activation cannot make the preserved host unavailable during partial deployment. | Forced power loss retains host bootability. Neither artifact construction nor deployment alters host firmware variables or its ESP. |
| UR-13 | Recovery UX states what to boot and run, and distinguishes explicit resume from automatic resume. | A new process after cold boot executes the supported recovery path without network or secrets from the original shell. If a resume service is provided, it is installed durably before target writes and removed safely after completion. |
| UR-14 | Every supported behavior is checked on the final source tree, not inferred from model tests alone. | Fresh real Ubuntu install/boot plus graph-derived interruption campaign; observed host, target, artifact, journal, and boot evidence must agree. |

## Non-claims

A passing VM campaign does not establish arbitrary physical firmware behavior,
lying storage hardware, recovery from loss of both host and target disks, or
immunity to every possible failure. The required outcome of an unsupported or
unreconcilable state is explicit refusal or manual recovery, never invented
success or unconfirmed writes. Hashes detect corruption but are not a defense
against a privileged attacker rewriting the running installer and all evidence.
