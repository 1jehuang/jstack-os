# Legacy installer preflight VM evidence

`install/vm/test-preflight-no-write.sh` is the acceptance test for the preflight
no-write guarantee introduced by `ef50773`. It runs the public
`install/jstack-install.sh` byte-for-byte, inside an Ubuntu QEMU/KVM guest, and
attaches only a new 256 MiB qcow2 target. The Ubuntu disk is a fresh overlay and
the configured backing image is opened read-only by libguestfs when extracting
cached bootstrap assets.

Run it with:

```sh
UBUNTU_BACKING=$HOME/.jcode/scratch/jstack-ubuntu-e2e/ubuntu.qcow2 \
  install/vm/test-preflight-no-write.sh
```

The backing image must contain the previously downloaded Arch bootstrap at
`/tmp/jstack-bootstrap`. The test restores its genuine synchronized repository
databases, serves those databases and the keyring package from a guest-local
HTTP endpoint, then returns HTTP 503 for base-package payloads. This lets
`host_prep` finish and makes the real `pacman -Syw` in `package_preflight` fail.
The test requires the preflight log marker, a real pacman retrieval error, no
post-destruction warning, and equal SHA-256 hashes of the entire target block
device before and after all invocations.

## Requirement-to-check matrix

| Requirement | Evidence type | Status and observation |
|---|---|---|
| Run the public installer without test instrumentation | Real VM | Observed. The host SHA-256 is compared with the copy printed by the guest before execution. |
| Exercise `package_preflight`, not only `host_prep` | Real VM | Observed. Real repo DBs and the keyring payload are served successfully first. The test then requires `Preflight: downloading base system before modifying the target` before accepting deliberate base-package HTTP 503 responses. |
| A failed package preflight cannot modify the target | Real VM | Observed. SHA-256 of all 256 MiB of `/dev/vdb` is captured before and after and must match. |
| Failure before destruction must not claim the disk was modified | Real VM | Observed. `INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED` must be absent. |
| Invalid username, hostname, timezone, and missing seed are rejected | Real VM | Observed. Each unmodified CLI invocation must return nonzero and emits a `guard-*=PASS` marker. |
| Empty-password prompt/EOF rejection | None | Not exercised by this harness. |
| Mirror propagation into the target | Static unit test | Covered by `test_working_mirrorlist_is_installed_after_pacstrap`, but not observed in this fault VM because partitioning never begins. |
| Preflight cache reuse by `pacstrap -c` | Static unit test | Command/config linkage is checked, but a successful preflight followed by real `pacstrap` is not exercised here. |
| Post-destructive recovery warning | Instrumented unit test | Message and secret non-disclosure are checked synthetically. This preflight fault correctly never reaches that state. |
| Do not mutate existing VM artifacts or host disks | Harness construction | Ubuntu uses a new qcow2 overlay; the target is newly created. The harness refuses an existing `WORK` path and QEMU receives no host block device. |
| Bound resource use | Harness construction | Defaults are 3 GiB RAM, two vCPUs, a 256 MiB target, and a 900-second timeout. |

## Observed run for `ef50773`

On 2026-09-04 PDT the final test completed in 41.2 seconds. The first real-VM
attempt exposed that pacman's configured `alpm` download user
could not write the root-owned `mktemp` database. The follow-up fix assigns the
temporary database to pacman's configured download user; its validated installer SHA-256 was
`54b289dd4db17e09f18ffe25864d6c3bc14c13de8414dd3f4b08bd0b6a1992ee`.
The before and after target SHA-256 values were both
`a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484`.
All four argument guards passed, pacman returned nonzero during the marked
preflight, and the test emitted `PREFLIGHT-E2E: RESULT=PASS`.

## Explicit limitations

This bounded fault test does not perform partitioning or a full installation.
It does not prove the success path from a fully populated package cache into
`pacstrap`, nor the interactive cancellation prompt after a successful
preflight. Those paths would require downloading the full base package set and
a realistically sized target, which was intentionally not attempted with only
about 7 GiB free. Existing unit coverage checks command ordering and the
post-destructive warning, while `install/vm/test-ubuntu.sh` remains the larger
full-install harness.

The successful serial log used for this evidence was
`~/.jcode/scratch/jstack-preflight-vm-downloaduser/serial.log`. This is a local
review artifact, not a checked-in or permanently retained test fixture.
