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
| Empty-password prompt/EOF rejection | Instrumented unit test | Empty newline and EOF both return nonzero before host preparation or wipe. Empty newline emits `password must not be empty`. Not exercised in the VM. |
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

## Full-install follow-up at `556b2a9` (2026-09-04 PDT)

The full public `install/vm/test-ubuntu.sh` workflow was attempted from
`556b2a91e43796a9eec5c76520308eba8896bee0`. It was **resource-blocked before
creating any artifact**. `df` reported 3.4 GiB available on `/home`; the real
command refused with status 1 and:

```text
[e2e] REFUSED: insufficient free space at /home/jeremy/.jcode/scratch: need 12 GiB, have 3 GiB
```

The alternate `arch-linux-desktop` host could not be inspected or used: the
non-interactive SSH connection timed out after 10 seconds. No host block device
was passed through. Existing proof images were not removed. In particular, the
older 8.1 GiB `jstack-ubuntu-e2e` directory and the three prior preflight proof
directories were preserved. A full run has previously consumed about 8 GiB, so
forcing it into 3.4 GiB would risk filling the host filesystem.

The harness now defaults to a unique work directory, rejects every existing
`WORK` path instead of deleting its qcow2 and seed contents, checks required
tools, and requires 12 GiB free before downloading or creating run artifacts.
`MIN_FREE_GIB` remains configurable for a deliberately provisioned environment.

### Remaining acceptance map

| Changed/public output | Evidence at `556b2a9` | Acceptance state |
|---|---|---|
| Full package preflight cache is consumed by real `pacstrap -c` | Source/unit linkage only; full VM stopped at disk-capacity guard | **Blocked, not accepted** |
| Working mirrors are propagated into the installed target | Unit ordering check passes; no target created in this attempt | **Blocked, not accepted** |
| Installed target boots under UEFI | Full VM could not start safely | **Blocked, not accepted** |
| Created user has passwordless sudo | Full VM could not start safely | **Blocked, not accepted** |
| Empty interactive password and EOF are refused before host preparation/wipe | `python -m unittest -v install.tests.test_install_safety` passes `test_empty_password_or_eof_prevents_host_prep_and_wipe` | Synthetic regression accepted; real VM prompt remains unobserved |
| Failure after destructive work prints recovery warning without disclosing secrets | Both post-destructive warning unit cases pass | Synthetic regression accepted; real destructive fault remains unobserved |
| Failed real package preflight leaves target byte-identical and prints no post-destruction warning | Prior real fault VM evidence and retained hashes/log above | Real fault-path accepted for the earlier installer hash; not a full success-path substitute |
| Full harness preserves prior run directories and refuses unsafe capacity | Direct guard execution returned status 1 before creating the requested unique work path; shell syntax check passes | Accepted for the harness guard |

Commands completed on this revision were `bash -n install/vm/test-ubuntu.sh
install/jstack-install.sh` and all six tests in
`install.tests.test_install_safety`. These checks do not turn the blocked full
install into acceptance.

The broader transactional installer crash-recovery architecture described under
`docs/installer/` remains unimplemented. Neither the earlier fault VM nor a
future legacy-installer happy-path boot proves that architecture or makes this
legacy destructive script transaction-safe.
