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

Integration of the transactional controller and crash-recovery machinery described under
`docs/installer/` into this legacy shell path remains unimplemented. Neither the earlier fault VM nor a
future legacy-installer happy-path boot proves that architecture or makes this
legacy destructive script transaction-safe.

Independent review directly invoked the public full-VM script for three guard
cases: an existing `WORK`, insufficient free space, and invalid `MIN_FREE_GIB`.
All returned status 1 with the corresponding refusal. A sentinel named
`target.qcow2` in the existing directory remained byte-identical, and neither
new requested work directory was created. These are real public harness checks,
not evidence that installation or boot succeeded.

## Successful full install and boot follow-up

After safely reclaiming unrelated, regenerable compiler incremental cache, the
public harness completed twice on 2026-09-04 PDT with `MEM=3072 CPUS=2`. The
first run's logs were hash-preserved under
`~/.jcode/scratch/jstack-full-556b2a9-success-20260904T172640-logs` before only
that run's newly generated VM images were removed to make room for the enhanced
rerun. The final, retained run is
`~/.jcode/scratch/jstack-full-mirror-acceptance-20260904T173335`. It used no
host block device and exited 0 after 524.4 seconds. The public installer
SHA-256 was
`54b289dd4db17e09f18ffe25864d6c3bc14c13de8414dd3f4b08bd0b6a1992ee`.

The final serial log observed package preflight followed by real `pacstrap` and
`E2E: INSTALL_OK`. The newly installed qcow2 then booted under OVMF, directly
observed 11 `Server =` entries in the target's `/etc/pacman.d/mirrorlist`, and
emitted `E2E-BOOT: DONE`. All 21 harness assertions passed. Retained artifact
hashes are:

```text
41edaa1dde6edd7dabc7778b5c7a440f4483a72a317dd6fc005f1a0c98db4e86  phase1.log
160bd451195074f648d469f4248451bdd9062bc4558d2a93eb52a16437d865d8  phase2.log
261e8afd656eb5a26da78f801b4896bb48785e2157d734182a582035897f9b5e  target.qcow2
```

### Final requirement-to-evidence map

| Requirement | Direct observation | State |
|---|---|---|
| Full preflight cache feeds `pacstrap -c` | One unmodified installer invocation logged successful package preflight followed by real `pacstrap` and installation completion | **Real success path accepted** |
| Working mirrors propagate into the target | First boot directly counted 11 enabled server lines in the installed target mirrorlist and the harness asserted a nonzero count | **Real boot accepted** |
| Installed target boots | The newly created target booted under OVMF and reached `E2E-BOOT: DONE` | **Real boot accepted** |
| Passwordless sudo | Boot output was `E2E-BOOT: sudo_nopasswd=yes` | **Real boot accepted** |
| Stable storage and desktop policy | Boot output confirmed btrfs `@`, `@home`, `@log`, `@pkg`, UUID fstab, fallback loader entry, all policy packages, desktop commands, and enabled services | **Real boot accepted** |
| Empty password and EOF refusal | The unmodified CLI was fed an empty newline and EOF in a real Ubuntu VM; both failed before the preflight marker | **Real VM guard accepted** |
| Post-destructive failure warning | After a real successful preflight, a 256 MiB target forced partitioning failure; the warning appeared and the supplied secret did not | **Real VM fault accepted** |
| Preflight failure leaves the target unchanged | Earlier fault VM compared whole-device SHA-256 before/after | **Real fault path accepted** |
| Existing work and low disk are refused | Public harness guard invocations and byte-identical sentinel | **Real guard path accepted** |

The bounded fault run is retained at
`~/.jcode/scratch/jstack-preflight-prompts-warning-20260904T174300`. Its public
installer hash matched the full run. Before and after the deliberate package
preflight outage, the whole target SHA-256 was identically
`a6d72ac7690f53be6ae46ba88506bd97302a093f7108472bd9efc3cefda06484`.
It then restored the cache and exercised the real post-destructive warning.
The serial log SHA-256 is
`642cacf2792c05b7e34845214578a6adca0f0f7378289df3e790adca056df697`.

This successful legacy happy path closes package-cache-to-`pacstrap`, install,
UEFI boot, mirror propagation, first-boot policy, prompt refusal, and bounded
post-destructive warning acceptance. It does **not** implement or prove the
transactional controller/crash-recovery architecture. The warning advises
manual recovery; it is not automatic interruption recovery.
