# Ubuntu recovery acceptance report

Date: 2026-09-05

This report separates compatibility evidence from final-tree acceptance. It does
not claim UR-01 through UR-14 complete. Paths below are preserved disposable VM
artifacts, not physical disks.

## Compatibility recovery checkpoint

Workspace: `/home/jeremy/.jcode/scratch/jstack-ubuntu-transactional-full-1788587409`

This transaction used the earlier 4 MiB plan
`775cd38a8ec492703bfea5bdd3502e4690e3f6618435a014a9eb5c3bc612792a`.
New plans use 64 MiB chunks. This run does not override that new default.

- Retained controller SHA-256: `c7842ef83a87e9fe737e3e64857c5ab6280c9b8cb6534b02215ea88d17d9ed2c`.
- The last captured pre-resume serial line was `READBACK_OK` for seq 6062,
  but that was not the actual durable stop boundary. On the next cold replay,
  the first controller record was `READBACK_OK` for seq 6094 without a new
  intent. The durable journal had therefore reached a dangling intent/effect at
  seq 6094, offset 25,560,088,576. The serial capture had stopped earlier than
  the VM writes. This report uses the replayed journal observation, not the
  intended or last serial marker.
- The preserved Ubuntu recovery host cold-booted with `-nic none`. Its seed
  removed `/root/jstack-os`, then invoked only the retained executable and exact
  plan. It reconciled seq 6094 and completed through seq 6143, independently
  verified the whole 24 GiB target, emitted exactly one
  `JSTK_UBUNTU_COMPLETE plan=775cd...`, returned rc 0, and powered off.
- Resume emitted 49 new intents and 50 readback, commit, and advance records.
  The extra readback/commit/advance is the reconciled dangling seq 6094.
- Resume log SHA-256:
  `28bdfe2e2feeefdc7b14b03e47766ccdda52f673889e02b51d518ecbdec7faa6`.
  Preserved prior serial SHA-256:
  `76a9e2dc5b95d155d7bb9675a072c42bd3692e79d5f3d4bf47cf71a1807bf37c`.
- Both host and target passed `qemu-img check` after completion.

The completed target then booted as the only disk under OVMF UEFI with networking
disconnected. The unmodified `install/vm/test-ubuntu.sh` policy probe emitted 25
`E2E-BOOT:` observation lines including `DONE`. It observed the expected user,
fish shell, passwordless sudo, jcode and fish policy, GitHub CLI, kitty config,
no snapper or snapshots, btrfs root and policy subvolumes, all expected services,
graphical target and autologin, package and desktop command sets, TLP policy,
NetworkManager/iwd and keyd policy, systemd-boot fallback, stable fstab, and 11
mirror servers. The VM powered off cleanly. Boot log SHA-256:
`df142532ba448e083c4c284fb0189c09faf3cd6e5f0a9e6f366964d6d623c1f4`.

A further networkless cold resume of the completed transaction emitted no intent,
readback, commit, or advance markers. It emitted the same completion marker and
returned rc 0. The complete target qcow2 was unchanged across that command:

- before and after SHA-256:
  `2160e343b47ff4cbc041d4bfb6bccae9df6acb87f8b5469fc5509427dda2700d`;
- before and after file size: 4,887,281,664 bytes;
- before and after mtime: 1788593197;
- no-op log SHA-256:
  `e2922a4cbe5d6887e5b235df12bdd9e5bbccb3711e47a98231aec6876fce0574`.

These observations are compatibility evidence for UR-03, UR-05, UR-09,
UR-10, UR-11, and UR-13. They are not final-tree closure.

## Final-tree firmware-refusal checkpoint

Attempted source revision:
`f7ef7a402343d32e2d1fd4c50449eaee1ba3d1a0`.
Packaged static controller SHA-256:
`9c44529ed3613db750003a786fd3cb7b3fe42b488dea5528629aa0cf6c016691`.
Workspace:
`/home/jeremy/.jcode/scratch/jstack-ubuntu-final64-1788593312`.

The fresh public installation refused before target writes because the VM runner
selected `OVMF_CODE.4m.fd`, whose guest did not expose exactly one readable
`SecureBoot-*` efivar. The controller reported:

```text
error: Secure Boot state is missing or ambiguous; unsigned artifact refused
E2E: INSTALL_FAILED rc=1
```

This is correct fail-closed behavior and evidence for the unsupported firmware
branch, not a successful installation. Phase-one log SHA-256:
`51ea71371c6574b1df3bee38127dc944a76a2f1f64afc9a2de98f1ddccafdb36`.
The disposable blank target remains preserved. The acceptance fixture must boot
firmware which exposes `SecureBoot=0`; production must not weaken the unknown or
ambiguous-state refusal.

## Final-tree successful baseline

### Successful 64 MiB baseline after mount-isolation fix

Revision `cb7d6c4` made the bootstrap bind private and refused a retained
artifact bind before promotion. A fresh run in
`/home/jeremy/.jcode/scratch/jstack-ubuntu-final64-mountfix-1788594203`
then passed the public transactional installation and target-only UEFI boot.
The plan was
`8cbd35388b51082a436d121b71c55803003983cd3bcf7d88227ab950ac566201`.
The controller emitted authorization, 384 64 MiB chunk transactions, whole
target completion, and `E2E: INSTALL_OK`. The installed target emitted all 25
existing policy observations including `E2E-BOOT: DONE` and powered off.

- static controller SHA-256:
  `9c44529ed3613db750003a786fd3cb7b3fe42b488dea5528629aa0cf6c016691`;
- phase-one log SHA-256:
  `2ecf7f53038d1e2cb81fff50405295322f4503f599500f4efc9012887271e1b5`;
- target boot log SHA-256:
  `0a5142745eb79587782f04310ce605f318718d074e16470dba0399623c75a649`;
- completed recovery-host qcow2 SHA-256:
  `d217836711f54398d9787e6703ac1382f160099d6a37dab8b6f6e9a77b10dadc`;
- completed target qcow2 SHA-256:
  `8bfdf032eb432ef106c66e16a0abb01817b02b1727efaced2e0f0c3b1f7c5213`.

This verifies the fresh baseline and boot observation. The completed-resume
no-write observation below verifies the positive no-op path. External fault,
identity, tamper, concurrency, and refusal no-write cases remain incomplete.

Every external-cut case must cold-boot a witness before resume, classify the
actual boundary from the durable journal and independent target/artifact range
hashes, and reject a missed or overshot intended cut. A requested serial marker
alone is not acceptance evidence.

## Final-tree fresh installation and boot checkpoint

Source revision `cb7d6c4` completed the public fresh-install and target-boot
workflow in preserved workspace
`/home/jeremy/.jcode/scratch/jstack-ubuntu-final64-mountfix-1788594203`.
This closes the earlier disposable-firmware blocker for this workflow, but does
not close the still-pending external interruption matrix.

- The secboot-capable OVMF fixture with blank setup-mode VARS exposed disabled
  Secure Boot. Production's missing, ambiguous and enabled-state refusals were
  not weakened.
- The first post-firmware attempt exposed a real propagated bootstrap mount:
  the artifact source changed while it was copied. Revision `cb7d6c4` made the
  bootstrap bind private and asserted its recursive artifact bind was absent
  before prepare. The corrected run's retained source and promoted artifact
  independently hashed to the same planned SHA-256,
  `8de490d6b1a51fa955314ae9f5f4d77c9958177c1842a839bf15664f5162cfc2`.
- The 64 MiB plan was
  `8cbd35388b51082a436d121b71c55803003983cd3bcf7d88227ab950ac566201`.
  The deployment emitted 384 intents and 384 advances, independently verified
  the whole target, emitted exactly one completion marker, and returned
  `E2E: INSTALL_OK`. Phase-one log SHA-256:
  `2ecf7f53038d1e2cb81fff50405295322f4503f599500f4efc9012887271e1b5`.
- The target then booted as the only disk under OVMF UEFI and emitted all 25
  current `E2E-BOOT:` policy observations through `DONE`. A direct grep of the
  retained log confirmed the count is 25. Phase-two log
  SHA-256: `0a5142745eb79587782f04310ce605f318718d074e16470dba0399623c75a649`.
- The packaged static controller SHA-256 remained
  `9c44529ed3613db750003a786fd3cb7b3fe42b488dea5528629aa0cf6c016691`.

This is final-tree evidence for the fresh public path, offline artifact
promotion, whole-target verification and target boot portions of UR-01, UR-03,
UR-08, UR-11 and UR-14. The completed no-write replay below and the later Commit
and Advance observations supersede those formerly open items. Other graph cuts
and real refusal cases remain open. At this checkpoint only 23 GiB remained on
the scratch filesystem, so no campaign VM was started at that time; the later
thin-target campaign worked around that constraint.

A subsequent target-preserving step cold-booted the retained host without a
source checkout or network and resumed the completed final64 plan. It emitted
the same completion marker and rc 0, with no intent, readback, commit, or
advance. The target qcow SHA-256, size, mtime, and allocated-block count were
identical before and after. No-op log SHA-256:
`8c51c37756f655beb43a0fe84500f0305b5b4fc44b1f663be2d07d8b56ad0ea5`.

The retained content-addressed artifact was then reused without another image
build. An offline thin host overlay and new blank 24 GiB target ran the public
prepare command and authorized plan
`9797ea9a82db2945b60c27d156c1b95dfd02682b0acbb05a17ed86d273049891`.
Both images passed `qemu-img check`. This preserved predeployment campaign
baseline is
`/home/jeremy/.jcode/scratch/jstack-ubuntu-final64-campaign-1788594980`.
The remaining external cut overlays were not started with only 22 GiB free,
because preserving three expected ~5.5 GiB target overlays would already leave
an unsafe filesystem margin before the rest of the required matrix.

## Subsequent cold-cut campaign observations

The capacity constraint above was worked around with fresh thin targets backed
by the preserved installed image and a deliberately mismatched first 64 MiB
chunk. This is a prepopulated-target fixture, not another blank-disk install.
The separately recorded fresh public install remains the blank-disk evidence.
All immutable backing ancestors are explicitly bound in campaign manifests.

The following observations were independently checked by the coordinator on
2026-09-05. They partially exercise UR-09 and UR-10, not the entire fault matrix.
Paths below are relative to the campaign baseline directory recorded above.

| Case | Actual cold witness | Observed recovery | Evidence |
|---|---|---|---|
| `commit-02` | Last valid record `Commit`, seq 0, cursor 0, first 64 MiB independently equal to artifact. Requested boundary matched. | After additional preserved fixture failures and forced stops, retry-b reached `COMPLETE`, printed `E2E-RESUME: rc=0`, and its systemd unit exited successfully. The retry began reconciling seq 1, so this is eventual recovery through multiple interruptions, not a clean first attempt directly from the original Commit record. | `commit-02-campaign/cases/commit-02/classified.json` SHA-256 `70a03e514e7e497ee6b3c0113703b9864eab5304cca890e08fac93f4cb24641f`; `resume-retry-b.serial.log` SHA-256 `bd2a1d574ca50e0fcb5471877b616f4fac65702e3c69dace7f880d13b2d836c7`; task `095109uxgd`. |
| `advance-01` | Last valid record `Advance`, seq 0, cursor 67,108,864, committed range independently equal. Requested boundary matched. | Cold resume reached `COMPLETE`, printed rc 0, and QEMU exited 0. | `advance-01-campaign/cases/advance-01/classified.json` SHA-256 `4096615f833c432faae7a829f2f11295287e4eda0b386dca27f4e7261263f4e1`; `resume.serial.log` SHA-256 `59b4e0b379c09c0d79a1eb4494c74efcdeb3a6fd59912fafe9f7eabcca62c2a8`; task `271130os14`. |

Earlier `readback-02` overshot into Advance and duplicated its witness output.
It is not a passing readback case. `readback-03` did produce a matching pending
Intent/effect-complete witness, but its first resumed VM was forcibly stopped
without a captured successful process exit. Its completion marker alone does
not close clean readback recovery acceptance. Those original logs are retained.

Fixture corrections include faster external-cut observation, bounded QEMU
process registration, preserved supervisor errors, and guest resume output
capture that does not depend on a serial-getty-controlled terminal remaining
writable. These harness changes are not changes to the pinned production graph.
Independent install-test discovery passed 32 tests after registration fix
`4460e39`; remaining actual boundary and refusal cases are still open.

## UR-01 through UR-14 current evidence and gaps

“Partial” below means that the named observation was obtained, not that the
requirement is accepted. Compatibility evidence is identified separately and
does not close a final-tree row. No row is marked complete.

| ID | Current evidence | Status and remaining gap |
|---|---|---|
| UR-01 | The final-tree fresh workflow entered through the public controller and completed. `test_install_safety` invokes the unmodified public shell for duplicate arguments and `--chroot-stage`; these are real parser checks, not instrumented-shell results. | **Partial.** Those parser checks do not prove VM target preservation. Real guest no-write refusal evidence for bypass cases and a physical-target builder attempt remains open. |
| UR-02 | The pinned Ubuntu graph drove the successful 64 MiB baseline and the observed Commit and Advance resumes. | **Partial.** Final real altered-graph/model, wrong-actor, and illegal-transition refusals, plus Windows-gate non-regression evidence, remain open. |
| UR-03 | The final baseline staged a complete content-addressed artifact before deployment. The earlier compatibility recovery completed networkless. | **Partial.** A final-tree fresh staging-to-deployment run with the network deliberately disconnected at the required boundary remains open. |
| UR-04 | The successful plan bound graph, artifact, target, recovery identity, and confirmation. | **Partial.** Real final-tree artifact, manifest, plan, target, recovery-identity, and confirmation tamper refusals with target no-write proof remain open. |
| UR-05 | A retained host completed a cold networkless no-checkout resume; Commit and Advance cuts retained recovery availability. | **Partial.** Root, ESP, mounted, swap, state, and artifact ancestry overlap refusals and explicit preserved-host comparisons remain open. |
| UR-06 | Stable identity was bound in successful plans. | **Open beyond baseline binding.** Enumeration change, same-size substitution, and missing, ambiguous, or duplicate serial/WWN cases need real observations. |
| UR-07 | The controller has a target transaction lock, exercised only by single-writer runs here. | **Open.** Concurrent public deploy/resume attempts through distinct aliases have not produced retained real-guest evidence. |
| UR-08 | Final staging promoted an artifact with matching hashes. Commit and Advance witnesses replayed authenticated journal records. | **Partial.** Torn-tail, stale-plan, symlink/hardlink, committed corruption, and interrupted-publication cases remain open in the real guest. |
| UR-09 | The final campaign independently classified matching durable `Commit` and `Advance` boundaries; both ranges matched, and both eventually completed. | **Partial.** Intent, in-write/effect, and readback boundaries remain open. `commit-02` required later retries, so it is not evidence of a clean first resume. |
| UR-10 | Cold production resume completed the verified Advance case and eventually recovered the Commit case. Earlier compatibility evidence reconciled a dangling intent/effect. | **Partial.** A clean final-tree resume for each supported boundary and committed-target corruption refusal remain open. |
| UR-11 | Final baseline performed whole-target verification, booted the target alone under UEFI, emitted 25 policy observations, and a later completed resume returned rc 0 with identical target qcow hash, size, mtime, and allocated blocks and no write markers. | **Partial.** These positive paths are verified, but the remaining failure-state and post-completion-change refusals are not. |
| UR-12 | The preserved host remained bootable through the observed final Commit and Advance campaigns. | **Partial.** Before/after firmware-variable and host ESP comparisons across build, deployment, and interruption cuts remain open. |
| UR-13 | A new cold process on the retained host resumed without the source checkout or network; the completed no-op did the same. | **Partial.** Final recovery UX/service lifecycle evidence for all supported interrupted states remains open. |
| UR-14 | A real final-tree fresh installation, target-only boot, completed no-op, and matching Commit and Advance cold witnesses are retained. | **Partial.** The refusal matrix and the remaining graph-derived interruption boundaries are incomplete, so this is not a completed frozen-tree campaign. |

Every remaining external-cut case must cold-boot a witness before resume,
classify the actual boundary from the durable journal and independent
target/artifact range hashes, and reject a missed or overshot intended cut. A
requested serial marker or completion marker alone is not acceptance evidence.

## Refusal-probe attempts that are not passes

The first canonical refusal-probe rerun stopped at its harness guard because the
guard incorrectly required link count 1 for the ext4 state directory. Normal
ext4 directories have link counts greater than 1. The guard was corrected to
require a root-owned directory while retaining the regular single-link and mode
checks for protected files. That stopped run is a harness failure, not a
controller refusal pass. Any subsequent result must come from a fresh real guest
run of the corrected probe and retain its output and exit status.

Executor attempts affected by `earlyoom` are likewise failures to obtain a probe
result. Process termination, a serial marker, or preserved partial output does
not establish any refusal case. No UR row above treats those attempts as a pass.
