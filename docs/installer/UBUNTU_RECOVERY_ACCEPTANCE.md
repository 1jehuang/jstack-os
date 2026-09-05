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

## Final-tree checkpoint and current blocker

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

## Explicitly open final-tree observations

The following remain open on a final frozen source revision:

- UR-01: real public bypass, duplicate-flag, and builder physical-target cases.
- UR-02: real adapter/graph observation agreement alongside final gates.
- UR-03: fresh complete image staging followed by networkless deployment.
- UR-04: real artifact, manifest, plan, target, and recovery identity tampering.
- UR-05: all recovery ancestry overlap refusals and preserved-host comparison.
- UR-06: enumeration change, same-size substitution, missing and duplicate identity.
- UR-07: concurrent public deploy/resume through distinct aliases.
- UR-08: real torn tail, stale plan, alias, corruption, and publication interruption.
- UR-09: externally killed VMs at actual journal-observed intent, write, readback,
  commit, and advance boundaries.
- UR-10: cold witness followed by production resume for every supported boundary,
  plus committed-target corruption refusal.
- UR-11: final-tree whole-target verification, target-only UEFI boot, and exact
  completed-resume no-write proof.
- UR-12: host firmware/ESP comparisons across final-tree build, deployment, and cuts.
- UR-13: final-tree retained recovery UX from a new cold process without checkout.
- UR-14: completed real campaign and final frozen-tree gates.

Every external-cut case must cold-boot a witness before resume, classify the
actual boundary from the durable journal and independent target/artifact range
hashes, and reject a missed or overshot intended cut. A requested serial marker
alone is not acceptance evidence.
