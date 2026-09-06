# Clean live USB installation acceptance

## Scope

The target workflow is one USB that boots a live Niri desktop and installs
Jstack OS onto an OS-less computer's blank internal disk, without Ubuntu or
package downloads. The installer is `iso/jstack-install-live.py`, not the
separate Ubuntu recovery controller. Read [the installation instructions](../iso/INSTALL.md).

**Status: PASS, 2026-09-06 10:45:42 UTC.** The complete clean-image run took
331.75 seconds and passed all six refusal checks, offline installation,
independent installed boot, desktop rendering, installed policy checks, and
normal shutdown. Both final desktop screenshots were visually inspected.
Earlier incomplete runs found test-harness issues, five orphan network sockets,
and a stale kernel partition table. Those failures were fixed, not counted as
acceptance passes. The final run used the image identified below.

A focused disposable-VM reproduction recorded `sgdisk` returning zero while
warning that the kernel still used the old partition table in all six trials.
Two of three baseline trials still had no kernel partition nodes after closing
the partitioner, settling udev, and waiting. An explicit `BLKRRPART` ioctl on a
pinned normal descriptor succeeded in all six trials and exposed the intended
geometry. The repair keeps strict identity/busy checks, a bounded pre-reread
settle, one metadata reread, and two matching complete observations of the exact
planned geometry, type GUIDs, and freshly generated PARTUUIDs before formatting.
Wrong completed layouts are fatal. Only incomplete discovery is retried, never
partitioning or formatting writes. The exact repaired production
`create_partitions()` helper passed five further real-VM cycles with generated
GUIDs and validated GPT geometry, without reimplementing the partitioning logic
in the diagnostic. Each preserved the partitioner's warning, completed the
explicit reread, and converged on the strict intended layout.

## Verified image identity

- Image: `jstack-live-2026.09.06-x86_64.iso`
- Bytes: `2731687936`
- SHA256: `1b7d398a9624f911b9bb0d141ca638eba3deb986cc6a4ea5325e302a66d5a428`
- Installer SHA256: `88fe2a40b5731e34d1ba2e6d1abe9b370947a1a35300029e58eba6d6d79077f4`
- Profile generator SHA256: `459f9b1385877685d9481dd62af63ac2ad3db977621b3918ace0214b8007ccfc`
- Bundled INSTALL.md SHA256: `f49ce59d3eef7d4b0d36281f22c5d2c9e9488f81ff426b513b0b3f8f97f557d9`
- Clean profile, no private overlay or host credentials.
- Cached package archives were reused, not an earlier private live filesystem.
- Foot defaults use `[colors-dark]`, validated by the real Foot parser without
  warnings. The final image also masks systemd 261's networkd/resolved sockets
  whose backing services are intentionally disabled.

## Repeat the verification

Run as an unprivileged KVM-capable user with the graphics/firmware dependencies
listed in [the build guide](../iso/README.md):

```sh
python3 -B -m unittest discover -s iso/tests -v
python3 -B -m unittest discover -s iso/vm -p test_harness.py -v
python3 -B iso/vm/test_live_install.py \
  --iso /absolute/path/to/jstack-live-2026.09.06-x86_64.iso \
  --artifacts /absolute/path/to/new-proof-directory
```

The harness refuses existing artifact directories and non-regular disk backing
files. It uses 2 virtual CPUs, 3 GiB RAM, secure-capable OVMF with Secure Boot
disabled, and `-nic none`. It creates a 40 GiB target and a separate disposable
40 GiB refusal fixture. The ISO is read-only USB mass storage. No host block
device, directory share, or credentials are attached.

The installed boot has neither ISO nor fixture attached and uses fresh firmware
variables. This checks the fallback EFI boot path rather than reusing a firmware
entry created during installation. SetupMode=1 is a fresh-OVMF fixture property,
not a requirement for every physical Secure-Boot-disabled machine.

## Measured results and retained evidence

- **67 installer/profile unit tests and 29 harness tests passed.** Shell syntax
  and the actual Foot configuration parser also passed without warnings.
- All six refusals returned the intended diagnostic and exit 1, with identical
  entire-device before/after hashes. The source ISO hash also remained unchanged.
- The installer handled the observed stale-table warning with an explicit
  successful kernel reread, then completed the real offline installation.
- The installed boot had no USB/ISO or fixture attached and fresh firmware
  variables. Normal user/password login and passwordless sudo worked.
- Actual Btrfs mounts were `/@`, `/@home`, `/@log`, and `/@pkg`, sharing one UUID
  and `compress=zstd:3`. The ESP mounted as VFAT and the UUID-based fstab verified.
- Root was locked, the machine ID was valid, the persistent keyring contained
  183 public keys, NetworkManager was active, the disabled backend/socket units
  were masked, and there were no failed system units at the installed check.
- Live and installed Niri each produced a real 1280x800 screenshot with the
  appropriate phase's proof terminal. Both were visually inspected without the
  old Foot configuration warning.
- Live poweroff took 2.861 seconds with an explicit poweroff broadcast and QEMU
  exit 0. Installed poweroff took 2.922 seconds with `Powering off` and
  `reboot: Power down` in serial, followed by QEMU exit 0. Neither was force-killed.
  `qemu-img check` reported no errors after installation and after installed boot.

Original full-run artifacts:
`/home/jeremy/.jcode/scratch/jstack-usb-install-proof-20260906-1040`.
The verified image, instructions, package list, final logs/screenshots/results,
partition reproduction/repair evidence, and `SHA256SUMS` are preserved outside
scratch at `/home/jeremy/Downloads/JstackOS-2026-09-06/`.

The frozen harness is commit `6e5098e`, SHA256
`b7b8907da30c9be6c65f4f209cf1efd3a9be69061d1b77d72556bf09cc72a4da`.
The final partition repair is commit `6a65fc7`.

## Guided interactive acceptance

A second independent VM run passed on **2026-09-06 at 10:52:05 UTC** in 196.21
seconds, using the unchanged verified ISO from Downloads. It exercised the
actual guided TTY interface rather than supplying installation settings as
command-line flags. The only flag was `--serial-console`, to allow checking the
installed system through the VM's serial connection.

- Cancelling with an empty disk selection returned exit 1 and the expected
  `cancelled` diagnostic. Full 40 GiB target hashes before and after were equal.
- The disk, displayed identity token, username, hostname, password, and repeated
  password prompts were answered through a real TTY. Prompt/input events were
  retained, with dummy password events redacted. No host credentials were used.
- The guided installation returned success. A fresh-firmware boot without the
  ISO passed the same installed-system checks and actual Niri rendering proof.
  The installed PNG was visually inspected. Both VM phases shut down normally
  in about three seconds, and both qcow2 integrity checks passed.

Original evidence is at
`/home/jeremy/.jcode/scratch/jstack-guided-install-proof-20260906-1048`.
Its scratch driver, results, prompt events, screenshots, and logs are also
preserved under `verification/guided/` in the Downloads bundle. This strengthens
the documented manual workflow but does not change the physical-USB status:
the inspected VFENG stick still contains ordinary Arch until separately
authorized reflashing and readback verification occur.

## Acceptance coverage

- ISO boots from emulated USB into Niri, with a focused real terminal visible.
- USB-root instructions equal the live filesystem help and `jstack-install-help`.
- Source USB, wrong confirmation, raw filesystem, mounted disk, partition target,
  and nonblank partitioned disk are refused with the expected error and exit 1.
  Every refusal compares the **entire block device's** before/after SHA256,
  including the parent disk when a partition is supplied. These are not samples.
- Real offline installer reports success and the target boots independently.
- Installed account login, sudo, actual Btrfs/ESP mount topology, UUID fstab,
  kernel/initramfs, fallback EFI loader, service policy, and live-artifact removal
  are checked through the booted installed system.
- Installed Niri runs and renders a focused real terminal. Both desktop PNGs are
  validated, transferred with matching guest/host SHA256, and visually inspected.
- Both VM phases power off normally, and `qemu-img check` reports no errors.

`egl-headless` can return QMP `screendump: no surface` while the guest renders
normally. The harness retains that diagnostic and requires a fresh native Niri
`screenshot-screen` capture instead. Niri IPC must prove the unique test terminal
is focused on the active output. PNG checks include dimensions, chunk CRCs, full
pixel decompression, and non-flat content. Capture failures are not skipped.

## Explicit limits

This is VM acceptance, not a physical Dell or flashed-USB boot test. It does not
prove Wi-Fi, audio, suspend, every GPU, firmware boot enumeration, BIOS
installation, or enabled Secure Boot. The no-NIC test proves installation needs
no network, not that DNS or connectivity works. Earlier private-overlay live
network/model tests used another image and are not substitutes for this proof.

Only blank whole internal disks of at least 32 GiB are supported. A disk with no
bootable OS can still have partitions and will be refused. There is no dual boot,
upgrade, disk encryption, rollback, or resumable power-loss recovery. Installed
policy intentionally enables tty1 autologin and passwordless sudo. These limits
are also in the on-USB instructions.

No physical USB or internal disk was written during this verification. Flashing
the selected USB is a separate destructive step requiring explicit confirmation.
