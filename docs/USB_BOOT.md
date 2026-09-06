# USB boot and permanent installation

## Choose the right image

| Medium | Live desktop | Permanent installation |
|---|---|---|
| Standard Arch Linux installer (`ARCH_YYYYMM`) | Console, not Jstack's Niri desktop | `archinstall` installs ordinary Arch, not Jstack OS |
| Newly built clean Jstack image (`JSTACK_LIVE`) | Niri starts on tty1 by default | `sudo jstack-install-live` installs offline onto a blank internal disk |
| Older Jstack image, or image built with a private overlay | Niri live desktop | Not an installation source. Rebuild a clean current image |
| Persistent Ubuntu recovery system on its own disk | The recovery host's desktop or console | Separate transactional installer deploys Jstack to another unused whole disk |

The USB initially inspected on 2026-09-06 contained the Arch 2026.09.01 install medium,
label `ARCH_202609`, with BIOS and UEFI boot entries. Its package manifest and
live filesystem contained Archinstall, but no Niri or Jstack installer. This was
a read-only content inspection, not a physical boot test or proof about other
USB drives. It describes the historical state before the separately authorized
flash below. Updating the repository alone did not change the USB.

## Verified physical USB, 2026-09-06

After explicit user approval at 11:01:29 UTC, the intended 58.6 GiB VFENG USB,
serial `FC12093679273`, was flashed with the accepted clean Jstack image. It now
contains `JSTACK_LIVE`. Exactly `2731687936` image bytes were written, and the
write-stream hash plus **two cache-invalidated physical readbacks of the full
image extent** matched SHA256
`1b7d398a9624f911b9bb0d141ca638eba3deb986cc6a4ea5325e302a66d5a428`.
These are image-length checks, not hashes of the USB's entire capacity.

The actual USB's boot catalog contains BIOS and UEFI entries, and its extracted
`JSTACK-INSTALL.md` matches the accepted instructions. Safe device poweroff
completed successfully, leaving it ready to unplug. The initial writer's
post-readback udev-settle timeout is retained, and the successful follow-up was
read-only, not a second flash. Evidence is under `verification/physical-usb/` in
`/home/jeremy/Downloads/JstackOS-2026-09-06/`; see the
[physical verification details](USB_INSTALL_ACCEPTANCE.md#physical-usb-flash-and-verification).

The same image passed live and installed Niri acceptance in VMs. The physical
stick has **not** yet been booted on the intended Dell. Boot-catalog presence and
matching readbacks do not prove that Dell's firmware, graphics, Wi-Fi, audio, or
suspend behavior. Permanent installation still requires reviewing and explicitly
confirming the Dell's own blank internal disk.

## OS-less Dell: boot and install from one USB

Use a **newly built, clean Jstack ISO**, not the standard Arch image and not a
private-overlay image. No Ubuntu installation is required. Follow the complete
[on-USB instructions](../iso/INSTALL.md), which cover:

1. Booting the USB through Dell's F12 one-time boot menu in UEFI mode.
2. Trying Niri or opening the console fallback.
3. Reading offline help with `jstack-install-help`.
4. Listing disks without writing anything with `sudo jstack-install-live --list`.
5. Running `sudo jstack-install-live`, reviewing the target, and explicitly
   confirming installation to a blank internal disk of at least 32 GiB.
6. Shutting down after success, removing the USB, and booting the internal disk.

Installation needs no package downloads. Secure Boot must be disabled. Existing
partitions or filesystem signatures are refused even when no operating system
can boot. USB/removable and in-use disks are also refused. There is no upgrade,
dual boot, encryption, automatic rollback, or power-loss resume guarantee.
A partial installation may require separately reviewed disk cleanup before retry.

The help file is included at `/usr/share/doc/jstack-live/INSTALL.md`, and the
application launcher includes installation and instructions entries. A successful
installation includes Niri and tty1 autostart. Test actual hardware with the live
desktop first: VM acceptance does not prove every Dell GPU or Wi-Fi adapter.

## Identify what is currently booted

These commands are read-only:

```sh
cat /etc/os-release
lsblk -o NAME,TRAN,SIZE,FSTYPE,LABEL,MOUNTPOINTS
command -v niri
command -v jstack-install-live
command -v archinstall
pacman -Q niri jstack-base jstack-niri
```

Missing commands/packages are expected on a standard Arch installer. Jstack is
Arch-based, so `/etc/os-release` alone does not establish which image is running.
Use the package checks and boot-media label together. An old Jstack ISO might
have the same `JSTACK_LIVE` label but no installer. Check the command too.

## Build and write the correct image

Follow [the live image build instructions](../iso/README.md), without `--overlay`.
Writing the resulting ISO onto a USB is a separate destructive operation that
replaces the selected USB's contents. Confirm its exact device, model, serial,
and capacity, and back up its contents first. Never assume that `/dev/sda` is the
USB or use the computer's internal disk as the imaging target.

## Existing Ubuntu recovery host

The separate [Ubuntu installation guide](INSTALL_FROM_UBUNTU.md) remains available
for deploying a complete image to a separate disk from a persistent recovery
host. Its transaction journal/recovery design does **not** apply to the offline
live-USB installer. Do not bypass either installer's safety checks.
