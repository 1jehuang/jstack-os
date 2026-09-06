# USB boot and permanent installation

## Choose the right image

| Medium | Live desktop | Permanent installation |
|---|---|---|
| Standard Arch Linux installer (`ARCH_YYYYMM`) | Console, not Jstack's Niri desktop | `archinstall` installs ordinary Arch, not Jstack OS |
| Custom Jstack live image (`JSTACK_LIVE`) | Niri starts on tty1 by default | No supported Jstack disk installer included |
| Persistent Ubuntu recovery system on its own disk | The recovery host's desktop or console | Repository installer deploys Jstack to a separate, unused whole disk |

The USB inspected on 2026-09-06 contained the Arch 2026.09.01 install medium,
label `ARCH_202609`, with BIOS and UEFI boot entries. Its package manifest and
live filesystem contained Archinstall, but no Niri or Jstack installer. This was
a read-only content inspection, not a physical boot test or proof about other
USB drives.

## Boot an existing USB

1. Save your work, leave the USB plugged in, and restart the target computer.
2. Open its one-time boot menu. On a Dell XPS, press **F12** during startup.
3. Select the USB's **UEFI** boot entry. Neither image is configured for Secure
   Boot here. If changing firmware settings, first ensure you have any required
   disk-encryption recovery keys. Do not clear TPM keys or reset passwords.
4. On the standard Arch image, choose **Arch Linux install medium**. A root
   console is expected. There is no Niri desktop to launch on that image.
5. On the custom image, choose **Jstack OS live desktop**. Use **Jstack OS live
   console (GPU fallback)** only when troubleshooting graphics. That entry
   deliberately skips Niri autostart. Ctrl+Alt+F2 also opens a console.

These steps only boot the live environment. Do not run partitioning, formatting,
or installation commands just to test boot. Keep the USB inserted while using
it. Jstack live-session changes are lost at reboot.

To identify the environment from its console, these commands are read-only:

```sh
cat /etc/os-release
lsblk -o NAME,TRAN,SIZE,FSTYPE,LABEL,MOUNTPOINTS
command -v niri
command -v archinstall
pacman -Q niri jstack-base jstack-niri
```

Missing commands/packages are expected on a standard Arch installer. Jstack is
Arch-based, so `/etc/os-release` alone does not establish which image is running.
Use the package checks and boot-media label together.

## Try the Jstack desktop without installing

Build the custom ISO using [the live image instructions](../iso/README.md).
Writing that ISO onto a USB is a separate destructive operation that replaces
the selected USB's contents. Confirm the exact device and back up its contents
first. Do not use an internal disk as the imaging target.

The custom image intentionally removes Archinstall and does not bundle the
repository's Ubuntu installer. It is a desktop preview, not a click-to-install
image. Replacing an Arch USB with it adds the live desktop, not a permanent
installation workflow.

## Install Jstack OS permanently

The current supported route is [installation from Ubuntu](INSTALL_FROM_UBUNTU.md):

1. Back up the intended target disk. Installation erases the entire target.
2. Use a persistent, bootable Ubuntu recovery system on a disk separate from
   the target. A standard Arch USB, Jstack live USB, or volatile Ubuntu live
   session is not a substitute for that recovery host.
3. Check the linked guide's prerequisites, including UEFI, Secure Boot disabled,
   internet access, a persistent state directory, and 512-byte target sectors.
4. On that Ubuntu host, clone this repository and build the pinned transaction
   controller as described in the guide. Identify the target by its stable
   `/dev/disk/by-id/` path, not an assumed `/dev/sda` name.
5. Follow the guide's install command only after confirming that the target is
   the separate disk you intend to erase. Preserve the Ubuntu recovery disk and
   installer state so an interrupted deployment can be resumed.
6. After successful deployment, boot the completed target using the firmware
   boot menu. The installed Jstack system includes Niri and tty1 autostart.

**There is currently no supported “boot this live USB, then install Jstack onto
the computer's internal disk” workflow.** Do not bypass the installer recovery
checks or use Archinstall expecting it to install Jstack. A dedicated live-USB
installer needs implementation and end-to-end validation before instructions
can promise that workflow.
