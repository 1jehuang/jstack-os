# Jstack live USB image

This builder creates a **live ISO with a manual offline installer**. It uses the installed
official Archiso `releng` profile for generic x86-64 BIOS and UEFI boot. No physical
disk is selected, formatted, mounted, or written by the builder.

For boot-menu steps and permanent-install options, see
[USB boot and permanent installation](../docs/USB_BOOT.md). A clean image includes
Niri and `jstack-install-live`, which installs onto a blank internal disk without
Ubuntu or package downloads. Read [the on-USB instructions](INSTALL.md).
The separate Ubuntu installer still requires its persistent recovery host.

## Build on Arch Linux

Install build prerequisites separately, then run the builder **as your normal
user**. It uses sudo only for `mkarchiso`, which builds a filesystem in scratch.

```sh
sudo pacman -S --needed archiso base-devel git rsync python rust cargo \
  meson ninja scdoc wayland-protocols wayland libxkbcommon cairo pango harfbuzz foot
bash iso/build-live.sh --work "$HOME/.cache/jstack-live-$(date +%s)"
```

The work directory must be new, absolute, outside this repository, and contain no
spaces or quotes. Allow at least 25 GiB free disk space. Compilation defaults to
two jobs and SquashFS uses two threads with a 512 MiB working-memory limit.
The complete GUI package set can need considerably more storage and RAM than a
minimal Arch ISO. Do not remove the USB while booted from it.

Outputs are `WORK/out/jstack-live-*.iso`, `WORK/iso-sha256.txt`, and
`WORK/package-sha256.txt`. All ten repository package directories are built from
scratch copies, including tofi and the pinned Jcode release. `vesktop-bin` is built
from its AUR PKGBUILD to satisfy `jstack-desktop-apps`. Review that upstream build
recipe as you would any AUR package. Alternatively supply
`--vesktop-package /absolute/path/to/vesktop-bin-*.pkg.tar.zst` from a trusted build.
The builder never uses `makepkg -s` or installs build dependencies on the host.

`--prepare-only` generates the profile without package downloads, builds, sudo,
or image construction. The latest installed Archiso releng, rolling Arch package
repositories, and unpinned tofi/AUR sources mean this is a repeatable build
procedure, **not a bit-for-bit reproducible release**. The Jcode x86-64 download
itself is version-pinned and checksum-verified by its PKGBUILD.

## Live session

- The live account is `jstack` (UID 1000), with tty1 autologin and passwordless sudo.
- Fish starts niri on tty1. Ctrl+Alt+F2 opens a console. The boot menu also offers
  **Jstack OS live console (GPU fallback)** with `nomodeset` and no niri autostart.
  A failed/exited desktop returns to a usable shell instead of a restart loop.
- NetworkManager manages networking and DNS, using iwd for Wi-Fi. Releng's
  networkd/resolved units are masked. SSH and cloud-init are disabled.
- `copytoram=n` avoids copying the whole desktop image into RAM. Writes use the
  volatile live overlay and are lost on reboot. Persistence is not implemented.
- The systemd GPT auto-generator is masked. No installer runs automatically.
  Run `jstack-install-help` for offline instructions, then explicitly launch
  `sudo jstack-install-live` to install on a blank internal disk. Manual disk
  tools are still available to the passwordless-sudo
  user, so this is not a security boundary against deliberate disk changes.
- Secure Boot signing is not configured. Disable Secure Boot for this unsigned
  image. The generic initramfs and firmware packages improve portability, but
  real Dell GPU, Wi-Fi, audio, suspend, and USB behavior still need hardware tests.

## Offline installation

The installer copies the clean, read-only live filesystem, not the running
session's writable overlay. It configures a new Btrfs system, account, initramfs,
and UEFI bootloader. Target selection refuses USB/removable drives, the boot
source, partitions, in-use disks, and nonblank disks. It requires UEFI with
Secure Boot off and an internal disk of at least 32 GiB. BIOS live boot does not
imply support for BIOS installation. There is no dual boot, upgrade, encryption,
automatic rollback, or resumable installation. See [INSTALL.md](INSTALL.md).

The installer and instructions are copied into newly built images. Existing
ISOs and USB drives do not gain this capability merely by updating the repo.

## Optional private overlay

`--overlay /absolute/private/overlay` copies regular files/directories into the
scratch profile's `airootfs`. Symlinks and special files are rejected. Generated
live defaults are applied afterward and replace overlapping overlay paths. This
is not a sandbox against a malicious overlay. For user files use `home/jstack/...`. On boot the home
tree becomes `jstack:jstack`, Jcode config directories/files become 700/600, and
NetworkManager connection profiles and iwd state become root-owned 700/600.

**Private overlay contents are readable from the ISO itself.** This is not
encryption. Treat both scratch and the resulting USB as sensitive, never publish
an image containing secrets, and do not commit overlays. The builder does not
discover or read credentials from the host. An overlay is a trusted input and
can contain executable programs, so only supply content you authorize.

**Overlay builds are live-only.** The profile deliberately removes the clean
installation marker when `--overlay` is supplied, even if that overlay provides
its own marker. The installer refuses these images to avoid copying private
credentials or arbitrary customizations into a permanent installation.

## Checks

```sh
python -B -m unittest discover -s iso/tests -v
bash -n iso/build-live.sh
```

Tests use the installed releng profile and disposable scratch directories, not
physical disks. They validate generation and refusal behavior, not a successful
ISO boot. The real offline installation harness is:

```sh
python -B -m unittest discover -s iso/vm -p 'test_harness.py' -v
python3 -B iso/vm/test_live_install.py \
  --iso /absolute/path/to/clean-jstack-live.iso \
  --artifacts /absolute/path/to/new-proof-directory
```

It uses only new virtual disks, read-only USB-emulated ISO media, and no network.
It checks disk refusals with full-device hashes, performs the offline install,
and boots the installed disk without the ISO using fresh UEFI variables. Both
live and installed phases require an actual rendered Niri desktop capture.
See [clean USB installation acceptance](../docs/USB_INSTALL_ACCEPTANCE.md) for
image identity, verification status, and limits.
BIOS live boot, console fallback, networking, and physical hardware need separate
checks. Writing an ISO to USB erases that selected USB and is a separate,
explicitly authorized step. Never point an imaging command at the Dell's internal
disk.

### Earlier private-overlay live-only VM proof (2026-09-06 UTC)

This earlier proof used a different, private-overlay image. It is **not** evidence
for the clean offline installer, and that private image cannot be used as an
installation source.

The generated ISO was built successfully and booted under QEMU with UEFI firmware,
`virtio-vga-gl`, and `egl-headless`. The acceptance run observed:

- niri running, a terminal launched, and the guest desktop visually verified
  through a screenshot.
- No failed systemd units, with NetworkManager active.
- Working DNS and ping over the VM's Ethernet connection.
- Correct ownership and private permissions for the explicitly supplied overlay.
- Packaged Jcode **0.81.4** completed an authenticated model-backed workflow with
  actual bash-tool execution. A malformed tool argument was retried successfully.

The VM was stopped after verification. This is evidence for the UEFI live desktop
workflow, not a physical Dell or USB boot guarantee. BIOS boot, the explicit
console fallback entry, physical Wi-Fi, GPU variants, audio, and suspend still
need their own acceptance checks. No physical disk was flashed in this proof.

On Arch, QEMU graphics support is split into optional packages. A basic
`qemu-system-x86_64` installation may lack the accelerated device and headless EGL
display backend even though the emulator itself runs. Install them before testing:

```sh
sudo pacman -S --needed qemu-system-x86 edk2-ovmf \
  qemu-hw-display-virtio-vga-gl qemu-ui-opengl qemu-ui-egl-headless
```

The tested graphics combination is `-device virtio-vga-gl -display egl-headless`.
It requires a working host EGL/render device. Check that the QEMU device and
display backends are available before attributing a VM startup failure to the
ISO. Headless EGL does not open a desktop window, so use a guest screenshot or
remote display plus serial checks to verify the actual desktop rather than only
asserting that the niri executable exists.
