# Installing jstack OS from an Ubuntu host

`install/jstack-install.sh` installs a complete jstack OS system onto a disk (or
onto existing partitions) using Arch's `pacstrap` running on Ubuntu/Debian. No
Arch ISO or USB needed. It also works from a running Arch system.

## What gets installed

Everything the reference machine has, minus the personal bits (see
`docs/TRIAGE.md`). Concretely:

| Area | Setting |
|---|---|
| Filesystem | btrfs, subvolumes `@ @home @log @pkg`, `compress=zstd:3,ssd,discard=async` |
| Snapshots | **none**. snapper/snap-pac/timeshift/grub-btrfs are `conflicts` of `jstack-base` and blocked by a pacman hook |
| Boot | systemd-boot, 1s timeout, `linux` + fallback entries |
| Desktop | niri + waybar + tofi-jstack + dunst, black wallpaper, Caps->Esc xkb |
| Terminals | kitty (`allow_remote_control yes`, `listen_on unix:/tmp/kitty.sock`), foot |
| Shell | fish, tty1 autologin -> `niri-session` |
| Input | keyd (Right Alt -> Enter) |
| Network | NetworkManager with iwd backend, captive portal helpers, wifi-pick |
| Power | TLP (powersave governor, perf EPP on AC), earlyoom |
| Agent | jcode preinstalled from a pinned release (`jstack-agent`), `JCODE_NO_AUTO_UPDATE=1` |

## Usage

```sh
git clone https://github.com/1jehuang/jstack-os
cd jstack-os

# Whole disk (destroys everything on it):
sudo ./install/jstack-install.sh --disk /dev/nvme0n1 --user jeremy --hostname xps13

# Existing partitions (dual boot; ESP is reused, not wiped):
sudo ./install/jstack-install.sh --root-part /dev/nvme0n1p5 --esp-part /dev/nvme0n1p1 --user jeremy
```

Flags: `--password`, `--timezone` (default America/Los_Angeles), `--locale`,
`--keymap`, `--mirror URL`, `--wipe-esp`, `--skip-source-pkgs`, `--yes`.

The host needs UEFI and internet. On Ubuntu the script uses a current official
Arch bootstrap environment rather than Ubuntu's pacman and keyring. Before it
formats or repartitions anything, it validates the inputs, initializes the
keyring, synchronizes the package databases, and downloads the complete base
package set with the same pacman configuration used by `pacstrap`. A failed
repository sync or base-package download therefore leaves the target untouched.
The working mirrorlist is explicitly copied into the installed system.

`install/jstack-install.sh` is the legacy direct shell installer. It does not run
through the newer Rust installer controller or its state model, so those
transaction and recovery guarantees do not protect this path. The preflight
reduces one important risk, but it is not crash recovery and does not make an
in-place replacement of the disk currently running the host safe.

This preflight cannot make the whole installation offline. Package builds can
still fetch sources (`--skip-source-pkgs` only skips the optional source and AUR
sets), and a mirror can fail after the preflight. If any command fails after
formatting has started, the installer prints a prominent warning. Do not reboot
into that incomplete target. Keep the live environment running and inspect or
repair it. Rerunning the installer formats the target again and may destroy
recoverable data. There is no automatic reboot recovery or rollback.

## Stages

1. `host_prep`: install host tools, prepare current Arch pacstrap/pacman, and init the keyring.
2. `package_preflight`: sync repositories and cache the base system before destructive work.
3. `partition`: GPT with 1G ESP + rest btrfs, or format the given root partition.
4. `bootstrap`: `pacstrap` base, preserve the working mirrorlist, `genfstab`, copy this repo to
   `/usr/src/jstack-os`, then `arch-chroot` into `install/chroot-stage.sh`.
5. `chroot-stage`: locale/users, `makepkg` every `packages/*` as an unprivileged
   `builder` user and `pacman -U` them, apply systemd presets, autologin,
   mkinitcpio, `bootctl install`, seed `/etc/skel` into the user's home, and
   assert that no snapshot tooling is present and `jcode` is on PATH.

## Updating jcode

Bump `pkgver` and `sha256sums_x86_64` in `packages/jstack-agent/PKGBUILD`, then
`cd packages/jstack-agent && makepkg -f && sudo pacman -U *.pkg.tar.zst`.
