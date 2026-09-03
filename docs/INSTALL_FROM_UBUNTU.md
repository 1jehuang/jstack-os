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

The host needs UEFI and internet. On Ubuntu the script apt-installs
`arch-install-scripts pacman-package-manager archlinux-keyring` and writes a
minimal `/etc/pacman.conf` + mirrorlist if none exist.

## Stages

1. `host_prep`: install pacstrap/pacman on the host, init the Arch keyring.
2. `partition`: GPT with 1G ESP + rest btrfs, or format the given root partition.
3. `bootstrap`: `pacstrap` base, `genfstab`, copy this repo to
   `/usr/src/jstack-os`, then `arch-chroot` into `install/chroot-stage.sh`.
4. `chroot-stage`: locale/users, `makepkg` every `packages/*` as an unprivileged
   `builder` user and `pacman -U` them, apply systemd presets, autologin,
   mkinitcpio, `bootctl install`, seed `/etc/skel` into the user's home, and
   assert that no snapshot tooling is present and `jcode` is on PATH.

## Updating jcode

Bump `pkgver` and `sha256sums_x86_64` in `packages/jstack-agent/PKGBUILD`, then
`cd packages/jstack-agent && makepkg -f && sudo pacman -U *.pkg.tar.zst`.
