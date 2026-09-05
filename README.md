# jstack OS

An agent-native, Arch-based Linux distribution. Everything is scriptable,
machine-readable, and pre-configured for AI coding agents: niri (IPC-first
compositor), terminal remote control, structured system introspection, and
preinstalled agent harnesses.

## Layout

- `packages/` - PKGBUILDs for jstack meta/config packages
  - `jstack-base/` - policy: services, keyd, NM/iwd, fish, **no snapshots**
  - `jstack-agent/` - jcode preinstalled from a pinned release
  - `jstack-terminals/` - kitty (remote-control socket) + foot defaults
  - `jstack-niri/` - niri desktop: config, keymap, helper scripts
  - `jstack-waybar/`, `jstack-network/`, `tofi-jstack/`
- `install/` - `jstack-install.sh`: full install from an Ubuntu/Debian or Arch
  host via pacstrap. See `docs/INSTALL_FROM_UBUNTU.md`
  - `jstack-scheduler/` - scx_lavd CPU scheduler (sched_ext), enabled by default
  - `jstack-firefox/` - Firefox policies, OLED theme, curated extensions
- `installer/` - executable no-USB Windows installer state model and tools
- `docs/installer/` - installer architecture, safety model, and generated graph
- `iso/` - archiso and RAM-installer profile (to come)
- `docs/TRIAGE.md` - the keep/drop decision log for everything migrated
  from the reference machine

## Installing from Ubuntu

`install/jstack-install.sh` builds a complete offline jstack OS disk image on a
preserved Ubuntu recovery host, then deploys that image transactionally to a
separate whole disk. It fetches the official `archlinux-bootstrap` tarball
(Ubuntu's own pacman and keyring are too old to be trusted), pacstraps into
btrfs subvolumes, builds every jstack package inside the offline image, and
writes systemd-boot entries without modifying firmware variables.

> **Supported scope:** the recovery host must remain bootable from a persistent
> disk separate from the uniquely identifiable target. The artifact, plan,
> controller, and journal are retained under `--state-dir`. Same-disk live
> conversion, volatile recovery, mounted/swap targets, and partition-only
> installation fail closed. Read [the safety limits](docs/INSTALL_FROM_UBUNTU.md).

```sh
git clone https://github.com/1jehuang/jstack-os && cd jstack-os
rustup toolchain install 1.85.0 --profile minimal --target x86_64-unknown-linux-musl
make -C installer/controller ubuntu-static
sudo ./install/jstack-install.sh --disk /dev/disk/by-id/<target> \
  --state-dir /var/lib/jstack-installer --user jeremy --hostname xps13
```

Building the controller requires `rustup`, `make`, and a native C compiler.
Build it as your normal user before running the installer. Other Debian-based
hosts are not accepted by this Ubuntu-specific recovery model.

What you end up with (see `packages/jstack-base/files/POLICY.md`):

- btrfs root, `@ @home @log @pkg`, zstd:3, **no snapper / snap-pac / timeshift**
  (blocked by a pacman hook)
- niri + waybar + tofi + kitty (`allow_remote_control`, `/tmp/kitty.sock`) + foot
- fish login shell, tty1 autologin, niri autostarts
- keyd, NetworkManager + iwd, TLP, earlyoom, bluetooth
- `jcode` preinstalled from a pinned release (`jstack-agent`)
- passwordless sudo for the primary user

### Proof

`install/vm/test-ubuntu.sh` boots a fresh Ubuntu 24.04 cloud image under
QEMU/OVMF, runs the installer against a blank virtual disk, then boots the
result and asserts each policy item on the serial console. Run it before
changing anything under `install/` or `packages/`.

## Design rules

1. Nothing is hand-copied onto the ISO. Everything ships inside a package.
2. User-facing defaults live in `/etc/skel`, shared assets in
   `/usr/share/jstack`, helper scripts in `/usr/lib/jstack/scripts`.
3. Every migrated config records a decision in `docs/TRIAGE.md`
   (distro / personal / hardware / cruft).
4. No hardcoded `/home/<user>` paths, hostnames, serials, or credentials in
   anything distro-bucketed.

## Building a package

```sh
cd packages/jstack-niri
makepkg -f
```
