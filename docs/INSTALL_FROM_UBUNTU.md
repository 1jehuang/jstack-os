# Installing jstack OS from an Ubuntu host

`install/jstack-install.sh` constructs a complete bootable jstack OS disk image
using Arch's `pacstrap` on a preserved Ubuntu recovery host, then deploys
that immutable image through the pinned Ubuntu transaction controller. No Arch
ISO or USB is needed.

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

First install `rustup`, `make`, and a native C compiler on the preserved Ubuntu
host. The repository does not contain a prebuilt controller binary. Build its
pinned static executable as your normal user before invoking the installer:

```sh
git clone https://github.com/1jehuang/jstack-os
cd jstack-os
rustup toolchain install 1.85.0 --profile minimal --target x86_64-unknown-linux-musl
make -C installer/controller ubuntu-static

# Whole disk (destroys everything on it):
sudo ./install/jstack-install.sh --disk /dev/disk/by-id/<target> \
  --state-dir /var/lib/jstack-installer --user jeremy --hostname xps13
```

Flags: `--password`, `--timezone` (default America/Los_Angeles), `--locale`,
`--keymap`, `--mirror URL`, `--skip-source-pkgs`, `--yes`.

The host needs UEFI with Secure Boot disabled, internet during artifact
construction, a persistent state directory, and its own bootable disk separate
from the target. The target must expose 512-byte logical sectors. Secure Boot
enabled or indeterminate, and non-512-byte-sector targets, are refused before
target writes because this release neither signs its boot chain nor builds the
artifact with matching non-512 GPT geometry. On Ubuntu the script uses a current official
Arch bootstrap environment rather than Ubuntu's pacman and keyring. Before it
formats or repartitions anything, it validates the inputs, initializes the
keyring, synchronizes the package databases, and downloads the complete base
package set with the same pacman configuration used by `pacstrap`. All package
and source builds finish in the offline image before deployment. A failed
download or build therefore leaves the target untouched.
The working mirrorlist is explicitly copied into the installed system.

The public entrypoint cannot directly format the physical target. It asks the
controller to inspect and initialize durable recovery state, constructs an
exclusively owned regular-file image through a loop mapping, and then supplies
that content-addressed image to the controller. Partition-only installation is
outside this transaction model and is refused.

Deployment records a durable intent for each fixed, plan-bound image chunk,
flushes the effect, independently reads it back, and only then commits it. To
recover after interruption, boot the preserved Ubuntu host and run the exact
`jstack-ubuntu-installer resume --plan ...` command printed before deployment.
This is explicit manual resume, not rollback or automatic recovery. Resume
fails closed if the graph, plan, artifact, recovery disk, or target identity has
changed. An incomplete target is never reported as complete.

## Stages

1. `host_prep`: install host tools, prepare current Arch pacstrap/pacman, and init the keyring.
2. `package_preflight`: sync repositories and cache the base system before destructive work.
3. `artifact`: create a private regular-file image, GPT with 1G ESP + btrfs, and never attach the physical target to the builder.
4. `bootstrap`: `pacstrap` base into the image, preserve the working mirrorlist, `genfstab`, copy this repo to
   `/usr/src/jstack-os`, then `arch-chroot` into `install/chroot-stage.sh`.
5. `chroot-stage`: locale/users, `makepkg` every `packages/*` as an unprivileged
   `builder` user and `pacman -U` them, apply systemd presets, autologin,
   mkinitcpio, `bootctl --no-variables install`, seed `/etc/skel` into the user's home, and
   assert that no snapshot tooling is present and `jcode` is on PATH.
6. `deploy`: bind the immutable artifact and chunk manifest to the confirmed
   hardware plan, then intent/write/readback/commit each chunk and verify the
   complete target before graph completion.

## Updating jcode

Bump `pkgver` and `sha256sums_x86_64` in `packages/jstack-agent/PKGBUILD`, then
`cd packages/jstack-agent && makepkg -f && sudo pacman -U *.pkg.tar.zst`.
