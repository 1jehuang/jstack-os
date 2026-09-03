#!/usr/bin/env bash
# jstack OS installer: run from an Ubuntu/Debian (or Arch) host to install a
# full jstack OS system onto a target disk or pre-made partitions.
#
#   sudo ./install/jstack-install.sh --disk /dev/nvme0n1 --user jeremy --hostname xps13
#   sudo ./install/jstack-install.sh --disk /dev/nvme0n1 --user jeremy --seed jstack-seed.tar.gz.enc
#   sudo ./install/jstack-install.sh --root-part /dev/nvme0n1p5 --esp-part /dev/nvme0n1p1 --user jeremy
#
# What you get (mirrors the reference machine, see packages/jstack-base/files/POLICY.md):
#   btrfs root (@ @home @log @pkg, zstd:3), systemd-boot, NO snapper/snapshots,
#   niri + waybar + tofi + kitty (remote control socket) + foot, fish login shell
#   with niri autostart on tty1, keyd, NetworkManager+iwd, TLP, jcode preinstalled.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MNT=/mnt/jstack
DISK="" ROOT_PART="" ESP_PART="" USERNAME="" HOSTNAME_="jstack" TZ_="America/Los_Angeles"
LOCALE="en_US.UTF-8" KEYMAP="us" PASSWORD="" WIPE_ESP=0 YES=0 SKIP_SOURCE_PKGS=0 MIRROR="" SEED="" SEED_PASS="${JSTACK_SEED_PASS:-}" JCODE_API_KEY=""
JSTACK_PKGS=(jstack-base jstack-terminals jstack-agent jstack-niri jstack-network jstack-waybar jstack-scheduler jstack-firefox jstack-desktop-apps)
SOURCE_PKGS=(tofi-jstack)   # in-repo PKGBUILDs built in chroot
AUR_PKGS=(vesktop-bin)      # AUR PKGBUILDs cloned + built in chroot (--skip-source-pkgs skips both)

usage() { sed -n '2,15p' "$0"; exit "${1:-0}"; }
die() { echo "error: $*" >&2; exit 1; }
log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISK=$2; shift 2 ;;
    --root-part) ROOT_PART=$2; shift 2 ;;
    --esp-part) ESP_PART=$2; shift 2 ;;
    --wipe-esp) WIPE_ESP=1; shift ;;
    --user) USERNAME=$2; shift 2 ;;
    --password) PASSWORD=$2; shift 2 ;;
    --hostname) HOSTNAME_=$2; shift 2 ;;
    --timezone) TZ_=$2; shift 2 ;;
    --locale) LOCALE=$2; shift 2 ;;
    --keymap) KEYMAP=$2; shift 2 ;;
    --mirror) MIRROR=$2; shift 2 ;;
    --skip-source-pkgs) SKIP_SOURCE_PKGS=1; shift ;;
    --seed) SEED=$2; shift 2 ;;              # bundle from install/seed/make-seed.sh
    --seed-pass) SEED_PASS=$2; shift 2 ;;
    --jcode-api-key) JCODE_API_KEY=$2; shift 2 ;;   # alternative to a seed: single Anthropic/OpenRouter-style key
    --yes) YES=1; shift ;;
    --chroot-stage) shift; exec "$REPO_DIR/install/chroot-stage.sh" "$@" ;;
    -h|--help) usage ;;
    *) die "unknown arg: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$USERNAME" ] || die "--user is required"
[ -d /sys/firmware/efi ] || die "UEFI boot required (systemd-boot)"
if [ -n "$DISK" ]; then
  [ -z "$ROOT_PART$ESP_PART" ] || die "use --disk OR --root-part/--esp-part"
  [ -b "$DISK" ] || die "$DISK is not a block device"
else
  [ -b "$ROOT_PART" ] && [ -b "$ESP_PART" ] || die "--root-part and --esp-part must be block devices"
fi

# ---------- host prerequisites ----------
# On non-Arch hosts we do not trust the distro's pacman/keyring (Ubuntu ships
# pacman 6.0 and a stale archlinux-keyring). Instead we unpack the official
# archlinux-bootstrap tarball and run pacstrap from inside it.
BOOT=""   # path to bootstrap root when used
ARCH_CHROOT=arch-chroot
host_prep() {
  if command -v pacman >/dev/null && [ -f /etc/arch-release ]; then
    pacman -Sy --needed --noconfirm arch-install-scripts btrfs-progs dosfstools gptfdisk rsync >/dev/null
    return
  fi
  command -v apt-get >/dev/null || die "need apt (Debian/Ubuntu) or an Arch host"
  log "Installing host tools (apt)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null
  apt-get install -y -q zstd curl ca-certificates btrfs-progs dosfstools gdisk rsync \
    parted util-linux >/dev/null

  BOOT=/tmp/jstack-bootstrap
  if [ ! -x "$BOOT/root.x86_64/usr/bin/pacstrap" ]; then
    log "Fetching archlinux-bootstrap tarball"
    local base="${MIRROR:-https://geo.mirror.pkgbuild.com/\$repo/os/\$arch}"
    base="${base%/\$repo*}"
    mkdir -p "$BOOT"
    curl -fL --retry 3 -o "$BOOT/bootstrap.tar.zst" "$base/iso/latest/archlinux-bootstrap-x86_64.tar.zst"
    curl -fL --retry 3 -o "$BOOT/bootstrap.tar.zst.sig" "$base/iso/latest/archlinux-bootstrap-x86_64.tar.zst.sig" || true
    tar -C "$BOOT" --zstd -xpf "$BOOT/bootstrap.tar.zst" --numeric-owner
  fi
  BOOT="$BOOT/root.x86_64"
  ARCH_CHROOT="$BOOT/usr/bin/arch-chroot"
  # pacman's CheckSpace needs the chroot root to be a mountpoint; bind it onto itself.
  mountpoint -q "$BOOT" || mount --bind "$BOOT" "$BOOT"

  log "Configuring bootstrap pacman"
  if [ -n "$MIRROR" ]; then
    echo "Server = $MIRROR" > "$BOOT/etc/pacman.d/mirrorlist"
  else
    { echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch';
      curl -fsSL 'https://archlinux.org/mirrorlist/?country=US&protocol=https&use_mirror_status=on' \
        | sed 's/^#Server/Server/' | grep '^Server' | head -10; } > "$BOOT/etc/pacman.d/mirrorlist"
  fi
  sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 8/' "$BOOT/etc/pacman.conf"
  cp -L /etc/resolv.conf "$BOOT/etc/resolv.conf" 2>/dev/null || true
  "$ARCH_CHROOT" "$BOOT" bash -c 'pacman-key --init >/dev/null 2>&1 && pacman-key --populate archlinux >/dev/null 2>&1 && pacman -Sy --noconfirm --needed archlinux-keyring >/dev/null'
}

# ---------- partitioning ----------
partition() {
  if [ -n "$DISK" ]; then
    echo; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS "$DISK"; echo
    echo "THIS WILL ERASE EVERYTHING ON $DISK."
    if [ "$YES" != 1 ]; then
      read -rp "Type the disk path to confirm: " c; [ "$c" = "$DISK" ] || die "aborted"
    fi
    wipefs -af "$DISK"
    sgdisk -Z "$DISK"
    sgdisk -n1:0:+1G -t1:ef00 -c1:"EFI" -n2:0:0 -t2:8304 -c2:"jstack" "$DISK"
    partprobe "$DISK" || true; udevadm settle; sleep 1
    ESP_PART=$(lsblk -lnpo NAME "$DISK" | sed -n 2p)
    ROOT_PART=$(lsblk -lnpo NAME "$DISK" | sed -n 3p)
    WIPE_ESP=1
  else
    echo "Root -> $ROOT_PART (will be formatted btrfs). ESP -> $ESP_PART (wipe=$WIPE_ESP)."
    if [ "$YES" != 1 ]; then read -rp "Continue? [y/N] " c; [ "$c" = y ] || die "aborted"; fi
  fi
  [ "$WIPE_ESP" = 1 ] && mkfs.fat -F32 -n EFI "$ESP_PART"
  mkfs.btrfs -f -L jstack "$ROOT_PART"

  log "Creating subvolumes"
  mkdir -p "$MNT"; mount "$ROOT_PART" "$MNT"
  for sv in @ @home @log @pkg; do btrfs subvolume create "$MNT/$sv"; done
  umount "$MNT"
  local o="rw,noatime,compress=zstd:3,ssd,discard=async,space_cache=v2"
  mount -o "$o,subvol=@" "$ROOT_PART" "$MNT"
  mkdir -p "$MNT"/{home,var/log,var/cache/pacman/pkg,boot}
  mount -o "$o,subvol=@home" "$ROOT_PART" "$MNT/home"
  mount -o "$o,subvol=@log"  "$ROOT_PART" "$MNT/var/log"
  mount -o "$o,subvol=@pkg"  "$ROOT_PART" "$MNT/var/cache/pacman/pkg"
  mount "$ESP_PART" "$MNT/boot"
}

# ---------- base system ----------
bootstrap() {
  log "pacstrap base system"
  local pkgs="base base-devel linux linux-firmware btrfs-progs efibootmgr networkmanager iwd fish git sudo vim intel-ucode amd-ucode"
  if [ -n "$BOOT" ]; then
    mkdir -p "$BOOT/mnt"; mount --rbind "$MNT" "$BOOT/mnt"
    "$ARCH_CHROOT" "$BOOT" bash -c "pacstrap -K /mnt $pkgs && genfstab -U /mnt > /mnt/etc/fstab"
    umount -R "$BOOT/mnt"
  else
    pacstrap -K "$MNT" $pkgs
    genfstab -U "$MNT" > "$MNT/etc/fstab"
  fi
  # genfstab may emit subvolid=; keep subvol= only so snapshots/rollbacks never confuse boot.
  sed -i 's/,subvolid=[0-9]*//g' "$MNT/etc/fstab"

  log "Staging jstack-os repo into target"
  mkdir -p "$MNT/usr/src/jstack-os"
  if [ -n "$SEED" ]; then
    [ -f "$SEED" ] || die "seed bundle not found: $SEED"
    install -Dm600 "$SEED" "$MNT/root/jstack-seed.bundle"
    if [ -z "$SEED_PASS" ]; then case "$SEED" in *.enc) read -rsp "Seed passphrase: " SEED_PASS; echo ;; esac; fi
  fi
  rsync -a --exclude .git --exclude 'target/' --exclude '*/pkg/' --exclude '*/src/' \
    --exclude '*.pkg.tar.zst' "$REPO_DIR/" "$MNT/usr/src/jstack-os/"

  local pw
  pw=${PASSWORD:-}
  if [ -z "$pw" ]; then
    read -rsp "Password for $USERNAME (also root): " pw; echo
  fi
  cp -L /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true
  mountpoint -q "$MNT" || mount --bind "$MNT" "$MNT"   # pacman CheckSpace needs a mountpoint
  "$ARCH_CHROOT" "$MNT" /usr/bin/env \
    J_USER="$USERNAME" J_HOST="$HOSTNAME_" J_TZ="$TZ_" J_LOCALE="$LOCALE" J_KEYMAP="$KEYMAP" \
    J_PASS="$pw" J_ROOT_PART="$ROOT_PART" J_SKIP_SOURCE="$SKIP_SOURCE_PKGS" \
    J_SEED="${SEED:+/root/jstack-seed.bundle}" JSTACK_SEED_PASS="$SEED_PASS" J_JCODE_API_KEY="$JCODE_API_KEY" \
    J_PKGS="${JSTACK_PKGS[*]}" J_SOURCE_PKGS="${SOURCE_PKGS[*]}" J_AUR_PKGS="${AUR_PKGS[*]}" \
    bash /usr/src/jstack-os/install/chroot-stage.sh
}

host_prep
partition
bootstrap
log "Done. umount -R $MNT && reboot"
