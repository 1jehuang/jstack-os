#!/usr/bin/env bash
# jstack OS installer: run from an Ubuntu/Debian (or Arch) host to install a
# full jstack OS system onto a target disk or pre-made partitions.
#
#   sudo ./install/jstack-install.sh --disk /dev/nvme0n1 --user jeremy --hostname xps13
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
LOCALE="en_US.UTF-8" KEYMAP="us" PASSWORD="" WIPE_ESP=0 YES=0 SKIP_SOURCE_PKGS=0 MIRROR=""
JSTACK_PKGS=(jstack-base jstack-terminals jstack-agent jstack-niri jstack-network jstack-waybar)
SOURCE_PKGS=(tofi-jstack)   # needs makedepends in chroot; heavy but required by niri/network

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
host_prep() {
  if command -v apt-get >/dev/null; then
    log "Installing host tools (apt)"
    apt-get install -y -q arch-install-scripts archlinux-keyring pacman-package-manager \
      btrfs-progs dosfstools gdisk curl ca-certificates >/dev/null
  elif command -v pacman >/dev/null; then
    pacman -Sy --needed --noconfirm arch-install-scripts btrfs-progs dosfstools gptfdisk >/dev/null
  else
    die "need apt or pacman on the host"
  fi
  command -v pacstrap >/dev/null || die "pacstrap missing"

  # Ubuntu's pacman ships without a usable pacman.conf/mirrorlist for Arch.
  mkdir -p /etc/pacman.d
  if [ ! -s /etc/pacman.d/mirrorlist ] || ! grep -q '^Server' /etc/pacman.d/mirrorlist; then
    log "Writing Arch mirrorlist"
    if [ -n "$MIRROR" ]; then
      echo "Server = $MIRROR" > /etc/pacman.d/mirrorlist
    else
      curl -fsSL 'https://archlinux.org/mirrorlist/?country=US&protocol=https&use_mirror_status=on' \
        | sed 's/^#Server/Server/' | head -20 > /etc/pacman.d/mirrorlist
    fi
  fi
  if ! grep -q '^\[core\]' /etc/pacman.conf 2>/dev/null; then
    log "Writing /etc/pacman.conf"
    cat > /etc/pacman.conf <<'PC'
[options]
HoldPkg = pacman glibc
Architecture = auto
CheckSpace
ParallelDownloads = 8
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
[core]
Include = /etc/pacman.d/mirrorlist
[extra]
Include = /etc/pacman.d/mirrorlist
PC
  fi
  if [ ! -d /etc/pacman.d/gnupg ] || ! pacman-key --list-keys >/dev/null 2>&1; then
    log "Initialising pacman keyring"
    pacman-key --init
    pacman-key --populate archlinux
  fi
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
    partprobe "$DISK"; udevadm settle
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
  pacstrap -K "$MNT" base base-devel linux linux-firmware btrfs-progs efibootmgr \
    networkmanager iwd fish git sudo vim intel-ucode amd-ucode
  genfstab -U "$MNT" > "$MNT/etc/fstab"
  # genfstab may emit subvolid=; keep subvol= only so snapshots/rollbacks never confuse boot.
  sed -i 's/,subvolid=[0-9]*//g' "$MNT/etc/fstab"

  log "Staging jstack-os repo into target"
  mkdir -p "$MNT/usr/src/jstack-os"
  rsync -a --exclude .git --exclude 'target/' --exclude '*/pkg/' --exclude '*/src/' \
    --exclude '*.pkg.tar.zst' "$REPO_DIR/" "$MNT/usr/src/jstack-os/"

  local pw
  pw=${PASSWORD:-}
  if [ -z "$pw" ]; then
    read -rsp "Password for $USERNAME (also root): " pw; echo
  fi
  arch-chroot "$MNT" /usr/bin/env \
    J_USER="$USERNAME" J_HOST="$HOSTNAME_" J_TZ="$TZ_" J_LOCALE="$LOCALE" J_KEYMAP="$KEYMAP" \
    J_PASS="$pw" J_ROOT_PART="$ROOT_PART" J_SKIP_SOURCE="$SKIP_SOURCE_PKGS" \
    J_PKGS="${JSTACK_PKGS[*]}" J_SOURCE_PKGS="${SOURCE_PKGS[*]}" \
    bash /usr/src/jstack-os/install/chroot-stage.sh
}

host_prep
partition
bootstrap
log "Done. umount -R $MNT && reboot"
