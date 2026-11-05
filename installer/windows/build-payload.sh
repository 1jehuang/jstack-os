#!/usr/bin/env bash
# Build the JStack Windows-installer payload from a built JStack live ISO.
#
#   installer/windows/build-payload.sh --iso /abs/jstack-live-*.iso --out /abs/new-dir
#
# Output directory (everything the Windows installer needs, plus SHA256SUMS):
#   jstack-root.img.gz    Btrfs root filesystem image (subvolumes @ @home @log @pkg)
#   boot/                 files for the shared Windows EFI partition, EFI\jstack\:
#     shimx64.efi           Microsoft-signed shim (Ubuntu build, MS UEFI CA 2011)
#     mmx64.efi             MOK manager shipped next to shim (only used on demand)
#     grubx64.efi           Canonical-signed GRUB
#     grub.cfg              finds the JStack root by filesystem UUID
#   manifest.json         versions, root UUID, sizes, digests
#
# Why the Ubuntu chain: firmware on almost every Windows PC trusts only
# Microsoft's keys. A Microsoft-signed shim, Canonical-signed GRUB and kernel
# boot with Secure Boot ON and no key enrollment prompt. JStack's userland is
# unchanged. The Arch kernel is replaced by the signed Ubuntu kernel and its
# modules, because the signed kernel only loads modules signed with its key.
set -euo pipefail
die() { printf 'build-payload: %s\n' "$*" >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
ISO= OUT= KVER=7.0.0-42-generic
UBUNTU=${UBUNTU_MIRROR:-http://archive.ubuntu.com/ubuntu}
while (($#)); do
  case $1 in
    --iso) ISO=$2; shift 2;;
    --out) OUT=$2; shift 2;;
    --kernel) KVER=$2; shift 2;;
    *) die "unknown argument $1";;
  esac
done
[[ $ISO == /* && -f $ISO ]] || die '--iso /absolute/path/to/jstack-live.iso required'
[[ $OUT == /* && ! -e $OUT ]] || die '--out must be a new absolute directory'
for t in unsquashfs mkfs.btrfs arch-chroot pigz curl bsdtar sbverify sha256sum python3; do
  command -v $t >/dev/null || die "missing tool $t"
done
mkdir -p -- "$OUT"/{boot,work}
W=$OUT/work

# --- Pinned Ubuntu signed boot chain ---------------------------------------
# Versions are pinned and every .deb is checked against the SHA256 published in
# the Ubuntu archive index (signed Release -> Packages -> SHA256).
fetch_deb() { # dist package -> path
  local dist=$1 pkg=$2
  local idx=$W/Packages-$dist
  [[ -f $idx ]] || curl -fsSL "$UBUNTU/dists/$dist/main/binary-amd64/Packages.gz" | zcat > "$idx"
  local rec; rec=$(awk -v p="$pkg" 'BEGIN{RS=""} $0 ~ "(^|\n)Package: " p "\n" {print; exit}' "$idx")
  [[ -n $rec ]] || die "package $pkg not in $dist"
  local file sha; file=$(sed -n 's/^Filename: //p' <<<"$rec"); sha=$(sed -n 's/^SHA256: //p' <<<"$rec")
  local dest=$W/debs/${file##*/}
  mkdir -p "$W/debs"
  [[ -f $dest ]] || curl -fsSL -o "$dest" "$UBUNTU/$file"
  echo "$sha  $dest" | sha256sum -c --quiet - || die "checksum mismatch for $pkg"
  mkdir -p "$W/ub"
  bsdtar -xOf "$dest" 'data.tar*' | bsdtar -xf - -C "$W/ub"
  printf '%s %s\n' "$pkg" "$(sed -n 's/^Version: //p' <<<"$rec")" >> "$W/versions"
}
fetch_deb questing shim-signed   # 1.59: newer SBAT level than noble's 1.58, same MS signature
fetch_deb noble-updates grub-efi-amd64-signed
fetch_deb noble-updates "linux-image-$KVER"
fetch_deb noble-updates "linux-modules-$KVER"   # 7.x: includes the former modules-extra
UB=$W/ub
SHIM=$UB/usr/lib/shim/shimx64.efi.signed.latest
[[ -f $SHIM ]] || SHIM=$UB/usr/lib/shim/shimx64.efi.signed
sbverify --list "$SHIM" | grep -q 'Microsoft Corporation UEFI CA 2011' || die 'shim is not Microsoft-signed'
sbverify --list "$UB/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed" | grep -q Canonical || die 'grub not Canonical-signed'
sbverify --list "$UB/boot/vmlinuz-$KVER" | grep -q Canonical || die 'kernel not Canonical-signed'

# --- Root filesystem ---------------------------------------------------------
MNT=$W/iso; mkdir -p "$MNT"
sudo mount -o loop,ro "$ISO" "$MNT"
trap 'sudo umount "$MNT" 2>/dev/null || true; for m in "$W"/root/{proc,sys,dev/pts,dev,run}; do sudo umount "$m" 2>/dev/null || true; done' EXIT
SFS=$MNT/arch/x86_64/airootfs.sfs
[[ -f $SFS ]] || die 'not a JStack live ISO (no arch/x86_64/airootfs.sfs)'
ROOT=$W/root
sudo unsquashfs -q -d "$ROOT" "$SFS"
sudo umount "$MNT"
sudo test -f "$ROOT/etc/jstack-live-installer.json" || die 'live image is missing the clean JStack marker'

# Swap the Arch kernel for the signed Ubuntu kernel and its modules.
sudo rm -rf "$ROOT"/usr/lib/modules/*
sudo cp -a "$UB/lib/modules/$KVER" "$ROOT/usr/lib/modules/"
sudo cp "$UB/boot/vmlinuz-$KVER" "$ROOT/usr/lib/modules/$KVER/vmlinuz"
sudo cp "$UB/boot/config-$KVER" "$UB/boot/System.map-$KVER" "$ROOT/usr/lib/modules/$KVER/" 2>/dev/null || true

ROOT_UUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
echo "$ROOT_UUID" > "$W/root-uuid"
sudo python3 "$HERE/payload/configure-root.py" "$ROOT" "$KVER" "$ROOT_UUID"

# Btrfs image with the same subvolume layout as the USB installer.
STAGE=$W/stage
sudo mkdir -p "$STAGE"
sudo mv "$ROOT" "$STAGE/@"
sudo mkdir -p "$STAGE/@home" "$STAGE/@log" "$STAGE/@pkg"
sudo sh -c "cp -a '$STAGE/@/var/log/.' '$STAGE/@log/' 2>/dev/null; true"
sudo find "$STAGE/@/var/log" -mindepth 1 -delete
IMG=$W/jstack-root.img
SIZE=$(( $(sudo du -sx --block-size=1M "$STAGE" | cut -f1) * 13 / 10 + 1024 ))
truncate -s "${SIZE}M" "$IMG"
sudo mkfs.btrfs -q -U "$ROOT_UUID" -L jstack --compress zstd:3 -r "$STAGE" \
  -u '@' -u '@home' -u '@log' -u '@pkg' --shrink "$IMG"
sudo chown "$(id -u):$(id -g)" "$IMG"
IMG_BYTES=$(stat -c %s "$IMG")
pigz -9 -c "$IMG" > "$OUT/jstack-root.img.gz" && rm -f "$IMG"  # gzip: Windows decompresses it natively
sudo rm -rf "$STAGE"

# --- Boot files --------------------------------------------------------------
install -m644 "$SHIM" "$OUT/boot/shimx64.efi"
install -m644 "$UB/usr/lib/shim/mmx64.efi" "$OUT/boot/mmx64.efi"
install -m644 "$UB/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed" "$OUT/boot/grubx64.efi"
sed "s/@ROOT_UUID@/$ROOT_UUID/g" "$HERE/payload/grub.cfg.in" > "$OUT/boot/grub.cfg"

python3 - "$OUT" "$ROOT_UUID" "$IMG_BYTES" "$KVER" "$W/versions" "$ISO" <<'PY'
import hashlib, json, os, sys, pathlib
out, uuid, size, kver, versions, iso = sys.argv[1:]
out = pathlib.Path(out)
def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()
files = {str(p.relative_to(out)).replace('\\', '/'): {'sha256': sha(p), 'bytes': p.stat().st_size}
         for p in sorted(out.rglob('*')) if p.is_file() and 'work' not in p.parts}
manifest = {'schema': 1, 'root_uuid': uuid, 'root_image_bytes': int(size), 'kernel': kver,
            'boot_chain': dict(l.split(' ', 1) for l in open(versions).read().split('\n') if l),
            'source_iso': os.path.basename(iso), 'files': files}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
(out / 'SHA256SUMS').write_text(''.join(f"{v['sha256']}  {k}\n" for k, v in files.items()))
PY
sudo rm -rf "$W"
echo "payload: $OUT"
