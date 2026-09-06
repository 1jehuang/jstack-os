#!/usr/bin/env bash
# Build a live ISO, never install onto a disk. Run as an ordinary Arch user.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK= OVERLAY= VESKTOP= PREPARE_ONLY=0
usage() {
  cat <<'EOF'
Usage: iso/build-live.sh --work /absolute/new/scratch-dir [options]
  --overlay DIR           Trusted private airootfs overlay (never copied to repo)
  --vesktop-package FILE  Trusted prebuilt vesktop-bin package instead of AUR build
  --prepare-only          Generate profile without packages or privileged work
All output lives beneath WORK. Existing WORK directories are refused.
Build dependencies must already be installed. Only mkarchiso runs under sudo.
EOF
}
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --work|--overlay|--vesktop-package)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in --work) WORK=$2;; --overlay) OVERLAY=$2;; --vesktop-package) VESKTOP=$2;; esac
      shift 2 ;;
    --prepare-only) PREPARE_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ $EUID != 0 ]] || die 'run as an ordinary user, not root or sudo'
[[ $WORK == /* ]] || die '--work must be an absolute new scratch path'
[[ ! -e $WORK && ! -L $WORK ]] || die 'WORK already exists, preserving it'
WORK=$(realpath -m -- "$WORK")
[[ $WORK != "$ROOT" && $WORK != "$ROOT/"* ]] || die 'WORK must be outside the repository'
[[ $WORK != *[$'\n\r\t ']* && $WORK != *\'* && $WORK != *\"* ]] || die 'WORK must not contain whitespace or quotes'
[[ -z $OVERLAY || -d $OVERLAY ]] || die 'overlay directory does not exist'
[[ -z $VESKTOP || -f $VESKTOP ]] || die 'vesktop package does not exist'
for tool in python3 rsync; do command -v "$tool" >/dev/null || die "missing tool: $tool"; done
if (( ! PREPARE_ONLY )); then
  for tool in makepkg repo-add mkarchiso sudo git cargo meson ninja scdoc arch-meson; do
    command -v "$tool" >/dev/null || die "missing build prerequisite: $tool"
  done
fi
umask 077
mkdir -p -- "$(dirname -- "$WORK")"
mkdir -- "$WORK"
mkdir -- "$WORK/packages" "$WORK/builds" "$WORK/sources" "$WORK/out"
args=(--work "$WORK")
[[ -z $OVERLAY ]] || args+=(--overlay "$(realpath -- "$OVERLAY")")
python3 "$ROOT/iso/prepare-profile.py" "${args[@]}"
(( ! PREPARE_ONLY )) || { printf 'PROFILE=%s/profile\n' "$WORK"; exit 0; }

# Do not install build/runtime dependencies into the host. makepkg's dependency
# checks cannot resolve our not-yet-installed local meta-packages, so --nodeps is
# intentional. The final pacstrap transaction resolves all runtime dependencies.
export MAKEFLAGS="${MAKEFLAGS:--j2}" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_HOME="$WORK/cargo-cache" PKGDEST="$WORK/packages" SRCDEST="$WORK/sources"
cat > "$WORK/makepkg.conf" <<'EOF'
source /etc/makepkg.conf
PKGEXT='.pkg.tar.zst'
COMPRESSZST=(zstd -c -T2 -)
EOF
build_package() {
  local dir=$1
  (cd -- "$dir" && BUILDDIR="$dir" makepkg --config "$WORK/makepkg.conf" --nodeps --noconfirm --cleanbuild)
}
for source in "$ROOT"/packages/*; do
  [[ -f $source/PKGBUILD ]] || continue
  name=${source##*/}
  mkdir -- "$WORK/builds/$name"
  rsync -a --exclude .git --exclude target --exclude /pkg/ --exclude /src/ \
    --exclude '*.pkg.tar.*' --exclude '.makepkg.log' --exclude /tofi/ \
    "$source/" "$WORK/builds/$name/"
  build_package "$WORK/builds/$name"
done
if [[ -n $VESKTOP ]]; then
  cp -- "$VESKTOP" "$WORK/packages/"
else
  git clone --depth 1 https://aur.archlinux.org/vesktop-bin.git "$WORK/builds/vesktop-bin"
  build_package "$WORK/builds/vesktop-bin"
fi
mapfile -d '' packages < <(find "$WORK/packages" -maxdepth 1 -type f -name '*.pkg.tar.zst' ! -name '*-debug-*' -print0 | sort -z)
((${#packages[@]})) || die 'no built packages found'
repo-add "$WORK/packages/jstack-local.db.tar.gz" "${packages[@]}"
sha256sum "${packages[@]}" > "$WORK/package-sha256.txt"
printf 'Building live ISO. No physical disk is attached or selected.\n'
sudo mkarchiso -v -w "$WORK/archiso-work" -o "$WORK/out" "$WORK/profile"
find "$WORK/out" -maxdepth 1 -name '*.iso' -type f -exec sha256sum {} \; > "$WORK/iso-sha256.txt"
printf 'ISO output: %s/out\nChecksums: %s/iso-sha256.txt\n' "$WORK" "$WORK"
