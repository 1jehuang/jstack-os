#!/usr/bin/env bash
# Real-VM acceptance test for the legacy installer's preflight no-write guard.
# Boots a disposable overlay of a previously prepared Ubuntu image, uses its
# cached Arch bootstrap, and makes a local HTTP mirror serve real repository
# databases while rejecting package payloads. The public installer is copied
# verbatim and is never instrumented.
set -Eeuo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKING="${UBUNTU_BACKING:-$HOME/.jcode/scratch/jstack-ubuntu-e2e/ubuntu.qcow2}"
WORK="${WORK:-${JCODE_SCRATCH_DIR:-$HOME/.jcode/scratch}/jstack-preflight-vm-$(date +%s)-$$}"
MEM="${MEM:-3072}"
CPUS="${CPUS:-2}"
TIMEOUT="${TIMEOUT:-900}"

find_ovmf() {
  for candidate in "$@"; do
    [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}
OVMF_CODE="${OVMF_CODE:-$(find_ovmf /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/OVMF/OVMF_CODE_4M.fd)}"
OVMF_VARS="${OVMF_VARS:-$(find_ovmf /usr/share/edk2/x64/OVMF_VARS.4m.fd /usr/share/OVMF/OVMF_VARS_4M.fd)}"

for command in qemu-img qemu-system-x86_64 xorriso sha256sum guestfish; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
[ -r "$BACKING" ] || { echo "missing Ubuntu backing: $BACKING" >&2; exit 2; }
[ ! -e "$WORK" ] || { echo "refusing pre-existing WORK directory: $WORK" >&2; exit 2; }
mkdir -p "$WORK/seed"
qemu-img create -q -f qcow2 -F qcow2 -b "$BACKING" "$WORK/ubuntu-overlay.qcow2"
qemu-img create -q -f qcow2 "$WORK/target.qcow2" 256M
cp "$OVMF_VARS" "$WORK/vars.fd"
cp "$REPO/install/jstack-install.sh" "$WORK/seed/jstack-install.sh"
guestfish --ro -a "$BACKING" -i <<EOF
download /tmp/jstack-bootstrap/bootstrap.tar.zst $WORK/seed/bootstrap.tar.zst
tar-out /tmp/jstack-bootstrap/root.x86_64/var/lib/pacman/sync $WORK/seed/pacman-sync.tar
tar-out /tmp/jstack-bootstrap/root.x86_64/var/cache/pacman/pkg $WORK/seed/pacman-cache.tar
EOF
INSTALLER_SHA="$(sha256sum "$REPO/install/jstack-install.sh" | awk '{print $1}')"

cat > "$WORK/seed/meta-data" <<EOF
instance-id: jstack-preflight-${RANDOM}-$$
local-hostname: jstack-preflight
EOF
cat > "$WORK/seed/user-data" <<'EOF'
#cloud-config
runcmd:
  - [ sh, -c, "mkdir -p /mnt/cidata && mount -o ro LABEL=cidata /mnt/cidata && bash /mnt/cidata/run.sh" ]
EOF
cat > "$WORK/seed/run.sh" <<'GUEST'
#!/bin/bash
set -Eeuo pipefail
exec > >(tee /dev/ttyS0) 2>&1
finish() { sync; poweroff; }
trap finish EXIT
INSTALLER=/mnt/cidata/jstack-install.sh
BOOT_BASE=/tmp/jstack-bootstrap
# /tmp is cleaned during boot, but the backing image retains the downloaded
# bootstrap archive. It may remain only in the overlay's deleted-file blocks,
# so seed a copy from the read-only cidata media when supplied.
if [ ! -x "$BOOT_BASE/root.x86_64/usr/bin/pacman" ] && [ -f /mnt/cidata/bootstrap.tar.zst ]; then
  mkdir -p "$BOOT_BASE"
  tar -C "$BOOT_BASE" --zstd -xpf /mnt/cidata/bootstrap.tar.zst --numeric-owner
  mkdir -p "$BOOT_BASE/root.x86_64/var/lib/pacman/sync" "$BOOT_BASE/root.x86_64/var/cache/pacman/pkg"
  tar -C "$BOOT_BASE/root.x86_64/var/lib/pacman/sync" -xpf /mnt/cidata/pacman-sync.tar
  tar -C "$BOOT_BASE/root.x86_64/var/cache/pacman/pkg" -xpf /mnt/cidata/pacman-cache.tar
fi
BOOT="$BOOT_BASE/root.x86_64"
[ -f "$INSTALLER" ] && [ -x "$BOOT/usr/bin/pacman" ] || { echo 'PREFLIGHT-E2E: missing installer or cached bootstrap'; ls -l "$INSTALLER" "$BOOT/usr/bin/pacman" 2>&1 || true; exit 1; }
echo "PREFLIGHT-E2E: installer_sha=$(sha256sum "$INSTALLER" | awk '{print $1}')"
BEFORE=$(sha256sum /dev/vdb | awk '{print $1}')
echo "PREFLIGHT-E2E: before=$BEFORE"

# Exercise the new argument guards through the same unmodified CLI.
for spec in \
  'invalid-user|--user Bad/User --password x' \
  'invalid-hostname|--user tester --hostname bad_name --password x' \
  'invalid-timezone|--user tester --timezone Mars/Olympus --password x' \
  'missing-seed|--user tester --seed /definitely/missing --password x'; do
  name=${spec%%|*}; args=${spec#*|}
  if "$INSTALLER" --disk /dev/vdb --yes $args >"/tmp/$name.log" 2>&1; then
    echo "PREFLIGHT-E2E: guard-$name=UNEXPECTED_SUCCESS"; exit 1
  fi
  echo "PREFLIGHT-E2E: guard-$name=PASS"
done

# Keep genuine synchronized databases available, but force a real pacman
# package transfer failure after host_prep has refreshed databases/keyring.
cat > /tmp/preflight-mirror.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
sync = Path('/tmp/jstack-bootstrap/root.x86_64/var/lib/pacman/sync')
cache = Path('/tmp/jstack-bootstrap/root.x86_64/var/cache/pacman/pkg')
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        leaf = self.path.rsplit('/', 1)[-1]
        source = sync / leaf
        if leaf.startswith('archlinux-keyring-'):
            matches = list(cache.glob('archlinux-keyring-*.pkg.tar.*'))
            source = matches[0] if matches else source
        if (leaf.endswith(('.db', '.db.sig')) or leaf.startswith('archlinux-keyring-')) and source.is_file():
            data = source.read_bytes(); self.send_response(200)
            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
        else:
            self.send_error(503, 'deliberate package payload outage')
    def log_message(self, fmt, *args): print('MIRROR:', fmt % args, flush=True)
HTTPServer(('127.0.0.1', 18080), H).serve_forever()
PY
python3 /tmp/preflight-mirror.py &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; finish' EXIT
printf 'Server = http://127.0.0.1:18080/$repo/os/$arch\n' > "$BOOT/etc/pacman.d/mirrorlist"
# Ensure at least one requested base package cannot be satisfied from cache.
rm -f "$BOOT"/var/cache/pacman/pkg/vim-[0-9]*.pkg.tar.*

set +e
"$INSTALLER" --disk /dev/vdb --user tester --password test-password --mirror 'http://127.0.0.1:18080/$repo/os/$arch' --yes > /tmp/install.log 2>&1
RC=$?
set -e
cat /tmp/install.log
AFTER=$(sha256sum /dev/vdb | awk '{print $1}')
echo "PREFLIGHT-E2E: installer_rc=$RC"
echo "PREFLIGHT-E2E: after=$AFTER"
[ "$RC" -ne 0 ]
grep -q 'Preflight: downloading base system before modifying the target' /tmp/install.log
grep -Eq 'failed retrieving file|failed to retrieve some files|The requested URL returned error|Service Unavailable' /tmp/install.log
! grep -q 'INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED' /tmp/install.log
[ "$BEFORE" = "$AFTER" ]
echo 'PREFLIGHT-E2E: RESULT=PASS'
GUEST
chmod +x "$WORK/seed/run.sh" "$WORK/seed/jstack-install.sh"
xorriso -as mkisofs -quiet -o "$WORK/seed.iso" -V cidata -J -r "$WORK/seed" >/dev/null 2>&1

set +e
timeout "$TIMEOUT" qemu-system-x86_64 -enable-kvm -cpu host -m "$MEM" -smp "$CPUS" -nographic \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file="$WORK/vars.fd" \
  -drive file="$WORK/ubuntu-overlay.qcow2",if=virtio,format=qcow2 \
  -drive file="$WORK/target.qcow2",if=virtio,format=qcow2 \
  -drive file="$WORK/seed.iso",if=virtio,format=raw,readonly=on \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 -serial mon:stdio >"$WORK/serial.log" 2>&1
QEMU_RC=$?
set -e
# A clean guest poweroff normally makes QEMU return zero. Preserve logs either way.
grep 'PREFLIGHT-E2E:' "$WORK/serial.log" || true
grep -q "PREFLIGHT-E2E: installer_sha=$INSTALLER_SHA" "$WORK/serial.log"
grep -q 'PREFLIGHT-E2E: RESULT=PASS' "$WORK/serial.log" || {
  echo "VM acceptance failed (qemu rc=$QEMU_RC), log: $WORK/serial.log" >&2; exit 1;
}
echo "PASS: real pacman preflight failed and /dev/vdb stayed byte-identical"
echo "Evidence: $WORK/serial.log"
