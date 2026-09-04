#!/usr/bin/env bash
# End-to-end proof: fresh Ubuntu cloud VM runs install/jstack-install.sh against
# a blank disk, then we boot that disk under UEFI and check the result.
#
#   install/vm/test-ubuntu.sh            # full run
#   WORK=/path ... to change scratch dir
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-${JCODE_SCRATCH_DIR:-/tmp}/jstack-ubuntu-e2e}"
UBUNTU_IMG_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
# Allow callers to override the firmware paths, while supporting both the
# Arch/Fedora-style edk2 location and Ubuntu's OVMF package layout.
find_ovmf() {
  for candidate in "$@"; do
    [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}
OVMF_CODE="${OVMF_CODE:-$(find_ovmf /usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/OVMF/OVMF_CODE_4M.fd)}"
OVMF_VARS="${OVMF_VARS:-$(find_ovmf /usr/share/edk2/x64/OVMF_VARS.4m.fd /usr/share/OVMF/OVMF_VARS_4M.fd)}"
MEM="${MEM:-4096}"; CPUS="${CPUS:-4}"
mkdir -p "$WORK"; cd "$WORK"
log() { printf '\033[1;35m[e2e]\033[0m %s\n' "$*"; }

# 1. Ubuntu base image
[ -f noble.img ] || { log "downloading Ubuntu noble cloud image"; curl -fL --retry 3 -o noble.img "$UBUNTU_IMG_URL"; }
rm -f ubuntu.qcow2 target.qcow2
qemu-img create -q -f qcow2 -b noble.img -F qcow2 ubuntu.qcow2 20G
qemu-img create -q -f qcow2 target.qcow2 24G

# 2. Seed ISO: cloud-init + repo tarball
rm -rf seed; mkdir -p seed
tar -C "$REPO" --anchored --no-wildcards-match-slash --exclude=.git --exclude='./installer/*/target' --exclude='./packages/*/pkg' --exclude='./packages/*/src' \
    --exclude='*.pkg.tar.zst' --exclude='./packages/tofi-jstack/tofi' -czf seed/repo.tgz .
cat > seed/meta-data <<'M'
instance-id: jstack-e2e
local-hostname: ubuntu-host
M
cat > seed/user-data <<'U'
#cloud-config
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: ubuntu
runcmd:
  - [ sh, -c, "mkdir -p /mnt/cd && mount -o ro LABEL=cidata /mnt/cd && bash /mnt/cd/run.sh" ]
U
cat > seed/run.sh <<'R'
#!/bin/bash
exec > >(tee /dev/ttyS0) 2>&1
echo "E2E: begin $(date)"
mkdir -p /root/jstack-os && tar -C /root/jstack-os -xzf /mnt/cd/repo.tgz
if /root/jstack-os/install/jstack-install.sh --disk /dev/vdb --user jeremy --password jstack \
     --hostname jstack-vm --yes; then
  echo "E2E: INSTALL_OK"
  T=/mnt/jstack
  sed -i 's/^options \(.*\)/options \1 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info/' $T/boot/loader/entries/jstack.conf
  install -m755 /mnt/cd/check.sh $T/usr/local/bin/jstack-e2e-check
  cat > $T/etc/systemd/system/jstack-e2e-check.service <<'S'
[Unit]
Description=jstack e2e first-boot check
After=multi-user.target home.mount
RequiresMountsFor=/home
[Service]
Type=oneshot
ExecStart=/usr/local/bin/jstack-e2e-check
[Install]
WantedBy=multi-user.target
S
  mkdir -p $T/etc/systemd/system/multi-user.target.wants
  ln -sf /etc/systemd/system/jstack-e2e-check.service $T/etc/systemd/system/multi-user.target.wants/
  umount -R $T
else
  echo "E2E: INSTALL_FAILED rc=$?"
fi
sync
poweroff
R
cat > seed/check.sh <<'C'
#!/bin/bash
exec > /dev/ttyS0 2>&1
echo "E2E-BOOT: hostname=$(cat /etc/hostname)"
echo "E2E-BOOT: user=$(id jeremy)"
echo "E2E-BOOT: shell=$(getent passwd jeremy | cut -d: -f7)"
echo "E2E-BOOT: sudo_nopasswd=$(sudo -n -u jeremy sudo -n true && echo yes || echo no)"
echo "E2E-BOOT: jcode=$(sudo -u jeremy /usr/bin/jcode --version 2>&1 | grep -m1 "^jcode v")"
echo "E2E-BOOT: jcode_fish=$(sudo -u jeremy fish -lc 'jcode --version; echo NOAUTO=$JCODE_NO_AUTO_UPDATE' 2>&1 | grep -E "^jcode v|NOAUTO" | tr "
" " ")"
echo "E2E-BOOT: gh=$(command -v gh)"
echo "E2E-BOOT: kitty_socket_cfg=$(grep -c 'listen_on unix:/tmp/kitty.sock' /home/jeremy/.config/kitty/kitty.conf)"
echo "E2E-BOOT: snapper=$(pacman -Q snapper snap-pac timeshift 2>/dev/null | wc -l)"
echo "E2E-BOOT: snapshots=$(btrfs subvolume list / | grep -c snapshot)"
echo "E2E-BOOT: hook=$(test -f /usr/share/libalpm/hooks/90-jstack-no-snapshots.hook && echo yes)"
echo "E2E-BOOT: fs=$(findmnt -no FSTYPE,OPTIONS /)"
echo "E2E-BOOT: enabled=$(systemctl is-enabled NetworkManager iwd keyd tlp earlyoom bluetooth 2>&1 | tr '\n' ' ')"
echo "E2E-BOOT: default=$(systemctl get-default)"
echo "E2E-BOOT: autologin=$(grep -c autologin /etc/systemd/system/getty@tty1.service.d/autologin.conf)"
echo "E2E-BOOT: pkgs=$(pacman -Q jstack-base jstack-agent jstack-terminals jstack-niri jstack-network jstack-waybar tofi-jstack 2>&1 | tr '\n' ';')"
echo "E2E-BOOT: niri=$(command -v niri) kitty=$(command -v kitty) waybar=$(command -v waybar) tofi=$(command -v tofi)"
echo "E2E-BOOT: DONE"
systemctl poweroff
C
xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r seed >/dev/null 2>&1

cp "$OVMF_VARS" vars-ubuntu.fd; cp "$OVMF_VARS" vars-target.fd
QEMU_BASE=(qemu-system-x86_64 -enable-kvm -cpu host -m "$MEM" -smp "$CPUS" -nographic
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE")

# 3. Phase 1: Ubuntu runs the installer
log "phase 1: booting Ubuntu, running installer (log: $WORK/phase1.log)"
timeout "${PHASE1_TIMEOUT:-5400}" "${QEMU_BASE[@]}" \
  -drive if=pflash,format=raw,file=vars-ubuntu.fd \
  -drive file=ubuntu.qcow2,if=virtio,format=qcow2 \
  -drive file=target.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.iso,if=virtio,format=raw,readonly=on \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio 2>&1 | tee phase1.log | grep --line-buffered -E "E2E|==>|  ->|error|Error|makepkg|Finished making" || true
grep -q "E2E: INSTALL_OK" phase1.log || { log "phase 1 FAILED; see $WORK/phase1.log"; exit 1; }

# 4. Phase 2: boot the installed disk
log "phase 2: booting installed jstack OS (log: $WORK/phase2.log)"
timeout "${PHASE2_TIMEOUT:-600}" "${QEMU_BASE[@]}" \
  -drive if=pflash,format=raw,file=vars-target.fd \
  -drive file=target.qcow2,if=virtio,format=qcow2 \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio 2>&1 | tee phase2.log | grep --line-buffered "E2E-BOOT" || true
grep -q "E2E-BOOT: DONE" phase2.log || { log "phase 2 FAILED; see $WORK/phase2.log"; exit 1; }

fail=0
chk() { grep -q "$1" phase2.log && log "PASS $2" || { log "FAIL $2"; fail=1; }; }
chk "E2E-BOOT: sudo_nopasswd=yes" "passwordless sudo"
chk "E2E-BOOT: jcode=jcode v" "jcode preinstalled"
chk "E2E-BOOT: jcode_fish=jcode v.*NOAUTO=1" "jcode on fish PATH with auto-update disabled"
chk "E2E-BOOT: gh=/usr/bin/gh" "GitHub CLI installed for restored auth"
chk "E2E-BOOT: kitty_socket_cfg=1" "kitty remote-control config"
chk "E2E-BOOT: snapper=0" "no snapper"
chk "E2E-BOOT: hook=yes" "no-snapshot pacman hook"
chk "E2E-BOOT: fs=btrfs" "btrfs root"
chk "E2E-BOOT: shell=/usr/bin/fish" "fish shell"
chk "E2E-BOOT: autologin=1" "tty1 autologin"
exit $fail
