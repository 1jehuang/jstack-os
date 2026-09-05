#!/usr/bin/env bash
# End-to-end proof: fresh Ubuntu cloud VM runs install/jstack-install.sh against
# a blank disk, then we boot that disk under UEFI and check the result.
#
#   install/vm/test-ubuntu.sh            # full run
#   WORK=/path ... to change scratch dir
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${WORK:-${JCODE_SCRATCH_DIR:-/tmp}/jstack-ubuntu-e2e-$(date +%s)-$$}"
MIN_FREE_GIB="${MIN_FREE_GIB:-12}"
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
log() { printf '\033[1;35m[e2e]\033[0m %s\n' "$*"; }
die() { log "REFUSED: $*" >&2; exit 1; }
MEM="${MEM:-4096}"; CPUS="${CPUS:-4}"

# A successful run has historically consumed about 8 GiB despite sparse qcow2
# disks. Keep a margin for package churn and never overwrite a prior proof run.
case "$MIN_FREE_GIB" in ''|*[!0-9]*) die "MIN_FREE_GIB must be a non-negative integer" ;; esac
[ ! -e "$WORK" ] || die "WORK already exists; choose a new path (preserving $WORK)"
work_parent=$(dirname "$WORK")
mkdir -p "$work_parent"
free_kib=$(df -Pk "$work_parent" | awk 'NR == 2 {print $4}')
need_kib=$((MIN_FREE_GIB * 1024 * 1024))
[ "$free_kib" -ge "$need_kib" ] || die "insufficient free space at $work_parent: need ${MIN_FREE_GIB} GiB, have $((free_kib / 1024 / 1024)) GiB"
for tool in cargo curl qemu-img qemu-system-x86_64 tar xorriso timeout; do
  command -v "$tool" >/dev/null || die "required tool not found: $tool"
done
mkdir "$WORK"; cd "$WORK"

# 1. Ubuntu base image
[ -f noble.img ] || { log "downloading Ubuntu noble cloud image"; curl -fL --retry 3 -o noble.img "$UBUNTU_IMG_URL"; }
qemu-img create -q -f qcow2 -b noble.img -F qcow2 ubuntu.qcow2 50G
qemu-img create -q -f qcow2 target.qcow2 24G

log "building static transactional controller"
(cd "$REPO/installer/controller" && cargo build --release --target x86_64-unknown-linux-musl --bin jstack-ubuntu-installer)
cp "$REPO/installer/controller/target/x86_64-unknown-linux-musl/release/jstack-ubuntu-installer" seed-controller

# 2. Seed ISO: cloud-init + repo tarball
mkdir seed
tar -C "$REPO" --anchored --no-wildcards-match-slash --exclude=.git --exclude='./installer/*/target' --exclude='./packages/*/pkg' --exclude='./packages/*/src' \
    --exclude='*.pkg.tar.zst' --exclude='./packages/tofi-jstack/tofi' -czf seed/repo.tgz .
install -m755 seed-controller seed/jstack-ubuntu-installer
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
if JSTACK_UBUNTU_INSTALLER=/mnt/cd/jstack-ubuntu-installer \
   /root/jstack-os/install/jstack-install.sh --disk /dev/disk/by-id/virtio-JSTACK_TARGET_01 \
     --state-dir /var/lib/jstack-installer --user jeremy --password jstack \
     --hostname jstack-vm --serial-console --yes; then
  echo "E2E: INSTALL_OK"
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
echo "E2E-BOOT: subvolumes=$(btrfs subvolume list / | awk '{print $NF}' | tr '\n' ' ')"
echo "E2E-BOOT: enabled=$(systemctl is-enabled NetworkManager iwd keyd tlp earlyoom bluetooth 2>&1 | tr '\n' ' ')"
echo "E2E-BOOT: scheduler=$(systemctl is-enabled jstack-scx.service)"
echo "E2E-BOOT: default=$(systemctl get-default)"
echo "E2E-BOOT: autologin=$(grep -c autologin /etc/systemd/system/getty@tty1.service.d/autologin.conf)"
echo "E2E-BOOT: pkgs=$(pacman -Q jstack-base jstack-agent jstack-terminals jstack-niri jstack-network jstack-waybar jstack-scheduler jstack-firefox jstack-desktop-apps tofi-jstack 2>&1 | tr '\n' ';')"
echo "E2E-BOOT: desktop=niri:$(command -v niri),kitty:$(command -v kitty),foot:$(command -v foot),waybar:$(command -v waybar),tofi:$(command -v tofi),dunst:$(command -v dunst)"
echo "E2E-BOOT: tlp_policy=$(grep -v '^#' /etc/tlp.d/10-jstack.conf | grep '=' | tr '\n' ' ')"
echo "E2E-BOOT: network=$(grep -c '^wifi.backend=iwd$' /etc/NetworkManager/conf.d/jstack-wifi.conf) keyd=$(test -f /etc/keyd/default.conf && echo yes)"
echo "E2E-BOOT: boot_timeout=$(awk '$1 == "timeout" {print $2}' /boot/loader/loader.conf) fallback=$(test -f /boot/loader/entries/jstack-fallback.conf && echo yes)"
echo "E2E-BOOT: fstab_stable=$(awk '$1 !~ /^#/ && $1 ~ /^\/dev\// {bad=1} END {print bad ? "no" : "yes"}' /etc/fstab)"
echo "E2E-BOOT: mirror_servers=$(grep -c '^Server = ' /etc/pacman.d/mirrorlist)"
echo "E2E-BOOT: DONE"
systemctl poweroff
C
xorriso -as mkisofs -quiet -o seed.iso -V cidata -J -r seed >/dev/null 2>&1

cp "$OVMF_VARS" vars-ubuntu.fd; cp "$OVMF_VARS" vars-target.fd
QEMU_BASE=(qemu-system-x86_64 -enable-kvm -cpu host -m "$MEM" -smp "$CPUS"
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE")

# 3. Phase 1: Ubuntu runs the installer
log "phase 1: booting Ubuntu, running installer (log: $WORK/phase1.log)"
timeout "${PHASE1_TIMEOUT:-5400}" "${QEMU_BASE[@]}" \
  -nographic \
  -drive if=pflash,format=raw,file=vars-ubuntu.fd \
  -drive file=ubuntu.qcow2,if=none,id=recovery,format=qcow2 \
  -device virtio-blk-pci,drive=recovery,serial=JSTACK_RECOVERY_01,bootindex=1 \
  -drive file=target.qcow2,if=none,id=target,format=qcow2 \
  -device virtio-blk-pci,drive=target,serial=JSTACK_TARGET_01 \
  -drive file=seed.iso,if=virtio,format=raw,readonly=on \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -serial mon:stdio 2>&1 | tee phase1.log | grep --line-buffered -E "E2E|==>|  ->|error|Error|makepkg|Finished making" || true
grep -q "E2E: INSTALL_OK" phase1.log || { log "phase 1 FAILED; see $WORK/phase1.log"; exit 1; }

# 4. Phase 2: boot the installed disk
log "phase 2: booting installed jstack OS (log: $WORK/phase2.log)"
mkfifo phase2.in
exec 9<>phase2.in
timeout "${PHASE2_TIMEOUT:-600}" "${QEMU_BASE[@]}" \
  -drive if=pflash,format=raw,file=vars-target.fd \
  -drive file=target.qcow2,if=none,id=installed,format=qcow2 \
  -device virtio-blk-pci,drive=installed,serial=JSTACK_TARGET_01,bootindex=1 \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -display none -monitor none -serial stdio <&9 >phase2.log 2>&1 &
phase2_pid=$!
wait_for_log() {
  local pattern=$1 limit=${2:-300} i
  for ((i=0; i<limit; i++)); do
    grep -q "$pattern" phase2.log 2>/dev/null && return 0
    kill -0 "$phase2_pid" 2>/dev/null || return 1
    sleep 1
  done
  return 1
}
wait_for_log 'jstack-vm login:' 300 || { log "installed system did not reach serial login"; kill "$phase2_pid" 2>/dev/null || true; exit 1; }
printf 'jeremy\n' >&9
wait_for_log 'Password:' 30 || { log "serial login did not request password"; kill "$phase2_pid" 2>/dev/null || true; exit 1; }
printf 'jstack\n' >&9
sleep 2
check_b64=$(base64 -w0 seed/check.sh)
printf "echo '%s' | base64 -d | sudo bash\n" "$check_b64" >&9
wait "$phase2_pid" || true
exec 9>&-
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
chk "E2E-BOOT: subvolumes=.*@home.*@log.*@pkg" "btrfs policy subvolumes"
chk "E2E-BOOT: shell=/usr/bin/fish" "fish shell"
chk "E2E-BOOT: autologin=1" "tty1 autologin"
chk "E2E-BOOT: enabled=enabled enabled enabled enabled enabled enabled" "base services enabled"
chk "E2E-BOOT: scheduler=enabled" "sched_ext service enabled"
chk "E2E-BOOT: default=graphical.target" "graphical default target"
chk "E2E-BOOT: pkgs=.*jstack-scheduler.*jstack-firefox.*jstack-desktop-apps" "all jstack policy packages installed"
chk "E2E-BOOT: desktop=niri:/usr/bin/niri,kitty:/usr/bin/kitty,foot:/usr/bin/foot,waybar:/usr/bin/waybar,tofi:/usr/bin/tofi,dunst:/usr/bin/dunst" "desktop commands installed"
chk "E2E-BOOT: tlp_policy=.*CPU_SCALING_GOVERNOR_ON_AC=powersave.*CPU_SCALING_GOVERNOR_ON_BAT=powersave.*CPU_ENERGY_PERF_POLICY_ON_AC=performance.*CPU_ENERGY_PERF_POLICY_ON_BAT=balance_power" "TLP power policy"
chk "E2E-BOOT: network=1 keyd=yes" "NetworkManager iwd backend and keyd policy"
chk "E2E-BOOT: boot_timeout=1 fallback=yes" "systemd-boot timeout and fallback entry"
chk "E2E-BOOT: fstab_stable=yes" "UUID-based fstab survives disk renumbering"
chk "E2E-BOOT: mirror_servers=[1-9]" "working mirrorlist propagated into target"
exit $fail
