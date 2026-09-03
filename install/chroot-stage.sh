#!/usr/bin/env bash
# Runs inside the freshly pacstrapped target (via arch-chroot). Do not run on a live host.
set -euo pipefail
: "${J_USER:?}" "${J_HOST:?}" "${J_TZ:?}" "${J_LOCALE:?}" "${J_KEYMAP:?}" "${J_PASS:?}"
[ "${J_SKIP_BOOT:-0}" = 1 ] || : "${J_ROOT_PART:?}"
REPO=/usr/src/jstack-os
log() { printf '\033[1;32m  ->\033[0m %s\n' "$*"; }
# Guard: the installer drops this marker into the target before chrooting.
[ -f /.jstack-install-target ] || { echo "refusing: not inside the install chroot" >&2; exit 1; }

log "locale/time/hostname"
ln -sf "/usr/share/zoneinfo/$J_TZ" /etc/localtime; hwclock --systohc || true
sed -i "s/^#\($J_LOCALE\)/\1/" /etc/locale.gen; locale-gen >/dev/null
echo "LANG=$J_LOCALE" > /etc/locale.conf
echo "KEYMAP=$J_KEYMAP" > /etc/vconsole.conf
echo "$J_HOST" > /etc/hostname
printf '127.0.0.1 localhost\n::1 localhost\n127.0.1.1 %s\n' "$J_HOST" > /etc/hosts

log "users"
echo "root:$J_PASS" | chpasswd
id "$J_USER" >/dev/null 2>&1 || useradd -m -G wheel,video,input,audio -s /usr/bin/fish "$J_USER"
echo "$J_USER:$J_PASS" | chpasswd
# Passwordless sudo for the primary user out of the box (agents and scripts
# must never block on a password prompt). Delete this file to require a password.
echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/10-wheel; chmod 440 /etc/sudoers.d/10-wheel
echo "$J_USER ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/15-jstack-nopasswd; chmod 440 /etc/sudoers.d/15-jstack-nopasswd
visudo -cf /etc/sudoers.d/15-jstack-nopasswd >/dev/null
# build user for makepkg (never builds as root)
echo 'builder ALL=(ALL) NOPASSWD: /usr/bin/pacman' > /etc/sudoers.d/20-builder; chmod 440 /etc/sudoers.d/20-builder
id builder >/dev/null 2>&1 || useradd -m -r builder

log "pacman config"
sed -i 's/^#ParallelDownloads.*/ParallelDownloads = 8/; s/^#Color/Color/' /etc/pacman.conf
pacman -Sy --noconfirm >/dev/null

build_and_install() {   # build_and_install <pkgdir>...
  local d out
  for d in "$@"; do
    log "makepkg $(basename "$d")"
    rm -rf /home/builder/build; cp -r "$d" /home/builder/build; chown -R builder /home/builder/build
    (cd /home/builder/build && sudo -u builder makepkg -s --noconfirm --needed --nocheck >.makepkg.log 2>&1) || { grep -vE "^\s*(Compiling|Downloading|Fresh)" /home/builder/build/.makepkg.log | tail -40; exit 1; }
    out=$(ls /home/builder/build/*.pkg.tar.zst | grep -v -- '-debug-' | head -1)
    pacman -U --noconfirm --needed "$out"
  done
}

# tofi-jstack is built from source (github.com/1jehuang/tofi); jstack-niri and
# jstack-network depend on it. --skip-source-pkgs assumes you provide tofi yourself.
if [ "${J_SKIP_SOURCE:-0}" != 1 ]; then
  for p in ${J_SOURCE_PKGS:-}; do build_and_install "$REPO/packages/$p"; done
  for p in ${J_AUR_PKGS:-}; do
    rm -rf "/home/builder/aur-$p"
    sudo -u builder git clone -q --depth 1 "https://aur.archlinux.org/$p.git" "/home/builder/aur-$p"
    build_and_install "/home/builder/aur-$p"
  done
fi
for p in ${J_PKGS:?}; do build_and_install "$REPO/packages/$p"; done

log "systemd presets (jstack-base ships them; snapper timers stay off)"
systemctl preset-all >/dev/null 2>&1 || true
mkdir -p /etc/systemd/system/getty@tty1.service.d
sed "s/%USER%/$J_USER/" /usr/share/jstack/systemd/autologin.conf.in > /etc/systemd/system/getty@tty1.service.d/autologin.conf
systemctl set-default graphical.target >/dev/null

if [ "${J_SKIP_BOOT:-0}" = 1 ]; then
  log "J_SKIP_BOOT=1: skipping initramfs and systemd-boot (container test)"
else
log "initramfs + systemd-boot"
sed -i 's/^MODULES=.*/MODULES=(btrfs)/; s/^HOOKS=.*/HOOKS=(base udev autodetect microcode modconf kms keyboard keymap consolefont block filesystems fsck)/' /etc/mkinitcpio.conf
mkinitcpio -P >/dev/null
bootctl install >/dev/null
PARTUUID=$(blkid -s PARTUUID -o value "$J_ROOT_PART")
printf 'default jstack.conf\ntimeout 1\n' > /boot/loader/loader.conf
cat > /boot/loader/entries/jstack.conf <<E
title   jstack OS
linux   /vmlinuz-linux
initrd  /initramfs-linux.img
options root=PARTUUID=$PARTUUID rootflags=subvol=@ rw rootfstype=btrfs zswap.enabled=0
E
cat > /boot/loader/entries/jstack-fallback.conf <<E
title   jstack OS (fallback initramfs)
linux   /vmlinuz-linux
initrd  /initramfs-linux-fallback.img
options root=PARTUUID=$PARTUUID rootflags=subvol=@ rw rootfstype=btrfs
E
fi

log "seed user config from /etc/skel (packages installed after useradd)"
for f in .config/niri .config/kitty .config/foot .config/tofi .config/waybar .config/fish; do
  [ -e "/etc/skel/$f" ] && [ ! -e "/home/$J_USER/$f" ] && cp -r "/etc/skel/$f" "/home/$J_USER/$f" || true
done
chown -R "$J_USER:$J_USER" "/home/$J_USER"
rm -rf /home/builder/build /.jstack-install-target

if [ -n "${J_SEED:-}" ]; then
  log "restoring seed (ssh, github, tailscale, wifi, jcode)"
  bash "$REPO/install/seed/restore-seed.sh" "$J_SEED" "$J_USER"
  shred -u "$J_SEED" 2>/dev/null || rm -f "$J_SEED"
elif [ -n "${J_JCODE_API_KEY:-}" ]; then
  log "seeding jcode API key"
  # jcode reads API keys from ~/.config/jcode/<provider>.env (KEY=value). Pick
  # the file from the key prefix so the provider is auto-detected on first run.
  case "$J_JCODE_API_KEY" in
    sk-ant-*)  envf=anthropic.env;          envk=ANTHROPIC_API_KEY ;;
    sk-or-*)   envf=openrouter.env;         envk=OPENROUTER_API_KEY ;;
    jck_*)     envf=jcode-subscription.env; envk=JCODE_API_KEY ;;
    sk-*)      envf=openai.env;             envk=OPENAI_API_KEY ;;
    *) echo "unrecognised key prefix; expected sk-ant-*, sk-or-*, sk-*, or jck_*" >&2; exit 1 ;;
  esac
  cfg="/home/$J_USER/.config/jcode"
  install -dm700 -o "$J_USER" -g "$J_USER" "/home/$J_USER/.config" "$cfg"
  printf '%s=%s\n' "$envk" "$J_JCODE_API_KEY" > "$cfg/$envf"
  chown "$J_USER:$J_USER" "$cfg/$envf"; chmod 600 "$cfg/$envf"
fi

log "sanity"
pacman -Q jstack-base jstack-agent jstack-terminals jstack-niri
! pacman -Q snapper snap-pac timeshift >/dev/null 2>&1 || { echo "snapshot tooling present!" >&2; exit 1; }
test -x /usr/bin/jcode && grep -q 'listen_on unix:/tmp/kitty.sock' /etc/skel/.config/kitty/kitty.conf
echo "chroot stage complete"
