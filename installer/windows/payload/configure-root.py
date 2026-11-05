#!/usr/bin/env python3
"""Turn an unpacked clean JStack live root into an installable dual-boot root.

Run as root by build-payload.sh:  configure-root.py ROOT KVER ROOT_UUID

Reuses the USB installer's cleanup rules (iso/jstack-install-live.py) so the
Windows-installed system and the USB-installed system have the same policy.
Differences, all forced by booting with Secure Boot on:
  * kernel is the Canonical-signed Ubuntu kernel (modules already copied in)
  * GRUB (Canonical-signed, loaded by the Microsoft-signed shim) reads the
    kernel and initramfs from /boot inside the Btrfs @ subvolume
  * the Arch 'linux' package is removed and ignored so pacman never installs an
    unsigned kernel that firmware would refuse
  * the account is created on first boot from answers the Windows installer
    left on the EFI partition (jstack-firstboot)
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('live', HERE.parents[2] / 'iso/jstack-install-live.py')
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
put, link, remove = live.put, live.link, live.remove

root, kver, root_uuid = Path(sys.argv[1]), sys.argv[2], sys.argv[3]


def chroot(*cmd, input=None):
    r = subprocess.run(['arch-chroot', str(root), *cmd], input=input, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if r.returncode:
        raise SystemExit(f'chroot {cmd}: {r.stdout}')
    return r.stdout


live.marker(root / live.MARKER)
for relative in ('etc/systemd/system', 'etc/systemd/system-generators',
                 'etc/systemd/system-preset', 'etc/systemd/journald.conf.d',
                 'etc/systemd/logind.conf.d', 'etc/mkinitcpio.conf.d', 'etc/mkinitcpio.d',
                 'etc/initcpio', 'etc/udev/rules.d/81-dhcpcd.rules',
                 'etc/NetworkManager/conf.d/20-jstack-live.conf',
                 'etc/sudoers.d/15-jstack-live', 'usr/local/lib/jstack-live-setup',
                 'usr/local/bin/jstack-install-live', live.MARKER,
                 'usr/local/bin/jstack-install-help', 'usr/local/bin/jstack-install-run',
                 'usr/share/applications/jstack-install.desktop',
                 'usr/share/applications/jstack-install-alongside.desktop',
                 'usr/share/applications/jstack-install-help.desktop',
                 'usr/share/doc/jstack-live', 'usr/share/jstack-seed',
                 'root/.automated_script.sh', 'root/.zlogin', 'etc/pacman.d/hooks',
                 'etc/machine-id', 'var/lib/dbus/machine-id', 'boot'):
    remove(root, relative)
for pattern in ('etc/ssh/ssh_host_*', 'etc/NetworkManager/system-connections/*',
                'var/lib/NetworkManager/*', 'var/lib/iwd/*', 'var/lib/systemd/random-seed',
                'var/lib/systemd/credential.secret', 'etc/pacman.d/gnupg', 'var/cache/pacman/pkg/*',
                'home/*', 'root/*', 'root/.*', 'tmp/*', 'var/tmp/*'):
    for p in root.glob(pattern):
        remove(root, p.relative_to(root))
(root / 'boot').mkdir()
(root / 'efi').mkdir(exist_ok=True)
put(root, 'etc/machine-id', '')
link(root, 'var/lib/dbus/machine-id', '/etc/machine-id')
put(root, 'etc/hostname', 'jstack\n')
put(root, 'etc/hosts', '127.0.0.1 localhost\n::1 localhost\n127.0.1.1 jstack\n')
put(root, 'etc/locale.gen', 'en_US.UTF-8 UTF-8\n')
put(root, 'etc/locale.conf', 'LANG=en_US.UTF-8\n')
put(root, 'etc/vconsole.conf', 'KEYMAP=us\n')
put(root, 'etc/pacman.conf',
    '[options]\nArchitecture = auto\nCheckSpace\nColor\nParallelDownloads = 8\n'
    'SigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n'
    '# Secure Boot: the running kernel is the Canonical-signed Ubuntu kernel.\n'
    '# An Arch kernel would be refused by firmware, so never install one.\n'
    'IgnorePkg = linux linux-lts linux-zen linux-hardened\n\n'
    '[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nInclude = /etc/pacman.d/mirrorlist\n')
link(root, 'etc/localtime', '/usr/share/zoneinfo/UTC')
link(root, 'etc/resolv.conf', '/run/NetworkManager/resolv.conf')
put(root, 'etc/motd', 'Jstack OS (dual boot with Windows).\n')
put(root, 'etc/fstab',
    ''.join(f'UUID={root_uuid} {path} btrfs rw,noatime,compress=zstd:3,subvol={sub} 0 0\n'
            for sub, path in (('@', '/'), ('@home', '/home'), ('@log', '/var/log'),
                              ('@pkg', '/var/cache/pacman/pkg'))) +
    '# The shared Windows EFI partition is added by jstack-firstboot.\n')

# Drop the Arch kernel package (its files were replaced by the signed kernel).
if 'linux ' in chroot('pacman', '-Q') or '\nlinux ' in chroot('pacman', '-Q'):
    chroot('pacman', '-Rdd', '--noconfirm', '--dbonly', 'linux')
chroot('depmod', kver)

# Generic initramfs: no autodetect, so it boots on any PC, not the build host.
put(root, 'etc/mkinitcpio.conf',
    'MODULES=(btrfs nvme vmd ahci xhci_pci usbhid hid_generic)\nBINARIES=()\nFILES=()\n'
    'HOOKS=(base udev microcode modconf kms keyboard keymap consolefont block filesystems fsck)\n'
    'COMPRESSION="zstd"\n')
shutil.copyfile(root / f'usr/lib/modules/{kver}/vmlinuz', root / 'boot/vmlinuz')
put(root, 'etc/mkinitcpio.d/jstack-signed.preset',
    f"ALL_kver='{kver}'\nPRESETS=('default')\ndefault_image='/boot/initrd.img'\n")
chroot('mkinitcpio', '-p', 'jstack-signed')

chroot('locale-gen')
put(root, 'etc/sudoers.d/10-wheel', '%wheel ALL=(ALL:ALL) ALL\n', 0o440)
chroot('visudo', '-c')
chroot('systemctl', 'preset-all')
chroot('systemctl', 'enable', *live.ENABLE)
chroot('systemctl', 'mask', *live.LIVE_UNITS, *live.DISABLE)
chroot('systemctl', 'set-default', 'graphical.target')

# First boot: account, Wi-Fi, disk growth, EFI mount, kernel update hook.
for name, mode in (('jstack-firstboot', 0o755), ('jstack-boot-windows', 0o755)):
    shutil.copyfile(HERE / name, root / 'usr/local/bin' / name)
    (root / 'usr/local/bin' / name).chmod(mode)
shutil.copyfile(HERE / 'jstack-firstboot.service', root / 'etc/systemd/system/jstack-firstboot.service')
chroot('systemctl', 'enable', 'jstack-firstboot.service')
put(root, 'usr/share/applications/jstack-boot-windows.desktop',
    '[Desktop Entry]\nType=Application\nName=Restart into Windows\n'
    'Exec=pkexec /usr/local/bin/jstack-boot-windows --reboot\nIcon=system-reboot\nTerminal=false\n')
put(root, 'var/lib/jstack/installed-from-windows.json',
    '{"schema": 1, "kernel": "%s", "root_uuid": "%s", "secure_boot_chain": "ubuntu-shim"}\n'
    % (kver, root_uuid))
print('configured', root)
