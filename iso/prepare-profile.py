#!/usr/bin/env python3
"""Generate a scratch-only Archiso profile. No mounts, disks, or root required."""
import argparse
from pathlib import Path
import shutil
import shlex

PACKAGES = (
    'tofi-jstack', 'jstack-base', 'jstack-agent', 'jstack-terminals',
    'jstack-network', 'jstack-niri', 'jstack-waybar', 'jstack-scheduler',
    'jstack-firefox', 'jstack-desktop-apps', 'vesktop-bin',
)
DISABLED = (
    'systemd-networkd.service', 'systemd-networkd.socket',
    'systemd-networkd-wait-online.service', 'systemd-resolved.service',
    'dbus-org.freedesktop.network1.service', 'dbus-org.freedesktop.resolve1.service',
    'sshd.service', 'sshd.socket', 'cloud-init.target', 'cloud-init-local.service',
    'cloud-init-main.service', 'cloud-init-network.service', 'cloud-config.service',
    'cloud-final.service', 'fstrim.timer',
)
ENABLED = (
    'NetworkManager.service', 'iwd.service', 'bluetooth.service', 'keyd.service',
    'tlp.service', 'earlyoom.service', 'jstack-scx.service',
    'jstack-wifi-boot-recovery.timer', 'jstack-live-setup.service',
)


def parent_dirs(p):
    missing = []
    parent = p.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    p.parent.mkdir(parents=True, exist_ok=True)
    for parent in missing:
        parent.chmod(0o755)


def put(root, path, text, mode=0o644):
    p = root / path.lstrip('/')
    parent_dirs(p)
    if p.is_symlink():
        p.unlink()
    p.write_text(text)
    p.chmod(mode)


def link(root, path, target):
    p = root / path.lstrip('/')
    parent_dirs(p)
    if p.exists() or p.is_symlink():
        p.unlink()
    p.symlink_to(target)


def prepare(work, releng, overlay=None):
    profile = work / 'profile'
    if profile.exists():
        raise ValueError('profile already exists')
    shutil.copytree(releng, profile, symlinks=True)
    root = profile / 'airootfs'
    # Private overlays may contain arbitrary trusted files. Reject special files
    # and symlinks so copying cannot dereference destinations outside airootfs.
    if overlay:
        for p in overlay.rglob('*'):
            if p.is_symlink() or not (p.is_file() or p.is_dir()):
                raise ValueError(f'overlay must contain regular files/directories: {p}')
            dest = root / p.relative_to(overlay)
            for ancestor in [dest, *dest.parents]:
                if ancestor == root:
                    break
                if ancestor.is_symlink():
                    raise ValueError(f'overlay destination is a symlink: {dest}')
        shutil.copytree(overlay, root, dirs_exist_ok=True)

    # Releng includes root login hooks that can execute a script from the kernel
    # command line. Remove them. No cloud-init or automatic installation runs.
    for name in ('root/.zlogin', 'root/.automated_script.sh'):
        (root / name).unlink(missing_ok=True)
    text = (profile / 'profiledef.sh').read_text()
    text = '\n'.join(line for line in text.splitlines() if '["/root/.automated_script.sh"]' not in line) + '\n'
    text += '''
# Jstack live settings. Preserve releng BIOS/UEFI and archiso initramfs hooks.
iso_name="jstack-live"
iso_label="JSTACK_LIVE"
iso_publisher="Jstack OS <https://github.com/1jehuang/jstack-os>"
iso_application="Jstack OS live desktop (no automatic installation)"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '9' '-b' '1M' '-processors' '2' '-mem' '512M')
file_permissions["/usr/local/lib/jstack-live-setup"]="0:0:755"
'''
    (profile / 'profiledef.sh').write_text(text)
    package_file = profile / 'packages.x86_64'
    packages = set(package_file.read_text().splitlines())
    packages -= {'archinstall', 'cloud-init', 'clonezilla', 'systemd-resolvconf'}
    packages.update(PACKAGES)
    package_file.write_text('\n'.join(sorted(packages)) + '\n')
    with (profile / 'pacman.conf').open('a') as f:
        f.write(f'\n[jstack-local]\nSigLevel = Optional TrustAll\nServer = file://{work}/packages\n')
    # The build resolver reads the host mirrorlist unless given an explicit one.
    mirrors = 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\nServer = https://mirrors.kernel.org/archlinux/$repo/os/$arch\n'
    (profile / 'mirrorlist').write_text(mirrors)
    pacman = profile / 'pacman.conf'
    pacman.write_text(pacman.read_text().replace('Include = /etc/pacman.d/mirrorlist', f'Include = {profile}/mirrorlist'))
    (work / 'pacman-cache').mkdir(exist_ok=True)
    pacman.write_text(pacman.read_text().replace('[options]', f'[options]\nCacheDir = {work}/pacman-cache', 1))
    put(root, '/etc/pacman.d/mirrorlist', mirrors)
    put(root, '/etc/hostname', 'jstack-live\n')
    put(root, '/etc/motd', 'Jstack OS live session. No installation runs automatically.\nChanges are volatile. Ctrl+Alt+F2 opens a console. sudo needs no password.\n')
    put(root, '/etc/shadow', 'root:!:14871::::::\n', 0o400)
    put(root, '/etc/cloud/cloud-init.disabled', '')
    put(root, '/etc/NetworkManager/conf.d/20-jstack-live.conf', '[main]\ndns=default\nrc-manager=symlink\n')
    link(root, '/etc/resolv.conf', '/run/NetworkManager/resolv.conf')
    system = root / 'etc/systemd/system'
    for p in system.rglob('*'):
        if p.is_symlink() and p.name in DISABLED:
            p.unlink()
    for unit in DISABLED:
        link(root, f'/etc/systemd/system/{unit}', '/dev/null')
    for unit in ENABLED:
        link(root, f'/etc/systemd/system/multi-user.target.wants/{unit}', f'/usr/lib/systemd/system/{unit}' if unit != 'jstack-live-setup.service' else '../jstack-live-setup.service')
    link(root, '/etc/systemd/system/default.target', '/usr/lib/systemd/system/graphical.target')
    # Keep releng's GPT auto-generator mask: internal ESP/root partitions must
    # not be automatically selected by systemd on this live medium.
    link(root, '/etc/systemd/system-generators/systemd-gpt-auto-generator', '/dev/null')
    put(root, '/etc/systemd/system/jstack-live-setup.service', '''[Unit]
Description=Initialize the ephemeral Jstack live account
After=local-fs.target
Before=systemd-user-sessions.service getty@tty1.service getty@tty2.service serial-getty@ttyS0.service NetworkManager.service iwd.service
[Service]
Type=oneshot
ExecStart=/usr/local/lib/jstack-live-setup
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''')
    put(root, '/usr/local/lib/jstack-live-setup', '''#!/usr/bin/env bash
set -euo pipefail
if ! id jstack >/dev/null 2>&1; then
  useradd -m -U -u 1000 -p '' -G wheel,video,input,audio -s /usr/bin/fish jstack
fi
mkdir -p /home/jstack
cp -rn /etc/skel/. /home/jstack/
chown -R jstack:jstack /home/jstack
chmod 700 /home/jstack
if [ -d /home/jstack/.config/jcode ]; then
  find /home/jstack/.config/jcode -type d -exec chmod 700 {} +
  find /home/jstack/.config/jcode -type f -exec chmod 600 {} +
fi
for private in /etc/NetworkManager/system-connections /var/lib/iwd; do
  if [ -d "$private" ]; then
    chown -R root:root "$private"
    find "$private" -type d -exec chmod 700 {} +
    find "$private" -type f -exec chmod 600 {} +
  fi
done
# Package policy normally execs niri on tty1. This live override can deliberately
# stay in a working shell using the console boot entry or after a GPU failure.
cat > /home/jstack/.config/fish/conf.d/00-jstack-niri-autostart.fish <<'FISH'
if status is-interactive; and test (tty) = /dev/tty1; and not set -q WAYLAND_DISPLAY; and not set -q DISPLAY; and not set -q NIRI_SESSION_AUTOSTARTED
    if not string match -qr '(^| )jstack.console=1( |$)' -- (cat /proc/cmdline)
        set -gx NIRI_SESSION_AUTOSTARTED 1
        niri-session
        echo "Desktop exited. This console remains usable. Run niri-session to retry."
    end
end
FISH
chown jstack:jstack /home/jstack/.config/fish/conf.d/00-jstack-niri-autostart.fish
echo 'JSTACK-LIVE: ready'
''', 0o755)
    put(root, '/etc/sudoers.d/15-jstack-live', 'jstack ALL=(ALL:ALL) NOPASSWD: ALL\n', 0o440)
    for unit in ('getty@tty1', 'getty@tty2', 'serial-getty@ttyS0'):
        put(root, f'/etc/systemd/system/{unit}.service.d/autologin.conf', '''[Unit]
Requires=jstack-live-setup.service
After=jstack-live-setup.service
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin jstack --noclear --keep-baud 115200,38400,9600 %I $TERM
''')
    link(root, '/etc/systemd/system/getty.target.wants/getty@tty2.service', '/usr/lib/systemd/system/getty@.service')
    link(root, '/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service', '/usr/lib/systemd/system/serial-getty@.service')
    # Never copy the large desktop SquashFS into RAM by default. Add a clear
    # console fallback on both firmware paths; normal releng kernel stays generic.
    entries = profile / 'efiboot/loader/entries'
    for p in entries.glob('*.conf'):
        text = p.read_text().replace('Arch Linux install medium', 'Jstack OS live desktop')
        text = '\n'.join(line + ' copytoram=n' if line.startswith('options ') else line for line in text.splitlines()) + '\n'
        p.write_text(text)
    base = next(p for p in sorted(entries.glob('*.conf')) if 'options ' in p.read_text())
    console = base.read_text().replace('Jstack OS live desktop', 'Jstack OS live console (GPU fallback)').replace('sort-key 01', 'sort-key 02')
    console = '\n'.join(line + ' jstack.console=1 nomodeset' if line.startswith('options ') else line for line in console.splitlines()) + '\n'
    (entries / '02-jstack-console.conf').write_text(console)
    syslinux = profile / 'syslinux/archiso_sys-linux.cfg'
    text = syslinux.read_text().replace('Arch Linux install medium', 'Jstack OS live desktop')
    text = text.replace('It allows you to install Arch Linux or perform system maintenance.', 'Starts a volatile live session. No automatic installation.')
    text = '\n'.join(line + ' copytoram=n' if line.startswith('APPEND ') else line for line in text.splitlines()) + '\n'
    text += '''
LABEL jstack-console
MENU LABEL Jstack OS live console (GPU fallback)
LINUX /%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux
INITRD /%INSTALL_DIR%/boot/%ARCH%/initramfs-linux.img
APPEND archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% copytoram=n jstack.console=1 nomodeset
'''
    syslinux.write_text(text)
    # mkarchiso deliberately copies airootfs with --no-preserve=ownership,mode.
    # Bind every overlay path explicitly so private files are private in the
    # SquashFS too, not just after first-boot initialization.
    with (profile / 'profiledef.sh').open('a') as permissions:
        if overlay:
            for source in sorted(overlay.rglob('*')):
                relative = source.relative_to(overlay)
                dest = root / relative
                if not dest.exists() or dest.is_symlink():
                    continue
                name = '/' + relative.as_posix()
                owner = '1000:1000' if name == '/home/jstack' or name.startswith('/home/jstack/') else '0:0'
                mode = dest.stat().st_mode & 0o777
                # A private staging tree often has umask 077. Do not preserve
                # that on shared ancestors or the live user cannot traverse
                # /home or read /etc/passwd even though its own home is owned.
                if dest.is_dir() and name in ('/home', '/etc', '/etc/NetworkManager', '/var', '/var/lib'):
                    mode = 0o755
                if name == '/home/jstack' or name.startswith('/home/jstack/.config/jcode') or name.startswith('/etc/NetworkManager/system-connections') or name.startswith('/var/lib/iwd'):
                    mode = 0o700 if dest.is_dir() else 0o600
                permissions.write(f'file_permissions[{shlex.quote(name)}]={shlex.quote(f"{owner}:{mode:o}")}\n')
        permissions.write('file_permissions["/etc/sudoers.d/15-jstack-live"]="0:0:440"\n')
    return profile


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--releng', type=Path, default=Path('/usr/share/archiso/configs/releng'))
    parser.add_argument('--overlay', type=Path)
    args = parser.parse_args()
    print(prepare(args.work.resolve(), args.releng, args.overlay))
