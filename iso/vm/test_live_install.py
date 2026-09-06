#!/usr/bin/env python3
"""Bounded, network-less live ISO -> offline install -> installed UEFI VM proof.

Usage: python3 iso/vm/test_live_install.py --iso /absolute/clean.iso \
    --artifacts /absolute/new-proof-directory

Only regular files are accepted. All writable VM disks and firmware variable
stores are newly created under a NEW artifact directory. No host block device,
USB device, directory share, network, or host credential is passed to QEMU.
The ISO is presented as read-only USB mass storage. Never run this as root.
Artifacts are intentionally retained on failure. The installed boot uses fresh
OVMF variables and has neither the ISO nor the refusal fixture disk attached.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid

GIB = 1024 ** 3
PACKAGES = ('linux', 'linux-firmware', 'niri', 'jstack-base', 'jstack-agent',
            'jstack-terminals', 'jstack-network', 'jstack-niri', 'jstack-waybar',
            'jstack-scheduler', 'jstack-firefox', 'jstack-desktop-apps')
USER = 'vmtest'
PASSWORD = 'Jstack-VM-only-4937'
TARGET = '/dev/vda'
FIXTURE = '/dev/vdb'
SOURCE = '/dev/sda'


class ProofError(RuntimeError):
    pass


def regular_file(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise ProofError(f'Only regular files may be attached: {path}')
    return resolved


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def checked_run(args: list[str], timeout: int = 60) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise ProofError(f'{shlex.join(args)} failed ({result.returncode}): {result.stdout}')
    return result.stdout


def disk_args(path: Path, ident: str, fmt: str, readonly: bool = False) -> list[str]:
    path = regular_file(path)
    # JSON avoids commas in filenames turning into additional QEMU options.
    node = {'driver': fmt, 'node-name': ident,
            'file': {'driver': 'file', 'filename': str(path)},
            'read-only': readonly}
    return ['-blockdev', json.dumps(node, separators=(',', ':'))]


def qemu_command(*, code: Path, variables: Path, target: Path, fixture: Path | None,
                 iso: Path | None, serial: Path, qmp: Path, memory: int,
                 acceleration: str) -> list[str]:
    if memory < 2048 or memory > 4096:
        raise ProofError('VM RAM must be between 2048 and 4096 MiB')
    if any(',' in str(p) or '\n' in str(p) for p in (serial, qmp)):
        raise ProofError('QEMU socket paths cannot contain commas or newlines')
    for p in (code, variables, target):
        regular_file(p)
    cmd = ['qemu-system-x86_64', '-name', 'jstack-offline-proof',
           '-machine', f'q35,accel={acceleration}', '-cpu', 'host' if acceleration == 'kvm' else 'max',
           '-m', str(memory), '-smp', '2', '-nic', 'none', '-no-reboot',
           '-device', 'virtio-vga-gl', '-display', 'egl-headless',
           '-chardev', f'socket,id=serial0,path={serial},server=on,wait=off',
           '-serial', 'chardev:serial0', '-qmp', f'unix:{qmp},server=on,wait=off',
           '-monitor', 'none', '-device', 'qemu-xhci,id=xhci',
           '-device', 'usb-kbd,bus=xhci.0', '-device', 'usb-tablet,bus=xhci.0']
    # pflash supports blockdev-backed firmware as well, avoiding option injection.
    cmd += disk_args(code, 'firmware-code', 'raw', True)
    cmd += disk_args(variables, 'firmware-vars', 'raw')
    cmd += ['-machine', 'pflash0=firmware-code,pflash1=firmware-vars']
    cmd += disk_args(target, 'target', 'qcow2')
    cmd += ['-device', f'virtio-blk-pci,drive=target,serial=JSTACKTARGET,bootindex={2 if iso else 1}']
    if fixture:
        cmd += disk_args(fixture, 'fixture', 'qcow2')
        cmd += ['-device', 'virtio-blk-pci,drive=fixture,serial=JSTACKFIXTURE']
    if iso:
        cmd += disk_args(iso, 'liveiso', 'raw', True)
        cmd += ['-device', 'usb-storage,bus=xhci.0,drive=liveiso,removable=on,bootindex=1,serial=JSTACKLIVE']
    return cmd


class Serial:
    def __init__(self, sock: socket.socket, log, process=None):
        self.sock, self.log, self.process = sock, log, process
        self.buffer = ''
        self.sock.settimeout(0.5)

    def send(self, text: str):
        self.sock.sendall(text.encode())

    def expect(self, pattern: str, timeout: float):
        end = time.monotonic() + timeout
        regex = re.compile(pattern)
        while True:
            match = regex.search(self.buffer)
            if match:
                consumed = self.buffer[:match.end()]
                self.buffer = self.buffer[match.end():]
                return match, consumed
            if time.monotonic() >= end:
                raise ProofError(f'Serial timeout waiting for {pattern!r}. See serial log.')
            if self.process and self.process.poll() is not None:
                raise ProofError(f'QEMU exited early: {self.process.returncode}')
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not data:
                raise ProofError('Serial socket closed')
            self.log.write(data)
            self.log.flush()
            self.buffer += data.decode('utf-8', errors='replace').replace('\r', '')

    def bootstrap(self, installed: bool, timeout: int):
        if installed:
            self.expect(r'login:\s*$', timeout)
            self.send(USER + '\n')
            self.expect(r'Password:\s*$', 30)
            self.send(PASSWORD + '\n')
        else:
            self.expect(r'automatic login', timeout)
        # A unique, split marker cannot be mistaken for an echoed command.
        # Confirm both privilege and shell, not just that serial input echoed.
        token = uuid.uuid4().hex
        self.send("sudo -n /bin/bash --noprofile --norc\n")
        self.send("if [ \"$(id -u)\" = 0 ] && [ -n \"$BASH_VERSION\" ]; then "
                  "stty -echo -onlcr; export TERM=dumb PS1=''; "
                  "printf '\\n%s%s\\n' 'READY-' '" + token + "'; fi\n")
        self.expect(r'\nREADY-' + token + r'\n', 60)

    def script(self, label: str, body: str, timeout: int = 120,
               check: bool = True) -> tuple[int, str]:
        token = uuid.uuid4().hex
        path = '/run/jstack-vm-' + token + '.sh'
        encoded = base64.b64encode(body.encode()).decode()
        # Linux canonical TTY input truncates long lines around 4096 bytes.
        self.send(f": > {path}.b64\n")
        for pos in range(0, len(encoded), 700):
            self.send(f"printf %s '{encoded[pos:pos + 700]}' >> {path}.b64\n")
        self.send(f"base64 -d {path}.b64 > {path}; printf '\\nBEGIN-%s\\n' '{token}'; "
                  f"bash {path}; r=$?; rm -f {path} {path}.b64; "
                  f"printf '\\nEND-%s:%s\\n' '{token}' \"$r\"\n")
        self.expect(r'\nBEGIN-' + token + r'\n', 30)
        match, output = self.expect(r'\nEND-' + token + r':([0-9]+)\n', timeout)
        rc = int(match.group(1))
        output = output[:match.start()]
        if check and rc:
            raise ProofError(f'Guest check {label!r} failed with exit {rc}:\n{output[-6000:]}')
        return rc, output


class VM:
    def __init__(self, args, artifacts: Path, phase: str, target: Path,
                 fixture: Path | None = None, iso: Path | None = None):
        self.phase = phase
        self.dir = artifacts / phase
        self.dir.mkdir()
        self.variables = self.dir / 'OVMF_VARS.fd'
        shutil.copyfile(regular_file(args.ovmf_vars), self.variables)
        # Use a short socket directory, since Unix socket paths max out at 108 bytes.
        import tempfile
        self.sockets = Path(tempfile.mkdtemp(prefix='jstack-vm-', dir=args.socket_dir))
        self.serial_path, self.qmp_path = self.sockets / 'serial', self.sockets / 'qmp'
        self.cmd = qemu_command(code=args.ovmf_code, variables=self.variables,
                                target=target, fixture=fixture, iso=iso,
                                serial=self.serial_path, qmp=self.qmp_path,
                                memory=args.memory, acceleration=args.accel)
        (self.dir / 'qemu-command.json').write_text(json.dumps(self.cmd, indent=2) + '\n')
        self.stderr = (self.dir / 'qemu.log').open('wb')
        self.serial_log = (self.dir / 'serial.log').open('wb')
        self.process = None
        self.serial = None

    def __enter__(self):
        self.process = subprocess.Popen(self.cmd, stdin=subprocess.DEVNULL,
                                        stdout=self.stderr, stderr=self.stderr,
                                        start_new_session=True)
        try:
            end = time.monotonic() + 30
            while not self.serial_path.exists():
                if self.process.poll() is not None:
                    raise ProofError(f'QEMU failed to launch. See {self.dir / "qemu.log"}')
                if time.monotonic() > end:
                    raise ProofError('QEMU serial socket creation timed out')
                time.sleep(0.1)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(str(self.serial_path))
            self.serial = Serial(sock, self.serial_log, self.process)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def qmp(self, command: str, arguments: dict | None = None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect(str(self.qmp_path))
            f = sock.makefile('rwb', buffering=0)
            json.loads(f.readline())
            for call in ({'execute': 'qmp_capabilities'},
                         {'execute': command, 'arguments': arguments or {}}):
                f.write((json.dumps(call) + '\n').encode())
                while True:
                    response = json.loads(f.readline())
                    if 'error' in response:
                        raise ProofError(str(response['error']))
                    if 'return' in response:
                        break
            return response['return']

    def screenshot(self, required=False):
        try:
            image = self.dir / 'desktop.ppm'
            self.qmp('screendump', {'filename': str(image)})
            if not image.is_file() or image.stat().st_size < 32:
                raise ProofError('Missing or empty QMP screenshot')
        except Exception as exc:
            (self.dir / 'screenshot-error.txt').write_text(str(exc) + '\n')
            if required:
                raise ProofError(f'Required QMP screenshot failed: {exc}') from exc

    def shutdown(self):
        self.serial.send('systemctl poweroff\n')
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise ProofError('Guest did not power off cleanly within 60 seconds')
        if self.process.returncode:
            raise ProofError(f'QEMU exited with status {self.process.returncode}')

    def __exit__(self, *_):
        if self.process and self.process.poll() is None:
            self.screenshot()
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.serial:
            self.serial.sock.close()
        self.serial_log.close()
        self.stderr.close()
        shutil.rmtree(self.sockets)


def desktop_script(user: str) -> str:
    return f'''set -euo pipefail
uid=$(id -u {shlex.quote(user)})
for attempt in $(seq 1 90); do
  pid=$(pgrep -u "$uid" -x niri | head -n1 || true)
  sock=$(find /run/user/"$uid" -maxdepth 1 -type s -name 'niri*.sock' -print -quit 2>/dev/null || true)
  if [ -n "$pid" ] && [ -n "$sock" ]; then
    if runuser -u {shlex.quote(user)} -- env XDG_RUNTIME_DIR=/run/user/"$uid" NIRI_SOCKET="$sock" niri msg --json outputs > /run/jstack-vm-niri-outputs.json; then
      python3 -c 'import json; x=json.load(open("/run/jstack-vm-niri-outputs.json")); assert isinstance(x, dict) and x, "Niri has no outputs"'
      printf 'NIRI_PROCESS=%s\\n' "$pid"
      cat /run/jstack-vm-niri-outputs.json
      echo NIRI_IPC_OK
      exit 0
    fi
  fi
  sleep 2
done
systemctl --no-pager status getty@tty1.service || true
journalctl -b --no-pager -n 100 _UID="$uid" || true
exit 1
'''


def guest_disk_hash(serial: Serial, device: str, timeout: int) -> str:
    _, output = serial.script('full disk SHA256 ' + device,
                              f'set -euo pipefail\nsync\nsha256sum {shlex.quote(device)}\n', timeout)
    match = re.search(r'(?m)^([a-f0-9]{64})\s+' + re.escape(device) + r'\s*$', output)
    if not match:
        raise ProofError(f'Missing whole-disk hash for {device}: {output}')
    return match.group(1)


def installer_command(args, disk: str, confirmation: str) -> str:
    # This is the real installed ISO command, never a copied or mocked installer.
    return shlex.join([args.installer, '--disk', disk, '--user', USER,
                       '--hostname', 'jstack-vm', '--password-stdin',
                       '--confirm', confirmation, '--serial-console']) + ' < /run/jstack-vm-password'


def refusal(serial: Serial, args, label: str, disk: str, hash_device: str,
            expected_error: str, results: list, token: str | None = None):
    print('JCODE_PROGRESS ' + json.dumps({'phase': 'refusal', 'case': label}), flush=True)
    before = guest_disk_hash(serial, hash_device, args.hash_timeout)
    rc, output = serial.script(label, installer_command(args, disk,
                                'INVALID-UNAUTHORIZED-TEST-TOKEN' if token is None else token),
                                args.refusal_timeout, check=False)
    after = guest_disk_hash(serial, hash_device, args.hash_timeout)
    record = {'case': label, 'disk': disk, 'hashed_device': hash_device,
              'scope': 'entire block device', 'before_sha256': before,
              'after_sha256': after, 'exit_status': rc, 'output': output,
              'expected_error_regex': expected_error}
    results.append(record)
    if rc != 1:
        raise ProofError(f'{label}: installer did not reject safely (exit {rc})')
    if before != after:
        raise ProofError(f'{label}: refused operation CHANGED disk bytes')
    diagnostics = re.findall(r'(?m)^jstack-install-live: REFUSED/FAILED: (.+)$', output)
    record['diagnostics'] = diagnostics
    if len(diagnostics) != 1 or not re.search(expected_error, diagnostics[0], re.IGNORECASE):
        raise ProofError(f'{label}: wrong refusal reason: {output}')
    record['passed'] = True


def installed_script() -> str:
    return '''set -euo pipefail
test -d /sys/firmware/efi
test "$(hostname)" = jstack-vm
if grep -qw archisobasedir /proc/cmdline; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if findmnt -rn -t overlay,squashfs | grep .; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
test "$(findmnt -n -o FSTYPE /)" = btrfs
test "$(findmnt -n -o FSTYPE /boot)" = vfat
findmnt --verify --verbose
cat /etc/fstab
python3 - <<'PY'
from pathlib import Path
lines=[x.split() for x in Path('/etc/fstab').read_text().splitlines() if x.strip() and not x.startswith('#')]
assert any(x[1]=='/' for x in lines)
assert any(x[1]=='/boot' for x in lines)
assert all(x[0].startswith(('UUID=', 'PARTUUID=')) for x in lines), lines
assert not any('archiso' in ' '.join(x) or '/dev/vd' in x[0] or '/dev/sd' in x[0] for x in lines)
PY
pacman -Q ''' + ' '.join(PACKAGES) + '''
test -x /usr/bin/jcode
jcode --version
test -s /boot/vmlinuz-linux
test -s /boot/initramfs-linux.img
test -s /boot/EFI/BOOT/BOOTX64.EFI
bootctl --no-pager status
grep -E '^options .*root=(PARTUUID|UUID)=' /boot/loader/entries/*.conf
if getent passwd jstack; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if test -d /home/jstack; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if test -e /etc/sudoers.d/15-jstack-live; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if test -e /usr/local/lib/jstack-live-setup; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
test "$(readlink /etc/systemd/system/jstack-live-setup.service)" = /dev/null
if test -e /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if test -e /etc/systemd/system/getty@tty2.service.d/autologin.conf; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if systemctl list-unit-files --no-legend | grep -E '^jstack-live[^ ]* .*enabled'; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if grep -R -l 'jstack-live-setup\\|--autologin jstack' /etc/systemd/system 2>/dev/null; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if grep -R -l 'jstack.console=1' /home/vmtest/.config/fish/conf.d 2>/dev/null; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if test -e /etc/mkinitcpio.conf.d/archiso.conf; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if grep -E '^HOOKS=.*archiso' /etc/mkinitcpio.conf; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
if find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | grep .; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
test -s /var/lib/jstack/installed-from-live.json
python3 - <<'PY'
from pathlib import Path
for name in ('/usr/local/bin/jstack-install-live', '/usr/share/applications/jstack-install.desktop',
             '/etc/jstack-live-installer.json', '/etc/systemd/journald.conf.d/volatile-storage.conf',
             '/etc/systemd/logind.conf.d/do-not-suspend.conf',
             '/etc/systemd/system/etc-pacman.d-gnupg.mount'):
    p = Path(name)
    assert not p.exists() and not p.is_symlink(), f'live artifact retained: {p}'
for p in Path('/etc/mkinitcpio.d').glob('*'):
    assert 'archiso' not in p.read_text(), f'live initramfs preset: {p}'
PY
test "$(id -u vmtest)" = 1000
getent passwd vmtest | grep -E '/usr/bin/fish$'
if findmnt -rn -t tmpfs -o TARGET | grep -Fx /etc/pacman.d/gnupg; then echo LIVE_KEYRING_TMPFS >&2; exit 1; fi
for unit in NetworkManager.service fstrim.timer; do systemctl is-enabled "$unit"; done
test "$(readlink /etc/resolv.conf)" = /run/NetworkManager/resolv.conf
echo INSTALLED_SYSTEM_OK
'''


def run(args, artifacts: Path, result: dict):
    iso = regular_file(args.iso)
    result['iso'] = {'path': str(iso), 'size': iso.stat().st_size,
                     'sha256': digest(iso)}
    result['qemu_version'] = checked_run(['qemu-system-x86_64', '--version'])
    result['firmware'] = {str(p): digest(regular_file(p)) for p in (args.ovmf_code, args.ovmf_vars)}
    result['network'] = 'QEMU -nic none for both boots, guest loopback-only assertions'
    result['resources'] = {'memory_mib': args.memory, 'vcpus': 2}
    target, fixture = artifacts / 'target.qcow2', artifacts / 'refusal-fixture.qcow2'
    for disk in (target, fixture):
        checked_run(['qemu-img', 'create', '-f', 'qcow2', str(disk), '40G'])
    result['refusals'] = []
    print('JCODE_PROGRESS ' + json.dumps({'phase': 'live-boot', 'artifacts': str(artifacts)}), flush=True)
    with VM(args, artifacts, 'live', target, fixture, iso) as vm:
        s = vm.serial
        s.bootstrap(False, args.boot_timeout)
        _, output = s.script('live prerequisites', f'''set -euo pipefail
test -d /sys/firmware/efi
test -b {SOURCE}; test -b {TARGET}; test -b {FIXTURE}
test "$(lsblk -dn -o SERIAL {TARGET})" = JSTACKTARGET
test "$(lsblk -dn -o SERIAL {FIXTURE})" = JSTACKFIXTURE
test "$(blockdev --getsize64 {TARGET})" = {40 * GIB}
test "$(blockdev --getsize64 {FIXTURE})" = {40 * GIB}
findmnt /run/archiso/bootmnt
findmnt -n -o SOURCE /run/archiso/bootmnt | grep -E '^/dev/sda[0-9]*$'
if find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo | grep .; then echo NEGATIVE_ASSERTION_FAILED >&2; exit 1; fi
command -v {shlex.quote(args.installer)}
test -s /run/archiso/bootmnt/JSTACK-INSTALL.md
cmp /run/archiso/bootmnt/JSTACK-INSTALL.md /usr/share/doc/jstack-live/INSTALL.md
jstack-install-help | cmp - /usr/share/doc/jstack-live/INSTALL.md
echo ON_USB_HELP_OK
pacman -Q {' '.join(PACKAGES)}
jcode --version
umask 077; printf '%s\\n' {shlex.quote(PASSWORD)} > /run/jstack-vm-password
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
echo LIVE_PREREQUISITES_OK
''')
        result['live_prerequisites'] = output
        _, result['live_desktop'] = s.script('live Niri process and IPC', desktop_script('jstack'), 210)
        vm.screenshot(required=True)
        for label, disk, hashed, regex, token in [
            ('source-boot-disk', SOURCE, SOURCE, r'^(read-only or removable disk refused|USB/external transport refused|target backs a mounted filesystem, live source, or swap|target or descendant is mounted)$', None),
            ('wrong-confirmation', TARGET, TARGET, r'confirmation does not exactly match target identity', 'WRONG-CONFIRMATION'),
        ]:
            refusal(s, args, label, disk, hashed, regex, result['refusals'], token)
        s.script('prepare disposable filesystem fixture', f'''set -euo pipefail
mkfs.ext4 -F -E lazy_itable_init=0,lazy_journal_init=0 {FIXTURE}
''', 180)
        refusal(s, args, 'nonblank-filesystem-disk', FIXTURE, FIXTURE,
                r'filesystem/partition signatures present, blank disks only', result['refusals'])
        s.script('mount disposable fixture read-only', f'''set -euo pipefail
mkdir -p /mnt/jstack-vm-fixture
mount -t ext4 -o ro,noload {FIXTURE} /mnt/jstack-vm-fixture
''')
        refusal(s, args, 'mounted-disk', FIXTURE, FIXTURE,
                r'target or descendant is mounted|target backs a mounted filesystem', result['refusals'])
        s.script('unmount disposable fixture', f'''set -euo pipefail
umount /mnt/jstack-vm-fixture
wipefs --all {FIXTURE}
''')
        s.script('prepare disposable partition fixture', f'''set -euo pipefail
printf 'label: gpt\\n,1G,L\\n' | sfdisk {FIXTURE}
udevadm settle
test -b {FIXTURE}1
''')
        refusal(s, args, 'partition-not-whole-disk', FIXTURE + '1', FIXTURE,
                r'whole|partition|disk type', result['refusals'])
        refusal(s, args, 'nonblank-partitioned-disk', FIXTURE, FIXTURE,
                r'blank|partition|signature|filesystem|existing', result['refusals'])
        print('JCODE_PROGRESS ' + json.dumps({'phase': 'offline-install'}), flush=True)
        _, preflight = s.script('blank target preflight', shlex.join([args.installer, '--check', '--disk', TARGET]), args.refusal_timeout)
        target_info = json.loads(preflight.strip().splitlines()[-1])
        token = target_info['confirmation']
        if not re.fullmatch(r'INSTALL-[a-f0-9]{16}', token):
            raise ProofError('Invalid preflight confirmation token')
        result['target_preflight'] = target_info
        _, result['install_output'] = s.script('offline install',
            installer_command(args, TARGET, token), args.install_timeout)
        if 'JSTACK-INSTALL: complete.' not in result['install_output']:
            raise ProofError('Installer exited without completion marker')
        s.script('remove VM-only password', 'rm -f /run/jstack-vm-password\nsync\n')
        vm.shutdown()
    result['disk_check'] = checked_run(['qemu-img', 'check', '-f', 'qcow2', str(target)], 120)
    print('JCODE_PROGRESS ' + json.dumps({'phase': 'installed-boot-no-iso'}), flush=True)
    with VM(args, artifacts, 'installed', target) as vm:
        vm.serial.bootstrap(True, args.boot_timeout)
        _, result['installed_checks'] = vm.serial.script('installed system checks', installed_script(), 180)
        _, result['installed_desktop'] = vm.serial.script('installed Niri process and IPC', desktop_script(USER), 210)
        vm.screenshot(required=True)
        vm.shutdown()
    result['iso']['sha256_after'] = digest(iso)
    if result['iso']['sha256_after'] != result['iso']['sha256']:
        raise ProofError('Source ISO changed on the host')
    result['disk_check_after_reboot'] = checked_run(['qemu-img', 'check', '-f', 'qcow2', str(target)], 120)
    result['installed_boot'] = {'iso_attached': False, 'fixture_attached': False,
                                'fresh_firmware_variables': True, 'passed': True}


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--iso', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True, help='NEW directory, never reused')
    p.add_argument('--ovmf-code', type=Path, default=Path('/usr/share/edk2/x64/OVMF_CODE.4m.fd'))
    p.add_argument('--ovmf-vars', type=Path, default=Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd'))
    p.add_argument('--memory', type=int, choices=(2048, 3072, 4096), default=3072)
    p.add_argument('--accel', choices=('kvm', 'tcg'), default='kvm')
    p.add_argument('--socket-dir', default=os.environ.get('XDG_RUNTIME_DIR', '/run/user/' + str(os.getuid())))
    p.add_argument('--installer', default='/usr/local/bin/jstack-install-live')
    p.add_argument('--boot-timeout', type=int, default=300)
    p.add_argument('--hash-timeout', type=int, default=300)
    p.add_argument('--refusal-timeout', type=int, default=90)
    p.add_argument('--install-timeout', type=int, default=1800)
    p.add_argument('--total-timeout', type=int, default=3600)
    args = p.parse_args(argv)
    for name in ('boot_timeout', 'hash_timeout', 'refusal_timeout', 'install_timeout', 'total_timeout'):
        if not 1 <= getattr(args, name) <= 3600:
            p.error(name.replace('_', '-') + ' must be between 1 and 3600 seconds')
    return args


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() == 0:
        print('Refusing to run as root. Use your unprivileged KVM-capable account.', file=sys.stderr)
        return 2
    artifacts = args.artifacts.absolute()
    if artifacts.exists() or artifacts.is_symlink():
        print(f'Refusing to reuse artifact path: {artifacts}', file=sys.stderr)
        return 2
    artifacts.mkdir(parents=True, mode=0o700)
    result = {'passed': False, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'artifacts': str(artifacts)}
    status = 1
    def interrupted(signum, frame):
        raise ProofError('Overall VM proof timeout' if signum == signal.SIGALRM else 'VM proof terminated')
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGALRM)}
    signal.alarm(args.total_timeout)
    try:
        run(args, artifacts, result)
        result['passed'] = True
        status = 0
    except (Exception, KeyboardInterrupt) as exc:
        result['failure'] = f'{type(exc).__name__}: {exc}'
        print(result['failure'], file=sys.stderr, flush=True)
    finally:
        signal.alarm(0)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        result['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        (artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(('PASS' if status == 0 else 'FAIL') + ': ' + str(artifacts / 'result.json'), flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
