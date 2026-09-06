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
import struct
import subprocess
import sys
import time
import uuid
import zlib

GIB = 1024 ** 3
PACKAGES = ('linux', 'linux-firmware', 'niri', 'jstack-base', 'jstack-agent',
            'jstack-terminals', 'jstack-network', 'jstack-niri', 'jstack-waybar',
            'jstack-scheduler', 'jstack-firefox', 'jstack-desktop-apps')
USER = 'vmtest'
PASSWORD = 'Jstack-VM-only-4937'
TARGET = '/dev/vda'
FIXTURE = '/dev/vdb'
SOURCE = '/dev/sda'
FISH_PROMPT_READY = r'\x1b\]133;B(?:;[^\x07\x1b]*)?(?:\x07|\x1b\\)'


class ProofError(RuntimeError):
    pass


def progress(message: str, **fields):
    print('JCODE_PROGRESS ' + json.dumps({'message': message, **fields}), flush=True)


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


def validate_png(data: bytes) -> dict:
    """Decode CRC-checked, non-interlaced 8-bit RGB(A), not just PNG magic."""
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ProofError('Native screenshot is not PNG')
    pos, compressed, header, ended = 8, bytearray(), None, False
    while pos + 12 <= len(data):
        size = struct.unpack('>I', data[pos:pos + 4])[0]
        kind, payload = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + size]
        if pos + size + 12 > len(data):
            raise ProofError('Truncated PNG chunk')
        crc = struct.unpack('>I', data[pos + 8 + size:pos + 12 + size])[0]
        if zlib.crc32(kind + payload) & 0xffffffff != crc:
            raise ProofError('PNG CRC mismatch')
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', payload)
        elif kind == b'IDAT':
            compressed.extend(payload)
        elif kind == b'IEND':
            ended = True
            pos += size + 12
            break
        pos += size + 12
    if not ended or pos != len(data) or header is None:
        raise ProofError('Incomplete PNG structure')
    width, height, depth, color, compression, filtering, interlace = header
    if not (320 <= width <= 8192 and 200 <= height <= 8192 and depth == 8
            and color in (2, 6) and (compression, filtering, interlace) == (0, 0, 0)):
        raise ProofError(f'Unsupported or empty screenshot PNG: {header}')
    channels = 3 if color == 2 else 4
    stride = width * channels
    expected = (stride + 1) * height
    if expected > 64 * 1024 * 1024:
        raise ProofError('Screenshot exceeds bounded decode size')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(compressed), expected + 1)
    if len(raw) != expected or not decoder.eof or decoder.unused_data:
        raise ProofError('PNG pixel data size mismatch')
    previous = bytearray(stride)
    pixels = bytearray()
    for y in range(height):
        start = y * (stride + 1)
        filter_type, row = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        if filter_type not in range(5):
            raise ProofError('Invalid PNG scanline filter')
        for x in range(stride):
            a, b, c = (row[x - channels] if x >= channels else 0), previous[x], (previous[x - channels] if x >= channels else 0)
            if filter_type == 1:
                row[x] = (row[x] + a) & 255
            elif filter_type == 2:
                row[x] = (row[x] + b) & 255
            elif filter_type == 3:
                row[x] = (row[x] + (a + b) // 2) & 255
            elif filter_type == 4:
                p = a + b - c
                distances = (abs(p - a), abs(p - b), abs(p - c))
                predictor = (a, b, c)[distances.index(min(distances))]
                row[x] = (row[x] + predictor) & 255
        pixels.extend(row)
        previous = row
    first = pixels[:channels]
    if not any(pixels[x:x + channels] != first for x in range(0, len(pixels), channels)):
        raise ProofError('Screenshot contains only one flat color')
    return {'width': width, 'height': height, 'decoded_pixel_bytes': len(pixels),
            'pixel_sha256': hashlib.sha256(pixels).hexdigest()}


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
           '-machine', f'q35,smm=on,accel={acceleration}',
           '-global', 'driver=cfi.pflash01,property=secure,value=on',
           '-cpu', 'host' if acceleration == 'kvm' else 'max',
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
        # login's banner is not shell readiness. Fish probes terminal features
        # during startup and consumes queued input as probe replies. OSC 133 B
        # is emitted only after the prompt is complete and command input is safe.
        # This applies equally to live autologin and installed password login.
        self.expect(FISH_PROMPT_READY, 60)
        # A unique, split marker cannot be mistaken for an echoed command.
        # Confirm both privilege and shell, not just that serial input echoed.
        token = uuid.uuid4().hex
        self.send("sudo -n /usr/bin/env PS1='JSTACK-BASH-''READY> ' /bin/bash --noprofile --norc\n")
        self.expect(re.escape('JSTACK-BASH-READY> '), 30)
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

    def capture_desktop(self, user: str) -> dict:
        # egl-headless/virgl can expose a real compositor output without a QMP
        # readback surface. Retain that diagnostic, then require a native render
        # capture, actual application IPC witness, and verified PNG pixels.
        self.qmp('send-key', {'keys': [{'type': 'qcode', 'data': 'esc'}]})
        token = uuid.uuid4().hex
        _, output = self.serial.script('native desktop application screenshot',
                                        screenshot_script(user, token, self.phase), 120)
        witness = re.search(r'APP_PROOF_BEGIN\n(.*?)\nAPP_PROOF_END', output, re.S)
        encoded = re.search(r'CAPTURE_PNG_BEGIN\n(.*?)\nCAPTURE_PNG_END', output, re.S)
        checksum = re.search(r'(?m)^CAPTURE_SHA256=([a-f0-9]{64})$', output)
        if not witness or not encoded or not checksum:
            raise ProofError('Missing native capture data, application witness or checksum')
        image = base64.b64decode(''.join(encoded[1].split()), validate=True)
        actual = hashlib.sha256(image).hexdigest()
        if actual != checksum[1]:
            raise ProofError('Native screenshot guest/host SHA256 mismatch')
        info = validate_png(image)
        (self.dir / 'desktop.png').write_bytes(image)
        info.update({'backend': 'niri-ipc-screenshot-screen', 'sha256': actual,
                     'guest_sha256': checksum[1], 'application': json.loads(witness[1]),
                     'file': str(self.dir / 'desktop.png')})
        self.screenshot()
        error = self.dir / 'screenshot-error.txt'
        info['qmp'] = {'captured': not error.exists(),
                       'error': error.read_text().strip() if error.exists() else None}
        (self.dir / 'screenshot.json').write_text(json.dumps(info, indent=2) + '\n')
        return info

    def shutdown(self):
        started = time.monotonic()
        deadline = started + 60
        progress(f'Powering off {self.phase} VM', phase='shutdown', vm_phase=self.phase)
        self.serial.send('systemctl poweroff\n')
        try:
            while self.process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ProofError('Guest did not power off cleanly within 60 seconds. See drained serial shutdown log.')
                try:
                    data = self.serial.sock.recv(65536)
                except socket.timeout:
                    continue
                if data:
                    self.serial.log.write(data)
                    self.serial.log.flush()
                else:
                    try:
                        self.process.wait(timeout=min(1, max(0.01, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        pass
            # Process exit may race the last UART bytes already in the socket.
            while True:
                try:
                    data = self.serial.sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                self.serial.log.write(data)
                self.serial.log.flush()
            if self.process.returncode:
                raise ProofError(f'QEMU exited with status {self.process.returncode}')
        finally:
            (self.dir / 'shutdown.json').write_text(json.dumps({
                'elapsed_seconds': time.monotonic() - started,
                'qemu_exit_status': self.process.poll(), 'deadline_seconds': 60,
                'serial_drained': True}, indent=2) + '\n')

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


def screenshot_script(user: str, token: str, phase: str) -> str:
    app = 'jstack-vm-proof-' + token
    return f'''set -euo pipefail
uid=$(id -u {shlex.quote(user)})
sock=$(find /run/user/"$uid" -maxdepth 1 -type s -name 'niri*.sock' -print -quit 2>/dev/null || true)
test -S "$sock"
niri_user() {{ runuser -u {shlex.quote(user)} -- env XDG_RUNTIME_DIR=/run/user/"$uid" NIRI_SOCKET="$sock" niri "$@"; }}
path=/run/user/"$uid"/jstack-vm-{token}.png
test ! -e "$path"
niri_user msg action spawn -- foot --app-id={app} --title='Jstack VM render proof' /bin/sh -c 'printf "JSTACK VM {phase.upper()} NIRI RENDER PROOF\\nOffline guest. Actual terminal window.\\n"; sleep 180'
for attempt in $(seq 1 100); do
  niri_user msg --json windows > /run/jstack-vm-{token}-windows.json
  niri_user msg --json workspaces > /run/jstack-vm-{token}-workspaces.json
  if python3 - <<'PY' > /run/jstack-vm-{token}-witness.json
import json
windows=json.load(open('/run/jstack-vm-{token}-windows.json'))
workspaces=json.load(open('/run/jstack-vm-{token}-workspaces.json'))
matches=[w for w in windows if w.get('app_id') == '{app}']
assert len(matches) == 1
w=matches[0]
assert w.get('is_focused') is True
active=[x for x in workspaces if x['id'] == w.get('workspace_id') and x.get('is_active') and x.get('output')]
assert len(active) == 1
print(json.dumps({{'window':w, 'workspace':active[0]}}))
PY
  then break; fi
  sleep .1
done
test -s /run/jstack-vm-{token}-witness.json
niri_user msg action screenshot-screen --show-pointer false --path "$path"
for attempt in $(seq 1 100); do
  if test -s "$path" && [ "$(tail -c 12 "$path" | base64 -w 0)" = AAAAAElFTkSuQmCC ]; then break; fi
  sleep .1
done
test -s "$path"
echo APP_PROOF_BEGIN
cat /run/jstack-vm-{token}-witness.json
echo APP_PROOF_END
printf 'CAPTURE_SHA256=%s\\n' "$(sha256sum "$path" | cut -d ' ' -f 1)"
echo CAPTURE_PNG_BEGIN
base64 -w 76 "$path"
echo CAPTURE_PNG_END
rm -f "$path" /run/jstack-vm-{token}-windows.json /run/jstack-vm-{token}-workspaces.json /run/jstack-vm-{token}-witness.json
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
    progress(f'Checking refusal: {label}', phase='refusal', case=label)
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


def firmware_script() -> str:
    return '''set -euo pipefail
python3 - <<'PY'
from pathlib import Path
base = Path('/sys/firmware/efi/efivars')
guid = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
for name, expected in (('SecureBoot', 0), ('SetupMode', 1)):
    data = (base / f'{name}-{guid}').read_bytes()
    assert len(data) == 5, f'{name}: malformed EFI variable'
    assert data[4] == expected, f'{name}: expected {expected}, got {data[4]}'
    print(f'UEFI_{name}={data[4]}')
PY
'''


def installed_policy_script() -> str:
    return '''set -euo pipefail
python3 - <<'PY'
import json, re, subprocess
from pathlib import Path
errors, facts = [], {}
def check(ok, message):
    if not ok: errors.append(message)
def command(*args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
def mount(path, exact=True):
    result = command('findmnt', '--json', '--mountpoint' if exact else '--target', path,
                     '--output', 'TARGET,FSTYPE,FSROOT,UUID,OPTIONS')
    check(result.returncode == 0, 'missing exact mount: ' + path)
    rows = json.loads(result.stdout).get('filesystems', []) if result.returncode == 0 else []
    check(len(rows) == 1, 'ambiguous mount: ' + path)
    return rows[0] if len(rows) == 1 else {}
mounts = {path: mount(path) for path in ('/', '/home', '/var/log', '/var/cache/pacman/pkg')}
root_uuid = mounts['/'].get('uuid')
check(bool(root_uuid), 'root filesystem UUID missing')
for path, subvol in (('/', '/@'), ('/home', '/@home'), ('/var/log', '/@log'), ('/var/cache/pacman/pkg', '/@pkg')):
    row = mounts[path]
    check(row.get('target') == path and row.get('fsroot') == subvol, 'wrong mount/subvolume: ' + path)
    check(row.get('fstype') == 'btrfs' and row.get('uuid') == root_uuid, 'wrong filesystem/UUID: ' + path)
    check(any(x == 'compress=zstd' or x.startswith('compress=zstd:') for x in row.get('options', '').split(',')),
          'missing zstd compression: ' + path)
entries = [line.split() for line in Path('/etc/fstab').read_text().splitlines() if line.strip() and not line.lstrip().startswith('#')]
for path in mounts:
    rows = [row for row in entries if row[1] == path]
    check(len(rows) == 1 and rows[0][0] == 'UUID=' + str(root_uuid), 'fstab/root UUID disagreement: ' + path)
facts['mounts'] = mounts
machine_id = Path('/etc/machine-id').read_text().strip()
check(bool(re.fullmatch('[0-9a-f]{32}', machine_id)) and machine_id != '0' * 32, 'invalid machine-id')
facts['machine_id_valid'] = bool(re.fullmatch('[0-9a-f]{32}', machine_id))
root_rows = [line.split(':') for line in Path('/etc/shadow').read_text().splitlines() if line.startswith('root:')]
locked = len(root_rows) == 1 and root_rows[0][1].startswith(('!', '*'))
check(locked, 'root account must remain locked')
facts['root_locked'] = locked
keyring_mount = mount('/etc/pacman.d/gnupg', exact=False)
check(keyring_mount.get('fstype') == 'btrfs' and keyring_mount.get('uuid') == root_uuid, 'keyring is not persistent on root filesystem')
keys = command('gpg', '--batch', '--no-auto-check-trustdb', '--no-autostart', '--homedir',
               '/etc/pacman.d/gnupg', '--with-colons', '--list-keys')
key_count = sum(line.startswith('pub:') for line in keys.stdout.splitlines())
check(keys.returncode == 0 and key_count > 1, 'persistent public keyring is not populated')
facts['public_key_count'] = key_count
facts['keyring_mount'] = keyring_mount
active = command('systemctl', 'is-active', 'NetworkManager.service')
check(active.returncode == 0 and active.stdout.strip() == 'active', 'NetworkManager is not active')
facts['NetworkManager'] = active.stdout.strip()
masks = {}
for unit in ('systemd-networkd.service', 'systemd-networkd.socket', 'systemd-resolved.service',
             'systemd-networkd-varlink-metrics.socket', 'systemd-networkd-varlink.socket',
             'systemd-networkd-resolve-hook.socket', 'systemd-resolved-monitor.socket',
             'systemd-resolved-varlink.socket'):
    state = command('systemctl', 'is-enabled', unit).stdout.strip()
    masks[unit] = state
    check(state == 'masked', 'backend/socket not masked: ' + unit + ' (' + state + ')')
facts['masks'] = masks
failed = command('systemctl', '--failed', '--no-legend', '--plain', '--no-pager')
check(failed.returncode == 0, 'failed-unit inventory unavailable')
units = [line.split()[0] for line in failed.stdout.splitlines() if line.strip()]
facts['failed_units'] = units
check(not units, 'unexpected failed units: ' + ', '.join(units))
print('INSTALLED_POLICY_FACTS=' + json.dumps(facts, sort_keys=True))
if units:
    print('FAILED_UNIT_JOURNAL_BEGIN')
    journal = command('journalctl', '-b', '--no-pager', '-n', '100', *[part for unit in units for part in ('-u', unit)])
    print(journal.stdout)
    print('FAILED_UNIT_JOURNAL_END')
assert not errors, '; '.join(errors)
PY
'''


def installed_script() -> str:
    # hostname belongs to inetutils, which is not part of the installed image.
    # Check all external probe tools up front, including those inside negative
    # assertions where an unavailable command could otherwise look like absence.
    return '''set -euo pipefail
for tool in python3 findmnt cat grep pacman jcode bootctl getent readlink find lsblk id systemctl pgrep head seq runuser niri sleep journalctl foot tail base64 sha256sum cut gpg; do
    command -v "$tool" >/dev/null || { printf 'Required installed probe tool missing: %s\\n' "$tool" >&2; exit 1; }
done
''' + firmware_script() + '''set -euo pipefail
test -d /sys/firmware/efi
test "$(cat /proc/sys/kernel/hostname)" = jstack-vm
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
''' + installed_policy_script() + '\necho INSTALLED_SYSTEM_OK\n'


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
    progress('Booting live ISO under UEFI', phase='live-boot', artifacts=str(artifacts))
    with VM(args, artifacts, 'live', target, fixture, iso) as vm:
        s = vm.serial
        s.bootstrap(False, args.boot_timeout)
        _, output = s.script('live prerequisites', f'''set -euo pipefail
test -d /sys/firmware/efi
{firmware_script()}
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
        result['live_screenshot'] = vm.capture_desktop('jstack')
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
        progress('Installing offline to disposable blank disk', phase='offline-install')
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
    progress('Booting installed system without ISO', phase='installed-boot-no-iso')
    with VM(args, artifacts, 'installed', target) as vm:
        vm.serial.bootstrap(True, args.boot_timeout)
        _, result['installed_checks'] = vm.serial.script('installed system checks', installed_script(), 180)
        _, result['installed_desktop'] = vm.serial.script('installed Niri process and IPC', desktop_script(USER), 210)
        result['installed_screenshot'] = vm.capture_desktop(USER)
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
    p.add_argument('--ovmf-code', type=Path, default=Path('/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd'))
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
