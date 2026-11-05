#!/usr/bin/env python3
"""Disposable Windows 11 VM lab for the JStack Windows installer.

Everything lives under $JCODE_SCRATCH_DIR/jstack-windows-vm (override with
JSTACK_WINVM). Only regular files are used as disks. No host block device is
ever attached.

  lab.py build-base            unattended Windows 11 install into base.qcow2
  lab.py up NAME [--fresh]     boot overlay NAME.qcow2 (Secure Boot on, MS keys,
                               TPM 2.0) with the command agent server
  lab.py ps NAME 'script'      run PowerShell in the guest, print output
  lab.py put NAME FILE         make FILE downloadable by the guest at /files/
  lab.py screenshot NAME OUT   PPM screendump of the guest display
  lab.py down NAME             power off
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
LAB = Path(os.environ.get('JSTACK_WINVM') or
           Path(os.environ.get('JCODE_SCRATCH_DIR', '/tmp')) / 'jstack-windows-vm')
ISO = Path(os.environ.get('JSTACK_WIN_ISO') or LAB / 'media/win11-ltsc-eval.iso')
OVMF_CODE = Path('/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd')
OVMF_VARS = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
DISK_GIB = 80
AGENT_PORT_BASE = 8765


def sh(*args, **kw):
    return subprocess.run([str(a) for a in args], check=True, **kw)


def ms_vars(dest: Path):
    """Microsoft-production PK/KEK/db, Secure Boot enabled, CustomMode off."""
    sh('virt-fw-vars', '-i', OVMF_VARS, '-o', dest, '--enroll-microsoft',
       '--microsoft-db', 'all', '--microsoft-kek', 'all', '--sb',
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def answer_image(dest: Path, bitlocker: bool):
    csize = DISK_GIB * 1024 - 100 - 16 - 1024 - 2
    xml = (HERE / 'autounattend.xml.in').read_text()
    xml = xml.replace('@CSIZE_MB@', str(csize)).replace('@PREVENT_BITLOCKER@', '0' if bitlocker else '1')
    stage = dest.with_suffix('.d')
    stage.mkdir(exist_ok=True)
    (stage / 'autounattend.xml').write_text(xml)
    for name in ('lab-setup.ps1', 'lab-agent.ps1'):
        shutil.copyfile(HERE / name, stage / name)
    sh('truncate', '-s', '16M', dest)
    sh('mkfs.fat', '-n', 'LABANS', dest, stdout=subprocess.DEVNULL)
    for f in stage.iterdir():
        sh('mcopy', '-i', dest, f, '::/' + f.name)


def tpm_start(state: Path) -> Path:
    state.mkdir(exist_ok=True)
    sock = state / 'swtpm.sock'
    if sock.exists():
        sock.unlink()
    subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state}',
                      '--ctrl', f'type=unixio,path={sock}', '--terminate'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if sock.exists():
            return sock
        time.sleep(0.1)
    raise SystemExit('swtpm did not start')


def qemu_args(name: str, disk: Path, vars_fd: Path, tpm_sock: Path, extra=(), port=None):
    mon = LAB / f'{name}.mon'
    net = 'user,id=n0'
    args = ['qemu-system-x86_64', '-name', name, '-machine', 'q35,smm=on,accel=kvm',
            '-cpu', 'host', '-smp', '4', '-m', '6144',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-global', 'ICH9-LPC.disable_s3=1',
            '-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}',
            '-drive', f'if=pflash,format=raw,unit=1,file={vars_fd}',
            '-chardev', f'socket,id=chrtpm,path={tpm_sock}',
            '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm', '-device', 'tpm-crb,tpmdev=tpm0',
            '-drive', f'file={disk},if=none,id=sys,format=qcow2,cache=unsafe,discard=unmap',
            '-device', 'nvme,drive=sys,serial=JSTACKLAB0001,bootindex=1',
            '-netdev', net, '-device', 'e1000e,netdev=n0',
            '-usb', '-device', 'usb-tablet',
            '-vga', 'std', '-display', 'none',
            '-monitor', f'unix:{mon},server,nowait',
            '-serial', f'file:{LAB / (name + ".serial")}',
            *extra]
    return args


def hmp(name: str, command: str) -> str:
    s = socket.socket(socket.AF_UNIX)
    s.connect(str(LAB / f'{name}.mon'))
    s.settimeout(5)
    time.sleep(0.2)
    try:
        s.recv(65536)
    except socket.timeout:
        pass
    s.sendall(command.encode() + b'\n')
    time.sleep(0.5)
    out = b''
    try:
        out = s.recv(65536)
    except socket.timeout:
        pass
    s.close()
    return out.decode(errors='replace')


def build_base(args):
    LAB.mkdir(parents=True, exist_ok=True)
    name = 'base-bl' if args.bitlocker else 'base'
    disk = LAB / f'{name}.qcow2'
    if disk.exists():
        raise SystemExit(f'{disk} exists')
    if not ISO.is_file():
        raise SystemExit(f'missing {ISO}')
    ms_vars(LAB / f'{name}.vars.fd')
    answer_image(LAB / f'{name}-answer.img', args.bitlocker)
    sh('qemu-img', 'create', '-q', '-f', 'qcow2', disk, f'{DISK_GIB}G')
    tpm = tpm_start(LAB / f'{name}.tpm')
    extra = ['-drive', f'file={ISO},media=cdrom,if=none,id=cd,readonly=on',
             '-device', 'ide-cd,drive=cd,bus=ide.0,bootindex=0',
             '-drive', f'file={LAB / (name + "-answer.img")},format=raw,if=none,id=ans',
             '-device', 'usb-storage,drive=ans']
    p = subprocess.Popen(qemu_args(name, disk, LAB / f'{name}.vars.fd', tpm, extra))
    # "Press any key to boot from CD or DVD": keep tapping for 40 s.
    time.sleep(3)
    for _ in range(40):
        try:
            hmp(name, 'sendkey ret')
        except OSError:
            pass
        time.sleep(1)
    print(f'installing Windows into {disk}; waiting for the agent', flush=True)
    server, jobs = serve(name)
    start = time.time()
    while time.time() - start < args.timeout:
        if p.poll() is not None:
            raise SystemExit(f'qemu exited {p.returncode} before the agent connected')
        if server.agent_seen:
            break
        time.sleep(5)
    else:
        raise SystemExit('timeout waiting for guest agent')
    print(f'agent up after {int(time.time() - start)} s', flush=True)
    print(run_job(jobs, 'Get-ComputerInfo -Property OsName,OsVersion,BiosFirmwareType | Format-List;'
                        'Confirm-SecureBootUEFI; Get-Partition | Format-Table -Auto;'
                        'Get-BitLockerVolume | Format-Table -Auto', 600))
    run_job(jobs, 'Stop-Computer -Force', 30, wait=False)
    p.wait(timeout=300)
    print(f'base image ready: {disk}')


class Server(http.server.ThreadingHTTPServer):
    agent_seen = False


def serve(name: str, port: int = AGENT_PORT_BASE):
    jobs: dict = {'pending': queue.Queue(), 'results': {}, 'files': {}}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b'', ctype='text/plain'):
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path == '/next':
                self.server.agent_seen = True
                try:
                    jid, script = jobs['pending'].get_nowait()
                    self._send(200, f'{jid}\n{script}'.encode())
                except queue.Empty:
                    self._send(200, b'')
            elif url.path.startswith('/files/'):
                path = jobs['files'].get(url.path[len('/files/'):])
                if not path:
                    return self._send(404)
                size = os.path.getsize(path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(size))
                self.end_headers()
                with open(path, 'rb') as f:
                    shutil.copyfileobj(f, self.wfile, 1 << 20)
            elif url.path == '/result':
                jid = urllib.parse.parse_qs(url.query)['id'][0]
                res = jobs['results'].get(jid)
                self._send(200 if res else 204, json.dumps(res).encode() if res else b'')
            else:
                self._send(404)

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            q = urllib.parse.parse_qs(url.query)
            if url.path == '/done':
                jobs['results'][q['id'][0]] = {'code': int(q['code'][0]), 'out': body.decode('utf-8', 'replace')}
                self._send(200)
            elif url.path == '/queue':
                jid = uuid.uuid4().hex[:12]
                jobs['pending'].put((jid, body.decode()))
                self._send(200, jid.encode())
            elif url.path == '/share':
                p = Path(body.decode())
                jobs['files'][p.name] = str(p)
                self._send(200, p.name.encode())
            else:
                self._send(404)

    server = Server(('127.0.0.1', port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, jobs


def run_job(jobs, script, timeout, wait=True):
    jid = uuid.uuid4().hex[:12]
    jobs['pending'].put((jid, script))
    if not wait:
        return ''
    end = time.time() + timeout
    while time.time() < end:
        if jid in jobs['results']:
            r = jobs['results'][jid]
            return r['out'] + (f'\n[exit {r["code"]}]' if r['code'] else '')
        time.sleep(0.5)
    raise SystemExit('job timeout')


def up(args):
    name = args.name
    base = LAB / (args.base + '.qcow2')
    disk = LAB / f'{name}.qcow2'
    if args.fresh or not disk.exists():
        for suffix in ('.qcow2', '.vars.fd'):
            (LAB / f'{name}{suffix}').unlink(missing_ok=True)
        sh('qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', base, disk)
        shutil.copyfile(LAB / f'{args.base}.vars.fd', LAB / f'{name}.vars.fd')
        tstate = LAB / f'{name}.tpm'
        if tstate.exists():
            shutil.rmtree(tstate)
        shutil.copytree(LAB / f'{args.base}.tpm', tstate)
    tpm = tpm_start(LAB / f'{name}.tpm')
    server, jobs = serve(name, args.port)
    (LAB / f'{name}.port').write_text(str(args.port))
    while True:
        p = subprocess.Popen(qemu_args(name, disk, LAB / f'{name}.vars.fd', tpm))
        print(f'{name}: qemu pid {p.pid}', flush=True)
        p.wait()
        print(f'{name}: qemu exited {p.returncode}', flush=True)
        if not args.persist or (LAB / f'{name}.stop').exists():
            break
        tpm = tpm_start(LAB / f'{name}.tpm')
    (LAB / f'{name}.stop').unlink(missing_ok=True)


def client(name, path, body=b''):
    port = (LAB / f'{name}.port').read_text().strip()
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=body, method='POST' if body else 'GET')
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read()


def ps(args):
    script = args.script if args.script != '-' else sys.stdin.read()
    _, jid = client(args.name, '/queue', script.encode())
    end = time.time() + args.timeout
    while time.time() < end:
        status, body = client(args.name, f'/result?id={jid.decode()}')
        if status == 200:
            r = json.loads(body)
            sys.stdout.write(r['out'])
            return r['code']
        time.sleep(1)
    print('timeout', file=sys.stderr)
    return 124


def put(args):
    _, n = client(args.name, '/share', str(Path(args.file).resolve()).encode())
    print(f'http://10.0.2.2:{(LAB / (args.name + ".port")).read_text().strip()}/files/{n.decode()}')


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build-base')
    b.add_argument('--bitlocker', action='store_true', help='allow automatic device encryption')
    b.add_argument('--timeout', type=int, default=5400)
    u = sub.add_parser('up')
    u.add_argument('name')
    u.add_argument('--base', default='base')
    u.add_argument('--fresh', action='store_true')
    u.add_argument('--persist', action='store_true', help='restart QEMU after guest reboot/poweroff')
    u.add_argument('--port', type=int, default=AGENT_PORT_BASE)
    e = sub.add_parser('ps')
    e.add_argument('name')
    e.add_argument('script')
    e.add_argument('--timeout', type=int, default=1800)
    f = sub.add_parser('put')
    f.add_argument('name')
    f.add_argument('file')
    s = sub.add_parser('screenshot')
    s.add_argument('name')
    s.add_argument('out')
    d = sub.add_parser('down')
    d.add_argument('name')
    d.add_argument('--hard', action='store_true')
    k = sub.add_parser('hmp')
    k.add_argument('name')
    k.add_argument('command')
    a = p.parse_args()
    if a.cmd == 'build-base':
        build_base(a)
    elif a.cmd == 'up':
        up(a)
    elif a.cmd == 'ps':
        sys.exit(ps(a))
    elif a.cmd == 'put':
        put(a)
    elif a.cmd == 'screenshot':
        print(hmp(a.name, f'screendump {Path(a.out).resolve()}'))
    elif a.cmd == 'down':
        (LAB / f'{a.name}.stop').touch()
        print(hmp(a.name, 'quit' if a.hard else 'system_powerdown'))
    elif a.cmd == 'hmp':
        print(hmp(a.name, a.command))


if __name__ == '__main__':
    main()
