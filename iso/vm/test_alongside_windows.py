#!/usr/bin/env python3
"""VM proof: install JStack into unallocated space next to a Windows-layout disk.

Usage: python3 iso/vm/test_alongside_windows.py --iso /abs/clean.iso \
    --artifacts /abs/new-proof-directory

The target disk is built on the host as a regular file with the Windows 11
UEFI layout: ESP (with stand-in Windows Boot Manager files), MSR, an NTFS
system volume holding a sentinel file, unallocated space, and a recovery
partition at the end. The real ISO installer runs with --alongside-windows.
Pass criteria:
  * every pre-existing non-ESP partition is byte-identical after install
  * the Windows Boot Manager and the ESP fallback loader are byte-identical
  * the ESP gains only EFI/systemd and loader/
  * the installed system boots from the disk with no ISO, and systemd-boot
    lists both Jstack OS and Windows Boot Manager
Run as an ordinary user. sudo is used only for losetup/mkfs on a scratch file.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
import test_live_install as h  # noqa: E402

DISK = h.TARGET
GIB = h.GIB
ESP_PROTECTED = ('EFI/Microsoft/Boot/bootmgfw.efi', 'EFI/Boot/bootx64.efi')


def sudo(*args, input=None):
    result = subprocess.run(['sudo', '-n', *map(str, args)], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise h.ProofError(f'{shlex.join(map(str, args))}: {result.stdout}')
    return result.stdout


def build_windows_disk(path: Path, size_gib: int = 80) -> dict:
    """Windows-like GPT on a regular file. Unallocated gap of ~49 GiB."""
    raw = path.with_suffix('.raw')
    subprocess.run(['truncate', '-s', f'{size_gib}G', str(raw)], check=True)
    subprocess.run(['sgdisk', '-o',
                    '-n1:2048:+100M', '-t1:ef00', '-c1:EFI system partition',
                    '-n2:0:+16M', '-t2:0c01', '-c2:Microsoft reserved partition',
                    '-n3:0:+30G', '-t3:0700', '-c3:Basic data partition',
                    '-n4:-800M:0', '-t4:2700', '-c4:Windows RE',
                    str(raw)], check=True, stdout=subprocess.DEVNULL)
    loop = sudo('losetup', '--show', '-fP', raw).strip()
    mnt = path.parent / 'esp-mnt'
    mnt.mkdir()
    try:
        sudo('mkfs.fat', '-F', '32', '-n', 'SYSTEM', loop + 'p1')
        sudo('mkntfs', '-Q', '-L', 'Windows', loop + 'p3')
        sudo('mkntfs', '-Q', '-L', 'Recovery', loop + 'p4')
        sudo('mount', loop + 'p1', mnt)
        try:
            for rel in ESP_PROTECTED:
                sudo('mkdir', '-p', (mnt / rel).parent)
                sudo('tee', mnt / rel, input=f'stand-in {rel} {os.urandom(8).hex()}\n')
        finally:
            sudo('umount', mnt)
        sudo('mount', '-t', 'ntfs3', loop + 'p3', mnt)
        try:
            sudo('mkdir', '-p', mnt / 'Windows/System32')
            sudo('tee', mnt / 'Windows/System32/jstack-sentinel.txt', input='windows data must survive\n')
        finally:
            sudo('umount', mnt)
    finally:
        sudo('losetup', '-d', loop)
        mnt.rmdir()
    subprocess.run(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2', str(raw), str(path)], check=True)
    raw.unlink()
    return {'size_gib': size_gib, 'layout': subprocess.run(
        ['qemu-img', 'info', '--output=json', str(path)], text=True, capture_output=True).stdout}


def snapshot_script() -> str:
    """Whole-partition hashes of Windows partitions plus protected ESP files."""
    protected = ' '.join(shlex.quote(p) for p in ESP_PROTECTED)
    return f'''set -euo pipefail
sync
for n in 2 3 4; do printf 'PART%s=%s\\n' "$n" "$(sha256sum {DISK}$n | cut -d' ' -f1)"; done
mkdir -p /run/jstack-esp-ro
mount -o ro {DISK}1 /run/jstack-esp-ro
cd /run/jstack-esp-ro
for f in {protected}; do printf 'ESPFILE %s=%s\\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"; done
find . -type f | sort | sed 's/^/ESPLIST /'
cd /
umount /run/jstack-esp-ro
sgdisk -p {DISK} | sed 's/^/GPT /'
'''


def parse_snapshot(text: str) -> dict:
    return {'parts': dict(re.findall(r'(?m)^PART(\d)=([a-f0-9]{64})$', text)),
            'esp_files': dict(re.findall(r'(?m)^ESPFILE (\S+)=([a-f0-9]{64})$', text)),
            'esp_list': re.findall(r'(?m)^ESPLIST (\S+)$', text),
            'gpt': re.findall(r'(?m)^GPT (.*)$', text)}


def installed_script() -> str:
    return f'''set -euo pipefail
test -d /sys/firmware/efi
test "$(findmnt -n -o FSTYPE /)" = btrfs
test "$(findmnt -n -o FSTYPE /boot)" = vfat
test "$(findmnt -n -o FSTYPE /efi)" = vfat
test "$(lsblk -no PARTTYPE $(findmnt -n -o SOURCE /boot))" = bc13c2ff-59e6-4262-a352-b275fd6f7172
test -s /boot/vmlinuz-linux && test -s /boot/initramfs-linux.img
test -s /efi/EFI/systemd/systemd-bootx64.efi
test -s /efi/EFI/Microsoft/Boot/bootmgfw.efi
bootctl --no-pager list | tee /run/bootctl-list
grep -q 'Jstack OS' /run/bootctl-list
grep -qi 'windows' /run/bootctl-list
efibootmgr | tee /run/efibootmgr
grep -q 'Jstack OS' /run/efibootmgr
python3 -c "import json;d=json.load(open('/var/lib/jstack/installed-from-live.json'));assert d['dual_boot'] is True"
systemctl --failed --no-legend --plain
echo DUALBOOT_INSTALLED_OK
'''


def run(args, artifacts: Path, result: dict):
    iso = h.regular_file(args.iso)
    result['iso'] = {'path': str(iso), 'sha256': h.digest(iso)}
    target = artifacts / 'windows-layout.qcow2'
    h.progress('Building Windows-layout disk', phase='disk')
    result['disk'] = build_windows_disk(target)
    with h.VM(args, artifacts, 'live', target, None, iso) as vm:
        s = vm.serial
        s.bootstrap(False, args.boot_timeout)
        s.script('live prerequisites', f'''set -euo pipefail
test "$(lsblk -dn -o SERIAL {DISK})" = JSTACKTARGET
umask 077; printf '%s\\n' {shlex.quote(args.password)} > /run/jstack-vm-password
lsblk -o NAME,TYPE,SIZE,FSTYPE,PARTTYPE,LABEL
''')
        _, before = s.script('pre-install snapshot', snapshot_script())
        result['before'] = parse_snapshot(before)
        # A blank-disk install must refuse this disk outright.
        rc, out = s.script('blank mode refuses Windows disk', shlex.join(
            [args.installer, '--check', '--disk', DISK]), args.refusal_timeout, check=False)
        if rc != 1 or 'blank disks only' not in out and 'partitions' not in out:
            raise h.ProofError('blank-disk mode did not refuse a Windows disk: ' + out)
        _, check = s.script('alongside preflight', shlex.join(
            [args.installer, '--alongside-windows', '--check', '--disk', DISK]), args.refusal_timeout)
        result['preflight'] = check
        token = json.loads([l for l in check.splitlines() if l.startswith('{"confirmation"')][-1])['confirmation']
        if not re.fullmatch(r'ALONGSIDE-[a-f0-9]{16}', token):
            raise h.ProofError('bad ALONGSIDE token')
        rc, out = s.script('wrong token refused', shlex.join(
            [args.installer, '--alongside-windows', '--disk', DISK, '--user', h.USER, '--password-stdin',
             '--confirm', 'ALONGSIDE-0000000000000000']) + ' < /run/jstack-vm-password',
            args.refusal_timeout, check=False)
        if rc != 1 or 'does not exactly match' not in out:
            raise h.ProofError('wrong token not refused: ' + out)
        h.progress('Installing alongside Windows', phase='install')
        _, out = s.script('alongside install', shlex.join(
            [args.installer, '--alongside-windows', '--disk', DISK, '--user', h.USER,
             '--hostname', 'jstack-vm', '--password-stdin', '--confirm', token, '--serial-console'])
            + ' < /run/jstack-vm-password', args.install_timeout)
        result['install_output'] = out[-8000:]
        if 'JSTACK-INSTALL: complete.' not in out:
            raise h.ProofError('installer did not complete')
        _, after = s.script('post-install snapshot', snapshot_script())
        result['after'] = parse_snapshot(after)
        s.script('cleanup', 'rm -f /run/jstack-vm-password; sync')
        vm.shutdown()
    b, a = result['before'], result['after']
    if len(b['parts']) != 3 or b['parts'] != a['parts']:
        raise h.ProofError(f'WINDOWS PARTITIONS CHANGED: {b["parts"]} -> {a["parts"]}')
    if len(b['esp_files']) != 2 or b['esp_files'] != a['esp_files']:
        raise h.ProofError('Windows ESP boot files changed')
    added = sorted(set(a['esp_list']) - set(b['esp_list']))
    removed = sorted(set(b['esp_list']) - set(a['esp_list']))
    if removed or not added or not all(p.startswith(('./EFI/systemd/', './loader/')) for p in added):
        raise h.ProofError(f'unexpected ESP changes: added={added} removed={removed}')
    result['esp_added'] = added
    # Real dual-boot machines keep their NVRAM. The fallback loader on this
    # disk is the (stand-in) Windows one, so JStack must boot via the entry
    # the installer registered, not via EFI/BOOT.
    args.ovmf_vars = artifacts / 'live' / 'OVMF_VARS.fd'
    h.progress('Booting installed dual-boot disk without ISO', phase='installed-boot')
    with h.VM(args, artifacts, 'installed', target) as vm:
        vm.serial.bootstrap(True, args.boot_timeout, args.password)
        _, result['installed_checks'] = vm.serial.script('installed dual-boot checks', installed_script(), 180)
        vm.shutdown()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--iso', type=Path, required=True)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--ovmf-code', type=Path, default=Path('/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd'))
    p.add_argument('--ovmf-vars', type=Path, default=Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd'))
    p.add_argument('--memory', type=int, default=4096)
    p.add_argument('--accel', default='kvm')
    p.add_argument('--socket-dir', default=os.environ.get('XDG_RUNTIME_DIR', '/run/user/' + str(os.getuid())))
    p.add_argument('--installer', default='/usr/local/bin/jstack-install-live')
    p.add_argument('--boot-timeout', type=int, default=300)
    p.add_argument('--refusal-timeout', type=int, default=120)
    p.add_argument('--install-timeout', type=int, default=1800)
    p.add_argument('--empty-password', action='store_true', help='install with an empty password')
    args = p.parse_args(argv)
    args.password = '' if args.empty_password else h.PASSWORD
    if os.geteuid() == 0:
        print('Run as an ordinary user', file=sys.stderr)
        return 2
    artifacts = args.artifacts.absolute()
    if artifacts.exists():
        print('Refusing to reuse artifact path', file=sys.stderr)
        return 2
    artifacts.mkdir(parents=True, mode=0o700)
    result = {'passed': False, 'started_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    status = 1
    try:
        run(args, artifacts, result)
        result['passed'] = True
        status = 0
        print('ALONGSIDE_WINDOWS_PROOF_PASSED')
    except Exception as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        print('ALONGSIDE_WINDOWS_PROOF_FAILED: ' + result['error'], file=sys.stderr)
    finally:
        (artifacts / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return status


if __name__ == '__main__':
    sys.exit(main())
