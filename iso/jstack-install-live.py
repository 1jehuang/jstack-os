#!/usr/bin/env python3
"""Offline, blank-internal-disk-only Jstack installer. No rollback or resume.

--list and --check are read-only. Installation requires the exact identity token
printed by --check. Noninteractive: --disk DEVICE --confirm TOKEN --user NAME
--password-stdin [--hostname NAME] [--serial-console]. Never use on the host.
The clean marker is build provenance, not a cryptographic authenticity claim.
"""
import argparse
import contextlib
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

MARKER = 'etc/jstack-live-installer.json'
TRUST = {'schema': 1, 'image': 'jstack-live', 'clean': True, 'architecture': 'x86_64'}
MIN_BYTES = 32 * 1024**3
TOOLS = ('lsblk', 'findmnt', 'wipefs', 'blkid', 'sgdisk', 'udevadm', 'mkfs.fat',
         'mkfs.btrfs', 'btrfs', 'rsync', 'mount', 'umount', 'arch-chroot',
         'unsquashfs', 'du', 'sync')
LIVE_UNITS = ('jstack-live-setup.service', 'choose-mirror.service',
              'pacman-init.service', 'reflector.service', 'reflector.timer')
ENABLE = ('NetworkManager.service', 'iwd.service', 'bluetooth.service',
          'keyd.service', 'tlp.service', 'earlyoom.service', 'fstrim.timer',
          'systemd-timesyncd.service', 'jstack-scx.service',
          'jstack-wifi-boot-recovery.timer')
DISABLE = ('systemd-networkd.service', 'systemd-networkd.socket',
           'systemd-networkd-wait-online.service', 'systemd-resolved.service',
           'systemd-networkd-varlink-metrics.socket', 'systemd-networkd-varlink.socket',
           'systemd-networkd-resolve-hook.socket', 'systemd-resolved-monitor.socket',
           'systemd-resolved-varlink.socket',
           'sshd.service', 'sshd.socket')
# Excludes apply to the immutable SquashFS, NEVER the running overlay root.
EXCLUDES = ('/dev/*', '/proc/*', '/sys/*', '/run/*', '/tmp/*', '/mnt/*', '/media/*',
            '/boot/*', '/efi/*', '/home/*', '/root/*', '/var/log/*', '/var/tmp/*',
            '/var/cache/pacman/pkg/*', '/etc/machine-id', '/var/lib/dbus/machine-id',
            '/etc/ssh/ssh_host_*', '/etc/NetworkManager/system-connections/*',
            '/var/lib/NetworkManager/*', '/var/lib/iwd/*', '/var/lib/bluetooth/*',
            '/var/lib/systemd/random-seed', '/var/lib/systemd/credential.secret',
            '/etc/pacman.d/gnupg/*')


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def run(*args, input=None, ok=(0,), pass_fds=()):
    result = subprocess.run([str(a) for a in args], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            pass_fds=pass_fds, env={**os.environ, 'LC_ALL': 'C',
                                                  'PATH': '/usr/bin:/usr/sbin:/bin:/sbin'})
    require(result.returncode in ok,
            f'{args[0]} failed ({result.returncode}): {result.stderr.strip()}')
    return result


def jsrun(*args):
    return json.loads(run(*args).stdout)


def marker(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
            info.st_gid == 0 and not info.st_mode & 0o022,
            'clean source marker must be a root-owned, non-writable regular file')
    require(json.loads(path.read_text()) == TRUST, 'not an approved CLEAN Jstack source')


def mount_for(path):
    rows = jsrun('findmnt', '--json', '--target', str(path),
                 '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN')['filesystems']
    require(len(rows) == 1, 'ambiguous source mount')
    return rows[0]


def live_environment():
    require(os.geteuid() == 0, 'run with sudo')
    require(Path('/run/archiso').is_dir(), 'not an Archiso live environment')
    marker(Path('/') / MARKER)
    require(Path('/sys/firmware/efi').is_dir(), 'UEFI boot required')
    sb = Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c')
    data = sb.read_bytes()
    require(len(data) == 5 and data[4] == 0, 'Secure Boot must be explicitly OFF')
    missing = [tool for tool in TOOLS if shutil.which(tool) is None]
    require(not missing, 'missing offline tools: ' + ', '.join(missing))


def source_info():
    """No mounts even in fallback discovery, so --check remains read-only."""
    image = Path('/run/archiso/bootmnt/arch/x86_64/airootfs.sfs')
    info = image.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'SquashFS source must be a root-owned regular file')
    m = mount_for(image)
    require(m['target'] == '/run/archiso/bootmnt' and 'ro' in m['options'].split(','),
            'source image must reside on the read-only Archiso boot mount')
    manifest = image.with_suffix('.sha512')
    manifest_stat = manifest.lstat()
    require(stat.S_ISREG(manifest_stat.st_mode) and manifest_stat.st_uid == 0 and
            not manifest_stat.st_mode & 0o022, 'unsafe SquashFS integrity manifest')
    match = re.fullmatch(r'([a-fA-F0-9]{128})\s+\*?(?:\./)?airootfs\.sfs\s*', manifest.read_text())
    require(match is not None, 'invalid SquashFS SHA512 manifest')
    digest = hashlib.sha512()
    with image.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    require(digest.hexdigest() == match[1].lower(), 'SquashFS SHA512 mismatch: damaged or incomplete live medium')
    base = Path('/run/archiso/airootfs')
    if base.is_dir():
        m = mount_for(base)
        if m['target'] == str(base) and m['fstype'] == 'squashfs' and 'ro' in m['options'].split(','):
            backing = Path('/sys/dev/block') / m['maj:min'] / 'loop/backing_file'
            require(Path(backing.read_text().strip()).resolve(strict=True) == image.resolve(strict=True),
                    'live base is not backed by the verified SquashFS')
            marker(base / MARKER)
            return base, False
    text = run('unsquashfs', '-cat', image, MARKER).stdout
    require(json.loads(text) == TRUST, 'SquashFS is not an approved CLEAN source')
    return image, True


def walk(nodes):
    for node in nodes:
        yield node
        yield from walk(node.get('children', []))


def inventory():
    return jsrun('lsblk', '--json', '--bytes', '--paths', '--output',
                 'NAME,TYPE,SIZE,RO,RM,TRAN,SERIAL,WWN,MODEL,MAJ:MIN,LOG-SEC,MOUNTPOINTS,START,PARTUUID,PARTTYPE')['blockdevices']


def node_for(device, nodes):
    real = str(Path(device).resolve(strict=True))
    found = [n for n in walk(nodes) if n['name'] == real]
    require(len(found) == 1, 'device is absent or ambiguous')
    return found[0]


def disk_identity(node):
    device = Path(node['name'])
    st = device.stat()
    require(stat.S_ISBLK(st.st_mode), 'target is not a block device')
    devnum = f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}'
    require(devnum == node['maj:min'], 'block identity changed during enumeration')
    syspath = (Path('/sys/dev/block') / devnum).resolve(strict=True)
    sequence = (syspath / 'diskseq').read_text().strip()
    require(sequence.isdecimal(), 'kernel disk sequence unavailable')
    require(node.get('serial') or node.get('wwn'), 'target requires a hardware serial or WWN (set a VM disk serial)')
    return {'device': str(device), 'devnum': devnum, 'sysfs': str(syspath),
            'diskseq': sequence, 'size': int(node['size']),
            'serial': node.get('serial'), 'wwn': node.get('wwn'),
            'model': node.get('model'), 'transport': node.get('tran'),
            'sector': int(node['log-sec'])}


def token(identity):
    return 'INSTALL-' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]


def mounted_devices():
    rows = jsrun('findmnt', '--json', '--list', '--output', 'MAJ:MIN')['filesystems']
    return {r['maj:min'] for r in rows}


def swap_devices():
    result = set()
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), line.split()[0])
        st = Path(name).stat()
        number = st.st_rdev if stat.S_ISBLK(st.st_mode) else st.st_dev
        result.add(f'{os.major(number)}:{os.minor(number)}')
    return result


def busy_check(node, allow_missing_children=False):
    mounted = mounted_devices()
    swaps = swap_devices()
    protected = backing_devices(mounted | swaps)
    complete = True
    for child in walk([node]):
        require(not any(child.get('mountpoints') or []), 'target or descendant is mounted')
        require(child['maj:min'] not in mounted, 'target or descendant is mounted')
        require(child['maj:min'] not in swaps, 'target or descendant is active swap')
        require(child['maj:min'] not in protected, 'target backs a mounted filesystem, live source, or swap')
        sys = Path('/sys/dev/block') / child['maj:min']
        try:
            holders = list((sys / 'holders').iterdir())
        except FileNotFoundError:
            if allow_missing_children and child is not node:
                complete = False
                continue
            raise
        require(not holders, 'target or descendant has holders')
    return complete


def backing_devices(numbers):
    """Follow partition parents, mapper slaves and file-backed loops to disks.

    A mounted loop filesystem can protect an otherwise unmounted backing disk.
    Missing sysfs for pseudo filesystems is normal, other errors fail closed.
    """
    protected = set()
    pending = list(numbers)
    while pending:
        number = pending.pop()
        if number in protected:
            continue
        protected.add(number)
        path = Path('/sys/dev/block') / number
        if not path.exists():
            continue
        path = path.resolve(strict=True)
        if (path / 'partition').exists():
            pending.append((path.parent / 'dev').read_text().strip())
        slaves = path / 'slaves'
        if slaves.exists():
            for slave in slaves.iterdir():
                pending.append((slave / 'dev').read_text().strip())
        backing = path / 'loop/backing_file'
        if backing.exists():
            name = backing.read_text().strip()
            require(name.startswith('/'), 'unresolvable loop backing file')
            pending.append(mount_for(name)['maj:min'])
    return protected


def inspect_disk(device, blank=True, expected=None):
    node = node_for(device, inventory())
    require(node['type'] == 'disk', 'select a whole disk, not a partition or mapped device')
    ident = disk_identity(node)
    require(not node['ro'] and not node['rm'], 'read-only or removable disk refused')
    # Transport can be empty for virtio/NVMe. Check actual ancestry as well.
    require((node.get('tran') or '').lower() not in ('usb', 'firewire', 'iscsi') and
            not re.search(r'/(usb\d*|firewire[^/]*)/', ident['sysfs']), 'USB/external transport refused')
    require(ident['size'] >= MIN_BYTES, 'target smaller than 32 GiB')
    require(ident['sector'] in (512, 4096), 'unsupported logical sector size')
    if expected is not None:
        require(ident == expected, 'TARGET IDENTITY CHANGED. Refusing all further writes')
    if blank:
        busy_check(node)
        require(not node.get('children'), 'target has partitions or mapped descendants, blank disks only')
        signatures = jsrun('wipefs', '--no-act', '--json', ident['device'])
        require(signatures.get('signatures') == [], 'filesystem/partition signatures present, blank disks only')
        probe = run('blkid', '-p', ident['device'], ok=(0, 2))
        require(probe.returncode == 2 and not probe.stdout.strip(), 'blkid detected data or ambiguous signature')
    return ident, node


def list_disks():
    eligible = []
    for disk in inventory():
        if disk['type'] != 'disk':
            continue
        try:
            ident, _ = inspect_disk(disk['name'])
            eligible.append(ident)
            print(json.dumps({'eligible': True, 'identity': ident, 'confirmation': token(ident)}, sort_keys=True))
        except (Refusal, OSError, ValueError, KeyError) as exc:
            print(json.dumps({'eligible': False, 'device': disk['name'], 'reason': str(exc)}))
    return eligible


@contextlib.contextmanager
def exclusive_device(device, expected_rdev, release_claim=False):
    fd = os.open(device, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC)
    try:
        require(stat.S_ISBLK(os.fstat(fd).st_mode) and os.fstat(fd).st_rdev == expected_rdev,
                'exclusive device identity mismatch')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if release_claim:
            # mkfs.btrfs and mount take their own exclusive kernel claims. Keep
            # the block object pinned by a normal FD but release our preflight
            # claim before their open, otherwise their O_EXCL always gets EBUSY.
            pinned_fd = os.open(f'/proc/self/fd/{fd}', os.O_RDWR | os.O_CLOEXEC)
            os.close(fd)
            fd = pinned_fd
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd, f'/proc/self/fd/{fd}'
    finally:
        os.close(fd)


def check_partition(identity, expected, number, count=2):
    _, disk = inspect_disk(identity['device'], blank=False, expected=identity)
    parts = disk.get('children', [])
    require(len(parts) == count, 'partition layout changed')
    matches = [p for p in parts if p['maj:min'] == expected['maj:min']]
    require(len(matches) == 1, 'partition identity changed')
    part = matches[0]
    require(all(part.get(k) == expected.get(k) for k in ('name', 'type', 'size', 'start', 'partuuid', 'parttype')),
            'partition identity or geometry changed')
    sys = (Path('/sys/dev/block') / part['maj:min']).resolve(strict=True)
    require(str(sys.parent) == identity['sysfs'] and (sys / 'partition').read_text().strip() == str(number),
            'partition ancestry changed')
    return part


def partition_plan(identity):
    """Exact GPT geometry in logical sectors, independent of observed nodes."""
    sector = identity['sector']
    require(identity['size'] % sector == 0, 'disk size is not a whole number of sectors')
    first = 1024**2 // sector
    esp_sectors = 1024**3 // sector
    # Standard 128-entry GPT: backup header plus ceil(16 KiB / sector) array.
    last = identity['size'] // sector - 2 - (16384 + sector - 1) // sector
    return [
        {'number': 1, 'first': first, 'last': first + esp_sectors - 1,
         'partuuid': str(uuid.uuid4()), 'parttype': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'},
        {'number': 2, 'first': first + esp_sectors, 'last': last,
         'partuuid': str(uuid.uuid4()), 'parttype': '0fc63daf-8483-4772-8e79-3d69d8477de4'},
    ]


class PartitionPending(Exception):
    """Only incomplete udev discovery may be retried, never unsafe geometry."""


ESP_TYPE = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
XBOOTLDR_TYPE = 'bc13c2ff-59e6-4262-a352-b275fd6f7172'
LINUX_TYPE = '0fc63daf-8483-4772-8e79-3d69d8477de4'
BOOT_BYTES = 1024**3
WINDOWS_LOADER = 'EFI/Microsoft/Boot/bootmgfw.efi'
SYSTEMD_BOOT = 'EFI/systemd/systemd-bootx64.efi'


def gpt_table(device):
    """Read-only GPT listing in logical sectors: usable range and partitions."""
    text = run('sgdisk', '--print', device).stdout
    require('Found invalid' not in text and 'GPT: not present' not in text and 'GPT: damaged' not in text,
            'disk does not have a clean GPT partition table')
    usable = re.search(r'First usable sector is (\d+), last usable sector is (\d+)', text)
    require(usable is not None, 'cannot read GPT usable range')
    table = {}
    for line in text.split('Number  Start', 1)[-1].splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and all(f.isdecimal() for f in fields[:3]):
            table[int(fields[0])] = (int(fields[1]), int(fields[2]))
    return int(usable[1]), int(usable[2]), table


def esp_report(part):
    """Mount the existing ESP read-only to confirm Windows and room for systemd-boot."""
    where = tempfile.mkdtemp(prefix='jstack-esp-', dir='/run')
    run('mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec', part['name'], where)
    try:
        root = Path(where)
        stats = os.statvfs(where)
        return {'windows': (root / WINDOWS_LOADER).is_file(),
                'free_bytes': stats.f_bavail * stats.f_frsize}
    finally:
        run('umount', where)
        os.rmdir(where)  # rmdir only, never recursive removal of a mount point


def free_space_layout(device, probe_esp=True):
    """Plan JStack in the largest unallocated GPT gap. Never moves, resizes,
    formats or deletes an existing partition. The existing ESP is shared."""
    ident, node = inspect_disk(device, blank=False)
    busy_check(node)
    probe = run('blkid', '-p', '-o', 'value', '-s', 'PTTYPE', ident['device'], ok=(0, 2))
    require(probe.stdout.strip() == 'gpt', 'disk is not GPT (Windows 11 UEFI disks always are)')
    sector = ident['sector']
    first, last, table = gpt_table(ident['device'])
    children = node.get('children') or []
    require(children and len(children) == len(table), 'kernel and GPT partition lists disagree')
    existing = []
    for part in children:
        require(part['type'] == 'part' and not part.get('children'), 'mapped or nested partitions refused')
        sysfs = (Path('/sys/dev/block') / part['maj:min']).resolve(strict=True)
        require(str(sysfs.parent) == ident['sysfs'], 'partition ancestry mismatch')
        number = int((sysfs / 'partition').read_text().strip())
        start = int((sysfs / 'start').read_text().strip()) * 512
        size = int((sysfs / 'size').read_text().strip()) * 512
        require(number in table and table[number] == (start // sector, (start + size) // sector - 1),
                'kernel and GPT partition geometry disagree')
        existing.append({'number': number, 'start_bytes': start, 'size_bytes': size,
                         'uuid': (part.get('partuuid') or '').lower(),
                         'type': (part.get('parttype') or '').lower(), 'name': part['name']})
    existing.sort(key=lambda p: p['start_bytes'])
    require(all(p['uuid'] and p['type'] for p in existing), 'partition identities not available yet, retry')
    esps = [p for p in existing if p['type'] == ESP_TYPE]
    require(len(esps) == 1, 'exactly one EFI System Partition is required')
    require(not any(p['type'] in (XBOOTLDR_TYPE, LINUX_TYPE) for p in existing),
            'disk already has Linux partitions. Remove them in Windows Disk Management first')
    align = 1024**2 // sector
    gaps, cursor = [], first
    for p in existing:
        begin = p['start_bytes'] // sector
        gaps.append((cursor, begin - 1))
        cursor = max(cursor, (p['start_bytes'] + p['size_bytes']) // sector)
    gaps.append((cursor, last))
    aligned = []
    for a, b in gaps:
        a = -(-a // align) * align
        b = (b + 1) // align * align - 1
        if b > a:
            aligned.append((a, b))
    require(aligned, 'no unallocated space. Shrink the Windows volume in Disk Management first')
    start, end = max(aligned, key=lambda g: g[1] - g[0])
    boot_sectors = BOOT_BYTES // sector
    root_bytes = (end - start + 1 - boot_sectors) * sector
    require(root_bytes >= MIN_BYTES,
            f'largest unallocated space is {(end - start + 1) * sector / 1024**3:.1f} GiB, '
            f'need at least {(MIN_BYTES + BOOT_BYTES) / 1024**3:.0f} GiB')
    used = {p['number'] for p in existing}
    free_numbers = [n for n in range(1, 129) if n not in used][:2]
    require(len(free_numbers) == 2, 'GPT has no free partition entries')
    plan = [
        {'number': free_numbers[0], 'first': start, 'last': start + boot_sectors - 1,
         'parttype': XBOOTLDR_TYPE, 'label': 'JSTACK-BOOT'},
        {'number': free_numbers[1], 'first': start + boot_sectors, 'last': end,
         'parttype': LINUX_TYPE, 'label': 'JSTACK-ROOT'},
    ]
    layout = {'identity': ident, 'existing': existing, 'esp': esps[0]['number'], 'plan': plan}
    if probe_esp:
        report = esp_report(next(c for c in children if c['name'] == esps[0]['name']))
        require(report['free_bytes'] >= 8 * 1024**2, 'EFI System Partition has less than 8 MiB free')
        layout['windows'] = report['windows']
        layout['bitlocker'] = [p['name'] for p in existing
                               if run('blkid', '-p', '-o', 'value', '-s', 'TYPE', p['name'], ok=(0, 2)).stdout.strip() == 'BitLocker']
    return layout


def stable_layout(layout):
    """What the user confirms: disk identity, every existing partition, the new geometry."""
    return {'identity': layout['identity'], 'esp': layout['esp'],
            'existing': [{k: p[k] for k in ('number', 'start_bytes', 'size_bytes', 'uuid', 'type')}
                         for p in layout['existing']],
            'plan': [{k: p[k] for k in ('number', 'first', 'last', 'parttype')} for p in layout['plan']]}


def alongside_token(layout):
    return 'ALONGSIDE-' + hashlib.sha256(json.dumps(stable_layout(layout), sort_keys=True).encode()).hexdigest()[:16]


def describe_layout(layout):
    sector = layout['identity']['sector']
    lines = [f"Disk {layout['identity']['device']} ({layout['identity'].get('model') or 'unknown model'}, "
             f"{layout['identity']['size'] / 1024**3:.1f} GiB). Existing partitions are KEPT unchanged:"]
    for p in layout['existing']:
        lines.append(f"  keep   #{p['number']:<3} {p['size_bytes'] / 1024**3:8.1f} GiB  {p['name']}"
                     + ('  (EFI, shared)' if p['number'] == layout['esp'] else ''))
    for p in layout['plan']:
        lines.append(f"  create #{p['number']:<3} {(p['last'] - p['first'] + 1) * sector / 1024**3:8.1f} GiB  "
                     f"{p['label']} in unallocated space")
    return '\n'.join(lines)


def create_free_space_partitions(layout, on_mutation=None):
    """Add exactly two partitions. sgdisk without --clear keeps every entry."""
    identity = layout['identity']
    confirmed = stable_layout(layout)
    require(stable_layout(free_space_layout(identity['device'], probe_esp=False)) == confirmed,
            'DISK CHANGED SINCE CONFIRMATION. Refusing all writes')
    plan = [{**p, 'partuuid': str(uuid.uuid4())} for p in layout['plan']]
    major, minor = map(int, identity['devnum'].split(':'))
    with exclusive_device(identity['device'], os.makedev(major, minor)) as (fd, pinned):
        require(stable_layout(free_space_layout(identity['device'], probe_esp=False)) == confirmed,
                'DISK CHANGED SINCE CONFIRMATION. Refusing all writes')
        args = ['sgdisk']
        for part in plan:
            n = part['number']
            args.extend((f'--new={n}:{part["first"]}:{part["last"]}', f'--typecode={n}:{part["parttype"]}',
                         f'--partition-guid={n}:{part["partuuid"]}', f'--change-name={n}:{part["label"]}'))
        if on_mutation is not None:
            on_mutation()
        result = run(*args, pinned, pass_fds=(fd,))
        print('Partitioner stdout:\n' + result.stdout)
        print('Partitioner stderr:\n' + result.stderr)
    reread_partitions(identity)
    disk, parts = wait_for_partitions(identity, plan, preserved=layout['existing'])
    return disk, parts, plan


def partition_snapshot(identity, disk, plan, preserved=()):
    """Planned partitions must match exactly; preserved ones must be unchanged."""
    planned = {p['number']: p for p in plan}
    kept = {p['number']: p for p in preserved}
    total = len(planned) + len(kept)
    parts = disk.get('children', [])
    require(len(parts) <= total and all(p['type'] == 'part' and not p.get('children') for p in parts),
            'unexpected partition layout: extra or non-partition descendants')
    found = {}
    for part in parts:
        try:
            sysfs = (Path('/sys/dev/block') / part['maj:min']).resolve(strict=True)
            require(str(sysfs.parent) == identity['sysfs'], 'partition ancestry mismatch')
            number = int((sysfs / 'partition').read_text().strip())
            require((number in planned or number in kept) and number not in found,
                    'unexpected or duplicate partition number')
            start_bytes = int((sysfs / 'start').read_text().strip()) * 512
            size_bytes = int((sysfs / 'size').read_text().strip()) * 512
            if number in kept:
                old = kept[number]
                require(start_bytes == old['start_bytes'] and size_bytes == old['size_bytes'],
                        'EXISTING PARTITION CHANGED. Refusing all further writes')
                if part.get('partuuid'):
                    require(part['partuuid'].lower() == old['uuid'], 'EXISTING PARTITION CHANGED. Refusing all further writes')
                found[number] = part
                continue
            wanted = planned[number]
            require(start_bytes == wanted['first'] * identity['sector'] and
                    size_bytes == (wanted['last'] - wanted['first'] + 1) * identity['sector'] and
                    int(part['size']) == size_bytes, 'partition geometry does not match planned GPT')
            st = Path(part['name']).stat()
            major, minor = map(int, part['maj:min'].split(':'))
            require(stat.S_ISBLK(st.st_mode) and st.st_rdev == os.makedev(major, minor),
                    'partition device identity mismatch')
        except FileNotFoundError as exc:
            raise PartitionPending('partition sysfs/device node not ready') from exc
        # udev attributes may arrive after kernel nodes. Nonempty wrong values
        # are unsafe, not a reason to wait for a more convenient observation.
        for key in ('partuuid', 'parttype'):
            if part.get(key):
                require(part[key].lower() == wanted[key], f'partition {key} does not match planned GPT')
        if not part.get('partuuid') or not part.get('parttype') or part.get('start') is None:
            raise PartitionPending('partition udev properties not ready')
        found[number] = part
    if len(found) != total:
        raise PartitionPending(f'only {len(found)} of {total} planned partitions visible')
    return [found[p['number']] for p in plan]


def wait_for_partitions(identity, plan, timeout=30, preserved=()):
    started = time.monotonic()
    deadline = started + timeout
    previous = None
    consecutive = False
    observed = []
    detail = 'no partition inventory available'
    # The iteration cap is independent of monotonic time for a strict retry bound.
    for _ in range(150):
        if time.monotonic() >= deadline:
            break
        # No writing tools in this loop. A changed/busy parent fails immediately.
        _, disk = inspect_disk(identity['device'], blank=False, expected=identity)
        busy_complete = busy_check(disk, allow_missing_children=True)
        observed = disk.get('children', [])
        try:
            if not busy_complete:
                raise PartitionPending('partition holders directory not ready')
            parts = partition_snapshot(identity, disk, plan, preserved)
            fingerprint = [{k: p.get(k) for k in ('name', 'maj:min', 'type', 'size', 'start', 'partuuid', 'parttype')}
                           for p in parts]
            require(previous is None or fingerprint == previous,
                    'complete partition identity or geometry changed during discovery')
            if consecutive:
                return disk, parts
            previous = fingerprint
            consecutive = True
            detail = 'waiting for a second identical complete partition inventory'
        except PartitionPending as exc:
            consecutive = False
            detail = str(exc)
        print(f'Partition discovery: {detail}. Observed: ' + json.dumps(disk.get('children', []), sort_keys=True))
        # settle alone only drains queued events. Re-enumerate after a bounded
        # delay as device nodes and their udev properties can arrive separately.
        settled = run('udevadm', 'settle', '--timeout=1', ok=(0, 1))
        if settled.returncode:
            diagnostics = (settled.stdout + settled.stderr).lower()
            require('timed out' in diagnostics or 'timeout' in diagnostics,
                    f'udevadm settle failed: {diagnostics.strip()}')
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(0.2, remaining))
    elapsed = time.monotonic() - started
    raise Refusal(f'partition discovery timed out after {elapsed:.1f}s (limit {timeout}s) '
                  f'without exact stable planned layout: {detail}. Observed: {json.dumps(observed, sort_keys=True)}')


def reread_partitions(identity):
    """Refresh kernel metadata after sgdisk closes, without rewriting the GPT."""
    _, disk = inspect_disk(identity['device'], blank=False, expected=identity)
    # Missing child sysfs is permissible only for this metadata reread. Mounted
    # and swap entries and all visible holders are still checked; the kernel
    # itself refuses BLKRRPART on busy partitions. Formatting never uses this.
    busy_check(disk, allow_missing_children=True)
    # Let probes triggered by sgdisk close partition descriptors before the ONE
    # kernel reread. A timeout/failure is fatal here, not an ignored ioctl retry.
    run('udevadm', 'settle', '--timeout=5')
    fd = os.open(identity['device'], os.O_RDONLY | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        major, minor = map(int, identity['devnum'].split(':'))
        require(stat.S_ISBLK(st.st_mode) and st.st_rdev == os.makedev(major, minor), 'reread device identity mismatch')
        _, disk = inspect_disk(identity['device'], blank=False, expected=identity)
        busy_check(disk, allow_missing_children=True)
        # BLKRRPART operates on this very descriptor, not a reopened procfd path.
        # It refreshes kernel partition metadata only, never writes the disk.
        try:
            fcntl.ioctl(fd, 0x125f)
        except OSError as exc:
            raise Refusal(f'kernel partition reread failed: {exc}') from exc
        print('Kernel partition reread completed (BLKRRPART on pinned descriptor).')
        inspect_disk(identity['device'], blank=False, expected=identity)
    finally:
        os.close(fd)


def mount_partition(identity, part, number, dest, mounts, options=None, count=2):
    check_partition(identity, part, number, count)
    major, minor = map(int, part['maj:min'].split(':'))
    # Further subvolume mounts cannot claim an already-mounted partition.
    fd = os.open(part['name'], os.O_RDONLY | os.O_CLOEXEC)
    try:
        require(os.fstat(fd).st_rdev == os.makedev(major, minor), 'mount device identity changed')
        check_partition(identity, part, number, count)
        args = ['mount'] + (['-o', options] if options else [])
        run(*args, f'/proc/self/fd/{fd}', dest, pass_fds=(fd,))
        mounts.append(dest)  # Register before any check that might fail.
        mounted = mount_for(dest)
        source = mounted['source'].split('[', 1)[0]
        require(mounted['target'] == str(dest) and Path(source).stat().st_rdev == os.makedev(major, minor),
                'mounted filesystem is not the confirmed partition')
    finally:
        os.close(fd)


def target_path(root, relative):
    """Never follow an image-provided symlink in a parent when editing target."""
    path = root / relative
    for parent in path.parents:
        if parent == root:
            break
        require(not parent.is_symlink(), f'unsafe target parent: {parent}')
    return path


def remove(root, relative):
    p = target_path(root, relative)
    if p.is_symlink() or p.is_file():
        p.unlink()
    elif p.is_dir():
        shutil.rmtree(p)


def put(root, relative, content, mode=0o644):
    p = target_path(root, relative)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    p.write_text(content)
    p.chmod(mode)


def link(root, relative, dest):
    remove(root, relative)
    p = target_path(root, relative)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.symlink_to(dest)


def validate_source(root, username):
    marker(root / MARKER)
    for binary in ('usr/bin/fish', 'usr/bin/niri', 'usr/bin/mkinitcpio',
                   'usr/bin/bootctl', 'usr/bin/useradd', 'usr/bin/chpasswd',
                   'usr/bin/locale-gen', 'usr/bin/visudo', 'usr/bin/systemctl',
                   'usr/bin/pacman-key'):
        require((root / binary).is_file(), f'offline source missing {binary}')
    require((root / 'usr/share/jstack/systemd/autologin.conf.in').is_file(), 'installed autologin policy missing')
    require('%USER%' in (root / 'usr/share/jstack/systemd/autologin.conf.in').read_text(), 'invalid installed autologin template')
    auto = root / 'etc/skel/.config/fish/conf.d/00-jstack-niri-autostart.fish'
    require(auto.is_file() and 'niri' in auto.read_text(), 'installed Niri defaults missing')
    require(len(list((root / 'usr/lib/modules').glob('*/vmlinuz'))) == 1, 'expected exactly one offline kernel payload')
    for line in (root / 'etc/passwd').read_text().splitlines():
        fields = line.split(':')
        require(len(fields) == 7, 'invalid source passwd')
        require(int(fields[2]) < 1000 or fields[0] == 'nobody', 'source has a human/live account')
        require(fields[0] != username, 'username already exists in source')
    for line in (root / 'etc/shadow').read_text().splitlines():
        fields = line.split(':')
        require(len(fields) >= 2 and fields[1].startswith(('!', '*')), 'source has unlocked credentials')


SEED_DIR = Path('/usr/share/jstack-seed/jcode')
SEED_FILES = ('openai.env',)


def seed_jcode_credentials(root, username):
    """Copy deliberately seeded jcode provider keys from the live USB to the
    new user's ~/.config/jcode, mode 0600. Absent seed means no-op."""
    for name in SEED_FILES:
        source = SEED_DIR / name
        if not source.is_file() or source.is_symlink():
            continue
        text = source.read_text()
        require(re.fullmatch(r'OPENAI_API_KEY=sk-[A-Za-z0-9_-]+\n', text), f'malformed seed {name}')
        home = target_path(root, f'home/{username}')
        config = target_path(root, f'home/{username}/.config/jcode')
        for d in (home / '.config', config):
            require(not d.is_symlink(), f'unsafe seed destination {d}')
            d.mkdir(mode=0o700, exist_ok=True)
        dest = config / name
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        uid = gid = None
        for line in (root / 'etc/passwd').read_text().splitlines():
            fields = line.split(':')
            if fields[0] == username:
                uid, gid = int(fields[2]), int(fields[3])
        require(uid is not None, 'seed: new user missing from passwd')
        for p in (home / '.config', config, dest):
            os.chown(p, uid, gid, follow_symlinks=False)
        print(f'Seeded jcode {name} for {username}.')


def configure_target(root, username, hostname, password, root_uuid, esp_uuid, serial, xbootldr_uuid=None):
    # Discard all releng/live systemd overrides, wants, masks, presets and getty
    # overrides. Reconstruct installed policy from package-owned /usr, not live /etc.
    for relative in ('etc/systemd/system', 'etc/systemd/system-generators',
                     'etc/systemd/system-preset', 'etc/systemd/journald.conf.d',
                     'etc/systemd/logind.conf.d',
                     'etc/mkinitcpio.conf.d', 'etc/mkinitcpio.d', 'etc/initcpio',
                     'etc/udev/rules.d/81-dhcpcd.rules',
                     'etc/NetworkManager/conf.d/20-jstack-live.conf',
                     'etc/sudoers.d/15-jstack-live', 'usr/local/lib/jstack-live-setup',
                     'usr/local/bin/jstack-install-live', MARKER,
                     'usr/local/bin/jstack-install-help',
                     'usr/share/applications/jstack-install.desktop',
                     'usr/share/applications/jstack-install-alongside.desktop',
                     'usr/share/applications/jstack-install-help.desktop',
                     'usr/share/doc/jstack-live', 'usr/share/jstack-seed',
                     'root/.automated_script.sh', 'root/.zlogin', 'etc/pacman.d/hooks'):
        remove(root, relative)
    # /root and /home were excluded, so neither live credentials nor runtime
    # home overrides can survive. Standard service accounts remain intact.
    put(root, 'etc/machine-id', '')
    link(root, 'var/lib/dbus/machine-id', '/etc/machine-id')
    put(root, 'etc/hostname', hostname + '\n')
    put(root, 'etc/hosts', f'127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {hostname}\n')
    put(root, 'etc/locale.gen', 'en_US.UTF-8 UTF-8\n')
    put(root, 'etc/locale.conf', 'LANG=en_US.UTF-8\n')
    put(root, 'etc/vconsole.conf', 'KEYMAP=us\n')
    put(root, 'etc/pacman.conf', '[options]\nArchitecture = auto\nCheckSpace\nColor\nParallelDownloads = 8\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\n\n[core]\nInclude = /etc/pacman.d/mirrorlist\n\n[extra]\nInclude = /etc/pacman.d/mirrorlist\n')
    link(root, 'etc/localtime', '/usr/share/zoneinfo/UTC')
    link(root, 'etc/resolv.conf', '/run/NetworkManager/resolv.conf')
    put(root, 'etc/motd', 'Jstack OS. No automatic snapshots or installer rollback.\n')
    put(root, 'etc/fstab',
        ''.join(f'UUID={root_uuid} {path} btrfs rw,noatime,compress=zstd:3,subvol={sub} 0 0\n'
                for sub, path in (('@', '/'), ('@home', '/home'), ('@log', '/var/log'), ('@pkg', '/var/cache/pacman/pkg'))) +
        (f'UUID={xbootldr_uuid} /boot vfat umask=0077 0 2\nUUID={esp_uuid} /efi vfat umask=0077 0 2\n'
         if xbootldr_uuid else f'UUID={esp_uuid} /boot vfat umask=0077 0 2\n'))
    put(root, 'etc/mkinitcpio.conf', 'MODULES=(btrfs)\nBINARIES=()\nFILES=()\nHOOKS=(base udev microcode modconf kms keyboard keymap consolefont block filesystems fsck)\n')
    # No autodetect: the installed initramfs must boot hardware other than the
    # build VM. Explicit preset ensures no archiso hooks/config survive.
    kernels = sorted((root / 'usr/lib/modules').glob('*/vmlinuz'))
    require(len(kernels) == 1, 'expected exactly one offline kernel')
    shutil.copyfile(kernels[0], root / 'boot/vmlinuz-linux')
    put(root, 'etc/mkinitcpio.d/linux.preset', "ALL_config='/etc/mkinitcpio.conf'\nALL_kver='/boot/vmlinuz-linux'\nPRESETS=('default')\ndefault_image='/boot/initramfs-linux.img'\n")
    def chroot(*command, input=None):
        return run('arch-chroot', root, *command, input=input)
    chroot('locale-gen')
    chroot('pacman-key', '--init')
    chroot('pacman-key', '--populate', 'archlinux')
    # Account creation uses clean package skel and never copies the live home.
    chroot('useradd', '-m', '-U', '-G', 'wheel,video,input,audio', '-s', '/usr/bin/fish', username)
    seed_jcode_credentials(root, username)
    chroot('chpasswd', input=f'{username}:{password}\n')
    put(root, 'etc/sudoers.d/10-wheel', '%wheel ALL=(ALL:ALL) ALL\n', 0o440)
    put(root, 'etc/sudoers.d/15-jstack-nopasswd', f'{username} ALL=(ALL:ALL) NOPASSWD: ALL\n', 0o440)
    chroot('visudo', '-c')
    chroot('systemctl', 'preset-all')
    chroot('systemctl', 'enable', *ENABLE)
    # Mask live-only units even if a package preset happens to enable one.
    chroot('systemctl', 'mask', *LIVE_UNITS, *DISABLE)
    chroot('systemctl', 'set-default', 'graphical.target')
    template = (root / 'usr/share/jstack/systemd/autologin.conf.in').read_text()
    put(root, 'etc/systemd/system/getty@tty1.service.d/autologin.conf', template.replace('%USER%', username))
    chroot('mkinitcpio', '-P')
    options = f'root=UUID={root_uuid} rootflags=subvol=@ rw rootfstype=btrfs zswap.enabled=0'
    if serial:
        options += ' console=tty0 console=ttyS0,115200n8 systemd.log_target=console'
        chroot('systemctl', 'enable', 'serial-getty@ttyS0.service')
    entry = f'title Jstack OS\nlinux /vmlinuz-linux\ninitrd /initramfs-linux.img\noptions {options}\n'
    if xbootldr_uuid:
        # Dual boot: never run bootctl here, it would replace the Windows
        # fallback loader EFI/BOOT/BOOTX64.EFI. Only add systemd-boot's own
        # path and loader.conf to the shared ESP. systemd-boot finds Windows
        # Boot Manager automatically, and reads entries from XBOOTLDR.
        loader = target_path(root, 'efi/EFI/systemd/systemd-bootx64.efi')
        loader.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / 'usr/lib/systemd/boot/efi/systemd-bootx64.efi', loader)
        put(root, 'efi/loader/loader.conf', 'default jstack.conf\ntimeout 5\nauto-entries yes\n')
        put(root, 'boot/loader/entries/jstack.conf', entry)
        require((root / 'efi/EFI/Microsoft/Boot/bootmgfw.efi').is_file(), 'Windows Boot Manager vanished from the ESP')
    else:
        chroot('bootctl', '--esp-path=/boot', '--no-variables', 'install')
        put(root, 'boot/loader/loader.conf', 'default jstack.conf\ntimeout 3\n')
        put(root, 'boot/loader/entries/jstack.conf', entry)
        require((root / 'boot/EFI/BOOT/BOOTX64.EFI').is_file(), 'UEFI fallback boot path missing')
    require((root / 'boot/initramfs-linux.img').stat().st_size > 0, 'initramfs missing')
    put(root, 'var/lib/jstack/installed-from-live.json', json.dumps({'schema': 1, 'source': TRUST,
        'username': username, 'hostname': hostname, 'root_uuid': root_uuid,
        'dual_boot': bool(xbootldr_uuid), 'rollback': False}, sort_keys=True) + '\n')


def create_partitions(identity, on_mutation=None):
    """Internal destructive phase, shared by install and disposable-VM proof.

    The public CLI still requires clean-live verification and explicit consent.
    This phase independently rechecks blankness and identity before writing.
    """
    plan = partition_plan(identity)
    inspect_disk(identity['device'], expected=identity)
    major, minor = map(int, identity['devnum'].split(':'))
    with exclusive_device(identity['device'], os.makedev(major, minor)) as (fd, pinned):
        inspect_disk(identity['device'], expected=identity)
        args = ['sgdisk', '--clear', '--resize-table=128', f'--set-alignment={1024**2 // identity["sector"]}']
        for part in plan:
            number = part['number']
            args.extend((f'--new={number}:{part["first"]}:{part["last"]}',
                         f'--typecode={number}:{part["parttype"]}',
                         f'--partition-guid={number}:{part["partuuid"]}',
                         f'--change-name={number}:JSTACK-' + ('ESP' if number == 1 else 'ROOT')))
        if on_mutation is not None:
            on_mutation()
        result = run(*args, pinned, pass_fds=(fd,))
        print('Partitioner stdout:\n' + result.stdout)
        print('Partitioner stderr:\n' + result.stderr)
    reread_partitions(identity)
    return wait_for_partitions(identity, plan)


def register_boot_entry(identity, esp_number):
    """Add one UEFI NVRAM entry for systemd-boot on the shared ESP and put it
    first. Windows Boot Manager's entry is kept and stays in the boot order.
    Failure is not fatal: firmware boot menus can still pick the entry."""
    try:
        current = run('efibootmgr').stdout
        if 'Jstack OS' not in current:
            run('efibootmgr', '--create', '--disk', identity['device'], '--part', str(esp_number),
                '--label', 'Jstack OS', '--loader', '\\EFI\\systemd\\systemd-bootx64.efi')
        print('UEFI boot entry "Jstack OS" registered. Windows Boot Manager remains available.')
    except Refusal as exc:
        print(f'WARNING: could not register UEFI boot entry ({exc}). Choose '
              '\\EFI\\systemd\\systemd-bootx64.efi from the firmware boot menu.', file=sys.stderr)


def install(identity, source, username, hostname, password, serial=False, layout=None):
    """layout=None: blank disk. Otherwise: alongside Windows in confirmed free space."""
    modified = False
    mounts = []
    workspace = Path(tempfile.mkdtemp(prefix='jstack-install-', dir='/run'))
    try:
        base, is_image = source
        if is_image:
            source_mount = workspace / 'source'
            source_mount.mkdir()
            run('mount', '-t', 'squashfs', '-o', 'loop,ro,nodev,nosuid', base, source_mount)
            mounts.append(source_mount)
            base = source_mount
        validate_source(base, username)
        needed = int(run('du', '-sx', '--block-size=1', base).stdout.split()[0])
        room = identity['size'] if layout is None else \
            (layout['plan'][1]['last'] - layout['plan'][1]['first'] + 1) * identity['sector']
        require(room > needed * 1.25 + 2 * 1024**3, 'target too small for expanded source and free space')
        # Recheck all environment, source, target and blankness immediately before
        # the first mutation, after potentially long prompts/source preparation.
        live_environment()
        require(source_info() == source, 'live source changed')
        def mark_modified():
            nonlocal modified
            modified = True
        if layout is None:
            disk, children = create_partitions(identity, on_mutation=mark_modified)
            numbers, count = (1, 2), 2
        else:
            disk, children, _ = create_free_space_partitions(layout, on_mutation=mark_modified)
            numbers = tuple(p['number'] for p in layout['plan'])
            count = len(layout['existing']) + 2
        for index, (number, part) in enumerate(zip(numbers, children), 1):
            partition_sysfs = (Path('/sys/dev/block') / part['maj:min']).resolve(strict=True)
            require(str(partition_sysfs.parent) == identity['sysfs'] and (partition_sysfs / 'partition').read_text().strip() == str(number),
                    'partition ancestry mismatch')
            inspect_disk(identity['device'], blank=False, expected=identity)
            busy_check(disk)
            major, minor = map(int, part['maj:min'].split(':'))
            with exclusive_device(part['name'], os.makedev(major, minor), release_claim=True) as (fd, pinned):
                check_partition(identity, part, number, count)
                if index == 1:
                    run('mkfs.fat', '-F', '32', '-n', 'JSTACK-ESP' if layout is None else 'JSTACK-BOOT', pinned, pass_fds=(fd,))
                else:
                    run('mkfs.btrfs', '-L', 'jstack', pinned, pass_fds=(fd,))
        boot, rootpart = (p['name'] for p in children)
        top = workspace / 'top'
        top.mkdir()
        inspect_disk(identity['device'], blank=False, expected=identity)
        mount_partition(identity, children[1], numbers[1], top, mounts, count=count)
        for sub in ('@', '@home', '@log', '@pkg'):
            run('btrfs', 'subvolume', 'create', top / sub)
        run('umount', top)
        mounts.remove(top)
        target = workspace / 'target'
        target.mkdir()
        for sub, relative in (('@', ''), ('@home', 'home'), ('@log', 'var/log'), ('@pkg', 'var/cache/pacman/pkg')):
            dest = target / relative
            dest.mkdir(parents=True, exist_ok=True)
            inspect_disk(identity['device'], blank=False, expected=identity)
            mount_partition(identity, children[1], numbers[1], dest, mounts, f'subvol={sub},compress=zstd:3,noatime', count=count)
        (target / 'boot').mkdir()
        mount_partition(identity, children[0], numbers[0], target / 'boot', mounts, 'umask=0077', count=count)
        esp = boot
        if layout is not None:
            # The shared Windows ESP. JStack only adds EFI/systemd and loader/.
            esp_node = next(p for p in disk['children']
                            if int((Path('/sys/dev/block') / p['maj:min'] / 'partition').read_text()) == layout['esp'])
            (target / 'efi').mkdir()
            mount_partition(identity, esp_node, layout['esp'], target / 'efi', mounts, 'umask=0077', count=count)
            esp = esp_node['name']
            require(not (target / 'efi/loader/loader.conf').exists() and not (target / 'efi' / SYSTEMD_BOOT).exists(),
                    'the EFI partition already has a systemd-boot loader, refusing to replace it')
        inspect_disk(identity['device'], blank=False, expected=identity)
        run('rsync', '-aHAXx', '--numeric-ids', *['--exclude=' + p for p in EXCLUDES],
            str(base) + '/', str(target) + '/')
        root_uuid = run('blkid', '-s', 'UUID', '-o', 'value', rootpart).stdout.strip()
        esp_uuid = run('blkid', '-s', 'UUID', '-o', 'value', esp).stdout.strip()
        boot_uuid = run('blkid', '-s', 'UUID', '-o', 'value', boot).stdout.strip() if layout else None
        require(all(re.fullmatch(r'[a-fA-F0-9-]+', u) for u in (root_uuid, esp_uuid, boot_uuid or '0')),
                'invalid new filesystem UUID')
        inspect_disk(identity['device'], blank=False, expected=identity)
        configure_target(target, username, hostname, password, root_uuid, esp_uuid, serial, boot_uuid)
        if layout is not None:
            register_boot_entry(identity, layout['esp'])
        # Flush the target, not unrelated disks.
        run('sync', '-f', target)
    except BaseException:
        if modified and layout is not None:
            print('INSTALLATION FAILED AFTER CREATING JSTACK PARTITIONS. Windows partitions were not modified '
                  'and Windows still boots. Delete the two JSTACK partitions in Windows Disk Management to '
                  'return the space, then retry.', file=sys.stderr)
        elif modified:
            print('INSTALLATION FAILED AFTER TARGET MODIFICATION. NO rollback or persistent recovery. '
                  'Target is incomplete and requires reinstallation. This blank-only installer will refuse '
                  'the partial target. Do not erase it without independently verifying its identity.', file=sys.stderr)
        raise
    finally:
        failed_unmount = False
        for mount in reversed(mounts):
            try:
                run('umount', mount)
            except (Refusal, OSError) as exc:
                failed_unmount = True
                print(f'Unmount failed, do not remove media: {mount}: {exc}', file=sys.stderr)
        if not failed_unmount:
            # NEVER recursively delete a workspace that ever held mounts.
            # An unexpected/unregistered mount must fail closed, not erase data.
            for name in ('source', 'top', 'target'):
                directory = workspace / name
                if directory.exists():
                    directory.rmdir()
            workspace.rmdir()
        else:
            raise Refusal('target cleanup incomplete. Do not remove media or treat this installation as successful')
    print('JSTACK-INSTALL: complete. Power off, remove the USB, then boot the internal disk.')


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--list', action='store_true', help='read-only target inventory')
    mode.add_argument('--check', action='store_true', help='read-only source/target preflight')
    p.add_argument('--disk', help='explicit whole internal blank disk, preferably /dev/disk/by-id/...')
    p.add_argument('--alongside-windows', action='store_true',
                   help='install into unallocated space next to Windows, keeping every existing partition')
    p.add_argument('--confirm', help='exact INSTALL- or ALONGSIDE- token from --check, no --yes bypass')
    p.add_argument('--user')
    p.add_argument('--hostname', default='jstack')
    p.add_argument('--password-stdin', action='store_true', help='read one password line, never pass passwords as arguments')
    p.add_argument('--serial-console', action='store_true', help='also enable normal serial login and kernel console')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    guided = not args.disk and not (args.list or args.check)
    live_environment()
    source = source_info()
    print('CLEAN offline source:', source[0])
    if args.list:
        list_disks()
        return 0
    if args.alongside_windows:
        return main_alongside(args, source, guided)
    if not args.disk:
        list_disks()
        if args.check:
            return 0
        require(sys.stdin.isatty(), 'noninteractive installation requires --disk, --confirm, --user, --password-stdin')
        args.disk = input('Explicit whole blank internal disk path (empty cancels): ').strip()
        require(bool(args.disk), 'cancelled')
    identity, _ = inspect_disk(args.disk)
    print(json.dumps({'identity': identity, 'confirmation': token(identity)}, sort_keys=True))
    if args.check:
        return 0
    print('This installs to the selected BLANK disk. NO rollback, snapshots, or persistent recovery.\n'
          'Failures require reinstallation. Installed policy enables tty1 autologin and passwordless sudo.')
    if args.confirm is None:
        require(sys.stdin.isatty(), 'exact --confirm identity token required noninteractively')
        args.confirm = input('Type the complete INSTALL- token above to authorize installation: ')
    require(args.confirm == token(identity), 'confirmation does not exactly match target identity')
    if not args.user:
        require(sys.stdin.isatty(), '--user required')
        args.user = input('New username: ')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', args.user) and args.user not in ('root', 'nobody', 'builder'), 'invalid username')
    if guided:
        args.hostname = input(f'Hostname [{args.hostname}]: ').strip() or args.hostname
    require(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', args.hostname), 'invalid hostname')
    if args.password_stdin:
        password = sys.stdin.readline().rstrip('\n')
    else:
        require(sys.stdin.isatty(), '--password-stdin required noninteractively')
        password = getpass.getpass('New user password: ')
        require(password == getpass.getpass('Repeat password: '), 'passwords differ')
    require(len(password) >= 8 and not any(c in password for c in '\r\n\x00:'), 'password must have at least 8 characters, without colon/newline/NUL')
    install(identity, source, args.user, args.hostname, password, args.serial_console)
    return 0


def ask_account(args, guided):
    if not args.user:
        require(sys.stdin.isatty(), '--user required')
        args.user = input('New username: ')
    require(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', args.user) and args.user not in ('root', 'nobody', 'builder'), 'invalid username')
    if guided:
        args.hostname = input(f'Hostname [{args.hostname}]: ').strip() or args.hostname
    require(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', args.hostname), 'invalid hostname')
    if args.password_stdin:
        password = sys.stdin.readline().rstrip('\n')
    else:
        require(sys.stdin.isatty(), '--password-stdin required noninteractively')
        password = getpass.getpass('New user password: ')
        require(password == getpass.getpass('Repeat password: '), 'passwords differ')
    require(len(password) >= 8 and not any(c in password for c in '\r\n\x00:'), 'password must have at least 8 characters, without colon/newline/NUL')
    return password


def windows_disks():
    """Read-only: internal GPT disks that can take JStack next to Windows."""
    found = []
    for disk in inventory():
        if disk['type'] != 'disk':
            continue
        try:
            layout = free_space_layout(disk['name'])
            found.append(layout)
            print(json.dumps({'eligible': True, 'device': disk['name'], 'windows': layout['windows'],
                              'confirmation': alongside_token(layout)}))
        except (Refusal, OSError, ValueError, KeyError) as exc:
            print(json.dumps({'eligible': False, 'device': disk['name'], 'reason': str(exc)}))
    return found


def main_alongside(args, source, guided):
    if not args.disk:
        found = windows_disks()
        require(found, 'no internal disk with enough unallocated space. In Windows, shrink C: in '
                       'Disk Management (at least 40 GiB), then boot this USB again')
        if len(found) == 1 and sys.stdin.isatty():
            args.disk = found[0]['identity']['device']
        else:
            require(sys.stdin.isatty(), 'noninteractive installation requires --disk')
            args.disk = input('Disk path (empty cancels): ').strip()
            require(bool(args.disk), 'cancelled')
    layout = free_space_layout(args.disk)
    print(describe_layout(layout))
    print(json.dumps({'confirmation': alongside_token(layout)}))
    if args.check:
        return 0
    if not layout['windows']:
        print('NOTE: no Windows Boot Manager found on the EFI partition.')
    if layout['bitlocker']:
        print('WARNING: BitLocker is ON for ' + ', '.join(layout['bitlocker']) + '. Windows may ask for the '
              'BitLocker RECOVERY KEY at its next boot. Have it ready (aka.ms/myrecoverykey) before continuing.')
    print('Only the two "create" partitions are written, plus systemd-boot files added to the EFI\n'
          'partition. Windows and its files are not touched. Installed policy enables tty1\n'
          'autologin and passwordless sudo.')
    if args.confirm is None:
        require(sys.stdin.isatty(), 'exact --confirm token required noninteractively')
        args.confirm = input('Type the complete ALONGSIDE- token above to authorize installation: ').strip()
    require(args.confirm == alongside_token(layout), 'confirmation does not exactly match this disk and plan')
    password = ask_account(args, guided)
    install(layout['identity'], source, args.user, args.hostname, password, args.serial_console, layout=layout)
    return 0


if __name__ == '__main__':
    # Cleanup mounts and report incomplete targets on normal termination too.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        sys.exit(main())
    except (Refusal, OSError, ValueError, KeyError, KeyboardInterrupt) as exc:
        print(f'jstack-install-live: REFUSED/FAILED: {exc}', file=sys.stderr)
        sys.exit(1)
