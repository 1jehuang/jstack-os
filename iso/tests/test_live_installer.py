#!/usr/bin/env python3
"""Host-safe tests. Every external command is mocked, no block device is opened.

Run: python -m unittest discover -s iso/tests -p test_live_installer.py -v
Real offline boot/install coverage belongs to the separate disposable VM harness.
"""
import contextlib
import copy
import importlib.util
import io
import hashlib
import json
import errno
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

SPEC = importlib.util.spec_from_file_location('live_installer', Path(__file__).parents[1] / 'jstack-install-live.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

IDENTITY = {'device': '/dev/vdb', 'devnum': '252:16', 'sysfs': '/sys/devices/pci/virtio2/block/vdb',
            'diskseq': '42', 'size': 40 * 1024**3, 'serial': 'JSTACK-TEST', 'wwn': None,
            'model': None, 'transport': None, 'sector': 512}
DISK = {'name': '/dev/vdb', 'type': 'disk', 'size': 40 * 1024**3, 'ro': False, 'rm': False,
        'tran': None, 'serial': 'JSTACK-TEST', 'wwn': None, 'model': None,
        'maj:min': '252:16', 'log-sec': 512, 'mountpoints': [None]}


class SafeTest(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(installer, 'run', side_effect=AssertionError('unexpected command'))
        self.run = self.guard.start()
        self.addCleanup(self.guard.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='jstack-live-test-', dir=os.environ.get('JCODE_SCRATCH_DIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, path, text='fixture'):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p


class DiskSafetyTests(SafeTest):
    def test_partition_without_slaves_directory_protects_parent(self):
        disk = self.root / 'devices/block/vdb'
        part = disk / 'vdb1'
        part.mkdir(parents=True)
        (part / 'partition').write_text('1\n')
        (disk / 'dev').write_text('252:16\n')
        (disk / 'slaves').mkdir()
        devdir = self.root / 'sys/dev/block'
        devdir.mkdir(parents=True)
        (devdir / '252:17').symlink_to(part)
        (devdir / '252:16').symlink_to(disk)
        realpath = Path
        def path(value):
            return devdir if str(value) == '/sys/dev/block' else realpath(value)
        with patch.object(installer, 'Path', side_effect=path):
            self.assertEqual(installer.backing_devices({'252:17'}), {'252:17', '252:16'})

    def test_mount_registered_before_post_mount_validation(self):
        mounts = []
        self.run.side_effect = None
        part = {**DISK, 'name': '/dev/vdb1', 'maj:min': '252:17'}
        with patch.object(installer, 'check_partition'), patch.object(installer.os, 'open', return_value=77), \
             patch.object(installer.os, 'close'), patch.object(installer.os, 'fstat', return_value=SimpleNamespace(st_rdev=os.makedev(252, 17))), \
             patch.object(installer, 'mount_for', side_effect=installer.Refusal('cannot verify mount')), \
             self.assertRaisesRegex(installer.Refusal, 'cannot verify mount'):
            installer.mount_partition(IDENTITY, part, 1, self.root, mounts)
        self.assertEqual(mounts, [self.root])

    @contextlib.contextmanager
    def disk(self, node=None, ident=None):
        node = copy.deepcopy(node or DISK)
        ident = copy.deepcopy(ident or IDENTITY)
        with patch.object(installer, 'inventory', return_value=[node]), \
             patch.object(installer, 'node_for', return_value=node), \
             patch.object(installer, 'disk_identity', return_value=ident), \
             patch.object(installer, 'busy_check') as busy, \
             patch.object(installer, 'jsrun', return_value={'signatures': []}) as signatures:
            self.run.side_effect = None
            self.run.return_value = SimpleNamespace(returncode=2, stdout='', stderr='')
            yield busy, signatures

    def test_blank_internal_disk_allowed(self):
        with self.disk() as (busy, signatures):
            got, _ = installer.inspect_disk('/dev/vdb')
            self.assertEqual(got, IDENTITY)
            busy.assert_called_once()
            signatures.assert_called_once_with('wipefs', '--no-act', '--json', '/dev/vdb')

    def test_partition_mapper_loop_readonly_removable_refused(self):
        for key, value in [('type', 'part'), ('type', 'crypt'), ('type', 'loop'), ('ro', True), ('rm', True)]:
            with self.subTest(key=key, value=value):
                disk = {**DISK, key: value}
                with self.disk(node=disk), self.assertRaises(installer.Refusal):
                    installer.inspect_disk('/dev/vdb')

    def test_usb_transport_and_usb_ancestry_refused(self):
        for disk, ident in [({**DISK, 'tran': 'usb'}, IDENTITY),
                            (DISK, {**IDENTITY, 'sysfs': '/sys/devices/pci/usb2/2-1/block/sda'})]:
            with self.disk(disk, ident), self.assertRaisesRegex(installer.Refusal, 'USB'):
                installer.inspect_disk('/dev/vdb')

    def test_minimum_is_32_gib_and_sector_limits(self):
        for change in ({'size': 32 * 1024**3 - 1}, {'size': 32_000_000_000}, {'sector': 2048}):
            with self.disk(ident={**IDENTITY, **change}), self.assertRaises(installer.Refusal):
                installer.inspect_disk('/dev/vdb')
        with self.disk(ident={**IDENTITY, 'size': 32 * 1024**3, 'sector': 4096}):
            installer.inspect_disk('/dev/vdb')

    def test_existing_descendants_refused_even_unmounted(self):
        with self.disk(node={**DISK, 'children': [{'type': 'part'}]}), self.assertRaisesRegex(installer.Refusal, 'descendants'):
            installer.inspect_disk('/dev/vdb')

    def test_any_signature_refused(self):
        for signature in ('gpt', 'dos', 'btrfs', 'ext4', 'linux_raid_member', 'crypto_LUKS'):
            with self.subTest(signature=signature), self.disk() as (_, probe):
                probe.return_value = {'signatures': [{'type': signature}]}
                with self.assertRaisesRegex(installer.Refusal, 'signatures'):
                    installer.inspect_disk('/dev/vdb')

    def test_second_independent_probe_must_be_blank(self):
        with self.disk():
            self.run.return_value = SimpleNamespace(returncode=0, stdout='TYPE=ext4', stderr='')
            with self.assertRaisesRegex(installer.Refusal, 'blkid'):
                installer.inspect_disk('/dev/vdb')

    def test_identity_changes_refused_even_after_partitioning(self):
        for field, changed in [('serial', 'OTHER'), ('diskseq', '43'), ('size', 80 * 1024**3),
                               ('sysfs', '/sys/devices/other'), ('devnum', '252:32')]:
            with self.subTest(field=field), self.disk(ident={**IDENTITY, field: changed}), self.assertRaisesRegex(installer.Refusal, 'IDENTITY CHANGED'):
                installer.inspect_disk('/dev/vdb', blank=False, expected=IDENTITY)

    def test_confirmation_covers_entire_identity(self):
        original = installer.token(IDENTITY)
        self.assertRegex(original, r'^INSTALL-[0-9a-f]{16}$')
        for field in IDENTITY:
            self.assertNotEqual(original, installer.token({**IDENTITY, field: 'changed'}))

    def test_mount_swap_holder_and_backing_conflicts_refused(self):
        for reason in ('mountpoints', 'mount', 'swap', 'holder', 'backing'):
            disk = {**DISK, 'mountpoints': ['/boot'] if reason == 'mountpoints' else [None]}
            with self.subTest(reason=reason), \
                 patch.object(installer, 'mounted_devices', return_value={'252:16'} if reason == 'mount' else set()), \
                 patch.object(installer, 'swap_devices', return_value={'252:16'} if reason == 'swap' else set()), \
                 patch.object(installer, 'backing_devices', return_value={'252:16'} if reason == 'backing' else set()), \
                 patch.object(Path, 'iterdir', return_value=iter([Path('dm-0')] if reason == 'holder' else [])), \
                 self.assertRaises(installer.Refusal):
                installer.busy_check(disk)

    def test_descendant_mount_refused(self):
        disk = {**DISK, 'children': [{**DISK, 'name': '/dev/vdb1', 'maj:min': '252:17', 'mountpoints': ['/run/archiso/bootmnt']}]}
        with patch.object(installer, 'mounted_devices', return_value=set()), \
             patch.object(installer, 'swap_devices', return_value=set()), \
             patch.object(installer, 'backing_devices', return_value=set()), \
             patch.object(Path, 'iterdir', return_value=iter([])), self.assertRaises(installer.Refusal):
            installer.busy_check(disk)

    def test_partition_geometry_revalidated(self):
        part = {**DISK, 'type': 'part', 'name': '/dev/vdb1', 'maj:min': '252:17', 'partuuid': 'a', 'start': 2048}
        for field, value in [('name', '/dev/vdc1'), ('partuuid', 'b'), ('start', 4096), ('size', 1)]:
            with self.subTest(field=field), patch.object(installer, 'inspect_disk', return_value=(IDENTITY, {'children': [{**part, field: value}, {'maj:min': '252:18'}]})), self.assertRaisesRegex(installer.Refusal, 'geometry'):
                installer.check_partition(IDENTITY, part, 1)


class PartitionReadinessTests(SafeTest):
    def fixture(self, sector=512):
        parent = self.root / 'devices/block/vdb'
        parent.mkdir(parents=True)
        devdir = self.root / 'sys/dev/block'
        devdir.mkdir(parents=True)
        identity = {**IDENTITY, 'sector': sector, 'sysfs': str(parent)}
        plan = installer.partition_plan(identity)
        parts = []
        for wanted in plan:
            number = wanted['number']
            path = parent / f'vdb{number}'
            path.mkdir()
            (path / 'partition').write_text(str(number))
            (path / 'start').write_text(str(wanted['first'] * sector // 512))
            size = (wanted['last'] - wanted['first'] + 1) * sector
            (path / 'size').write_text(str(size // 512))
            (devdir / f'252:{16+number}').symlink_to(path)
            parts.append({**DISK, 'name': f'/dev/vdb{number}', 'type': 'part',
                          'maj:min': f'252:{16+number}', 'size': size,
                          'start': wanted['first'] * sector // 512,
                          'partuuid': wanted['partuuid'], 'parttype': wanted['parttype']})
        return identity, plan, {**DISK, 'children': parts}, devdir

    @contextlib.contextmanager
    def paths(self, devdir):
        realpath, realstat = Path, Path.stat
        def path(value):
            return devdir if str(value) == '/sys/dev/block' else realpath(value)
        def stat_path(path, *args, **kwargs):
            if str(path) in ('/dev/vdb1', '/dev/vdb2'):
                number = int(str(path)[-1])
                return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(252, 16 + number))
            return realstat(path, *args, **kwargs)
        with patch.object(installer, 'Path', side_effect=path), patch.object(Path, 'stat', new=stat_path):
            yield

    def test_plan_exact_512_and_4kn_geometry(self):
        for sector in (512, 4096):
            plan = installer.partition_plan({**IDENTITY, 'sector': sector})
            esp, root = plan
            self.assertEqual(esp['first'] * sector, 1024**2)
            self.assertEqual((esp['last'] - esp['first'] + 1) * sector, 1024**3)
            self.assertEqual(root['first'], esp['last'] + 1)
            self.assertEqual(root['last'], IDENTITY['size'] // sector - 2 - (16384 + sector - 1) // sector)
            self.assertNotEqual(esp['partuuid'], root['partuuid'])

    def test_complete_snapshot_matches_intended_geometry(self):
        identity, plan, disk, devdir = self.fixture(4096)
        with self.paths(devdir):
            self.assertEqual(installer.partition_snapshot(identity, disk, plan), disk['children'])

    def test_pending_only_for_incomplete_nodes_or_attributes(self):
        identity, plan, disk, devdir = self.fixture()
        with self.paths(devdir):
            for children in ([], disk['children'][:1], [{**disk['children'][0], 'partuuid': None}, disk['children'][1]]):
                with self.subTest(children=len(children)), self.assertRaises(installer.PartitionPending):
                    installer.partition_snapshot(identity, {**disk, 'children': children}, plan)
            (devdir / '252:17').unlink()
            with self.assertRaises(installer.PartitionPending):
                installer.partition_snapshot(identity, disk, plan)

    def test_wrong_geometry_uuid_type_and_extra_children_never_pending(self):
        identity, plan, disk, devdir = self.fixture()
        with self.paths(devdir):
            for key, value in [('size', 1234), ('partuuid', 'wrong'), ('parttype', 'wrong'), ('type', 'crypt')]:
                bad = {**disk, 'children': [{**disk['children'][0], key: value}, disk['children'][1]]}
                with self.subTest(key=key), self.assertRaises(installer.Refusal):
                    installer.partition_snapshot(identity, bad, plan)
            with self.assertRaises(installer.Refusal):
                installer.partition_snapshot(identity, {**disk, 'children': disk['children'] * 2}, plan)

    @contextlib.contextmanager
    def waiting(self, snapshots):
        parts = [{**DISK, 'name': '/dev/vdb1', 'maj:min': '252:17'},
                 {**DISK, 'name': '/dev/vdb2', 'maj:min': '252:18'}]
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(installer, 'inspect_disk', return_value=(IDENTITY, {**DISK, 'children': parts})) as inspect, \
             patch.object(installer, 'busy_check', return_value=True) as busy, \
             patch.object(installer, 'partition_snapshot', side_effect=snapshots) as snapshot, \
             patch.object(installer.time, 'sleep'), patch.object(installer.time, 'monotonic', return_value=0), \
             contextlib.redirect_stdout(io.StringIO()):
            yield parts, inspect, busy, snapshot

    def test_waits_for_two_complete_snapshots_after_incomplete_discovery(self):
        with self.waiting(None) as (parts, inspect, _, snapshot):
            snapshot.side_effect = [installer.PartitionPending('no nodes'), parts, parts]
            self.assertEqual(installer.wait_for_partitions(IDENTITY, [] )[1], parts)
            self.assertEqual(inspect.call_count, 3)
            self.assertEqual(self.run.call_count, 2)
            self.assertTrue(all(call.args[0] == 'udevadm' for call in self.run.call_args_list))

    def test_changed_complete_snapshot_is_fatal_even_after_incomplete_view(self):
        with self.waiting(None) as (parts, _, _, snapshot):
            changed = [{**parts[0], 'maj:min': '252:99'}, parts[1]]
            snapshot.side_effect = [parts, installer.PartitionPending('node temporarily absent'), changed]
            with self.assertRaisesRegex(installer.Refusal, 'changed during discovery'):
                installer.wait_for_partitions(IDENTITY, [])

    def test_parent_identity_and_busy_failure_are_not_retried(self):
        for location in ('identity', 'busy'):
            with self.waiting(None) as (_, inspect, busy, snapshot):
                (inspect if location == 'identity' else busy).side_effect = installer.Refusal('unsafe parent')
                with self.assertRaisesRegex(installer.Refusal, 'unsafe parent'):
                    installer.wait_for_partitions(IDENTITY, [])
                self.assertEqual(inspect.call_count, 1)
                snapshot.assert_not_called()
                self.run.assert_not_called()

    def test_missing_child_holders_waits_but_parent_missing_is_fatal(self):
        with self.waiting(None) as (parts, inspect, busy, snapshot):
            busy.side_effect = [False, True, True]
            snapshot.side_effect = [parts, parts]
            installer.wait_for_partitions(IDENTITY, [])
            self.assertEqual(inspect.call_count, 3)
            self.assertEqual(snapshot.call_count, 2)

    def test_retry_limit_retains_last_inventory(self):
        with self.waiting(installer.PartitionPending('not ready')) as (_, inspect, _, _):
            with self.assertRaisesRegex(installer.Refusal, 'timed out.*Observed:'):
                installer.wait_for_partitions(IDENTITY, [])
            self.assertEqual(inspect.call_count, 150)

    def test_deadline_stops_before_retry_limit(self):
        with self.waiting(installer.PartitionPending('not ready')) as (_, inspect, _, _), \
             patch.object(installer.time, 'monotonic', side_effect=[0, 0, 31, 32, 32]):
            with self.assertRaisesRegex(installer.Refusal, 'limit 30s'):
                installer.wait_for_partitions(IDENTITY, [])
            self.assertEqual(inspect.call_count, 1)

    def test_udev_timeout_may_retry_but_other_failures_do_not(self):
        with self.waiting(None) as (parts, _, _, snapshot):
            snapshot.side_effect = [installer.PartitionPending('pending'), parts, parts]
            self.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='Timed out waiting for queue')
            installer.wait_for_partitions(IDENTITY, [])
        with self.waiting(installer.PartitionPending('pending')):
            self.run.return_value = SimpleNamespace(returncode=1, stdout='', stderr='Cannot connect to udev')
            with self.assertRaisesRegex(installer.Refusal, 'settle failed'):
                installer.wait_for_partitions(IDENTITY, [])

    def test_reread_uses_actual_pinned_fd_and_revalidates(self):
        self.run.side_effect = None
        st = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(252, 16))
        with patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)) as inspect, \
             patch.object(installer, 'busy_check'), patch.object(installer.os, 'open', return_value=77), \
             patch.object(installer.os, 'close') as close, patch.object(installer.os, 'fstat', return_value=st), \
             patch.object(installer.fcntl, 'ioctl') as ioctl, contextlib.redirect_stdout(io.StringIO()):
            installer.reread_partitions(IDENTITY)
            ioctl.assert_called_once_with(77, 0x125f)
            self.assertEqual(inspect.call_count, 3)
            close.assert_called_once_with(77)
        self.run.assert_called_once_with('udevadm', 'settle', '--timeout=5')

    def test_reread_errno_fails_without_retry(self):
        self.run.side_effect = None
        st = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(252, 16))
        with patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)), \
             patch.object(installer, 'busy_check'), patch.object(installer.os, 'open', return_value=77), \
             patch.object(installer.os, 'close'), patch.object(installer.os, 'fstat', return_value=st), \
             patch.object(installer.fcntl, 'ioctl', side_effect=OSError(errno.EBUSY, 'busy')) as ioctl, \
             self.assertRaisesRegex(installer.Refusal, 'reread failed'):
            installer.reread_partitions(IDENTITY)
        ioctl.assert_called_once()
        self.run.assert_called_once_with('udevadm', 'settle', '--timeout=5')

    def test_reread_rejects_changed_parent_or_descriptor_before_ioctl(self):
        self.run.side_effect = None
        for failure in ('parent', 'descriptor'):
            st = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600,
                                 st_rdev=os.makedev(252, 99 if failure == 'descriptor' else 16))
            with patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)) as inspect, \
                 patch.object(installer, 'busy_check'), patch.object(installer.os, 'open', return_value=77), \
                 patch.object(installer.os, 'close'), patch.object(installer.os, 'fstat', return_value=st), \
                 patch.object(installer.fcntl, 'ioctl') as ioctl, self.assertRaises(installer.Refusal):
                if failure == 'parent':
                    inspect.side_effect = [(IDENTITY, DISK), installer.Refusal('identity changed')]
                installer.reread_partitions(IDENTITY)
            ioctl.assert_not_called()

    def test_pre_reread_settle_failure_is_fatal_without_ioctl(self):
        self.run.side_effect = installer.Refusal('udev settle timeout')
        with patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)), \
             patch.object(installer, 'busy_check'), patch.object(installer.os, 'open') as opening, \
             patch.object(installer.fcntl, 'ioctl') as ioctl, \
             self.assertRaisesRegex(installer.Refusal, 'settle timeout'):
            installer.reread_partitions(IDENTITY)
        self.run.assert_called_once_with('udevadm', 'settle', '--timeout=5')
        opening.assert_not_called()
        ioctl.assert_not_called()

    def test_creation_uses_plan_and_closes_claim_before_reread(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        identity = {**IDENTITY, 'sector': 4096}
        plan = installer.partition_plan(identity)
        events = []
        @contextlib.contextmanager
        def exclusive(*args, **kwargs):
            events.append('claim-open')
            try:
                yield 77, '/proc/self/fd/77'
            finally:
                events.append('claim-closed')
        def command(*args, **kwargs):
            if args[0] == 'sgdisk':
                events.append('sgdisk')
                return SimpleNamespace(returncode=0, stdout='GPT written', stderr='kernel reread warning')
            return SimpleNamespace(returncode=0, stdout='1000\t/source\n', stderr='')
        def reread(*args):
            self.assertEqual(events, ['claim-open', 'sgdisk', 'claim-closed'])
            raise installer.Refusal('stop before formatting')
        self.run.side_effect = command
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source'), patch.object(installer, 'live_environment'), \
             patch.object(installer, 'source_info', return_value=(self.root, False)), \
             patch.object(installer, 'inspect_disk', return_value=(identity, DISK)), \
             patch.object(installer, 'partition_plan', return_value=plan), \
             patch.object(installer, 'exclusive_device', side_effect=exclusive), \
             patch.object(installer, 'reread_partitions', side_effect=reread), \
             contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaisesRegex(installer.Refusal, 'stop before formatting'):
            installer.install(identity, (self.root, False), 'alice', 'dell', 'password123')
        call = next(call for call in self.run.call_args_list if call.args[0] == 'sgdisk')
        self.assertIn('--resize-table=128', call.args)
        self.assertIn('--set-alignment=256', call.args)
        self.assertEqual(call.args[-1], '/proc/self/fd/77')
        self.assertEqual(call.kwargs['pass_fds'], (77,))
        for wanted in plan:
            number = wanted['number']
            self.assertIn(f'--new={number}:{wanted["first"]}:{wanted["last"]}', call.args)
            self.assertIn(f'--partition-guid={number}:{wanted["partuuid"]}', call.args)
            self.assertIn(f'--typecode={number}:{wanted["parttype"]}', call.args)
        self.assertIn('GPT written', output.getvalue())
        self.assertIn('kernel reread warning', output.getvalue())
        self.assertEqual(self.run.call_count, 2)


class SourceSafetyTests(SafeTest):
    def test_verified_fallback_source_check_does_not_mount(self):
        contents = b'synthetic image bytes'
        image = self.put('run/archiso/bootmnt/arch/x86_64/airootfs.sfs', contents.decode())
        self.put('run/archiso/bootmnt/arch/x86_64/airootfs.sha512', hashlib.sha512(contents).hexdigest() + '  airootfs.sfs\n')
        realpath = Path
        def path(value):
            value = str(value)
            return self.root / value.lstrip('/') if value.startswith(('/run/', '/sys/')) else realpath(value)
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout=json.dumps(installer.TRUST), returncode=0)
        st = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with patch.object(installer, 'Path', side_effect=path), patch.object(Path, 'lstat', return_value=st), \
             patch.object(installer, 'mount_for', return_value={'target': '/run/archiso/bootmnt', 'options': 'ro'}):
            self.assertEqual(installer.source_info(), (image, True))
        self.run.assert_called_once_with('unsquashfs', '-cat', image, installer.MARKER)

    def test_bios_and_missing_secureboot_variable_refused(self):
        with patch.object(installer.os, 'geteuid', return_value=0), patch.object(installer, 'marker'), \
             patch.object(Path, 'is_dir', side_effect=[True, False]), self.assertRaisesRegex(installer.Refusal, 'UEFI'):
            installer.live_environment()
        with patch.object(installer.os, 'geteuid', return_value=0), patch.object(installer, 'marker'), \
             patch.object(Path, 'is_dir', return_value=True), patch.object(Path, 'read_bytes', side_effect=FileNotFoundError()), \
             self.assertRaises(FileNotFoundError):
            installer.live_environment()

    def test_owned_marker_contract(self):
        fake = Mock()
        fake.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
        fake.read_text.return_value = json.dumps(installer.TRUST)
        installer.marker(fake)
        for change in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFREG | 0o666}, {'st_mode': stat.S_IFLNK | 0o777}):
            fake.lstat.return_value = SimpleNamespace(**{'st_mode': stat.S_IFREG | 0o644, 'st_uid': 0, 'st_gid': 0, **change})
            with self.assertRaises(installer.Refusal):
                installer.marker(fake)

    def test_private_or_unknown_marker_refused(self):
        fake = Mock()
        fake.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_gid=0)
        for marker in ({**installer.TRUST, 'clean': False}, {}, {**installer.TRUST, 'schema': 2}, {**installer.TRUST, 'extra': 'overlay'}):
            fake.read_text.return_value = json.dumps(marker)
            with self.assertRaises(installer.Refusal):
                installer.marker(fake)

    def test_host_execution_fails_before_commands(self):
        with patch.object(installer.os, 'geteuid', return_value=0), patch.object(Path, 'is_dir', return_value=False), self.assertRaisesRegex(installer.Refusal, 'live environment'):
            installer.live_environment()
        self.run.assert_not_called()

    def test_secure_boot_on_unknown_missing_fail_closed(self):
        for contents in (b'\x07\0\0\0\x01', b'', b'\x07\0\0\0\x02'):
            with patch.object(installer.os, 'geteuid', return_value=0), patch.object(Path, 'is_dir', return_value=True), \
                 patch.object(installer, 'marker'), patch.object(Path, 'read_bytes', return_value=contents), self.assertRaisesRegex(installer.Refusal, 'Secure Boot'):
                installer.live_environment()

    def test_missing_tool_refused(self):
        with patch.object(installer.os, 'geteuid', return_value=0), patch.object(Path, 'is_dir', return_value=True), \
             patch.object(installer, 'marker'), patch.object(Path, 'read_bytes', return_value=b'\x07\0\0\0\0'), \
             patch.object(installer.shutil, 'which', return_value=None), self.assertRaisesRegex(installer.Refusal, 'offline tools'):
            installer.live_environment()

    def source_fixture(self):
        for binary in ('fish', 'niri', 'mkinitcpio', 'bootctl', 'useradd', 'chpasswd', 'locale-gen', 'visudo', 'systemctl', 'pacman-key'):
            self.put('usr/bin/' + binary)
        self.put('usr/share/jstack/systemd/autologin.conf.in', 'autologin %USER%')
        self.put('etc/skel/.config/fish/conf.d/00-jstack-niri-autostart.fish', 'exec niri-session')
        self.put('usr/lib/modules/6.19/vmlinuz', 'kernel')
        self.put('etc/passwd', 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\n')
        self.put('etc/shadow', 'root:!:14871::::::\nnobody:*:14871::::::\n')

    def test_clean_source_accounts_and_kernel(self):
        self.source_fixture()
        with patch.object(installer, 'marker'):
            installer.validate_source(self.root, 'alice')
            self.put('usr/lib/modules/6.20/vmlinuz', 'other kernel')
            with self.assertRaisesRegex(installer.Refusal, 'exactly one'):
                installer.validate_source(self.root, 'alice')

    def test_source_live_human_and_unlocked_credentials_refused(self):
        for filename, text in [('etc/passwd', 'jstack:x:1000:1000::/home/jstack:/usr/bin/fish\n'),
                               ('etc/shadow', 'root::14871::::::\n'), ('etc/shadow', 'root:$y$livehash:14871::::::\n')]:
            self.source_fixture()
            self.put(filename, text)
            with patch.object(installer, 'marker'), self.assertRaises(installer.Refusal):
                installer.validate_source(self.root, 'alice')

    def test_source_sha512_rejects_corruption_read_only(self):
        image = self.put('run/archiso/bootmnt/arch/x86_64/airootfs.sfs', 'not a real squashfs')
        self.put('run/archiso/bootmnt/arch/x86_64/airootfs.sha512', '0' * 128 + '  airootfs.sfs\n')
        realpath = Path
        def path(value):
            value = str(value)
            return self.root / value.lstrip('/') if value.startswith(('/run/', '/sys/')) else realpath(value)
        st = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with patch.object(installer, 'Path', side_effect=path), patch.object(Path, 'lstat', return_value=st), \
             patch.object(installer, 'mount_for', return_value={'target': '/run/archiso/bootmnt', 'options': 'ro'}), \
             self.assertRaisesRegex(installer.Refusal, 'SHA512 mismatch'):
            installer.source_info()
        self.run.assert_not_called()


class CliTests(SafeTest):
    @contextlib.contextmanager
    def cli(self):
        with patch.object(installer, 'live_environment'), \
             patch.object(installer, 'source_info', return_value=(Path('/run/archiso/airootfs'), False)), \
             patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)), \
             patch.object(installer, 'list_disks') as listing, \
             patch.object(installer, 'install') as install, \
             contextlib.redirect_stdout(io.StringIO()):
            yield install, listing

    def test_list_and_check_never_install(self):
        for args in (['--list'], ['--check'], ['--check', '--disk', '/dev/vdb']):
            with self.subTest(args=args), self.cli() as (install, _):
                self.assertEqual(installer.main(args), 0)
                install.assert_not_called()
                self.run.assert_not_called()

    def test_yes_bypass_does_not_exist(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            installer.parser().parse_args(['--yes'])

    def args(self):
        return ['--disk', '/dev/vdb', '--confirm', installer.token(IDENTITY), '--user', 'alice', '--password-stdin']

    def test_noninteractive_explicit_confirmation_and_password(self):
        with self.cli() as (install, _), patch.object(installer.sys, 'stdin', io.StringIO('correct-horse\n')):
            installer.main(self.args() + ['--hostname', 'test-host', '--serial-console'])
            install.assert_called_once_with(IDENTITY, (Path('/run/archiso/airootfs'), False), 'alice', 'test-host', 'correct-horse', True)

    def test_wrong_confirmation_never_installs(self):
        for confirm in ('yes', installer.token(IDENTITY).lower(), installer.token(IDENTITY) + ' ', 'INSTALL-other'):
            args = self.args()
            args[3] = confirm
            with self.cli() as (install, _), self.assertRaisesRegex(installer.Refusal, 'confirmation'):
                installer.main(args)
            install.assert_not_called()

    def test_empty_short_and_injectable_passwords_refused(self):
        for password in ('', '\n', 'short\n', 'long:password\n', 'long\x00password\n', 'long\rpassword\n'):
            with self.subTest(password=repr(password)), self.cli() as (install, _), patch.object(installer.sys, 'stdin', io.StringIO(password)), self.assertRaisesRegex(installer.Refusal, 'password'):
                installer.main(self.args())
            install.assert_not_called()

    def test_invalid_username_hostname_refused(self):
        for option, value in [('--user', 'root'), ('--user', '-bad'), ('--user', 'alice;id'), ('--user', 'a' * 33),
                              ('--hostname', '../root'), ('--hostname', 'bad\nname'), ('--hostname', '-bad')]:
            args = self.args()
            if option in args:
                args[args.index(option) + 1] = value
            else:
                args += [option, value]
            with self.subTest(value=value), self.cli() as (install, _), patch.object(installer.sys, 'stdin', io.StringIO('password123\n')), contextlib.redirect_stderr(io.StringIO()), self.assertRaises((installer.Refusal, SystemExit)):
                installer.main(args)
            install.assert_not_called()

    def test_missing_noninteractive_disk_or_token_refused(self):
        for args in ([], ['--disk', '/dev/vdb']):
            with self.cli() as (install, _), patch.object(installer.sys, 'stdin', io.StringIO('')), self.assertRaises(installer.Refusal):
                installer.main(args)
            install.assert_not_called()


class TargetPolicyTests(SafeTest):
    def test_unexpected_workspace_contents_never_recursively_deleted(self):
        workspace = self.root / 'workspace'
        (workspace / 'target').mkdir(parents=True)
        sentinel = workspace / 'target/DO-NOT-DELETE'
        sentinel.write_text('simulates an unregistered mounted filesystem')
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source', side_effect=installer.Refusal('bad source')), \
             self.assertRaises(OSError):
            installer.install(IDENTITY, (self.root, False), 'alice', 'dell', 'password123')
        self.assertTrue(sentinel.exists())

    def test_failed_unmount_is_failure_and_retains_workspace(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        def command(*args, **kwargs):
            if args[0] == 'umount':
                raise installer.Refusal('device busy')
            return SimpleNamespace(returncode=0, stdout='')
        self.run.side_effect = command
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source', side_effect=installer.Refusal('bad source')), \
             contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()) as output, \
             self.assertRaisesRegex(installer.Refusal, 'cleanup incomplete'):
            installer.install(IDENTITY, (self.root / 'image.sfs', True), 'alice', 'dell', 'password123')
        self.assertTrue(workspace.exists())
        self.assertNotIn('complete.', output.getvalue())

    def test_mutation_failure_reports_no_rollback_and_no_success(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        @contextlib.contextmanager
        def exclusive(*args, **kwargs):
            yield 77, '/proc/self/fd/77'
        def command(*args, **kwargs):
            if args[0] == 'sgdisk':
                raise installer.Refusal('write failed')
            return SimpleNamespace(returncode=0, stdout='1000\t/source\n')
        self.run.side_effect = command
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source'), patch.object(installer, 'live_environment'), \
             patch.object(installer, 'source_info', return_value=(self.root, False)), \
             patch.object(installer, 'inspect_disk', return_value=(IDENTITY, DISK)), \
             patch.object(installer, 'exclusive_device', side_effect=exclusive), \
             contextlib.redirect_stderr(io.StringIO()) as errors, contextlib.redirect_stdout(io.StringIO()) as output, \
             self.assertRaisesRegex(installer.Refusal, 'write failed'):
            installer.install(IDENTITY, (self.root, False), 'alice', 'dell', 'password123')
        self.assertIn('NO rollback', errors.getvalue())
        self.assertIn('requires reinstallation', errors.getvalue())
        self.assertNotIn('complete.', output.getvalue())

    def test_conversion_rebuilds_installed_policy_offline(self):
        self.put('usr/lib/modules/6.19/vmlinuz', 'real kernel payload')
        self.put('usr/share/jstack/systemd/autologin.conf.in', '[Service]\nExecStart=-agetty --autologin %USER%\n')
        live_files = ('etc/systemd/system/getty@tty2.service.d/autologin.conf',
                      'etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf',
                      'etc/systemd/system/jstack-live-setup.service',
                      'etc/systemd/logind.conf.d/do-not-suspend.conf',
                      'etc/systemd/journald.conf.d/volatile-storage.conf',
                      'etc/mkinitcpio.conf.d/archiso.conf', 'etc/mkinitcpio.d/linux.preset',
                      installer.MARKER, 'etc/sudoers.d/15-jstack-live', 'usr/local/lib/jstack-live-setup')
        for path in live_files:
            self.put(path, 'LIVE SECRET CONFIG')
        self.put('boot/EFI/BOOT/BOOTX64.EFI', 'efi')
        self.put('boot/initramfs-linux.img', 'generated test image')
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout='', stderr='', returncode=0)
        installer.configure_target(self.root, 'alice', 'dell', 'new-password', 'abcd-1234', 'ABCD-1234', True)
        for path in live_files:
            self.assertNotIn('LIVE SECRET CONFIG', (self.root / path).read_text() if (self.root / path).is_file() else '')
        config = (self.root / 'etc/mkinitcpio.conf').read_text()
        self.assertNotIn('archiso', config)
        self.assertNotIn('autodetect', config)
        self.assertIn('MODULES=(btrfs)', config)
        self.assertIn("PRESETS=('default')", (self.root / 'etc/mkinitcpio.d/linux.preset').read_text())
        self.assertEqual((self.root / 'boot/vmlinuz-linux').read_text(), 'real kernel payload')
        fstab = (self.root / 'etc/fstab').read_text()
        for sub in ('@', '@home', '@log', '@pkg'):
            self.assertIn('subvol=' + sub, fstab)
        self.assertIn('/boot vfat umask=0077', fstab)
        self.assertEqual((self.root / 'etc/machine-id').read_text(), '')
        self.assertIn('autologin alice', (self.root / 'etc/systemd/system/getty@tty1.service.d/autologin.conf').read_text())
        self.assertIn('console=ttyS0,115200n8', (self.root / 'boot/loader/entries/jstack.conf').read_text())
        self.assertFalse(json.loads((self.root / 'var/lib/jstack/installed-from-live.json').read_text())['rollback'])
        calls = [tuple(map(str, call.args)) for call in self.run.call_args_list]
        self.assertIn(('arch-chroot', str(self.root), 'pacman-key', '--init'), calls)
        self.assertIn(('arch-chroot', str(self.root), 'pacman-key', '--populate', 'archlinux'), calls)
        self.assertIn(('arch-chroot', str(self.root), 'bootctl', '--esp-path=/boot', '--no-variables', 'install'), calls)
        self.assertTrue(any('enable' in call and 'fstrim.timer' in call for call in calls))
        self.assertTrue(any('mask' in call and 'systemd-resolved.service' in call for call in calls))
        # New systemd 261 sockets otherwise fail at boot when their backend
        # services are masked. Mask them AFTER preset-all can enable them.
        preset_index = next(i for i, call in enumerate(calls) if 'preset-all' in call)
        sockets = ('systemd-networkd-varlink-metrics.socket',
                   'systemd-networkd-varlink.socket',
                   'systemd-networkd-resolve-hook.socket',
                   'systemd-resolved-monitor.socket',
                   'systemd-resolved-varlink.socket')
        for socket in sockets:
            with self.subTest(socket=socket):
                self.assertTrue(any(i > preset_index and 'mask' in call and socket in call
                                    for i, call in enumerate(calls)))
        self.assertTrue(any('useradd' in call and 'alice' in call for call in calls))
        self.assertFalse(any('pacman' in call or 'curl' in call or 'wget' in call for call in calls))
        password_call = next(call for call in self.run.call_args_list if 'chpasswd' in call.args)
        self.assertEqual(password_call.kwargs['input'], 'alice:new-password\n')
        self.assertNotIn('new-password', repr(calls))

    def test_excludes_all_live_identity_and_never_live_root_source(self):
        for exclusion in ('/root/*', '/home/*', '/etc/machine-id', '/etc/ssh/ssh_host_*',
                          '/etc/NetworkManager/system-connections/*', '/var/lib/iwd/*',
                          '/etc/pacman.d/gnupg/*', '/var/lib/systemd/random-seed'):
            self.assertIn(exclusion, installer.EXCLUDES)

    def test_edit_parent_symlink_never_writes_outside_target(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'etc').symlink_to(outside)
        with self.assertRaisesRegex(installer.Refusal, 'unsafe target parent'):
            installer.put(self.root, 'etc/hostname', 'oops')
        self.assertFalse((outside / 'hostname').exists())

    def test_source_failure_happens_before_opening_target(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source', side_effect=installer.Refusal('bad source')), \
             patch.object(installer, 'exclusive_device') as opening, self.assertRaisesRegex(installer.Refusal, 'bad source'):
            installer.install(IDENTITY, (self.root, False), 'alice', 'dell', 'password123')
        opening.assert_not_called()
        self.run.assert_not_called()

    def test_final_revalidation_failure_prevents_mutation(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        self.run.side_effect = None
        self.run.return_value = SimpleNamespace(stdout='1000\t/source\n', returncode=0)
        with patch.object(installer.tempfile, 'mkdtemp', return_value=str(workspace)), \
             patch.object(installer, 'validate_source'), patch.object(installer, 'live_environment'), \
             patch.object(installer, 'source_info', return_value=(self.root, False)), \
             patch.object(installer, 'inspect_disk', side_effect=installer.Refusal('identity changed')), \
             patch.object(installer, 'exclusive_device') as opening, self.assertRaisesRegex(installer.Refusal, 'identity changed'):
            installer.install(IDENTITY, (self.root, False), 'alice', 'dell', 'password123')
        opening.assert_not_called()
        self.assertEqual(self.run.call_args_list[0].args[0], 'du')
        self.assertEqual(self.run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
