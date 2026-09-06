#!/usr/bin/env python3
"""Host-only contract tests. These never run an installer or boot a VM."""
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('live_vm', Path(__file__).with_name('test_live_install.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('JCODE_SCRATCH_DIR'))
        self.root = Path(self.temp.name)
        self.paths = {}
        for name in ('code', 'vars', 'target', 'fixture', 'iso'):
            p = self.root / (name + ',test.file')
            p.write_bytes(b'test')
            self.paths[name] = p

    def tearDown(self):
        self.temp.cleanup()

    def command(self, live=True, **kwargs):
        return vm.qemu_command(code=self.paths['code'], variables=self.paths['vars'],
            target=self.paths['target'], fixture=self.paths['fixture'] if live else None,
            iso=self.paths['iso'] if live else None, serial=self.root / 'serial',
            qmp=self.root / 'qmp', memory=kwargs.get('memory', 3072), acceleration='kvm')

    def test_regular_files_only(self):
        for path in (Path('/dev/null'), self.root):
            with self.assertRaises(vm.ProofError):
                vm.regular_file(path)
        link = self.root / 'device-link'
        link.symlink_to('/dev/null')
        with self.assertRaises(vm.ProofError):
            vm.regular_file(link)

    def test_file_json_cannot_inject_qemu_options(self):
        args = vm.disk_args(self.paths['iso'], 'liveiso', 'raw', True)
        node = json.loads(args[1])
        self.assertEqual(node['file']['filename'], str(self.paths['iso']))
        self.assertTrue(node['read-only'])
        self.assertEqual(len(args), 2)

    def test_live_vm_has_no_network_or_host_passthrough(self):
        cmd = self.command()
        self.assertEqual(cmd[cmd.index('-nic') + 1], 'none')
        self.assertEqual(cmd[cmd.index('-m') + 1], '3072')
        self.assertEqual(cmd[cmd.index('-smp') + 1], '2')
        self.assertIn('usb-storage,bus=xhci.0,drive=liveiso,removable=on,bootindex=1,serial=JSTACKLIVE', cmd)
        for bad in ('-netdev', '-virtfs', '-fsdev', '-drive', 'usb-host', 'vfio-pci'):
            self.assertNotIn(bad, cmd)
        nodes = [json.loads(cmd[i+1]) for i, a in enumerate(cmd) if a == '-blockdev']
        self.assertEqual(len(nodes), 5)
        self.assertTrue(next(x for x in nodes if x['node-name'] == 'liveiso')['read-only'])
        self.assertTrue(next(x for x in nodes if x['node-name'] == 'firmware-code')['read-only'])

    def test_installed_boot_has_only_target_and_firmware(self):
        cmd = self.command(live=False)
        nodes = [json.loads(cmd[i+1]) for i, a in enumerate(cmd) if a == '-blockdev']
        self.assertEqual({x['node-name'] for x in nodes}, {'firmware-code', 'firmware-vars', 'target'})
        self.assertNotIn(str(self.paths['iso']), ' '.join(cmd))
        self.assertNotIn(str(self.paths['fixture']), ' '.join(cmd))
        self.assertIn('virtio-blk-pci,drive=target,serial=JSTACKTARGET,bootindex=1', cmd)

    def test_memory_bound(self):
        for memory in (1024, 4097, 8192):
            with self.assertRaises(vm.ProofError):
                self.command(memory=memory)

    def test_serial_fragmentation_and_retained_bytes(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        log = io.BytesIO()
        serial = vm.Serial(a, log)
        b.sendall(b'abc\r\nTOKEN:')
        b.sendall(b'17\r\nremaining')
        match, output = serial.expect(r'\nTOKEN:([0-9]+)\n', 1)
        self.assertEqual(match[1], '17')
        self.assertEqual(output, 'abc\nTOKEN:17\n')
        self.assertEqual(serial.buffer, 'remaining')
        self.assertIn(b'\r\n', log.getvalue())

    def test_serial_eof_and_timeout_fail(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        b.close()
        with self.assertRaisesRegex(vm.ProofError, 'closed'):
            vm.Serial(a, io.BytesIO()).expect('never', 1)
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        with self.assertRaisesRegex(vm.ProofError, 'timeout'):
            vm.Serial(a, io.BytesIO()).expect('never', 0.01)

    def test_serial_script_nonzero_and_chunk_limits(self):
        class FakeSerial(vm.Serial):
            def __init__(self):
                self.sent = []
                self.token = None
            def send(self, text):
                self.sent.append(text)
            def expect(self, regex, timeout):
                import re
                if 'BEGIN-' in regex:
                    return None, ''
                token = regex.split('END-')[1].split(':')[0]
                output = 'fixture output\nEND-' + token + ':9\n'
                return re.search(regex, output), output
        serial = FakeSerial()
        rc, output = serial.script('fixture', '# long\n' * 2000, check=False)
        self.assertEqual(rc, 9)
        self.assertEqual(output, 'fixture output')
        self.assertTrue(all(len(x) < 4096 for x in serial.sent))
        with self.assertRaisesRegex(vm.ProofError, 'exit 9'):
            serial.script('fixture', 'exit 9')

    def test_full_hash_parser_rejects_missing_or_wrong_device(self):
        class FakeSerial:
            def script(self, *a):
                return 0, '0' * 64 + '  /dev/wrong\n'
        with self.assertRaises(vm.ProofError):
            vm.guest_disk_hash(FakeSerial(), '/dev/vda', 1)

    def test_refusal_requires_status_reason_and_unchanged_hash(self):
        args = vm.parse_args(['--iso', '/unused', '--artifacts', '/unused'])
        class FakeSerial:
            rc, text = 1, 'whole disk required'
            def script(self, *a, **kw):
                return self.rc, self.text
        for hashes, rc, text, passes in [
            (['a', 'a'], 1, 'whole disk required', True),
            (['a', 'b'], 1, 'whole disk required', False),
            (['a', 'a'], 0, 'whole disk required', False),
            (['a', 'a'], 2, 'usage error whole disk', False),
            (['a', 'a'], 1, 'missing source', False),
        ]:
            s = FakeSerial()
            s.rc, s.text = rc, 'CLEAN offline source: /run/archiso/airootfs\njstack-install-live: REFUSED/FAILED: ' + text
            results = []
            with patch.object(vm, 'guest_disk_hash', side_effect=hashes):
                if passes:
                    vm.refusal(s, args, 'case', '/dev/vda1', '/dev/vda', 'whole', results)
                    self.assertTrue(results[0]['passed'])
                else:
                    with self.assertRaises(vm.ProofError):
                        vm.refusal(s, args, 'case', '/dev/vda1', '/dev/vda', 'whole', results)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]['scope'], 'entire block device')

    def test_installer_cli_uses_real_contract(self):
        args = vm.parse_args(['--iso', '/unused', '--artifacts', '/unused'])
        cmd = vm.installer_command(args, '/dev/vda', 'INSTALL-token')
        self.assertIn('--user vmtest', cmd)
        self.assertIn('--password-stdin', cmd)
        self.assertIn('--serial-console', cmd)
        self.assertNotIn(vm.PASSWORD, cmd)
        self.assertNotIn('--username', cmd)

    def test_normal_source_banner_cannot_satisfy_refusal_reason(self):
        args = vm.parse_args(['--iso', '/unused', '--artifacts', '/unused'])
        class FakeSerial:
            def script(self, *a, **kw):
                return 1, ('CLEAN offline source: /run/archiso/airootfs\n'
                           'jstack-install-live: REFUSED/FAILED: wrong confirmation\n')
        with patch.object(vm, 'guest_disk_hash', side_effect=['a', 'a']):
            with self.assertRaisesRegex(vm.ProofError, 'wrong refusal reason'):
                vm.refusal(FakeSerial(), args, 'source', '/dev/sda', '/dev/sda',
                           'live|source|boot', [])

    def test_required_screenshot_failure_is_fatal(self):
        machine = object.__new__(vm.VM)
        machine.dir = self.root
        machine.qmp = lambda *a: None
        with self.assertRaisesRegex(vm.ProofError, 'Required QMP screenshot failed'):
            machine.screenshot(required=True)
        self.assertTrue((self.root / 'screenshot-error.txt').is_file())
        machine.screenshot(required=False)

    def test_socket_options_cannot_be_injected(self):
        with self.assertRaisesRegex(vm.ProofError, 'socket paths'):
            vm.qemu_command(code=self.paths['code'], variables=self.paths['vars'],
                target=self.paths['target'], fixture=None, iso=None,
                serial=self.root / 'serial,server=off', qmp=self.root / 'qmp',
                memory=3072, acceleration='kvm')

    def test_generated_checks_shell_parse_and_negative_assertions(self):
        for text in (vm.installed_script(), vm.desktop_script('vmtest')):
            result = subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(x.startswith('! ') for x in vm.installed_script().splitlines()),
                         'Bash negation is exempt from set -e and cannot be a standalone assertion')
        self.assertIn('NIRI_IPC_OK', vm.desktop_script('vmtest'))
        self.assertIn('json.load', vm.desktop_script('vmtest'))

    def test_main_refuses_existing_artifact_directory_without_mutation(self):
        with patch.object(vm.os, 'geteuid', return_value=1000), patch.object(vm, 'run') as run:
            self.assertEqual(vm.main(['--iso', str(self.paths['iso']), '--artifacts', str(self.root)]), 2)
            run.assert_not_called()

    def test_main_refuses_root(self):
        with patch.object(vm.os, 'geteuid', return_value=0), patch.object(vm, 'run') as run:
            self.assertEqual(vm.main(['--iso', '/unused', '--artifacts', '/unused']), 2)
            run.assert_not_called()

    def test_main_failure_writes_nonzero_artifact(self):
        dest = self.root / 'new'
        with patch.object(vm.os, 'geteuid', return_value=1000), patch.object(vm, 'run', side_effect=vm.ProofError('fixture failure')):
            self.assertEqual(vm.main(['--iso', str(self.paths['iso']), '--artifacts', str(dest)]), 1)
        result = json.loads((dest / 'result.json').read_text())
        self.assertFalse(result['passed'])
        self.assertIn('fixture failure', result['failure'])


if __name__ == '__main__':
    unittest.main()
