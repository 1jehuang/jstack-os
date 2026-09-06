#!/usr/bin/env python3
"""Host-only contract tests. These never run an installer or boot a VM."""
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('live_vm', Path(__file__).with_name('test_live_install.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class HarnessTests(unittest.TestCase):
    @staticmethod
    def png(flat=False):
        def chunk(kind, payload):
            return (vm.struct.pack('>I', len(payload)) + kind + payload
                    + vm.struct.pack('>I', vm.zlib.crc32(kind + payload) & 0xffffffff))
        row = b'\0' + bytes(320 * 3)
        raw = bytearray(row * 200)
        if not flat:
            raw[1:4] = b'\xff\xff\xff'
        return (b'\x89PNG\r\n\x1a\n'
                + chunk(b'IHDR', vm.struct.pack('>IIBBBBB', 320, 200, 8, 2, 0, 0, 0))
                + chunk(b'IDAT', vm.zlib.compress(raw)) + chunk(b'IEND', b''))

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

    def test_secure_capable_firmware_configuration(self):
        args = vm.parse_args(['--iso', '/unused', '--artifacts', '/unused'])
        self.assertEqual(args.ovmf_code.name, 'OVMF_CODE.secboot.4m.fd')
        cmd = self.command()
        self.assertIn('q35,smm=on,accel=kvm', cmd)
        self.assertIn('driver=cfi.pflash01,property=secure,value=on', cmd)

    def test_firmware_check_requires_present_valid_disabled_variables(self):
        source = vm.firmware_script().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        source = source.replace("'/sys/firmware/efi/efivars'", repr(str(self.root)))
        guid = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
        secure, setup = self.root / ('SecureBoot-' + guid), self.root / ('SetupMode-' + guid)
        for sb, sm, success in ((None, b'\7\0\0\0\1', False),
                                (b'\7\0\0\0\0', b'\7\0\0\0\1', True),
                                (b'\7\0\0\0\1', b'\7\0\0\0\1', False),
                                (b'\0', b'\7\0\0\0\1', False),
                                (b'\7\0\0\0\0', b'\7\0\0\0\0', False)):
            if sb is None:
                secure.unlink(missing_ok=True)
            else:
                secure.write_bytes(sb)
            setup.write_bytes(sm)
            result = subprocess.run(['python3', '-c', source], capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, success, result.stderr)
            if success:
                self.assertIn('UEFI_SecureBoot=0', result.stdout)
                self.assertIn('UEFI_SetupMode=1', result.stdout)

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

    def test_fish_prompt_requires_end_marker_not_login_or_terminal_probes(self):
        startup = ('jstack-live login: jstack (automatic login)\n'
                   '\x1b[?u\x1b[>0q\x1b]11;?\x1b\\\x1b[0c'
                   'Welcome to fish\n\x1b]133;A;click_events=1\x1b\\'
                   '\x1b[92mjstack\x1b[m@jstack-live ~> ')
        self.assertIsNone(re.search(vm.FISH_PROMPT_READY, startup))
        for marker in ('\x1b]133;B\x1b\\', '\x1b]133;B\x07',
                       '\x1b]133;B;click_events=1\x1b\\'):
            self.assertIsNotNone(re.search(vm.FISH_PROMPT_READY, startup + marker))

    def test_both_logins_wait_for_fish_and_bash_before_commands(self):
        class Recorder(vm.Serial):
            def __init__(self):
                self.events = []
            def expect(self, pattern, timeout):
                self.events.append(('expect', pattern))
            def send(self, text):
                self.events.append(('send', text))
        for installed in (False, True):
            serial = Recorder()
            serial.bootstrap(installed, 300)
            events = serial.events
            fish = events.index(('expect', vm.FISH_PROMPT_READY))
            self.assertEqual(events[fish + 1][0], 'send')
            self.assertTrue(events[fish + 1][1].startswith('sudo -n '))
            self.assertEqual(events[fish + 2], ('expect', re.escape('JSTACK-BASH-READY> ')))
            self.assertIn('$BASH_VERSION', events[fish + 3][1])
            # The command's quoted fragments do not look like its real prompt.
            self.assertNotIn('JSTACK-BASH-READY> ', events[fish + 1][1])
            early = [text for kind, text in events[:fish] if kind == 'send']
            self.assertEqual(early, [vm.USER + '\n', vm.PASSWORD + '\n'] if installed else [])

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

    def test_png_is_decoded_with_real_pixel_dimensions(self):
        info = vm.validate_png(self.png())
        self.assertEqual((info['width'], info['height']), (320, 200))
        self.assertEqual(info['decoded_pixel_bytes'], 320 * 200 * 3)

    def test_png_rejects_corruption_truncation_and_flat_color(self):
        image = bytearray(self.png())
        image[45] ^= 1
        for data in (b'not a PNG', bytes(image), self.png()[:-2], self.png(flat=True)):
            with self.assertRaises(vm.ProofError):
                vm.validate_png(data)

    def test_native_capture_rejects_guest_host_hash_mismatch(self):
        machine = object.__new__(vm.VM)
        machine.phase, machine.dir = 'live', self.root
        machine.qmp = lambda *a: None
        output = ('APP_PROOF_BEGIN\n{}\nAPP_PROOF_END\nCAPTURE_SHA256=' + '0' * 64
                  + '\nCAPTURE_PNG_BEGIN\n' + vm.base64.b64encode(self.png()).decode()
                  + '\nCAPTURE_PNG_END\n')
        class FakeSerial:
            def script(self, *a):
                return 0, output
        machine.serial = FakeSerial()
        with self.assertRaisesRegex(vm.ProofError, 'guest/host SHA256 mismatch'):
            machine.capture_desktop('jstack')
        self.assertFalse((self.root / 'desktop.png').exists())

    def test_socket_options_cannot_be_injected(self):
        with self.assertRaisesRegex(vm.ProofError, 'socket paths'):
            vm.qemu_command(code=self.paths['code'], variables=self.paths['vars'],
                target=self.paths['target'], fixture=None, iso=None,
                serial=self.root / 'serial,server=off', qmp=self.root / 'qmp',
                memory=3072, acceleration='kvm')

    def test_generated_checks_shell_parse_and_negative_assertions(self):
        for text in (vm.installed_script(), vm.desktop_script('vmtest'), vm.screenshot_script('vmtest', 'abc123', 'live')):
            result = subprocess.run(['bash', '-n'], input=text, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(x.startswith('! ') for x in vm.installed_script().splitlines()),
                         'Bash negation is exempt from set -e and cannot be a standalone assertion')
        self.assertIn('NIRI_IPC_OK', vm.desktop_script('vmtest'))
        self.assertIn('json.load', vm.desktop_script('vmtest'))

    def test_installed_checks_do_not_require_inetutils_hostname(self):
        script = vm.installed_script()
        self.assertIn('$(cat /proc/sys/kernel/hostname)', script)
        self.assertNotRegex(script, r'\$\(\s*hostname(?:\s|\))')
        # Empty PATH must fail at tool preflight, before probing this host.
        result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script],
                                env={'PATH': str(self.root / 'empty')}, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Required installed probe tool missing: python3', result.stderr)

    def test_progress_has_recognized_message_and_preserves_case(self):
        with patch('builtins.print') as output:
            vm.progress('Checking refusal: mounted-disk', phase='refusal', case='mounted-disk')
        text = output.call_args.args[0]
        self.assertTrue(text.startswith('JCODE_PROGRESS '))
        data = json.loads(text.removeprefix('JCODE_PROGRESS '))
        self.assertEqual(data['message'], 'Checking refusal: mounted-disk')
        self.assertEqual(data['case'], 'mounted-disk')
        self.assertTrue(output.call_args.kwargs['flush'])

    def test_shutdown_drains_serial_backpressure_and_final_bytes(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        finished = threading.Event()
        payload = b'Stopping guest services\n' * 50000 + b'Power down\n'
        class Process:
            returncode = None
            def poll(self):
                if finished.is_set(): self.returncode = 0
                return self.returncode
            def wait(self, timeout):
                if not finished.wait(timeout):
                    raise subprocess.TimeoutExpired('fake-qemu', timeout)
                self.returncode = 0
                return 0
        def guest():
            b.recv(4096)
            b.sendall(payload)
            b.shutdown(socket.SHUT_WR)
            finished.set()
        worker = threading.Thread(target=guest, daemon=True)
        worker.start()
        machine = object.__new__(vm.VM)
        machine.phase, machine.dir, machine.process = 'installed', self.root, Process()
        log = io.BytesIO()
        machine.serial = vm.Serial(a, log)
        machine.shutdown()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(log.getvalue(), payload)
        evidence = json.loads((self.root / 'shutdown.json').read_text())
        self.assertEqual(evidence['qemu_exit_status'], 0)
        self.assertEqual(evidence['deadline_seconds'], 60)
        self.assertTrue(evidence['serial_drained'])

    def test_installed_policy_checks_exact_mounts_and_collects_failures(self):
        script = vm.installed_policy_script()
        code = script.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        compile(code, '<installed-policy>', 'exec')
        self.assertIn("'--mountpoint' if exact else '--target'", code)
        for subvol in ('/@', '/@home', '/@log', '/@pkg'):
            self.assertIn(repr(subvol), code)
        for required in ('root_locked', 'machine_id_valid', 'public_key_count',
                         'compress=zstd', 'is-active', 'failed_units', 'FAILED_UNIT_JOURNAL_BEGIN'):
            self.assertIn(required, code)

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
