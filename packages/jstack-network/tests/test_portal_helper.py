#!/usr/bin/env python3
"""Isolated helper regressions. No real NetworkManager, network or desktop calls."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "files/bin/captive-portal-helper"
loader = importlib.machinery.SourceFileLoader("portal_helper", str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)

STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ['FAKE_ROOT'])
name = pathlib.Path(sys.argv[0]).name
if name == 'xdg-open':
    with (root / 'browser-pids').open('a') as f:
        f.write(str(os.getpid()) + '\n')
args = sys.argv[1:]
with (root / 'calls').open('a') as f:
    f.write(json.dumps([name] + args) + '\n')
cfg = json.loads((root / 'config').read_text())
if name == 'nmcli':
    if 'wifi' in args:
        ssid = cfg.get('ssid', 'Cafe: tea | "coffee" \\')
        if (root / 'changed').exists():
            ssid = 'Different network'
        esc = lambda s: s.replace('\\', '\\\\').replace(':', '\\:')
        if not cfg.get('disconnected'):
            print(':'.join(map(esc, ['yes', 'wlan0', 'aa:bb:cc:dd:ee:ff', ssid])))
    else:
        time.sleep(cfg.get('nm_delay', 0))
        print(cfg.get('verified', 'portal') if 'check' in args else cfg.get('state', 'portal'))
elif name == 'captive-portal-autoaccept':
    (root / 'started').touch()
    time.sleep(cfg.get('accept_delay', 0))
    if cfg.get('change'):
        (root / 'changed').touch()
    print('NEED_INPUT: an email address')
    sys.exit(cfg.get('rc', 1))
'''


class PortalHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ['nmcli', 'captive-portal-autoaccept', 'notify-send', 'xdg-open']:
            p = self.bin / name
            p.write_text(STUB)
            p.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        XDG_CACHE_HOME=str(self.root / 'cache'), FAKE_ROOT=str(self.root))
        self.cache = self.root / 'cache/captive-portal-helper'
        self.configure()

    def configure(self, **config):
        (self.root / 'config').write_text(json.dumps(config))

    def launch(self):
        result = subprocess.run([str(HELPER)], env=self.env, capture_output=True, text=True, timeout=12)
        self.drain_browsers()
        return result

    def drain_browsers(self):
        expected = sum(c[-2] == 'Wi-Fi portal needs attention' for c in self.calls('notify-send'))
        for _ in range(200):
            pids = self.root / 'browser-pids'
            active = False
            if pids.exists():
                for pid in pids.read_text().splitlines():
                    try:
                        # Zombie children have finished all file access too.
                        active |= Path(f'/proc/{pid}/stat').read_text().split()[2] != 'Z'
                    except FileNotFoundError:
                        pass
            if len(self.calls('xdg-open')) >= expected and not active:
                return
            time.sleep(.01)
        self.fail('browser stubs did not finish')

    def calls(self, name=None):
        p = self.root / 'calls'
        calls = [json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []
        return [c for c in calls if name is None or c[0] == name]

    def await_browser(self):
        for _ in range(100):
            if self.calls('xdg-open'):
                return
            time.sleep(.01)
        self.fail('browser stub did not run')

    def test_failure_single_browser_and_cached_preflight(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.await_browser()
        self.assertEqual(len(self.calls('xdg-open')), 1)
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 1)
        self.assertFalse(any('check' in c for c in self.calls('nmcli')))
        self.assertTrue(all(c[-2:] == ['--rescan', 'no'] for c in self.calls('nmcli') if 'wifi' in c))
        self.assertIn('Cafe: tea | "coffee" \\', (self.cache / 'ssid-status.tsv').read_text())
        self.assertRegex(result.stdout, r'^\d{4}-\d\d-\d\dT')
        self.assertIn('an email address', str(self.calls('notify-send')))

    def test_success_trusts_engine_despite_stale_nm_cache(self):
        self.configure(rc=0, state='limited')
        self.assertEqual(self.launch().returncode, 0)
        self.assertFalse(any('check' in c for c in self.calls('nmcli')))
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 1)
        self.assertFalse(self.calls('xdg-open'))
        self.assertIn('\tfull\t', (self.cache / 'ssid-status.tsv').read_text())

    def test_failure_cooldown_expires(self):
        self.launch()
        self.launch()
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 1)
        p = self.cache / 'attempt.json'
        state = json.loads(p.read_text())
        state['finished'] -= 61
        p.write_text(json.dumps(state))
        self.launch()
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 2)

    def test_network_change_discards_result_and_browser(self):
        self.configure(change=True, rc=0)
        result = self.launch()
        self.assertIn('network changed during accept', result.stdout)
        self.assertFalse(self.calls('xdg-open'))
        self.assertFalse((self.cache / 'attempt.json').exists())
        self.assertFalse(any('check' in c for c in self.calls()))

    def test_concurrent_launch_does_not_wait_or_accept_twice(self):
        self.configure(accept_delay=.8)
        first = subprocess.Popen([str(HELPER)], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: first.poll() is None and first.kill())
        for _ in range(200):
            if (self.root / 'started').exists():
                break
            time.sleep(.01)
        self.assertTrue((self.root / 'started').exists())
        start = time.monotonic()
        second = self.launch()
        self.assertLess(time.monotonic() - start, .5)
        self.assertIn('another portal helper', second.stdout)
        first.communicate(timeout=5)
        self.drain_browsers()
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 1)

    def test_nonactionable_states_never_accept_or_open(self):
        for state in ['full', 'none', 'unknown']:
            self.configure(state=state)
            self.assertEqual(self.launch().returncode, 0)
        self.assertFalse(self.calls('captive-portal-autoaccept'))
        self.assertFalse(self.calls('xdg-open'))

    def test_corrupt_retry_state_is_safe(self):
        self.cache.mkdir(parents=True)
        for data in ['bad json', '[]', '{"finished":"bad"}']:
            (self.cache / 'attempt.json').write_text(data)
            self.assertEqual(self.launch().returncode, 0)
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 3)

    def test_parser_handles_escaped_separator_after_backslash(self):
        self.assertEqual(helper.fields(r'yes:dev\\:ssid\:x\\'), ['yes', 'dev\\', 'ssid:x\\'])

    def test_all_command_timeouts_are_explicit(self):
        with patch.object(helper.subprocess, 'run', side_effect=subprocess.TimeoutExpired('nmcli', 3)) as run:
            self.assertEqual(helper.connectivity(), 'unknown')
            self.assertEqual(run.call_args.kwargs['timeout'], 3)

    def test_missing_acceptor_keeps_browser_fallback(self):
        (self.bin / 'captive-portal-autoaccept').write_text('#!/usr/bin/env nonexistent-portal-engine\n')
        self.assertEqual(self.launch().returncode, 0)
        self.await_browser()
        self.assertEqual(len(self.calls('xdg-open')), 1)

    def test_disconnect_resets_retry_for_reconnect(self):
        self.launch()
        self.configure(disconnected=True)
        self.launch()
        self.configure()
        self.launch()
        self.assertEqual(len(self.calls('captive-portal-autoaccept')), 2)

    def test_cached_nm_timeout_is_bounded_and_conservative(self):
        self.configure(nm_delay=10)
        start = time.monotonic()
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - start, 5)
        self.assertIn('timed out', result.stdout)
        self.assertFalse(self.calls('captive-portal-autoaccept'))
        self.assertFalse(self.calls('xdg-open'))

    def test_network_change_before_acceptor_is_guarded(self):
        with patch.object(helper, 'CACHE', self.cache), \
             patch.object(helper, 'network', side_effect=[['wlan0', 'ap', 'old'], ['wlan0', 'ap', 'new']]), \
             patch.object(helper, 'connectivity', return_value='portal'), \
             patch.object(helper, 'run') as run:
            helper.main()
            run.assert_not_called()
        self.assertFalse((self.cache / 'attempt.json').exists())

    def test_monitor_initial_and_event_invocations(self):
        # Exercise the actual monitor shell with inert PATH stubs.
        (self.bin / 'nmcli').write_text('#!/bin/sh\nprintf "changed\\nchanged\\n"\n')
        (self.bin / 'captive-portal-helper').write_text('#!/bin/sh\necho helper >> "$FAKE_ROOT/events"\n')
        (self.bin / 'captive-portal-helper').chmod(0o755)
        result = subprocess.run(['bash', str(ROOT / 'files/bin/captive-portal-monitor')],
                                env=self.env, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1)  # requests service restart at EOF
        for _ in range(100):
            p = self.root / 'events'
            if p.exists() and len(p.read_text().splitlines()) == 3:
                break
            time.sleep(.01)
        self.assertTrue(p.exists(), result.stderr.decode())
        self.assertEqual(len(p.read_text().splitlines()), 3)


if __name__ == '__main__':
    unittest.main()
