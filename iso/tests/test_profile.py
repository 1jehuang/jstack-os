import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('profile', ROOT / 'iso/prepare-profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)
RELENG = Path('/usr/share/archiso/configs/releng')


@unittest.skipUnless(RELENG.is_dir(), 'installed Archiso releng required')
class ProfileTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get('JCODE_SCRATCH_DIR', Path.home() / '.cache'))
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='jstack-live-test-', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_live_policy(self):
        p = profile.prepare(self.work, RELENG)
        root = p / 'airootfs'
        self.assertIn('jstack-desktop-apps', (p / 'packages.x86_64').read_text())
        self.assertNotIn('\ncloud-init\n', (p / 'packages.x86_64').read_text())
        packages = (p / 'packages.x86_64').read_text().splitlines()
        self.assertNotIn('broadcom-wl', packages)
        self.assertIn('linux-firmware', packages)
        self.assertIn('b43-fwcutter', packages)
        self.assertEqual(os.readlink(root / 'etc/resolv.conf'), '/run/NetworkManager/resolv.conf')
        for unit in profile.DISABLED:
            self.assertEqual(os.readlink(root / f'etc/systemd/system/{unit}'), '/dev/null')
        for unit in profile.ENABLED:
            self.assertTrue((root / f'etc/systemd/system/multi-user.target.wants/{unit}').is_symlink())
        self.assertEqual(os.readlink(root / 'etc/systemd/system-generators/systemd-gpt-auto-generator'), '/dev/null')
        self.assertFalse((root / 'root/.automated_script.sh').exists())
        self.assertFalse((root / 'root/.zlogin').exists())
        setup = root / 'usr/local/lib/jstack-live-setup'
        subprocess.run(['bash', '-n', str(setup)], check=True)
        self.assertIn('-u 1000', setup.read_text())
        self.assertIn('chmod 600', setup.read_text())
        self.assertIn('jstack.console=1', setup.read_text())
        self.assertNotIn('exec niri-session', setup.read_text())
        self.assertIn('--autologin jstack', (root / 'etc/systemd/system/getty@tty1.service.d/autologin.conf').read_text())

    def test_generic_boot_and_bounded_memory(self):
        p = profile.prepare(self.work, RELENG)
        conf = (p / 'profiledef.sh').read_text()
        self.assertIn("'bios.syslinux'", conf)
        self.assertIn("'uefi.systemd-boot'", conf)
        self.assertIn("'-processors' '2' '-mem' '512M'", conf)
        self.assertIn(f'CacheDir = {self.work}/pacman-cache', (p / 'pacman.conf').read_text())
        hooks = (p / 'airootfs/etc/mkinitcpio.conf.d/archiso.conf').read_text()
        self.assertIn('archiso', hooks)
        self.assertNotIn('autodetect', hooks)
        for entry in (p / 'efiboot/loader/entries').glob('*.conf'):
            for line in entry.read_text().splitlines():
                if line.startswith('options '):
                    self.assertIn('copytoram=n', line)
        for menu in ('efiboot/loader/entries/02-jstack-console.conf', 'syslinux/archiso_sys-linux.cfg'):
            self.assertIn('jstack.console=1 nomodeset', (p / menu).read_text())
        subprocess.run(['bash', '-n', str(p / 'profiledef.sh')], check=True)

    def test_overlay_modes_and_no_host_credential_discovery(self):
        overlay = self.work / 'overlay'
        fixture = overlay / 'home/jstack/.config/jcode/example.env'
        fixture.parent.mkdir(parents=True)
        (overlay / 'home').chmod(0o700)
        fixture.write_text('NON_SECRET_TEST_FIXTURE=1\n')
        fixture.chmod(0o600)
        p = profile.prepare(self.work, RELENG, overlay)
        copied = p / 'airootfs/home/jstack/.config/jcode/example.env'
        self.assertEqual(copied.read_text(), fixture.read_text())
        self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
        conf = (p / 'profiledef.sh').read_text()
        self.assertIn('file_permissions[/home/jstack/.config/jcode/example.env]=1000:1000:600', conf)
        self.assertIn('file_permissions[/home/jstack/.config/jcode]=1000:1000:700', conf)
        self.assertIn('file_permissions[/home]=0:0:755', conf)
        subprocess.run(['bash', '-n', str(p / 'profiledef.sh')], check=True)

    def test_overlay_symlink_refused(self):
        overlay = self.work / 'overlay'
        overlay.mkdir()
        (overlay / 'bad').symlink_to('/etc/hostname')
        with self.assertRaisesRegex(ValueError, 'regular files'):
            profile.prepare(self.work, RELENG, overlay)

    def test_existing_profile_refused(self):
        profile.prepare(self.work, RELENG)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            profile.prepare(self.work, RELENG)

    def test_public_cli_refuses_existing_work(self):
        result = subprocess.run(['bash', str(ROOT / 'iso/build-live.sh'),
                                 '--prepare-only', '--work', str(self.work)],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('WORK already exists', result.stderr)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_public_cli_refuses_repository_work(self):
        result = subprocess.run(['bash', str(ROOT / 'iso/build-live.sh'),
                                 '--prepare-only', '--work', str(ROOT / 'iso/not-created')],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('outside the repository', result.stderr)
        self.assertFalse((ROOT / 'iso/not-created').exists())

    def test_package_staging_keeps_nested_rust_sources(self):
        # Run the real staging loop with an inert package builder. Stop before
        # the AUR clone, repo generation, or sudo. No network/build/root effects.
        tools = self.work / 'tools'
        tools.mkdir()
        for name in ('repo-add', 'mkarchiso', 'sudo', 'git', 'cargo', 'meson',
                     'ninja', 'scdoc', 'arch-meson'):
            tool = tools / name
            tool.write_text('#!/bin/sh\necho UNEXPECTED_TOOL_EXECUTION >&2\nexit 99\n')
            tool.chmod(0o755)
        makepkg = tools / 'makepkg'
        makepkg.write_text('''#!/bin/sh
if [ "${PWD##*/}" = jstack-waybar ]; then
  for crate in niri-workspaces-rs battery-rs window-uptime-rs; do
    test -f "files/rs/$crate/src/main.rs" || { echo MISSING_RUST_SOURCE >&2; exit 94; }
  done
  echo RUST_SOURCES_PRESERVED >&2
  exit 93
fi
exit 0
''')
        makepkg.chmod(0o755)
        env = dict(os.environ, PATH=f'{tools}:{os.environ["PATH"]}')
        result = subprocess.run(['bash', str(ROOT / 'iso/build-live.sh'), '--work',
                                 str(self.work / 'build')], env=env,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 93, result.stdout + result.stderr)
        self.assertIn('RUST_SOURCES_PRESERVED', result.stderr)
        self.assertNotIn('UNEXPECTED_TOOL_EXECUTION', result.stderr)


if __name__ == '__main__':
    unittest.main()
