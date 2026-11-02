import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / 'packages/jofi-jstack/PKGBUILD'


class LauncherPackagingTests(unittest.TestCase):
    def test_default_and_prompt_boundaries(self):
        config = (ROOT / 'packages/jstack-niri/files/config.kdl').read_text()
        self.assertIn('spawn "/usr/bin/jofi-workspace"', config)
        self.assertNotIn('spawn "tofi-drun-workspace"', config)
        for prompt in ('tofi-bring-here', 'tofi-power-menu', 'wifi-pick'):
            self.assertIn(f'spawn "{prompt}"', config)
        deps = (ROOT / 'packages/jstack-niri/PKGBUILD').read_text()
        self.assertIn("'jofi-jstack'", deps)
        self.assertIn("'tofi-jstack'", deps)
        installer = (ROOT / 'install/jstack-install.sh').read_text()
        self.assertIn('SOURCE_PKGS=(tofi-jstack jofi-jstack)', installer)

    def test_pinned_source_and_locked_build(self):
        text = PACKAGE.read_text()
        self.assertIn('_commit=9f85fa0d6c2b4d96dd4c138dbcbd75e023c5cf38', text)
        self.assertIn('#commit=$_commit', text)
        self.assertIn('cargo build --release --locked', text)
        self.assertIn('cargo test --locked', text)
        self.assertIn("'glib2'", text)  # gio launches desktop entries
        self.assertIn("'fontconfig'", text)

    def test_package_installs_binary_wrapper_and_license(self):
        scratch = Path(os.environ.get('JCODE_SCRATCH_DIR', Path.home() / '.cache'))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='jofi-package-test-', dir=scratch) as tmp:
            work = Path(tmp)
            source = work / 'src/jofi'
            for path, content in [('target/release/jofi', '#!/bin/sh\nexit 0\n'),
                                  ('contrib/jofi-workspace', '#!/bin/bash\nexit 0\n'),
                                  ('LICENSE', 'test license\n')]:
                dest = source / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
            env = dict(os.environ, srcdir=str(work / 'src'), pkgdir=str(work / 'pkg'))
            subprocess.run(['bash', '-c', 'source "$1"; package', 'bash', str(PACKAGE)],
                           env=env, check=True)
            for name in ('jofi', 'jofi-workspace'):
                path = work / 'pkg/usr/bin' / name
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
                subprocess.run([str(path)], check=True)
            self.assertEqual((work / 'pkg/usr/share/licenses/jofi-jstack/LICENSE').read_text(),
                             'test license\n')


if __name__ == '__main__':
    unittest.main()
