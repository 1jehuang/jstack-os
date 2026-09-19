#!/usr/bin/env python3
"""Exercise the real package() layout and launcher without downloading releases."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get("JCODE_SCRATCH_DIR", Path.home() / ".jcode/scratch"))
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="agent-launcher-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home with spaces"
        self.local = self.home / ".local/bin/jcode"
        self.local.parent.mkdir(parents=True)
        self.env = dict(os.environ, HOME=str(self.home), PATH="/usr/bin:/bin")
        self.stage("x86_64")

    def script(self, path, body):
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def stage(self, arch):
        src = self.root / ("src-" + arch)
        src.mkdir()
        shutil.copyfile(PACKAGE / "jcode-launcher", src / "jcode-launcher")
        self.script(src / ("jcode-linux-" + arch),
                    'dir=$(dirname "$(readlink -f "$0")")\n'
                    'export JSTACK_TEST_WRAPPER=wrapped\n'
                    'exec "$dir/jcode-linux-' + arch + '.bin" "$@"')
        self.script(src / ("jcode-linux-" + arch + ".bin"),
                    'printf "%s\\n" "bundle:$JSTACK_TEST_WRAPPER" "$@"')
        pkg = self.root / ("pkg-" + arch)
        subprocess.run(["bash", "-euc", 'source "$1"; package', "package-test",
                        str(PACKAGE / "PKGBUILD")], check=True,
                       env=dict(self.env, CARCH=arch, srcdir=str(src), pkgdir=str(pkg)))
        self.agent = pkg / "usr/lib/jstack/agent"
        self.launcher = self.agent / "jcode"
        self.assertEqual(os.readlink(pkg / "usr/bin/jcode"), "/usr/lib/jstack/agent/jcode")

    def run_launcher(self, *args, env=None, path=None):
        return subprocess.run([str(path or self.launcher), *args], env=env or self.env,
                              text=True, capture_output=True, timeout=5)

    def assert_bundle(self):
        result = self.run_launcher("--version", "argument with spaces", "")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "bundle:wrapped\n--version\nargument with spaces\n\n")

    def test_missing_local_uses_upstream_wrapper(self):
        self.assert_bundle()

    def test_aarch64_package_layout(self):
        self.stage("aarch64")
        self.assert_bundle()

    def test_local_preferred_without_local_bin_on_path(self):
        self.script(self.local, 'printf "%s\\n" local "$@"')
        result = self.run_launcher("hello world", "'quoted'", "", "--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "local\nhello world\n'quoted'\n\n--version\n")

    def test_local_failure_is_not_retried_with_bundle(self):
        self.script(self.local, "exit 42")
        result = self.run_launcher()
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "")

    def test_stable_local_symlink_follows_updates(self):
        for name in ("first", "second"):
            target = self.root / name
            self.script(target, 'echo "' + name + '"')
            self.local.unlink(missing_ok=True)
            self.local.symlink_to(target)
            self.assertEqual(self.run_launcher().stdout, name + "\n")

    def test_broken_local_symlink_falls_back(self):
        self.local.symlink_to(self.root / "missing")
        self.assert_bundle()

    def test_nonexecutable_local_falls_back(self):
        self.local.write_text("not executable")
        self.assert_bundle()

    def test_directory_local_falls_back(self):
        self.local.mkdir()
        self.assert_bundle()

    def test_self_symlink_does_not_recurse(self):
        self.local.symlink_to(self.launcher)
        self.assert_bundle()

    def test_self_hardlink_does_not_recurse(self):
        os.link(self.launcher, self.local)
        self.assert_bundle()

    def test_bundled_wrapper_symlink_falls_back(self):
        self.local.symlink_to(self.agent / "jcode-bundled")
        self.assert_bundle()

    def test_invocation_through_symlink(self):
        link = self.root / "jcode"
        link.symlink_to(self.launcher)
        self.assertEqual(self.run_launcher(path=link).stdout, "bundle:wrapped\n")

    def test_unset_home_falls_back(self):
        env = dict(self.env)
        env.pop("HOME")
        self.assertEqual(self.run_launcher(env=env).stdout, "bundle:wrapped\n")


if __name__ == "__main__":
    unittest.main()
