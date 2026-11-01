"""Isolated launcher tests: no browser or live user manager is invoked."""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "files/bin/network-login"
loader = importlib.machinery.SourceFileLoader("network_login", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
login = importlib.util.module_from_spec(spec)
loader.exec_module(login)


class NetworkLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "run"
        self.runtime.mkdir(mode=0o700)
        self.data = self.root / "data"
        self.env = patch.dict(os.environ, {
            "HOME": str(self.root / "home"), "XDG_DATA_HOME": str(self.data),
            "XDG_RUNTIME_DIR": str(self.runtime), "DISPLAY": ":42",
            "XDG_ACTIVATION_TOKEN": "test-token", "DESKTOP_STARTUP_ID": "test-startup",
            "UNRELATED_SECRET": "must-not-forward",
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.which = patch.object(login.shutil, "which", side_effect=lambda name: "/usr/bin/" + name)
        self.which.start()
        self.addCleanup(self.which.stop)
        self.run = patch.object(login.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", ""))
        self.mock_run = self.run.start()
        self.addCleanup(self.run.stop)

    def launch(self):
        self.assertEqual(login.main([]), 0)
        argv = self.mock_run.call_args.args[0]
        return argv, Path(argv[argv.index("--profile") + 1])

    def test_launch_argv_and_private_configuration(self):
        argv, profile = self.launch()
        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        for flag in ("--user", "--collect", "--property=Type=exec", "--property=ExitType=cgroup"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--") + 1:], ["/usr/bin/firefox", "--no-remote", "--new-window", "--profile", str(profile), "http://neverssl.com/"])
        self.assertEqual(self.mock_run.call_args.kwargs["timeout"], 5)
        self.assertNotIn("--scope", argv)
        self.assertIn("--setenv=DISPLAY=:42", argv)
        self.assertIn("--setenv=XDG_ACTIVATION_TOKEN=test-token", argv)
        self.assertIn("--setenv=DESKTOP_STARTUP_ID=test-startup", argv)
        self.assertFalse(any("UNRELATED_SECRET" in arg for arg in argv))
        base = self.data / "jstack/network-login"
        self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(profile.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((profile / "user.js").stat().st_mode), 0o600)
        policy = (profile / "user.js").read_text()
        self.assertEqual(policy, (base / "user.js").read_text())
        for key in ("dom.security.https_only_mode", "dom.security.https_only_mode_pbm", "dom.security.https_first", "dom.security.https_first_pbm"):
            self.assertIn(f'user_pref("{key}", false);', policy)
        self.assertIn('user_pref("network.trr.mode", 5);', policy)
        self.assertIn('user_pref("network.proxy.type", 0);', policy)
        self.assertIn('user_pref("browser.privatebrowsing.autostart", true);', policy)
        self.assertIn('user_pref("extensions.allowPrivateBrowsingByDefault", false);', policy)
        self.assertIn("--expand-environment=no", argv)
        self.assertFalse((self.root / "home/.mozilla").exists())
        self.assertFalse(any(key.startswith(("security.", "network.stricttransportsecurity")) for key in login.PREFERENCES))
        stop = next(arg for arg in argv if arg.startswith("--property=ExecStopPost="))
        self.assertIn("--cleanup", stop)
        self.assertIn(str(profile), stop)

    def test_existing_browser_configuration_is_untouched(self):
        normal = self.root / "home/.mozilla/firefox/default"
        normal.mkdir(parents=True)
        sentinel = normal / "user.js"
        sentinel.write_text('user_pref("dom.security.https_only_mode", true);\n')
        before = sentinel.read_bytes()
        self.launch()
        self.assertEqual(sentinel.read_bytes(), before)
        self.assertEqual(list(normal.iterdir()), [sentinel])

    def test_repeated_launches_use_distinct_profiles_and_units(self):
        first, one = self.launch()
        second, two = self.launch()
        self.assertNotEqual(one, two)
        self.assertNotEqual(next(a for a in first if a.startswith("--unit=")), next(a for a in second if a.startswith("--unit=")))
        (one / "cookies.sqlite").write_text("private")
        self.assertFalse((two / "cookies.sqlite").exists())
        self.assertEqual(login.main(["--cleanup", str(one)]), 0)
        self.assertFalse(one.exists())
        self.assertTrue(two.exists())

    def test_submission_failure_visible_nonzero_and_cleaned(self):
        self.mock_run.return_value = subprocess.CompletedProcess([], 1, "", "No user bus")
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(login.main([]), 1)
        self.assertIn("No user bus", output.getvalue())
        self.assertEqual(list((self.runtime / "jstack/network-login").iterdir()), [])

    def test_timeout_is_bounded_visible_and_does_not_delete_live_profile(self):
        self.mock_run.side_effect = subprocess.TimeoutExpired("systemd-run", 5)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(login.main([]), 1)
        self.assertIn("timed out after 5 seconds", output.getvalue())
        self.assertEqual(len(list((self.runtime / "jstack/network-login").iterdir())), 1)

    def test_missing_dependency_and_spawn_error(self):
        with patch.object(login.shutil, "which", return_value=None), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main([]), 1)
        self.mock_run.assert_not_called()
        self.mock_run.side_effect = FileNotFoundError("gone")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main([]), 1)
        self.assertEqual(list((self.runtime / "jstack/network-login").iterdir()), [])

    def test_unsafe_runtime_and_symlink_base_rejected(self):
        self.runtime.chmod(0o755)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main([]), 1)
        self.mock_run.assert_not_called()
        self.runtime.chmod(0o700)
        base = self.data / "jstack/network-login"
        (base / "user.js").unlink()
        base.rmdir()
        victim = self.root / "victim"
        victim.mkdir()
        base.symlink_to(victim, target_is_directory=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main([]), 1)
        self.assertEqual(list(victim.iterdir()), [])

    def test_cleanup_rejects_unrelated_paths_and_symlinks(self):
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "keep").touch()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main(["--cleanup", str(victim)]), 1)
        root = login.runtime_root()
        link = root / "profile-symlink"
        link.symlink_to(victim, target_is_directory=True)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main(["--cleanup", str(link)]), 1)
        self.assertTrue((victim / "keep").exists())

    def test_systemd_quoting_and_desktop_entry(self):
        self.assertEqual(login.systemd_argument('a%"\\b'), '"a%%\\"\\\\b"')
        self.assertEqual(login.systemd_argument("$HOME\n%t"), '"$$HOME\\n%%t"')
        desktop = (SCRIPT.parents[1] / "applications/network-login.desktop").read_text()
        self.assertIn("Exec=network-login\n", desktop)
        self.assertIn("Terminal=false\n", desktop)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(login.main(["https://untrusted.example"]), 1)
        self.mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
