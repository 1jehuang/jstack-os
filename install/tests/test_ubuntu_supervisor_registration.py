"""Registration regressions independent of guest payloads and physical disks."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

path = Path(__file__).parents[1] / "vm" / "test-ubuntu-recovery.py"
spec = importlib.util.spec_from_file_location("supervisor_under_test", path)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class RegistrationTests(unittest.TestCase):
    def test_host_lock_is_global_to_the_user_and_exclusive(self):
        runtime = MagicMock()
        runtime.stat.return_value = SimpleNamespace(st_uid=1000)
        runtime.is_dir.return_value = True
        runtime.is_symlink.return_value = False
        runtime.__truediv__.return_value = Path("/run/user/1000") / h.HOST_LOCK_NAME
        opened = Mock()
        with patch.object(h.os, "getuid", return_value=1000), patch.object(h, "Path", return_value=runtime), patch.object(h.os, "open", return_value=17) as os_open, patch.object(h.os, "fdopen", return_value=opened), patch.object(h.fcntl, "flock") as flock:
            self.assertIs(h.host_lock(), opened)
        flags = os_open.call_args.args[1]
        self.assertTrue(flags & h.os.O_CREAT)
        self.assertTrue(flags & getattr(h.os, "O_NOFOLLOW", 0))
        flock.assert_called_once_with(opened, h.fcntl.LOCK_EX)

    def test_transient_exec_identity_is_retried(self):
        proc = SimpleNamespace(pid=123, poll=Mock(return_value=None))
        expected = {"starttime": "42", "cmdline_sha256": "a" * 64}
        with patch.object(h, "proc_identity", side_effect=[SystemExit("not ready"), expected]) as identity, patch.object(h.time, "sleep"):
            self.assertEqual(h.registered_identity(proc), expected)
            self.assertEqual(identity.call_count, 2)

    def test_exited_child_is_not_retried(self):
        proc = SimpleNamespace(pid=123, poll=Mock(return_value=1))
        with patch.object(h, "proc_identity", side_effect=SystemExit("gone")), patch.object(h.time, "sleep") as sleep:
            with self.assertRaises(SystemExit):
                h.registered_identity(proc)
            sleep.assert_not_called()

    def test_unrecognizable_live_child_has_bounded_registration(self):
        proc = SimpleNamespace(pid=123, poll=Mock(return_value=None))
        with patch.object(h, "proc_identity", side_effect=SystemExit("wrong process")), patch.object(h.time, "monotonic", side_effect=[0, 3]):
            with self.assertRaises(SystemExit):
                h.registered_identity(proc, timeout=2)
