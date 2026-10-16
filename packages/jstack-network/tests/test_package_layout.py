#!/usr/bin/env python3
"""Exercise the real package() function without dependency changes or root."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackageLayoutTests(unittest.TestCase):
    def test_staged_recovery_tools_units_and_presets(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            subprocess.run([
                "bash", "-euc",
                'source "$1/PKGBUILD"; startdir="$1"; pkgdir="$2"; package',
                "stage-package", str(ROOT), str(stage),
            ], check=True, capture_output=True, text=True)
            for tool in ("wifi-pick", "captive-portal-helper", "captive-portal-autoaccept",
                         "captive-portal-monitor"):
                installed = stage / "usr/bin" / tool
                self.assertEqual(installed.read_bytes(), (ROOT / "files/bin" / tool).read_bytes())
                self.assertTrue(installed.stat().st_mode & 0o111)
            preset = (stage / "usr/lib/systemd/user-preset/90-jstack-network.preset").read_text()
            self.assertIn("enable captive-portal-monitor.service", preset)
            self.assertIn("enable captive-portal-helper.timer", preset)
            self.assertIn("disable captive-portal-watch.service", preset)
            units = stage / "usr/lib/systemd/user"
            self.assertIn("WantedBy=default.target", (units / "captive-portal-monitor.service").read_text())
            self.assertIn("TimeoutStartSec=120", (units / "captive-portal-helper.service").read_text())
            self.assertIn("'python-requests'", (ROOT / "PKGBUILD").read_text())


if __name__ == "__main__":
    unittest.main()
