#!/usr/bin/env python3
"""Non-destructive regression tests for the legacy disk installer."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "jstack-install.sh"
CHROOT_STAGE = Path(__file__).parents[1] / "chroot-stage.sh"


class InstallerSafetyTests(unittest.TestCase):
    def run_instrumented(self, fail_preflight: bool, bootstrap: bool = False, die_after_destructive: bool = False, password: str = "secret", stdin: str = ""):
        scratch = Path(os.environ.get("JCODE_SCRATCH_DIR", Path.home() / ".jcode" / "scratch"))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as td:
            root = Path(td)
            text = SCRIPT.read_text()
            text = text.replace('[ "$(id -u)" = 0 ] || die "run as root"', ":")
            text = text.replace('[ -d /sys/firmware/efi ] || die "UEFI boot required (systemd-boot)"', ":")
            text = text.replace('[ -b "$DISK" ] || die "$DISK is not a block device"', ":")
            text = text.replace("if command -v pacman >/dev/null && [ -f /etc/arch-release ]; then", "if true; then")
            if bootstrap:
                text = text.replace("host_prep\npackage_preflight", "BOOT=/fake; ARCH_CHROOT=arch-chroot\npackage_preflight")
            if die_after_destructive:
                text = text.replace("partition\nbootstrap", 'DESTRUCTIVE_STARTED=1\ndie "synthetic post-wipe failure"')
            script = root / "installer.sh"
            script.write_text(text)
            script.chmod(0o755)
            bindir = root / "bin"
            bindir.mkdir()
            log = root / "commands"
            generic = "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$COMMAND_LOG\"\nexit 0\n"
            for command in ("lsblk", "wipefs", "sgdisk", "partprobe", "udevadm", "sleep", "chown"):
                p = bindir / command
                p.write_text(generic)
                p.chmod(0o755)
            pacman = bindir / "pacman"
            pacman.write_text(
                "#!/bin/sh\n"
                'echo "pacman $*" >> "$COMMAND_LOG"\n'
                + ('case "$*" in *-Syw*) exit 42;; esac\n' if fail_preflight else "")
                + "exit 0\n"
            )
            pacman.chmod(0o755)
            arch_chroot = bindir / "arch-chroot"
            arch_chroot.write_text(
                "#!/bin/sh\n"
                'echo "arch-chroot $*" >> "$COMMAND_LOG"\n'
                + ("exit 42\n" if fail_preflight else "exit 0\n")
            )
            arch_chroot.chmod(0o755)
            if not fail_preflight:
                sgdisk = bindir / "sgdisk"
                sgdisk.write_text(
                    "#!/bin/sh\n"
                    'echo "sgdisk $*" >> "$COMMAND_LOG"\n'
                    "exit 43\n"
                )
                sgdisk.chmod(0o755)
            env = os.environ | {"PATH": f"{bindir}:{os.environ['PATH']}", "COMMAND_LOG": str(log)}
            result = subprocess.run(
                [str(script), "--disk", "/dev/fake", "--user", "tester", "--password", password, "--yes"],
                env=env,
                input=stdin,
                text=True,
                capture_output=True,
                timeout=10,
            )
            return result, log.read_text() if log.exists() else ""

    def test_empty_password_or_eof_prevents_host_prep_and_wipe(self):
        for stdin in ("", "\n"):
            with self.subTest(stdin=repr(stdin)):
                result, commands = self.run_instrumented(True, password="", stdin=stdin)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("pacman", commands)
                self.assertNotIn("wipefs", commands)
                self.assertNotIn("INSTALLATION FAILED AFTER", result.stderr)
                if stdin:
                    self.assertIn("password must not be empty", result.stderr)

    def test_failed_package_sync_prevents_wipe(self):
        result, commands = self.run_instrumented(fail_preflight=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-Syw", commands)
        self.assertNotIn("wipefs", commands)
        self.assertNotIn("INSTALLATION FAILED AFTER", result.stderr)

    def test_ubuntu_bootstrap_sync_failure_prevents_wipe(self):
        result, commands = self.run_instrumented(fail_preflight=True, bootstrap=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arch-chroot /fake", commands)
        self.assertIn("db=$(mktemp -d)", commands)
        self.assertNotIn("wipefs", commands)

    def test_post_destructive_failure_prints_recovery_warning(self):
        # Once preflight succeeds, fail the first partition-table operation.
        result, commands = self.run_instrumented(fail_preflight=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wipefs", commands)
        self.assertIn("INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED", result.stderr)
        self.assertIn("Do not reboot into the target", result.stderr)
        self.assertIn("rerun formats it again", result.stderr)
        self.assertNotIn("secret", result.stderr)

    def test_explicit_die_after_destructive_start_prints_warning(self):
        result, _ = self.run_instrumented(fail_preflight=False, die_after_destructive=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("synthetic post-wipe failure", result.stderr)
        self.assertIn("INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED", result.stderr)

    def test_working_mirrorlist_is_installed_after_pacstrap(self):
        text = SCRIPT.read_text()
        copy = 'install -Dm644 "$MIRRORLIST" "$MNT/etc/pacman.d/mirrorlist"'
        self.assertIn(copy, text)
        self.assertGreater(text.index(copy), text.index('pacstrap -c -C "$PACMAN_CONF"'))
        self.assertIn('pacman --config "$PACMAN_CONF" --dbpath "$db"', text)
        self.assertIn("db=$(mktemp -d)", text)
        self.assertIn('pacman-conf DownloadUser', text)
        self.assertIn('pacman-conf --config "$PACMAN_CONF" DownloadUser', text)
        self.assertEqual(text.count('[ -z "$user" ] || chown "$user" "$db"'), 2)
        self.assertNotIn('chown alpm:alpm', text)
        self.assertNotIn("--cachedir /var/cache/pacman/pkg", text)

    def test_bootloader_install_never_mutates_host_efi_variables(self):
        text = CHROOT_STAGE.read_text()
        self.assertIn("bootctl --no-variables install", text)
        self.assertNotIn("bootctl install", text)


if __name__ == "__main__":
    unittest.main()
