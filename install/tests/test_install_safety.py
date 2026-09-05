#!/usr/bin/env python3
"""Non-destructive regression tests for transactional installer routing."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / "jstack-install.sh"
CHROOT_STAGE = Path(__file__).parents[1] / "chroot-stage.sh"


class InstallerSafetyTests(unittest.TestCase):
    def test_bootstrap_artifact_mount_is_isolated_and_gone_before_prepare(self):
        text = SCRIPT.read_text()
        private = text.index('mount --make-private "$BOOT"')
        recursive_bind = text.index('mount --rbind "$MNT" "$BOOT/mnt"')
        unmount = text.index('umount -R "$BOOT/mnt"')
        absence_check = text.index('mountpoint -q "$BOOT/mnt" && die')
        prepare = text.index('"$controller" prepare --disk')
        self.assertLess(private, recursive_bind)
        self.assertLess(recursive_bind, unmount)
        self.assertLess(unmount, absence_check)
        self.assertLess(absence_check, prepare)

    def test_real_public_cli_rejects_stage_escape_before_host_checks(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), "--chroot-stage"],
            text=True, capture_output=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot bypass transactional installation", result.stderr)

    def test_real_public_cli_rejects_duplicate_options_before_host_checks(self):
        for args in (
            ["--disk", "/dev/never-open-a", "--disk", "/dev/never-open-b", "--yes"],
            ["--yes", "--yes"],
            ["--password", "private-one", "--password", "private-two"],
        ):
            with self.subTest(option=args[0]):
                result = subprocess.run(
                    ["bash", str(SCRIPT), *args],
                    text=True, capture_output=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("duplicate option", result.stderr)
                self.assertNotIn("private-one", result.stderr)
                self.assertNotIn("private-two", result.stderr)

    def run_instrumented(self, fail_preflight: bool, bootstrap: bool = False, die_after_destructive: bool = False, password: str = "secret", stdin: str = "", sector_size: int = 512):
        scratch = Path(os.environ.get("JCODE_SCRATCH_DIR", Path.home() / ".jcode" / "scratch"))
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as td:
            root = Path(td)
            text = SCRIPT.read_text()
            text = text.replace('[ "$(id -u)" = 0 ] || die "run as root"', ":")
            text = text.replace('[ -d /sys/firmware/efi ] || die "UEFI boot required (systemd-boot)"', ":")
            text = text.replace('[ -b "$DISK" ] || die "$DISK is not a block device"', ":")
            text = text.replace('[ -b "$ARTIFACT_LOOP" ] || die "failed to attach artifact loop device"', ":")
            text = text.replace("if command -v pacman >/dev/null && [ -f /etc/arch-release ]; then", "if true; then")
            if bootstrap:
                text = text.replace("host_prep\npackage_preflight", "BOOT=/fake; ARCH_CHROOT=arch-chroot\npackage_preflight")
            if die_after_destructive:
                text = text.replace("  partition\n  # Mutating", '  DESTRUCTIVE_STARTED=1\n  die "synthetic post-wipe failure"\n  # Mutating')
            script = root / "installer.sh"
            script.write_text(text)
            script.chmod(0o755)
            bindir = root / "bin"
            bindir.mkdir()
            log = root / "commands"
            controller = root / "controller"
            controller.write_text(
                "#!/bin/sh\n"
                'if [ "$1" = init ]; then shift; while [ $# -gt 0 ]; do '
                'case "$1" in --state-dir) mkdir -p "$2/artifact-build"; exit 0;; esac; shift; done; fi\n'
                "exit 0\n"
            )
            controller.chmod(0o755)
            generic = "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"$COMMAND_LOG\"\nexit 0\n"
            for command in ("lsblk", "wipefs", "sgdisk", "partprobe", "udevadm", "sleep", "chown", "losetup", "blockdev"):
                p = bindir / command
                p.write_text(generic)
                p.chmod(0o755)
            (bindir / "losetup").write_text(
                "#!/bin/sh\n"
                'echo "losetup $*" >> "$COMMAND_LOG"\n'
                'case "$*" in *--find*) for last do :; done; echo "$last" > "$LOOP_BACKING"; echo /dev/loop-test;; '
                '*BACK-FILE*) cat "$LOOP_BACKING";; esac\n'
                "exit 0\n"
            )
            (bindir / "blockdev").write_text(
                "#!/bin/sh\n"
                'echo "blockdev $*" >> "$COMMAND_LOG"\n'
                'case "$1" in --getss) echo "$SECTOR_SIZE";; *) echo 4294967296;; esac\n'
            )
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
            env = os.environ | {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "COMMAND_LOG": str(log),
                "LOOP_BACKING": str(root / "loop-backing"),
                "JSTACK_UBUNTU_INSTALLER": str(controller),
                "SECTOR_SIZE": str(sector_size),
            }
            result = subprocess.run(
                [str(script), "--disk", "/dev/fake", "--state-dir", str(root / "state"), "--user", "tester", "--password", password, "--yes"],
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

    def test_non_512_sector_target_is_refused_before_host_or_target_effects(self):
        result, commands = self.run_instrumented(False, sector_size=4096)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only 512-byte-sector targets are supported", result.stderr)
        self.assertNotIn("pacman", commands)
        self.assertNotIn("wipefs", commands)

    def test_ubuntu_bootstrap_sync_failure_prevents_wipe(self):
        result, commands = self.run_instrumented(fail_preflight=True, bootstrap=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arch-chroot /fake", commands)
        self.assertIn("db=$(mktemp -d)", commands)
        self.assertNotIn("wipefs", commands)

    def test_artifact_build_failure_never_mutates_or_condemns_target(self):
        # Once preflight succeeds, fail the first disposable-image partition
        # operation. The real target must not be passed to a destructive tool.
        result, commands = self.run_instrumented(fail_preflight=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wipefs -af /dev/loop-test", commands)
        self.assertNotIn("wipefs -af /dev/fake", commands)
        self.assertNotIn("INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED", result.stderr)
        self.assertNotIn("secret", result.stderr)

    def test_partition_builder_is_hard_bound_to_owned_loop_artifact(self):
        text = SCRIPT.read_text()
        self.assertIn('internal partition builder may operate only on its owned artifact', text)
        self.assertIn('[ "$DISK" = "$ARTIFACT_LOOP" ]', text)
        self.assertIn('loop device is not backed by the exclusively created artifact', text)
        self.assertIn('artifact partition does not belong to owned loop device', text)

    def test_explicit_artifact_failure_does_not_claim_target_was_modified(self):
        result, _ = self.run_instrumented(fail_preflight=False, die_after_destructive=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("synthetic post-wipe failure", result.stderr)
        self.assertNotIn("INSTALLATION FAILED AFTER THE TARGET WAS MODIFIED", result.stderr)

    def test_public_path_requires_durable_state_directory(self):
        text = SCRIPT.read_text()
        self.assertIn('[ -n "$STATE_DIR" ] || die "--state-dir on a persistent separate host disk is required"', text)

    def test_partition_only_install_is_outside_transactional_scope(self):
        text = SCRIPT.read_text()
        refusal = "transactional Ubuntu installation supports only a separate whole disk"
        self.assertIn(refusal, text)
        self.assertLess(text.index(refusal), text.index("# ---------- host prerequisites ----------"))

    def test_read_only_inspect_and_safe_init_precede_host_or_artifact_work(self):
        text = SCRIPT.read_text()
        inspect = '"$CONTROLLER" inspect --disk "$DISK" --state-dir "$STATE_DIR"'
        init = '"$CONTROLLER" init --disk "$DISK" --state-dir "$STATE_DIR"'
        self.assertLess(text.rindex(inspect), text.rindex(init))
        self.assertLess(text.rindex(init), text.rindex("host_prep"))
        self.assertNotIn('chmod 700 "$STATE_DIR"', text)
        self.assertNotIn('mkdir -p "$STATE_DIR', text)
        self.assertNotIn("MNT=/mnt/jstack", text)
        self.assertIn('MNT="$STATE_DIR/artifact-build/mnt-$$"', text)

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

    def test_serial_console_is_explicit_and_built_into_artifact(self):
        installer = SCRIPT.read_text()
        stage = CHROOT_STAGE.read_text()
        self.assertIn("--serial-console) SERIAL_CONSOLE=1", installer)
        self.assertIn('J_SERIAL_CONSOLE="$SERIAL_CONSOLE"', installer)
        self.assertIn('J_SERIAL_CONSOLE:-0', stage)
        self.assertEqual(stage.count("$SERIAL_OPTIONS"), 2)


if __name__ == "__main__":
    unittest.main()
