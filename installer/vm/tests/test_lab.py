from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jstack_vm_lab", ROOT / "lab.py")
assert SPEC and SPEC.loader
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class LabSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "scratch"
        self.root.mkdir()
        self.workspace = self.root / "jstack-windows-vm"
        self.workspace.mkdir()
        (self.workspace / "images").mkdir()

    def test_workspace_must_be_strictly_below_scratch_root(self) -> None:
        self.assertEqual(
            lab.safe_workspace(self.workspace, self.root), self.workspace.resolve()
        )
        for unsafe in (self.root, self.root.parent, Path("/dev"), Path("/")):
            with self.subTest(path=unsafe):
                with self.assertRaises(lab.LabSafetyError):
                    lab.safe_workspace(unsafe, self.root)

    def test_workspace_rejects_lexical_symlink_components(self) -> None:
        target = self.root / "target"
        target.mkdir()
        link = self.root / "linked"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(lab.LabSafetyError, "contains a symlink"):
            lab.safe_workspace(link / "lab", self.root)

    def test_workspace_scan_rejects_symlinks_and_special_entries(self) -> None:
        unsafe = self.workspace / "images" / "host-device"
        unsafe.symlink_to("/dev/null")
        with self.assertRaisesRegex(lab.LabSafetyError, "symlink is forbidden"):
            lab.reject_unsafe_entries(self.workspace)

    def test_workspace_must_be_private(self) -> None:
        self.workspace.chmod(0o755)
        with self.assertRaisesRegex(lab.LabSafetyError, "must not grant"):
            lab.require_private_workspace(self.workspace)
        self.workspace.chmod(0o700)
        lab.require_private_workspace(self.workspace)

    def test_nested_mount_check_accepts_only_mounts_outside_workspace(self) -> None:
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "filesystems": [
                        {"target": "/", "source": "/dev/root"},
                        {"target": str(self.root / "other"), "source": "tmpfs"},
                    ]
                }
            ),
            stderr="",
        )
        with mock.patch.object(lab.subprocess, "run", return_value=result):
            lab.reject_nested_mounts(self.workspace)

    def test_nested_mount_check_rejects_workspace_and_descendants(self) -> None:
        targets = (
            self.workspace,
            self.workspace / "images",
            "//" + str(self.workspace / "images").lstrip("/"),
        )
        for target in targets:
            with self.subTest(target=target):
                result = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=json.dumps(
                        {"filesystems": [{"target": str(target), "source": "tmpfs"}]}
                    ),
                    stderr="",
                )
                with mock.patch.object(lab.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(
                        lab.LabSafetyError, "mounts are forbidden"
                    ):
                        lab.reject_nested_mounts(self.workspace)

    def test_nested_mount_check_decodes_spaces_and_json_escapes(self) -> None:
        workspace = self.root / 'workspace with spaces \\ and "quotes"'
        workspace.mkdir()
        target = workspace / "mounted\tchild"
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {"filesystems": [{"target": str(target), "source": "escaped source"}]}
            ),
            stderr="",
        )
        self.assertIn("\\\\", result.stdout)
        self.assertIn("\\\"", result.stdout)
        self.assertIn("\\t", result.stdout)
        with mock.patch.object(lab.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(lab.LabSafetyError, "mounts are forbidden"):
                lab.reject_nested_mounts(workspace)

    def test_nested_mount_check_ignores_caller_path(self) -> None:
        poisoned_path = self.root / "poisoned-bin"
        poisoned_path.mkdir()
        fake_findmnt = poisoned_path / "findmnt"
        fake_findmnt.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_findmnt.chmod(0o755)
        result = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"filesystems": []}),
            stderr="",
        )
        with (
            mock.patch.dict(os.environ, {"PATH": str(poisoned_path)}),
            mock.patch.object(lab.subprocess, "run", return_value=result) as run,
        ):
            lab.reject_nested_mounts(self.workspace)
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/findmnt")
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/findmnt",
                "--json",
                "--list",
                "--output",
                "TARGET,SOURCE",
            ],
        )
        self.assertEqual(run.call_args.kwargs["env"]["PATH"], lab.SYSTEM_PATH)
        self.assertNotEqual(run.call_args.args[0][0], str(fake_findmnt))

    def test_nested_mount_check_fails_closed_on_malformed_output(self) -> None:
        malformed_outputs = (
            "not JSON",
            '[["filesystems"]]',
            "{}",
            '{"filesystems": {}}',
            '{"filesystems": [[]]}',
            '{"filesystems": [{"source": "tmpfs"}]}',
            '{"filesystems": [{"target": 7, "source": "tmpfs"}]}',
            '{"filesystems": [{"target": "/tmp", "source": null}]}',
            '{"filesystems": [{"target": "relative", "source": "tmpfs"}]}',
            '{"filesystems": [{"target": "/tmp", "source": "tmpfs", "children": []}]}',
            '{"filesystems": [], "filesystems": []}',
        )
        for stdout in malformed_outputs:
            with self.subTest(stdout=stdout):
                result = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=stdout, stderr=""
                )
                with mock.patch.object(lab.subprocess, "run", return_value=result):
                    with self.assertRaises(lab.LabSafetyError):
                        lab.reject_nested_mounts(self.workspace)

    def test_nested_mount_check_fails_closed_when_findmnt_fails(self) -> None:
        with mock.patch.object(
            lab.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, ["/usr/bin/findmnt"]),
        ):
            with self.assertRaisesRegex(lab.LabSafetyError, "cannot enumerate mounts"):
                lab.reject_nested_mounts(self.workspace)

    @unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
    def test_qcow2_validation_accepts_only_regular_workspace_qcow2(self) -> None:
        disk = self.workspace / "images" / "test.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(disk), "1M"],
            check=True,
        )
        information = lab.validate_qcow2(disk, self.workspace)
        self.assertEqual(information["format"], "qcow2")
        self.assertEqual(information["validated-backing-chain"], [str(disk)])

        raw = self.workspace / "images" / "raw.img"
        raw.write_bytes(b"not a qcow2 image")
        with self.assertRaisesRegex(lab.LabSafetyError, "format must be qcow2"):
            lab.validate_qcow2(raw, self.workspace)

    @unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is required")
    def test_qcow2_backing_chain_must_remain_inside_workspace(self) -> None:
        base = self.workspace / "images" / "base.qcow2"
        overlay = self.workspace / "images" / "overlay.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(base), "1M"],
            check=True,
        )
        subprocess.run(
            [
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(base),
                str(overlay),
            ],
            check=True,
        )
        information = lab.validate_qcow2(overlay, self.workspace)
        self.assertEqual(
            information["validated-backing-chain"], [str(overlay), str(base)]
        )

        outside = self.root / "outside-base.qcow2"
        unsafe_overlay = self.workspace / "images" / "unsafe-overlay.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-q", "-f", "qcow2", str(outside), "1M"],
            check=True,
        )
        subprocess.run(
            [
                "qemu-img",
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(outside),
                str(unsafe_overlay),
            ],
            check=True,
        )
        with self.assertRaises(lab.LabSafetyError):
            lab.validate_qcow2(unsafe_overlay, self.workspace)

    def test_disk_validation_rejects_escape_and_device_paths(self) -> None:
        outside = self.root / "outside.qcow2"
        outside.write_bytes(b"")
        for unsafe in (outside, Path("/dev/null"), Path("/dev/nvme0n1")):
            with self.subTest(path=unsafe):
                with self.assertRaises(lab.LabSafetyError):
                    lab.validate_qcow2(unsafe, self.workspace)

    def test_disk_validation_rejects_symlink_even_when_target_is_inside(self) -> None:
        target = self.workspace / "images" / "target.qcow2"
        target.write_bytes(b"")
        link = self.workspace / "images" / "linked.qcow2"
        link.symlink_to(target)
        with self.assertRaises(lab.LabSafetyError):
            lab.validate_qcow2(link, self.workspace)

    def test_atomic_evidence_write_replaces_and_fsyncs_file_and_directory(self) -> None:
        output = self.workspace / "evidence" / "host.json"
        real_fsync = os.fsync
        with mock.patch.object(lab.os, "fsync", wraps=real_fsync) as fsync:
            lab.atomic_write_json(output, {"schema_version": 2, "safe": True})
        self.assertEqual(json.loads(output.read_text()), {"schema_version": 2, "safe": True})
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertGreaterEqual(fsync.call_count, 2)
        self.assertEqual(list(output.parent.glob(".host.json.*.tmp")), [])

    def test_atomic_evidence_write_cleans_temporary_file_on_replace_failure(self) -> None:
        output = self.workspace / "evidence" / "host.json"
        with mock.patch.object(lab.os, "replace", side_effect=OSError("injected")):
            with self.assertRaisesRegex(OSError, "injected"):
                lab.atomic_write_json(output, {"safe": False})
        self.assertFalse(output.exists())
        self.assertEqual(list(output.parent.glob(".host.json.*.tmp")), [])

    def test_command_facts_bind_version_to_exact_executable_bytes(self) -> None:
        executable = self.root / "test-command"
        executable.write_text("#!/bin/sh\necho pinned-version\n", encoding="utf-8")
        executable.chmod(0o755)
        with mock.patch.object(lab.shutil, "which", return_value=str(executable)):
            facts = lab.command_facts("test-command", "--version")
        self.assertEqual(facts["version"], "pinned-version")
        self.assertEqual(facts["binary_path"], str(executable))
        self.assertEqual(
            facts["binary_sha256"], hashlib.sha256(executable.read_bytes()).hexdigest()
        )
        self.assertEqual(facts["binary_mode"], 0o755)

    def test_host_evidence_hashes_firmware_and_records_machine_host_facts(self) -> None:
        firmware = []
        for name in ("code.fd", "secure.fd", "vars.fd"):
            path = self.root / name
            path.write_bytes(name.encode())
            firmware.append(path)
        host_facts = {
            "kernel": {"release": "test", "cmdline_sha256": "a" * 64},
            "cpu": {"model_name": "test cpu", "cpuinfo_sha256": "b" * 64},
            "kvm": {"path": "/dev/kvm", "readable": True, "writable": True},
        }
        disk_usage = mock.Mock(free=lab.MIN_AVAILABLE_DISK_BYTES + 1)
        with (
            mock.patch.object(lab, "OVMF_CODE", firmware[0]),
            mock.patch.object(lab, "OVMF_SECURE_CODE", firmware[1]),
            mock.patch.object(lab, "OVMF_VARS", firmware[2]),
            mock.patch.object(lab, "require_private_workspace"),
            mock.patch.object(lab, "reject_unsafe_entries"),
            mock.patch.object(lab, "reject_nested_mounts"),
            mock.patch.object(lab.os, "access", return_value=True),
            mock.patch.object(Path, "exists", return_value=True),
            mock.patch.object(lab.shutil, "disk_usage", return_value=disk_usage),
            mock.patch.object(
                lab,
                "available_memory_bytes",
                return_value=lab.MIN_AVAILABLE_MEMORY_BYTES + 1,
            ),
            mock.patch.object(
                lab,
                "command_facts",
                return_value={
                    "version": "test-version",
                    "binary_path": "/usr/bin/test-command",
                    "binary_sha256": "c" * 64,
                    "binary_size": 123,
                    "binary_device": 1,
                    "binary_inode": 2,
                    "binary_mode": 0o755,
                },
            ),
            mock.patch.object(
                lab, "command_output", return_value="pc-q35-11.0 test machine"
            ),
            mock.patch.object(lab, "kernel_cpu_kvm_facts", return_value=host_facts),
        ):
            evidence = lab.host_evidence(self.workspace)
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(evidence["kernel"], host_facts["kernel"])
        self.assertEqual(evidence["cpu"], host_facts["cpu"])
        self.assertEqual(evidence["kvm"], host_facts["kvm"])
        self.assertTrue(evidence["qemu_machine"]["available"])
        self.assertEqual(evidence["versions"]["qemu"]["binary_sha256"], "c" * 64)
        self.assertEqual(evidence["versions"]["swtpm"]["version"], "test-version")
        for key, path in zip(
            ("ovmf_code", "ovmf_secure_code", "ovmf_vars"), firmware
        ):
            self.assertEqual(
                evidence["firmware"][key]["sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
