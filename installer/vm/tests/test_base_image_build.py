"""Tests for Windows base-image construction.

This module is the one place in the tree that cannot be proven by comparing
bytes, because its job is to make a real Windows installer run. So these tests
concentrate on the two things that *are* checkable without a 45-minute install:
that the QEMU command line cannot reach anything it should not, and that the
post-install inspection actually refuses a disk that is not a finished Windows
install.

The inspection tests build synthetic GPT disks rather than mocking, because the
failure being guarded against is "the checker silently inspects nothing", which a
mock would reproduce perfectly while proving nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import base_image_build  # noqa: E402
import lab  # noqa: E402

PROFILE_KEY = "windows-11-enterprise-25h2-en-us-eval"

# ESP, MSR, Windows basic data: the roles a finished UEFI install must expose.
WINDOWS_LAYOUT = ("ef00", "0c01", "0700")


def have(*tools: str) -> bool:
    return all(shutil.which(tool) is not None for tool in tools)


def make_gpt_qcow2(destination: Path, type_codes: tuple[str, ...]) -> Path:
    """Build a synthetic qcow2 with the given GPT partition type codes."""

    raw = destination.with_suffix(".raw")
    subprocess.run(["truncate", "-s", "2G", str(raw)], check=True)
    arguments = ["sgdisk"]
    for index, code in enumerate(type_codes, start=1):
        size = "+100M" if index < len(type_codes) else "0"
        start = "2048" if index == 1 else "0"
        arguments += ["-n", f"{index}:{start}:{size}", "-t", f"{index}:{code}"]
    arguments.append(str(raw))
    subprocess.run(arguments, check=True, capture_output=True)
    subprocess.run(
        ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(destination)],
        check=True,
    )
    raw.unlink()
    return destination


class CommandLineSafetyTests(unittest.TestCase):
    """The build command line is reviewed statically; a VM is not needed."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-argv-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.inputs = base_image_build.BuildInputs(
            record_key=PROFILE_KEY,
            iso=self.workspace / "media.iso",
            answer_media=self.workspace / "answer.img",
            firmware_code=Path("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"),
            firmware_vars=self.workspace / "vars.fd",
            disk=self.workspace / "base.qcow2",
            virtual_size_bytes=137438953472,
        )

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def argv(self) -> list[str]:
        return base_image_build.build_qemu_argv(self.inputs, self.workspace / "q.sock")

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_guest_gets_no_network(self) -> None:
        """A base image must be a function of the ISO alone."""

        argv = self.argv()
        self.assertIn("none", argv[argv.index("-nic") + 1])
        joined = " ".join(argv)
        for forbidden in ("user,model=", "hostfwd", "tap,", "bridge"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, joined)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_no_host_device_or_passthrough_is_reachable(self) -> None:
        joined = " ".join(self.argv())
        for forbidden in ("/dev/", "file=/dev", "iothread", "vfio", "usb-host", "virtfs"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, joined)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_installation_media_is_attached_read_only(self) -> None:
        """The ISO and answer media are inputs and must not be writable."""

        argv = self.argv()
        for drive in [a for a in argv if a.startswith("if=none")]:
            if "install-iso" in drive or "answer" in drive:
                with self.subTest(drive=drive):
                    self.assertIn("readonly=on", drive)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_firmware_code_is_read_only_and_vars_are_a_copy(self) -> None:
        argv = self.argv()
        pflash = [a for a in argv if "if=pflash" in a]
        self.assertEqual(len(pflash), 2)
        code = next(a for a in pflash if "unit=0" in a)
        variables = next(a for a in pflash if "unit=1" in a)
        self.assertIn("readonly=on", code)
        # The writable store must be the per-build copy, never the enrolled
        # master and never the distribution template.
        self.assertNotIn("readonly=on", variables)
        self.assertIn(str(self.workspace), variables)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_secure_boot_requires_smm_and_the_secboot_firmware(self) -> None:
        argv = self.argv()
        machine = argv[argv.index("-machine") + 1]
        self.assertIn("smm=on", machine)
        code = next(a for a in argv if "if=pflash" in a and "unit=0" in a)
        self.assertIn("secboot", code)

    @unittest.skipUnless(have("qemu-system-x86_64"), "qemu is unavailable")
    def test_the_disk_matches_the_profile_storage_topology(self) -> None:
        """A base image is only valid for the topology the campaign will use."""

        profile = base_image_build.load_profile(PROFILE_KEY)
        joined = " ".join(self.argv())
        self.assertIn(profile["storage"]["serial"], joined)
        self.assertIn("nvme", joined)
        self.assertIn(
            f"logical_block_size={profile['storage']['logical_sector_bytes']}", joined
        )
        self.assertIn(
            f"physical_block_size={profile['storage']['physical_sector_bytes']}", joined
        )


class DiskCreationTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-disk-", dir=scratch))
        os.chmod(self.workspace, 0o700)
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

    @unittest.skipUnless(have("qemu-img"), "qemu-img is unavailable")
    def test_a_disk_is_created_sparse_at_the_requested_size(self) -> None:
        disk = base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)
        self.assertTrue(disk.is_file())
        # qcow2 is sparse: the file on disk is far smaller than the virtual size.
        self.assertLess(os.stat(disk).st_size, 8 * 1024**3)

    @unittest.skipUnless(have("qemu-img"), "qemu-img is unavailable")
    def test_an_existing_disk_is_never_clobbered(self) -> None:
        base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.create_disk(self.workspace, "d.qcow2", 8 * 1024**3)

    def test_a_nonpositive_size_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.create_disk(self.workspace, "z.qcow2", 0)


@unittest.skipUnless(
    have("guestfish", "qemu-img", "sgdisk", "truncate"),
    "guestfish, qemu-img, sgdisk or truncate is unavailable",
)
class InspectionTests(unittest.TestCase):
    """The central property: inspection must refuse a disk that is not an install."""

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp(prefix="bib-inspect-"))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)
        self.profile = base_image_build.load_profile(PROFILE_KEY)

    def inspect(self, type_codes: tuple[str, ...]):
        disk = make_gpt_qcow2(self.workspace / "d.qcow2", type_codes)
        return base_image_build.inspect_disk(disk, self.profile, self.workspace)

    def test_a_windows_like_layout_is_accepted(self) -> None:
        result = self.inspect(WINDOWS_LAYOUT)
        self.assertTrue(result["gpt_present"])
        self.assertEqual(result["partition_count"], 3)
        self.assertEqual(
            result["required_roles_present"], ["esp", "msr", "windows"]
        )

    def test_a_linux_layout_is_refused(self) -> None:
        """A GPT alone is not a Windows install."""

        with self.assertRaises(base_image_build.BaseImageBuildError) as caught:
            self.inspect(("8300",))
        self.assertIn("missing required partition roles", str(caught.exception))

    def test_a_disk_without_the_esp_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            self.inspect(("0c01", "0700"))

    def test_a_disk_without_the_windows_volume_is_refused(self) -> None:
        with self.assertRaises(base_image_build.BaseImageBuildError):
            self.inspect(("ef00", "0c01"))

    def test_an_unpartitioned_disk_is_refused(self) -> None:
        disk = self.workspace / "empty.qcow2"
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2", str(disk), "1G"],
            check=True,
            capture_output=True,
        )
        with self.assertRaises(base_image_build.BaseImageBuildError):
            base_image_build.inspect_disk(disk, self.profile, self.workspace)

    def test_the_gpt_digest_is_stable_and_layout_sensitive(self) -> None:
        """The pinned GPT digest must change when the table changes."""

        first = make_gpt_qcow2(self.workspace / "a.qcow2", WINDOWS_LAYOUT)
        digest_a = base_image_build.gpt_sha256(first, self.workspace)
        self.assertEqual(
            digest_a, base_image_build.gpt_sha256(first, self.workspace)
        )
        second = make_gpt_qcow2(self.workspace / "b.qcow2", ("8300",))
        self.assertNotEqual(
            digest_a, base_image_build.gpt_sha256(second, self.workspace)
        )

    def test_the_gpt_digest_leaves_no_temporary_behind(self) -> None:
        disk = make_gpt_qcow2(self.workspace / "c.qcow2", WINDOWS_LAYOUT)
        before = set(os.listdir(self.workspace))
        base_image_build.gpt_sha256(disk, self.workspace)
        self.assertEqual(set(os.listdir(self.workspace)), before)

    def test_inspection_does_not_use_sgdisk_on_the_qcow2(self) -> None:
        """sgdisk cannot read qcow2; using it would inspect nothing at all.

        This was a real defect during development: the first implementation used
        sgdisk and silently reported no partition table for a valid image.
        """

        import ast

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        tree = ast.parse(body)
        function = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "inspect_disk"
        )
        # Compare against the string literals the function actually executes,
        # parsed rather than grepped. The docstring names sgdisk precisely to
        # record why it is unsuitable, and that explanation must not trip the
        # check it explains.
        literals = {
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        literals.discard(ast.get_docstring(function))
        self.assertNotIn("sgdisk", literals)
        self.assertIn("guestfish", literals)


class StaticSafetyTests(unittest.TestCase):
    def test_the_module_names_no_privileged_or_device_primitive(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        for forbidden in ("losetup", "partprobe", "kpartx", "sudo", "mount(", "libvirt"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_a_timeout_is_a_failure_not_a_success(self) -> None:
        """A stalled installer must never be recorded as a completed build."""

        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        waiter = body[body.index("def wait_for_shutdown") : body.index("def prepare_inputs")]
        self.assertIn("raise BaseImageBuildError", waiter)
        self.assertIn("did not power off", waiter)

    def test_a_nonzero_qemu_exit_is_a_failure(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        self.assertIn('raise BaseImageBuildError(f"QEMU exited {exit_code}', body)

    def test_building_as_root_is_refused(self) -> None:
        body = (ROOT / "base_image_build.py").read_text(encoding="utf-8")
        self.assertIn("refusing to build a base image as root", body)


if __name__ == "__main__":
    unittest.main()
