#!/usr/bin/env python3
"""PH-10 boot-proof tests: the artifacts boot and Secure Boot enforces.

These are the only cases in the tree that observe *firmware behaviour* rather
than byte equality. They are slow (three real VM boots) and they skip cleanly on
a host without KVM, OVMF, or a kernel, so they never turn an unrelated CI machine
red.
"""

from __future__ import annotations

import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boot_proof  # noqa: E402
import lab  # noqa: E402


class BootProofTests(unittest.TestCase):
    """One shared run of the three-case proof, asserted from several angles."""

    evidence: dict | None = None
    skip_reason: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        ready, reason = boot_proof.available()
        if not ready:
            cls.skip_reason = reason
            return
        scratch = lab.require_scratch_root()
        cls.workspace = scratch / "jstack-windows-vm" / "bootproof-tests"
        shutil.rmtree(cls.workspace, ignore_errors=True)
        cls.workspace.mkdir(parents=True)
        os.chmod(cls.workspace, 0o700)
        cls.evidence = boot_proof.run_boot_proof(cls.workspace)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.skip_reason is None:
            shutil.rmtree(cls.workspace, ignore_errors=True)

    def setUp(self) -> None:
        if self.skip_reason is not None:
            self.skipTest(f"host cannot run the boot proof: {self.skip_reason}")

    def test_the_signed_artifact_boots_under_secure_boot(self) -> None:
        """The claim the row makes: it is genuinely bootable, not merely signed."""
        case = self.evidence["cases"]["signed"]
        self.assertTrue(case["booted"], "the signed UKI must reach the guest marker")
        self.assertFalse(case["refused"], "firmware must not refuse a correctly signed UKI")

    def test_a_tampered_artifact_is_refused_by_firmware(self) -> None:
        """One flipped byte inside the PE must stop the boot at the firmware."""
        case = self.evidence["cases"]["tampered"]
        self.assertFalse(
            case["booted"], "a tampered UKI must never reach the guest marker"
        )
        self.assertTrue(
            case["refused"], "firmware must report an authentication failure"
        )

    def test_an_unsigned_artifact_is_refused_by_firmware(self) -> None:
        """The control that makes the tamper result meaningful.

        If an unsigned image booted, Secure Boot would not actually be enforcing
        and the tamper refusal above would prove nothing.
        """
        case = self.evidence["cases"]["unsigned"]
        self.assertFalse(case["booted"])
        self.assertTrue(case["refused"])

    def test_the_three_cases_are_genuinely_different_images(self) -> None:
        """Guard against all three cases accidentally booting the same bytes."""
        self.assertNotEqual(
            self.evidence["signed_sha256"], self.evidence["unsigned_sha256"]
        )
        self.assertEqual(len(self.evidence["signed_sha256"]), 64)
        self.assertEqual(len(self.evidence["certificate_sha256"]), 64)

    def test_the_tampered_byte_is_deep_inside_the_image(self) -> None:
        """A header-adjacent flip could fail for reasons other than the signature."""
        offset = self.evidence["tampered_byte_offset"]
        self.assertGreater(
            offset, 4096, "the flipped byte must be past the PE headers"
        )


class BootProofSafetyTests(unittest.TestCase):
    """Static properties of the harness, checkable without booting anything."""

    def source(self) -> str:
        return Path(boot_proof.__file__).read_text(encoding="utf-8")

    def code(self) -> str:
        return "\n".join(
            line
            for line in self.source().splitlines()
            if not line.strip().startswith("#")
        )

    def test_the_guest_gets_no_network_and_no_host_device(self) -> None:
        code = self.code()
        self.assertIn('"-nic",', code)
        self.assertIn('"none",', code)
        for forbidden in ("/dev/sd", "/dev/nvme", "if=none,file=/dev", "host_device"):
            self.assertNotIn(forbidden, code, f"{forbidden} must not appear")

    def test_firmware_code_is_opened_read_only(self) -> None:
        """The distribution firmware must never be writable by a run."""
        self.assertIn("readonly=on", self.code())

    def test_the_variable_store_is_a_per_run_copy(self) -> None:
        """Enrolling keys must not mutate the shared distribution template."""
        code = self.code()
        self.assertIn("shutil.copyfile(OVMF_VARS", code)
        self.assertIn("secure-boot-vars.fd", code)

    def test_every_boot_has_a_hard_timeout(self) -> None:
        """A refused boot never powers off, so it must be capped."""
        self.assertIn("timeout=BOOT_TIMEOUT_SECONDS", self.code())
        self.assertLessEqual(boot_proof.BOOT_TIMEOUT_SECONDS, 120)

    def test_secure_boot_is_actually_enabled_by_the_enrollment(self) -> None:
        code = self.code()
        self.assertIn("--secure-boot", code)
        self.assertIn("--set-pk", code)
        self.assertIn("--add-db", code)

    def test_availability_is_reported_rather_than_assumed(self) -> None:
        """The proof must skip with a reason, not crash, on an unequipped host."""
        ready, reason = boot_proof.available()
        self.assertIsInstance(ready, bool)
        self.assertTrue(reason)

    def test_the_marker_is_distinctive_enough_to_be_unambiguous(self) -> None:
        marker = boot_proof.BOOT_MARKER
        self.assertGreater(len(marker), 12)
        self.assertEqual(marker, marker.upper())
        self.assertIn("JSTACK", marker)


if __name__ == "__main__":
    unittest.main()
