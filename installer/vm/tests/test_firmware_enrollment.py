"""Tests for Microsoft-production OVMF variable enrollment.

The enrolled store is what every Secure Boot claim about a Windows guest will
rest on, so these tests attack the ways it could be wrong while still looking
right: the tool silently no-opping, the shared distribution template being
mutated, Secure Boot left off, custom mode left on, or a stale store being
reused. Each must be caught by reading the produced bytes rather than by
trusting an exit code.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import firmware_enrollment  # noqa: E402
import lab  # noqa: E402


def tools_available() -> bool:
    return (
        shutil.which(firmware_enrollment.VIRT_FW_VARS) is not None
        and firmware_enrollment.OVMF_VARS_TEMPLATE.is_file()
    )


@unittest.skipUnless(tools_available(), "virt-fw-vars or the OVMF template is unavailable")
class EnrollmentTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = Path(tempfile.mkdtemp(prefix="enroll-", dir=scratch))
        os.chmod(self.workspace, 0o700)
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

    def enroll(self, **kwargs):
        return firmware_enrollment.enroll_microsoft_vars(self.workspace, **kwargs)

    def test_enrollment_produces_a_verified_store(self) -> None:
        evidence = self.enroll()
        store = Path(evidence["path"])
        self.assertTrue(store.is_file())
        self.assertEqual(evidence["enrollment"], "microsoft-production")
        self.assertEqual(len(evidence["sha256"]), 64)
        self.assertGreater(evidence["size_bytes"], 0)

    def test_the_store_really_contains_the_trust_anchors(self) -> None:
        """Read back from the produced file, not from the return value."""

        evidence = self.enroll()
        variables = firmware_enrollment.parse_variables(Path(evidence["path"]))
        for name in firmware_enrollment.REQUIRED_VARIABLES:
            with self.subTest(variable=name):
                self.assertIn(name, variables)
        self.assertIn("ON", variables["SecureBootEnable"].upper())

    def test_the_distribution_template_is_not_modified(self) -> None:
        """A build that mutates the shared template would poison every later run."""

        before = lab.sha256_file(firmware_enrollment.OVMF_VARS_TEMPLATE)
        evidence = self.enroll()
        after = lab.sha256_file(firmware_enrollment.OVMF_VARS_TEMPLATE)
        self.assertEqual(before, after)
        self.assertEqual(evidence["template_sha256"], before)
        # And the enrolled store must actually differ from its template,
        # otherwise nothing was enrolled.
        self.assertNotEqual(evidence["sha256"], before)

    def test_enrollment_refuses_to_clobber_an_existing_store(self) -> None:
        self.enroll()
        with self.assertRaises(firmware_enrollment.EnrollmentError):
            self.enroll()

    def test_overwrite_permits_a_deliberate_rebuild(self) -> None:
        first = self.enroll()
        second = self.enroll(overwrite=True)
        self.assertEqual(first["canonical_name"], second["canonical_name"])
        # Enrollment embeds a timestamp, so a rebuild is expected to differ.
        # This is asserted rather than assumed so the recorded
        # reproducible=False stays honest.
        self.assertFalse(second["reproducible"])

    def test_a_silently_noop_tool_is_caught(self) -> None:
        """The central property: exit 0 is not evidence of enrollment."""

        real_run = firmware_enrollment._run

        def noop(*arguments: str) -> str:
            # Pretend the enrolling invocation succeeded without doing anything,
            # but let the verification read-back run for real.
            if "--enroll-microsoft" in arguments:
                return ""
            return real_run(*arguments)

        with mock.patch.object(firmware_enrollment, "_run", side_effect=noop):
            with self.assertRaises(firmware_enrollment.EnrollmentError) as caught:
                self.enroll()
        self.assertIn("missing required variables", str(caught.exception))

    def test_a_store_without_secure_boot_is_refused(self) -> None:
        variables = {name: "blob" for name in firmware_enrollment.REQUIRED_VARIABLES}
        variables["SecureBootEnable"] = "bool: OFF"
        with mock.patch.object(
            firmware_enrollment, "parse_variables", return_value=variables
        ):
            with self.assertRaises(firmware_enrollment.EnrollmentError) as caught:
                firmware_enrollment.verify_enrollment(Path("/nonexistent"))
        self.assertIn("Secure Boot", str(caught.exception))

    def test_a_store_left_in_custom_mode_is_refused(self) -> None:
        """Custom mode lets the guest rewrite the anchors, voiding the evidence."""

        variables = {name: "blob" for name in firmware_enrollment.REQUIRED_VARIABLES}
        variables["SecureBootEnable"] = "bool: ON"
        variables["CustomMode"] = "bool: ON"
        with mock.patch.object(
            firmware_enrollment, "parse_variables", return_value=variables
        ):
            with self.assertRaises(firmware_enrollment.EnrollmentError) as caught:
                firmware_enrollment.verify_enrollment(Path("/nonexistent"))
        self.assertIn("CustomMode", str(caught.exception))

    def test_each_required_variable_is_individually_load_bearing(self) -> None:
        """Dropping any one anchor must fail; none of them is decorative."""

        for dropped in firmware_enrollment.REQUIRED_VARIABLES:
            with self.subTest(dropped=dropped):
                variables = {
                    name: "blob"
                    for name in firmware_enrollment.REQUIRED_VARIABLES
                    if name != dropped
                }
                variables["SecureBootEnable"] = "bool: ON"
                with mock.patch.object(
                    firmware_enrollment, "parse_variables", return_value=variables
                ):
                    with self.assertRaises(firmware_enrollment.EnrollmentError):
                        firmware_enrollment.verify_enrollment(Path("/nonexistent"))

    def test_a_workspace_outside_the_scratch_root_is_refused(self) -> None:
        with self.assertRaises((lab.LabSafetyError, firmware_enrollment.EnrollmentError)):
            firmware_enrollment.enroll_microsoft_vars(Path("/etc"))

    def test_a_symlinked_destination_is_refused(self) -> None:
        target = self.workspace / "elsewhere.fd"
        target.write_bytes(b"")
        link = self.workspace / "linked.fd"
        link.symlink_to(target)
        with self.assertRaises(firmware_enrollment.EnrollmentError):
            self.enroll(name="linked.fd")

    def test_a_missing_template_is_reported_clearly(self) -> None:
        with mock.patch.object(
            firmware_enrollment, "OVMF_VARS_TEMPLATE", Path("/nonexistent/OVMF_VARS.fd")
        ):
            with self.assertRaises(firmware_enrollment.EnrollmentError) as caught:
                self.enroll()
        self.assertIn("missing", str(caught.exception))


class StaticSafetyTests(unittest.TestCase):
    """The module must not reach outside the workspace or need privilege."""

    def test_the_module_names_no_device_or_privileged_call(self) -> None:
        body = (ROOT / "firmware_enrollment.py").read_text(encoding="utf-8")
        for forbidden in ("/dev/", "losetup", "partprobe", "kpartx", "sudo", "mount("):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_the_template_is_only_ever_a_copy_source(self) -> None:
        """The template path must never be handed to the enrolling writer."""

        body = (ROOT / "firmware_enrollment.py").read_text(encoding="utf-8")
        self.assertIn("shutil.copyfile(OVMF_VARS_TEMPLATE, destination)", body)
        self.assertNotIn('"--output",\n        str(OVMF_VARS_TEMPLATE)', body)


if __name__ == "__main__":
    unittest.main()
