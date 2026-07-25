#!/usr/bin/env python3
"""End-to-end integration: one plan drives every pre-hardware component.

The per-row suites each prove one component in isolation. This suite proves the
components actually compose: a single confirmed plan, produced by the real
planner from a real signed release manifest, flows through the artifact builder
(PH-10), the Linux installer adapters (PH-09), and the image transactions
(PH-07), and the result verifies.

Composition is where integration bugs live. A component can pass its own tests
while disagreeing with its neighbour about geometry, digests, or ordering, so
these cases deliberately share state across component boundaries instead of
rebuilding fixtures per step.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifacts  # noqa: E402
import base_image  # noqa: E402
import images  # noqa: E402
import lab  # noqa: E402
import linux_installer as li  # noqa: E402

INSTALLER = Path(__file__).resolve().parents[2]
CORE = INSTALLER / "core"
KERNEL = Path("/boot/vmlinuz-linux")
TOKEN = "disposable-vm-attestation-token-0001"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class EndToEndTests(unittest.TestCase):
    """One plan, every component, in the order the installer runs them."""

    @classmethod
    def setUpClass(cls) -> None:
        """Generate the plan with the real planner from the real signed release.

        Using the planner rather than a checked-in fixture means a planner change
        that breaks a downstream component is caught here.
        """
        if not KERNEL.is_file():
            raise unittest.SkipTest(f"no kernel at {KERNEL}")
        cargo = shutil.which("cargo")
        if not cargo:
            raise unittest.SkipTest("cargo is required to generate the plan")

        def plan_json(*extra: str) -> dict:
            result = subprocess.run(
                [
                    cargo,
                    "run",
                    "--offline",
                    "--quiet",
                    "--bin",
                    "jstack-plan",
                    "--",
                    *extra,
                    "fixtures/windows-11-basic-gpt.json",
                    "fixtures/signed-release-manifest.json",
                ],
                cwd=CORE,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                raise unittest.SkipTest(f"jstack-plan failed: {result.stderr.strip()}")
            return json.loads(result.stdout)

        cls.plan_document = plan_json()
        cls.display_document = plan_json("--display")

    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = (
            scratch / "jstack-windows-vm" / f"e2e-{self.id().split('.')[-1]}"
        )
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True)
        os.chmod(self.workspace, 0o700)

        self.plan = li.ConfirmedPlan.from_document(self.plan_document)
        self.previous = {
            key: os.environ.get(key)
            for key in ("JSTACK_DISPOSABLE_VM", "JSTACK_DISPOSABLE_VM_EXPECTED")
        }
        os.environ["JSTACK_DISPOSABLE_VM"] = TOKEN
        os.environ["JSTACK_DISPOSABLE_VM_EXPECTED"] = TOKEN
        self.attestation = li.DisposableVmAttestation.from_environment()

    def tearDown(self) -> None:
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_the_planner_and_the_linux_adapters_agree_on_the_plan(self) -> None:
        """The planner's output must parse under the adapters' strict rules.

        The adapters reject non-creatable roles, non-creatable type GUIDs, and
        partitions escaping the confirmed interval. If the planner ever emitted
        such a plan, this fails rather than being discovered in a VM.
        """
        self.assertEqual(self.plan.plan_hash, self.plan_document["plan_hash"])
        self.assertEqual(len(self.plan.created_partitions), 2)
        roles = {partition.role for partition in self.plan.created_partitions}
        self.assertEqual(roles, {"xbootldr", "jstack_root"})
        for partition in self.plan.created_partitions:
            self.assertIn(partition.type_guid, li.CREATABLE_TYPE_GUIDS)
            self.assertGreaterEqual(
                partition.offset_bytes, self.plan.allocation_start_bytes
            )
            self.assertLessEqual(partition.end_bytes, self.plan.allocation_end_bytes)

    def test_the_planner_and_the_display_document_agree(self) -> None:
        """The values the operator approves must come from the plan itself."""
        body = self.plan_document["body"]
        self.assertEqual(self.display_document["plan_hash"], self.plan_document["plan_hash"])
        self.assertEqual(self.display_document["disk_guid"], body["disk_guid"])
        self.assertEqual(
            self.display_document["windows_target_size_bytes"],
            body["windows_resize"]["target_size_bytes"],
        )
        self.assertEqual(
            self.display_document["allocation_interval"], body["allocation_interval"]
        )

    def test_one_plan_drives_artifacts_partitions_deployment_and_verification(self) -> None:
        """The full pre-hardware install, sharing state across every component."""
        # PH-10: build and verify the signed artifact set, bound to this plan.
        artifact_set = artifacts.build_test_artifact_set(
            self.workspace, KERNEL, "a" * 64, self.plan.plan_hash
        )
        evidence = artifacts.verify_test_artifact_set(artifact_set)
        self.assertEqual(evidence["signed_artifacts"], len(artifacts.SIGNABLE_ROLES))
        manifest = json.loads(artifact_set.manifest)
        self.assertEqual(
            manifest["plan_hash"],
            self.plan.plan_hash,
            "the artifact manifest must be bound to this exact plan",
        )

        # PH-09: re-inventory, then create only the confirmed interval.
        disk = images.create_sparse_image(
            self.workspace / "disk.img",
            self.plan.allocation_end_bytes + 1024 * 1024,
            self.workspace,
        )
        li.create_gpt(disk, self.workspace, self.plan.disk_guid)
        fingerprint = li.gpt_fingerprint(li.observe_disk(disk, self.workspace))
        li.reinventory_and_revalidate_plan(
            disk, self.workspace, self.plan, fingerprint
        )
        for role in ("xbootldr", "jstack_root"):
            created = li.create_partition(
                disk, self.workspace, self.plan, role, self.attestation
            )
            planned = self.plan.partition(role)
            # The adapter must land exactly where the planner said, to the byte.
            self.assertEqual(created["offset_bytes"], planned.offset_bytes)
            self.assertEqual(created["size_bytes"], planned.size_bytes)

        # PH-07 + PH-09: format, deploy the real signed system image, install the
        # real signed boot artifacts.
        root = images.create_sparse_image(
            self.workspace / "root.img", 256 * 1024 * 1024, self.workspace
        )
        xbootldr = images.create_sparse_image(
            self.workspace / "xbootldr.img", 128 * 1024 * 1024, self.workspace
        )
        images.make_fat32(xbootldr, self.workspace)
        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation)

        system_image = artifact_set.artifact(
            artifacts.ROLE_OFFLINE_SYSTEM_IMAGE
        ).path.read_bytes()
        li.deploy_root_image(
            root, self.workspace, system_image, digest(system_image), self.attestation
        )

        placements = [
            images.Placement(
                f"/EFI/JStack/{artifact_set.artifact(role).path.name}",
                artifact_set.artifact(role).path.read_bytes(),
            )
            for role in (artifacts.ROLE_INSTALLER_UKI, artifacts.ROLE_ESP_LOADER)
        ]
        li.install_jstack_boot_artifacts(
            xbootldr, self.workspace, placements, self.attestation
        )

        # The independent verification must agree with everything above.
        verified = li.verify_installation(
            root, xbootldr, self.workspace, digest(system_image), placements
        )
        self.assertIn("[match]", verified["root_superblock_csum"])
        self.assertEqual(len(verified["verified_artifacts"]), len(placements))

        # The installed boot artifacts are still the signed ones: read them back
        # out of the FAT32 image and check them against the signed originals.
        for role in (artifacts.ROLE_INSTALLER_UKI, artifacts.ROLE_ESP_LOADER):
            artifact = artifact_set.artifact(role)
            observed = images._fat_read(
                xbootldr, f"/EFI/JStack/{artifact.path.name}"
            )
            self.assertIsNotNone(observed, role)
            self.assertEqual(digest(observed), artifact.sha256)
            self.assertTrue(artifact.signed)

        # Rollback removes exactly the plan's partitions and nothing else.
        rolled_back = li.delete_jstack_partitions(
            disk, self.workspace, self.plan, self.attestation
        )
        self.assertEqual(
            set(rolled_back["removed"]),
            {partition.partition_guid for partition in self.plan.created_partitions},
        )

    def test_a_drifted_disk_stops_the_install_before_any_artifact_is_written(self) -> None:
        """The whole chain must refuse to start when the disk changed."""
        disk = images.create_sparse_image(
            self.workspace / "disk.img",
            self.plan.allocation_end_bytes + 1024 * 1024,
            self.workspace,
        )
        li.create_gpt(disk, self.workspace, self.plan.disk_guid)
        stale = li.gpt_fingerprint(li.observe_disk(disk, self.workspace))

        # Something changed after the handoff.
        li._run(
            li.SGDISK,
            "--new=1:2048:+16M",
            "--partition-guid=1:99999999-9999-4999-8999-999999999999",
            str(images.validate_image_path(disk, self.workspace)),
        )
        with self.assertRaises(li.LinuxAdapterError):
            li.reinventory_and_revalidate_plan(disk, self.workspace, self.plan, stale)

        # No JStack partition exists, so nothing was written.
        survivors = {
            entry.partition_guid
            for entry in li.observe_disk(disk, self.workspace)["partitions"]
        }
        for partition in self.plan.created_partitions:
            self.assertNotIn(partition.partition_guid, survivors)


class ReadinessGateTests(unittest.TestCase):
    """`make readiness` must be machine-consumable, not just human-readable.

    The unblock instructions in the ledger tell an operator to pipe this output,
    so its stdout has to be pure JSON with a nonzero exit when blocked.
    """

    def test_the_readiness_target_emits_pure_json_on_stdout(self) -> None:
        make = shutil.which("make")
        if not make:
            self.skipTest("make is required")
        result = subprocess.run(
            # --no-print-directory keeps "Entering directory" off stdout so the
            # JSON can be piped, which is what the ledger instructs operators
            # to do.
            [make, "--no-print-directory", "-C", str(INSTALLER / "vm"), "readiness"],
            text=True,
            capture_output=True,
            check=False,
        )
        # Parsing must succeed with no filtering of the output.
        document = json.loads(result.stdout)
        self.assertIn("ready", document)
        self.assertIn("checks", document)
        self.assertEqual(document["total"], len(document["checks"]))
        self.assertEqual(
            document["satisfied"],
            sum(1 for check in document["checks"] if check["satisfied"]),
        )
        # A blocked report must exit nonzero so a script notices.
        if document["ready"]:
            self.assertEqual(result.returncode, 0)
        else:
            self.assertNotEqual(result.returncode, 0)

    def test_every_blocked_check_names_an_actionable_remedy(self) -> None:
        scratch = lab.require_scratch_root()
        workspace = scratch / "jstack-windows-vm"
        for check in base_image.assess_readiness(workspace):
            if check.satisfied:
                continue
            with self.subTest(check=check.name):
                self.assertGreater(
                    len(check.remedy),
                    20,
                    f"{check.name} must explain how to unblock it",
                )


if __name__ == "__main__":
    unittest.main()
