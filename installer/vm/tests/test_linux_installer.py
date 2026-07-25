#!/usr/bin/env python3
"""PH-09 tests: Linux RAM-installer adapters.

The adapters run against sparse regular files inside the VM workspace, so the
whole Linux install path is exercised with no block device, no mount, no loop
device, and no privilege. The suite proves the properties the ledger names:
re-inventory refuses drift, only the confirmed interval is created, formatting
and deployment are independently verified, rollback removes only plan-owned
objects, and every mutating adapter refuses without a disposable-VM attestation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import images  # noqa: E402
import lab  # noqa: E402
import linux_installer as li  # noqa: E402

CORE = Path(__file__).resolve().parents[2] / "core"
PLAN_DOCUMENT = json.loads((CORE / "generated" / "example-plan.json").read_text())

TOKEN = "disposable-vm-attestation-token-0001"
ROOT_PAYLOAD = b"jstack-offline-system-image-fixture\n" * 512
UKI = b"jstack-installer-uki-fixture\n" * 64
LOADER = b"jstack-esp-loader-fixture\n" * 64

# The full disk is far larger than the host's free space, so tests build a
# sparse file. Only the GPT header, table, and the partitions actually written
# occupy blocks.
ROOT_IMAGE_BYTES = 256 * 1024 * 1024
XBOOTLDR_IMAGE_BYTES = 128 * 1024 * 1024


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class LinuxAdapterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = (
            scratch / "jstack-windows-vm" / f"ph09-{self.id().split('.')[-1]}"
        )
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True)
        os.chmod(self.workspace, 0o700)
        self.plan = li.ConfirmedPlan.from_document(PLAN_DOCUMENT)
        self.previous_environment = {
            key: os.environ.get(key)
            for key in ("JSTACK_DISPOSABLE_VM", "JSTACK_DISPOSABLE_VM_EXPECTED")
        }
        os.environ["JSTACK_DISPOSABLE_VM"] = TOKEN
        os.environ["JSTACK_DISPOSABLE_VM_EXPECTED"] = TOKEN

    def tearDown(self) -> None:
        for key, value in self.previous_environment.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.workspace, ignore_errors=True)

    def attestation(self) -> li.DisposableVmAttestation:
        return li.DisposableVmAttestation.from_environment()

    def disk(self, name: str = "disk.img") -> Path:
        """A sparse image large enough to hold the whole confirmed layout."""
        image = images.create_sparse_image(
            self.workspace / name,
            self.plan.allocation_end_bytes + 1024 * 1024,
            self.workspace,
        )
        li.create_gpt(image, self.workspace, self.plan.disk_guid)
        return image

    def disk_with_windows(self, name: str = "disk.img") -> Path:
        """A disk that also carries the pre-existing Windows-side partitions.

        These stand in for the ESP, MSR, Windows, and recovery partitions the
        rollback path must never delete.
        """
        image = self.disk(name)
        confined = images.validate_image_path(image, self.workspace)
        # One partition before the confirmed interval, modelling Windows.
        li._run(
            li.SGDISK,
            "--new=1:2048:+64M",
            "--typecode=1:EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
            "--partition-guid=1:33333333-3333-4333-8333-333333333333",
            "--change-name=1:Windows",
            str(confined),
        )
        return image


class PlanBindingTests(LinuxAdapterTestCase):
    def test_the_plan_is_parsed_with_exact_geometry(self) -> None:
        root = self.plan.partition("jstack_root")
        self.assertEqual(root.type_guid, li.JSTACK_ROOT_TYPE_GUID)
        self.assertEqual(root.filesystem, "btrfs")
        xbootldr = self.plan.partition("xbootldr")
        self.assertEqual(xbootldr.type_guid, li.XBOOTLDR_TYPE_GUID)
        # Both live inside the confirmed interval.
        for partition in self.plan.created_partitions:
            self.assertGreaterEqual(
                partition.offset_bytes, self.plan.allocation_start_bytes
            )
            self.assertLessEqual(partition.end_bytes, self.plan.allocation_end_bytes)

    def test_a_plan_naming_a_non_creatable_role_is_refused(self) -> None:
        document = json.loads(json.dumps(PLAN_DOCUMENT))
        document["body"]["created_partitions"][0]["role"] = "esp"
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.ConfirmedPlan.from_document(document)
        self.assertIn("non-creatable role", str(caught.exception))

    def test_a_plan_naming_a_non_creatable_type_guid_is_refused(self) -> None:
        document = json.loads(json.dumps(PLAN_DOCUMENT))
        # The ESP type GUID must never be creatable by the Linux installer.
        document["body"]["created_partitions"][0]["type_guid"] = (
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        )
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.ConfirmedPlan.from_document(document)
        self.assertIn("non-creatable type GUID", str(caught.exception))

    def test_a_plan_escaping_the_confirmed_interval_is_refused(self) -> None:
        document = json.loads(json.dumps(PLAN_DOCUMENT))
        interval = document["body"]["allocation_interval"]
        # Shift the interval so the planned partitions now fall outside it.
        interval["start_bytes"] = int(interval["start_bytes"]) + 8 * 1024**3
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.ConfirmedPlan.from_document(document)
        self.assertIn("escapes the confirmed allocation", str(caught.exception))

    def test_overlapping_planned_partitions_are_refused(self) -> None:
        document = json.loads(json.dumps(PLAN_DOCUMENT))
        first, second = document["body"]["created_partitions"][:2]
        second["offset_bytes"] = int(first["offset_bytes"])
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.ConfirmedPlan.from_document(document)
        self.assertIn("overlaps", str(caught.exception))


class TargetConfinementTests(LinuxAdapterTestCase):
    def test_a_block_device_path_is_refused(self) -> None:
        for candidate in ("/dev/sda", "/dev/nvme0n1", "/dev/null"):
            with self.subTest(path=candidate):
                with self.assertRaises(Exception):
                    li.observe_disk(Path(candidate), self.workspace)

    def test_a_path_outside_the_workspace_is_refused(self) -> None:
        with self.assertRaises(Exception):
            li.observe_disk(Path("/etc/passwd"), self.workspace)

    def test_a_symlinked_image_is_refused(self) -> None:
        image = self.disk()
        link = self.workspace / "link.img"
        link.symlink_to(image)
        with self.assertRaises(Exception):
            li.observe_disk(link, self.workspace)

    def test_the_module_never_names_a_device_path(self) -> None:
        # Static guarantee: no adapter can construct a /dev path.
        source = (Path(li.__file__)).read_text()
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        # The docstring mentions /dev/... only as prose; strip the module
        # docstring before scanning.
        body = code.split('"""', 2)[-1]
        self.assertNotIn("/dev/", body)
        for forbidden in ("losetup", "mount(", "kpartx", "partprobe", "sudo"):
            self.assertNotIn(forbidden, body, f"{forbidden} must not appear")

    def test_every_mutating_adapter_refuses_without_an_attestation(self) -> None:
        os.environ.pop("JSTACK_DISPOSABLE_VM", None)
        os.environ.pop("JSTACK_DISPOSABLE_VM_EXPECTED", None)
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.DisposableVmAttestation.from_environment()
        self.assertIn("attestation is absent", str(caught.exception))

    def test_a_mismatched_attestation_is_refused(self) -> None:
        os.environ["JSTACK_DISPOSABLE_VM_EXPECTED"] = "disposable-vm-attestation-token-0002"
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.DisposableVmAttestation.from_environment()
        self.assertIn("does not match this run", str(caught.exception))


class ReinventoryTests(LinuxAdapterTestCase):
    def test_a_matching_disk_revalidates(self) -> None:
        image = self.disk_with_windows()
        observation = li.observe_disk(image, self.workspace)
        fingerprint = li.gpt_fingerprint(observation)
        evidence = li.reinventory_and_revalidate_plan(
            image, self.workspace, self.plan, fingerprint
        )
        self.assertEqual(evidence["gpt_fingerprint"], fingerprint)
        self.assertTrue(evidence["interval_unallocated"])

    def test_a_drifted_disk_is_refused_before_any_write(self) -> None:
        image = self.disk_with_windows()
        stale = li.gpt_fingerprint(li.observe_disk(image, self.workspace))

        # Something changed the disk after the Windows handoff.
        confined = images.validate_image_path(image, self.workspace)
        li._run(
            li.SGDISK,
            "--new=2:200000:+16M",
            "--partition-guid=2:99999999-9999-4999-8999-999999999999",
            str(confined),
        )
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.reinventory_and_revalidate_plan(image, self.workspace, self.plan, stale)
        self.assertIn("changed since the Windows handoff", str(caught.exception))

    def test_a_wrong_disk_guid_is_refused(self) -> None:
        image = images.create_sparse_image(
            self.workspace / "other.img",
            self.plan.allocation_end_bytes + 1024 * 1024,
            self.workspace,
        )
        li.create_gpt(image, self.workspace, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        fingerprint = li.gpt_fingerprint(li.observe_disk(image, self.workspace))
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.reinventory_and_revalidate_plan(
                image, self.workspace, self.plan, fingerprint
            )
        self.assertIn("is not plan disk", str(caught.exception))

    def test_an_occupied_confirmed_interval_is_refused(self) -> None:
        image = self.disk()
        confined = images.validate_image_path(image, self.workspace)
        # Something already occupies the interval the user approved.
        start = self.plan.allocation_start_bytes // li.SECTOR_BYTES
        li._run(
            li.SGDISK,
            f"--new=1:{start}:+32M",
            "--partition-guid=1:88888888-8888-4888-8888-888888888888",
            str(confined),
        )
        fingerprint = li.gpt_fingerprint(li.observe_disk(image, self.workspace))
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.reinventory_and_revalidate_plan(
                image, self.workspace, self.plan, fingerprint
            )
        self.assertIn("not unallocated", str(caught.exception))


class PartitionCreationTests(LinuxAdapterTestCase):
    def test_partitions_are_created_at_exactly_the_planned_geometry(self) -> None:
        image = self.disk_with_windows()
        for role in ("xbootldr", "jstack_root"):
            with self.subTest(role=role):
                planned = self.plan.partition(role)
                evidence = li.create_partition(
                    image, self.workspace, self.plan, role, self.attestation()
                )
                self.assertFalse(evidence["already_satisfied"])
                self.assertEqual(evidence["partition_guid"], planned.partition_guid)
                self.assertEqual(evidence["offset_bytes"], planned.offset_bytes)
                self.assertEqual(evidence["size_bytes"], planned.size_bytes)

        # Both exist, with the planned type GUIDs, and nothing overlaps.
        observation = li.observe_disk(image, self.workspace)
        by_guid = {entry.partition_guid: entry for entry in observation["partitions"]}
        for planned in self.plan.created_partitions:
            entry = by_guid[planned.partition_guid]
            self.assertEqual(entry.type_guid, planned.type_guid)
        ordered = sorted(observation["partitions"], key=lambda item: item.first_sector)
        for first, second in zip(ordered, ordered[1:]):
            self.assertLess(first.last_sector, second.first_sector)

    def test_creation_is_idempotent_after_a_crash(self) -> None:
        image = self.disk_with_windows()
        first = li.create_partition(
            image, self.workspace, self.plan, "jstack_root", self.attestation()
        )
        self.assertFalse(first["already_satisfied"])
        # Retrying the same action accepts the existing partition rather than
        # creating a second one or failing.
        second = li.create_partition(
            image, self.workspace, self.plan, "jstack_root", self.attestation()
        )
        self.assertTrue(second["already_satisfied"])
        observation = li.observe_disk(image, self.workspace)
        matching = [
            entry
            for entry in observation["partitions"]
            if entry.partition_guid == self.plan.partition("jstack_root").partition_guid
        ]
        self.assertEqual(len(matching), 1)

    def test_an_overlapping_existing_partition_blocks_creation(self) -> None:
        image = self.disk()
        confined = images.validate_image_path(image, self.workspace)
        planned = self.plan.partition("jstack_root")
        # Squat on the middle of the planned interval with a foreign partition.
        squat = (planned.offset_bytes + planned.size_bytes // 2) // li.SECTOR_BYTES
        li._run(
            li.SGDISK,
            f"--new=1:{squat}:+16M",
            "--partition-guid=1:77777777-7777-4777-8777-777777777777",
            str(confined),
        )
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.create_partition(
                image, self.workspace, self.plan, "jstack_root", self.attestation()
            )
        self.assertIn("overlaps the interval", str(caught.exception))

    def test_a_mismatched_existing_partition_is_refused_not_accepted(self) -> None:
        image = self.disk()
        confined = images.validate_image_path(image, self.workspace)
        planned = self.plan.partition("jstack_root")
        # Same GUID, wrong geometry: a retry must not accept this.
        li._run(
            li.SGDISK,
            f"--new=1:{planned.first_sector}:+16M",
            f"--partition-guid=1:{planned.partition_guid.upper()}",
            str(confined),
        )
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.create_partition(
                image, self.workspace, self.plan, "jstack_root", self.attestation()
            )
        self.assertIn("does not match the confirmed plan", str(caught.exception))


class RollbackTests(LinuxAdapterTestCase):
    def test_rollback_removes_only_plan_owned_partitions(self) -> None:
        image = self.disk_with_windows()
        windows_guid = "33333333-3333-4333-8333-333333333333"
        for role in ("xbootldr", "jstack_root"):
            li.create_partition(
                image, self.workspace, self.plan, role, self.attestation()
            )

        evidence = li.delete_jstack_partitions(
            image, self.workspace, self.plan, self.attestation()
        )
        self.assertEqual(
            set(evidence["removed"]),
            {partition.partition_guid for partition in self.plan.created_partitions},
        )
        # The Windows partition survived.
        self.assertIn(windows_guid, evidence["preserved"])
        observation = li.observe_disk(image, self.workspace)
        survivors = {entry.partition_guid for entry in observation["partitions"]}
        self.assertEqual(survivors, {windows_guid})

    def test_rollback_is_idempotent(self) -> None:
        image = self.disk_with_windows()
        li.create_partition(
            image, self.workspace, self.plan, "jstack_root", self.attestation()
        )
        li.delete_jstack_partitions(image, self.workspace, self.plan, self.attestation())
        # A second rollback removes nothing and still succeeds.
        again = li.delete_jstack_partitions(
            image, self.workspace, self.plan, self.attestation()
        )
        self.assertEqual(again["removed"], [])

    def test_rollback_never_touches_a_partition_the_plan_does_not_own(self) -> None:
        image = self.disk_with_windows()
        confined = images.validate_image_path(image, self.workspace)
        # An OEM recovery partition the plan knows nothing about.
        li._run(
            li.SGDISK,
            "--new=2:400000:+32M",
            "--typecode=2:DE94BBA4-06D1-4D40-A16A-BFD50179D6AC",
            "--partition-guid=2:66666666-6666-4666-8666-666666666666",
            "--change-name=2:Recovery",
            str(confined),
        )
        before = {
            entry.partition_guid
            for entry in li.observe_disk(image, self.workspace)["partitions"]
        }
        li.delete_jstack_partitions(image, self.workspace, self.plan, self.attestation())
        after = {
            entry.partition_guid
            for entry in li.observe_disk(image, self.workspace)["partitions"]
        }
        self.assertEqual(before, after, "rollback must not touch unowned partitions")


class DeploymentTests(LinuxAdapterTestCase):
    def root_image(self) -> Path:
        return images.create_sparse_image(
            self.workspace / "root.img", ROOT_IMAGE_BYTES, self.workspace
        )

    def xbootldr_image(self) -> Path:
        image = images.create_sparse_image(
            self.workspace / "xbootldr.img", XBOOTLDR_IMAGE_BYTES, self.workspace
        )
        images.make_fat32(image, self.workspace)
        return image

    def test_formatting_the_root_is_independently_verified(self) -> None:
        image = self.root_image()
        evidence = li.format_root_btrfs(
            image, self.workspace, self.plan, self.attestation()
        )
        self.assertIn("[match]", evidence["superblock_csum"])
        self.assertEqual(evidence["label"], self.plan.partition("jstack_root").name)

    def test_deployment_and_verification_agree(self) -> None:
        root = self.root_image()
        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation())
        deployed = li.deploy_root_image(
            root, self.workspace, ROOT_PAYLOAD, digest(ROOT_PAYLOAD), self.attestation()
        )
        self.assertEqual(deployed["payload_sha256"], digest(ROOT_PAYLOAD))

        xbootldr = self.xbootldr_image()
        artifacts = [
            images.Placement("/EFI/JStack/installer.uki", UKI),
            images.Placement("/EFI/JStack/loader.efi", LOADER),
        ]
        installed = li.install_jstack_boot_artifacts(
            xbootldr, self.workspace, artifacts, self.attestation()
        )
        self.assertEqual(len(installed["published"]), 2)

        verified = li.verify_installation(
            root, xbootldr, self.workspace, digest(ROOT_PAYLOAD), artifacts
        )
        self.assertIn("[match]", verified["root_superblock_csum"])
        self.assertEqual(len(verified["verified_artifacts"]), 2)

    def test_verification_fails_when_a_boot_artifact_is_tampered(self) -> None:
        root = self.root_image()
        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation())
        li.deploy_root_image(
            root, self.workspace, ROOT_PAYLOAD, digest(ROOT_PAYLOAD), self.attestation()
        )
        xbootldr = self.xbootldr_image()
        artifacts = [images.Placement("/EFI/JStack/loader.efi", LOADER)]
        li.install_jstack_boot_artifacts(
            xbootldr, self.workspace, artifacts, self.attestation()
        )

        # Claim a different payload for the same destination.
        tampered = [images.Placement("/EFI/JStack/loader.efi", LOADER + b"extra")]
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.verify_installation(
                root, xbootldr, self.workspace, digest(ROOT_PAYLOAD), tampered
            )
        self.assertIn("does not match its digest", str(caught.exception))

    def test_verification_fails_when_a_boot_artifact_is_absent(self) -> None:
        root = self.root_image()
        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation())
        xbootldr = self.xbootldr_image()
        artifacts = [images.Placement("/EFI/JStack/loader.efi", LOADER)]
        with self.assertRaises(li.LinuxAdapterError) as caught:
            li.verify_installation(
                root, xbootldr, self.workspace, digest(ROOT_PAYLOAD), artifacts
            )
        self.assertIn("is absent", str(caught.exception))

    def test_deployment_refuses_a_payload_that_does_not_match_its_digest(self) -> None:
        root = self.root_image()
        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation())
        with self.assertRaises(images.ImageTransactionError):
            li.deploy_root_image(
                root, self.workspace, ROOT_PAYLOAD, digest(b"different"), self.attestation()
            )


class EndToEndLinuxSideTests(LinuxAdapterTestCase):
    def test_the_whole_linux_side_runs_in_order_on_a_sparse_disk(self) -> None:
        """Re-inventory, create both partitions, format, deploy, install, verify."""
        disk = self.disk_with_windows()
        fingerprint = li.gpt_fingerprint(li.observe_disk(disk, self.workspace))

        li.reinventory_and_revalidate_plan(disk, self.workspace, self.plan, fingerprint)
        for role in ("xbootldr", "jstack_root"):
            li.create_partition(
                disk, self.workspace, self.plan, role, self.attestation()
            )

        # The partition contents live in their own images, exactly as the VM
        # harness will extract them.
        root = images.create_sparse_image(
            self.workspace / "root.img", ROOT_IMAGE_BYTES, self.workspace
        )
        xbootldr = images.create_sparse_image(
            self.workspace / "xbootldr.img", XBOOTLDR_IMAGE_BYTES, self.workspace
        )
        images.make_fat32(xbootldr, self.workspace)

        li.format_root_btrfs(root, self.workspace, self.plan, self.attestation())
        li.deploy_root_image(
            root, self.workspace, ROOT_PAYLOAD, digest(ROOT_PAYLOAD), self.attestation()
        )
        artifacts = [
            images.Placement("/EFI/JStack/installer.uki", UKI),
            images.Placement("/EFI/JStack/loader.efi", LOADER),
        ]
        li.install_jstack_boot_artifacts(
            xbootldr, self.workspace, artifacts, self.attestation()
        )
        verified = li.verify_installation(
            root, xbootldr, self.workspace, digest(ROOT_PAYLOAD), artifacts
        )

        self.assertEqual(len(verified["verified_artifacts"]), 2)
        # The Windows partition is untouched throughout.
        survivors = {
            entry.partition_guid
            for entry in li.observe_disk(disk, self.workspace)["partitions"]
        }
        self.assertIn("33333333-3333-4333-8333-333333333333", survivors)


if __name__ == "__main__":
    unittest.main()
