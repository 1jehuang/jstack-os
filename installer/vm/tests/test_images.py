#!/usr/bin/env python3
"""PH-07 tests: descriptor-confined FAT32 and Btrfs image transactions.

Every case operates on a sparse regular file inside the VM workspace. No test
opens a block device, mounts a filesystem, or requires privilege. The suite
covers the failure modes the ledger names: short writes, ENOSPC, crashes at
each protocol boundary, FAT32 case collisions, hard links, tampering, and
replay.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import images  # noqa: E402
import lab  # noqa: E402


FAT_IMAGE_BYTES = 128 * 1024 * 1024
BTRFS_IMAGE_BYTES = 256 * 1024 * 1024
LOADER = b"jstack-esp-loader-fixture\n" * 64
UKI = b"jstack-installer-uki-fixture\n" * 64
ROOT_IMAGE = b"jstack-offline-system-image-fixture\n" * 512


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ImageTransactionTestCase(unittest.TestCase):
    """Base fixture that builds a private workspace under the scratch root."""

    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = scratch / "jstack-windows-vm" / f"ph07-{self.id().split('.')[-1]}"
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True)
        os.chmod(self.workspace, 0o700)

    def tearDown(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def fat_image(self, name: str = "boot.img") -> Path:
        image = images.create_sparse_image(self.workspace / name, FAT_IMAGE_BYTES, self.workspace)
        images.make_fat32(image, self.workspace)
        return image

    def btrfs_image(self, name: str = "root.img") -> Path:
        image = images.create_sparse_image(
            self.workspace / name, BTRFS_IMAGE_BYTES, self.workspace
        )
        images.make_btrfs(image, self.workspace)
        return image


class PathConfinementTests(ImageTransactionTestCase):
    def test_images_are_confined_to_the_vm_workspace(self) -> None:
        image = self.fat_image()
        images.validate_image_path(image, self.workspace)

        # A path outside the scratch root is refused before any I/O.
        with self.assertRaises(Exception):
            images.validate_image_path(Path("/etc/passwd"), self.workspace)
        with self.assertRaises(Exception):
            images.validate_image_path(Path("/dev/sda"), self.workspace)

    def test_symlinked_image_paths_are_rejected(self) -> None:
        image = self.fat_image()
        link = self.workspace / "link.img"
        link.symlink_to(image)
        with self.assertRaises(Exception):
            images.validate_image_path(link, self.workspace)

    def test_hard_linked_images_are_rejected(self) -> None:
        image = self.fat_image()
        clone = self.workspace / "clone.img"
        os.link(image, clone)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.validate_image_path(clone, self.workspace)
        self.assertIn("hard-linked", str(caught.exception))

    def test_creating_an_image_never_clobbers_an_existing_file(self) -> None:
        image = self.fat_image()
        with self.assertRaises(FileExistsError):
            images.create_sparse_image(image, FAT_IMAGE_BYTES, self.workspace)

    def test_created_images_are_sparse_private_regular_files(self) -> None:
        image = images.create_sparse_image(
            self.workspace / "sparse.img", FAT_IMAGE_BYTES, self.workspace
        )
        metadata = image.stat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_size, FAT_IMAGE_BYTES)
        # Sparse: the apparent size is far larger than the allocated blocks.
        self.assertLess(metadata.st_blocks * 512, FAT_IMAGE_BYTES // 2)


class DestinationValidationTests(unittest.TestCase):
    def test_only_absolute_non_traversing_destinations_are_accepted(self) -> None:
        self.assertEqual(
            images.validate_destination("/EFI/JStack/loader.efi"),
            ("EFI", "JStack", "loader.efi"),
        )
        for bad in (
            "EFI/loader.efi",
            "/EFI/../../etc/passwd",
            "/EFI/./loader.efi/..",
            "\\EFI\\loader.efi",
            "/EFI/load\ner.efi",
            "/",
            "/EFI/" + "a" * 256,
        ):
            with self.subTest(destination=bad):
                with self.assertRaises(images.ImageTransactionError):
                    images.validate_destination(bad)

    def test_a_manifest_role_cannot_select_a_host_path(self) -> None:
        # Destinations are in-image paths. Even an absolute host path is treated
        # as an in-image path and can never escape the image file.
        components = images.validate_destination("/etc/passwd")
        self.assertEqual(components, ("etc", "passwd"))


class Fat32TransactionTests(ImageTransactionTestCase):
    def test_exact_payloads_are_published_and_verified_from_the_image(self) -> None:
        image = self.fat_image()
        placements = [
            images.Placement("/EFI/JStack/loader.efi", LOADER),
            images.Placement("/EFI/JStack/installer.uki", UKI),
        ]
        evidence = images.fat32_transaction(image, self.workspace, placements)

        self.assertEqual(evidence["filesystem"], "fat32")
        self.assertEqual(len(evidence["published"]), 2)
        for placement in placements:
            observed = images._fat_read(image, placement.destination)
            self.assertIsNotNone(observed, placement.destination)
            self.assertEqual(digest(observed), placement.digest())

        # No temporary survives a clean transaction.
        self.assertEqual(images.reconcile_fat32(image, self.workspace), [])

    def test_a_short_write_is_caught_by_read_back_verification(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        faults = images.FaultPlan(short_write_index=0)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.fat32_transaction(image, self.workspace, [placement], faults)
        self.assertIn("read-back verification failed", str(caught.exception))
        # The final name was never published.
        self.assertIsNone(images._fat_read(image, placement.destination))

    def test_silent_corruption_is_caught_by_read_back_verification(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        faults = images.FaultPlan(corrupt_index=0)
        with self.assertRaises(images.ImageTransactionError):
            images.fat32_transaction(image, self.workspace, [placement], faults)
        self.assertIsNone(images._fat_read(image, placement.destination))

    def test_enospc_fails_before_publishing_anything(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        faults = images.FaultPlan(free_space_bytes=len(LOADER) - 1)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.fat32_transaction(image, self.workspace, [placement], faults)
        self.assertIn("ENOSPC", str(caught.exception))
        self.assertIsNone(images._fat_read(image, placement.destination))

    def test_a_real_full_filesystem_reports_enospc_not_a_partial_file(self) -> None:
        image = self.fat_image()
        oversized = b"x" * (FAT_IMAGE_BYTES * 2)
        placement = images.Placement("/EFI/JStack/huge.bin", oversized)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.fat32_transaction(image, self.workspace, [placement])
        self.assertIn("ENOSPC", str(caught.exception))
        self.assertIsNone(images._fat_read(image, placement.destination))

    def test_case_collisions_are_rejected_because_fat32_folds_case(self) -> None:
        image = self.fat_image()
        images.fat32_transaction(
            image, self.workspace, [images.Placement("/EFI/JStack/LOADER.EFI", LOADER)]
        )
        # FAT32 treats these as the same name; the transaction must refuse
        # rather than silently overwrite the existing loader.
        with self.assertRaises(images.ImageTransactionError):
            images.fat32_transaction(
                image, self.workspace, [images.Placement("/EFI/JStack/LOADER.EFI", UKI)]
            )
        self.assertEqual(digest(images._fat_read(image, "/EFI/JStack/LOADER.EFI")), digest(LOADER))

    def test_an_existing_destination_is_never_silently_overwritten(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        images.fat32_transaction(image, self.workspace, [placement])
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.fat32_transaction(
                image, self.workspace, [images.Placement("/EFI/JStack/loader.efi", UKI)]
            )
        self.assertIn("already exists", str(caught.exception))
        self.assertEqual(digest(images._fat_read(image, placement.destination)), digest(LOADER))

    def test_every_crash_boundary_leaves_a_reconcilable_state(self) -> None:
        """Crash at each protocol boundary; nothing is ever half-published."""
        boundaries = [
            images.FaultPlan(fail_before_temporary=0),
            images.FaultPlan(fail_after_temporary=0),
            images.FaultPlan(fail_before_publish=0),
            images.FaultPlan(fail_after_publish=0),
            images.FaultPlan(fail_before_sync=True),
        ]
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)

        for index, faults in enumerate(boundaries):
            with self.subTest(boundary=index):
                image = self.fat_image(f"crash-{index}.img")
                with self.assertRaises(images.InjectedFault):
                    images.fat32_transaction(image, self.workspace, [placement], faults)

                published = images._fat_read(image, placement.destination)
                if published is not None:
                    # If the final name exists at all, it holds exactly the
                    # right bytes. A partially written payload is never visible.
                    self.assertEqual(digest(published), placement.digest())

                # Reconciliation removes any leftover temporary, and a retry
                # then either succeeds or reports the payload already present.
                images.reconcile_fat32(image, self.workspace)
                if images._fat_read(image, placement.destination) is None:
                    evidence = images.fat32_transaction(image, self.workspace, [placement])
                    self.assertEqual(evidence["published"][0]["sha256"], placement.digest())
                final = images._fat_read(image, placement.destination)
                self.assertEqual(digest(final), placement.digest())

    def test_a_partial_batch_never_publishes_the_later_payload(self) -> None:
        image = self.fat_image()
        first = images.Placement("/EFI/JStack/loader.efi", LOADER)
        second = images.Placement("/EFI/JStack/installer.uki", UKI)
        faults = images.FaultPlan(fail_before_temporary=1)
        with self.assertRaises(images.InjectedFault):
            images.fat32_transaction(image, self.workspace, [first, second], faults)

        self.assertIsNotNone(images._fat_read(image, first.destination))
        self.assertIsNone(images._fat_read(image, second.destination))

    def test_replay_after_a_complete_transaction_is_refused_not_duplicated(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        first = images.fat32_transaction(image, self.workspace, [placement])
        with self.assertRaises(images.ImageTransactionError):
            images.fat32_transaction(image, self.workspace, [placement])
        # The image is unchanged by the refused replay.
        second_digest = lab.sha256_file(image)
        self.assertEqual(first["image_sha256"], second_digest)

    def test_reconciliation_removes_only_temporaries(self) -> None:
        image = self.fat_image()
        placement = images.Placement("/EFI/JStack/loader.efi", LOADER)
        images.fat32_transaction(image, self.workspace, [placement])
        with self.assertRaises(images.InjectedFault):
            images.fat32_transaction(
                image,
                self.workspace,
                [images.Placement("/EFI/JStack/installer.uki", UKI)],
                images.FaultPlan(fail_after_temporary=0),
            )
        images.reconcile_fat32(image, self.workspace)
        # The previously published payload survived reconciliation.
        self.assertEqual(digest(images._fat_read(image, placement.destination)), digest(LOADER))


class BtrfsTransactionTests(ImageTransactionTestCase):
    def test_a_fresh_btrfs_image_passes_its_own_checker(self) -> None:
        image = self.btrfs_image()
        superblock = images.btrfs_superblock(image, self.workspace)
        self.assertIn("[match]", superblock["csum"])
        images.btrfs_check(image, self.workspace)

    def test_deployment_is_verified_by_reading_the_image_back(self) -> None:
        image = self.btrfs_image()
        evidence = images.deploy_btrfs_image(
            image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE)
        )
        self.assertEqual(evidence["payload_sha256"], digest(ROOT_IMAGE))
        self.assertIn("[match]", evidence["superblock_csum"])
        # The superblock still verifies after deployment, so the metadata
        # region was not damaged by the payload write.
        images.btrfs_check(image, self.workspace)

    def test_a_wrong_expected_digest_is_refused_before_any_write(self) -> None:
        image = self.btrfs_image()
        before = lab.sha256_file(image)
        with self.assertRaises(images.ImageTransactionError):
            images.deploy_btrfs_image(image, self.workspace, ROOT_IMAGE, digest(b"other"))
        self.assertEqual(lab.sha256_file(image), before)

    def test_a_short_write_is_caught_by_read_back_verification(self) -> None:
        image = self.btrfs_image()
        faults = images.FaultPlan(short_write_index=0)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.deploy_btrfs_image(
                image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE), faults
            )
        self.assertIn("read-back verification", str(caught.exception))

    def test_silent_corruption_is_caught_by_read_back_verification(self) -> None:
        image = self.btrfs_image()
        faults = images.FaultPlan(corrupt_index=0)
        with self.assertRaises(images.ImageTransactionError):
            images.deploy_btrfs_image(
                image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE), faults
            )

    def test_enospc_fails_before_writing(self) -> None:
        image = self.btrfs_image()
        before = lab.sha256_file(image)
        faults = images.FaultPlan(free_space_bytes=len(ROOT_IMAGE) - 1)
        with self.assertRaises(images.ImageTransactionError) as caught:
            images.deploy_btrfs_image(
                image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE), faults
            )
        self.assertIn("ENOSPC", str(caught.exception))
        self.assertEqual(lab.sha256_file(image), before)

    def read_payload(self, image: Path, evidence: dict) -> bytes:
        """Read the deployed payload region straight out of the image file."""
        descriptor = lab.open_regular_nofollow(image)
        try:
            return os.pread(descriptor, len(ROOT_IMAGE), evidence["payload_offset"])
        finally:
            os.close(descriptor)

    def test_every_crash_boundary_is_retryable_to_the_same_result(self) -> None:
        boundaries = [
            images.FaultPlan(fail_before_temporary=0),
            images.FaultPlan(fail_after_temporary=0),
            images.FaultPlan(fail_before_publish=0),
            images.FaultPlan(fail_after_publish=0),
        ]
        reference_image = self.btrfs_image("reference.img")
        reference = images.deploy_btrfs_image(
            reference_image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE)
        )
        reference_payload = self.read_payload(reference_image, reference)

        # mkfs.btrfs stamps a fresh random fsid into every image, so whole-image
        # digests legitimately differ between images. The invariant that matters
        # is that the deployed payload region and the superblock are identical.
        for index, faults in enumerate(boundaries):
            with self.subTest(boundary=index):
                image = self.btrfs_image(f"crash-{index}.img")
                with self.assertRaises(images.InjectedFault):
                    images.deploy_btrfs_image(
                        image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE), faults
                    )
                # Retrying the idempotent deployment reaches exactly the same
                # payload bytes as an uninterrupted deployment.
                retried = images.deploy_btrfs_image(
                    image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE)
                )
                self.assertEqual(retried["payload_sha256"], reference["payload_sha256"])
                self.assertEqual(retried["payload_offset"], reference["payload_offset"])
                self.assertEqual(self.read_payload(image, retried), reference_payload)
                self.assertIn("[match]", retried["superblock_csum"])
                images.btrfs_check(image, self.workspace)

    def test_deployment_is_idempotent_under_replay(self) -> None:
        image = self.btrfs_image()
        first = images.deploy_btrfs_image(image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE))
        second = images.deploy_btrfs_image(image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE))
        self.assertEqual(first["image_sha256"], second["image_sha256"])

    def test_tampering_after_deployment_is_detected(self) -> None:
        image = self.btrfs_image()
        evidence = images.deploy_btrfs_image(
            image, self.workspace, ROOT_IMAGE, digest(ROOT_IMAGE)
        )
        descriptor = lab.open_regular_nofollow(image, writable=True)
        try:
            os.pwrite(descriptor, b"tampered", evidence["payload_offset"])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.assertNotEqual(lab.sha256_file(image), evidence["image_sha256"])

    def test_an_undersized_image_is_refused(self) -> None:
        tiny = images.create_sparse_image(self.workspace / "tiny.img", 1024 * 1024, self.workspace)
        with self.assertRaises(images.ImageTransactionError):
            images.make_btrfs(tiny, self.workspace)


class ToolResolutionTests(unittest.TestCase):
    def test_tools_resolve_only_from_the_trusted_system_path(self) -> None:
        for tool in (images.MKFS_BTRFS, images.MCOPY, images.MDIR, images.BTRFS):
            with self.subTest(tool=tool):
                resolved = images._tool(tool)
                self.assertTrue(resolved.startswith(("/usr/bin/", "/bin/")), resolved)

    def test_an_unknown_tool_is_refused_rather_than_searched_for(self) -> None:
        with self.assertRaises(images.ImageTransactionError):
            images._tool("definitely-not-a-real-tool")

    def test_multicall_applets_keep_their_invoked_name(self) -> None:
        # mtools applets are symlinks to one binary that dispatches on argv[0].
        self.assertTrue(images._tool(images.MDIR).endswith("mdir"))
        self.assertTrue(images._tool(images.MCOPY).endswith("mcopy"))


if __name__ == "__main__":
    unittest.main()
