#!/usr/bin/env python3
"""PH-12 tests: base-image media verification and unattended answer media.

The ISO itself is not required to test the logic that governs it. These cases
build synthetic ISO-shaped files with known digests, so the verifier's accept and
reject behaviour is proven exactly, and they assert the answer file is
byte-reproducible, well-formed, and pins the exact edition and layout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import unittest
import xml.dom.minidom
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifacts  # noqa: E402
import base_image  # noqa: E402
import images  # noqa: E402
import lab  # noqa: E402


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def synthetic_iso(size_bytes: int) -> bytes:
    """A file shaped like an ISO 9660 image: CD001 at the right offset."""
    payload = bytearray(b"\0" * size_bytes)
    payload[base_image.ISO_MAGIC_OFFSET : base_image.ISO_MAGIC_OFFSET + 5] = (
        base_image.ISO_MAGIC
    )
    # Some non-zero content so the digest is not trivially all zeros.
    payload[0:16] = b"jstack-test-iso\n"
    return bytes(payload)


class BaseImageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        scratch = lab.require_scratch_root()
        self.workspace = (
            scratch / "jstack-windows-vm" / f"ph12-{self.id().split('.')[-1]}"
        )
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True)
        os.chmod(self.workspace, 0o700)
        self.records = base_image.load_media_records()

    def tearDown(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def write_media(self, name: str, payload: bytes) -> Path:
        path = images.create_sparse_image(
            self.workspace / name, len(payload), self.workspace
        )
        descriptor = lab.open_regular_nofollow(path, writable=True)
        try:
            os.pwrite(descriptor, payload, 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path


class MediaRecordTests(BaseImageTestCase):
    def test_both_declared_records_parse_completely(self) -> None:
        self.assertEqual(len(self.records), 2)
        for key, record in self.records.items():
            with self.subTest(record=key):
                self.assertEqual(len(record.sha256), 64)
                self.assertEqual(record.sha256, record.sha256.lower())
                self.assertGreater(record.size_bytes, 4 * 1024**3)
                self.assertTrue(record.filename.endswith(".iso"))
                self.assertTrue(record.source_page_url.startswith("https://"))
                self.assertTrue(record.selected_name)
                self.assertGreaterEqual(record.selected_index, 1)

    def test_the_recorded_windows_10_digest_matches_the_published_value(self) -> None:
        """The Windows 10 download page publishes English 64-bit as a6f470ca...

        This is transcribed from the Microsoft download page's own verification
        table, so a silent edit to the media record is caught here.
        """
        record = self.records["windows-10-pro-22h2-en-us"]
        self.assertEqual(
            record.sha256,
            "a6f470ca6d331eb353b815c043e327a347f594f37ff525f17764738fe812852e",
        )
        self.assertEqual(record.size_bytes, 6140975104)

    def test_the_recorded_windows_11_digest_matches_the_published_value(self) -> None:
        record = self.records["windows-11-enterprise-25h2-en-us-eval"]
        self.assertEqual(
            record.sha256,
            "a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9",
        )
        self.assertEqual(record.size_bytes, 7092807680)

    def test_a_non_media_document_is_refused(self) -> None:
        path = self.workspace / "not-media.json"
        path.write_text(json.dumps({"kind": "something-else"}))
        with self.assertRaises(base_image.BaseImageError):
            base_image.MediaRecord.load(path)


class MediaVerificationTests(BaseImageTestCase):
    def small_record(self, payload: bytes) -> base_image.MediaRecord:
        """A record describing an exact synthetic payload."""
        template = self.records["windows-10-pro-22h2-en-us"]
        return replace(
            template,
            filename="synthetic.iso",
            size_bytes=len(payload),
            sha256=digest(payload),
        )

    def test_an_exactly_matching_iso_verifies(self) -> None:
        payload = synthetic_iso(1024 * 1024)
        record = self.small_record(payload)
        self.write_media(record.filename, payload)
        evidence = base_image.verify_media(
            self.workspace / record.filename, record, self.workspace
        )
        self.assertTrue(evidence["verified"])
        self.assertTrue(evidence["iso9660"])
        self.assertEqual(evidence["sha256"], record.sha256)
        self.assertEqual(evidence["size_bytes"], record.size_bytes)

    def test_a_wrong_size_is_refused_before_hashing(self) -> None:
        payload = synthetic_iso(1024 * 1024)
        record = replace(self.small_record(payload), size_bytes=len(payload) + 1)
        self.write_media(record.filename, payload)
        with self.assertRaises(base_image.BaseImageError) as caught:
            base_image.verify_media(
                self.workspace / record.filename, record, self.workspace
            )
        self.assertIn("bytes", str(caught.exception))

    def test_a_single_flipped_byte_is_refused(self) -> None:
        payload = bytearray(synthetic_iso(1024 * 1024))
        record = self.small_record(bytes(payload))
        payload[len(payload) // 2] ^= 0xFF
        self.write_media(record.filename, bytes(payload))
        with self.assertRaises(base_image.BaseImageError) as caught:
            base_image.verify_media(
                self.workspace / record.filename, record, self.workspace
            )
        self.assertIn("SHA-256 mismatch", str(caught.exception))

    def test_a_non_iso_file_of_the_right_size_and_digest_is_still_refused(self) -> None:
        """Structure is checked, not just the digest.

        A renamed archive with a forged matching record must not pass as install
        media, so the ISO 9660 magic is verified independently.
        """
        payload = b"x" * (1024 * 1024)
        record = self.small_record(payload)
        self.write_media(record.filename, payload)
        with self.assertRaises(base_image.BaseImageError) as caught:
            base_image.verify_media(
                self.workspace / record.filename, record, self.workspace
            )
        self.assertIn("not an ISO 9660 image", str(caught.exception))

    def test_an_absent_iso_is_refused(self) -> None:
        record = self.records["windows-10-pro-22h2-en-us"]
        with self.assertRaises(Exception):
            base_image.verify_media(
                self.workspace / record.filename, record, self.workspace
            )

    def test_media_outside_the_workspace_is_refused(self) -> None:
        record = self.records["windows-10-pro-22h2-en-us"]
        for candidate in (Path("/etc/passwd"), Path("/dev/sda")):
            with self.subTest(path=candidate):
                with self.assertRaises(Exception):
                    base_image.verify_media(candidate, record, self.workspace)

    def test_symlinked_and_hard_linked_media_are_refused(self) -> None:
        payload = synthetic_iso(1024 * 1024)
        record = self.small_record(payload)
        real = self.write_media(record.filename, payload)

        link = self.workspace / "link.iso"
        link.symlink_to(real)
        with self.assertRaises(Exception):
            base_image.verify_media(link, record, self.workspace)

        clone = self.workspace / "clone.iso"
        os.link(real, clone)
        with self.assertRaises(base_image.BaseImageError) as caught:
            base_image.verify_media(clone, record, self.workspace)
        self.assertIn("hard-linked", str(caught.exception))


class AutounattendTests(BaseImageTestCase):
    def record(self) -> base_image.MediaRecord:
        return self.records["windows-11-enterprise-25h2-en-us-eval"]

    def test_the_answer_file_is_well_formed_xml(self) -> None:
        payload = base_image.build_autounattend(self.record(), 64 * 1024**3)
        # Raises on malformed XML.
        document = xml.dom.minidom.parseString(payload)
        self.assertEqual(document.documentElement.tagName, "unattend")

    def test_the_answer_file_is_byte_reproducible(self) -> None:
        first = base_image.build_autounattend(self.record(), 64 * 1024**3)
        second = base_image.build_autounattend(self.record(), 64 * 1024**3)
        self.assertEqual(first, second)
        self.assertNotIn(b"\r", first, "the answer file must use LF endings")

    def test_the_answer_file_pins_the_exact_edition(self) -> None:
        record = self.record()
        payload = base_image.build_autounattend(record, 64 * 1024**3).decode()
        self.assertIn(f"<Value>{record.selected_name}</Value>", payload)
        self.assertIn("<Key>/IMAGE/NAME</Key>", payload)
        self.assertIn(f"<UILanguage>{record.language}</UILanguage>", payload)

    def test_the_answer_file_declares_the_exact_uefi_gpt_layout(self) -> None:
        """ESP, MSR, then one extended Windows partition, and no recovery.

        The installer's planner expects exactly this layout, and a base image
        without a recovery partition makes every later partition change
        attributable to the installer itself.
        """
        payload = base_image.build_autounattend(self.record(), 64 * 1024**3).decode()
        self.assertIn("<Type>EFI</Type>", payload)
        self.assertIn("<Type>MSR</Type>", payload)
        self.assertIn("<Type>Primary</Type>", payload)
        self.assertIn("<Extend>true</Extend>", payload)
        self.assertIn("<Format>FAT32</Format>", payload)
        self.assertIn("<Format>NTFS</Format>", payload)
        self.assertIn("<Letter>C</Letter>", payload)
        # Exactly three partitions are created.
        self.assertEqual(payload.count("<CreatePartition "), 3)
        # No recovery partition is created.
        self.assertNotIn("Recovery", payload)

    def test_a_different_record_yields_a_different_answer_file(self) -> None:
        first = base_image.build_autounattend(
            self.records["windows-10-pro-22h2-en-us"], 64 * 1024**3
        )
        second = base_image.build_autounattend(self.record(), 64 * 1024**3)
        self.assertNotEqual(digest(first), digest(second))

    def test_an_undersized_base_disk_is_refused(self) -> None:
        with self.assertRaises(base_image.BaseImageError):
            base_image.build_autounattend(self.record(), 8 * 1024**3)

    def test_the_answer_file_asks_the_guest_to_power_off(self) -> None:
        """The build's only success signal is a guest-initiated shutdown.

        Regression coverage for a real defect: the answer file autologged on and
        left the guest sitting at the desktop, so a *successful* install was
        indistinguishable from a wedged one and could only ever end in the
        build's timeout. An observed run held a byte-identical disk for 25
        minutes after the install was complete.
        """

        answer = base_image.build_autounattend(self.record(), 64 * 1024**3).decode()
        self.assertIn("<FirstLogonCommands>", answer)
        self.assertIn("shutdown /s /t 0 /f", answer)

    def test_the_shutdown_is_not_in_a_pass_it_would_abort(self) -> None:
        """A shutdown during specialize would abort the pass running it."""

        answer = base_image.build_autounattend(self.record(), 64 * 1024**3).decode()
        oobe_at = answer.index('<settings pass="oobeSystem">')
        self.assertGreater(
            answer.index("shutdown /s /t 0 /f"),
            oobe_at,
            "the shutdown must run in oobeSystem, after specialize has finished",
        )

    def test_the_shutdown_is_the_last_ordered_command(self) -> None:
        """Anything ordered after a shutdown would never run."""

        answer = base_image.build_autounattend(self.record(), 64 * 1024**3).decode()
        block = answer[
            answer.index("<FirstLogonCommands>") : answer.index("</FirstLogonCommands>")
        ]
        orders = re.findall(r"<Order>(\d+)</Order>", block)
        commands = re.findall(r"<CommandLine>([^<]+)</CommandLine>", block)
        self.assertEqual(len(orders), len(commands))
        latest = commands[orders.index(max(orders, key=int))]
        self.assertIn("shutdown", latest)

    def test_the_answer_media_carries_the_verified_answer_file(self) -> None:
        record = self.record()
        evidence = base_image.build_answer_media(self.workspace, record, 64 * 1024**3)
        expected = digest(base_image.build_autounattend(record, 64 * 1024**3))
        self.assertEqual(evidence["autounattend_sha256"], expected)

        # The bytes really are in the FAT32 image, at the root where Windows
        # setup looks for them.
        observed = images._fat_read(Path(evidence["image"]), "/Autounattend.xml")
        self.assertIsNotNone(observed)
        self.assertEqual(digest(observed), expected)

    def test_the_answer_media_is_reproducible_for_the_same_record(self) -> None:
        record = self.record()
        first = base_image.build_answer_media(
            self.workspace, record, 64 * 1024**3, name="a.img"
        )
        second = base_image.build_answer_media(
            self.workspace, record, 64 * 1024**3, name="b.img"
        )
        self.assertEqual(first["autounattend_sha256"], second["autounattend_sha256"])
        # FAT32 embeds a random volume serial, so image digests may differ; the
        # payload identity is what must be stable.
        self.assertEqual(first["autounattend_bytes"], second["autounattend_bytes"])

    def test_both_supported_records_can_be_built_into_one_workspace(self) -> None:
        """Regression: a fixed answer.img made the second profile unbuildable.

        Both supported profiles are prepared in the same lab workspace, so a
        shared default filename collided with the no-clobber rule. The worse
        outcome it invited is silent: an image built for one edition being used
        to install the other. Names are now derived from the record id.
        """

        built = {}
        for key, record in sorted(self.records.items()):
            evidence = base_image.build_answer_media(self.workspace, record, 64 * 1024**3)
            built[key] = evidence

        paths = [evidence["image"] for evidence in built.values()]
        self.assertEqual(len(set(paths)), len(paths), "answer media must not share a path")
        for evidence in built.values():
            self.assertTrue(Path(evidence["image"]).is_file())

        # The two profiles pin different editions, so identical answer payloads
        # would mean the record is not actually reaching the answer file.
        digests = {evidence["autounattend_sha256"] for evidence in built.values()}
        self.assertEqual(len(digests), len(built), "each record needs its own answer file")

    def test_the_answer_media_name_is_derived_from_the_record(self) -> None:
        for record in self.records.values():
            with self.subTest(record=record.record_id):
                self.assertIn(record.record_id, base_image.answer_media_name(record))

    def test_rebuilding_the_same_record_refuses_to_clobber(self) -> None:
        """The no-clobber rule must still hold now that names are derived."""

        record = self.record()
        base_image.build_answer_media(self.workspace, record, 64 * 1024**3)
        with self.assertRaises(FileExistsError):
            base_image.build_answer_media(self.workspace, record, 64 * 1024**3)


class ReadinessTests(BaseImageTestCase):
    def test_readiness_reports_every_precondition_with_a_remedy(self) -> None:
        checks = base_image.assess_readiness(self.workspace)
        self.assertGreaterEqual(len(checks), 10)
        names = {check.name for check in checks}
        # Tooling, firmware, media, and host envelope are all covered.
        self.assertIn("tool:qemu-system-x86_64", names)
        self.assertIn("firmware:ovmf-secure-code", names)
        self.assertIn("media:windows-10-pro-22h2-en-us", names)
        self.assertIn("media:windows-11-enterprise-25h2-en-us-eval", names)
        self.assertIn("host:memory", names)
        self.assertIn("host:disk", names)
        # Every check, satisfied or not, carries an actionable remedy.
        for check in checks:
            with self.subTest(check=check.name):
                self.assertTrue(check.remedy, f"{check.name} has no remedy")
                self.assertTrue(check.detail, f"{check.name} has no detail")

    def test_absent_media_is_reported_as_unsatisfied_with_the_download_page(self) -> None:
        checks = {check.name: check for check in base_image.assess_readiness(self.workspace)}
        media = checks["media:windows-10-pro-22h2-en-us"]
        self.assertFalse(media.satisfied, "a fresh workspace has no media")
        self.assertIn("https://", media.remedy)
        self.assertIn("manual", media.remedy)

    def test_present_media_of_the_right_size_is_reported_as_satisfied(self) -> None:
        record = self.records["windows-10-pro-22h2-en-us"]
        # A sparse file of exactly the declared size: readiness checks presence
        # and size, and `verify-media` is what checks the digest.
        images.create_sparse_image(
            self.workspace / record.filename, record.size_bytes, self.workspace
        )
        checks = {check.name: check for check in base_image.assess_readiness(self.workspace)}
        self.assertTrue(checks["media:windows-10-pro-22h2-en-us"].satisfied)

    def test_wrong_sized_media_is_reported_as_unsatisfied(self) -> None:
        record = self.records["windows-10-pro-22h2-en-us"]
        images.create_sparse_image(
            self.workspace / record.filename, 1024, self.workspace
        )
        checks = {check.name: check for check in base_image.assess_readiness(self.workspace)}
        media = checks["media:windows-10-pro-22h2-en-us"]
        self.assertFalse(media.satisfied)
        self.assertIn(str(record.size_bytes), media.detail)


if __name__ == "__main__":
    unittest.main()


class HostIdentityTests(BaseImageTestCase):
    """PH-11 host-scoped inputs must be resolvable without a VM launch.

    `lab.py init` refuses to run below the 6 GiB VM memory gate, which is right
    for launching a VM but wrong for reading digests off disk. These cases pin
    the separation so a future change cannot re-couple them.
    """

    def test_every_host_scoped_input_resolves_on_this_machine(self) -> None:
        identities = base_image.collect_host_identities()
        self.assertEqual(set(identities), set(base_image.HOST_SCOPED_INPUTS))
        for key, value in identities.items():
            with self.subTest(input=key):
                self.assertTrue(value["resolved"], f"{key}: {value.get('reason')}")
                self.assertEqual(len(value["sha256"]), 64)
                self.assertGreater(value["size_bytes"], 0)
                self.assertTrue(Path(value["path"]).is_file())

    def test_digests_match_an_independent_hash_of_the_same_file(self) -> None:
        """The collector must not be its own oracle."""
        for key, value in base_image.collect_host_identities().items():
            if not value["resolved"]:
                continue
            with self.subTest(input=key):
                expected = digest(Path(value["path"]).read_bytes())
                self.assertEqual(value["sha256"], expected)

    def test_collection_does_not_require_the_vm_memory_envelope(self) -> None:
        """This is the whole point: it works on a busy host.

        `lab.host_evidence` raises below the memory gate. Collection must not,
        because a read-only digest cannot exhaust memory.
        """
        source = Path(base_image.__file__).read_text()
        body = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        function = body.split("def collect_host_identities(")[1].split("\ndef ")[0]
        for coupled in (
            "MIN_AVAILABLE_MEMORY_BYTES",
            "available_memory_bytes",
            "host_evidence",
            "/dev/kvm",
        ):
            self.assertNotIn(
                coupled,
                function,
                f"collection must not depend on {coupled}",
            )

    def test_host_scoped_inputs_are_exactly_the_profiles_host_scope_entries(self) -> None:
        """The collector's coverage is derived from the profiles, not guessed."""
        scopes = base_image.profile_input_scopes()
        self.assertEqual(len(scopes), 2)
        for profile, entries in scopes.items():
            with self.subTest(profile=profile):
                declared = {
                    key for key, scope in entries.items() if scope == "host-acquisition"
                }
                self.assertEqual(
                    declared,
                    set(base_image.HOST_SCOPED_INPUTS),
                    "the collector must cover exactly the host-acquisition inputs",
                )

    def test_the_remaining_inputs_are_base_image_or_release_scoped(self) -> None:
        """Everything the collector cannot resolve has a named reason."""
        scopes = base_image.profile_input_scopes()
        for profile, entries in scopes.items():
            for key, scope in entries.items():
                if key in base_image.HOST_SCOPED_INPUTS:
                    continue
                with self.subTest(profile=profile, input=key):
                    self.assertIn(
                        scope,
                        {"base-image-acquisition", "release-build"},
                        f"{key} is neither host-scoped nor a known blocked scope",
                    )

    def test_a_set_id_executable_would_be_refused(self) -> None:
        """The collector applies the same set-id refusal as the rest of the harness."""
        source = Path(base_image.__file__).read_text()
        function = source.split("def collect_host_identities(")[1].split("\ndef ")[0]
        self.assertIn("S_ISUID", function)
        self.assertIn("set-id command is forbidden", function)


class ReleaseIdentityTests(BaseImageTestCase):
    """PH-11 release-build inputs are digests of things this repo builds.

    None of them needs Windows media, so all four must be resolvable now.
    """

    def test_the_graph_and_manifest_digests_resolve_from_the_repository(self) -> None:
        identities = base_image.collect_release_identities()
        for key in ("installer-graph-sha256", "release-manifest-sha256"):
            with self.subTest(input=key):
                value = identities[key]
                self.assertTrue(value["resolved"], value.get("reason"))
                self.assertEqual(len(value["sha256"]), 64)
                # Independent hash of the same file.
                self.assertEqual(
                    value["sha256"], digest(Path(value["path"]).read_bytes())
                )

    def test_the_graph_digest_matches_the_value_the_release_manifest_pins(self) -> None:
        """A drift here would mean the signed release names a different graph."""
        identities = base_image.collect_release_identities()
        graph_digest = identities["installer-graph-sha256"]["sha256"]
        manifest = json.loads(base_image.RELEASE_MANIFEST.read_text())
        self.assertEqual(
            graph_digest,
            manifest["signed"]["state_model_sha256"],
            "the signed release must pin exactly this state graph",
        )

    def test_the_boot_artifact_digest_is_accepted_only_as_a_real_sha256(self) -> None:
        identities = base_image.collect_release_identities(
            boot_artifact_manifest_sha256="c" * 64
        )
        self.assertTrue(identities["boot-artifacts-sha256"]["resolved"])
        self.assertEqual(identities["boot-artifacts-sha256"]["sha256"], "c" * 64)

        with self.assertRaises(base_image.BaseImageError):
            base_image.collect_release_identities(boot_artifact_manifest_sha256="short")

    def test_an_absent_boot_artifact_digest_reports_how_to_produce_it(self) -> None:
        identities = base_image.collect_release_identities()
        value = identities["boot-artifacts-sha256"]
        self.assertFalse(value["resolved"])
        self.assertIn("build_test_artifact_set", value["reason"])

    def test_a_missing_installer_binary_reports_the_build_command(self) -> None:
        identities = base_image.collect_release_identities(
            installer_binary=self.workspace / "does-not-exist"
        )
        value = identities["installer-sha256"]
        self.assertFalse(value["resolved"])
        self.assertIn("cargo build", value["reason"])

    def test_all_four_release_inputs_resolve_with_a_real_artifact_manifest(self) -> None:
        """The full release-scope set, using a genuinely built manifest."""
        kernel = Path("/boot/vmlinuz-linux")
        if not kernel.is_file():
            self.skipTest("no kernel available")
        artifact_set = artifacts.build_test_artifact_set(
            self.workspace, kernel, "a" * 64, "b" * 64
        )
        installer = (
            base_image.INSTALLER_ROOT / "controller" / "target" / "debug" / "jstack-installer"
        )
        if not installer.is_file():
            self.skipTest("installer binary is not built")

        identities = base_image.collect_release_identities(
            installer_binary=installer,
            boot_artifact_manifest_sha256=artifact_set.manifest_sha256,
        )
        unresolved = [key for key, value in identities.items() if not value["resolved"]]
        self.assertEqual(unresolved, [], "every release input must resolve")
        self.assertEqual(set(identities), set(base_image.RELEASE_SCOPED_INPUTS))

    def test_release_scoped_inputs_are_exactly_the_profiles_release_entries(self) -> None:
        """Coverage is derived from the profiles, not hardcoded independently."""
        for profile, entries in base_image.profile_input_scopes().items():
            with self.subTest(profile=profile):
                declared = {
                    key for key, scope in entries.items() if scope == "release-build"
                }
                self.assertEqual(declared, set(base_image.RELEASE_SCOPED_INPUTS))

    def test_only_base_image_inputs_remain_unresolvable(self) -> None:
        """After host and release scopes, the only gap is the base image itself.

        This is the precise statement of what the missing ISOs still block.
        """
        covered = set(base_image.HOST_SCOPED_INPUTS) | set(
            base_image.RELEASE_SCOPED_INPUTS
        )
        for profile, entries in base_image.profile_input_scopes().items():
            remaining = {key for key in entries if key not in covered}
            with self.subTest(profile=profile):
                self.assertTrue(remaining, "something must still be blocked")
                for key in remaining:
                    self.assertEqual(
                        entries[key],
                        "base-image-acquisition",
                        f"{key} should be base-image scoped",
                    )
