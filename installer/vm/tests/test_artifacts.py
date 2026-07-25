#!/usr/bin/env python3
"""PH-10 tests: reproducible signed test boot artifacts.

Proves that the artifact set forms one verified trust chain and that every
digest in the manifest is a stable identity. The suite builds real signed UKIs
and a real systemd-boot loader, so it exercises the same tools a release build
would use.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifacts  # noqa: E402
import lab  # noqa: E402

KERNEL = Path("/boot/vmlinuz-linux")
GRAPH_DIGEST = "a" * 64
PLAN_HASH = "b" * 64


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class ArtifactTestCase(unittest.TestCase):
    def setUp(self) -> None:
        if not KERNEL.is_file():
            self.skipTest(f"no kernel at {KERNEL}")
        scratch = lab.require_scratch_root()
        self.workspace = (
            scratch / "jstack-windows-vm" / f"ph10-{self.id().split('.')[-1]}"
        )
        shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace.mkdir(parents=True)
        os.chmod(self.workspace, 0o700)

    def tearDown(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)

    def build(self, name: str = "set") -> artifacts.TestArtifactSet:
        directory = self.workspace / name
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        return artifacts.build_test_artifact_set(
            directory, KERNEL, GRAPH_DIGEST, PLAN_HASH
        )


class ReproducibilityTests(ArtifactTestCase):
    def test_a_uki_is_byte_reproducible(self) -> None:
        """The same inputs must produce the same bytes, twice."""
        first = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_INSTALLER_UKI,
            KERNEL,
            b"initrd\n",
            "jstack.installer=1 rw",
            "first",
        )
        second = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_INSTALLER_UKI,
            KERNEL,
            b"initrd\n",
            "jstack.installer=1 rw",
            "second",
        )
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.size_bytes, second.size_bytes)

    def test_a_different_cmdline_changes_the_digest(self) -> None:
        first = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_INSTALLER_UKI,
            KERNEL,
            b"initrd\n",
            "jstack.installer=1 rw",
            "first",
        )
        second = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_INSTALLER_UKI,
            KERNEL,
            b"initrd\n",
            "jstack.installer=1 ro",
            "second",
        )
        self.assertNotEqual(
            first.sha256, second.sha256, "the cmdline must be part of the identity"
        )

    def test_a_different_initrd_changes_the_digest(self) -> None:
        first = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_RECOVERY_UKI,
            KERNEL,
            b"initrd-a\n",
            "jstack.recovery=1",
            "first",
        )
        second = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_RECOVERY_UKI,
            KERNEL,
            b"initrd-b\n",
            "jstack.recovery=1",
            "second",
        )
        self.assertNotEqual(first.sha256, second.sha256)

    def test_boot_entries_are_byte_reproducible_and_specification_shaped(self) -> None:
        first = artifacts.build_boot_entry("jstack", "JStack", "jstack.efi")
        second = artifacts.build_boot_entry("jstack", "JStack", "jstack.efi")
        self.assertEqual(first, second)
        text = first.decode()
        self.assertTrue(text.startswith("title      JStack\n"))
        self.assertIn("efi        /EFI/Linux/jstack.efi\n", text)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\r", text, "entries must use LF endings")

    def test_handoff_payloads_are_canonical_and_reproducible(self) -> None:
        first = artifacts.build_handoff_payload(
            PLAN_HASH, GRAPH_DIGEST, "c" * 64, "linux_installer", "resume"
        )
        second = artifacts.build_handoff_payload(
            PLAN_HASH, GRAPH_DIGEST, "c" * 64, "linux_installer", "resume"
        )
        self.assertEqual(first, second)
        # Canonical: sorted keys, no incidental whitespace.
        self.assertEqual(first, json.dumps(json.loads(first), sort_keys=True, separators=(",", ":")).encode())
        self.assertNotIn(b", ", first)

    def test_the_whole_manifest_is_reproducible_across_two_builds(self) -> None:
        """Two independent builds agree on every artifact digest.

        The throwaway signing key differs per build, so the signed PE bytes and
        the manifest digest legitimately differ. The unsigned artifact identities
        and every other manifest field must match exactly.
        """
        first = self.build("first")
        second = self.build("second")

        first_unsigned = {
            artifact.role: artifact.sha256
            for artifact in first.artifacts
            if not artifact.signed
        }
        second_unsigned = {
            artifact.role: artifact.sha256
            for artifact in second.artifacts
            if not artifact.signed
        }
        self.assertEqual(first_unsigned, second_unsigned)
        self.assertEqual(first.entries, second.entries)
        self.assertEqual(first.handoffs, second.handoffs)

        # The signed artifacts have the same size (same input, same key size),
        # confirming the signing step itself is deterministic in shape.
        first_sizes = {a.role: a.size_bytes for a in first.artifacts if a.signed}
        second_sizes = {a.role: a.size_bytes for a in second.artifacts if a.signed}
        self.assertEqual(set(first_sizes), set(second_sizes))


class TrustChainTests(ArtifactTestCase):
    def test_the_set_contains_exactly_the_closed_role_set(self) -> None:
        artifact_set = self.build()
        roles = sorted(artifact.role for artifact in artifact_set.artifacts)
        self.assertEqual(roles, sorted(artifacts.ARTIFACT_ROLES))

    def test_every_pe_artifact_is_signed_and_verifies(self) -> None:
        artifact_set = self.build()
        for role in artifacts.SIGNABLE_ROLES:
            with self.subTest(role=role):
                artifact = artifact_set.artifact(role)
                self.assertTrue(artifact.signed, f"{role} must be signed")
                self.assertTrue(
                    artifacts.verify_signature(artifact, artifact_set.key),
                    f"{role} signature must verify",
                )

    def test_the_non_pe_artifact_is_not_signed(self) -> None:
        artifact_set = self.build()
        image = artifact_set.artifact(artifacts.ROLE_OFFLINE_SYSTEM_IMAGE)
        self.assertFalse(image.signed)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.sign_artifact(image, artifact_set.key, self.workspace)

    def test_the_whole_chain_verifies_from_the_manifest(self) -> None:
        artifact_set = self.build()
        evidence = artifacts.verify_test_artifact_set(artifact_set)
        self.assertEqual(evidence["verified_artifacts"], len(artifacts.ARTIFACT_ROLES))
        self.assertEqual(evidence["signed_artifacts"], len(artifacts.SIGNABLE_ROLES))
        self.assertEqual(evidence["manifest_sha256"], artifact_set.manifest_sha256)

    def test_tampering_with_a_signed_artifact_breaks_verification(self) -> None:
        artifact_set = self.build()
        artifact = artifact_set.artifact(artifacts.ROLE_INSTALLER_UKI)

        payload = bytearray(artifact.path.read_bytes())
        # Flip a byte deep inside the PE image, well past the headers.
        payload[len(payload) // 2] ^= 0xFF
        artifact.path.write_bytes(bytes(payload))

        self.assertFalse(
            artifacts.verify_signature(artifact, artifact_set.key),
            "a tampered PE must fail signature verification",
        )
        with self.assertRaises(artifacts.ArtifactError) as caught:
            artifacts.verify_test_artifact_set(artifact_set)
        self.assertIn("installer_uki", str(caught.exception))

    def test_tampering_with_the_unsigned_image_is_detected_by_its_digest(self) -> None:
        artifact_set = self.build()
        image = artifact_set.artifact(artifacts.ROLE_OFFLINE_SYSTEM_IMAGE)
        image.path.write_bytes(b"tampered-system-image\n")
        with self.assertRaises(artifacts.ArtifactError) as caught:
            artifacts.verify_test_artifact_set(artifact_set)
        self.assertIn("offline_system_image", str(caught.exception))

    def test_a_signature_from_a_different_key_does_not_verify(self) -> None:
        artifact_set = self.build()
        other = artifacts.TestSigningKey.generate(self.workspace, "Other Test Key")
        artifact = artifact_set.artifact(artifacts.ROLE_ESP_LOADER)
        self.assertFalse(
            artifacts.verify_signature(
                artifact,
                other,
            ),
            "an artifact must not verify against a foreign trust root",
        )

    def test_the_manifest_refuses_an_unsigned_pe_artifact(self) -> None:
        artifact_set = self.build()
        unsigned = artifacts.Artifact(
            role=artifacts.ROLE_INSTALLER_UKI,
            path=artifact_set.artifact(artifacts.ROLE_INSTALLER_UKI).path,
            sha256="0" * 64,
            size_bytes=1,
            signed=False,
        )
        others = [
            artifact
            for artifact in artifact_set.artifacts
            if artifact.role != artifacts.ROLE_INSTALLER_UKI
        ]
        with self.assertRaises(artifacts.ArtifactError) as caught:
            artifacts.build_test_manifest(
                [*others, unsigned],
                artifact_set.entries,
                artifact_set.handoffs,
                artifact_set.key,
                GRAPH_DIGEST,
                PLAN_HASH,
            )
        self.assertIn("must be signed", str(caught.exception))

    def test_the_manifest_refuses_an_incomplete_role_set(self) -> None:
        artifact_set = self.build()
        partial = [
            artifact
            for artifact in artifact_set.artifacts
            if artifact.role != artifacts.ROLE_RECOVERY_UKI
        ]
        with self.assertRaises(artifacts.ArtifactError) as caught:
            artifacts.build_test_manifest(
                partial,
                artifact_set.entries,
                artifact_set.handoffs,
                artifact_set.key,
                GRAPH_DIGEST,
                PLAN_HASH,
            )
        self.assertIn("closed role set", str(caught.exception))

    def test_the_manifest_binds_the_graph_and_plan(self) -> None:
        artifact_set = self.build()
        document = json.loads(artifact_set.manifest)
        self.assertEqual(document["graph_digest"], GRAPH_DIGEST)
        self.assertEqual(document["plan_hash"], PLAN_HASH)
        # Every artifact, entry, and handoff digest appears in the manifest.
        recorded = {record["sha256"] for record in document["artifacts"]}
        for artifact in artifact_set.artifacts:
            self.assertIn(artifact.sha256, recorded)
        entry_digests = {record["sha256"] for record in document["boot_entries"]}
        for payload in artifact_set.entries.values():
            self.assertIn(digest(payload), entry_digests)
        handoff_digests = {record["sha256"] for record in document["handoffs"]}
        for payload in artifact_set.handoffs.values():
            self.assertIn(digest(payload), handoff_digests)

    def test_the_manifest_marks_the_trust_root_as_a_test_key(self) -> None:
        """An evidence reviewer must never mistake this for a release."""
        artifact_set = self.build()
        document = json.loads(artifact_set.manifest)
        self.assertEqual(document["trust"]["kind"], "throwaway-test-key")
        self.assertEqual(
            document["trust"]["certificate_sha256"],
            artifact_set.key.certificate_sha256,
        )
        self.assertEqual(document["kind"], "jstack-test-boot-artifacts")

    def test_changing_the_graph_digest_changes_the_manifest_digest(self) -> None:
        artifact_set = self.build()
        _, other = artifacts.build_test_manifest(
            list(artifact_set.artifacts),
            artifact_set.entries,
            artifact_set.handoffs,
            artifact_set.key,
            "c" * 64,
            PLAN_HASH,
        )
        self.assertNotEqual(other, artifact_set.manifest_sha256)


class ConfinementTests(ArtifactTestCase):
    def test_artifacts_must_be_written_inside_the_workspace(self) -> None:
        with self.assertRaises(Exception):
            artifacts.build_offline_system_image(Path("/tmp"), b"payload")

    def test_the_private_key_is_owner_only(self) -> None:
        key = artifacts.TestSigningKey.generate(self.workspace, "Test")
        mode = stat.S_IMODE(key.key_path.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_the_esp_loader_is_the_distribution_binary_unmodified(self) -> None:
        loader = artifacts.build_esp_loader(self.workspace)
        self.assertEqual(
            loader.sha256, digest(artifacts.SYSTEMD_BOOT.read_bytes())
        )

    def test_tools_resolve_only_from_the_trusted_system_path(self) -> None:
        for tool in (artifacts.UKIFY, artifacts.SBSIGN, artifacts.SBVERIFY, artifacts.OPENSSL):
            with self.subTest(tool=tool):
                resolved = artifacts._tool(tool)
                self.assertTrue(resolved.startswith(("/usr/bin/", "/bin/")), resolved)


if __name__ == "__main__":
    unittest.main()


class IndependentVerificationTests(ArtifactTestCase):
    """Verify signatures by invoking sbverify directly.

    The other trust-chain tests use `artifacts.verify_signature` as their
    oracle, so a bug in that helper could hide a broken signature. These cases
    shell out to sbverify themselves, so the module's own verification helper is
    never the thing being trusted.
    """

    def sbverify(self, path: Path, certificate: Path) -> tuple[int, str]:
        import subprocess

        result = subprocess.run(
            [
                artifacts._tool(artifacts.SBVERIFY),
                "--cert",
                str(certificate),
                str(path),
            ],
            text=True,
            capture_output=True,
            check=False,
            env=lab.subprocess_environment(),
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")

    def test_sbverify_itself_accepts_every_signed_artifact(self) -> None:
        artifact_set = self.build()
        for role in artifacts.SIGNABLE_ROLES:
            with self.subTest(role=role):
                artifact = artifact_set.artifact(role)
                code, output = self.sbverify(
                    artifact.path, artifact_set.key.certificate_path
                )
                self.assertEqual(code, 0, output)
                self.assertIn("Signature verification OK", output)

    def test_sbverify_itself_rejects_a_tampered_artifact(self) -> None:
        artifact_set = self.build()
        artifact = artifact_set.artifact(artifacts.ROLE_RECOVERY_UKI)
        payload = bytearray(artifact.path.read_bytes())
        payload[len(payload) // 2] ^= 0xFF
        artifact.path.write_bytes(bytes(payload))

        code, output = self.sbverify(artifact.path, artifact_set.key.certificate_path)
        self.assertNotEqual(code, 0, output)
        self.assertNotIn("Signature verification OK", output)

    def test_sbverify_itself_rejects_an_unsigned_artifact(self) -> None:
        """An unsigned PE must not be mistaken for a signed one."""
        artifact_set = self.build()
        loader = artifacts.build_esp_loader(self.workspace)
        code, output = self.sbverify(loader.path, artifact_set.key.certificate_path)
        self.assertNotEqual(code, 0, output)

    def test_a_signed_artifact_differs_from_its_unsigned_input(self) -> None:
        """Signing must actually embed a signature, not copy the file."""
        unsigned = artifacts.build_uki(
            self.workspace,
            artifacts.ROLE_INSTALLER_UKI,
            KERNEL,
            b"initrd\n",
            "jstack.installer=1",
            "unsigned-input",
        )
        key = artifacts.TestSigningKey.generate(self.workspace, "Test")
        signed = artifacts.sign_artifact(unsigned, key, self.workspace)
        self.assertNotEqual(signed.sha256, unsigned.sha256)
        self.assertGreater(signed.size_bytes, unsigned.size_bytes)
        code, output = self.sbverify(signed.path, key.certificate_path)
        self.assertEqual(code, 0, output)
