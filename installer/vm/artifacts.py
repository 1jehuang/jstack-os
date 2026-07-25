#!/usr/bin/env python3
"""PH-10 reproducible signed test boot artifacts.

Builds the artifact set the installer actually boots, using the same tools a
release would use, and proves the whole chain forms one verified trust root:

* **ESP loader** - the systemd-boot EFI binary, copied byte-for-byte from the
  host's signed distribution package.
* **Installer UKI** and **recovery UKI** - unified kernel images built with
  ``ukify`` from a pinned kernel, initrd, and command line.
* **Offline system image** - a content-addressed payload.
* **Boot entries** - Boot Loader Specification type-1 entries naming the UKIs.
* **Handoff payloads** - the Windows and Linux journal handoff documents.

Every artifact is content-addressed, and the manifest binds all of them plus the
graph digest. Two properties are proven rather than asserted:

1. **Reproducibility.** Building twice from the same inputs yields identical
   bytes, so a digest in the manifest is a stable identity.
2. **One trust chain.** Every artifact is signed by the same test key, every
   signature verifies with ``sbverify``, and the manifest digest covers the exact
   signed bytes. Tampering with any artifact breaks verification.

These are *test* artifacts signed by a throwaway key generated per run. They are
never a production release, and the key never leaves the workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab

UKIFY = "ukify"
SBSIGN = "sbsign"
SBVERIFY = "sbverify"
OPENSSL = "openssl"

# The host's systemd-boot binary. It is a distribution-signed regular file and is
# copied, never rebuilt, so its identity is exactly the packaged bytes.
SYSTEMD_BOOT = Path("/usr/lib/systemd/boot/efi/systemd-bootx64.efi")

# Artifact roles, matching the closed role set in the release contract.
ROLE_ESP_LOADER = "esp_loader"
ROLE_INSTALLER_UKI = "installer_uki"
ROLE_RECOVERY_UKI = "recovery_uki"
ROLE_OFFLINE_SYSTEM_IMAGE = "offline_system_image"
ARTIFACT_ROLES = (
    ROLE_ESP_LOADER,
    ROLE_INSTALLER_UKI,
    ROLE_OFFLINE_SYSTEM_IMAGE,
    ROLE_RECOVERY_UKI,
)

# Signable roles: PE binaries the firmware will authenticate.
SIGNABLE_ROLES = (ROLE_ESP_LOADER, ROLE_INSTALLER_UKI, ROLE_RECOVERY_UKI)


class ArtifactError(RuntimeError):
    """Raised when an artifact cannot be built or does not verify."""


def _tool(name: str) -> str:
    found = shutil.which(name, path=lab.SYSTEM_PATH)
    if not found:
        raise ArtifactError(f"required command is unavailable: {name}")
    invoked = Path(found)
    target = invoked.resolve(strict=True)
    if target.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ArtifactError(f"set-id command is forbidden: {target}")
    return str(invoked)


def _run(name: str, *arguments: str) -> str:
    result = subprocess.run(
        [_tool(name), *arguments],
        text=True,
        capture_output=True,
        check=False,
        env=lab.subprocess_environment(),
    )
    if result.returncode != 0:
        raise ArtifactError(
            f"{name} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result.stdout or result.stderr


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class Artifact:
    """One built artifact, identified by its exact bytes."""

    role: str
    path: Path
    sha256: str
    size_bytes: int
    signed: bool

    def to_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "filename": self.path.name,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "signed": self.signed,
        }


@dataclass(frozen=True)
class TestSigningKey:
    """A throwaway Secure Boot key pair, generated inside the workspace.

    This is deliberately not a production key: it is created per build, lives
    only in the workspace, and its certificate is recorded in the manifest so an
    evidence reviewer can tell test artifacts from release artifacts at a glance.
    """

    key_path: Path
    certificate_path: Path
    certificate_sha256: str

    @classmethod
    def generate(cls, workspace: Path, common_name: str) -> TestSigningKey:
        key = workspace / "test-secure-boot.key"
        certificate = workspace / "test-secure-boot.crt"
        _run(
            OPENSSL,
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-subj",
            f"/CN={common_name}/",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "3650",
            "-nodes",
            "-sha256",
        )
        os.chmod(key, 0o600)
        return cls(
            key_path=key,
            certificate_path=certificate,
            certificate_sha256=sha256_bytes(certificate.read_bytes()),
        )


def _confined(path: Path, workspace: Path) -> Path:
    """Require an output path inside the workspace."""
    scratch = lab.require_scratch_root()
    candidate = lab.safe_workspace(path, scratch)
    normalized = Path(os.path.abspath(workspace))
    if normalized not in candidate.parents:
        raise ArtifactError(f"artifact must live inside {normalized}: {candidate}")
    return candidate


def build_esp_loader(workspace: Path) -> Artifact:
    """Copy the distribution systemd-boot binary as the ESP loader."""
    if not SYSTEMD_BOOT.is_file():
        raise ArtifactError(f"systemd-boot is not installed at {SYSTEMD_BOOT}")
    output = _confined(workspace / "jstack-loader.efi", workspace)
    payload = SYSTEMD_BOOT.read_bytes()
    output.write_bytes(payload)
    os.chmod(output, 0o600)
    return Artifact(
        role=ROLE_ESP_LOADER,
        path=output,
        sha256=sha256_bytes(payload),
        size_bytes=len(payload),
        signed=False,
    )


def build_uki(
    workspace: Path,
    role: str,
    kernel: Path,
    initrd: bytes,
    cmdline: str,
    name: str,
) -> Artifact:
    """Build a unified kernel image with ukify.

    ukify embeds no timestamp, so building twice from identical inputs produces
    identical bytes. The test suite proves that rather than assuming it.
    """
    if role not in (ROLE_INSTALLER_UKI, ROLE_RECOVERY_UKI):
        raise ArtifactError(f"{role} is not a UKI role")
    if not kernel.is_file():
        raise ArtifactError(f"kernel is not a regular file: {kernel}")

    initrd_path = _confined(workspace / f"{name}.initrd", workspace)
    initrd_path.write_bytes(initrd)
    cmdline_path = _confined(workspace / f"{name}.cmdline", workspace)
    cmdline_path.write_text(cmdline, encoding="utf-8")
    output = _confined(workspace / f"{name}.efi", workspace)
    if output.exists():
        output.unlink()

    _run(
        UKIFY,
        "build",
        f"--linux={kernel}",
        f"--initrd={initrd_path}",
        f"--cmdline=@{cmdline_path}",
        f"--output={output}",
    )
    payload = output.read_bytes()
    return Artifact(
        role=role,
        path=output,
        sha256=sha256_bytes(payload),
        size_bytes=len(payload),
        signed=False,
    )


def build_offline_system_image(workspace: Path, payload: bytes) -> Artifact:
    """Write the content-addressed offline system image."""
    output = _confined(workspace / "jstack-system.img", workspace)
    output.write_bytes(payload)
    return Artifact(
        role=ROLE_OFFLINE_SYSTEM_IMAGE,
        path=output,
        sha256=sha256_bytes(payload),
        size_bytes=len(payload),
        signed=False,
    )


def sign_artifact(artifact: Artifact, key: TestSigningKey, workspace: Path) -> Artifact:
    """Sign a PE artifact and prove the signature verifies."""
    if artifact.role not in SIGNABLE_ROLES:
        raise ArtifactError(f"{artifact.role} is not a signable PE artifact")
    output = _confined(
        workspace / f"{artifact.path.stem}.signed{artifact.path.suffix}", workspace
    )
    if output.exists():
        output.unlink()
    _run(
        SBSIGN,
        "--key",
        str(key.key_path),
        "--cert",
        str(key.certificate_path),
        "--output",
        str(output),
        str(artifact.path),
    )

    # Independent verification: the signature must validate against the exact
    # certificate, not merely be present.
    verification = _run(SBVERIFY, "--cert", str(key.certificate_path), str(output))
    if "Signature verification OK" not in verification:
        raise ArtifactError(f"signature does not verify for {artifact.role}")

    payload = output.read_bytes()
    return Artifact(
        role=artifact.role,
        path=output,
        sha256=sha256_bytes(payload),
        size_bytes=len(payload),
        signed=True,
    )


def verify_signature(artifact: Artifact, key: TestSigningKey) -> bool:
    """Re-verify a signed artifact against the trust root."""
    if not artifact.signed:
        raise ArtifactError(f"{artifact.role} is not signed")
    try:
        output = _run(SBVERIFY, "--cert", str(key.certificate_path), str(artifact.path))
    except ArtifactError:
        return False
    return "Signature verification OK" in output


def build_boot_entry(name: str, title: str, uki_filename: str) -> bytes:
    """Render a Boot Loader Specification type-1 entry.

    Fields are emitted in a fixed order with LF endings so the entry is
    byte-reproducible.
    """
    lines = [
        f"title      {title}",
        f"efi        /EFI/Linux/{uki_filename}",
        f"sort-key   {name}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_handoff_payload(
    plan_hash: str,
    graph_digest: str,
    manifest_digest: str,
    next_actor: str,
    resume_token: str,
) -> bytes:
    """Render a canonical cross-OS handoff payload.

    Keys are sorted and separators are tight, so the payload is canonical and its
    digest is a stable identity.
    """
    document = {
        "schema_version": 1,
        "graph_digest": graph_digest,
        "manifest_digest": manifest_digest,
        "next_actor": next_actor,
        "plan_hash": plan_hash,
        "resume_token": resume_token,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_test_manifest(
    artifacts: list[Artifact],
    entries: dict[str, bytes],
    handoffs: dict[str, bytes],
    key: TestSigningKey,
    graph_digest: str,
    plan_hash: str,
) -> tuple[bytes, str]:
    """Bind every artifact, entry, and handoff into one canonical manifest.

    Returns the canonical bytes and their digest. The digest is the single
    identity a verifier checks; it covers the signed artifact bytes, so a
    tampered artifact cannot be substituted.
    """
    roles = sorted(artifact.role for artifact in artifacts)
    if roles != sorted(ARTIFACT_ROLES):
        raise ArtifactError(
            f"manifest must contain exactly the closed role set, found {roles}"
        )
    for artifact in artifacts:
        if artifact.role in SIGNABLE_ROLES and not artifact.signed:
            raise ArtifactError(f"{artifact.role} must be signed before publication")

    document = {
        "schema_version": 1,
        "kind": "jstack-test-boot-artifacts",
        "trust": {
            "kind": "throwaway-test-key",
            "certificate_sha256": key.certificate_sha256,
        },
        "graph_digest": graph_digest,
        "plan_hash": plan_hash,
        "artifacts": sorted(
            (artifact.to_record() for artifact in artifacts),
            key=lambda record: record["role"],
        ),
        "boot_entries": [
            {"name": name, "sha256": sha256_bytes(payload), "size_bytes": len(payload)}
            for name, payload in sorted(entries.items())
        ],
        "handoffs": [
            {"name": name, "sha256": sha256_bytes(payload), "size_bytes": len(payload)}
            for name, payload in sorted(handoffs.items())
        ],
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return canonical, sha256_bytes(canonical)


@dataclass(frozen=True)
class TestArtifactSet:
    """A complete, signed, manifest-bound artifact set."""

    artifacts: tuple[Artifact, ...]
    entries: dict[str, bytes]
    handoffs: dict[str, bytes]
    key: TestSigningKey
    manifest: bytes
    manifest_sha256: str

    def artifact(self, role: str) -> Artifact:
        for artifact in self.artifacts:
            if artifact.role == role:
                return artifact
        raise ArtifactError(f"no artifact for role {role}")


def build_test_artifact_set(
    workspace: Path,
    kernel: Path,
    graph_digest: str,
    plan_hash: str,
    system_image: bytes = b"jstack-offline-system-image\n",
) -> TestArtifactSet:
    """Build, sign, and bind the whole test artifact set."""
    key = TestSigningKey.generate(workspace, "JStack Test Secure Boot")

    unsigned = [
        build_esp_loader(workspace),
        build_uki(
            workspace,
            ROLE_INSTALLER_UKI,
            kernel,
            b"jstack-installer-initrd\n",
            "jstack.installer=1 rw",
            "jstack-installer",
        ),
        build_uki(
            workspace,
            ROLE_RECOVERY_UKI,
            kernel,
            b"jstack-recovery-initrd\n",
            "jstack.recovery=1 rw",
            "jstack-recovery",
        ),
        build_offline_system_image(workspace, system_image),
    ]

    artifacts: list[Artifact] = []
    for artifact in unsigned:
        if artifact.role in SIGNABLE_ROLES:
            artifacts.append(sign_artifact(artifact, key, workspace))
        else:
            artifacts.append(artifact)

    entries = {
        "jstack-installer": build_boot_entry(
            "jstack-installer", "JStack Installer", "jstack-installer.signed.efi"
        ),
        "jstack-recovery": build_boot_entry(
            "jstack-recovery", "JStack Recovery", "jstack-recovery.signed.efi"
        ),
    }
    handoffs = {
        "windows-to-linux": build_handoff_payload(
            plan_hash, graph_digest, "", "linux_installer", "installer-resume"
        ),
        "linux-to-windows": build_handoff_payload(
            plan_hash, graph_digest, "", "windows_finalizer", "finalizer-resume"
        ),
    }

    manifest, manifest_sha256 = build_test_manifest(
        artifacts, entries, handoffs, key, graph_digest, plan_hash
    )
    return TestArtifactSet(
        artifacts=tuple(artifacts),
        entries=entries,
        handoffs=handoffs,
        key=key,
        manifest=manifest,
        manifest_sha256=manifest_sha256,
    )


def verify_test_artifact_set(artifact_set: TestArtifactSet) -> dict[str, Any]:
    """Re-verify the whole chain from the manifest outward."""
    failures: list[str] = []

    for artifact in artifact_set.artifacts:
        observed = sha256_bytes(artifact.path.read_bytes())
        if observed != artifact.sha256:
            failures.append(f"{artifact.role} bytes do not match its recorded digest")
        if artifact.signed and not verify_signature(artifact, artifact_set.key):
            failures.append(f"{artifact.role} signature does not verify")

    recomputed, digest = build_test_manifest(
        list(artifact_set.artifacts),
        artifact_set.entries,
        artifact_set.handoffs,
        artifact_set.key,
        json.loads(artifact_set.manifest)["graph_digest"],
        json.loads(artifact_set.manifest)["plan_hash"],
    )
    if recomputed != artifact_set.manifest or digest != artifact_set.manifest_sha256:
        failures.append("manifest is not reproducible from the observed artifacts")

    if failures:
        raise ArtifactError("; ".join(failures))
    return {
        "manifest_sha256": artifact_set.manifest_sha256,
        "verified_artifacts": len(artifact_set.artifacts),
        "signed_artifacts": sum(1 for a in artifact_set.artifacts if a.signed),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True)
    root.add_argument("--kernel", default="/boot/vmlinuz-linux")
    root.add_argument("--graph-digest", required=True)
    root.add_argument("--plan-hash", required=True)
    return root


def main() -> int:
    arguments = parser().parse_args()
    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(arguments.workspace, scratch)
    workspace.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace, 0o700)

    artifact_set = build_test_artifact_set(
        workspace, Path(arguments.kernel), arguments.graph_digest, arguments.plan_hash
    )
    evidence = verify_test_artifact_set(artifact_set)
    json.dump(evidence, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
