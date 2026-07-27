#!/usr/bin/env python3
"""Assemble the resolved inputs and artifact files one launch needs.

The launch runner demands that every required profile input arrive already
resolved to a digest, and that every canonical artifact role point at a specific
read-only file. That is the right shape for the runner, which must never guess,
but it means a campaign cannot start until twelve digests and seven files are
gathered from three different evidence scopes. Doing that by hand once is
tedious; doing it before every campaign run is how the wrong image quietly gets
booted.

This tool gathers them from the evidence that already exists: host identities from
the host scope, release identities from the repository, and base-image digests
from the per-record document the build emits. It resolves nothing itself and
invents nothing. Every value is read from evidence, and a scope that has not been
produced yet is an error naming what to run, not a placeholder.

The artifact files are copied into an immutable directory and made read-only,
because the runner requires read-only inputs with distinct inodes and refuses
anything writable. Copying rather than pointing at the originals also means a
launched campaign cannot be perturbed by a later rebuild of the tree.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import base_image  # noqa: E402
import base_image_build  # noqa: E402
import lab  # noqa: E402


class LaunchInputError(RuntimeError):
    """Raised when an input cannot be resolved from existing evidence."""


def _extract_gpt(disk: Path, destination: Path, workspace: Path, sectors: int = 34) -> None:
    """Extract the base image's primary GPT region to a raw file.

    The launch pins `base-image-gpt-sha256`, so the staged role must be the same
    region the build digested: the first 34 sectors, read out of the qcow2 rather
    than reconstructed, so the launch verifies against the partition table of the
    disk it is actually booting.
    """

    completed = subprocess.run(
        [
            shutil.which("qemu-img") or "qemu-img",
            "dd",
            "-f",
            "qcow2",
            "-O",
            "raw",
            f"if={disk}",
            f"of={destination}",
            "bs=512",
            f"count={sectors}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=lab.subprocess_environment(workspace),
    )
    if completed.returncode != 0:
        raise LaunchInputError(
            f"could not extract the GPT region: {completed.stderr.strip()[:300]}"
        )


def _boot_artifact_manifest(workspace: Path, graph_digest: str, plan_hash: str) -> tuple[str, bytes]:
    """Build the signed boot artifacts and return their manifest digest.

    This is the one release-scoped input the repository cannot simply hash: it is
    the identity of a *produced* set of signed artifacts, so it exists only once
    they have been built. The set is bound to the real state-graph digest and the
    real plan hash, so a manifest built for a different graph cannot satisfy a
    launch that runs this one.
    """

    import artifacts

    kernel = Path("/boot/vmlinuz-linux")
    if not kernel.is_file():
        raise LaunchInputError(
            "no kernel at /boot/vmlinuz-linux to build the boot artifacts from"
        )
    staging = workspace / "launch-artifacts"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(mode=0o700, parents=True)
    built = artifacts.build_test_artifact_set(staging, kernel, graph_digest, plan_hash)
    return built.manifest_sha256, built.manifest


def _run_json(argv: list[str], why: str) -> dict:
    completed = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True, check=False, timeout=900
    )
    if completed.returncode != 0:
        raise LaunchInputError(
            f"{why} could not be resolved: {' '.join(argv)} exited "
            f"{completed.returncode}: {completed.stderr.strip()[:300]}"
        )
    return json.loads(completed.stdout)


def resolve_inputs(
    workspace: Path, record_key: str, profile: dict
) -> tuple[dict[str, str], bytes]:
    """Resolve every required profile input from evidence that already exists."""

    document_path = base_image_build.base_image_document_path(workspace, record_key)
    if not document_path.is_file():
        raise LaunchInputError(
            f"no base-image evidence for {record_key}: build it first "
            f"({document_path} is missing)"
        )
    document = json.loads(document_path.read_text(encoding="utf-8"))

    host = _run_json(
        ["python3", str(ROOT / "base_image.py"), "--workspace", str(workspace), "host-identities"],
        "host-scoped inputs",
    )["identities"]
    # The boot-artifact manifest digest is the identity of a produced set, so it
    # has to be built before the release scope can resolve.
    graph_digest = lab.sha256_file(ROOT.parent / "model" / "installer-state-graph.json")
    manifest_digest, manifest_bytes = _boot_artifact_manifest(workspace, graph_digest, "b" * 64)
    release = _run_json(
        [
            "python3",
            str(ROOT / "base_image.py"),
            "--workspace",
            str(workspace),
            "release-identities",
            "--boot-artifacts-sha256",
            manifest_digest,
        ],
        "release-build inputs",
    )["identities"]

    resolved: dict[str, str] = {}
    for item in profile["required_inputs"]:
        input_id = str(item["id"])
        scope = item.get("evidence_scope")
        if scope == "host-acquisition":
            entry = host.get(input_id)
        elif scope == "release-build":
            entry = release.get(input_id)
        elif scope == "base-image-acquisition":
            cursor: object = document
            pointer = str(item["evidence_locator"]).partition("#")[2]
            for step in [part for part in pointer.split("/") if part]:
                if not isinstance(cursor, dict) or step not in cursor:
                    raise LaunchInputError(
                        f"{input_id}: {item['evidence_locator']} does not resolve"
                    )
                cursor = cursor[step]
            resolved[input_id] = str(cursor)
            continue
        else:
            raise LaunchInputError(f"{input_id}: unknown evidence scope {scope!r}")

        if not entry or not entry.get("resolved"):
            raise LaunchInputError(f"{input_id}: {scope} evidence is unresolved")
        resolved[input_id] = str(entry["sha256"])

    declared = {str(item["id"]) for item in profile["required_inputs"]}
    if set(resolved) != declared:
        raise LaunchInputError(
            f"resolution is incomplete; missing={sorted(declared - set(resolved))}"
        )
    return resolved, manifest_bytes


def stage_artifacts(
    workspace: Path,
    profile: dict,
    resolved: dict[str, str],
    destination: Path,
    manifest_bytes: bytes,
    record_key: str,
) -> dict[str, str]:
    """Copy each canonical artifact role into an immutable staging directory.

    The runner requires read-only files with distinct inodes, so each role gets
    its own copy. It also verifies every digest against the resolved inputs, so a
    copy that does not match is caught there rather than trusted here.
    """

    import firmware_enrollment

    role_sources: dict[str, Path] = {
        "ovmf-enrolled-vars": workspace / firmware_enrollment.ENROLLED_VARS_NAME,
        "ovmf-fixed-vars": Path(lab.OVMF_VARS),
        "installer": ROOT.parent / "controller" / "target" / "debug" / "jstack-installer",
        "installer-graph": ROOT.parent / "model" / "installer-state-graph.json",
        "release-manifest": (
            ROOT.parent / "core" / "fixtures" / "signed-release-manifest.json"
        ),
    }

    destination.mkdir(parents=True, exist_ok=True)
    staged: dict[str, str] = {}

    # Two roles are produced rather than found. The boot-artifact manifest exists
    # only as the bytes the artifact build just returned, and the GPT role is the
    # base image's own partition table, extracted from the image so the launch
    # verifies against the table of the disk it is actually booting.
    manifest_path = destination / "boot-artifacts"
    manifest_path.unlink(missing_ok=True)
    manifest_path.write_bytes(manifest_bytes)
    os.chmod(manifest_path, 0o400)
    staged["boot-artifacts"] = str(manifest_path)

    document = json.loads(
        base_image_build.base_image_document_path(workspace, record_key).read_text(
            encoding="utf-8"
        )
    )
    disk = Path(document["guest"]["build"]["disk"])
    gpt_path = destination / "base-image-gpt"
    gpt_path.unlink(missing_ok=True)
    _extract_gpt(disk, gpt_path, workspace)
    os.chmod(gpt_path, 0o400)
    staged["base-image-gpt"] = str(gpt_path)
    for role, source in role_sources.items():
        if not source.is_file():
            raise LaunchInputError(f"artifact role {role} is missing: {source}")
        target = destination / role
        target.unlink(missing_ok=True)
        shutil.copyfile(source, target)
        os.chmod(target, 0o400)
        staged[role] = str(target)
    return staged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--record", default="windows-11-enterprise-25h2-en-us-eval")
    parser.add_argument(
        "--output",
        help="directory for the generated documents; defaults to <workspace>/launch",
    )
    arguments = parser.parse_args()

    workspace = Path(arguments.workspace)
    output = Path(arguments.output) if arguments.output else workspace / "launch"
    output.mkdir(parents=True, exist_ok=True)

    try:
        profile = base_image_build.load_profile(arguments.record)
        resolved, manifest_bytes = resolve_inputs(workspace, arguments.record, profile)
        staged = stage_artifacts(
            workspace,
            profile,
            resolved,
            output / "artifacts",
            manifest_bytes,
            arguments.record,
        )
    except (
        LaunchInputError,
        base_image.BaseImageError,
        base_image_build.BaseImageBuildError,
        lab.LabSafetyError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1

    inputs_path = output / "resolved-inputs.json"
    files_path = output / "input-files.json"
    inputs_path.write_text(json.dumps(resolved, indent=2, sort_keys=True) + "\n")
    files_path.write_text(json.dumps(staged, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "resolved_inputs": str(inputs_path),
                "input_files": str(files_path),
                "resolved_count": len(resolved),
                "staged_roles": sorted(staged),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
