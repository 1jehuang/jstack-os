#!/usr/bin/env python3
"""Verify a built base image against the evidence that describes it.

PH-12's closure claim is "a Windows base image exists and is the one the
evidence describes". That is a statement about a workspace artifact, not about
the repository, so it cannot be established by any file or grep probe over the
tree. This tool is the measurement: it re-reads the disk and recomputes its
digests rather than trusting the recorded numbers, because a document that was
true when it was written says nothing about the file that is there now.

Exits zero only when the image exists, its digests still match, its partition
roles are the ones the profile declares, and every base-image-scoped profile
input resolves through `base-image.json`. Anything else is a nonzero exit with
the reason on stderr, so the ledger can use it as a probe.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import base_image  # noqa: E402
import base_image_build  # noqa: E402
import lab  # noqa: E402


class VerificationError(RuntimeError):
    """Raised when the image and its evidence disagree."""


def verify(workspace: Path, record_key: str) -> dict[str, object]:
    """Re-measure the built image and confirm the evidence still describes it."""

    document_path = workspace / "base-image.json"
    if not document_path.is_file():
        raise VerificationError(f"no base-image evidence document: {document_path}")
    document = json.loads(document_path.read_text(encoding="utf-8"))

    build = document.get("guest", {}).get("build")
    if not isinstance(build, dict):
        raise VerificationError("the evidence document carries no build record")
    if build.get("record_key") != record_key:
        raise VerificationError(
            f"the document describes {build.get('record_key')!r}, not {record_key!r}"
        )

    disk = Path(build["disk"])
    if not disk.is_file():
        raise VerificationError(f"the built image is gone: {disk}")

    # Recompute rather than trust. This is the whole point of the tool.
    observed_sha = lab.sha256_file(disk)
    if observed_sha != document["image"]["sha256"]:
        raise VerificationError(
            f"image digest drifted: disk is {observed_sha}, document says "
            f"{document['image']['sha256']}"
        )
    observed_gpt = base_image_build.gpt_sha256(disk, workspace)
    if observed_gpt != document["disk"]["gpt_sha256"]:
        raise VerificationError(
            f"GPT digest drifted: disk is {observed_gpt}, document says "
            f"{document['disk']['gpt_sha256']}"
        )

    # The disk must still satisfy the profile's declared layout, checked by
    # reading the image back rather than by rereading the recorded inspection.
    profile = base_image_build.load_profile(record_key)
    inspection = base_image_build.inspect_disk(disk, profile, workspace)

    # Every base-image-scoped profile input must resolve through the document,
    # since an image nothing can reference is not usable evidence.
    resolved: dict[str, str] = {}
    for item in profile["required_inputs"]:
        if item.get("evidence_scope") != "base-image-acquisition":
            continue
        name, _, pointer = str(item["evidence_locator"]).partition("#")
        if name != "base-image.json":
            raise VerificationError(f"unexpected evidence document {name!r}")
        cursor: object = document
        for step in [part for part in pointer.split("/") if part]:
            if not isinstance(cursor, dict) or step not in cursor:
                raise VerificationError(
                    f"{item['id']}: {item['evidence_locator']} does not resolve"
                )
            cursor = cursor[step]
        if not isinstance(cursor, str) or len(cursor) != 64:
            raise VerificationError(f"{item['id']} did not resolve to a digest")
        resolved[str(item["id"])] = cursor

    if not resolved:
        raise VerificationError("the profile declares no base-image-scoped inputs")

    return {
        "record_key": record_key,
        "disk": str(disk),
        "sha256": observed_sha,
        "gpt_sha256": observed_gpt,
        "inspection": inspection,
        "resolved_profile_inputs": resolved,
        "install_seconds": build.get("install_seconds"),
        "verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True)
    parser.add_argument(
        "--record",
        default="windows-11-enterprise-25h2-en-us-eval",
        help="media record key whose base image is verified",
    )
    arguments = parser.parse_args()

    try:
        report = verify(Path(arguments.workspace), arguments.record)
    except (
        VerificationError,
        base_image.BaseImageError,
        base_image_build.BaseImageBuildError,
        lab.LabSafetyError,
        KeyError,
    ) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
