#!/usr/bin/env python3
"""Check that each media record's declared WIM edition really is in its ISO.

`Autounattend.xml` selects the edition to install by *name*, via the
`/IMAGE/NAME` metadata key. Windows setup matches that string exactly, and a
mismatch is not a fast failure: setup stops on its edition-picker UI and waits
for a human. In an unattended build nobody answers, so the guest sits there
until the ninety-minute timeout expires. The cost of a stale or misspelled name
is therefore an hour per attempt, and the symptom points at the timeout rather
than at the name.

Reading the ISO's own WIM makes that specific hour unspendable. It is a separate
tool rather than part of `verify_media` because it extracts six gigabytes and
takes a few minutes, while `verify_media` runs on every build.

Confined by construction: the ISO is opened read-only, extraction goes to a
caller-supplied scratch directory, and nothing is mounted.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import base_image  # noqa: E402
import lab  # noqa: E402


class EditionCheckError(RuntimeError):
    """Raised when a record's declared edition is not the one in the ISO."""


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise EditionCheckError(f"{name} is not installed")
    return found


def wim_editions(install_wim: Path) -> dict[int, str]:
    """Return the WIM's index-to-edition-name mapping, as the WIM states it."""

    completed = subprocess.run(
        [_tool("wiminfo"), str(install_wim)],
        capture_output=True,
        text=True,
        check=False,
        env=lab.subprocess_environment(install_wim.parent),
    )
    if completed.returncode != 0:
        raise EditionCheckError(f"wiminfo failed: {completed.stderr.strip()[:300]}")

    editions: dict[int, str] = {}
    index: int | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("Index:"):
            index = int(line.split(":", 1)[1].strip())
        elif line.startswith("Name:") and index is not None:
            editions[index] = line.split(":", 1)[1].strip()
            index = None
    if not editions:
        raise EditionCheckError("the WIM reported no editions")
    return editions


def check_record(record: base_image.MediaRecord, workspace: Path, scratch: Path) -> dict[str, object]:
    """Confirm the record's declared index and name agree with its ISO."""

    iso = workspace / record.filename
    if not iso.is_file():
        raise EditionCheckError(f"{record.record_id}: ISO is missing: {iso}")

    destination = scratch / f"{record.record_id}.install.wim"
    subprocess.run(
        [_tool("7z"), "e", str(iso), record.install_image_path, f"-o{scratch}", "-y"],
        capture_output=True,
        check=True,
        env=lab.subprocess_environment(scratch),
    )
    extracted = scratch / Path(record.install_image_path).name
    if not extracted.is_file():
        raise EditionCheckError(
            f"{record.record_id}: {record.install_image_path} is not in the ISO"
        )
    extracted.replace(destination)

    editions = wim_editions(destination)
    observed = editions.get(record.selected_index)
    if observed is None:
        raise EditionCheckError(
            f"{record.record_id}: the ISO has no image at index "
            f"{record.selected_index}; it has {sorted(editions)}"
        )
    if observed != record.selected_name:
        raise EditionCheckError(
            f"{record.record_id}: record declares index {record.selected_index} is "
            f"{record.selected_name!r}, but the ISO says {observed!r}. Windows setup "
            "matches /IMAGE/NAME exactly and stops on its edition picker when it "
            "cannot, which in an unattended build means a full install timeout."
        )
    return {
        "record_id": record.record_id,
        "selected_index": record.selected_index,
        "selected_name": record.selected_name,
        "editions": {str(k): v for k, v in sorted(editions.items())},
        "agrees": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--record", help="one record key; default is every record")
    arguments = parser.parse_args()

    workspace = Path(arguments.workspace)
    records = base_image.load_media_records()
    if arguments.record is not None:
        if arguments.record not in records:
            print(json.dumps({"error": f"unknown record {arguments.record}"}), file=sys.stderr)
            return 2
        records = {arguments.record: records[arguments.record]}

    results = []
    with tempfile.TemporaryDirectory(prefix="edition-check-") as temporary:
        scratch = Path(temporary)
        for record in records.values():
            try:
                results.append(check_record(record, workspace, scratch))
            except (EditionCheckError, subprocess.CalledProcessError) as error:
                print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
                return 1
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
