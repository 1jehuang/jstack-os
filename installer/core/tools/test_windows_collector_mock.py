#!/usr/bin/env python3
"""Execute the exact Windows collector against mocks and validate normalization."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate(schema_name: str, document: dict) -> list[str]:
    schemas = {path.name: load(path) for path in (ROOT / "schemas").glob("*.json")}
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    schema = schemas[schema_name]
    validator = validator_for(schema)(
        schema, registry=registry, format_checker=FormatChecker()
    )
    return [error.message for error in validator.iter_errors(document)]


def main() -> int:
    if os.name != "nt":
        live = subprocess.run(
            ["cargo", "run", "--offline", "--quiet", "--bin", "jstack-inventory"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if live.returncode == 0 or "live collection is available only on Windows" not in live.stderr:
            print("ERROR: non-Windows live collection did not fail closed", file=sys.stderr)
            return 1

    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        print("skipped mocked collector execution: PowerShell is unavailable")
        return 0

    env = {
        **os.environ,
        "JSTACK_MOCKS": str(ROOT / "tests" / "windows-collector-mocks.ps1"),
        "JSTACK_COLLECTOR": str(ROOT / "assets" / "collect-windows-inventory.ps1"),
    }
    collected = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ". $env:JSTACK_MOCKS; . $env:JSTACK_COLLECTOR",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if collected.returncode != 0:
        print(f"ERROR: mocked collector failed: {collected.stderr.strip()}", file=sys.stderr)
        return 1
    try:
        snapshot = json.loads(collected.stdout)
    except json.JSONDecodeError as error:
        print(f"ERROR: mocked collector returned invalid JSON: {error}", file=sys.stderr)
        return 1
    errors = validate("windows-storage-snapshot.schema.json", snapshot)
    if errors:
        print(f"ERROR: mocked snapshot violated schema: {errors}", file=sys.stderr)
        return 1
    if [disk["number"] for disk in snapshot["disks"]] != [0, 1]:
        print("ERROR: collector did not deterministically order disks", file=sys.stderr)
        return 1
    if [partition["number"] for partition in snapshot["disks"][0]["partitions"]] != [1, 2, 3, 4]:
        print("ERROR: collector did not deterministically order partitions", file=sys.stderr)
        return 1
    unrelated = snapshot["disks"][1]
    if (
        unrelated["partition_style"] != "MBR"
        or unrelated["guid"] is not None
        or unrelated["partitions"][0]["guid"] is not None
        or unrelated["partitions"][0]["type_guid"] is not None
    ):
        print("ERROR: collector did not preserve nullable unrelated MBR identities", file=sys.stderr)
        return 1

    failed_observation = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ". $env:JSTACK_MOCKS; . $env:JSTACK_COLLECTOR",
        ],
        cwd=ROOT,
        env={**env, "JSTACK_FAIL_BATTERY": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    if failed_observation.returncode == 0:
        print("ERROR: collector suppressed a failed readiness observation", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
        json.dump(snapshot, handle)
        handle.flush()
        normalized = subprocess.run(
            [
                "cargo",
                "run",
                "--offline",
                "--quiet",
                "--bin",
                "jstack-inventory",
                "--",
                "--from-snapshot",
                handle.name,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
    if normalized.returncode != 0:
        print(f"ERROR: snapshot normalization failed: {normalized.stderr.strip()}", file=sys.stderr)
        return 1
    inventory = json.loads(normalized.stdout)
    errors = validate("inventory.schema.json", inventory)
    if errors:
        print(f"ERROR: normalized inventory violated schema: {errors}", file=sys.stderr)
        return 1
    if inventory["host"]["secure_boot"] != "enabled_untrusted":
        print("ERROR: observation incorrectly asserted Secure Boot artifact trust", file=sys.stderr)
        return 1
    if inventory["readiness"]["bitlocker_recovery_material_confirmed"]:
        print("ERROR: observation incorrectly asserted recovery-material confirmation", file=sys.stderr)
        return 1

    print(
        "validated mocked Windows collection, fail-closed errors, and schema-valid normalization"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
