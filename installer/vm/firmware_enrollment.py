#!/usr/bin/env python3
"""PH-12 firmware enrollment: the Microsoft-production OVMF variable store.

Booting a real Windows guest with Secure Boot on requires a firmware variable
store enrolled with Microsoft's production keys, which is what the support
profiles name as ``ovmf-enrolled-vars-sha256``. The distribution ships an
*empty* ``OVMF_VARS.4m.fd``; enrolling it is a build step, and this module is
that step.

Two properties matter more than the enrollment succeeding:

**The master template is never modified.** Enrollment reads the read-only
distribution file and writes a new store inside the workspace. A build that
mutated the shared template would silently change every future run's starting
firmware state, and nothing downstream would notice.

**Enrollment is verified by reading the result back, not by trusting the tool's
exit code.** ``virt-fw-vars`` returning 0 is not evidence that PK, KEK, db, and
the Secure Boot flag are actually present in the produced bytes. This module
re-parses the output store and asserts each one, because the entire point of
this file is to be the thing a Secure Boot claim rests on.

Enrollment is deliberately *not* byte-reproducible: an EFI signature list
includes a timestamp, so two enrollments of the same keys differ. The identity
that is pinned is therefore the digest of one specific produced store, recorded
once and reused, rather than a digest expected to recur.

Nothing here mounts a filesystem, opens a block device, or needs privilege.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab

# The distribution firmware templates. Read-only inputs, never write targets.
OVMF_DIRECTORY = Path("/usr/share/edk2/x64")
OVMF_VARS_TEMPLATE = OVMF_DIRECTORY / "OVMF_VARS.4m.fd"
OVMF_SECBOOT_CODE = OVMF_DIRECTORY / "OVMF_CODE.secboot.4m.fd"

VIRT_FW_VARS = "virt-fw-vars"

# The canonical name the support profiles expect for the enrolled store.
ENROLLED_VARS_NAME = "OVMF_VARS.ms-enrolled.4m.fd"

# Variables that must exist in an enrolled store for Secure Boot to mean
# anything. PK establishes platform ownership and takes the firmware out of
# setup mode; without it, Secure Boot cannot be enforcing however the flag reads.
REQUIRED_VARIABLES = ("PK", "KEK", "db")


class EnrollmentError(RuntimeError):
    """Raised when firmware enrollment is unsafe, incomplete, or unverifiable."""


def _run(*arguments: str) -> str:
    """Run an enrollment tool with a clean environment, failing loudly."""

    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
            env=lab.subprocess_environment(),
        )
    except FileNotFoundError as exc:
        raise EnrollmentError(f"{arguments[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise EnrollmentError(f"{arguments[0]} timed out") from exc
    if completed.returncode != 0:
        raise EnrollmentError(
            f"{arguments[0]} failed with exit {completed.returncode}: "
            f"{completed.stderr.strip()[:400]}"
        )
    return completed.stdout + completed.stderr


def _require_readable_template(path: Path) -> None:
    """Refuse a template that is missing, a symlink, or not a regular file."""

    if path.is_symlink():
        raise EnrollmentError(f"firmware template must not be a symlink: {path}")
    if not path.is_file():
        raise EnrollmentError(f"firmware template is missing: {path}")
    if os.stat(path).st_size == 0:
        raise EnrollmentError(f"firmware template is empty: {path}")


def parse_variables(store: Path) -> dict[str, str]:
    """Return the variable names present in a firmware store.

    Parsed from the produced bytes rather than inferred from the command that
    wrote them, so a tool that silently no-ops cannot pass for a successful
    enrollment.
    """

    output = _run(VIRT_FW_VARS, "--input", str(store), "--print")
    variables: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        name, _, detail = line.partition(":")
        name = name.strip()
        # Tool log lines are prefixed (INFO:, WARNING:) and are not variables.
        if not name or " " in name or name.isupper() and name in {"INFO", "WARNING", "ERROR"}:
            continue
        variables[name] = detail.strip()
    return variables


def verify_enrollment(store: Path) -> dict[str, Any]:
    """Assert an enrolled store really carries the trust anchors and the flag.

    Raises rather than returning a verdict, because every caller of this
    function is about to treat the store as trustworthy.
    """

    variables = parse_variables(store)
    missing = [name for name in REQUIRED_VARIABLES if name not in variables]
    if missing:
        raise EnrollmentError(
            f"enrolled store is missing required variables: {', '.join(missing)}"
        )

    flag = variables.get("SecureBootEnable", "")
    if "ON" not in flag.upper():
        raise EnrollmentError(f"enrolled store does not enable Secure Boot: {flag!r}")

    custom = variables.get("CustomMode", "")
    if custom and "ON" in custom.upper():
        # Custom mode lets the guest rewrite the trust anchors, which would make
        # any later Secure Boot observation meaningless.
        raise EnrollmentError("enrolled store leaves CustomMode enabled")

    return {
        "variables": sorted(variables),
        "secure_boot": True,
        "custom_mode": False,
    }


def enroll_microsoft_vars(
    workspace: Path, name: str = ENROLLED_VARS_NAME, *, overwrite: bool = False
) -> dict[str, Any]:
    """Produce a Microsoft-production enrolled variable store in the workspace.

    Returns the evidence a support profile needs: the store's path, size, and
    SHA-256, plus the digest of the template it came from so the provenance of
    the enrolled bytes is recorded rather than assumed.
    """

    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(workspace, scratch)
    if not workspace.is_dir():
        raise EnrollmentError(f"workspace must already exist: {workspace}")
    lab.require_private_workspace(workspace)

    _require_readable_template(OVMF_VARS_TEMPLATE)
    template_digest = lab.sha256_file(OVMF_VARS_TEMPLATE)

    destination = workspace / name
    if destination.exists() and not overwrite:
        raise EnrollmentError(
            f"refusing to clobber an existing store: {destination}. "
            "Pass overwrite only when deliberately rebuilding."
        )
    if destination.is_symlink():
        raise EnrollmentError(f"destination must not be a symlink: {destination}")

    # Copy first, enroll into the copy. The template is an input.
    shutil.copyfile(OVMF_VARS_TEMPLATE, destination)
    os.chmod(destination, 0o600)

    _run(
        VIRT_FW_VARS,
        "--input",
        str(destination),
        "--output",
        str(destination),
        "--enroll-microsoft",
        "--secure-boot",
    )

    # The template must be byte-identical to what it was before this ran.
    if lab.sha256_file(OVMF_VARS_TEMPLATE) != template_digest:
        raise EnrollmentError(
            "the distribution firmware template was modified by enrollment; "
            "this is a serious defect and the produced store is not trustworthy"
        )

    verified = verify_enrollment(destination)
    digest = lab.sha256_file(destination)

    return {
        "canonical_name": name,
        "path": str(destination),
        "sha256": digest,
        "size_bytes": os.stat(destination).st_size,
        "enrollment": "microsoft-production",
        "template_path": str(OVMF_VARS_TEMPLATE),
        "template_sha256": template_digest,
        "verified": verified,
        # Recorded so a consumer does not expect a digest that cannot recur.
        "reproducible": False,
        "reproducibility_note": (
            "EFI signature lists embed a timestamp, so re-enrolling the same keys "
            "produces different bytes. Pin this exact digest rather than expecting "
            "a rebuild to match it."
        ),
    }


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    argument_parser.add_argument("--workspace", required=True)
    argument_parser.add_argument("--name", default=ENROLLED_VARS_NAME)
    argument_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="rebuild an existing store instead of refusing to clobber it",
    )
    return argument_parser


def main() -> int:
    arguments = parser().parse_args()
    try:
        evidence = enroll_microsoft_vars(
            Path(arguments.workspace), arguments.name, overwrite=arguments.overwrite
        )
    except (EnrollmentError, lab.LabSafetyError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
