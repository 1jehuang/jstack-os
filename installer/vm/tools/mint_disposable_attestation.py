#!/usr/bin/env python3
"""Mint the per-run disposable-VM attestation the mutation adapters demand.

Both adapter families refuse to mutate anything without a matching pair of
harness-minted tokens in `JSTACK_DISPOSABLE_VM` and
`JSTACK_DISPOSABLE_VM_EXPECTED`. That gate is the reason a stray adapter run
cannot damage a real machine, and it is deliberately impossible to satisfy by
accident. Nothing in the harness minted one, so the Windows adapters had never
executed anywhere.

The token is bound to one run, so it cannot be reused:

* It is derived from the run id, the plan hash, and fresh entropy, so two runs
  never share a token and a token from a previous run fails the equality check.
* It is written only into the run directory, which the harness already treats as
  exclusive per-run mutable state.
* It carries the run id in plaintext, so a token found in an evidence bundle can
  be traced to the exact run that minted it.

This mints; it does not weaken. The adapters still compare the presented token
against the expected one and still require a controller capability bound to the
same plan. A minted token authorises a *disposable VM*, never a real machine,
and the token alone is not sufficient to mutate anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import lab  # noqa: E402

# The adapters reject anything shorter than 32 characters. A SHA-256 hex digest
# is 64, comfortably above the floor and a fixed width regardless of inputs.
TOKEN_PREFIX = "jstack-disposable-vm"


class AttestationError(RuntimeError):
    """Raised when an attestation cannot be minted for a run."""


def mint(run_id: str, plan_hash: str) -> str:
    """Return a fresh attestation token bound to one run and plan.

    Fresh entropy is mixed in so the token is not a pure function of its inputs:
    a token must not be predictable from a run id and a plan hash that both
    appear in the evidence bundle.
    """

    if not run_id or not plan_hash:
        raise AttestationError("an attestation must be bound to a run and a plan")
    entropy = secrets.token_hex(32)
    digest = hashlib.sha256(
        "\x1f".join((TOKEN_PREFIX, run_id, plan_hash, entropy)).encode("utf-8")
    ).hexdigest()
    return f"{TOKEN_PREFIX}-{run_id}-{digest}"


def write(run_directory: Path, run_id: str, plan_hash: str) -> dict[str, str]:
    """Mint a token and record it inside the run directory.

    Written with owner-only permissions into the run's own directory, which the
    harness already holds exclusively, so one run's attestation is never visible
    as another run's expected value.
    """

    resolved = run_directory.resolve()
    if not resolved.is_dir():
        raise AttestationError(f"run directory does not exist: {run_directory}")

    token = mint(run_id, plan_hash)
    record = {
        "run_id": run_id,
        "plan_hash": plan_hash,
        "token": token,
        "environment": {
            "JSTACK_DISPOSABLE_VM": token,
            "JSTACK_DISPOSABLE_VM_EXPECTED": token,
        },
    }
    destination = resolved / "disposable-vm-attestation.json"
    destination.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(destination, 0o600)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-directory", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--plan-hash", required=True)
    arguments = parser.parse_args()

    try:
        record = write(
            Path(arguments.run_directory), arguments.run_id, arguments.plan_hash
        )
    except (AttestationError, OSError, lab.LabSafetyError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
