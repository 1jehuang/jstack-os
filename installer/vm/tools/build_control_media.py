#!/usr/bin/env python3
"""Build the read-only control medium that carries one action into a guest.

The launch topology is sealed on purpose: host forwarding is disabled, there is
no guest agent, and no shared folder. That seal is a safety property, because it
is the reason a controller running on this host cannot reach out and mutate the
host itself. Building a channel into the guest must not weaken it.

So the channel is a small FAT32 image attached read-only, published through the
same verified transaction the answer media uses. It is one-directional and inert:
a disk image carries bytes and executes nothing, and the guest chooses whether to
read it. Nothing on the host is reachable through it.

The medium carries exactly one action request:

* the adapter script, byte-identical to the repository copy, so what runs in the
  guest is what was reviewed here;
* the request document naming the action, the plan hash, the target GUIDs, and
  the controller capability that authorises it;
* the disposable-VM attestation minted for this run.

It is deliberately not a general file-transfer mechanism. One medium authorises
one action against one plan in one run, so a medium recovered from an evidence
bundle cannot be replayed into a different run: the attestation binds the run and
the capability binds the plan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import images  # noqa: E402
import lab  # noqa: E402

# The payload is a script and a small JSON document, so the size is set by the
# FAT32 minimum rather than by need. Matching the answer media's size keeps the
# two removable volumes indistinguishable in geometry, which is one less thing
# for a guest to key off.
CONTROL_IMAGE_BYTES = images.MINIMUM_FAT32_BYTES

ADAPTER_SOURCE = ROOT.parent / "core" / "assets" / "windows-mutation-adapters.ps1"


class ControlMediaError(RuntimeError):
    """Raised when a control medium cannot be built."""


def build_request(
    action: str,
    plan_hash: str,
    capability: dict,
    attestation: str,
    targets: dict,
) -> bytes:
    """Render the canonical request document one adapter invocation reads.

    Sorted keys and a fixed separator, so the same inputs always produce the same
    bytes and the medium's digest is a stable identity for the action it carries.
    """

    if not action or not plan_hash:
        raise ControlMediaError("a request must name an action and a plan")
    if capability.get("action") != action:
        raise ControlMediaError(
            f"capability authorises {capability.get('action')!r}, not {action!r}"
        )
    if capability.get("plan_hash") != plan_hash:
        raise ControlMediaError("capability is bound to a different plan")
    if len(attestation) < 32:
        raise ControlMediaError("attestation is absent or malformed")

    document = {
        "action": action,
        "plan_hash": plan_hash,
        "capability": capability,
        "attestation": attestation,
        **targets,
    }
    return (
        json.dumps(document, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode("utf-8")


def build(
    workspace: Path,
    destination: Path,
    action: str,
    plan_hash: str,
    capability: dict,
    attestation: str,
    targets: dict | None = None,
) -> dict:
    """Build the control medium and return its content-addressed evidence."""

    if not ADAPTER_SOURCE.is_file():
        raise ControlMediaError(f"adapter script is missing: {ADAPTER_SOURCE}")
    adapter = ADAPTER_SOURCE.read_bytes()
    request = build_request(action, plan_hash, capability, attestation, targets or {})

    destination.unlink(missing_ok=True)
    image = images.create_sparse_image(destination, CONTROL_IMAGE_BYTES, workspace)
    images.make_fat32(image, workspace, label="JSTACKCTL")
    result = images.fat32_transaction(
        image,
        workspace,
        [
            images.Placement("/jstack-adapters.ps1", adapter),
            images.Placement("/jstack-request.json", request),
        ],
    )

    # Read the payloads back out of the built image rather than trusting the
    # transaction's own report, so the digests describe the medium the guest will
    # actually see.
    for name, expected in (
        ("/jstack-adapters.ps1", adapter),
        ("/jstack-request.json", request),
    ):
        observed = images._fat_read(image, name)
        if observed != expected:
            raise ControlMediaError(f"{name} did not read back byte-identically")

    return {
        "image": str(image),
        "image_sha256": lab.sha256_file(image),
        "action": action,
        "plan_hash": plan_hash,
        "adapter_sha256": hashlib.sha256(adapter).hexdigest(),
        "request_sha256": hashlib.sha256(request).hexdigest(),
        "transaction": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--plan-hash", required=True)
    parser.add_argument("--capability", required=True, help="capability JSON document")
    parser.add_argument("--attestation-file", required=True)
    parser.add_argument("--targets", help="JSON object of plan-derived target GUIDs")
    arguments = parser.parse_args()

    try:
        attestation = json.loads(Path(arguments.attestation_file).read_text())["token"]
        evidence = build(
            Path(arguments.workspace),
            Path(arguments.output),
            arguments.action,
            arguments.plan_hash,
            json.loads(arguments.capability),
            attestation,
            json.loads(arguments.targets) if arguments.targets else {},
        )
    except (ControlMediaError, OSError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
