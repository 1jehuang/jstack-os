#!/usr/bin/env python3
"""Read a guest adapter's observation back out of the run's overlay.

An adapter has to report what it did, and the obvious ways to let it are all
ways of putting a hole in the seal: a port forward, a guest agent, a shared
folder. Each would give code inside the guest a live channel to the host, and
the guest is the component being deliberately exposed to a real mutation.

There is a return path that needs none of them. The guest already writes to its
own copy-on-write overlay, so an adapter writing its observation to a file inside
the guest has, by construction, written it into a qcow2 on this host. Reading it
back *after the guest has stopped* is an offline operation on a disk image: the
guest is not running, nothing is listening, and libguestfs needs no privilege, no
loop device, and no mount.

That ordering is the safety property, not an implementation detail. A live guest
cannot reach the host because there is nothing to reach, and a stopped guest
cannot act at all. The observation is bytes left behind, which is exactly the
same relationship the base-image inspection already has with the image it checks.

The observation is parsed defensively for the same reason the harness never
trusts an exit code: it was produced inside a machine that was being mutated, so
it is a claim to be checked against the plan, never a fact.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import lab  # noqa: E402

# Where an adapter is told to leave its observation inside the guest.
OBSERVATION_GUEST_PATH = "/jstack-observation.json"

# An observation is a small JSON document. Anything larger is malformed, and
# reading it unbounded would let a compromised guest exhaust host memory.
MAX_OBSERVATION_BYTES = 256 * 1024


class ObservationError(RuntimeError):
    """Raised when an observation cannot be read or does not agree with the plan."""


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise ObservationError(f"{name} is not installed")
    return found


def _overlay_is_in_use(overlay: Path) -> bool:
    """Report whether a guest still holds this overlay open.

    qcow2 carries a write lock, so a running guest makes the image unreadable.
    Detecting that here means the caller is told the guest is still up, rather
    than being handed a `qemu-img info exited with error status 1` that names the
    wrong component. This exact misattribution has already cost this build path
    hours, so it is worth one extra check.
    """

    probe = shutil.which("qemu-img")
    if probe is None:
        return False
    completed = subprocess.run(
        [probe, "info", str(overlay)],
        capture_output=True,
        check=False,
        timeout=60,
        env=lab.subprocess_environment(overlay.parent),
    )
    if completed.returncode == 0:
        return False
    message = completed.stderr.decode("utf-8", errors="replace").lower()
    return "lock" in message or "in use" in message


def read_observation(
    overlay: Path, guest_path: str = OBSERVATION_GUEST_PATH, scratch: Path | None = None
) -> bytes:
    """Extract one file from a stopped guest's overlay.

    Refuses to run against an overlay whose guest may still be live: a qcow2 that
    is being written has no consistent state to read, and a result taken from one
    would be a guess presented as evidence.
    """

    if not overlay.is_file():
        raise ObservationError(f"no overlay at {overlay}")

    if _overlay_is_in_use(overlay):
        raise ObservationError(
            f"the guest still holds {overlay.name} open. An observation must be "
            "read after the guest has stopped: a qcow2 being written has no "
            "consistent state, and a result taken from one would be a guess "
            "presented as evidence. Shut the guest down and read it again."
        )

    home = scratch if scratch is not None else overlay.parent
    completed = subprocess.run(
        [
            _tool("guestfish"),
            "--ro",
            "-a",
            str(overlay),
            "-i",
            "download",
            guest_path,
            "/dev/stdout",
        ],
        capture_output=True,
        check=False,
        timeout=600,
        env=lab.subprocess_environment(home),
    )
    if completed.returncode != 0:
        raise ObservationError(
            f"could not read {guest_path} from the overlay: "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()[:300]}"
        )
    if len(completed.stdout) > MAX_OBSERVATION_BYTES:
        raise ObservationError(
            f"observation is {len(completed.stdout)} bytes, over the "
            f"{MAX_OBSERVATION_BYTES} cap"
        )
    return completed.stdout


def verify_observation(raw: bytes, request: dict) -> dict:
    """Check an observation against the request that authorised it.

    The guest was being mutated while it wrote this, so nothing in it is taken on
    trust. An observation that describes a different action, a different plan, or
    a different target is a report about something nobody authorised, which is
    strictly worse than no report.
    """

    try:
        observation = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObservationError(f"observation is not valid JSON: {error}") from error
    if not isinstance(observation, dict):
        raise ObservationError("observation must be a JSON object")

    for field, expected in (
        ("action", request["action"]),
        ("plan_hash", request["plan_hash"]),
    ):
        if observation.get(field) != expected:
            raise ObservationError(
                f"observation reports {field}={observation.get(field)!r}, "
                f"but the request authorised {expected!r}"
            )

    # A postcondition is the point of the observation. An adapter that reports
    # success without one has reported only that it did not crash.
    if "postcondition" not in observation:
        raise ObservationError(
            "observation carries no postcondition, so it reports only that the "
            "adapter did not crash"
        )
    return observation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--overlay", required=True)
    parser.add_argument("--request", required=True, help="the dispatch document")
    parser.add_argument("--guest-path", default=OBSERVATION_GUEST_PATH)
    arguments = parser.parse_args()

    try:
        request = json.loads(Path(arguments.request).read_text(encoding="utf-8"))
        raw = read_observation(Path(arguments.overlay), arguments.guest_path)
        observation = verify_observation(raw, request)
    except (ObservationError, OSError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
