#!/usr/bin/env python3
"""Install the campaign agent into a guest's overlay, offline.

A campaign guest has to run something at logon, and the harness provides no way
to reach a running guest. The obvious alternative is to rebuild the base image
with the agent baked in, which costs forty-five minutes per change and couples
the agent's contents to an image digest that a campaign then has to re-pin.

Writing the agent into the run's own overlay instead is both faster and safer.
The overlay is per-run and disposable, so the base image stays byte-identical and
its pinned digest keeps meaning what it meant. And the write happens *offline*:
the guest is stopped, libguestfs opens the qcow2 directly, and no privilege, loop
device, or mount is involved.

The ordering is the safety property. A stopped guest cannot act, so this can
never race the thing it is configuring, and nothing here is reachable from a
running guest.

Refusing to touch a live overlay is therefore not politeness. A qcow2 being
written has no consistent state, and modifying one would corrupt the very run it
was meant to instrument.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import lab  # noqa: E402
from read_guest_observation import _overlay_is_in_use  # noqa: E402

AGENT_SOURCE = ROOT.parent / "core" / "assets" / "jstack-campaign-agent.ps1"

# Windows runs everything in this directory at logon for the local machine, and
# it needs no scheduled task, no service, and no registry edit. Fewer moving
# parts is the point: each one is something that can silently not happen.
STARTUP_DIRECTORY = "/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"
AGENT_GUEST_PATH = "/jstack-campaign-agent.ps1"


class AgentInstallError(RuntimeError):
    """Raised when the agent cannot be installed into an overlay."""


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise AgentInstallError(f"{name} is not installed")
    return found


def install(overlay: Path, scratch: Path | None = None) -> dict[str, str]:
    """Write the agent and its logon launcher into a stopped guest's overlay."""

    if not overlay.is_file():
        raise AgentInstallError(f"no overlay at {overlay}")
    if not AGENT_SOURCE.is_file():
        raise AgentInstallError(f"agent source is missing: {AGENT_SOURCE}")
    if _overlay_is_in_use(overlay):
        raise AgentInstallError(
            f"the guest still holds {overlay.name} open. The agent is installed "
            "offline, into a stopped guest: modifying a qcow2 that is being "
            "written would corrupt the run it is meant to instrument."
        )

    agent = AGENT_SOURCE.read_bytes()
    # A one-line launcher, because a .ps1 in StartUp opens an editor rather than
    # running. The batch file is what Windows will actually execute.
    launcher = (
        "@echo off\r\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        f"C:{AGENT_GUEST_PATH.replace('/', chr(92))}\r\n"
    ).encode("ascii")

    home = scratch if scratch is not None else overlay.parent
    staging = Path(home) / ".agent-staging"
    staging.mkdir(mode=0o700, exist_ok=True)
    agent_file = staging / "jstack-campaign-agent.ps1"
    launcher_file = staging / "jstack-campaign-agent.bat"
    agent_file.write_bytes(agent)
    launcher_file.write_bytes(launcher)

    try:
        completed = subprocess.run(
            [
                _tool("guestfish"),
                "--rw",
                "-a",
                str(overlay),
                "-i",
                "upload",
                str(agent_file),
                AGENT_GUEST_PATH,
                ":",
                "upload",
                str(launcher_file),
                f"{STARTUP_DIRECTORY}/jstack-campaign-agent.bat",
            ],
            capture_output=True,
            check=False,
            timeout=900,
            env=lab.subprocess_environment(home),
        )
        if completed.returncode != 0:
            raise AgentInstallError(
                "could not install the agent: "
                f"{completed.stderr.decode('utf-8', errors='replace').strip()[:400]}"
            )
    finally:
        agent_file.unlink(missing_ok=True)
        launcher_file.unlink(missing_ok=True)
        staging.rmdir()

    return {
        "overlay": str(overlay),
        "agent_guest_path": AGENT_GUEST_PATH,
        "agent_sha256": hashlib.sha256(agent).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        "startup_entry": f"{STARTUP_DIRECTORY}/jstack-campaign-agent.bat",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--overlay", required=True)
    arguments = parser.parse_args()

    try:
        evidence = install(Path(arguments.overlay))
    except (AgentInstallError, OSError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
