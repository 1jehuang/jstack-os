#!/usr/bin/env python3
"""Run one campaign step: one fresh guest, one authorised action, one observation.

This is the first tool that closes the loop the harness pieces were built for:

1. allocate a run id and mint its disposable-VM attestation;
2. build the read-only control medium carrying exactly one request;
3. create the run's fresh overlay over the immutable base image and, while no
   guest exists, write the campaign agent into it offline;
4. launch through `runner.prepare_launch`/`runner.launch`, which audits the
   pinned block graph while the guest is paused and only then continues it;
5. wait for the guest to power itself off (the agent's completion signal), or
   kill it at the deadline;
6. read the agent's observation out of the stopped overlay and check it
   against the request that authorised it.

Every step is an existing reviewed component. This file only sequences them and
records what happened in the run's evidence directory. A harness exit code is
never success evidence, so the result is the verified observation, not the
return value of QEMU.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import lab  # noqa: E402
import runner  # noqa: E402
import build_control_media  # noqa: E402
import install_campaign_agent  # noqa: E402
import mint_disposable_attestation  # noqa: E402
import read_guest_observation  # noqa: E402

DEFAULT_PROFILE = "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0"
DEFAULT_SCENARIO = "secureboot-tpm-bitlocker-off"
DEFAULT_RECORD_DISK = "base-windows-11-enterprise-25h2-eval-en-us-x64.qcow2"
DEFAULT_ISO = "windows-11-enterprise-25h2-eval-en-us-x64.iso"

# A cold boot of the base image to an idle SYSTEM task is a few minutes under
# KVM. The deadline is generous so a slow host is not reported as a failure,
# and finite so a wedged guest cannot hold the run forever.
DEFAULT_DEADLINE_SECONDS = 20 * 60


class CampaignStepError(RuntimeError):
    """Raised when a campaign step cannot produce a verified observation."""


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def run_step(
    workspace: Path,
    request: dict[str, Any],
    *,
    profile_id: str = DEFAULT_PROFILE,
    scenario_id: str = DEFAULT_SCENARIO,
    deadline_seconds: int = DEFAULT_DEADLINE_SECONDS,
    run_id: str | None = None,
) -> dict[str, Any]:
    workspace = lab.safe_workspace(workspace, lab.require_scratch_root())
    launch_directory = workspace / "launch"
    resolved_inputs = json.loads((launch_directory / "resolved-inputs.json").read_text())
    input_files = json.loads((launch_directory / "input-files.json").read_text())
    disk = workspace / DEFAULT_RECORD_DISK
    iso = workspace / DEFAULT_ISO

    run_id = run_id or f"step-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}"
    plan_hash = str(request["plan_hash"])

    # The attestation and medium are bound to the run id, and the runner only
    # creates the run directory itself, so they are staged in a sibling
    # directory and copied into the evidence afterwards.
    staging = workspace / "campaign-staging" / run_id
    staging.mkdir(mode=0o700, parents=True, exist_ok=False)
    attestation = mint_disposable_attestation.write(staging, run_id, plan_hash)
    medium_path = staging / "control.img"
    medium = build_control_media.build(
        workspace,
        medium_path,
        str(request["action"]),
        plan_hash,
        dict(request["capability"]),
        attestation["token"],
        dict(request.get("targets", {})),
    )
    os.chmod(medium_path, 0o400)

    agent_evidence: dict[str, Any] = {}

    def hook(overlay: Path, _run_directory: Path, _run_id: str) -> None:
        agent_evidence.update(install_campaign_agent.install(overlay, scratch=staging))

    plan = runner.prepare_launch(
        workspace,
        disk,
        iso,
        profile_id=profile_id,
        scenario_id=scenario_id,
        resolved_inputs=resolved_inputs,
        input_files=input_files,
        run_id=run_id,
        control_media=medium_path,
        overlay_hook=hook,
    )
    evidence = plan.evidence_directory
    started = time.time()
    outcome: dict[str, Any] = {"run_id": run_id, "request": request}
    try:
        result: dict[str, Any] = {}

        def target() -> None:
            try:
                result["exit"] = runner.launch(plan)
            except BaseException as error:  # recorded, not swallowed
                result["error"] = repr(error)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(deadline_seconds)
        if thread.is_alive():
            # The guest never powered off. Kill QEMU through its QMP socket so
            # the overlay is released, and record the timeout as the outcome.
            try:
                with runner.QMPClient(plan.qmp_socket) as qmp:
                    qmp.execute("quit")
            except Exception:
                pass
            thread.join(60)
            outcome["timed_out"] = True
        outcome["qemu"] = result
    finally:
        plan.close()
    outcome["elapsed_seconds"] = round(time.time() - started, 1)

    overlay = plan.run_directory / "disk-overlay.qcow2"
    try:
        raw = read_guest_observation.read_observation(overlay, scratch=staging)
        observation = read_guest_observation.verify_observation(raw, request)
        outcome["observation"] = observation
        outcome["observation_sha256"] = hashlib.sha256(raw).hexdigest()
        outcome["verified"] = observation.get("status") == "completed"
    except read_guest_observation.ObservationError as error:
        outcome["observation_error"] = str(error)
        outcome["verified"] = False

    outcome["control_medium"] = medium
    outcome["agent"] = agent_evidence
    _write_json(evidence / "campaign-step.json", outcome)
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--request", required=True, help="dispatch document JSON")
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--deadline-seconds", type=int, default=DEFAULT_DEADLINE_SECONDS)
    parser.add_argument("--run-id")
    arguments = parser.parse_args()
    try:
        request = json.loads(Path(arguments.request).read_text(encoding="utf-8"))
        outcome = run_step(
            Path(arguments.workspace),
            request,
            profile_id=arguments.profile,
            scenario_id=arguments.scenario,
            deadline_seconds=arguments.deadline_seconds,
            run_id=arguments.run_id,
        )
    except (CampaignStepError, lab.LabSafetyError, OSError, KeyError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 0 if outcome.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
