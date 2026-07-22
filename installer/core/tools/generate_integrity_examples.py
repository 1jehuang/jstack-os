#!/usr/bin/env python3
"""Generate hash-consistent confirmation, journal, and handoff examples."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--display", type=Path, required=True)
    parser.add_argument("--state-model", type=Path, required=True)
    parser.add_argument("--staging-evidence", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    plan = load(args.plan)
    display = load(args.display)
    state_model = load(args.state_model)
    staging_evidence = load(args.staging_evidence)
    release_manifest = load(args.release_manifest)
    graph_model_id = state_model.get("model_id")
    if graph_model_id != "jstack-no-usb-dual-boot-v1":
        parser.error(f"unexpected executable state-model id: {graph_model_id!r}")
    if plan.get("body", {}).get("state_model_id") != graph_model_id:
        parser.error("plan state_model_id does not match the executable state graph")
    confirmation = {
        "schema_version": 1,
        "plan_hash": plan["plan_hash"],
        "display_digest": digest(display),
        "confirmed_at_unix_ms": 1800000001000,
        "authorization": "explicit_user_confirmation",
    }
    intent = {
        "schema_version": 1,
        "sequence": 0,
        "previous_record_hash": None,
        "actor": "windows_bootstrap",
        "transition_id": "create_installer_entry",
        "record_type": "action_intent",
        "precondition_hash": "11" * 32,
        "postcondition_hash": None,
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    committed = {
        "schema_version": 1,
        "sequence": 1,
        "previous_record_hash": digest(intent),
        "actor": "windows_bootstrap",
        "transition_id": "create_installer_entry",
        "record_type": "action_committed",
        "precondition_hash": "11" * 32,
        "postcondition_hash": "22" * 32,
        "plan_hash": plan["plan_hash"],
        "created_objects": [
            {"kind": "boot_entry", "stable_id": "uefi:Boot0007"}
        ],
    }
    loader_advanced = {
        "schema_version": 1,
        "sequence": 2,
        "previous_record_hash": digest(committed),
        "actor": "windows_bootstrap",
        "transition_id": "create_installer_entry",
        "record_type": "state_advanced",
        "precondition_hash": "22" * 32,
        "postcondition_hash": digest("windows.installer_loader_staged"),
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    reboot_intent = {
        "schema_version": 1,
        "sequence": 3,
        "previous_record_hash": digest(loader_advanced),
        "actor": "windows_bootstrap",
        "transition_id": "reboot_to_installer",
        "record_type": "action_intent",
        "precondition_hash": "33" * 32,
        "postcondition_hash": None,
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    reboot_committed = {
        "schema_version": 1,
        "sequence": 4,
        "previous_record_hash": digest(reboot_intent),
        "actor": "windows_bootstrap",
        "transition_id": "reboot_to_installer",
        "record_type": "action_committed",
        "precondition_hash": "33" * 32,
        "postcondition_hash": "44" * 32,
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    state = "windows.reboot_to_installer_pending"
    state_advanced = {
        "schema_version": 1,
        "sequence": 5,
        "previous_record_hash": digest(reboot_committed),
        "actor": "windows_bootstrap",
        "transition_id": "reboot_to_installer",
        "record_type": "state_advanced",
        "precondition_hash": "44" * 32,
        "postcondition_hash": digest(state),
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    journal = [
        intent,
        committed,
        loader_advanced,
        reboot_intent,
        reboot_committed,
        state_advanced,
    ]
    handoff = {
        "schema_version": 1,
        "graph_model_id": plan["body"]["state_model_id"],
        "control_state": state,
        "journal_head_hash": digest(state_advanced),
        "release_manifest_hash": plan["body"]["release_manifest_hash"],
        "staging_evidence_hash": digest(staging_evidence),
        "plan_hash": plan["plan_hash"],
        "disk_guid": plan["body"]["disk_guid"],
        "partition_phase": "windows_handoff",
        "partition_fingerprint": plan["body"]["partition_fingerprints"]["windows_handoff"],
        "intended_boot_target": "installer",
        "nonce": "fixture-nonce-1",
    }
    artifacts_by_role = {
        artifact["role"]: artifact for artifact in release_manifest["signed"]["artifacts"]
    }
    partitions_by_role = {
        partition["role"]: partition for partition in plan["body"]["created_partitions"]
    }
    destination_intent = {
        "schema_version": 1,
        "graph_model_id": graph_model_id,
        "transition_id": "copy_verified_payload",
        "actor": "windows_bootstrap",
        "plan_hash": plan["plan_hash"],
        "staging_evidence_hash": digest(staging_evidence),
        "partition_phase": "windows_handoff",
        "partition_fingerprint": plan["body"]["partition_fingerprints"]["windows_handoff"],
        "artifacts": [],
    }
    for role, placement in [
        ("installer_uki", "xbootldr_installer_uki"),
        ("offline_system_image", "xbootldr_offline_system_image"),
        ("recovery_uki", "xbootldr_recovery_uki"),
    ]:
        artifact = artifacts_by_role[role]
        destination_intent["artifacts"].append(
            {
                "artifact": {
                    "manifest_digest": plan["body"]["release_manifest_hash"],
                    "role": role,
                    "sha256": artifact["sha256"],
                    "size_bytes": artifact["size_bytes"],
                },
                "destination": {
                    "disk_guid": plan["body"]["disk_guid"],
                    "partition_guid": partitions_by_role["xbootldr"]["partition_guid"],
                    "placement": placement,
                    "transform": "exact_file_copy",
                },
            }
        )
    destination_action_intent = {
        "schema_version": 1,
        "sequence": 0,
        "previous_record_hash": None,
        "actor": destination_intent["actor"],
        "transition_id": destination_intent["transition_id"],
        "record_type": "action_intent",
        "precondition_hash": digest(destination_intent),
        "postcondition_hash": None,
        "plan_hash": plan["plan_hash"],
        "created_objects": [],
    }
    destination_commit = {
        "schema_version": 1,
        "graph_model_id": graph_model_id,
        "transition_id": destination_intent["transition_id"],
        "actor": destination_intent["actor"],
        "plan_hash": plan["plan_hash"],
        "intent_hash": digest(destination_intent),
        "action_intent_record_hash": digest(destination_action_intent),
        "artifacts": [
            {
                "artifact": item["artifact"],
                "destination": item["destination"],
                "written_size_bytes": item["artifact"]["size_bytes"],
                "written_sha256": item["artifact"]["sha256"],
            }
            for item in destination_intent["artifacts"]
        ],
    }
    write(args.output / "example-confirmation.json", confirmation)
    write(args.output / "example-journal-record.json", intent)
    write(args.output / "example-journal-chain.json", journal)
    write(args.output / "example-handoff.json", handoff)
    write(args.output / "example-destination-intent.json", destination_intent)
    write(args.output / "example-destination-commit.json", destination_commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
