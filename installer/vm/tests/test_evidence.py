from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("jstack_evidence_verify", ROOT / "evidence" / "verify.py")
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)

VM_IDENTITY = {
    "vm_id": "vm-evidence-1",
    "machine_uuid": "12345678-1234-4123-8123-123456789abc",
    "smbios_uuid": "12345678-1234-4123-8123-123456789abc",
    "disk_serial": "disk-evidence-1",
}
INITIAL_GUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
FINAL_GUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
BOOT_VOLUME_UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
_CAMPAIGN_TRACE_TEMPLATE_CACHE: dict[tuple[str, ...], tuple[list[Any], str]] = {}


def canonical(value: Any) -> bytes:
    return verify.canonical_json_bytes(value)


def _path_steps(
    graph: dict[str, Any],
    start: str,
    targets: set[str],
    *,
    success_only: bool = False,
    forbidden_transition_ids: set[str] | None = None,
) -> tuple[list[Any], str] | None:
    transitions = graph["transitions"]
    forbidden = forbidden_transition_ids or set()
    queue: list[tuple[str, list[Any]]] = [(start, [])]
    visited = {start}
    while queue:
        state, steps = queue.pop(0)
        if state in targets:
            return steps, state
        for transition in transitions:
            if transition["from"] != state or transition["id"] in forbidden:
                continue
            edges: list[tuple[Any, str]] = [(transition["id"], transition["to"])]
            if not success_only and "failure_to" in transition:
                edges.append(
                    (
                        {"transition": transition["id"], "outcome": "failure"},
                        transition["failure_to"],
                    )
                )
            for step, target in edges:
                if target not in visited:
                    visited.add(target)
                    queue.append((target, [*steps, step]))
    return None


def _recovery_outcome(terminal: str) -> str:
    return {
        "terminal.completed": "retry",
        "terminal.rolled_back": "rollback",
        "terminal.manual_recovery": "manual-recovery",
        "terminal.cancelled": "rejected",
        "terminal.unsupported": "rejected",
    }[terminal]


def _campaign_trace(
    graph: dict[str, Any], category: str, record: dict[str, Any]
) -> dict[str, Any]:
    case_key = (
        graph["model_id"],
        category,
        record.get("transition_id", ""),
        record.get("boundary", ""),
        record.get("edge_id", ""),
        record.get("class", ""),
        record.get("checkpoint", ""),
        record.get("recovery_outcome", ""),
    )
    cached = _CAMPAIGN_TRACE_TEMPLATE_CACHE.get(case_key)
    if cached is not None:
        steps, terminal = cached
        if category in ("interruption_runs", "failure_edge_runs"):
            record["recovery_outcome"] = _recovery_outcome(terminal)
        return {
            "id": record["run_id"],
            "description": f"Canonical {category} graph execution for {record['run_id']}",
            "steps": copy.deepcopy(steps),
            "expected_terminal": terminal,
        }

    state_model = verify._state_model_tool()
    transitions = {item["id"]: item for item in graph["transitions"]}
    initial = graph["initial_state"]
    recovery_terminals = {
        "terminal.completed",
        "terminal.rolled_back",
        "terminal.manual_recovery",
    }
    if category in ("happy_path_runs", "fresh_base_reconstruction_runs"):
        result = _path_steps(graph, initial, {"terminal.completed"}, success_only=True)
        assert result is not None
        steps, terminal = result
    elif category == "interruption_runs":
        transition = transitions[record["transition_id"]]
        prefix = _path_steps(graph, initial, {transition["from"]}, success_only=True)
        assert prefix is not None
        boundary_index = verify.INTERRUPTION_BOUNDARIES.index(record["boundary"])
        preferred_outcomes = {
            0: ("interrupted_precondition",),
            1: ("interrupted_precondition",),
            2: ("interrupted_precondition", "interrupted_divergent"),
            3: ("interrupted_divergent", "interrupted_postcondition"),
            4: ("interrupted_postcondition",),
            5: ("interrupted_postcondition",),
            6: ("interrupted_postcondition",),
            7: ("interrupted_divergent", "interrupted_postcondition"),
        }[boundary_index]
        actions = state_model.index_by_id(graph["actions"])
        selected = None
        for outcome in preferred_outcomes:
            observed = outcome.removeprefix("interrupted_")
            resumed = state_model.reconcile_interruption(transition, actions, observed)
            suffix = _path_steps(graph, resumed, recovery_terminals)
            if suffix is not None:
                selected = (outcome, suffix)
                break
        assert selected is not None
        outcome, (suffix_steps, terminal) = selected
        steps = [
            *prefix[0],
            {"transition": transition["id"], "outcome": outcome},
            *suffix_steps,
        ]
        record["recovery_outcome"] = _recovery_outcome(terminal)
    elif category == "failure_edge_runs":
        transition = transitions[record["edge_id"]]
        prefix = _path_steps(graph, initial, {transition["from"]}, success_only=True)
        assert prefix is not None
        suffix = _path_steps(graph, transition["failure_to"], recovery_terminals)
        assert suffix is not None
        suffix_steps, terminal = suffix
        steps = [
            *prefix[0],
            {"transition": transition["id"], "outcome": "failure"},
            *suffix_steps,
        ]
        record["recovery_outcome"] = _recovery_outcome(terminal)
    else:
        desired = {
            "retry": {"terminal.completed"},
            "advance": {"terminal.completed"},
            "rollback": {"terminal.rolled_back"},
            "manual-recovery": {"terminal.manual_recovery"},
            "rejected": {
                "terminal.manual_recovery",
                "terminal.unsupported",
                "terminal.cancelled",
            },
        }[record["recovery_outcome"]]
        result = _path_steps(graph, initial, desired)
        assert result is not None
        steps, terminal = result
    _CAMPAIGN_TRACE_TEMPLATE_CACHE[case_key] = (copy.deepcopy(steps), terminal)
    return {
        "id": record["run_id"],
        "description": f"Canonical {category} graph execution for {record['run_id']}",
        "steps": steps,
        "expected_terminal": terminal,
    }


def build_campaign_bundles(
    graph: dict[str, Any], coverage: dict[str, Any]
) -> dict[tuple[str, str], dict[str, Any]]:
    _, trace_schema_digest = verify._trace_schema()
    inputs = coverage["inputs"]
    bundles: dict[tuple[str, str], dict[str, Any]] = {}
    for category in verify.CAMPAIGN_RUN_SECTIONS:
        for record in coverage[category]:
            trace = _campaign_trace(graph, category, record)
            terminal = trace["expected_terminal"]
            state_digest = hashlib.sha256(
                canonical({"run_id": record["run_id"], "state": "initial"})
            ).hexdigest()
            rollback = (
                {
                    "initial_state_digest": state_digest,
                    "restored_state_digest": state_digest,
                    "retained_jstack_objects": [],
                    "windows_security_restored": True,
                }
                if terminal == "terminal.rolled_back"
                else None
            )
            bundle = {
                "contract": verify.CAMPAIGN_RUN_CONTRACT,
                "schema_version": 1,
                "category": category,
                "run": verify._campaign_claim(record),
                "identity": {
                    "run_id": record["run_id"],
                    "profile_id": record["profile_id"],
                    "input_digest": inputs["combined_digest"],
                    "graph_digest": inputs["graph_digest"],
                    "evidence_verifier_digest": inputs["evidence_verifier_digest"],
                },
                "trace": trace,
                "rollback": rollback,
                "verification": {
                    "verifier_digest": inputs["evidence_verifier_digest"],
                    "trace_schema_digest": trace_schema_digest,
                },
            }
            record.pop("passed", None)
            record["evidence_bundle_digest"] = hashlib.sha256(canonical(bundle)).hexdigest()
            bundles[(category, record["run_id"])] = bundle
    return bundles


def _write_manifest(root: Path, value: dict[str, Any]) -> None:
    (root / "evidence.json").write_bytes(canonical(value))


def build_bundle(root: Path) -> dict[str, Any]:
    artifacts_dir = root / "artifacts"
    artifacts_dir.mkdir(parents=True)
    artifacts: list[dict[str, Any]] = []
    by_role: dict[str, dict[str, Any]] = {}
    for index, role in enumerate(verify.REQUIRED_ARTIFACT_ROLES):
        content = f"evidence:{index}:{role}\n".encode()
        relative = f"artifacts/{index:02d}-{role}.txt"
        (root / relative).write_bytes(content)
        record = {
            "id": role,
            "role": role,
            "path": relative,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        artifacts.append(record)
        by_role[role] = record

    def set_artifact(role: str, content: bytes, filename: str | None = None) -> None:
        record = by_role[role]
        old_path = root / record["path"]
        relative = record["path"] if filename is None else f"artifacts/{filename}"
        if relative != record["path"]:
            old_path.unlink()
            record["path"] = relative
        (root / relative).write_bytes(content)
        record["size"] = len(content)
        record["sha256"] = hashlib.sha256(content).hexdigest()

    installer_root = ROOT.parent
    graph_raw = (installer_root / "model" / "installer-state-graph.json").read_bytes()
    graph = json.loads(graph_raw)
    set_artifact("state-model", graph_raw)
    graph_digest = hashlib.sha256(graph_raw).hexdigest()
    graph_id = graph["model_id"]
    _, mutation_transitions, failure_edges = verify._derive_mutation_transitions(graph)

    release_template = json.loads(
        (installer_root / "core" / "fixtures" / "signed-release-manifest.json").read_text()
    )
    signed = copy.deepcopy(release_template["signed"])
    signed["state_model_id"] = graph_id
    signed["state_model_sha256"] = graph_digest
    body = verify.canonical_json_document_bytes(signed)
    release_message = (
        verify.RELEASE_SIGNATURE_DOMAIN + len(body).to_bytes(8, "big") + body
    )
    release_digest = hashlib.sha256(release_message).hexdigest()
    private_keys = [Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32) for seed in (1, 2)]
    trusted_keys = []
    signatures = []
    for private_key in private_keys:
        public_bytes = private_key.public_key().public_bytes_raw()
        key_id = hashlib.sha256(public_bytes).hexdigest()
        trusted_keys.append(
            {"key_id": key_id, "public_key_hex": public_bytes.hex(), "channels": ["stable"]}
        )
        signatures.append(
            {"key_id": key_id, "signature_hex": private_key.sign(release_message).hex()}
        )
    trusted_keys.sort(key=lambda item: item["key_id"])
    signatures.sort(key=lambda item: item["key_id"])
    release_envelope = {"signatures": signatures, "signed": signed}
    set_artifact("release-manifest", verify.canonical_json_document_bytes(release_envelope))

    release_policy = {
        "schema_version": 1,
        "channel": "stable",
        "architecture": "x86_64",
        "state_model_id": graph_id,
        "state_model_sha256": graph_digest,
        "installer_protocol_version": 1,
        "trusted_time_unix_secs": signed["issued_at_unix_secs"],
        "maximum_future_skew_secs": 300,
        "maximum_manifest_lifetime_secs": 86400,
        "signature_threshold": 2,
        "trusted_keys": trusted_keys,
    }
    set_artifact("release-policy", canonical(release_policy))

    acceptance = {
        "schema_version": 1,
        "channel": signed["channel"],
        "state_model_sha256": graph_digest,
        "highest_sequence": signed["release_sequence"],
        "manifest_digest": release_digest,
        "issued_at_unix_secs": signed["issued_at_unix_secs"],
        "trusted_time_unix_secs": signed["issued_at_unix_secs"],
    }
    set_artifact("release-acceptance", verify.canonical_json_document_bytes(acceptance))
    acceptance_digest = by_role["release-acceptance"]["sha256"]

    staging = {
        "schema_version": 1,
        "acceptance_state_hash": acceptance_digest,
        "manifest_digest": release_digest,
        "artifacts": [
            {"role": item["role"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}
            for item in signed["artifacts"]
        ],
    }
    set_artifact("staging-evidence", canonical(staging))

    disk_guid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    plan = json.loads((installer_root / "core" / "generated" / "example-plan.json").read_text())
    plan["body"]["release_manifest_hash"] = release_digest
    plan["body"]["state_model_id"] = graph_id
    plan["body"]["disk_guid"] = disk_guid
    plan["plan_hash"] = hashlib.sha256(
        verify.canonical_json_document_bytes(plan["body"])
    ).hexdigest()
    confirmation = json.loads(
        (installer_root / "core" / "generated" / "example-confirmation.json").read_text()
    )
    confirmation["plan_hash"] = plan["plan_hash"]
    confirmation["display_digest"] = verify._canonical_sha256(verify._plan_display(plan))
    confirmed_plan = {"schema_version": 1, "plan": plan, "confirmation": confirmation}
    set_artifact("confirmed-plan", canonical(confirmed_plan))

    disk_identity = {
        "schema_version": 1,
        "disk_guid": disk_guid,
        "disk_serial": VM_IDENTITY["disk_serial"],
    }
    set_artifact("disk-identity", canonical(disk_identity))

    core_journal = json.loads(
        (installer_root / "core" / "generated" / "example-journal-chain.json").read_text()
    )
    previous_hash = None
    for index, record in enumerate(core_journal):
        record["sequence"] = index
        record["previous_record_hash"] = previous_hash
        record["plan_hash"] = plan["plan_hash"]
        previous_hash = hashlib.sha256(
            verify.canonical_json_document_bytes(record)
        ).hexdigest()
    set_artifact("journal", canonical(core_journal))

    handoff = json.loads(
        (installer_root / "core" / "generated" / "example-handoff.json").read_text()
    )
    handoff.update(
        {
            "graph_model_id": graph_id,
            "journal_head_hash": previous_hash,
            "release_manifest_hash": release_digest,
            "staging_evidence_hash": by_role["staging-evidence"]["sha256"],
            "plan_hash": plan["plan_hash"],
            "disk_guid": disk_guid,
        }
    )
    set_artifact("handoff", canonical(handoff))

    iso_bytes = b"synthetic-windows-iso-fixture\n"
    media = json.loads(
        (installer_root / "vm" / "profiles" / "windows-10-pro-22h2-en-us.media.json").read_text()
    )
    media["iso"]["size_bytes"] = len(iso_bytes)
    media["iso"]["sha256"] = hashlib.sha256(iso_bytes).hexdigest()
    media["authentication"]["published_iso_sha256"] = media["iso"]["sha256"]
    set_artifact("windows-iso", iso_bytes, media["iso"]["filename"])
    set_artifact("official-media-record", canonical(media))

    resolved_profile = json.loads(
        (installer_root / "vm" / "profiles" / "windows-10-pro-22h2-en-us.profile.json").read_text()
    )
    resolved_profile["status"] = "resolved"
    resolved_profile["guest"]["installed_build"]["state"] = "resolved"
    resolved_profile["guest"]["installed_build"]["value"] = "19045.2965"
    resolved_profile["media"]["record_sha256"] = by_role["official-media-record"]["sha256"]
    for item in resolved_profile["required_inputs"]:
        item["state"] = "resolved"
        item["value"] = hashlib.sha256(f"resolved:{item['id']}".encode()).hexdigest()
    set_artifact("resolved-profile-record", canonical(resolved_profile))

    identity = {
        "graph_digest": graph_digest,
        "release_digest": release_digest,
        "release_acceptance_digest": acceptance_digest,
        "staging_evidence_digest": by_role["staging-evidence"]["sha256"],
        "plan_digest": plan["plan_hash"],
        "disk_identity": by_role["disk-identity"]["sha256"],
        "release_policy_digest": by_role["release-policy"]["sha256"],
        "profile_digest": by_role["resolved-profile-record"]["sha256"],
        "media_digest": by_role["official-media-record"]["sha256"],
        "journal_digest": by_role["journal"]["sha256"],
        "handoff_digest": by_role["handoff"]["sha256"],
    }

    profile_ids = sorted(verify.SUPPORTED_PROFILES)
    profile_id = profile_ids[0]
    profile = verify.SUPPORTED_PROFILES[profile_id]

    def snapshot(label: str, observed_at: str, guids: list[str], jstack: bool) -> dict[str, Any]:
        enabled = profile["bitlocker"]
        present = profile["tpm"] == "2.0"
        return {
            "observed_at": observed_at,
            **VM_IDENTITY,
            "disk_identity": identity["disk_identity"],
            "firmware": {
                "artifact_id": f"firmware-{label}",
                "uefi": True,
                "secure_boot": profile["secure_boot"],
                "setup_mode": False,
            },
            "tpm": {
                "artifact_id": f"tpm-{label}",
                "present": present,
                "version": profile["tpm"],
                "ready": present,
            },
            "bitlocker": {
                "artifact_id": f"bitlocker-{label}",
                "enabled": enabled,
                "protection_on": enabled,
                "recovery_key_confirmed": enabled,
            },
            "disk": {
                "artifact_id": f"disk-inspection-{label}",
                "partition_table": "gpt",
                "logical_sector_size": 512,
                "total_bytes": 64 * 1024 * 1024,
                "serial": VM_IDENTITY["disk_serial"],
            },
            "gpt": {
                "artifact_id": f"gpt-{label}",
                "primary_header_valid": True,
                "backup_header_valid": True,
                "partition_guids": guids,
            },
            "esp": {
                "artifact_id": f"esp-{label}",
                "filesystem": "fat32",
                "windows_loader_present": True,
                "jstack_loader_present": jstack,
            },
        }

    journal: list[dict[str, Any]] = []
    transition_ids = ["run-created"] + [
        verify.JOURNAL_TRANSITIONS[(before, after)]
        for before, after in zip(verify.HAPPY_JOURNAL_STATES, verify.HAPPY_JOURNAL_STATES[1:])
    ]
    for index, (state, transition_id) in enumerate(zip(verify.HAPPY_JOURNAL_STATES, transition_ids)):
        pre, post = verify.JOURNAL_OBSERVATIONS[state]
        journal.append(
            {
                "id": f"journal-{index}",
                "sequence": index,
                "state": state,
                "transition_id": transition_id,
                "observed_at": f"2026-01-01T00:{index + 1:02d}:00Z",
                **identity_fields(identity),
                **VM_IDENTITY,
                "observed_preconditions": list(pre),
                "observed_postconditions": list(post),
            }
        )

    witness_specs = [
        ("windows-pre-install", "windows", False, r"\EFI\Microsoft\Boot\bootmgfw.efi", "windows-pre-install-boot-witness"),
        ("windows-post-deploy", "windows", False, r"\EFI\Microsoft\Boot\bootmgfw.efi", "windows-post-deploy-boot-witness"),
        ("jstack-first-boot", "jstack", False, r"\EFI\JStack\jstack.efi", "jstack-first-boot-witness"),
        ("cold-boot-windows", "windows", True, r"\EFI\Microsoft\Boot\bootmgfw.efi", "cold-boot-windows-witness"),
        ("cold-boot-jstack", "jstack", True, r"\EFI\JStack\jstack.efi", "cold-boot-jstack-witness"),
    ]
    witness_times = (
        "2026-01-01T00:03:00Z",
        "2026-01-01T00:11:00Z",
        "2026-01-01T00:12:00Z",
        "2026-01-01T00:13:00Z",
        "2026-01-01T00:14:00Z",
    )
    witnesses = []
    for index, (kind, os_name, cold, loader, artifact_id) in enumerate(witness_specs):
        witnesses.append(
            {
                "id": f"witness-{index}",
                "kind": kind,
                "artifact_id": artifact_id,
                "observed_at": witness_times[index],
                "boot_id": f"0000000{index + 1}-0000-4000-8000-00000000000{index + 1}",
                "os": os_name,
                "os_version": "test-version",
                "cold_boot": cold,
                "loader_path": loader,
                "boot_volume_uuid": BOOT_VOLUME_UUID,
                **identity_fields(identity),
                **VM_IDENTITY,
            }
        )

    inputs = {
        "runtime_digest": by_role["runtime"]["sha256"],
        "adapters_digest": by_role["adapters"]["sha256"],
        "graph_digest": by_role["state-model"]["sha256"],
        "release_policy_digest": by_role["release-policy"]["sha256"],
        "boot_artifacts_digest": by_role["boot-artifacts"]["sha256"],
        "vm_harness_digest": by_role["vm-harness"]["sha256"],
        "evidence_verifier_digest": by_role["evidence-verifier"]["sha256"],
    }
    inputs["combined_digest"] = hashlib.sha256(canonical(inputs)).hexdigest()
    digest = inputs["combined_digest"]

    happy = []
    run_counter = 0

    def run_id(prefix: str) -> str:
        nonlocal run_counter
        run_counter += 1
        return f"{prefix}-{run_counter}"

    for pid in profile_ids:
        for index in range(10):
            happy.append(
                {
                    "run_id": "run-main" if pid == profile_id and index == 0 else run_id("happy"),
                    "profile_id": pid,
                    "input_digest": digest,
                    "passed": True,
                    "fresh_overlay": True,
                }
            )

    transitions = [
        {
            "transition_id": transition,
            "applicable_profile_ids": profile_ids,
            "boundaries": list(verify.INTERRUPTION_BOUNDARIES),
        }
        for transition in mutation_transitions
    ]
    interruptions = [
        {
            "run_id": run_id("interrupt"),
            "profile_id": pid,
            "input_digest": digest,
            "passed": True,
            "transition_id": transition,
            "boundary": boundary,
            "abrupt_qemu_termination": True,
            "recovery_outcome": "retry",
        }
        for transition in mutation_transitions
        for pid in profile_ids
        for boundary in verify.INTERRUPTION_BOUNDARIES
    ]
    edges = [
        {"edge_id": edge, "applicable_profile_ids": profile_ids}
        for edge in failure_edges
    ]
    failure_runs = [
        {
            "run_id": run_id("edge"),
            "profile_id": pid,
            "input_digest": digest,
            "passed": True,
            "edge_id": edge,
            "recovery_outcome": "retry",
        }
        for edge in failure_edges
        for pid in profile_ids
    ]
    checkpoints = sorted(verify.POST_MUTATION_CHECKPOINTS)
    fault_cases = []
    fault_runs = []
    for fault_class in verify.MANDATORY_FAULT_CLASSES:
        case_checkpoints = checkpoints if fault_class in ("rollback-request", "rollback-interruption") else ["campaign"]
        fault_cases.append(
            {
                "class": fault_class,
                "applicable_profile_ids": profile_ids,
                "checkpoints": case_checkpoints,
            }
        )
        for pid in profile_ids:
            for checkpoint in case_checkpoints:
                fault_runs.append(
                    {
                        "run_id": run_id("fault"),
                        "profile_id": pid,
                        "input_digest": digest,
                        "passed": True,
                        "class": fault_class,
                        "checkpoint": checkpoint,
                        "recovery_outcome": (
                            "rollback"
                            if fault_class in ("rollback-request", "rollback-interruption")
                            else "rejected"
                        ),
                    }
                )
    base_runs = [
        {
            "run_id": run_id("base"),
            "profile_id": pid,
            "input_digest": digest,
            "passed": True,
            "base_image_reconstructed": True,
        }
        for pid in profile_ids
    ]

    coverage = {
        "supported_profile_ids": profile_ids,
        "inputs": inputs,
        "happy_path_runs": happy,
        "production_transitions": transitions,
        "interruption_runs": interruptions,
        "modeled_failure_edges": edges,
        "failure_edge_runs": failure_runs,
        "post_mutation_checkpoints": checkpoints,
        "mandatory_fault_cases": fault_cases,
        "mandatory_fault_runs": fault_runs,
        "fresh_base_reconstruction_runs": base_runs,
    }
    bundles = build_campaign_bundles(graph, coverage)
    set_artifact(
        "campaign-index", canonical(verify._campaign_index_value(coverage, bundles))
    )
    inputs["campaign_index_digest"] = by_role["campaign-index"]["sha256"]

    manifest = {
        "contract": verify.CONTRACT,
        "schema_version": verify.SCHEMA_VERSION,
        "run": {
            "id": "run-main",
            "scenario_id": "happy-path",
            "profile_id": profile_id,
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:30:00Z",
            "final_outcome": "terminal.completed",
            "source_commit": "d" * 64,
            "clean_tree_digest": by_role["source-tree"]["sha256"],
        },
        "profiles": [copy.deepcopy(verify.SUPPORTED_PROFILES[pid]) for pid in profile_ids],
        "identity": identity,
        "vm_identity": copy.deepcopy(VM_IDENTITY),
        "environment": {
            "windows_iso_source_url": media["acquisition"]["source_page_url"],
            "windows_hash_document_digest": by_role["windows-iso-hash-document"]["sha256"],
            "verified_iso_digest": by_role["windows-iso"]["sha256"],
            "qemu_command_line_artifact_id": "qemu-command-line",
            "base_image_artifact_id": "base-image-identity",
            "overlay_artifact_id": "overlay-identity",
            "ovmf_code_artifact_id": "ovmf-code-identity",
            "ovmf_vars_artifact_id": "ovmf-vars-identity",
            "tpm_state_artifact_id": "tpm-state-identity",
        },
        "artifacts": artifacts,
        "observations": {
            "initial": snapshot("initial", "2026-01-01T00:02:00Z", [INITIAL_GUID], False),
            "final": snapshot("final", "2026-01-01T00:10:00Z", [INITIAL_GUID, FINAL_GUID], True),
        },
        "journal": journal,
        "witnesses": witnesses,
        "fault": {"mode": "none"},
        "coverage": coverage,
    }
    _write_manifest(root, manifest)
    return manifest


def identity_fields(identity: dict[str, Any]) -> dict[str, str]:
    return {field: identity[field] for field in verify.IDENTITY_FIELDS}


def make_recovery_completed(manifest: dict[str, Any]) -> None:
    manifest["run"]["final_outcome"] = "recovery.completed"
    prefix = manifest["journal"][:3]
    common = {
        **identity_fields(manifest["identity"]),
        **manifest["vm_identity"],
    }

    def recovery_record(
        sequence: int, state: str, transition_id: str, observed_at: str
    ) -> dict[str, Any]:
        pre, post = verify.JOURNAL_OBSERVATIONS[state]
        return {
            "id": f"journal-{sequence}",
            "sequence": sequence,
            "state": state,
            "transition_id": transition_id,
            "observed_at": observed_at,
            **common,
            "observed_preconditions": list(pre),
            "observed_postconditions": list(post),
        }

    manifest["journal"] = prefix + [
        recovery_record(3, "recovery.started", "enter-recovery", "2026-01-01T00:04:00Z"),
        recovery_record(4, "recovery.completed", "finish-recovery", "2026-01-01T00:05:00Z"),
    ]
    fault = {
        "mode": "injected",
        "class": "artifact-tamper",
        "trigger": "test trigger",
        "exact_boundary": verify.INTERRUPTION_BOUNDARIES[0],
        "transition_id": manifest["coverage"]["production_transitions"][0]["transition_id"],
        "checkpoint": "campaign",
        "boundary_observation_artifact_id": "serial-output",
        "process_exit_cause": "qemu killed",
        "recovery_outcome": "retry",
        "recovery_observation_artifact_ids": ["log"],
    }
    manifest["fault"] = fault
    current_profile = manifest["run"]["profile_id"]
    for record in manifest["coverage"]["happy_path_runs"]:
        if record["run_id"] == manifest["run"]["id"]:
            record["run_id"] = "happy-replacement"
            break
    for record in manifest["coverage"]["mandatory_fault_runs"]:
        if (
            record["class"] == fault["class"]
            and record["profile_id"] == current_profile
            and record["checkpoint"] == fault["checkpoint"]
        ):
            record["run_id"] = manifest["run"]["id"]
            record["recovery_outcome"] = fault["recovery_outcome"]
            break


def make_rolled_back(manifest: dict[str, Any]) -> None:
    make_recovery_completed(manifest)
    manifest["run"]["final_outcome"] = "terminal.rolled_back"
    terminal = manifest["journal"][-1]
    terminal["state"] = "terminal.rolled_back"
    terminal["transition_id"] = "complete-rollback"
    pre, post = verify.JOURNAL_OBSERVATIONS["terminal.rolled_back"]
    terminal["observed_preconditions"] = list(pre)
    terminal["observed_postconditions"] = list(post)
    manifest["fault"]["recovery_outcome"] = "rollback"
    for record in manifest["coverage"]["mandatory_fault_runs"]:
        if record["run_id"] == manifest["run"]["id"]:
            record["recovery_outcome"] = "rollback"
            break
    initial = manifest["observations"]["initial"]
    final = manifest["observations"]["final"]
    for section in ("firmware", "tpm", "bitlocker", "disk", "gpt", "esp"):
        artifact_id = final[section]["artifact_id"]
        final[section] = copy.deepcopy(initial[section])
        final[section]["artifact_id"] = artifact_id
    manifest["witnesses"] = [manifest["witnesses"][0], manifest["witnesses"][3]]
class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "bundle"
        self.root.mkdir()
        self.manifest = build_bundle(self.root)
        self.base_trust_roots = {
            "trusted_release_policy_digest": self.manifest["identity"]["release_policy_digest"],
            "trusted_profile_digest": self.manifest["identity"]["profile_digest"],
            "trusted_media_digest": self.manifest["identity"]["media_digest"],
            "trusted_campaign_index_digest": self.manifest["coverage"]["inputs"][
                "campaign_index_digest"
            ],
        }
        self.trust_roots = dict(self.base_trust_roots)

    def rewrite(self) -> None:
        _write_manifest(self.root, self.manifest)

    def artifact(self, role: str) -> dict[str, Any]:
        return next(record for record in self.manifest["artifacts"] if record["role"] == role)

    def artifact_json(self, role: str) -> Any:
        return json.loads((self.root / self.artifact(role)["path"]).read_bytes())

    def propagate_identity(self, field: str, digest: str) -> None:
        self.manifest["identity"][field] = digest
        for record in [*self.manifest["journal"], *self.manifest["witnesses"]]:
            record[field] = digest
        if field == "disk_identity":
            for snapshot in self.manifest["observations"].values():
                snapshot["disk_identity"] = digest

    def rewrite_artifact(
        self,
        role: str,
        value: Any,
        *,
        compact_without_lf: bool = False,
        identity_field: str | None = None,
    ) -> str:
        raw = (
            verify.canonical_json_document_bytes(value)
            if compact_without_lf
            else canonical(value)
        )
        return self.rewrite_artifact_bytes(role, raw, identity_field=identity_field)

    def rewrite_artifact_bytes(
        self, role: str, raw: bytes, *, identity_field: str | None = None
    ) -> str:
        record = self.artifact(role)
        (self.root / record["path"]).write_bytes(raw)
        record["size"] = len(raw)
        record["sha256"] = hashlib.sha256(raw).hexdigest()
        if identity_field is not None:
            self.propagate_identity(identity_field, record["sha256"])
        return record["sha256"]

    def refresh_campaign_index(self, *, trust: bool = True) -> str:
        graph = self.artifact_json("state-model")
        bundles = build_campaign_bundles(graph, self.manifest["coverage"])
        digest = self.rewrite_artifact(
            "campaign-index",
            verify._campaign_index_value(self.manifest["coverage"], bundles),
        )
        self.manifest["coverage"]["inputs"]["campaign_index_digest"] = digest
        if trust:
            self.trust_roots["trusted_campaign_index_digest"] = digest
        return digest

    def rewrite_core_journal(self, records: list[dict[str, Any]]) -> None:
        previous_hash = None
        for index, record in enumerate(records):
            record["sequence"] = index
            record["previous_record_hash"] = previous_hash
            previous_hash = verify._canonical_sha256(record)
        self.rewrite_artifact("journal", records, identity_field="journal_digest")
        handoff = self.artifact_json("handoff")
        handoff["journal_head_hash"] = previous_hash
        self.rewrite_artifact("handoff", handoff, identity_field="handoff_digest")

    def rewrite_trusted_campaign_bundle(
        self,
        category: str,
        row_index: int,
        mutate: Callable[[dict[str, Any]], None],
        *,
        bind_digest: bool = True,
    ) -> None:
        campaign_index = self.artifact_json("campaign-index")
        offset = sum(
            len(self.manifest["coverage"][section])
            for section in verify.CAMPAIGN_RUN_SECTIONS
            if section != category
            and verify.CAMPAIGN_RUN_SECTIONS.index(section)
            < verify.CAMPAIGN_RUN_SECTIONS.index(category)
        ) + row_index
        bundle = campaign_index["runs"][offset]["bundle"]
        mutate(bundle)
        if bind_digest:
            self.manifest["coverage"][category][row_index][
                "evidence_bundle_digest"
            ] = hashlib.sha256(canonical(bundle)).hexdigest()
        digest = self.rewrite_artifact("campaign-index", campaign_index)
        self.manifest["coverage"]["inputs"]["campaign_index_digest"] = digest
        self.trust_roots["trusted_campaign_index_digest"] = digest

    def assert_rejected(self, pattern: str, *, refresh_campaign_index: bool = False) -> None:
        if refresh_campaign_index:
            self.refresh_campaign_index()
        self.rewrite()
        with self.assertRaisesRegex(verify.EvidenceError, pattern):
            verify.verify_bundle(self.root, **self.trust_roots)

    def test_minimal_host_independent_bundle_is_accepted(self) -> None:
        accepted = verify.verify_bundle(self.root, **self.trust_roots)
        self.assertEqual(accepted["run"]["id"], "run-main")
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "evidence" / "verify.py"),
                str(self.root),
                "--trusted-release-policy-sha256",
                self.trust_roots["trusted_release_policy_digest"],
                "--trusted-profile-sha256",
                self.trust_roots["trusted_profile_digest"],
                "--trusted-media-sha256",
                self.trust_roots["trusted_media_digest"],
                "--trusted-campaign-index-sha256",
                self.trust_roots["trusted_campaign_index_digest"],
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK run=run-main", result.stdout)

    def test_bundle_cannot_choose_its_own_policy_profile_media_or_campaign_trust_roots(
        self,
    ) -> None:
        cases = (
            ("release-policy", "release_policy_digest", "release-policy"),
            ("resolved-profile-record", "profile_digest", "resolved-profile-record"),
            ("official-media-record", "media_digest", "official-media-record"),
            ("campaign-index", None, "campaign-index"),
        )
        original_manifest = copy.deepcopy(self.manifest)
        original_raw = {
            role: (self.root / self.artifact(role)["path"]).read_bytes()
            for role, _, _ in cases
        }
        for role, identity_field, pattern in cases:
            with self.subTest(role=role):
                self.manifest = copy.deepcopy(original_manifest)
                self.trust_roots = dict(self.base_trust_roots)
                for restore_role, raw in original_raw.items():
                    (self.root / self.artifact(restore_role)["path"]).write_bytes(raw)
                value = json.loads(original_raw[role])
                value["untrusted_bundle_selected_marker"] = True
                self.rewrite_artifact(role, value, identity_field=identity_field)
                self.assert_rejected(
                    f"{pattern} artifact does not match its external trusted digest",
                    refresh_campaign_index=False,
                )

    def test_reviewer_accepted_placeholder_artifact_attack_is_rejected(self) -> None:
        self.rewrite_artifact(
            "release-manifest",
            {"signed": "opaque-release-placeholder", "signatures": []},
            compact_without_lf=True,
        )
        self.assert_rejected("release-manifest.signed must be an object")

    def test_reviewer_zero_overlap_mutation_campaign_attack_is_rejected(self) -> None:
        pseudo = (
            "stage-release",
            "write-gpt",
            "write-esp",
            "write-firmware",
            "deploy-root",
            "commit-handoff",
        )
        graph = self.artifact_json("state-model")
        derived = verify._derive_mutation_transitions(graph)[1]
        self.assertFalse(set(pseudo) & set(derived))
        profiles = self.manifest["coverage"]["supported_profile_ids"]
        digest = self.manifest["coverage"]["inputs"]["combined_digest"]
        self.manifest["coverage"]["production_transitions"] = [
            {
                "transition_id": transition_id,
                "applicable_profile_ids": profiles,
                "boundaries": list(verify.INTERRUPTION_BOUNDARIES),
            }
            for transition_id in pseudo
        ]
        self.manifest["coverage"]["interruption_runs"] = [
            {
                "run_id": f"zero-overlap-{index}",
                "profile_id": profile_id,
                "input_digest": digest,
                "passed": True,
                "transition_id": transition_id,
                "boundary": boundary,
                "abrupt_qemu_termination": True,
                "recovery_outcome": "retry",
            }
            for index, (transition_id, profile_id, boundary) in enumerate(
                (transition_id, profile_id, boundary)
                for transition_id in pseudo
                for profile_id in profiles
                for boundary in verify.INTERRUPTION_BOUNDARIES
            )
        ]
        self.assert_rejected("exactly match graph-derived mutations")

    def test_reviewer_all_witnesses_before_mutation_attack_is_rejected(self) -> None:
        for index, witness in enumerate(self.manifest["witnesses"]):
            witness["observed_at"] = f"2026-01-01T00:03:{index:02d}Z"
        self.assert_rejected("post-deploy witness must follow mutation observation")

    def test_state_model_artifact_duplicate_keys_are_rejected_before_derivation(self) -> None:
        raw = (self.root / self.artifact("state-model")["path"]).read_bytes()
        duplicate = b'{"schema_version":1,' + raw.lstrip()[1:]
        self.rewrite_artifact_bytes(
            "state-model", duplicate, identity_field="graph_digest"
        )
        self.assert_rejected("duplicate JSON object key: 'schema_version'")

    def test_unsigned_threshold_and_mixed_graph_release_are_rejected(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original_raw = (self.root / self.artifact("release-manifest")["path"]).read_bytes()
        cases = (
            (
                "unsigned",
                lambda envelope: envelope.__setitem__("signatures", []),
                "must not be empty",
            ),
            (
                "below threshold",
                lambda envelope: envelope["signatures"].pop(),
                "insufficient valid trusted signatures",
            ),
            (
                "mixed graph",
                lambda envelope: envelope["signed"].__setitem__("state_model_id", "other-model"),
                "different state model id",
            ),
        )
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original_manifest)
                (self.root / self.artifact("release-manifest")["path"]).write_bytes(original_raw)
                envelope = json.loads(original_raw)
                mutate(envelope)
                self.rewrite_artifact(
                    "release-manifest", envelope, compact_without_lf=True
                )
                self.assert_rejected(pattern)

    def test_semantic_chain_rejects_stale_acceptance_staging_plan_journal_and_handoff(self) -> None:
        roles = (
            "release-acceptance",
            "staging-evidence",
            "confirmed-plan",
            "journal",
            "handoff",
        )
        original_manifest = copy.deepcopy(self.manifest)
        original_raw = {
            role: (self.root / self.artifact(role)["path"]).read_bytes() for role in roles
        }
        cases = (
            ("release-acceptance", "release_acceptance_digest", True, "manifest_digest", "stale or bound"),
            ("staging-evidence", "staging_evidence_digest", False, "manifest_digest", "different signed release"),
            ("confirmed-plan", None, False, "confirmation.plan_hash", "confirmation is stale"),
            ("journal", "journal_digest", False, "previous_record_hash", "hash chain is broken"),
            ("handoff", "handoff_digest", False, "release_manifest_hash", "stale or mixed"),
        )
        for role, identity_field, compact_without_lf, target, pattern in cases:
            with self.subTest(role=role):
                self.manifest = copy.deepcopy(original_manifest)
                for restore_role, raw in original_raw.items():
                    (self.root / self.artifact(restore_role)["path"]).write_bytes(raw)
                value = json.loads(original_raw[role])
                if target == "confirmation.plan_hash":
                    value["confirmation"]["plan_hash"] = "0" * 64
                elif role == "journal":
                    value[1][target] = "0" * 64
                else:
                    value[target] = "0" * 64
                self.rewrite_artifact(
                    role,
                    value,
                    compact_without_lf=compact_without_lf,
                    identity_field=identity_field,
                )
                self.assert_rejected(pattern)

    def test_core_plan_and_confirmation_match_authoritative_runtime_contracts(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original = self.artifact_json("confirmed-plan")
        cases: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            (
                "missing rollback objects",
                lambda value: value["plan"]["body"].pop("rollback_objects"),
                "violates checked-in install-plan.schema.json",
            ),
            (
                "missing complete layout",
                lambda value: value["plan"]["body"].pop("before_layout"),
                "violates checked-in install-plan.schema.json",
            ),
            (
                "unknown plan field",
                lambda value: value["plan"]["body"].__setitem__("invented", True),
                "violates checked-in install-plan.schema.json",
            ),
            (
                "self-attested display digest",
                lambda value: value["confirmation"].__setitem__("display_digest", "0" * 64),
                "display digest does not match",
            ),
            (
                "unknown confirmation field",
                lambda value: value["confirmation"].__setitem__("passed", True),
                "violates checked-in confirmation.schema.json",
            ),
        ]
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original_manifest)
                self.trust_roots = dict(self.base_trust_roots)
                value = copy.deepcopy(original)
                mutate(value)
                self.rewrite_artifact("confirmed-plan", value)
                self.assert_rejected(pattern, refresh_campaign_index=False)

    def test_core_journal_enforces_runtime_phases_graph_ownership_and_state_binding(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original = self.artifact_json("journal")
        graph = self.artifact_json("state-model")

        def incomplete(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return records[:1]

        def state_advanced_only(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [copy.deepcopy(records[2])]

        def skip_commit(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [records[0], records[2]]

        def failed_without_evidence(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            records[1]["record_type"] = "action_failed"
            return records

        def invented_actor(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            records[0]["actor"] = "invented_actor"
            return records

        def invented_transition(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            records[0]["transition_id"] = "invented_transition"
            return records

        def invented_state(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            records[2]["postcondition_hash"] = verify._canonical_sha256("invented.state")
            return records

        def unowned_object(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            records[1]["created_objects"] = [
                {"kind": "partition", "stable_id": "ffffffff-ffff-4fff-8fff-ffffffffffff"}
            ]
            return records

        def wrong_state_owner(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
            transition = next(
                item for item in graph["transitions"] if item["id"] == "verify_linux_handoff"
            )
            for record in records[3:6]:
                record["actor"] = transition["actor"]
                record["transition_id"] = transition["id"]
            records[5]["postcondition_hash"] = verify._canonical_sha256(transition["to"])
            return records

        cases = [
            ("incomplete triplet", incomplete, "ends before durable state advancement"),
            ("single state advanced", state_advanced_only, "must begin with an action_intent"),
            ("intent skips commit", skip_commit, "phases must repeat intent, commit"),
            (
                "failed action without a bound failure-evidence artifact",
                failed_without_evidence,
                "phases must repeat intent, commit",
            ),
            ("invented actor", invented_actor, "does not own transition"),
            ("invented transition", invented_transition, "not a transition in the signed graph"),
            ("invented state", invented_state, "does not bind graph state"),
            ("unowned rollback object", unowned_object, "outside the confirmed rollback set"),
            ("wrong next state owner", wrong_state_owner, "does not own the previously advanced graph state"),
        ]
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original_manifest)
                self.trust_roots = dict(self.base_trust_roots)
                records = mutate(copy.deepcopy(original))
                self.rewrite_core_journal(records)
                self.assert_rejected(pattern, refresh_campaign_index=False)

    def test_handoff_binds_control_state_boot_target_fingerprint_and_journal_head(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original = self.artifact_json("handoff")
        cases: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            (
                "control state",
                lambda value: value.__setitem__("control_state", "windows.installer_loader_staged"),
                "stale or mixed across graph/state",
            ),
            (
                "boot target",
                lambda value: value.__setitem__("intended_boot_target", "invented"),
                "boot target disagrees",
            ),
            (
                "partition fingerprint",
                lambda value: value.__setitem__("partition_fingerprint", "0" * 64),
                "fingerprint disagrees",
            ),
            (
                "partition phase",
                lambda value: value.__setitem__("partition_phase", "source"),
                "partition phase disagrees",
            ),
            (
                "journal head",
                lambda value: value.__setitem__("journal_head_hash", "0" * 64),
                "stale or mixed across graph/state",
            ),
        ]
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original_manifest)
                self.trust_roots = dict(self.base_trust_roots)
                value = copy.deepcopy(original)
                mutate(value)
                self.rewrite_artifact("handoff", value, identity_field="handoff_digest")
                self.assert_rejected(pattern, refresh_campaign_index=False)

    def test_stale_profile_media_and_exact_iso_size_sha_are_rejected(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        roles = ("resolved-profile-record", "official-media-record", "windows-iso")
        original_raw = {
            role: (self.root / self.artifact(role)["path"]).read_bytes() for role in roles
        }

        def reset() -> None:
            self.manifest = copy.deepcopy(original_manifest)
            self.trust_roots = dict(self.base_trust_roots)
            for role, raw in original_raw.items():
                (self.root / self.artifact(role)["path"]).write_bytes(raw)

        reset()
        profile = json.loads(original_raw["resolved-profile-record"])
        profile["profile_id"] = "stale-profile"
        profile_digest = self.rewrite_artifact(
            "resolved-profile-record", profile, identity_field="profile_digest"
        )
        self.trust_roots["trusted_profile_digest"] = profile_digest
        self.assert_rejected("stale for the selected support profile")

        reset()
        media = json.loads(original_raw["official-media-record"])
        media["product"]["release"] = "future"
        media_digest = self.rewrite_artifact(
            "official-media-record", media, identity_field="media_digest"
        )
        profile = json.loads(original_raw["resolved-profile-record"])
        profile["media"]["record_sha256"] = media_digest
        profile_digest = self.rewrite_artifact(
            "resolved-profile-record", profile, identity_field="profile_digest"
        )
        self.trust_roots["trusted_media_digest"] = media_digest
        self.trust_roots["trusted_profile_digest"] = profile_digest
        self.assert_rejected("official media product is stale")

        for name, replacement, pattern in (
            ("size", original_raw["windows-iso"] + b"x", "exact byte size"),
            (
                "sha",
                bytes([original_raw["windows-iso"][0] ^ 1]) + original_raw["windows-iso"][1:],
                "SHA-256 disagrees",
            ),
        ):
            with self.subTest(iso=name):
                reset()
                digest = self.rewrite_artifact_bytes("windows-iso", replacement)
                self.manifest["environment"]["verified_iso_digest"] = digest
                self.assert_rejected(pattern)

    def test_injected_fault_with_ordered_recovery_and_matching_campaign_is_accepted(self) -> None:
        make_recovery_completed(self.manifest)
        self.refresh_campaign_index()
        self.rewrite()
        accepted = verify.verify_bundle(self.root, **self.trust_roots)
        self.assertEqual(accepted["run"]["final_outcome"], "recovery.completed")

    def test_terminal_rolled_back_requires_restored_initial_state_and_windows_only_boots(self) -> None:
        make_rolled_back(self.manifest)
        self.refresh_campaign_index()
        self.rewrite()
        accepted = verify.verify_bundle(self.root, **self.trust_roots)
        self.assertEqual(accepted["run"]["final_outcome"], "terminal.rolled_back")

    def test_terminal_rolled_back_rejects_retained_or_divergent_jstack_state(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original_witnesses = copy.deepcopy(self.manifest["witnesses"])
        cases: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            (
                "retained partition",
                lambda value: value["observations"]["final"]["gpt"]["partition_guids"].append(FINAL_GUID),
                "do not restore|retains JStack",
            ),
            (
                "retained loader",
                lambda value: value["observations"]["final"]["esp"].__setitem__("jstack_loader_present", True),
                "do not restore|retains JStack",
            ),
            (
                "divergent disk",
                lambda value: value["observations"]["final"]["disk"].__setitem__(
                    "total_bytes", value["observations"]["final"]["disk"]["total_bytes"] + 512
                ),
                "do not restore the complete initial",
            ),
            (
                "retained JStack boot witness",
                lambda value: value["witnesses"].append(copy.deepcopy(original_witnesses[2])),
                "rolled-back runs require only",
            ),
        ]
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original_manifest)
                self.trust_roots = dict(self.base_trust_roots)
                make_rolled_back(self.manifest)
                mutate(self.manifest)
                self.refresh_campaign_index()
                self.assert_rejected(pattern, refresh_campaign_index=False)

    def test_rollback_outcome_cannot_be_collapsed_into_recovery_completed(self) -> None:
        make_rolled_back(self.manifest)
        self.manifest["run"]["final_outcome"] = "recovery.completed"
        self.refresh_campaign_index()
        self.assert_rejected(
            "final GPT must preserve|journal terminal state disagrees|fault recovery_outcome disagrees",
            refresh_campaign_index=False,
        )

    def test_noncanonical_duplicate_float_bom_and_invalid_utf8_are_rejected(self) -> None:
        canonical_raw = (self.root / "evidence.json").read_bytes()
        variants = (
            ("canonical JSON", json.dumps(self.manifest, indent=2).encode()),
            ("canonical JSON", (json.dumps(self.manifest, ensure_ascii=False, separators=(",", ":")) + "\n").encode()),
            ("canonical JSON", canonical_raw + b"\n"),
            ("duplicate", canonical_raw.replace(b'{"artifacts":', b'{"contract":"jstack.vm.run-evidence","artifacts":', 1)),
            ("floating-point", canonical({**self.manifest, "schema_version": 1.0})),
            ("BOM", b"\xef\xbb\xbf" + canonical_raw),
            ("valid UTF-8", b"\xff"),
        )
        for expected, raw in variants:
            with self.subTest(expected=expected):
                (self.root / "evidence.json").write_bytes(raw)
                with self.assertRaisesRegex(verify.EvidenceError, expected):
                    verify.verify_bundle(self.root, **self.trust_roots)

    def test_unknown_and_missing_fields_fail_closed(self) -> None:
        mutations: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            ("root unknown", lambda m: m.__setitem__("unexpected", True), "unknown fields"),
            ("root missing", lambda m: m.pop("vm_identity"), "missing fields"),
            ("run unknown", lambda m: m["run"].__setitem__("counter", 1), "unknown fields"),
            ("snapshot missing", lambda m: m["observations"]["final"].pop("gpt"), "missing fields"),
            ("witness missing", lambda m: m["witnesses"][0].pop("boot_id"), "missing fields"),
            ("coverage unknown", lambda m: m["coverage"].__setitem__("score", 100), "unknown fields"),
        ]
        original = copy.deepcopy(self.manifest)
        for name, mutate, pattern in mutations:
            with self.subTest(name=name):
                self.manifest = copy.deepcopy(original)
                mutate(self.manifest)
                self.assert_rejected(pattern)

    def test_supported_profiles_are_complete_ordered_and_immutable(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["profiles"].pop(),
            lambda m: m["profiles"].reverse(),
            lambda m: m["profiles"][0].__setitem__("secure_boot", True),
            lambda m: m["profiles"][0].__setitem__("secure_boot", 0),
            lambda m: m["profiles"][0].__setitem__("windows_release", "future"),
        ]
        for mutate in mutations:
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(mutation=repr(mutate)):
                self.assert_rejected("immutable supported|complete immutable|must be a boolean")

    def test_schema_version_rejects_boolean_integer_alias(self) -> None:
        self.manifest["schema_version"] = True
        self.assert_rejected("unsupported schema_version")

    def test_artifact_hash_size_path_and_content_reuse_are_rejected(self) -> None:
        original = copy.deepcopy(self.manifest)
        cases: list[tuple[str, Callable[[], None], str]] = [
            ("digest", lambda: self.manifest["artifacts"][0].__setitem__("sha256", "0" * 64), "hash mismatch"),
            ("size", lambda: self.manifest["artifacts"][0].__setitem__("size", 999), "size mismatch"),
            ("absolute", lambda: self.manifest["artifacts"][0].__setitem__("path", "/etc/passwd"), "normalized relative|below artifacts"),
            ("traversal", lambda: self.manifest["artifacts"][0].__setitem__("path", "artifacts/../escape"), "normalized relative|byte-normalized"),
            ("dot component", lambda: self.manifest["artifacts"][0].__setitem__("path", "artifacts/./escape"), "byte-normalized"),
            ("duplicate slash", lambda: self.manifest["artifacts"][0].__setitem__("path", self.manifest["artifacts"][0]["path"].replace("artifacts/", "artifacts//")), "byte-normalized"),
        ]
        for name, mutate, pattern in cases:
            self.manifest = copy.deepcopy(original)
            mutate()
            with self.subTest(name=name):
                self.assert_rejected(pattern)

        self.manifest = copy.deepcopy(original)
        first, second = self.manifest["artifacts"][:2]
        data = (self.root / first["path"]).read_bytes()
        (self.root / second["path"]).write_bytes(data)
        second["size"] = len(data)
        second["sha256"] = hashlib.sha256(data).hexdigest()
        self.assert_rejected("duplicate logical record in artifact content digests")

        self.manifest = copy.deepcopy(original)
        first, second = self.manifest["artifacts"][:2]
        second["path"] = first["path"]
        second["size"] = first["size"]
        second["sha256"] = first["sha256"]
        self.assert_rejected("duplicate logical record in artifact paths")

    def test_missing_nonregular_and_hard_linked_artifacts_are_rejected(self) -> None:
        artifact = self.manifest["artifacts"][0]
        path = self.root / artifact["path"]
        path.unlink()
        self.assert_rejected("does not resolve safely")

        path.write_bytes(b"replacement")
        target = path.with_name("hardlink-target")
        target.write_bytes(path.read_bytes())
        path.unlink()
        os.link(target, path)
        self.assert_rejected("hard-linked")

        path.unlink()
        target.unlink()
        path.mkdir()
        self.assert_rejected("not a regular file")

    def test_artifact_and_bundle_symlinks_are_rejected(self) -> None:
        artifact = self.manifest["artifacts"][0]
        path = self.root / artifact["path"]
        target = path.with_name("target.txt")
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        self.assert_rejected("symlink")

        other = Path(self.temporary.name) / "linked-bundle"
        other.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(verify.EvidenceError, "symlink component"):
            verify.verify_bundle(other, **self.trust_roots)

    def test_identity_disagreement_is_rejected_everywhere(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["vm_identity"].__setitem__("smbios_uuid", "22345678-1234-4123-8123-123456789abc"),
            lambda m: m["observations"]["final"].__setitem__("vm_id", "different-vm"),
            lambda m: m["journal"][2].__setitem__("disk_serial", "different-disk"),
            lambda m: m["witnesses"][1].__setitem__("graph_digest", "f" * 64),
            lambda m: m["observations"]["initial"].__setitem__("disk_identity", "e" * 64),
        ]
        for mutate in mutations:
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(mutation=repr(mutate)):
                self.assert_rejected("disagree")

    def test_impossible_journal_order_timestamps_and_labels_are_rejected(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["journal"].__setitem__(3, copy.deepcopy(m["journal"][4])),
            lambda m: m["journal"][4].__setitem__("observed_at", m["journal"][3]["observed_at"]),
            lambda m: m["journal"][4].__setitem__("transition_id", "begin-mutation"),
            lambda m: m["journal"][4].__setitem__("observed_postconditions", ["invented"]),
        ]
        patterns = ["duplicate|state order|sequence", "strictly increasing", "impossible or mislabeled|duplicate", "not canonical"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_platform_security_and_disk_observations_are_concrete(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["observations"]["final"]["firmware"].__setitem__("uefi", False),
            lambda m: m["observations"]["final"]["firmware"].__setitem__("secure_boot", True),
            lambda m: m["observations"]["final"]["tpm"].__setitem__("present", True),
            lambda m: m["observations"]["final"]["bitlocker"].__setitem__("enabled", True),
            lambda m: m["observations"]["final"]["gpt"].__setitem__("backup_header_valid", False),
            lambda m: m["observations"]["final"]["gpt"].__setitem__("partition_guids", [FINAL_GUID]),
            lambda m: m["observations"]["final"]["esp"].__setitem__("jstack_loader_present", False),
        ]
        patterns = ["UEFI", "Secure Boot", "TPM", "BitLocker", "GPT header", "preserve initial", "JStack ESP loader"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_success_requires_distinct_ordered_concrete_boot_witnesses(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["witnesses"].pop(),
            lambda m: m["witnesses"][1].__setitem__("boot_id", m["witnesses"][0]["boot_id"]),
            lambda m: m["witnesses"][2].__setitem__("loader_path", r"\EFI\wrong.efi"),
            lambda m: m["witnesses"][3].__setitem__("cold_boot", False),
            lambda m: m["witnesses"][3].__setitem__("observed_at", m["witnesses"][2]["observed_at"]),
        ]
        patterns = ["claimed success", "duplicate logical record in witness boot ids", "concrete expected EFI loader", "cold_boot", "strictly increasing"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_fault_boundary_and_outcome_are_fail_closed(self) -> None:
        original = copy.deepcopy(self.manifest)
        base_fault = {
            "mode": "injected",
            "class": "artifact-tamper",
            "trigger": "test trigger",
            "exact_boundary": verify.INTERRUPTION_BOUNDARIES[0],
            "transition_id": self.manifest["coverage"]["production_transitions"][0]["transition_id"],
            "checkpoint": "campaign",
            "boundary_observation_artifact_id": "serial-output",
            "process_exit_cause": "qemu killed",
            "recovery_outcome": "retry",
            "recovery_observation_artifact_ids": ["log"],
        }
        mutations = [
            lambda m: m.__setitem__("fault", {**base_fault, "exact_boundary": "somewhere"}),
            lambda m: m.__setitem__("fault", {**base_fault, "transition_id": "invented"}),
            lambda m: m.__setitem__("fault", base_fault),
            lambda m: (m["run"].__setitem__("final_outcome", "recovery.completed"), m.__setitem__("fault", {"mode": "none"})),
        ]
        patterns = ["exact_boundary", "graph-derived production mutation", "disagrees with run.final_outcome", "journal terminal|requires an injected fault"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_fault_boundary_and_recovery_require_distinct_concrete_artifacts(self) -> None:
        make_recovery_completed(self.manifest)
        self.manifest["fault"]["recovery_observation_artifact_ids"] = [
            self.manifest["fault"]["boundary_observation_artifact_id"]
        ]
        self.assert_rejected("boundary and recovery reuse")

    def test_campaign_rejects_missing_mutation_edge_fault_and_profile_coverage(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["coverage"]["production_transitions"].pop(),
            lambda m: m["coverage"]["interruption_runs"].pop(),
            lambda m: m["coverage"]["modeled_failure_edges"].pop(),
            lambda m: m["coverage"]["failure_edge_runs"].pop(),
            lambda m: m["coverage"]["mandatory_fault_cases"].pop(),
            lambda m: m["coverage"]["mandatory_fault_runs"].pop(),
            lambda m: m["coverage"]["fresh_base_reconstruction_runs"].pop(),
            lambda m: m["coverage"]["happy_path_runs"].pop(),
        ]
        patterns = ["exactly match graph-derived mutations", "incomplete interruption", "exactly match graph-derived failure edges", "incomplete modeled", "missing mandatory", "incomplete mandatory", "fresh base-image", "only 9"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_campaign_failure_edges_are_exactly_graph_derived(self) -> None:
        graph = self.artifact_json("state-model")
        derived = verify._derive_mutation_transitions(graph)[2]
        declared = tuple(
            record["edge_id"]
            for record in self.manifest["coverage"]["modeled_failure_edges"]
        )
        self.assertEqual(len(derived), 39)
        self.assertEqual(declared, derived)

        self.manifest["coverage"]["modeled_failure_edges"] = [
            {
                "edge_id": "mutation-failed",
                "applicable_profile_ids": self.manifest["coverage"][
                    "supported_profile_ids"
                ],
            }
        ]
        self.assert_rejected("exactly match graph-derived failure edges")

    def test_campaign_rows_require_external_index_and_unique_evidence_bundles(self) -> None:
        original = copy.deepcopy(self.manifest)
        first, second = self.manifest["coverage"]["happy_path_runs"][:2]
        second["evidence_bundle_digest"] = first["evidence_bundle_digest"]
        self.assert_rejected(
            "duplicate logical record in all campaign evidence bundle digests"
        )

        self.manifest = copy.deepcopy(original)
        self.trust_roots = dict(self.base_trust_roots)
        self.rewrite_trusted_campaign_bundle(
            "happy_path_runs",
            0,
            lambda bundle: bundle["verification"].__setitem__("status", "passed"),
        )
        self.assert_rejected("verification has unknown fields: status", refresh_campaign_index=False)

    def test_campaign_rejects_self_attested_or_mismatched_actual_run_bundles(self) -> None:
        row = self.manifest["coverage"]["happy_path_runs"][0]
        row["evidence_bundle_digest"] = hashlib.sha256(
            canonical(verify._campaign_claim(row))
        ).hexdigest()
        self.assert_rejected(
            "canonical digest disagrees with its campaign row",
            refresh_campaign_index=False,
        )

    def test_trusted_campaign_index_revalidates_bundle_identity_digest_trace_and_rollback(self) -> None:
        original_manifest = copy.deepcopy(self.manifest)
        original_index = self.artifact_json("campaign-index")

        def reset() -> None:
            self.manifest = copy.deepcopy(original_manifest)
            self.trust_roots = dict(self.base_trust_roots)
            self.rewrite_artifact("campaign-index", copy.deepcopy(original_index))

        reset()
        self.rewrite_trusted_campaign_bundle(
            "happy_path_runs",
            0,
            lambda bundle: bundle["identity"].__setitem__("profile_id", "invented-profile"),
        )
        self.assert_rejected("identity is stale or belongs to another run", refresh_campaign_index=False)

        reset()
        self.rewrite_trusted_campaign_bundle(
            "happy_path_runs",
            0,
            lambda bundle: bundle["trace"].__setitem__("description", "changed canonical bytes"),
            bind_digest=False,
        )
        self.assert_rejected("canonical digest disagrees with its campaign row", refresh_campaign_index=False)

        reset()
        graph = self.artifact_json("state-model")
        selected_failure: tuple[int, dict[str, Any], str, tuple[list[Any], str]] | None = None
        for failure_index, candidate in enumerate(
            self.manifest["coverage"]["failure_edge_runs"]
        ):
            candidate_terminal = {
                "retry": "terminal.completed",
                "advance": "terminal.completed",
                "rollback": "terminal.rolled_back",
                "manual-recovery": "terminal.manual_recovery",
            }[candidate["recovery_outcome"]]
            candidate_replacement = _path_steps(
                graph,
                graph["initial_state"],
                {candidate_terminal},
                forbidden_transition_ids={candidate["edge_id"]},
            )
            if candidate_replacement is not None:
                selected_failure = (
                    failure_index,
                    candidate,
                    candidate_terminal,
                    candidate_replacement,
                )
                break
        assert selected_failure is not None
        failure_index, failure_record, terminal, replacement = selected_failure
        replacement_steps, _ = replacement

        def remove_claimed_edge(bundle: dict[str, Any]) -> None:
            bundle["trace"] = {
                "id": failure_record["run_id"],
                "description": "Graph-valid trace that omits the claimed failure edge",
                "steps": replacement_steps,
                "expected_terminal": terminal,
            }

        self.rewrite_trusted_campaign_bundle(
            "failure_edge_runs", failure_index, remove_claimed_edge
        )
        self.assert_rejected("does not execute the claimed modeled failure edge", refresh_campaign_index=False)

        reset()
        campaign_index = self.artifact_json("campaign-index")
        rollback_location: tuple[str, int] | None = None
        offset = 0
        for category in verify.CAMPAIGN_RUN_SECTIONS:
            for row_index, _ in enumerate(self.manifest["coverage"][category]):
                if campaign_index["runs"][offset]["bundle"]["rollback"] is not None:
                    rollback_location = (category, row_index)
                    break
                offset += 1
            if rollback_location is not None:
                break
        assert rollback_location is not None
        category, row_index = rollback_location
        self.rewrite_trusted_campaign_bundle(
            category,
            row_index,
            lambda bundle: bundle["rollback"]["retained_jstack_objects"].append(
                "partition:retained"
            ),
        )
        self.assert_rejected("rollback retains JStack-created objects", refresh_campaign_index=False)

    def test_campaign_rejects_stale_inputs_failures_and_cross_section_run_reuse(self) -> None:
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["coverage"]["interruption_runs"][0].__setitem__("input_digest", "0" * 64),
            lambda m: m["coverage"]["mandatory_fault_runs"][0].__setitem__("passed", True),
            lambda m: m["coverage"]["failure_edge_runs"][0].__setitem__("run_id", m["coverage"]["happy_path_runs"][0]["run_id"]),
            lambda m: m["coverage"]["production_transitions"][0].__setitem__("applicable_profile_ids", m["coverage"]["supported_profile_ids"][:-1]),
        ]
        patterns = ["stale", "unknown fields: passed", "all campaign run ids", "every immutable supported profile"]
        for mutate, pattern in zip(mutations, patterns):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(pattern=pattern):
                self.assert_rejected(pattern)

    def test_schema_declares_new_strict_sections(self) -> None:
        schema = json.loads((ROOT / "evidence" / "schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.manifest)
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["contract"]["const"], verify.CONTRACT)
        self.assertIn("vm_identity", schema["required"])
        self.assertIn("observations", schema["required"])
        self.assertEqual(
            schema["properties"]["profiles"]["const"],
            [verify.SUPPORTED_PROFILES[key] for key in sorted(verify.SUPPORTED_PROFILES)],
        )
        self.assertEqual(
            schema["$defs"]["artifact"]["properties"]["role"]["enum"],
            list(verify.REQUIRED_ARTIFACT_ROLES),
        )
        self.assertEqual(schema["$defs"]["identity"]["required"], list(verify.IDENTITY_FIELDS))
        self.assertIn("terminal.rolled_back", schema["$defs"]["run"]["properties"]["final_outcome"]["enum"])
        self.assertIn("terminal.rolled_back", schema["$defs"]["journal"]["properties"]["state"]["enum"])
        for name in ("base-run", "failure-edge-run", "fault-run", "happy-run", "interruption-run"):
            self.assertNotIn("passed", schema["$defs"][name]["properties"])


if __name__ == "__main__":
    unittest.main()
