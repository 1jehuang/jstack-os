#!/usr/bin/env python3
"""Shared loader, validator, and trace simulator for the installer graph."""

from __future__ import annotations

import copy
import json
import re
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


MUTATING_RISKS = {
    "staging_mutation",
    "filesystem_mutation",
    "security_mutation",
    "disk_mutation",
    "boot_mutation",
    "reboot",
}

SYSTEM_MUTATING_RISKS = MUTATING_RISKS - {"staging_mutation"}

ROLLBACK_MUTATION_ENTRY_STATE = "recovery.rollback_required"

ROLLBACK_MUTATING_TRANSITION_IDS = frozenset(
    {
        "dispatch_rollback_linux",
        "reboot_to_windows_rollback",
        "execute_windows_rollback",
        "rollback_remove_esp_files",
        "rollback_delete_partitions",
        "rollback_expand_windows",
        "rollback_restore_security",
        "rollback_unregister_finalizer",
    }
)

ROLLBACK_RECOVERY_STATE_IDS = frozenset(
    {
        "recovery.rollback_required",
        "linux.rollback_to_windows_pending",
        "windows.rollback_running",
        "windows.rollback_boot_entries_removed",
        "windows.rollback_esp_cleaned",
        "windows.rollback_partitions_deleted",
        "windows.rollback_ntfs_restored",
        "windows.rollback_security_restored",
    }
)

ROLLBACK_RECOVERY_TERMINAL_IDS = frozenset(
    {"terminal.rolled_back", "terminal.manual_recovery"}
)

ROLLBACK_PROOF_WITNESS_ROLES = ("journal",)

EXPECTED_TERMINAL_OUTCOMES = {
    "success",
    "safe_abort",
    "unsupported",
    "rolled_back",
    "manual_recovery",
}

REQUIRED_ACTION_RISKS = {
    "reconcile_staging_store": "staging_mutation",
    "persist_release_acceptance": "staging_mutation",
    "stage_payload_quarantine": "staging_mutation",
    "promote_verified_payload": "staging_mutation",
    "register_windows_finalizer": "filesystem_mutation",
    "suspend_bitlocker": "security_mutation",
    "shrink_windows_ntfs": "disk_mutation",
    "create_xbootldr_partition": "disk_mutation",
    "format_xbootldr_fat32": "filesystem_mutation",
    "copy_payload_to_xbootldr": "filesystem_mutation",
    "stage_namespaced_esp_loader": "boot_mutation",
    "create_installer_boot_entry": "boot_mutation",
    "set_installer_bootnext": "boot_mutation",
    "request_reboot": "reboot",
    "create_root_partition": "disk_mutation",
    "format_root_btrfs": "filesystem_mutation",
    "deploy_root_image": "filesystem_mutation",
    "configure_installed_system": "filesystem_mutation",
    "install_jstack_boot_artifacts": "boot_mutation",
    "arm_windows_finalizer": "boot_mutation",
    "restore_bitlocker": "security_mutation",
    "cleanup_windows_bootstrap": "filesystem_mutation",
    "set_jstack_bootnext": "boot_mutation",
    "arm_windows_rollback": "boot_mutation",
    "remove_jstack_boot_entries": "boot_mutation",
    "remove_namespaced_esp_files": "filesystem_mutation",
    "delete_jstack_partitions": "disk_mutation",
    "expand_windows_ntfs": "disk_mutation",
    "unregister_windows_finalizer": "filesystem_mutation",
}

REQUIRED_TRANSITION_ACTIONS = {
    "begin_preflight": ["reconcile_staging_store"],
    "persist_release_acceptance": ["persist_release_acceptance"],
    "begin_payload_staging": ["stage_payload_quarantine"],
    "accept_verified_payload": ["promote_verified_payload"],
}

EXPECTED_HANDOFF_ACTORS = {
    "reboot_to_installer": "linux_installer",
    "rearm_installer_boot": "linux_installer",
    "arm_windows_finalize": "windows_finalizer",
    "reboot_to_installed_jstack": "jstack_first_boot",
    "reboot_rearmed_jstack": "jstack_first_boot",
    "reboot_to_windows_rollback": "windows_finalizer",
}

STAGING_SAFE_FAILURE_TARGETS = {
    "windows.payload_invalid",
    "terminal.manual_recovery",
}

EVIDENCE_IDENTITY_FIELDS = (
    "graph_digest",
    "release_digest",
    "release_acceptance_digest",
    "staging_evidence_digest",
    "plan_digest",
    "disk_identity",
)

ASSURANCE_TRANSITION_REQUIREMENTS = {
    "installer_boot_observed": {
        "guard": "installer_boot_evidence_current",
        "preconditions": (
            "installer_boot_witnesses_content_addressed",
            "installer_boot_identity_agrees",
        ),
        "postconditions": ("installer_boot_observation_committed_with_evidence",),
        "witness_roles": ("handoff", "journal", "guest-output"),
    },
    "windows_finalizer_booted": {
        "guard": "windows_finalizer_boot_evidence_current",
        "preconditions": (
            "windows_finalizer_boot_witnesses_content_addressed",
            "windows_finalizer_boot_identity_agrees",
        ),
        "postconditions": (
            "windows_finalizer_boot_observation_committed_with_evidence",
        ),
        "witness_roles": ("handoff", "journal", "windows-boot-attestation"),
    },
    "jstack_boot_observed": {
        "guard": "jstack_boot_evidence_current",
        "preconditions": (
            "jstack_boot_witnesses_content_addressed",
            "jstack_boot_identity_agrees",
        ),
        "postconditions": ("jstack_boot_observation_committed_with_evidence",),
        "witness_roles": ("handoff", "journal", "jstack-boot-attestation"),
    },
    "complete_after_first_boot": {
        "guard": "first_boot_completion_evidence_current",
        "preconditions": (
            "first_boot_completion_witnesses_content_addressed",
            "first_boot_completion_identity_agrees",
        ),
        "postconditions": ("terminal_completion_committed_with_evidence",),
        "witness_roles": (
            "journal",
            "windows-boot-attestation",
            "jstack-boot-attestation",
            "dual-boot-verification",
        ),
    },
}

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_PATH_RE = re.compile(
    r"^artifacts/(?!\.\.?(?:/|$))(?!.*(?:/\.\.?)(?:/|$))(?!.*\\)[^\x00]+$"
)


def load_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_against_schema(
    instance: dict[str, Any], schema: dict[str, Any]
) -> list[str]:
    """Validate a JSON document with the schema's declared draft."""

    try:
        from jsonschema.validators import validator_for
    except ImportError as error:  # pragma: no cover - exercised by packaging checks
        raise RuntimeError(
            "python-jsonschema is required for installer model validation"
        ) from error

    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"{location}: {error.message}")
    return errors


def _duplicates(values: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def index_by_id(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in items}


def transition_is_mutating(
    transition: dict[str, Any], actions: dict[str, dict[str, Any]]
) -> bool:
    return any(
        actions[action_id]["risk"] in MUTATING_RISKS
        for action_id in transition.get("actions", [])
        if action_id in actions
    )


def transition_is_system_mutating(
    transition: dict[str, Any], actions: dict[str, dict[str, Any]]
) -> bool:
    return any(
        actions[action_id]["risk"] in SYSTEM_MUTATING_RISKS
        for action_id in transition.get("actions", [])
        if action_id in actions
    )


def rollback_mutating_transition_ids(
    model: dict[str, Any], actions: dict[str, dict[str, Any]]
) -> set[str]:
    """Derive system mutations in the rollback region over every control edge."""

    adjacency = all_adjacency(model)
    rollback_states = {ROLLBACK_MUTATION_ENTRY_STATE}
    queue = deque(rollback_states)
    while queue:
        current = queue.popleft()
        for target in adjacency.get(current, set()):
            if target not in rollback_states:
                rollback_states.add(target)
                queue.append(target)

    return {
        transition["id"]
        for transition in model["transitions"]
        if transition.get("from") in rollback_states
        and transition_is_system_mutating(transition, actions)
    }


def valid_failure_target(transition: dict[str, Any]) -> str | None:
    failure = transition.get("failure_to")
    return failure if isinstance(failure, str) and failure else None


def reconcile_interruption(
    transition: dict[str, Any],
    actions: dict[str, dict[str, Any]],
    observed: str,
) -> str:
    """Resolve a pending mutation from independently observed disk state."""

    if not transition_is_mutating(transition, actions):
        raise AssertionError(f"cannot reconcile non-mutating transition {transition['id']}")
    if observed == "precondition":
        return transition["from"]
    if observed == "postcondition":
        return transition["to"]
    if observed == "divergent":
        failure = valid_failure_target(transition)
        if not failure:
            raise AssertionError(
                f"mutation {transition['id']} has divergent state without failure_to"
            )
        return failure
    raise AssertionError(f"unknown interruption observation {observed}")


def normal_adjacency(model: dict[str, Any]) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for transition in model["transitions"]:
        adjacency[transition["from"]].add(transition["to"])
    return adjacency


def all_adjacency(model: dict[str, Any]) -> dict[str, set[str]]:
    adjacency = normal_adjacency(model)
    for transition in model["transitions"]:
        if failure := valid_failure_target(transition):
            adjacency[transition["from"]].add(failure)
    return adjacency


def reachable_states(model: dict[str, Any]) -> set[str]:
    adjacency = all_adjacency(model)
    seen = {model["initial_state"]}
    queue = deque(seen)
    while queue:
        current = queue.popleft()
        for target in adjacency.get(current, set()):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def states_reaching_any(model: dict[str, Any], targets: set[str]) -> set[str]:
    """Return states that can reach any target through success or failure edges."""

    reverse: dict[str, set[str]] = defaultdict(set)
    for source, destinations in all_adjacency(model).items():
        for destination in destinations:
            reverse[destination].add(source)

    seen = set(targets)
    queue = deque(targets)
    while queue:
        current = queue.popleft()
        for predecessor in reverse.get(current, set()):
            if predecessor not in seen:
                seen.add(predecessor)
                queue.append(predecessor)
    return seen


def dominators(model: dict[str, Any]) -> dict[str, set[str]]:
    """Compute dominators over every legal control edge, including failures."""

    states = {state["id"] for state in model["states"]}
    initial = model["initial_state"]
    predecessors: dict[str, set[str]] = defaultdict(set)
    for transition in model["transitions"]:
        predecessors[transition["to"]].add(transition["from"])
        if failure := valid_failure_target(transition):
            predecessors[failure].add(transition["from"])

    dom = {state: set(states) for state in states}
    dom[initial] = {initial}
    changed = True
    while changed:
        changed = False
        for state in states - {initial}:
            preds = predecessors.get(state, set())
            if not preds:
                new = {state}
            else:
                common = set(states)
                for pred in preds:
                    common &= dom[pred]
                new = {state} | common
            if new != dom[state]:
                dom[state] = new
                changed = True
    return dom


def validate_model(model: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "model_id",
        "initial_state",
        "actors",
        "actor_platforms",
        "guards",
        "actions",
        "invariants",
        "states",
        "transitions",
    }
    missing = sorted(required - model.keys())
    if missing:
        return [f"missing top-level field: {field}" for field in missing]
    if model["schema_version"] != 1:
        errors.append("schema_version must be 1")

    catalogs = {
        "guard": model["guards"],
        "action": model["actions"],
        "invariant": model["invariants"],
        "state": model["states"],
        "transition": model["transitions"],
    }
    for name, items in catalogs.items():
        for duplicate in sorted(_duplicates(item.get("id", "") for item in items)):
            errors.append(f"duplicate {name} id: {duplicate}")

    states = index_by_id(model["states"])
    guards = index_by_id(model["guards"])
    actions = index_by_id(model["actions"])
    transitions = index_by_id(model["transitions"])
    actors = set(model["actors"])
    actor_platforms = model["actor_platforms"]

    derived_rollback_mutations = rollback_mutating_transition_ids(model, actions)
    missing_rollback_mutations = (
        ROLLBACK_MUTATING_TRANSITION_IDS - derived_rollback_mutations
    )
    unexpected_rollback_mutations = (
        derived_rollback_mutations - ROLLBACK_MUTATING_TRANSITION_IDS
    )
    rollback_mutations = (
        ROLLBACK_MUTATING_TRANSITION_IDS | derived_rollback_mutations
    )
    if missing_rollback_mutations:
        errors.append(
            "rollback mutation closure lacks required transitions: "
            + ", ".join(sorted(missing_rollback_mutations))
        )
    if unexpected_rollback_mutations:
        errors.append(
            "rollback mutation closure contains unexpected transitions: "
            + ", ".join(sorted(unexpected_rollback_mutations))
        )

    closed_rollback_states = (
        ROLLBACK_RECOVERY_STATE_IDS | ROLLBACK_RECOVERY_TERMINAL_IDS
    )
    for transition_id, transition in transitions.items():
        if transition.get("from") not in ROLLBACK_RECOVERY_STATE_IDS:
            continue
        for edge_name, target in (
            ("success", transition.get("to")),
            ("failure", valid_failure_target(transition)),
        ):
            if target is not None and target not in closed_rollback_states:
                errors.append(
                    f"rollback transition {transition_id} {edge_name} target {target} "
                    "escapes closed recovery subgraph"
                )

    for action_id, expected_risk in REQUIRED_ACTION_RISKS.items():
        action = actions.get(action_id)
        if not action:
            errors.append(f"required safety-critical action is missing: {action_id}")
        elif action.get("risk") != expected_risk:
            errors.append(
                f"safety-critical action {action_id} risk must be {expected_risk}"
            )

    for transition_id, expected_actions in REQUIRED_TRANSITION_ACTIONS.items():
        transition = transitions.get(transition_id)
        if not transition:
            errors.append(f"required safety-critical transition is missing: {transition_id}")
        elif transition.get("actions") != expected_actions:
            errors.append(
                f"safety-critical transition {transition_id} actions must be exactly "
                + ", ".join(expected_actions)
            )

    if set(actor_platforms) != actors:
        missing_actor_platforms = sorted(actors - set(actor_platforms))
        unknown_actor_platforms = sorted(set(actor_platforms) - actors)
        if missing_actor_platforms:
            errors.append(
                "actors lack platform authority: " + ", ".join(missing_actor_platforms)
            )
        if unknown_actor_platforms:
            errors.append(
                "platform authority references unknown actors: "
                + ", ".join(unknown_actor_platforms)
            )

    if model["initial_state"] not in states:
        errors.append(f"initial state does not exist: {model['initial_state']}")

    terminal_states = {
        state_id for state_id, state in states.items() if state.get("kind") == "terminal"
    }
    success_states = {
        state_id
        for state_id, state in states.items()
        if state.get("terminal_outcome") == "success"
    }
    if success_states != {"terminal.completed"}:
        errors.append(
            "the only success terminal must be terminal.completed; got "
            + ", ".join(sorted(success_states))
        )

    outcome_counts = Counter(
        state.get("terminal_outcome")
        for state in states.values()
        if state.get("kind") == "terminal"
    )
    if set(outcome_counts) != EXPECTED_TERMINAL_OUTCOMES:
        errors.append(
            "terminal outcomes must be exactly "
            + ", ".join(sorted(EXPECTED_TERMINAL_OUTCOMES))
        )
    for outcome, count in sorted(outcome_counts.items()):
        if count != 1:
            errors.append(f"terminal outcome {outcome} has {count} states; expected 1")

    for state_id, state in states.items():
        if state.get("actor") not in actors:
            errors.append(f"state {state_id} references unknown actor {state.get('actor')}")
        if state.get("kind") == "terminal" and not state.get("terminal_outcome"):
            errors.append(f"terminal state {state_id} lacks terminal_outcome")
        if state.get("kind") != "terminal" and state.get("terminal_outcome"):
            errors.append(f"nonterminal state {state_id} declares terminal_outcome")

    outgoing: dict[str, list[str]] = defaultdict(list)
    for transition_id, transition in transitions.items():
        source = transition.get("from")
        target = transition.get("to")
        outgoing[source].append(transition_id)
        if source not in states:
            errors.append(f"transition {transition_id} has unknown source {source}")
        if target not in states:
            errors.append(f"transition {transition_id} has unknown target {target}")
        if transition.get("actor") not in actors:
            errors.append(
                f"transition {transition_id} references unknown actor {transition.get('actor')}"
            )
        for guard_id in transition.get("guards", []):
            if guard_id not in guards:
                errors.append(f"transition {transition_id} references unknown guard {guard_id}")
                continue
            guard_platform = guards[guard_id].get("platform")
            allowed_platforms = set(actor_platforms.get(transition.get("actor"), []))
            if guard_platform not in allowed_platforms:
                errors.append(
                    f"transition {transition_id} actor {transition.get('actor')} "
                    f"cannot evaluate {guard_id} on platform {guard_platform}"
                )
        for action_id in transition.get("actions", []):
            if action_id not in actions:
                errors.append(f"transition {transition_id} references unknown action {action_id}")
                continue
            action_platform = actions[action_id].get("platform")
            allowed_platforms = set(actor_platforms.get(transition.get("actor"), []))
            if action_platform not in allowed_platforms:
                errors.append(
                    f"transition {transition_id} actor {transition.get('actor')} "
                    f"cannot execute {action_id} on platform {action_platform}"
                )
        if "failure_to" in transition:
            failure = transition["failure_to"]
            if not isinstance(failure, str) or not failure:
                errors.append(
                    f"transition {transition_id} failure_to must be a non-empty state id"
                )
            elif failure not in states:
                errors.append(
                    f"transition {transition_id} has unknown failure target {failure}"
                )

        is_mutating = transition_is_mutating(transition, actions)
        is_system_mutating = transition_is_system_mutating(transition, actions)
        is_rollback_mutation = transition_id in rollback_mutations
        authorization = set(transition.get("authorization", []))
        if is_rollback_mutation:
            if not is_system_mutating:
                errors.append(
                    f"rollback transition {transition_id} must be system-mutating"
                )
            if "rollback_authorized" not in authorization:
                errors.append(
                    f"rollback mutation {transition_id} lacks rollback_authorized"
                )
            rollback_guards = {"rollback_permitted", "rollback_identity_current"}
            missing_rollback_guards = rollback_guards - set(
                transition.get("guards", [])
            )
            if missing_rollback_guards:
                errors.append(
                    f"rollback mutation {transition_id} lacks guards: "
                    + ", ".join(sorted(missing_rollback_guards))
                )
        elif is_mutating and "rollback_authorized" in authorization:
            errors.append(
                f"non-rollback mutation {transition_id} must not use rollback_authorized"
            )

        if is_mutating:
            mutating_action_ids = [
                action_id
                for action_id in transition.get("actions", [])
                if action_id in actions and actions[action_id]["risk"] in MUTATING_RISKS
            ]
            if len(mutating_action_ids) > 1:
                errors.append(
                    f"transition {transition_id} combines multiple mutations: "
                    + ", ".join(mutating_action_ids)
                )
            if is_system_mutating:
                if (
                    not is_rollback_mutation
                    and "confirmed_plan" not in authorization
                ):
                    errors.append(
                        f"forward mutation {transition_id} lacks confirmed_plan authorization"
                    )
            elif "release_policy" not in authorization:
                errors.append(
                    f"staging transition {transition_id} lacks release_policy authorization"
                )
            journal = transition.get("journal", {})
            if not journal.get("intent_before_actions"):
                errors.append(
                    f"mutating transition {transition_id} lacks a pre-action intent record"
                )
            if not journal.get("commit_after_postconditions"):
                errors.append(
                    f"mutating transition {transition_id} lacks a postcondition commit record"
                )
            if not transition.get("preconditions"):
                errors.append(f"mutating transition {transition_id} lacks preconditions")
            if not transition.get("postconditions"):
                errors.append(f"mutating transition {transition_id} lacks postconditions")
            if not transition.get("failure_to"):
                errors.append(f"mutating transition {transition_id} lacks failure_to")
            if "confirmed_plan" in authorization and "confirmed_plan_current" not in set(
                transition.get("guards", [])
            ):
                errors.append(
                    f"confirmed mutation {transition_id} lacks confirmed_plan_current guard"
                )
            if "confirmed_plan" in authorization and "plan_fingerprint_current" not in set(
                transition.get("guards", [])
            ):
                errors.append(
                    f"confirmed mutation {transition_id} lacks plan_fingerprint_current guard"
                )
            for action_id in transition.get("actions", []):
                action = actions.get(action_id)
                if not action or action["risk"] not in MUTATING_RISKS:
                    continue
                if action.get("idempotency") not in {
                    "idempotent",
                    "content_addressed",
                    "reconcile_required",
                }:
                    errors.append(
                        f"mutating action {action_id} lacks explicit idempotency policy"
                    )
                if action.get("recovery") not in {
                    "retry",
                    "reconcile",
                    "compensate",
                    "reconcile_then_compensate",
                }:
                    errors.append(
                        f"mutating action {action_id} lacks explicit recovery policy"
                    )

        if "request_reboot" in transition.get("actions", []):
            handoff = transition.get("handoff")
            if not handoff:
                errors.append(f"reboot transition {transition_id} lacks handoff metadata")
            else:
                if len(set(handoff.get("journal_replicas", []))) < 2:
                    errors.append(
                        f"reboot transition {transition_id} needs at least two journal replicas"
                    )
                if handoff.get("next_actor") not in actors:
                    errors.append(
                        f"reboot transition {transition_id} has unknown next actor"
                    )
                expected_actor = EXPECTED_HANDOFF_ACTORS.get(transition_id)
                if expected_actor and handoff.get("next_actor") != expected_actor:
                    errors.append(
                        f"reboot transition {transition_id} must hand off to {expected_actor}"
                    )
            if not transition.get("journal", {}).get("advance_before_handoff"):
                errors.append(
                    f"reboot transition {transition_id} must advance durable state before handoff"
                )

    for state_id, state in states.items():
        if state_id in terminal_states and outgoing.get(state_id):
            errors.append(f"terminal state {state_id} has outgoing transitions")
        if state_id not in terminal_states and not outgoing.get(state_id):
            errors.append(f"nonterminal state {state_id} has no outgoing transition")

    reachable = reachable_states(model)
    for state_id in sorted(states.keys() - reachable):
        errors.append(f"unreachable state: {state_id}")

    terminal_reachable = states_reaching_any(model, terminal_states)
    for state_id in sorted(reachable - terminal_reachable):
        errors.append(f"reachable state cannot reach a terminal outcome: {state_id}")

    system_failure_reachable = states_reaching_any(
        model, {"terminal.rolled_back", "terminal.manual_recovery"}
    )
    staging_failure_reachable = states_reaching_any(
        model, {"terminal.cancelled", "terminal.manual_recovery"}
    )
    for transition_id, transition in transitions.items():
        if not transition_is_mutating(transition, actions):
            continue
        failure_target = valid_failure_target(transition)
        if not failure_target:
            continue
        if transition_is_system_mutating(transition, actions):
            if failure_target not in system_failure_reachable:
                errors.append(
                    f"mutating transition {transition_id} failure target {failure_target} "
                    "cannot reach rollback or manual recovery"
                )
        else:
            if failure_target not in staging_failure_reachable:
                errors.append(
                    f"staging transition {transition_id} failure target {failure_target} "
                    "cannot reach safe cancellation or manual recovery"
                )
            if failure_target not in STAGING_SAFE_FAILURE_TARGETS:
                errors.append(
                    f"staging transition {transition_id} failure target {failure_target} "
                    "is not an explicit staging recovery checkpoint"
                )

    dom = dominators(model)
    for required_dominator in {
        "windows.plan_confirmed",
        "windows.security_restored",
        "jstack.first_boot",
    }:
        if required_dominator not in dom.get("terminal.completed", set()):
            errors.append(
                f"success is reachable without required state {required_dominator}"
            )

    for transition_id, transition in transitions.items():
        if not transition_is_system_mutating(transition, actions):
            continue
        source = transition["from"]
        if source != "windows.plan_confirmed" and "windows.plan_confirmed" not in dom.get(
            source, set()
        ):
            errors.append(
                f"mutating transition {transition_id} is reachable without plan confirmation"
            )
        if (
            transition_id in rollback_mutations
            and source != ROLLBACK_MUTATION_ENTRY_STATE
            and ROLLBACK_MUTATION_ENTRY_STATE not in dom.get(source, set())
        ):
            errors.append(
                f"rollback mutation {transition_id} is reachable without "
                f"{ROLLBACK_MUTATION_ENTRY_STATE}"
            )

    for transition_id in ("arm_installer_bootnext", "arm_installed_jstack"):
        transition = transitions.get(transition_id)
        if transition and "boot_chain_trusted" not in transition.get("guards", []):
            errors.append(f"{transition_id} lacks boot_chain_trusted guard")

    for transition_id, requirement in ASSURANCE_TRANSITION_REQUIREMENTS.items():
        transition = transitions.get(transition_id)
        if not transition:
            errors.append(f"required assurance transition is missing: {transition_id}")
            continue
        guard_id = requirement["guard"]
        if guard_id not in transition.get("guards", []):
            errors.append(
                f"assurance transition {transition_id} lacks evidence guard {guard_id}"
            )
        for precondition in requirement["preconditions"]:
            if precondition not in transition.get("preconditions", []):
                errors.append(
                    f"assurance transition {transition_id} lacks precondition {precondition}"
                )
        for postcondition in requirement["postconditions"]:
            if postcondition not in transition.get("postconditions", []):
                errors.append(
                    f"assurance transition {transition_id} lacks postcondition {postcondition}"
                )

        guard = guards.get(guard_id)
        if not guard:
            errors.append(f"assurance evidence guard is missing: {guard_id}")
            continue
        declaration = guard.get("evidence")
        if not isinstance(declaration, dict):
            errors.append(f"assurance evidence guard {guard_id} lacks a declaration")
            continue
        expected_keys = {
            "claim",
            "content_address",
            "identity_fields",
            "witness_roles",
        }
        if set(declaration) != expected_keys:
            errors.append(
                f"assurance evidence guard {guard_id} declaration fields must be exactly "
                + ", ".join(sorted(expected_keys))
            )
        if declaration.get("claim") != transition_id:
            errors.append(
                f"assurance evidence guard {guard_id} claim must be {transition_id}"
            )
        if declaration.get("content_address") != "sha256":
            errors.append(
                f"assurance evidence guard {guard_id} must require sha256 content addresses"
            )
        if declaration.get("identity_fields") != list(EVIDENCE_IDENTITY_FIELDS):
            errors.append(
                f"assurance evidence guard {guard_id} must require the complete run identity"
            )
        if declaration.get("witness_roles") != list(requirement["witness_roles"]):
            errors.append(
                f"assurance evidence guard {guard_id} witness roles must be exactly "
                + ", ".join(requirement["witness_roles"])
            )

    for transition_id in ("arm_installer_bootnext", "arm_installer_reboot_retry"):
        transition = transitions.get(transition_id)
        if not transition:
            continue
        if "staging_evidence_current" not in transition.get("guards", []):
            errors.append(f"{transition_id} lacks staging_evidence_current guard")
        if "rehash_installer_boot_payload" not in transition.get("actions", []):
            errors.append(f"{transition_id} lacks immediate installer payload rehash")
        if "payload_hashes_valid" in transition.get("guards", []):
            errors.append(f"{transition_id} relies on stale payload_hashes_valid evidence")

    for transition_id in (
        "copy_verified_payload",
        "stage_installer_loader",
        "deploy_jstack_image",
        "install_jstack_boot",
    ):
        transition = transitions.get(transition_id)
        if transition and "staging_evidence_current" not in transition.get("guards", []):
            errors.append(f"{transition_id} lacks staging_evidence_current guard")

    rearm = transitions.get("arm_installer_reboot_retry")
    if rearm and "installer_rearm_not_attempted" not in rearm.get("guards", []):
        errors.append(
            "arm_installer_reboot_retry lacks installer_rearm_not_attempted guard"
        )
    exhausted_rearm = transitions.get("exhaust_installer_rearm")
    if not exhausted_rearm:
        errors.append("installer BootNext flow lacks an exhausted-rearm transition")
    elif (
        exhausted_rearm.get("from") != "windows.installer_rearm"
        or exhausted_rearm.get("to") != "recovery.rollback_required"
        or "installer_rearm_exhausted" not in exhausted_rearm.get("guards", [])
    ):
        errors.append("exhaust_installer_rearm must route exhausted retry to rollback")

    jstack_rearm = transitions.get("arm_jstack_reboot_retry")
    if jstack_rearm and "jstack_rearm_not_attempted" not in jstack_rearm.get(
        "guards", []
    ):
        errors.append("arm_jstack_reboot_retry lacks jstack_rearm_not_attempted guard")
    exhausted_jstack_rearm = transitions.get("exhaust_jstack_rearm")
    if not exhausted_jstack_rearm:
        errors.append("installed JStack BootNext flow lacks an exhausted-rearm transition")
    elif (
        exhausted_jstack_rearm.get("from") != "windows.jstack_rearm"
        or exhausted_jstack_rearm.get("to") != "recovery.rollback_required"
        or "jstack_rearm_exhausted"
        not in exhausted_jstack_rearm.get("guards", [])
    ):
        errors.append("exhaust_jstack_rearm must route exhausted retry to rollback")

    prepare = transitions.get("prepare_bitlocker")
    if prepare:
        action_ids = prepare.get("actions", [])
        if action_ids != ["register_windows_finalizer"]:
            errors.append("prepare_bitlocker must only register the Windows finalizer")
        for guard in ("bitlocker_recovery_key_confirmed", "confirmed_plan_current"):
            if guard not in prepare.get("guards", []):
                errors.append(f"prepare_bitlocker lacks {guard}")

    suspend = transitions.get("suspend_bitlocker_after_finalizer")
    if not suspend:
        errors.append("BitLocker flow lacks suspend_bitlocker_after_finalizer")
    elif (
        suspend.get("from") != "windows.bitlocker_finalizer_registered"
        or suspend.get("to") != "windows.bitlocker_prepared"
        or suspend.get("actions") != ["suspend_bitlocker"]
        or "finalizer_registered" not in suspend.get("guards", [])
    ):
        errors.append("BitLocker suspension must follow durable finalizer registration")

    suspend_action = actions.get("suspend_bitlocker", {})
    if suspend_action.get("parameters", {}).get("reboot_count") != 0:
        errors.append("suspend_bitlocker must use explicit RebootCount 0")
    finalizer_action = actions.get("register_windows_finalizer", {})
    finalizer_parameters = finalizer_action.get("parameters", {})
    if (
        finalizer_parameters.get("startup_trigger") != "boot"
        or finalizer_parameters.get("requires_signed_handoff_token") is not True
    ):
        errors.append(
            "register_windows_finalizer must install a boot-start signed-token dispatcher"
        )

    complete = transitions.get("complete_after_first_boot")
    if complete:
        for guard in {
            "jstack_boot_entry_valid",
            "bitlocker_restored_or_not_applicable",
            "windows_boot_entry_present",
        }:
            if guard not in complete.get("guards", []):
                errors.append(f"complete_after_first_boot lacks {guard}")

    unsupported_reachable = states_reaching_any(model, {"terminal.unsupported"})
    for transition_id, transition in transitions.items():
        if transition.get("from") not in reachable:
            continue
        destinations = {transition.get("to"), valid_failure_target(transition)}
        if not any(destination in unsupported_reachable for destination in destinations):
            continue
        forbidden_actions = [
            action_id
            for action_id in transition.get("actions", [])
            if action_id in actions and actions[action_id].get("risk") in SYSTEM_MUTATING_RISKS
        ]
        if forbidden_actions:
            errors.append(
                f"unsupported-platform path includes system mutation in {transition_id}: "
                + ", ".join(forbidden_actions)
            )

    for action_id in ("shrink_windows_ntfs", "expand_windows_ntfs"):
        action = actions.get(action_id)
        if action and action.get("platform") != "windows":
            errors.append(f"NTFS action {action_id} must run on Windows")

    forbidden_terms = ("replace_disk", "erase_windows", "delete_windows")
    serialized = json.dumps(model).lower()
    for term in forbidden_terms:
        if term in serialized and term not in model.get("scope", {}).get("unsupported", []):
            errors.append(f"v1 model contains forbidden destructive term: {term}")

    known_enforcers = set(guards) | set(actions)
    for invariant in model["invariants"]:
        for enforcer in invariant.get("enforced_by", []):
            if not enforcer.startswith("validator:") and enforcer not in known_enforcers:
                errors.append(
                    f"invariant {invariant['id']} references unknown enforcer {enforcer}"
                )

    return errors


def _valid_trace_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == set(EVIDENCE_IDENTITY_FIELDS)
        and all(
            isinstance(value.get(field), str) and DIGEST_RE.fullmatch(value[field])
            for field in EVIDENCE_IDENTITY_FIELDS
        )
    )


def validate_trace(model: dict[str, Any], trace: dict[str, Any]) -> list[str]:
    """Validate semantic evidence/proof linkage while abstract traces stay compact."""

    errors: list[str] = []
    trace_id = trace.get("id", "<unknown>")
    trace_kind = trace.get("trace_kind", "abstract")
    if trace_kind not in {"abstract", "evidence"}:
        return [f"trace {trace_id} has unknown trace_kind {trace_kind}"]

    steps = trace.get("steps", [])
    if not isinstance(steps, list):
        return [f"trace {trace_id} steps must be an array"]

    if trace_kind == "abstract":
        for field in ("identity", "evidence", "proofs"):
            if field in trace:
                errors.append(
                    f"abstract trace {trace_id} must not embed evidence field {field}"
                )
        for index, step in enumerate(steps):
            if isinstance(step, dict) and "proof" in step:
                errors.append(
                    f"abstract trace {trace_id} step {index} must not reference a proof"
                )
        return errors

    identity = trace.get("identity")
    if not _valid_trace_identity(identity):
        errors.append(f"evidence trace {trace_id} has invalid or incomplete run identity")

    raw_evidence = trace.get("evidence")
    if not isinstance(raw_evidence, list) or not raw_evidence:
        errors.append(f"evidence trace {trace_id} requires a non-empty evidence index")
        raw_evidence = []
    evidence_by_id: dict[str, dict[str, Any]] = {}
    evidence_paths: set[str] = set()
    evidence_digests: set[str] = set()
    for index, witness in enumerate(raw_evidence):
        where = f"evidence trace {trace_id} witness {index}"
        if not isinstance(witness, dict):
            errors.append(f"{where} must be an object")
            continue
        witness_id = witness.get("id")
        if not isinstance(witness_id, str) or not IDENTIFIER_RE.fullmatch(witness_id):
            errors.append(f"{where} has invalid id")
            continue
        if witness_id in evidence_by_id:
            errors.append(f"evidence trace {trace_id} has duplicate witness id {witness_id}")
            continue
        evidence_by_id[witness_id] = witness
        expected_witness_keys = {"id", "role", "path", "size", "sha256", "identity"}
        if set(witness) != expected_witness_keys:
            errors.append(
                f"{where} fields must be exactly "
                + ", ".join(sorted(expected_witness_keys))
            )
        role = witness.get("role")
        if not isinstance(role, str) or not IDENTIFIER_RE.fullmatch(role):
            errors.append(f"{where} has invalid role")
        path = witness.get("path")
        if not isinstance(path, str) or not EVIDENCE_PATH_RE.fullmatch(path):
            errors.append(f"{where} has invalid artifact path")
        elif path in evidence_paths:
            errors.append(f"{where} reuses artifact path {path}")
        else:
            evidence_paths.add(path)
        size = witness.get("size")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 1 <= size <= 67108864
        ):
            errors.append(f"{where} has invalid artifact size")
        digest = witness.get("sha256")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            errors.append(f"{where} lacks a lowercase sha256 content address")
        elif digest in evidence_digests:
            errors.append(f"{where} reuses witness content digest {digest}")
        else:
            evidence_digests.add(digest)
        if witness.get("identity") != identity:
            errors.append(f"{where} identity disagrees with the trace run identity")

    raw_proofs = trace.get("proofs")
    if not isinstance(raw_proofs, list) or not raw_proofs:
        errors.append(f"evidence trace {trace_id} requires proof declarations")
        raw_proofs = []
    proofs_by_id: dict[str, dict[str, Any]] = {}
    referenced_witnesses: set[str] = set()
    witness_owner: dict[str, str] = {}
    for index, proof in enumerate(raw_proofs):
        where = f"evidence trace {trace_id} proof {index}"
        if not isinstance(proof, dict):
            errors.append(f"{where} must be an object")
            continue
        proof_id = proof.get("id")
        if not isinstance(proof_id, str) or not IDENTIFIER_RE.fullmatch(proof_id):
            errors.append(f"{where} has invalid id")
            continue
        if proof_id in proofs_by_id:
            errors.append(f"evidence trace {trace_id} has duplicate proof id {proof_id}")
            continue
        proofs_by_id[proof_id] = proof
        transition_id = proof.get("transition")
        if transition_id not in index_by_id(model["transitions"]):
            errors.append(f"{where} references unknown transition {transition_id}")
        kind = proof.get("kind")
        if kind not in {"transition", "rollback"}:
            errors.append(f"{where} has unknown kind {kind}")
        expected_proof_keys = {"id", "kind", "transition", "witnesses"}
        if kind == "rollback":
            expected_proof_keys.add("expected_terminal")
        if set(proof) != expected_proof_keys:
            errors.append(
                f"{where} fields must be exactly "
                + ", ".join(sorted(expected_proof_keys))
            )
        raw_witness_ids = proof.get("witnesses")
        if not isinstance(raw_witness_ids, list) or not raw_witness_ids:
            errors.append(f"{where} requires at least one witness")
        witness_ids = raw_witness_ids if isinstance(raw_witness_ids, list) else []
        witness_references_valid = not any(
            not isinstance(witness_id, str)
            or not IDENTIFIER_RE.fullmatch(witness_id)
            for witness_id in witness_ids
        )
        if not witness_references_valid:
            errors.append(f"{where} has invalid witness references")
        if witness_references_valid and len(set(witness_ids)) != len(witness_ids):
            errors.append(f"{where} contains duplicate witness references")
        for witness_id in witness_ids if witness_references_valid else []:
            referenced_witnesses.add(witness_id)
            if witness_id not in evidence_by_id:
                errors.append(f"{where} references missing witness {witness_id}")
            previous_owner = witness_owner.get(witness_id)
            if previous_owner is not None and previous_owner != proof_id:
                errors.append(
                    f"{where} reuses witness {witness_id} already owned by proof "
                    f"{previous_owner}"
                )
            else:
                witness_owner[witness_id] = proof_id
        if kind == "transition" and "expected_terminal" in proof:
            errors.append(f"{where} transition proof must not declare expected_terminal")
        if kind == "rollback":
            witness_roles = [
                evidence_by_id[witness_id].get("role")
                for witness_id in witness_ids
                if witness_id in evidence_by_id
            ]
            roles_are_exact = all(
                isinstance(role, str) for role in witness_roles
            ) and Counter(witness_roles) == Counter(ROLLBACK_PROOF_WITNESS_ROLES)
            if not roles_are_exact:
                errors.append(
                    f"{where} rollback witness roles must be exactly "
                    + ", ".join(ROLLBACK_PROOF_WITNESS_ROLES)
                )
            expected = proof.get("expected_terminal")
            if expected not in {"terminal.rolled_back", "terminal.manual_recovery"}:
                errors.append(f"{where} rollback proof has invalid expected_terminal")
            if trace.get("expected_terminal") != expected:
                errors.append(
                    f"{where} rollback outcome disagrees with trace expected_terminal"
                )

    used_proofs: set[str] = set()
    transitions = index_by_id(model["transitions"])
    for index, step in enumerate(steps):
        if isinstance(step, str):
            transition_id = step
            outcome = "success"
            proof_id = None
        elif isinstance(step, dict):
            transition_id = step.get("transition")
            outcome = step.get("outcome", "success")
            proof_id = step.get("proof")
        else:
            continue

        requirement = ASSURANCE_TRANSITION_REQUIREMENTS.get(transition_id)
        if requirement and outcome == "success" and not proof_id:
            errors.append(
                f"evidence trace {trace_id} step {index} transition {transition_id} "
                "requires a proof reference"
            )
        if not proof_id:
            continue
        proof = proofs_by_id.get(proof_id)
        if not proof:
            errors.append(
                f"evidence trace {trace_id} step {index} references missing proof {proof_id}"
            )
            continue
        used_proofs.add(proof_id)
        if proof.get("transition") != transition_id:
            errors.append(
                f"evidence trace {trace_id} step {index} proof {proof_id} is for "
                f"{proof.get('transition')}, not {transition_id}"
            )
        if requirement and outcome == "success":
            if proof.get("kind") != "transition":
                errors.append(
                    f"assurance transition {transition_id} requires a transition proof"
                )
            witness_roles = [
                evidence_by_id[witness_id].get("role")
                for witness_id in proof.get("witnesses", [])
                if witness_id in evidence_by_id
            ]
            required_roles = list(requirement["witness_roles"])
            if sorted(witness_roles) != sorted(required_roles):
                errors.append(
                    f"assurance transition {transition_id} proof {proof_id} witness roles "
                    "must be exactly "
                    + ", ".join(required_roles)
                )
        if proof.get("kind") == "rollback" and transition_id in transitions:
            result = (
                transitions[transition_id].get("to")
                if outcome == "success"
                else valid_failure_target(transitions[transition_id])
                if outcome == "failure"
                else None
            )
            if result != proof.get("expected_terminal"):
                errors.append(
                    f"rollback proof {proof_id} does not attest a step reaching "
                    f"{proof.get('expected_terminal')}"
                )

    for proof_id in sorted(set(proofs_by_id) - used_proofs):
        errors.append(f"evidence trace {trace_id} proof {proof_id} is not linked from a step")
    for witness_id in sorted(set(evidence_by_id) - referenced_witnesses):
        errors.append(
            f"evidence trace {trace_id} witness {witness_id} is not linked from a proof"
        )

    return errors


def simulate_trace(model: dict[str, Any], trace: dict[str, Any]) -> str:
    trace_errors = validate_trace(model, trace)
    if trace_errors:
        raise AssertionError(trace_errors[0])
    transitions = index_by_id(model["transitions"])
    actions = index_by_id(model["actions"])
    current = model["initial_state"]

    for index, raw_step in enumerate(trace["steps"]):
        if isinstance(raw_step, str):
            transition_id = raw_step
            outcome = "success"
        else:
            transition_id = raw_step["transition"]
            outcome = raw_step.get("outcome", "success")

        if transition_id not in transitions:
            raise AssertionError(
                f"trace {trace['id']} step {index} references unknown transition {transition_id}"
            )
        transition = transitions[transition_id]
        if transition["from"] != current:
            raise AssertionError(
                f"trace {trace['id']} step {index} expected source {current}, "
                f"but {transition_id} starts at {transition['from']}"
            )

        if outcome == "success":
            current = transition["to"]
        elif outcome == "failure":
            failure = valid_failure_target(transition)
            if not failure:
                raise AssertionError(
                    f"trace {trace['id']} injects failure into {transition_id} without failure_to"
                )
            current = failure
        elif outcome in {
            "interrupted_precondition",
            "interrupted_postcondition",
            "interrupted_divergent",
        }:
            if not transition_is_mutating(transition, actions):
                raise AssertionError(
                    f"trace {trace['id']} interrupts non-mutating transition {transition_id}"
                )
            observed = outcome.removeprefix("interrupted_")
            current = reconcile_interruption(transition, actions, observed)
        else:
            raise AssertionError(f"trace {trace['id']} uses unknown outcome {outcome}")

    return current


def clone_model(model: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(model)
