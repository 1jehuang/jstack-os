from __future__ import annotations

import hashlib
import json
import sys
import unittest
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from state_model import (  # noqa: E402
    ASSURANCE_TRANSITION_REQUIREMENTS,
    EVIDENCE_IDENTITY_FIELDS,
    MUTATING_RISKS,
    ROLLBACK_MUTATING_TRANSITION_IDS,
    ROLLBACK_PROOF_WITNESS_ROLES,
    SYSTEM_MUTATING_RISKS,
    clone_model,
    index_by_id,
    load_json,
    reconcile_interruption,
    rollback_mutating_transition_ids,
    simulate_trace,
    states_reaching_any,
    transition_is_mutating,
    transition_is_system_mutating,
    validate_against_schema,
    validate_model,
    validate_trace,
)


def path_to_state(model: dict, target: str) -> list[str | dict[str, str]]:
    """Return a shortest executable sequence reaching target through any edge."""

    initial = model["initial_state"]
    if target == initial:
        return []

    transitions_by_source: dict[str, list[dict]] = {}
    for transition in model["transitions"]:
        transitions_by_source.setdefault(transition["from"], []).append(transition)

    queue = deque([(initial, [])])
    visited = {initial}
    while queue:
        state, steps = queue.popleft()
        for transition in transitions_by_source.get(state, []):
            outcomes: list[tuple[str, str | dict[str, str]]] = [
                (transition["to"], transition["id"])
            ]
            if "failure_to" in transition:
                failure = transition["failure_to"]
                if not isinstance(failure, str) or not failure:
                    raise AssertionError(
                        f"transition {transition['id']} has invalid failure_to"
                    )
                outcomes.append(
                    (
                        failure,
                        {"transition": transition["id"], "outcome": "failure"},
                    )
                )
            for next_state, step in outcomes:
                next_steps = [*steps, step]
                if next_state == target:
                    return next_steps
                if next_state not in visited:
                    visited.add(next_state)
                    queue.append((next_state, next_steps))

    raise AssertionError(f"no executable path reaches {target}")


def evidence_identity() -> dict[str, str]:
    return {
        field: hashlib.sha256(f"test-{field}".encode()).hexdigest()
        for field in EVIDENCE_IDENTITY_FIELDS
    }


def evidence_trace(
    model: dict,
    steps: list[str | dict[str, str]],
    expected_terminal: str,
) -> dict:
    identity = evidence_identity()
    witnesses: list[dict] = []
    proofs: list[dict] = []
    linked_steps: list[str | dict[str, str]] = []
    for raw_step in steps:
        if isinstance(raw_step, str):
            transition_id = raw_step
            outcome = "success"
        else:
            transition_id = raw_step["transition"]
            outcome = raw_step.get("outcome", "success")
        requirement = ASSURANCE_TRANSITION_REQUIREMENTS.get(transition_id)
        if not requirement or outcome != "success":
            linked_steps.append(raw_step)
            continue

        proof_id = f"{transition_id}.proof"
        witness_ids: list[str] = []
        for role in requirement["witness_roles"]:
            witness_id = f"{transition_id}.{role}"
            witness_ids.append(witness_id)
            witnesses.append(
                {
                    "id": witness_id,
                    "role": role,
                    "path": f"artifacts/{witness_id}.json",
                    "size": 1,
                    "sha256": hashlib.sha256(witness_id.encode()).hexdigest(),
                    "identity": dict(identity),
                }
            )
        proofs.append(
            {
                "id": proof_id,
                "kind": "transition",
                "transition": transition_id,
                "witnesses": witness_ids,
            }
        )
        linked_steps.append(
            {"transition": transition_id, "outcome": outcome, "proof": proof_id}
        )

    return {
        "id": "evidence_trace",
        "description": "Proof-bearing trace with external content-addressed witnesses.",
        "trace_kind": "evidence",
        "identity": identity,
        "evidence": witnesses,
        "proofs": proofs,
        "steps": linked_steps,
        "expected_terminal": expected_terminal,
    }


class StateModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = load_json(ROOT / "model" / "installer-state-graph.json")

    def test_model_is_semantically_valid(self) -> None:
        self.assertEqual(validate_model(self.model), [])

    def test_all_scenario_traces_reach_expected_terminal(self) -> None:
        for trace_path in sorted((ROOT / "traces").glob("*.json")):
            with self.subTest(trace=trace_path.name):
                trace = load_json(trace_path)
                self.assertEqual(simulate_trace(self.model, trace), trace["expected_terminal"])

    def test_scenario_traces_cover_every_terminal(self) -> None:
        expected = {
            state["id"]
            for state in self.model["states"]
            if state["kind"] == "terminal"
        }
        actual = {
            load_json(path)["expected_terminal"]
            for path in (ROOT / "traces").glob("*.json")
        }
        self.assertEqual(actual, expected)

    def test_every_transition_success_edge_is_executable(self) -> None:
        for transition in self.model["transitions"]:
            with self.subTest(transition=transition["id"]):
                steps = path_to_state(self.model, transition["from"])
                steps.append(transition["id"])
                trace = {"id": f"generated-{transition['id']}-success", "steps": steps}
                self.assertEqual(simulate_trace(self.model, trace), transition["to"])

    def test_every_transition_failure_edge_is_executable(self) -> None:
        for transition in self.model["transitions"]:
            if "failure_to" not in transition:
                continue
            failure = transition["failure_to"]
            self.assertIsInstance(failure, str)
            self.assertTrue(failure)
            with self.subTest(transition=transition["id"]):
                steps = path_to_state(self.model, transition["from"])
                steps.append({"transition": transition["id"], "outcome": "failure"})
                trace = {"id": f"generated-{transition['id']}-failure", "steps": steps}
                self.assertEqual(simulate_trace(self.model, trace), failure)

    def test_validator_rejects_invalid_failure_targets(self) -> None:
        model_schema = load_json(ROOT / "model" / "schema.json")
        cases = (
            ("", "failure_to must be a non-empty state id", True),
            (None, "failure_to must be a non-empty state id", True),
            ([], "failure_to must be a non-empty state id", True),
            (
                "definitely_absent.failure_target",
                "has unknown failure target definitely_absent.failure_target",
                False,
            ),
        )
        for value, expected_error, schema_rejects in cases:
            with self.subTest(value=value):
                unsafe = clone_model(self.model)
                transition = next(
                    transition
                    for transition in unsafe["transitions"]
                    if transition["id"] == "mark_release_acquisition_failed"
                )
                transition["failure_to"] = value

                self.assertTrue(
                    any(expected_error in error for error in validate_model(unsafe))
                )
                schema_errors = validate_against_schema(unsafe, model_schema)
                self.assertEqual(bool(schema_errors), schema_rejects)

        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "begin_preflight"
        )
        transition.pop("failure_to")
        self.assertIn(
            "mutating transition begin_preflight lacks failure_to",
            validate_model(unsafe),
        )

    def test_every_mutation_has_deterministic_interruption_semantics(self) -> None:
        actions = index_by_id(self.model["actions"])
        for transition in self.model["transitions"]:
            if not transition_is_mutating(transition, actions):
                continue
            with self.subTest(transition=transition["id"]):
                self.assertTrue(transition["journal"]["intent_before_actions"])
                self.assertTrue(transition["journal"]["commit_after_postconditions"])
                self.assertTrue(transition["preconditions"])
                self.assertTrue(transition["postconditions"])
                self.assertIn("failure_to", transition)
                for action_id in transition["actions"]:
                    action = actions[action_id]
                    if action["risk"] in MUTATING_RISKS:
                        self.assertIn(
                            action["recovery"],
                            {"retry", "reconcile", "compensate", "reconcile_then_compensate"},
                        )

    def test_every_mutation_resolves_all_documented_power_loss_points(self) -> None:
        actions = index_by_id(self.model["actions"])
        phase_observations = {
            "before_intent": "precondition",
            "after_intent_before_mutation": "precondition",
            "during_mutation_before_effect": "precondition",
            "during_mutation_after_effect": "postcondition",
            "after_mutation_before_observation": "postcondition",
            "after_observation_before_commit": "postcondition",
            "after_commit_before_state_advance": "postcondition",
        }
        for transition in self.model["transitions"]:
            if not transition_is_mutating(transition, actions):
                continue
            for phase, observed in phase_observations.items():
                with self.subTest(transition=transition["id"], phase=phase):
                    expected = (
                        transition["from"]
                        if observed == "precondition"
                        else transition["to"]
                    )
                    self.assertEqual(
                        reconcile_interruption(transition, actions, observed), expected
                    )
            with self.subTest(transition=transition["id"], phase="divergent"):
                self.assertEqual(
                    reconcile_interruption(transition, actions, "divergent"),
                    transition["failure_to"],
                )

    def test_every_mutation_failure_can_reach_safe_terminal(self) -> None:
        actions = index_by_id(self.model["actions"])
        system_safe_reachable = states_reaching_any(
            self.model, {"terminal.rolled_back", "terminal.manual_recovery"}
        )
        staging_safe_reachable = states_reaching_any(
            self.model, {"terminal.cancelled", "terminal.manual_recovery"}
        )
        for transition in self.model["transitions"]:
            if not transition_is_mutating(transition, actions):
                continue
            with self.subTest(transition=transition["id"]):
                reachable = (
                    system_safe_reachable
                    if transition_is_system_mutating(transition, actions)
                    else staging_safe_reachable
                )
                self.assertIn(transition["failure_to"], reachable)

    def test_validator_rejects_unauthorized_disk_mutation(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["authorization"] = []
        errors = validate_model(unsafe)
        self.assertIn(
            "forward mutation reserve_windows_space lacks confirmed_plan authorization",
            errors,
        )

    def test_rollback_mutation_set_is_exact_and_graph_derived(self) -> None:
        expected = {
            "dispatch_rollback_linux",
            "reboot_to_windows_rollback",
            "execute_windows_rollback",
            "rollback_remove_esp_files",
            "rollback_delete_partitions",
            "rollback_expand_windows",
            "rollback_restore_security",
            "rollback_unregister_finalizer",
        }
        actions = index_by_id(self.model["actions"])

        self.assertEqual(set(ROLLBACK_MUTATING_TRANSITION_IDS), expected)
        self.assertEqual(
            rollback_mutating_transition_ids(self.model, actions), expected
        )

    def test_validator_requires_rollback_authorization_on_rollback_mutations(
        self,
    ) -> None:
        for transition_id in ROLLBACK_MUTATING_TRANSITION_IDS:
            with self.subTest(transition=transition_id):
                unsafe = clone_model(self.model)
                transition = next(
                    transition
                    for transition in unsafe["transitions"]
                    if transition["id"] == transition_id
                )
                transition["authorization"] = []

                self.assertIn(
                    f"rollback mutation {transition_id} lacks rollback_authorized",
                    validate_model(unsafe),
                )

    def test_validator_rejects_expanded_rollback_mutation_closure(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["from"] = "recovery.rollback_required"
        transition["authorization"] = ["rollback_authorized"]
        transition["guards"].extend(
            ["rollback_permitted", "rollback_identity_current"]
        )

        errors = validate_model(unsafe)
        closure_errors = [
            error
            for error in errors
            if error.startswith(
                "rollback mutation closure contains unexpected transitions: "
            )
        ]
        self.assertEqual(len(closure_errors), 1)
        self.assertIn("reserve_windows_space", closure_errors[0])

    def test_validator_rejects_preconfirmation_failure_entry_into_rollback(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = index_by_id(unsafe["transitions"])["acquire_release_manifest"]
        transition["failure_to"] = "recovery.rollback_required"

        errors = validate_model(unsafe)
        self.assertIn(
            "mutating transition dispatch_rollback_linux is reachable without "
            "plan confirmation",
            errors,
        )

    def test_validator_rejects_preconfirmation_success_entry_into_rollback(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = index_by_id(unsafe["transitions"])["acquire_release_manifest"]
        transition["to"] = "recovery.rollback_required"

        errors = validate_model(unsafe)
        self.assertIn(
            "mutating transition dispatch_rollback_linux is reachable without "
            "plan confirmation",
            errors,
        )

    def test_validator_rejects_preconfirmation_failure_entry_mid_rollback(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = index_by_id(unsafe["transitions"])["acquire_release_manifest"]
        transition["failure_to"] = "windows.rollback_boot_entries_removed"

        errors = validate_model(unsafe)
        self.assertIn(
            "mutating transition rollback_remove_esp_files is reachable without "
            "plan confirmation",
            errors,
        )
        self.assertIn(
            "rollback mutation rollback_remove_esp_files is reachable without "
            "recovery.rollback_required",
            errors,
        )

    def test_validator_rejects_rollback_failure_edges_escaping_to_forward_states(
        self,
    ) -> None:
        for target in ("windows.plan_confirmed", "windows.preflight"):
            with self.subTest(target=target):
                unsafe = clone_model(self.model)
                transition = index_by_id(unsafe["transitions"])[
                    "rollback_remove_esp_files"
                ]
                transition["failure_to"] = target

                errors = validate_model(unsafe)
                self.assertIn(
                    "rollback transition rollback_remove_esp_files failure target "
                    f"{target} escapes closed recovery subgraph",
                    errors,
                )

    def test_validator_rejects_rollback_success_edges_escaping_to_forward_states(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = index_by_id(unsafe["transitions"])["rollback_remove_esp_files"]
        transition["to"] = "windows.plan_confirmed"

        errors = validate_model(unsafe)
        self.assertIn(
            "rollback transition rollback_remove_esp_files success target "
            "windows.plan_confirmed escapes closed recovery subgraph",
            errors,
        )

    def test_validator_applies_rollback_authorization_across_all_edges(
        self,
    ) -> None:
        for edge_name in ("to", "failure_to"):
            with self.subTest(edge=edge_name):
                unsafe = clone_model(self.model)
                transition = index_by_id(unsafe["transitions"])[
                    "rollback_remove_esp_files"
                ]
                transition[edge_name] = "windows.plan_confirmed"

                errors = validate_model(unsafe)
                self.assertIn(
                    "rollback mutation reserve_windows_space lacks rollback_authorized",
                    errors,
                )
                self.assertTrue(
                    any(
                        error.startswith(
                            "rollback mutation closure contains unexpected "
                            "transitions: "
                        )
                        and "reserve_windows_space" in error
                        for error in errors
                    )
                )

    def test_validator_rejects_required_rollback_mutation_outside_closed_set(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = index_by_id(unsafe["transitions"])["rollback_delete_partitions"]
        transition["from"] = "windows.plan_confirmed"

        errors = validate_model(unsafe)
        self.assertTrue(
            any(
                error.startswith(
                    "rollback mutation closure lacks required transitions: "
                )
                and "rollback_delete_partitions" in error
                for error in errors
            )
        )
        self.assertIn(
            "rollback mutation rollback_delete_partitions is reachable without "
            "recovery.rollback_required",
            errors,
        )

    def test_validator_rejects_rollback_authorization_on_forward_mutation(
        self,
    ) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["authorization"] = ["rollback_authorized"]
        transition["guards"].extend(
            ["rollback_permitted", "rollback_identity_current"]
        )

        errors = validate_model(unsafe)
        self.assertIn(
            "non-rollback mutation reserve_windows_space must not use rollback_authorized",
            errors,
        )
        self.assertIn(
            "forward mutation reserve_windows_space lacks confirmed_plan authorization",
            errors,
        )

    def test_rollback_authorization_cannot_bypass_plan_dominance(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["from"] = unsafe["initial_state"]
        transition["authorization"] = ["rollback_authorized"]
        transition["guards"].extend(
            ["rollback_permitted", "rollback_identity_current"]
        )

        errors = validate_model(unsafe)
        self.assertIn(
            "non-rollback mutation reserve_windows_space must not use rollback_authorized",
            errors,
        )
        self.assertIn(
            "mutating transition reserve_windows_space is reachable without plan confirmation",
            errors,
        )

    def test_validator_rejects_unauthorized_staging_mutation(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "persist_release_acceptance"
        )
        transition["authorization"] = []
        errors = validate_model(unsafe)
        self.assertIn(
            "staging transition persist_release_acceptance lacks release_policy authorization",
            errors,
        )

    def test_validator_cannot_relabel_staging_mutations_as_read_only(self) -> None:
        for action_id in (
            "reconcile_staging_store",
            "persist_release_acceptance",
            "stage_payload_quarantine",
            "promote_verified_payload",
        ):
            with self.subTest(action=action_id):
                unsafe = clone_model(self.model)
                action = next(
                    action for action in unsafe["actions"] if action["id"] == action_id
                )
                action["risk"] = "read_only"
                transition = next(
                    transition
                    for transition in unsafe["transitions"]
                    if action_id in transition["actions"]
                )
                transition["authorization"] = []
                transition["preconditions"] = []
                transition["postconditions"] = []
                transition.pop("failure_to", None)
                transition["journal"] = {
                    "intent_before_actions": False,
                    "commit_after_postconditions": False,
                }

                errors = validate_model(unsafe)
                self.assertIn(
                    f"safety-critical action {action_id} risk must be staging_mutation",
                    errors,
                )

    def test_validator_rejects_read_only_aliases_in_staging_transitions(self) -> None:
        bindings = {
            "begin_preflight": "reconcile_staging_store",
            "persist_release_acceptance": "persist_release_acceptance",
            "begin_payload_staging": "stage_payload_quarantine",
            "accept_verified_payload": "promote_verified_payload",
        }
        for transition_id, action_id in bindings.items():
            with self.subTest(transition=transition_id):
                unsafe = clone_model(self.model)
                original = next(
                    action for action in unsafe["actions"] if action["id"] == action_id
                )
                alias = dict(original)
                alias["id"] = f"{action_id}_alias"
                alias["risk"] = "read_only"
                unsafe["actions"].append(alias)

                transition = next(
                    transition
                    for transition in unsafe["transitions"]
                    if transition["id"] == transition_id
                )
                transition["actions"] = [alias["id"]]
                transition["authorization"] = []
                transition["preconditions"] = []
                transition["postconditions"] = []
                transition.pop("failure_to", None)
                transition["journal"] = {
                    "intent_before_actions": False,
                    "commit_after_postconditions": False,
                }

                errors = validate_model(unsafe)
                self.assertIn(
                    f"safety-critical transition {transition_id} actions must be exactly {action_id}",
                    errors,
                )

    def test_validator_rejects_staging_failure_that_can_reach_success(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "begin_payload_staging"
        )
        transition["failure_to"] = "windows.payload_verified"
        errors = validate_model(unsafe)
        self.assertTrue(
            any("is not an explicit staging recovery checkpoint" in error for error in errors)
        )

    def test_release_acquisition_failure_is_retryable_without_manual_recovery(self) -> None:
        transitions = index_by_id(self.model["transitions"])
        begin = transitions["begin_preflight"]
        acquire = transitions["acquire_release_manifest"]
        retry = transitions["retry_release_acquisition"]
        cancel = transitions["cancel_release_acquisition"]

        self.assertEqual(begin["actions"], ["reconcile_staging_store"])
        self.assertEqual(begin["to"], "windows.staging_reconciled")
        self.assertEqual(acquire["failure_to"], "windows.release_acquisition_failed")
        self.assertNotIn("reconcile_staging_store", acquire["actions"])
        self.assertEqual(retry["to"], "windows.staging_reconciled")
        self.assertEqual(cancel["to"], "terminal.cancelled")

    def test_validator_rejects_missing_pre_action_intent(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "create_linux_root"
        )
        transition["journal"]["intent_before_actions"] = False
        errors = validate_model(unsafe)
        self.assertTrue(any("lacks a pre-action intent record" in error for error in errors))

    def test_validator_rejects_stale_plan_before_mutation(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "deploy_jstack_image"
        )
        transition["guards"].remove("plan_fingerprint_current")
        errors = validate_model(unsafe)
        self.assertTrue(
            any("lacks plan_fingerprint_current guard" in error for error in errors)
        )

    def test_validator_rejects_cross_platform_action_authority(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["actor"] = "linux_installer"
        errors = validate_model(unsafe)
        self.assertTrue(any("cannot execute shrink_windows_ntfs" in error for error in errors))

    def test_validator_rejects_stale_rollback_identity(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "execute_windows_rollback"
        )
        transition["guards"].remove("rollback_identity_current")
        errors = validate_model(unsafe)
        self.assertTrue(any("lacks guards" in error for error in errors))

    def test_validator_rejects_unbounded_bootnext_rearm(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "arm_installer_reboot_retry"
        )
        transition["guards"].remove("installer_rearm_not_attempted")
        errors = validate_model(unsafe)
        self.assertIn(
            "arm_installer_reboot_retry lacks installer_rearm_not_attempted guard",
            errors,
        )

    def test_validator_rejects_stale_hash_guard_instead_of_bootnext_rehash(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "arm_installer_bootnext"
        )
        transition["actions"].remove("rehash_installer_boot_payload")
        transition["guards"].append("payload_hashes_valid")
        errors = validate_model(unsafe)
        self.assertIn(
            "arm_installer_bootnext lacks immediate installer payload rehash", errors
        )
        self.assertIn(
            "arm_installer_bootnext relies on stale payload_hashes_valid evidence",
            errors,
        )

    def test_validator_rejects_failure_edge_that_bypasses_success_gates(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "begin_preflight"
        )
        transition["failure_to"] = "terminal.completed"
        errors = validate_model(unsafe)
        self.assertTrue(any("success is reachable without required state" in e for e in errors))

    def test_validator_rejects_safety_critical_risk_relabeling(self) -> None:
        unsafe = clone_model(self.model)
        action = next(
            action
            for action in unsafe["actions"]
            if action["id"] == "shrink_windows_ntfs"
        )
        action["risk"] = "read_only"
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reserve_windows_space"
        )
        transition["authorization"] = []
        transition["guards"] = []
        transition["journal"]["intent_before_actions"] = False
        transition["journal"]["commit_after_postconditions"] = False
        transition["preconditions"] = []
        transition["postconditions"] = []
        transition.pop("failure_to")
        errors = validate_model(unsafe)
        self.assertIn(
            "safety-critical action shrink_windows_ntfs risk must be disk_mutation",
            errors,
        )

    def test_validator_rejects_missing_bitlocker_suspension(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "suspend_bitlocker_after_finalizer"
        )
        transition["actions"] = []
        errors = validate_model(unsafe)
        self.assertIn(
            "BitLocker suspension must follow durable finalizer registration", errors
        )

    def test_validator_rejects_missing_first_boot_security_guard(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "complete_after_first_boot"
        )
        transition["guards"].remove("bitlocker_restored_or_not_applicable")
        errors = validate_model(unsafe)
        self.assertIn(
            "complete_after_first_boot lacks bitlocker_restored_or_not_applicable",
            errors,
        )

    def test_validator_rejects_wrong_handoff_actor(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "reboot_to_installer"
        )
        transition["handoff"]["next_actor"] = "windows_finalizer"
        errors = validate_model(unsafe)
        self.assertIn(
            "reboot transition reboot_to_installer must hand off to linux_installer",
            errors,
        )

    def test_validator_rejects_multiple_mutations_in_one_transition(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "prepare_bitlocker"
        )
        transition["actions"].append("suspend_bitlocker")
        errors = validate_model(unsafe)
        self.assertTrue(any("combines multiple mutations" in error for error in errors))

    def test_validator_rejects_implicit_bitlocker_reboot_count(self) -> None:
        unsafe = clone_model(self.model)
        action = next(
            action
            for action in unsafe["actions"]
            if action["id"] == "suspend_bitlocker"
        )
        action["parameters"]["reboot_count"] = 2
        errors = validate_model(unsafe)
        self.assertIn("suspend_bitlocker must use explicit RebootCount 0", errors)

    def test_validator_rejects_unbounded_jstack_boot_rearm(self) -> None:
        unsafe = clone_model(self.model)
        transition = next(
            transition
            for transition in unsafe["transitions"]
            if transition["id"] == "arm_jstack_reboot_retry"
        )
        transition["guards"].remove("jstack_rearm_not_attempted")
        errors = validate_model(unsafe)
        self.assertIn(
            "arm_jstack_reboot_retry lacks jstack_rearm_not_attempted guard", errors
        )

    def test_assurance_transitions_declare_concrete_identity_bound_evidence(self) -> None:
        transitions = index_by_id(self.model["transitions"])
        guards = index_by_id(self.model["guards"])
        for transition_id, requirement in ASSURANCE_TRANSITION_REQUIREMENTS.items():
            with self.subTest(transition=transition_id):
                transition = transitions[transition_id]
                guard_id = requirement["guard"]
                self.assertIn(guard_id, transition["guards"])
                self.assertTrue(
                    set(requirement["preconditions"]).issubset(
                        transition["preconditions"]
                    )
                )
                self.assertTrue(
                    set(requirement["postconditions"]).issubset(
                        transition["postconditions"]
                    )
                )
                declaration = guards[guard_id]["evidence"]
                self.assertEqual(declaration["claim"], transition_id)
                self.assertEqual(declaration["content_address"], "sha256")
                self.assertEqual(
                    declaration["identity_fields"], list(EVIDENCE_IDENTITY_FIELDS)
                )
                self.assertEqual(
                    declaration["witness_roles"], list(requirement["witness_roles"])
                )

    def test_validator_rejects_weakened_assurance_declarations(self) -> None:
        for transition_id, requirement in ASSURANCE_TRANSITION_REQUIREMENTS.items():
            cases = (
                (
                    "guard",
                    lambda transition, guard: transition["guards"].remove(
                        requirement["guard"]
                    ),
                    f"assurance transition {transition_id} lacks evidence guard",
                ),
                (
                    "precondition",
                    lambda transition, guard: transition["preconditions"].remove(
                        requirement["preconditions"][0]
                    ),
                    f"assurance transition {transition_id} lacks precondition",
                ),
                (
                    "postcondition",
                    lambda transition, guard: transition["postconditions"].remove(
                        requirement["postconditions"][0]
                    ),
                    f"assurance transition {transition_id} lacks postcondition",
                ),
                (
                    "claim",
                    lambda transition, guard: guard["evidence"].update(
                        claim="different_transition"
                    ),
                    f"assurance evidence guard {requirement['guard']} claim must be",
                ),
                (
                    "content-address",
                    lambda transition, guard: guard["evidence"].update(
                        content_address="path"
                    ),
                    "must require sha256 content addresses",
                ),
                (
                    "identity",
                    lambda transition, guard: guard["evidence"][
                        "identity_fields"
                    ].pop(),
                    "must require the complete run identity",
                ),
                (
                    "roles",
                    lambda transition, guard: guard["evidence"][
                        "witness_roles"
                    ].pop(),
                    "witness roles must be exactly",
                ),
            )
            for name, mutate, expected in cases:
                with self.subTest(transition=transition_id, mutation=name):
                    unsafe = clone_model(self.model)
                    transition = index_by_id(unsafe["transitions"])[transition_id]
                    guard = index_by_id(unsafe["guards"])[requirement["guard"]]
                    mutate(transition, guard)
                    self.assertTrue(
                        any(expected in error for error in validate_model(unsafe))
                    )

    def test_evidence_trace_links_content_addresses_without_bloating_abstract_traces(
        self,
    ) -> None:
        trace_schema = load_json(ROOT / "model" / "trace-schema.json")
        abstract = load_json(ROOT / "traces" / "happy-path-bitlocker.json")
        for field in ("trace_kind", "identity", "evidence", "proofs"):
            self.assertNotIn(field, abstract)
        self.assertEqual(validate_trace(self.model, abstract), [])

        trace = evidence_trace(
            self.model, abstract["steps"], abstract["expected_terminal"]
        )
        self.assertEqual(validate_against_schema(trace, trace_schema), [])
        self.assertEqual(validate_trace(self.model, trace), [])
        self.assertEqual(simulate_trace(self.model, trace), "terminal.completed")

    def test_evidence_trace_rejects_missing_mismatched_and_unaddressed_witnesses(
        self,
    ) -> None:
        abstract = load_json(ROOT / "traces" / "happy-path-bitlocker.json")
        trace_schema = load_json(ROOT / "model" / "trace-schema.json")
        valid = evidence_trace(
            self.model, abstract["steps"], abstract["expected_terminal"]
        )

        for transition_id in ASSURANCE_TRANSITION_REQUIREMENTS:
            step_index = next(
                index
                for index, step in enumerate(valid["steps"])
                if isinstance(step, dict) and step["transition"] == transition_id
            )
            with self.subTest(transition=transition_id, attack="missing-proof"):
                unsafe = clone_model(valid)
                unsafe["steps"][step_index].pop("proof")
                self.assertTrue(
                    any(
                        f"transition {transition_id} requires a proof reference" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

            with self.subTest(transition=transition_id, attack="identity-mismatch"):
                unsafe = clone_model(valid)
                proof_id = unsafe["steps"][step_index]["proof"]
                proof = next(item for item in unsafe["proofs"] if item["id"] == proof_id)
                witness_id = proof["witnesses"][0]
                witness = next(
                    item for item in unsafe["evidence"] if item["id"] == witness_id
                )
                witness["identity"]["plan_digest"] = "f" * 64
                self.assertTrue(
                    any(
                        "identity disagrees with the trace run identity" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

            with self.subTest(transition=transition_id, attack="missing-role"):
                unsafe = clone_model(valid)
                proof_id = unsafe["steps"][step_index]["proof"]
                proof = next(item for item in unsafe["proofs"] if item["id"] == proof_id)
                proof["witnesses"].pop()
                self.assertTrue(
                    any(
                        f"assurance transition {transition_id} proof" in error
                        and "witness roles must be exactly" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

            with self.subTest(transition=transition_id, attack="aliased-artifacts"):
                unsafe = clone_model(valid)
                proof_id = unsafe["steps"][step_index]["proof"]
                proof = next(item for item in unsafe["proofs"] if item["id"] == proof_id)
                witnesses = [
                    next(item for item in unsafe["evidence"] if item["id"] == witness_id)
                    for witness_id in proof["witnesses"]
                ]
                for witness in witnesses[1:]:
                    witness["path"] = witnesses[0]["path"]
                    witness["sha256"] = witnesses[0]["sha256"]
                    witness["size"] = witnesses[0]["size"]
                errors = validate_trace(self.model, unsafe)
                self.assertTrue(any("reuses artifact path" in error for error in errors))
                self.assertTrue(any("reuses witness content digest" in error for error in errors))

            with self.subTest(transition=transition_id, attack="extra-role"):
                unsafe = clone_model(valid)
                proof_id = unsafe["steps"][step_index]["proof"]
                proof = next(item for item in unsafe["proofs"] if item["id"] == proof_id)
                extra = clone_model(unsafe["evidence"][0])
                extra["id"] = f"{transition_id}.extra"
                extra["role"] = "extra"
                extra["path"] = f"artifacts/{transition_id}.extra.json"
                extra["sha256"] = hashlib.sha256(extra["id"].encode()).hexdigest()
                unsafe["evidence"].append(extra)
                proof["witnesses"].append(extra["id"])
                self.assertTrue(
                    any(
                        f"assurance transition {transition_id} proof" in error
                        and "witness roles must be exactly" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

        bad_digest = clone_model(valid)
        bad_digest["evidence"][0]["sha256"] = "not-a-digest"
        self.assertTrue(validate_against_schema(bad_digest, trace_schema))
        self.assertTrue(
            any(
                "lacks a lowercase sha256 content address" in error
                for error in validate_trace(self.model, bad_digest)
            )
        )

        dangling = clone_model(valid)
        dangling["proofs"][0]["witnesses"][0] = "missing.witness"
        self.assertTrue(
            any(
                "references missing witness missing.witness" in error
                for error in validate_trace(self.model, dangling)
            )
        )

        shared = clone_model(valid)
        first, second = shared["proofs"][:2]
        second["witnesses"][0] = first["witnesses"][0]
        self.assertTrue(
            any(
                "reuses witness" in error and "already owned by proof" in error
                for error in validate_trace(self.model, shared)
            )
        )

    def test_rollback_proof_declaration_is_schema_and_runtime_representable(self) -> None:
        trace_schema = load_json(ROOT / "model" / "trace-schema.json")
        trace = load_json(ROOT / "traces" / "post-shrink-failure-rollback.json")
        identity = evidence_identity()
        witness_id = "rollback.journal"
        proof_id = "rollback.completion.proof"
        trace.update(
            {
                "trace_kind": "evidence",
                "identity": identity,
                "evidence": [
                    {
                        "id": witness_id,
                        "role": "journal",
                        "path": "artifacts/rollback-journal.json",
                        "size": 1,
                        "sha256": hashlib.sha256(witness_id.encode()).hexdigest(),
                        "identity": dict(identity),
                    }
                ],
                "proofs": [
                    {
                        "id": proof_id,
                        "kind": "rollback",
                        "transition": "rollback_unregister_finalizer",
                        "witnesses": [witness_id],
                        "expected_terminal": "terminal.rolled_back",
                    }
                ],
            }
        )
        final_index = trace["steps"].index("rollback_unregister_finalizer")
        trace["steps"][final_index] = {
            "transition": "rollback_unregister_finalizer",
            "outcome": "success",
            "proof": proof_id,
        }
        self.assertEqual(validate_against_schema(trace, trace_schema), [])
        self.assertEqual(validate_trace(self.model, trace), [])
        self.assertEqual(simulate_trace(self.model, trace), "terminal.rolled_back")
        self.assertEqual(ROLLBACK_PROOF_WITNESS_ROLES, ("journal",))

        role_attacks = {
            "invented": lambda unsafe: unsafe["evidence"][0].update(
                role="invented-role"
            ),
            "missing": lambda unsafe: unsafe["proofs"][0].update(witnesses=[]),
        }
        for name, attack in role_attacks.items():
            with self.subTest(attack=name):
                unsafe = clone_model(trace)
                attack(unsafe)
                self.assertTrue(
                    any(
                        "rollback witness roles must be exactly journal" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

        for role in ("invented-role", "journal"):
            with self.subTest(attack="extra-role", role=role):
                unsafe = clone_model(trace)
                extra_id = f"rollback.extra.{role}"
                unsafe["evidence"].append(
                    {
                        "id": extra_id,
                        "role": role,
                        "path": f"artifacts/{extra_id}.json",
                        "size": 1,
                        "sha256": hashlib.sha256(extra_id.encode()).hexdigest(),
                        "identity": dict(identity),
                    }
                )
                unsafe["proofs"][0]["witnesses"].append(extra_id)
                self.assertTrue(
                    any(
                        "rollback witness roles must be exactly journal" in error
                        for error in validate_trace(self.model, unsafe)
                    )
                )

        missing_outcome = clone_model(trace)
        missing_outcome["proofs"][0].pop("expected_terminal")
        self.assertTrue(validate_against_schema(missing_outcome, trace_schema))
        self.assertTrue(validate_trace(self.model, missing_outcome))

        wrong_transition = clone_model(trace)
        wrong_transition["proofs"][0]["transition"] = "rollback_restore_security"
        wrong_transition["steps"][final_index][
            "transition"
        ] = "rollback_restore_security"
        self.assertTrue(
            any(
                "does not attest a step reaching terminal.rolled_back" in error
                for error in validate_trace(self.model, wrong_transition)
            )
        )

    def test_trace_schema_and_runtime_reject_the_same_new_structural_attacks(
        self,
    ) -> None:
        trace_schema = load_json(ROOT / "model" / "trace-schema.json")
        abstract = load_json(ROOT / "traces" / "happy-path-bitlocker.json")
        valid = evidence_trace(
            self.model, abstract["steps"], abstract["expected_terminal"]
        )
        attacks = {
            "path-traversal": lambda trace: trace["evidence"][0].update(
                path="artifacts/../escape.json"
            ),
            "empty-artifact": lambda trace: trace["evidence"][0].update(size=0),
            "extra-witness-field": lambda trace: trace["evidence"][0].update(
                unbound="value"
            ),
            "transition-proof-terminal": lambda trace: trace["proofs"][0].update(
                expected_terminal="terminal.rolled_back"
            ),
        }
        for name, attack in attacks.items():
            with self.subTest(attack=name):
                unsafe = clone_model(valid)
                attack(unsafe)
                self.assertTrue(validate_against_schema(unsafe, trace_schema))
                self.assertTrue(validate_trace(self.model, unsafe))

        abstract_with_proof = clone_model(abstract)
        abstract_with_proof["steps"][0] = {
            "transition": "begin_preflight",
            "outcome": "success",
            "proof": "not-allowed",
        }
        self.assertTrue(validate_against_schema(abstract_with_proof, trace_schema))
        self.assertTrue(validate_trace(self.model, abstract_with_proof))

    def test_unsupported_platform_path_allows_only_staging_persistence(self) -> None:
        trace = load_json(ROOT / "traces" / "preflight-rejection.json")
        transitions = index_by_id(self.model["transitions"])
        actions = index_by_id(self.model["actions"])
        path = [transitions[step] for step in trace["steps"]]
        self.assertEqual(
            [
                transition["id"]
                for transition in path
                if transition_is_system_mutating(transition, actions)
            ],
            [],
        )
        self.assertEqual(
            [
                transition["id"]
                for transition in path
                if transition_is_mutating(transition, actions)
            ],
            ["begin_preflight", "persist_release_acceptance"],
        )
        self.assertEqual(simulate_trace(self.model, trace), "terminal.unsupported")

        for action_id, action in actions.items():
            if action["risk"] not in SYSTEM_MUTATING_RISKS:
                continue
            with self.subTest(forbidden_action=action_id):
                unsafe = clone_model(self.model)
                reject = index_by_id(unsafe["transitions"])[
                    "reject_unsupported_platform"
                ]
                reject["actions"] = [action_id]
                self.assertIn(
                    "unsupported-platform path includes system mutation in "
                    f"reject_unsupported_platform: {action_id}",
                    validate_model(unsafe),
                )

    def test_schema_and_documents_are_valid(self) -> None:
        model_schema = load_json(ROOT / "model" / "schema.json")
        trace_schema = load_json(ROOT / "model" / "trace-schema.json")
        self.assertEqual(validate_against_schema(self.model, model_schema), [])
        for path in (ROOT / "model").glob("*.json"):
            with self.subTest(path=path.name):
                with path.open(encoding="utf-8") as handle:
                    self.assertIsInstance(json.load(handle), dict)
        for path in (ROOT / "traces").glob("*.json"):
            with self.subTest(trace=path.name):
                self.assertEqual(
                    validate_against_schema(load_json(path), trace_schema), []
                )


if __name__ == "__main__":
    unittest.main()
