from __future__ import annotations

import json
import sys
import unittest
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from state_model import (  # noqa: E402
    MUTATING_RISKS,
    clone_model,
    index_by_id,
    load_json,
    reconcile_interruption,
    simulate_trace,
    states_reaching_any,
    transition_is_mutating,
    transition_is_system_mutating,
    validate_against_schema,
    validate_model,
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
            if failure := transition.get("failure_to"):
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
            failure = transition.get("failure_to")
            if not failure:
                continue
            with self.subTest(transition=transition["id"]):
                steps = path_to_state(self.model, transition["from"])
                steps.append({"transition": transition["id"], "outcome": "failure"})
                trace = {"id": f"generated-{transition['id']}-failure", "steps": steps}
                self.assertEqual(simulate_trace(self.model, trace), failure)

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
        self.assertTrue(any("lacks plan or rollback authorization" in error for error in errors))

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
