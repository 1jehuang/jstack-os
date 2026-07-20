#!/usr/bin/env python3
"""Generate human-readable docs from the executable installer model."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from state_model import index_by_id, load_json


def node_id(state_id: str) -> str:
    return state_id.replace(".", "_").replace("-", "_")


def render_mermaid(model: dict) -> str:
    states_by_phase: dict[str, list[dict]] = defaultdict(list)
    for state in model["states"]:
        states_by_phase[state["phase"]].append(state)

    lines = ["stateDiagram-v2", "    direction LR"]
    lines.append(f"    [*] --> {node_id(model['initial_state'])}")
    for phase in sorted(states_by_phase):
        lines.append(f'    state "{phase}" as phase_{node_id(phase)} {{')
        for state in states_by_phase[phase]:
            label = state["id"]
            lines.append(f'        state "{label}" as {node_id(state["id"])}')
        lines.append("    }")

    for transition in model["transitions"]:
        lines.append(
            f"    {node_id(transition['from'])} --> {node_id(transition['to'])}: "
            f"{transition['id']}"
        )
        if failure := transition.get("failure_to"):
            lines.append(
                f"    {node_id(transition['from'])} --> {node_id(failure)}: "
                f"failure({transition['id']})"
            )
    for state in model["states"]:
        if state["kind"] == "terminal":
            lines.append(f"    {node_id(state['id'])} --> [*]")
    return "\n".join(lines) + "\n"


def render_transitions(model: dict) -> str:
    actions = index_by_id(model["actions"])
    lines = [
        "# Generated transition table",
        "",
        "Generated from `installer/model/installer-state-graph.json`. Do not edit manually.",
        "",
        "| Transition | From | To | Actor | Max risk | Guards | Failure target |",
        "|---|---|---|---|---|---|---|",
    ]
    risk_order = {
        "read_only": 0,
        "external_io": 1,
        "user_authorization": 2,
        "filesystem_mutation": 3,
        "security_mutation": 4,
        "disk_mutation": 5,
        "boot_mutation": 6,
        "reboot": 7,
    }
    for transition in model["transitions"]:
        risks = [actions[action]["risk"] for action in transition["actions"]]
        max_risk = max(risks, key=risk_order.get) if risks else "read_only"
        lines.append(
            "| `{id}` | `{from_}` | `{to}` | `{actor}` | `{risk}` | {guards} | {failure} |".format(
                id=transition["id"],
                from_=transition["from"],
                to=transition["to"],
                actor=transition["actor"],
                risk=max_risk,
                guards=", ".join(f"`{guard}`" for guard in transition["guards"]) or "-",
                failure=f"`{transition['failure_to']}`" if transition.get("failure_to") else "-",
            )
        )
    return "\n".join(lines) + "\n"


def render_actions(model: dict) -> str:
    lines = [
        "# Generated action catalog",
        "",
        "Generated from `installer/model/installer-state-graph.json`. Do not edit manually.",
        "",
        "| Action | Platform | Risk | Idempotency | Recovery | Description |",
        "|---|---|---|---|---|---|",
    ]
    for action in model["actions"]:
        lines.append(
            f"| `{action['id']}` | `{action['platform']}` | `{action['risk']}` | "
            f"`{action['idempotency']}` | `{action['recovery']}` | {action['description']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    model = load_json(args.model)
    args.output.mkdir(parents=True, exist_ok=True)
    mermaid = render_mermaid(model)
    (args.output / "state-graph.mmd").write_text(mermaid, encoding="utf-8")
    (args.output / "STATE_GRAPH.md").write_text(
        "# Generated installer state graph\n\n"
        "Generated from `installer/model/installer-state-graph.json`. Do not edit manually.\n\n"
        "```mermaid\n" + mermaid + "```\n",
        encoding="utf-8",
    )
    (args.output / "TRANSITIONS.md").write_text(
        render_transitions(model), encoding="utf-8"
    )
    (args.output / "ACTIONS.md").write_text(render_actions(model), encoding="utf-8")
    print(f"generated installer docs in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
