#!/usr/bin/env python3
"""Validate the JStack installer state graph and scenario traces."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from state_model import (
    load_json,
    simulate_trace,
    validate_against_schema,
    validate_model,
    validate_trace,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--trace-schema", type=Path)
    parser.add_argument(
        "--traces",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "traces",
    )
    args = parser.parse_args()

    model = load_json(args.model)
    schema_path = args.schema or args.model.with_name("schema.json")
    trace_schema_path = args.trace_schema or args.model.with_name("trace-schema.json")
    model_schema = load_json(schema_path)
    trace_schema = load_json(trace_schema_path)
    errors = [
        f"model schema: {error}"
        for error in validate_against_schema(model, model_schema)
    ]
    errors.extend(validate_model(model))
    trace_count = 0
    trace_ids: set[str] = set()
    traced_terminals: set[str] = set()
    for trace_path in sorted(args.traces.glob("*.json")):
        trace_count += 1
        trace = load_json(trace_path)
        errors.extend(
            f"trace {trace_path.name} schema: {error}"
            for error in validate_against_schema(trace, trace_schema)
        )
        trace_errors = validate_trace(model, trace)
        errors.extend(f"trace {trace_path.name}: {error}" for error in trace_errors)
        if trace.get("id") in trace_ids:
            errors.append(f"duplicate trace id: {trace.get('id')}")
        trace_ids.add(trace.get("id"))
        if expected_terminal := trace.get("expected_terminal"):
            traced_terminals.add(expected_terminal)
        if trace_errors:
            continue
        try:
            terminal = simulate_trace(model, trace)
        except AssertionError as error:
            errors.append(str(error))
            continue
        if terminal != trace["expected_terminal"]:
            errors.append(
                f"trace {trace['id']} ended at {terminal}, expected {trace['expected_terminal']}"
            )

    declared_terminals = {
        state["id"] for state in model["states"] if state.get("kind") == "terminal"
    }
    for terminal in sorted(declared_terminals - traced_terminals):
        errors.append(f"terminal outcome lacks a checked-in trace: {terminal}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"validated {len(model['states'])} states, "
        f"{len(model['transitions'])} transitions, and {trace_count} traces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
