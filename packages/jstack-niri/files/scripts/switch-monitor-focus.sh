#!/usr/bin/env bash
set -euo pipefail

notify_error() {
    if command -v notify-send >/dev/null 2>&1; then
        notify-send "Switch Monitor Focus" "$1"
    fi
}

if ! command -v niri >/dev/null 2>&1; then
    notify_error "niri is not installed or not in PATH."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    notify_error "jq is required for this launcher."
    exit 1
fi

current_output=$(niri msg -j focused-output 2>/dev/null | jq -r '.name // empty') || {
    notify_error "Could not read the currently focused output."
    exit 1
}

outputs_json=$(niri msg -j outputs 2>/dev/null) || {
    notify_error "Could not read niri outputs."
    exit 1
}

target_output=$(printf '%s' "$outputs_json" | python3 -c '
import json
import sys

current = sys.argv[1]
try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)

outputs = []
for key, info in data.items():
    logical = info.get("logical") or {}
    name = info.get("name") or key
    outputs.append({
        "name": name,
        "x": logical.get("x", 0),
        "y": logical.get("y", 0),
    })

outputs = [output for output in outputs if output["name"]]
if len(outputs) <= 1:
    sys.exit(1)

outputs.sort(key=lambda output: (output["y"], output["x"], output["name"]))
names = [output["name"] for output in outputs]

if current in names:
    index = names.index(current)
    print(names[(index + 1) % len(names)])
else:
    print(names[0])
' "$current_output") || {
    notify_error "Could not determine the next monitor to focus."
    exit 1
}

if [[ -z "$target_output" || "$target_output" == "$current_output" ]]; then
    notify_error "No other monitor was found to focus."
    exit 1
fi

niri msg action focus-monitor "$target_output" >/dev/null 2>&1 || {
    notify_error "Failed to focus monitor: $target_output"
    exit 1
}
