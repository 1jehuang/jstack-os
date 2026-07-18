#!/usr/bin/env bash
set -euo pipefail

# jstack OS: keep a single external monitor stacked above the laptop screen (eDP-1).
#
# Desired layout:
# - external monitor at (0, 0)
# - laptop monitor (eDP-1) at (0, external_height)
#
# Monitors whose make/model matches JSTACK_MONITOR_ABOVE_EXCLUDE are skipped,
# so machines with an explicitly configured output block can opt out.
# This script polls because niri's event stream does not expose output
# connect/disconnect changes in a way this script can reliably react to.

EXCLUDE_MATCH="${JSTACK_MONITOR_ABOVE_EXCLUDE:-}"
POLL_SECONDS=5

apply_positions() {
    local result
    result=$(niri msg -j outputs 2>/dev/null | python3 -c "
import json, os, sys

exclude = '$EXCLUDE_MATCH'
data = json.load(sys.stdin)

laptop = None
ext = None
for key, info in data.items():
    name = info.get('name', key)
    logical = info.get('logical') or {}
    if name == 'eDP-1':
        laptop = {
            'name': name,
            'x': int(logical.get('x', 0)),
            'y': int(logical.get('y', 0)),
            'h': int(logical.get('height', 0)),
        }
    elif not exclude or (exclude not in key and exclude not in (info.get('make') or '')):
        ext = {
            'name': name,
            'x': int(logical.get('x', 0)),
            'y': int(logical.get('y', 0)),
            'h': int(logical.get('height', 0)),
        }

if not laptop or not ext:
    sys.exit(0)

print(f\"{ext['name']}\t{ext['x']}\t{ext['y']}\t{ext['h']}\t{laptop['x']}\t{laptop['y']}\")
") || return

    [[ -z "$result" ]] && return

    local connector ext_x ext_y ext_h laptop_x laptop_y desired_laptop_y
    IFS=$'\t' read -r connector ext_x ext_y ext_h laptop_x laptop_y <<< "$result"

    desired_laptop_y="$ext_h"

    if [[ "$ext_x" == "0" && "$ext_y" == "0" && "$laptop_x" == "0" && "$laptop_y" == "$desired_laptop_y" ]]; then
        return
    fi

    echo "[monitor-above] $(date '+%H:%M:%S') $connector -> (0, 0), eDP-1 -> (0, $desired_laptop_y)"
    niri msg output "$connector" position set -- 0 0 >/dev/null 2>&1 || true
    niri msg output "eDP-1" position set -- 0 "$desired_laptop_y" >/dev/null 2>&1 || true
}

sleep 2

while true; do
    apply_positions
    sleep "$POLL_SECONDS"
done
