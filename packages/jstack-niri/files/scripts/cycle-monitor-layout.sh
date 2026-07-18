#!/usr/bin/env bash
set -euo pipefail

readonly UNIT='niri-monitor-mirror.service'
readonly MIRROR_APP_ID='niri-monitor-mirror'
readonly WORKER="/usr/lib/jstack/scripts/niri-monitor-mirror-worker.sh"
readonly RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}"
readonly MODE="${1:-cycle}"

notify() {
    local urgency=$1
    shift
    notify-send -u "$urgency" -i video-display 'External monitor mode' "$*" 2>/dev/null || true
}

die() {
    notify critical "$*"
    exit 1
}

for command in niri python3 systemctl systemd-run wf-recorder mpv flock; do
    command -v "$command" >/dev/null 2>&1 || die "Required command is unavailable: $command"
done

case "$MODE" in
    cycle|above|mirror) ;;
    *) die "Unknown mode: $MODE" ;;
esac

# Prevent two rapid launcher clicks from racing each other.
exec 9>"$RUNTIME_DIR/niri-monitor-layout.lock"
flock -n 9 || exit 0

get_outputs() {
    niri msg -j outputs 2>/dev/null
}

find_output_pair() {
    python3 -c '
import json, sys

data = json.load(sys.stdin)
outputs = []
for connector, info in data.items():
    name = info.get("name") or connector
    outputs.append((name, info))

builtins = [(name, info) for name, info in outputs if name.startswith("eDP")]
if not builtins:
    raise SystemExit(2)

source_name, _ = sorted(builtins, key=lambda item: item[0])[0]
external = [(name, info) for name, info in outputs if name != source_name]
if not external:
    print(source_name)
    raise SystemExit(0)

# Prefer an output that is already active, then use a stable connector order.
external.sort(key=lambda item: (item[1].get("logical") is None, item[0]))
print(source_name + "\t" + external[0][0])
'
}

get_logical_height() {
    local output=$1
    python3 -c '
import json, sys
output = sys.argv[1]
data = json.load(sys.stdin)
for connector, info in data.items():
    if (info.get("name") or connector) == output:
        logical = info.get("logical")
        if logical and logical.get("height"):
            print(int(logical["height"]))
            raise SystemExit(0)
raise SystemExit(1)
' "$output"
}

outputs_json=$(get_outputs) || die 'Could not query Niri outputs.'
pair=$(printf '%s' "$outputs_json" | find_output_pair) || die 'Could not identify the built-in display.'
IFS=$'\t' read -r laptop external <<< "$pair"

if [[ -z "${external:-}" ]]; then
    systemctl --user stop "$UNIT" >/dev/null 2>&1 || true
    die 'No external monitor is connected.'
fi

# The output may be connected but disabled.
niri msg output "$external" on >/dev/null 2>&1 || die "Could not enable $external."

external_height=''
for _ in {1..30}; do
    outputs_json=$(get_outputs) || true
    external_height=$(printf '%s' "$outputs_json" | get_logical_height "$external" 2>/dev/null || true)
    [[ -n "$external_height" ]] && break
    sleep 0.1
done
[[ -n "$external_height" ]] || die "Could not determine the size of $external."

apply_above_layout() {
    niri msg output "$external" position set -- 0 0 >/dev/null 2>&1 || return 1
    niri msg output "$laptop" position set -- 0 "$external_height" >/dev/null 2>&1 || return 1
}

mirror_is_active() {
    systemctl --user is-active --quiet "$UNIT"
}

close_mirror_windows() {
    local ids
    ids=$(niri msg -j windows 2>/dev/null | python3 -c '
import json, sys
try:
    windows = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for window in windows:
    if window.get("app_id") == "niri-monitor-mirror":
        print(window["id"])
' || true)
    while IFS= read -r id; do
        [[ -n "$id" ]] && niri msg action close-window --id "$id" >/dev/null 2>&1 || true
    done <<< "$ids"
}

stop_mirror() {
    systemctl --user stop "$UNIT" >/dev/null 2>&1 || true
    close_mirror_windows
    systemctl --user reset-failed "$UNIT" >/dev/null 2>&1 || true
}

start_mirror() {
    apply_above_layout || die 'Could not arrange the external monitor above the laptop.'
    niri msg action focus-monitor "$external" >/dev/null 2>&1 || true

    local -a env_args=()
    for variable in WAYLAND_DISPLAY NIRI_SOCKET DISPLAY XAUTHORITY; do
        if [[ -n "${!variable:-}" ]]; then
            env_args+=(--setenv="$variable=${!variable}")
        fi
    done
    env_args+=(--setenv="XDG_RUNTIME_DIR=$RUNTIME_DIR")

    systemctl --user reset-failed "$UNIT" >/dev/null 2>&1 || true
    systemd-run --user --quiet --collect \
        --unit="$UNIT" \
        --property=KillMode=control-group \
        "${env_args[@]}" \
        "$WORKER" "$laptop" >/dev/null \
        || die 'Could not start the software mirror.'

    local window_id=''
    for _ in {1..100}; do
        window_id=$(niri msg -j windows 2>/dev/null | python3 -c '
import json, sys
try:
    windows = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for window in windows:
    if window.get("app_id") == "niri-monitor-mirror":
        print(window["id"])
        break
' || true)
        [[ -n "$window_id" ]] && break
        mirror_is_active || break
        sleep 0.05
    done

    if [[ -z "$window_id" ]]; then
        stop_mirror
        die 'The mirror player did not open. Check: journalctl --user -u niri-monitor-mirror'
    fi

    niri msg action move-window-to-monitor --id "$window_id" "$external" >/dev/null 2>&1 || true
    niri msg action focus-monitor "$laptop" >/dev/null 2>&1 || true
    notify normal "Software mirror enabled on $external. Click again for the extended-above layout."
}

switch_to_above() {
    stop_mirror
    apply_above_layout || die 'Could not arrange the external monitor above the laptop.'
    notify normal "Extended desktop enabled: $external is above the laptop display."
}

case "$MODE" in
    above)
        switch_to_above
        ;;
    mirror)
        if mirror_is_active; then
            notify low "Software mirror is already enabled on $external."
        else
            start_mirror
        fi
        ;;
    cycle)
        if mirror_is_active; then
            switch_to_above
        else
            start_mirror
        fi
        ;;
esac
