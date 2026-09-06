#!/usr/bin/env bash
# Use foot's real parser, not a partial INI reimplementation. No GUI required.
# Reject warnings too: foot 1.27 warns about [colors], newer versions reject it.
set -euo pipefail
config=${1:-"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/files/foot/foot.ini"}
command -v foot >/dev/null || { echo 'foot is required for config validation' >&2; exit 1; }
if ! output=$(env -u WAYLAND_DISPLAY -u DISPLAY LC_ALL=C.UTF-8 foot --check-config --log-no-syslog --log-level=warning --config "$config" 2>&1); then
  printf '%s\n' "$output" >&2
  exit 1
fi
if [[ -n $output ]]; then
  printf 'foot config must validate without warnings:\n%s\n' "$output" >&2
  exit 1
fi
printf 'foot config validated without warnings: %s\n' "$config"
