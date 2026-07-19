#!/usr/bin/env bash
set -euo pipefail

if pgrep -x "niri" > /dev/null; then
  exec waybar
fi

# Fallback to default Waybar config when running elsewhere.
exec waybar
