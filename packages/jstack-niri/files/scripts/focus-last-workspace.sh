#!/usr/bin/env bash
set -euo pipefail

current_output=$(niri msg -j focused-output | jq -r '.name')

last_idx=$(niri msg -j workspaces | jq --arg output "$current_output" '
    [ .[] | select(.output == $output) ]
    | if length == 0 then null else (max_by(.idx).idx) end
')

if [[ -z "$last_idx" || "$last_idx" == "null" ]]; then
    exit 0
fi

niri msg action focus-workspace "$last_idx"
