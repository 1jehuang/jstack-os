#!/usr/bin/env bash
set -euo pipefail

focused_json="$(niri msg -j focused-window 2>/dev/null || printf '{}')"
app_id="$(python3 -c 'import json,sys; 
try:
    data=json.load(sys.stdin)
    print(data.get("app_id", "") or "")
except Exception:
    print("")' <<< "$focused_json")"

if [[ "$app_id" == "firefox" || "$app_id" == "org.mozilla.firefox" ]]; then
    exec firefox --private-window
else
    exec wtype -M ctrl -M shift -k n -m shift -m ctrl
fi
