#!/usr/bin/env bash
# Run one base-image build and report its phase from the guest's own behaviour.
#
# A Windows install takes most of an hour with no output, so "still running" and
# "wedged" look identical from outside. The qcow2's size is the guest writing,
# which distinguishes them within one poll: no growth for many polls while the
# process is alive means the installer is waiting on something.
set -uo pipefail

record="${1:?record key required}"
workspace="${2:?workspace required}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The disk is named for the media record's *record_id*, not its key, and the
# two differ. Ask the module rather than guessing: an incorrect path made the
# watcher report "no-disk" while the guest was 3 GiB into its install.
record_id="$(python3 -c "
import sys; sys.path.insert(0, '$here')
import base_image
print(base_image.load_media_records()['$record'].record_id)")"
disk="$workspace/base-${record_id}.qcow2"
evidence="$workspace/build-${record}.evidence.json"
errors="$workspace/build-${record}.error.json"

python3 "$here/base_image_build.py" --workspace "$workspace" --record "$record" \
  >"$evidence" 2>"$errors" &
builder=$!

last=0
stalled=0
while kill -0 "$builder" 2>/dev/null; do
  size=$( [ -f "$disk" ] && stat -c %s "$disk" || echo 0 )
  mib=$(( size / 1024 / 1024 ))
  if [ "$size" -gt "$last" ]; then stalled=0; else stalled=$(( stalled + 1 )); fi
  last="$size"
  if [ "$size" -eq 0 ]; then phase="no-disk"
  elif [ "$mib" -lt 8 ]; then phase="boot-prompt"
  else phase="setup-writing"
  fi
  echo "JCODE_PROGRESS {\"kind\":\"indeterminate\",\"current\":$mib,\"unit\":\"MiB\",\"message\":\"$phase (stalled polls: $stalled)\"}"
  sleep 30
done

wait "$builder"
status=$?
echo "JCODE_CHECKPOINT {\"message\":\"build exited $status\"}"
if [ "$status" -ne 0 ]; then cat "$errors"; else cat "$evidence"; fi
exit "$status"
