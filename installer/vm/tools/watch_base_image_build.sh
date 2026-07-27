#!/usr/bin/env bash
# Run one base-image build and report its phase from the guest's own behaviour.
#
# A Windows install takes most of an hour with no output, so "still running" and
# "wedged" look identical from outside. The qcow2's size is the guest writing,
# which distinguishes them within one poll: no growth for many polls while the
# process is alive means the installer is waiting on something.
#
# Every defect this build path has produced had the same signature: the disk
# stops growing because setup is holding a modal dialog that nobody will answer,
# and the build then burns its full ninety-minute timeout reporting nothing.
# Five separate defects hid there. So on a sustained stall this script captures
# the guest's screen through QMP, which is what actually identified three of
# them, and turns an hour of silence into a picture of the dialog.
set -uo pipefail

# Bash re-reads a script file as it executes, so editing this file while a build
# is running corrupts the running copy. That happened: a mid-run edit killed a
# Windows 10 install at ten gigabytes. A watcher that supervises a
# forty-minute job must therefore be immune to its own source being edited, so
# it re-executes from a private snapshot and runs the rest from there.
if [ "${JSTACK_WATCH_PINNED:-0}" != "1" ]; then
    snapshot="$(mktemp -t jstack-watch-XXXXXX.sh)"
    cat "${BASH_SOURCE[0]}" >"$snapshot"
    trap 'rm -f "$snapshot"' EXIT
    JSTACK_WATCH_PINNED=1 JSTACK_WATCH_ORIGIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" \
        bash "$snapshot" "$@"
    exit $?
fi

record="${1:?record key required}"
workspace="${2:?workspace required}"
# Resolved from the origin the snapshot recorded, since the snapshot itself lives
# in a temporary directory and knows nothing about the tree.
here="$(cd "${JSTACK_WATCH_ORIGIN}/.." && pwd)"
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
monitor="$workspace/build-${record}.qmp"

# Four polls is two minutes. Long enough that ordinary pauses between install
# phases do not trigger it, short enough that a stalled build is diagnosed in
# minutes rather than at the timeout.
STALL_POLLS=4

python3 "$here/base_image_build.py" --workspace "$workspace" --record "$record" \
  >"$evidence" 2>"$errors" &
builder=$!

last=0
stalled=0
captured=0
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

  # Capture once per stall episode, not once per poll: a wall of identical
  # screenshots is not more evidence than one.
  if [ "$stalled" -ge "$STALL_POLLS" ] && [ "$captured" -eq 0 ] && [ -S "$monitor" ]; then
    shot="$workspace/stall-${record}.png"
    if python3 "$here/tools/capture_guest_screen.py" --monitor "$monitor" --output "$shot" >/dev/null 2>&1; then
      echo "JCODE_CHECKPOINT {\"message\":\"stalled at ${mib} MiB; guest screen captured to ${shot}\"}"
      captured=1
    fi
  fi
  [ "$stalled" -lt "$STALL_POLLS" ] && captured=0
  sleep 30
done

wait "$builder"
status=$?
echo "JCODE_CHECKPOINT {\"message\":\"build exited $status\"}"
if [ "$status" -ne 0 ]; then cat "$errors"; else cat "$evidence"; fi
exit "$status"
