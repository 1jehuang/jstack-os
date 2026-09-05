#!/usr/bin/env bash
set -euo pipefail
script=$(cd "$(dirname "$0")" && pwd)/ubuntu-refusal-probes.sh

bash -n "$script"
out=$($script --help)
grep -Fq 'JSTK_DISPOSABLE_UBUNTU_REFUSAL_VM_V1' <<<"$out"
grep -Fq 'PASS/FAIL/SKIP/INCONCLUSIVE' <<<"$out"

# This is deliberately only a host-side harness safety test, never acceptance.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
set +e
out=$($script --marker "$tmp/missing" --installer /nonexistent --plan /nonexistent --target /nonexistent 2>&1)
rc=$?
set -e
[[ $rc -eq 2 ]]
grep -Eq 'root is required|disposable VM marker missing or invalid' <<<"$out"

# Guard the core evidence and classification requirements against accidental removal.
grep -Fq 'target_before=%s target_after=%s state_before=%s state_after=%s' "$script"
grep -Fq 'else verdict=INCONCLUSIVE' "$script"
grep -Fq 'systemd-detect-virt --vm' "$script"
grep -Fq "mount -o ro" "$script"
! grep -Eq '(^|[[:space:]])(mkfs|wipefs|sgdisk|parted)[[:space:]]' "$script"
! grep -Fq 'of="$target"' "$script"
printf 'host-side refusal harness checks passed (not VM acceptance)\n'
