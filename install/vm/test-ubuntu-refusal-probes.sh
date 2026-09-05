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
grep -Fq '"$state/journal/$hash.wal"' "$script"
grep -Fq "b[0]^0xff" "$script"
grep -Fq 'JSTACK_TARGET_01' "$script"
grep -Fq 'active target deployment detected' "$script"
grep -Fq 'duplicate-cli-argument' "$script"
grep -Fq 'invalid-cli-argument' "$script"
grep -Fq 'torn-journal-tail-copy' "$script"
grep -Fq 'artifact-restore' "$script"
grep -Fq "trap 'exit 129' HUP" "$script"
grep -Fq "trap 'exit 130' INT" "$script"
grep -Fq "trap 'exit 143' TERM" "$script"
grep -Fq 'retaining recovery evidence' "$script"
grep -Fq 'partition-target-unsupported' "$script"
grep -Fq 'target is not a whole disk' "$script"
! grep -Fq '"$state"/.' "$script"
! grep -Eq '(^|[[:space:]])(mkfs|wipefs|sgdisk|parted)[[:space:]]' "$script"
! grep -Fq 'of="$target"' "$script"
printf 'host-side refusal harness checks passed (not VM acceptance)\n'
