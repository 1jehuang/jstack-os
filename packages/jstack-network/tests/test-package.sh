#!/usr/bin/env bash
set -euo pipefail

package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
files="$package_dir/files"

bash -n "$files/libexec/wifi-boot-recovery"
systemd-analyze verify \
  "$files/systemd/jstack-wifi-boot-recovery.service" \
  "$files/systemd/jstack-wifi-boot-recovery.timer"

grep -Fq 'enable jstack-wifi-boot-recovery.timer' "$package_dir/PKGBUILD"
grep -Fq '/usr/lib/jstack/network/wifi-boot-recovery' "$package_dir/PKGBUILD"

"$package_dir/tests/test-wifi-boot-recovery.sh"
printf 'jstack-network static package tests passed\n'
