#!/usr/bin/env bash
set -euo pipefail

package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
files="$package_dir/files"

bash -n "$files/libexec/wifi-boot-recovery"
bash -n "$files/bin/captive-portal-monitor"
bash -n "$package_dir/PKGBUILD"
systemd-analyze verify \
  "$files/systemd/jstack-wifi-boot-recovery.service" \
  "$files/systemd/jstack-wifi-boot-recovery.timer"

grep -Fq 'enable jstack-wifi-boot-recovery.timer' "$package_dir/PKGBUILD"
grep -Fq '/usr/lib/jstack/network/wifi-boot-recovery' "$package_dir/PKGBUILD"

"$package_dir/tests/test-wifi-boot-recovery.sh"
grep -Fq "enable captive-portal-monitor.service" "$package_dir/PKGBUILD"
python3 -B -m unittest discover -s "$package_dir/tests" -p "test_*.py"
printf 'jstack-network static package tests passed\n'
