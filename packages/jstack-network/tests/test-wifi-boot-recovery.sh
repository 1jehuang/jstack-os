#!/usr/bin/env bash
set -euo pipefail

package_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
script="$package_dir/files/libexec/wifi-boot-recovery"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/net" "$tmp/ieee80211" "$tmp/module"
cat > "$tmp/bin/nmcli" <<'EOF'
#!/usr/bin/env bash
if [ -n "${TEST_NM_STATE_FILE:-}" ]; then
  state=$(cat "$TEST_NM_STATE_FILE")
else
  state=${TEST_NM_STATE:-100}
fi
printf '%s (test)\n' "$state"
EOF

cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$TEST_ACTIONS"
if [ "$*" = 'is-active --quiet iwd.service' ]; then
  [ "${TEST_IWD_ACTIVE:-1}" = 1 ]
  exit
fi
if [ "${TEST_RECOVER_ON_USERSPACE:-0}" = 1 ] \
    && [ "$*" = 'restart NetworkManager.service' ]; then
  printf '30\n' > "$TEST_NM_STATE_FILE"
fi
EOF

cat > "$tmp/bin/modprobe" <<'EOF'
#!/usr/bin/env bash
printf 'modprobe %s\n' "$*" >> "$TEST_ACTIONS"
if [ "${1:-}" = -r ]; then
  rm -rf "$TEST_ROOT/module/${2:?module required}"
  exit 0
fi

if [ "${1:-}" = iwlwifi ]; then
  for module in iwlwifi iwlmld mac80211 cfg80211; do
    mkdir -p "$TEST_ROOT/module/$module/holders"
  done
  rm -rf "$TEST_ROOT/net"
  mkdir -p "$TEST_ROOT/net/wlan0/phy80211"
  printf '30\n' > "$TEST_NM_STATE_FILE"
fi
EOF

cat > "$tmp/bin/noop" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

chmod +x "$tmp/bin/"*

run_classify() {
  JSTACK_WIFI_SYS_CLASS_NET="$tmp/net" \
  JSTACK_WIFI_SYS_CLASS_IEEE80211="$tmp/ieee80211" \
  JSTACK_WIFI_SYS_MODULE="$tmp/module" \
  JSTACK_WIFI_NMCLI="$tmp/bin/nmcli" \
  JSTACK_WIFI_TEST_CRASH_COUNT="${TEST_CRASH_COUNT:-0}" \
  TEST_NM_STATE="${TEST_NM_STATE:-100}" \
    "$script" --classify
}

run_recovery() {
  JSTACK_WIFI_SYS_CLASS_NET="$tmp/net" \
  JSTACK_WIFI_SYS_CLASS_IEEE80211="$tmp/ieee80211" \
  JSTACK_WIFI_SYS_MODULE="$tmp/module" \
  JSTACK_WIFI_NMCLI="$tmp/bin/nmcli" \
  JSTACK_WIFI_SYSTEMCTL="$tmp/bin/systemctl" \
  JSTACK_WIFI_MODPROBE="$tmp/bin/modprobe" \
  JSTACK_WIFI_UDEVADM="$tmp/bin/noop" \
  JSTACK_WIFI_LOGGER="$tmp/bin/noop" \
  JSTACK_WIFI_SLEEP="$tmp/bin/noop" \
  JSTACK_WIFI_LOCK_FILE="$tmp/recovery.lock" \
  JSTACK_WIFI_TEST_CRASH_COUNT="${TEST_CRASH_COUNT:-0}" \
  TEST_ACTIONS="$tmp/actions" \
  TEST_NM_STATE_FILE="$tmp/nm-state" \
  TEST_RECOVER_ON_USERSPACE="${TEST_RECOVER_ON_USERSPACE:-0}" \
  TEST_IWD_ACTIVE="${TEST_IWD_ACTIVE:-1}" \
  TEST_ROOT="$tmp" \
    "$script" --run
}

reset_fixture() {
  rm -rf "$tmp/net" "$tmp/ieee80211" "$tmp/module"
  mkdir -p "$tmp/net" "$tmp/ieee80211" "$tmp/module"
  : > "$tmp/actions"
  printf '100\n' > "$tmp/nm-state"
  TEST_CRASH_COUNT=0
  TEST_NM_STATE=100
  TEST_RECOVER_ON_USERSPACE=0
  TEST_IWD_ACTIVE=1
}

add_phy() {
  mkdir -p "$tmp/ieee80211/phy0"
}

add_iface() {
  mkdir -p "$tmp/net/$1/phy80211"
}

assert_class() {
  local expected=$1 actual
  actual=$(run_classify)
  if [ "$actual" != "$expected" ]; then
    printf 'expected %s, got %s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

bash -n "$script"

reset_fixture
assert_class no-hardware

reset_fixture
add_phy
add_iface wlan0
assert_class healthy

reset_fixture
add_phy
add_iface wlan7
TEST_NM_STATE=20
assert_class userspace-recovery

reset_fixture
add_phy
add_iface wlan0
add_iface wlan1
mkdir -p "$tmp/module/iwlwifi"
assert_class driver-recovery

reset_fixture
add_phy
add_iface wlan0
mkdir -p "$tmp/module/iwlwifi"
TEST_CRASH_COUNT=1
assert_class driver-recovery

reset_fixture
add_phy
add_iface wlan0
add_iface wlan1
assert_class userspace-recovery

# iwd ENFILE-style failure: one interface remains unavailable until iwd and
# NetworkManager are restarted. The recovery must not touch kernel modules.
reset_fixture
add_phy
add_iface wlan0
printf '20\n' > "$tmp/nm-state"
TEST_RECOVER_ON_USERSPACE=1
run_recovery >/dev/null
grep -Fq 'systemctl restart iwd.service' "$tmp/actions"
grep -Fq 'systemctl restart NetworkManager.service' "$tmp/actions"
if grep -Fq 'modprobe ' "$tmp/actions"; then
  printf 'userspace recovery unexpectedly reloaded a kernel module\n' >&2
  exit 1
fi

# NetworkManager may use wpa_supplicant or another backend. In that case the
# generic recovery must leave inactive iwd alone.
reset_fixture
add_phy
add_iface wlan0
printf '20\n' > "$tmp/nm-state"
TEST_RECOVER_ON_USERSPACE=1
TEST_IWD_ACTIVE=0
run_recovery >/dev/null
grep -Fq 'systemctl restart NetworkManager.service' "$tmp/actions"
if grep -Fq 'systemctl restart iwd.service' "$tmp/actions"; then
  printf 'recovery unexpectedly started inactive iwd\n' >&2
  exit 1
fi

# Intel firmware crash: duplicate interfaces require a full stack reload. The
# recovery also unloads mac80211/cfg80211 so the clean interface returns as
# wlan0 instead of incrementing to wlan1.
reset_fixture
add_phy
add_iface wlan0
add_iface wlan1
for module in iwlwifi iwlmld mac80211 cfg80211; do
  mkdir -p "$tmp/module/$module/holders"
done
printf '20\n' > "$tmp/nm-state"
TEST_CRASH_COUNT=1
run_recovery >/dev/null
for action in \
  'modprobe -r iwlmld' \
  'modprobe -r iwlwifi' \
  'modprobe -r mac80211' \
  'modprobe -r cfg80211' \
  'modprobe iwlwifi'; do
  grep -Fq "$action" "$tmp/actions"
done
[ -e "$tmp/net/wlan0/phy80211" ]
[ ! -e "$tmp/net/wlan1" ]

printf 'wifi boot recovery classification and action tests passed\n'
