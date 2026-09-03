#!/usr/bin/env bash
# Restore a seed bundle into an installed system. Runs inside the target chroot
# (called from chroot-stage.sh) or on a live jstack machine.
#   restore-seed.sh <bundle> <user> [--pass PASS]
set -euo pipefail
B=${1:?bundle}; U=${2:?user}; shift 2; PASS="${JSTACK_SEED_PASS:-}"
while [ $# -gt 0 ]; do case "$1" in --pass) PASS=$2; shift 2 ;; *) shift ;; esac; done
H=$(getent passwd "$U" | cut -d: -f6); [ -n "$H" ] || { echo "no such user $U" >&2; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
log() { printf '  ~ %s\n' "$*"; }

case "$B" in
  *.enc) [ -n "$PASS" ] || { read -rsp "Seed passphrase: " PASS; echo; }
         JSTACK_SEED_PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:JSTACK_SEED_PASS -in "$B" | tar -C "$W" -xzf - ;;
  *)     tar -C "$W" -xzf "$B" ;;
esac
S="$W/seed"; [ -f "$S/MANIFEST" ] || { echo "not a seed bundle" >&2; exit 1; }
cat "$S/MANIFEST" | sed 's/^/    /'

if [ -d "$S/home" ]; then
  cp -a "$S/home/." "$H/"
  chown -R "$U:$U" "$H"
  [ -d "$H/.ssh" ] && chmod 700 "$H/.ssh" && find "$H/.ssh" -type f -exec chmod 600 {} + && log "ssh keys"
  [ -d "$H/.jcode" ] && chmod 700 "$H/.jcode" && find "$H/.jcode" -maxdepth 1 -type f -name '*.json' -exec chmod 600 {} + && log "jcode auth/config"
  [ -d "$H/.config/jcode" ] && chmod 700 "$H/.config/jcode" && find "$H/.config/jcode" -name '*.env' -exec chmod 600 {} + && log "jcode provider keys"
  [ -d "$H/.config/gh" ] && chmod -R go-rwx "$H/.config/gh" && log "gh auth"
  [ -f "$H/.gitconfig" ] && log "gitconfig"
fi
if [ -f "$S/system/var/lib/tailscale/tailscaled.state" ]; then
  install -Dm600 -o root -g root "$S/system/var/lib/tailscale/tailscaled.state" /var/lib/tailscale/tailscaled.state
  log "tailscale node state (will rejoin tailnet on boot)"
fi
if [ -d "$S/system/var/lib/iwd" ]; then
  mkdir -p /var/lib/iwd; cp -a "$S/system/var/lib/iwd/." /var/lib/iwd/
  chown -R root:root /var/lib/iwd; chmod 700 /var/lib/iwd; chmod 600 /var/lib/iwd/* 2>/dev/null || true
  log "wifi: $(ls /var/lib/iwd | wc -l) iwd networks"
fi
if [ -d "$S/system/etc/NetworkManager/system-connections" ]; then
  mkdir -p /etc/NetworkManager/system-connections
  cp -a "$S/system/etc/NetworkManager/system-connections/." /etc/NetworkManager/system-connections/
  chown -R root:root /etc/NetworkManager/system-connections; chmod 600 /etc/NetworkManager/system-connections/* 2>/dev/null || true
  log "NetworkManager connections"
fi
echo "seed restored for $U"
