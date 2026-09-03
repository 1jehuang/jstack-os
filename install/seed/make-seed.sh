#!/usr/bin/env bash
# Capture identity + access state from a running jstack/Arch machine into one
# encrypted bundle that jstack-install.sh --seed restores before first boot.
#
#   ./install/seed/make-seed.sh [-o jstack-seed.tar.gz.enc] [--no-encrypt]
#
# Contents (all optional; missing items are skipped):
#   jcode      ~/.jcode/{auth.json,config.toml,mcp.json,ssh_remotes.json,swarm-prompt.md,skills/}
#   ssh        ~/.ssh (keys, config, known_hosts)
#   github     ~/.gitconfig, ~/.config/gh (gh CLI auth)
#   tailscale  /var/lib/tailscale/tailscaled.state (same node identity, no re-login)
#   wifi       /var/lib/iwd/*.psk|*.open|*.8021x, /etc/NetworkManager/system-connections/
#
# Encryption: openssl aes-256-cbc -pbkdf2 with a passphrase (present everywhere;
# no extra tools on the Ubuntu host). Use --no-encrypt only onto trusted media.
set -euo pipefail
OUT="jstack-seed.tar.gz.enc"; ENCRYPT=1; PASS="${JSTACK_SEED_PASS:-}"
while [ $# -gt 0 ]; do case "$1" in
  -o) OUT=$2; shift 2 ;; --no-encrypt) ENCRYPT=0; shift ;; --pass) PASS=$2; shift 2 ;;
  -h|--help) sed -n '2,16p' "$0"; exit 0 ;; *) echo "unknown arg $1" >&2; exit 1 ;; esac; done

SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo -n"
if ! $SUDO true 2>/dev/null; then SUDO="sudo"; fi
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
S="$W/seed"; mkdir -p "$S/home" "$S/system"
log() { printf '  + %s\n' "$*"; }

copy_home() {  # copy_home <path-relative-to-HOME>
  local p="$HOME/$1"; [ -e "$p" ] || return 0
  mkdir -p "$S/home/$(dirname "$1")"; cp -a "$p" "$S/home/$1"; log "~/$1"
}
copy_sys() {   # copy_sys <absolute path>
  $SUDO test -e "$1" 2>/dev/null || return 0
  mkdir -p "$S/system$(dirname "$1")"; $SUDO cp -a "$1" "$S/system$1"; log "$1"
}

echo "Collecting seed from $(hostname) for user $USER"
for f in auth.json config.toml mcp.json ssh_remotes.json swarm-prompt.md skills; do copy_home ".jcode/$f"; done
copy_home .ssh
copy_home .gitconfig
copy_home .config/gh
copy_sys /var/lib/tailscale/tailscaled.state
copy_sys /var/lib/iwd
copy_sys /etc/NetworkManager/system-connections
# Prune iwd runtime noise, keep only credential files.
[ -d "$S/system/var/lib/iwd" ] && $SUDO find "$S/system/var/lib/iwd" -mindepth 1 -maxdepth 1 ! -name '*.psk' ! -name '*.open' ! -name '*.8021x' -exec rm -rf {} +

$SUDO chown -R "$(id -u):$(id -g)" "$S"
cat > "$S/MANIFEST" <<M
source_host=$(hostname)
source_user=$USER
created=$(date -Is)
tailscale_hostname=$(tailscale status --json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["Self"]["HostName"])' 2>/dev/null || true)
M
( cd "$S" && find . -type f | sort ) > "$S/FILES"

if [ "$ENCRYPT" = 1 ]; then
  [ -n "$PASS" ] || { read -rsp "Seed passphrase: " PASS; echo; read -rsp "Again: " P2; echo; [ "$PASS" = "$P2" ] || { echo "mismatch" >&2; exit 1; }; }
  tar -C "$W" -czf - seed | JSTACK_SEED_PASS="$PASS" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:JSTACK_SEED_PASS -out "$OUT"
else
  OUT="${OUT%.enc}"; tar -C "$W" -czf "$OUT" seed
fi
chmod 600 "$OUT"
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1)), $(wc -l < "$S/FILES") files"
echo "Restore: sudo ./install/jstack-install.sh ... --seed $OUT"
