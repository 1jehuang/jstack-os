#!/usr/bin/env bash
# Bounded public-CLI refusal probes. Run only inside the dedicated disposable QEMU guest.
set -euo pipefail
umask 077

MARKER_TEXT=JSTK_DISPOSABLE_UBUNTU_REFUSAL_VM_V1
usage() {
  cat <<EOF
usage: $(basename "$0") --marker FILE --installer FILE --plan FILE --state DIR \\
  --target BLOCKDEV --expected-serial SERIAL

The marker must contain exactly: $MARKER_TEXT
PLAN and STATE must be the retained authorized transaction. TARGET must be the
whole disposable target whose current stable serial is SERIAL. This script never
creates geometry or writes TARGET. It makes only bounded, reversible mutations
to protected transaction files after excluding a running deploy/resume process.
EOF
}
die() { printf 'HARNESS_REFUSAL: %s\n' "$*" >&2; exit 2; }
marker= installer= plan= state= target= expected_serial=
while (($#)); do
  case "$1" in
    --marker|--installer|--plan|--state|--target|--expected-serial)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --marker) marker=$2;; --installer) installer=$2;; --plan) plan=$2;;
        --state) state=$2;; --target) target=$2;; --expected-serial) expected_serial=$2;;
      esac
      shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument $1";;
  esac
done
[[ $EUID -eq 0 ]] || die 'root is required'
[[ -n $marker && -n $installer && -n $plan && -n $state && -n $target && -n $expected_serial ]] || { usage >&2; exit 2; }
[[ -f $marker && $(cat -- "$marker") == "$MARKER_TEXT" ]] || die 'disposable QEMU guest marker missing or invalid'
case "$(systemd-detect-virt --vm 2>/dev/null || true)" in qemu|kvm) ;; *) die 'not a QEMU/KVM guest';; esac
for c in python3 sha256sum lsblk findmnt stat readlink cmp dd truncate pgrep; do command -v "$c" >/dev/null || die "$c is required"; done
[[ -x $installer && -f $plan && -d $state && -b $target ]] || die 'installer, plan, state, or target is invalid'
installer=$(readlink -f -- "$installer"); plan=$(readlink -f -- "$plan"); state=$(readlink -f -- "$state"); target=$(readlink -f -- "$target")
[[ $state != / && $(dirname -- "$plan") == "$state" && -f $state/initialized.json ]] || die 'plan is not directly inside retained initialized state'
[[ $(lsblk -dnro TYPE -- "$target") == disk ]] || die 'target is not a whole disk'
actual_serial=$(lsblk -dnro SERIAL -- "$target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
[[ -n $actual_serial && $actual_serial == "$expected_serial" ]] || die "target stable serial mismatch (observed '$actual_serial')"
state_mode=$(stat -Lc '%a' -- "$state")
(( (8#$state_mode & 8#022) == 0 )) || die 'state directory is group/world writable'
[[ $(stat -Lc '%U:%h:%F' -- "$state") == root:1:directory ]] || die 'state directory ownership/link/type is unsafe'
[[ $(stat -Lc '%U:%h:%F' -- "$plan") == 'root:1:regular file' ]] || die 'plan ownership/link/type is unsafe'

# Do not touch transaction state while any actual retained installer process is deploying.
while IFS= read -r pid; do
  [[ $pid == $$ ]] && continue
  cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
  [[ $cmd == *"$installer"* && ( $cmd == *' deploy '* || $cmd == *' resume '* ) ]] && die "deploy/resume process $pid is active"
done < <(pgrep -f -- "$(basename "$installer")" 2>/dev/null || true)

target_hash() { sha256sum -- "$target" | awk '{print $1}'; }
original_target_hash=$(target_hash)
work=$(mktemp -d "$state/.refusal-probe.XXXXXX")
restore_file= restore_backup= restore_size= restore_hash=
cleanup() {
  set +e
  if [[ -n $restore_file && -f $restore_backup ]]; then
    dd if="$restore_backup" of="$restore_file" bs=1M conv=notrunc status=none
    truncate -s "$restore_size" "$restore_file"
    [[ $(sha256sum "$restore_file" | awk '{print $1}') == "$restore_hash" ]] || printf 'HARNESS_REFUSAL: cleanup could not restore %s\n' "$restore_file" >&2
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM

passes=0; skips=0
assert_target() { [[ $(target_hash) == "$original_target_hash" ]] || die "TARGET CHANGED during $1"; }
run_refusal() {
  local name=$1 expected=$2; shift 2
  local before after out rc
  before=$(target_hash)
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  after=$(target_hash)
  [[ $before == "$after" && $after == "$original_target_hash" ]] || die "TARGET CHANGED during $name"
  [[ $rc -ne 0 ]] || die "$name unexpectedly succeeded"
  [[ -n $out && $out == *error:* && $out == *"$expected"* ]] || die "$name lacked expected error '$expected' (rc=$rc output=$out)"
  printf 'PASS case=%s rc=%d target_before=%s target_after=%s evidence=%q\n' "$name" "$rc" "$before" "$after" "${out//$'\n'/ | }"
  ((passes+=1))
}
begin_mutation() {
  local f=$1
  [[ -f $f && ! -L $f && $(stat -Lc '%U:%h:%F' -- "$f") == 'root:1:regular file' ]] || die "unsafe mutation file $f"
  restore_file=$f; restore_backup=$work/backup; restore_size=$(stat -Lc %s -- "$f")
  cp --preserve=mode,ownership,timestamps -- "$f" "$restore_backup"
  restore_hash=$(sha256sum "$f" | awk '{print $1}')
}
begin_first_byte_mutation() {
  local f=$1
  [[ -s $f && ! -L $f && $(stat -Lc '%U:%h:%F' -- "$f") == 'root:1:regular file' ]] || die "unsafe mutation file $f"
  restore_file=$f; restore_backup=$work/backup; restore_size=$(stat -Lc %s -- "$f")
  restore_hash=$(sha256sum "$f" | awk '{print $1}')
  dd if="$f" of="$restore_backup" bs=1 count=1 status=none
}
end_mutation() {
  dd if="$restore_backup" of="$restore_file" bs=1M conv=notrunc status=none
  truncate -s "$restore_size" "$restore_file"
  [[ $(sha256sum "$restore_file" | awk '{print $1}') == "$restore_hash" ]] || die "exact-byte restoration failed for $restore_file"
  restore_file= restore_backup= restore_size= restore_hash=
}

run_refusal invalid-argument 'unknown or unsupported argument' "$installer" status --plan "$plan" --bogus value
run_refusal duplicate-argument 'duplicate argument --plan' "$installer" status --plan "$plan" --plan "$plan"

begin_mutation "$plan"
python3 - "$plan" <<'PY'
import json,sys
p=sys.argv[1]
with open(p) as f: x=json.load(f)
x['plan_hash']='0'*64
with open(p,'w') as f: json.dump(x,f,separators=(',',':'))
PY
run_refusal wrong-plan-hash 'plan' "$installer" status --plan "$plan"
end_mutation

begin_mutation "$plan"
python3 - "$plan" <<'PY'
import json,sys
p=sys.argv[1]
with open(p) as f: x=json.load(f)
x['confirmation']['confirmed_plan_hash']='f'*64
with open(p,'w') as f: json.dump(x,f,separators=(',',':'))
PY
run_refusal tampered-authorization 'authorization' "$installer" status --plan "$plan"
end_mutation

artifact=$(python3 - "$plan" "$state" <<'PY'
import json,os,sys
with open(sys.argv[1]) as f: x=json.load(f)
print(os.path.join(sys.argv[2],x['body']['artifact']['relative_store_path']))
PY
)
if [[ -s $artifact ]]; then
  begin_first_byte_mutation "$artifact"; original_artifact_hash=$restore_hash
  printf '\377' | dd of="$artifact" bs=1 seek=0 conv=notrunc status=none
  run_refusal tampered-artifact 'artifact' "$installer" resume --plan "$plan"
  end_mutation
  [[ $(sha256sum "$artifact" | awk '{print $1}') == "$original_artifact_hash" ]] || die 'artifact original hash was not restored'
else printf 'SKIP case=tampered-artifact reason=%q\n' 'retained artifact unavailable or empty'; ((skips+=1)); fi

journal=$(find "$state/journal" -maxdepth 1 -type f -name '*.wal' -links 1 -user root -print -quit 2>/dev/null || true)
if [[ -n $journal && -s $journal ]]; then
  begin_mutation "$journal"
  printf '\377' | dd of="$journal" bs=1 seek=0 conv=notrunc status=none
  run_refusal corrupted-journal 'journal' "$installer" status --plan "$plan"
  end_mutation

  # A torn tail may be accepted as the last durable prefix, but status must be byte-for-byte read-only.
  begin_mutation "$journal"; printf 'TORN' >>"$journal"; torn_hash=$(sha256sum "$journal" | awk '{print $1}')
  before=$(target_hash); set +e; out=$("$installer" status --plan "$plan" 2>&1); rc=$?; set -e; after=$(target_hash)
  [[ $before == "$after" && $after == "$original_target_hash" && $(sha256sum "$journal" | awk '{print $1}') == "$torn_hash" ]] || die 'status repaired torn tail or changed target'
  [[ $rc -eq 0 || ( $rc -ne 0 && -n $out && $out == *error:* ) ]] || die 'torn-tail status produced no accountable result'
  printf 'PASS case=status-torn-tail-read-only rc=%d target_before=%s target_after=%s evidence=%q\n' "$rc" "$before" "$after" "${out//$'\n'/ | }"; ((passes+=1))
  end_mutation
else printf 'SKIP case=journal-probes reason=%q\n' 'no protected nonempty journal WAL'; ((skips+=2)); fi

state_source=$(findmnt -nro SOURCE --target "$state" 2>/dev/null || true); state_disk=
if [[ $state_source == /dev/* ]]; then state_disk=$(lsblk -nro PKNAME -- "$state_source" 2>/dev/null | head -1); [[ -n $state_disk ]] && state_disk=/dev/$state_disk || state_disk=$state_source; fi
if [[ -b ${state_disk:-} ]]; then run_refusal state-overlap 'overlap' "$installer" inspect --disk "$state_disk" --state-dir "$state"
else printf 'SKIP case=state-overlap reason=%q\n' 'state has no simple block-disk ancestry'; ((skips+=1)); fi
root_source=$(findmnt -nro SOURCE --target / 2>/dev/null || true); root_disk=
if [[ $root_source == /dev/* ]]; then root_disk=$(lsblk -nro PKNAME -- "$root_source" 2>/dev/null | head -1); [[ -n $root_disk ]] && root_disk=/dev/$root_disk || root_disk=$root_source; fi
if [[ -b ${root_disk:-} ]]; then run_refusal root-overlap 'overlap' "$installer" inspect --disk "$root_disk" --state-dir "$state"
else printf 'SKIP case=root-overlap reason=%q\n' 'root has no simple block-disk ancestry'; ((skips+=1)); fi

part=$(lsblk -lnpo NAME,TYPE -- "$target" | awk '$2=="part"{print $1;exit}')
if [[ -n $part ]]; then
  # Existing geometry only: partition targets are unsupported, without mounting or creating anything.
  run_refusal partition-target-unsupported 'whole disk' "$installer" inspect --disk "$part" --state-dir "$state"
  if findmnt -rn --source "$part" >/dev/null 2>&1; then run_refusal target-mounted 'mounted' "$installer" inspect --disk "$target" --state-dir "$state"
  else printf 'SKIP case=target-mounted reason=%q\n' 'no existing target partition is mounted; risky setup refused'; ((skips+=1)); fi
else printf 'SKIP case=partition-target-unsupported reason=%q\n' 'target has no existing partition; destructive setup refused'; ((skips+=2)); fi

assert_target final
printf 'SUMMARY pass=%d skip=%d target_sha256=%s\n' "$passes" "$skips" "$original_target_hash"
