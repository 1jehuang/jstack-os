#!/usr/bin/env bash
# Real public-CLI refusal probes for an explicitly disposable Ubuntu QEMU/KVM guest.
# This script is destructive-test tooling: never run it on a host or valuable disks.
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
usage: ubuntu-refusal-probes.sh --marker FILE --installer FILE --plan FILE --target BLOCKDEV

FILE must contain exactly: JSTK_DISPOSABLE_UBUNTU_REFUSAL_VM_V1
PLAN must bind TARGET's observed serial exactly to JSTACK_TARGET_01. Its state
directory must contain .jstk-disposable-refusal-state with exactly
JSTK_DISPOSABLE_REFUSAL_STATE_V1. The script mutates private sibling copies. The
artifact test reversibly flips one byte in this explicitly disposable state and
restores that byte and verifies its full digest. It never writes TARGET.
Run as root inside a disposable QEMU/KVM guest. Results are PASS/FAIL/SKIP/INCONCLUSIVE.
EOF
}

die() { printf 'HARNESS_REFUSAL: %s\n' "$*" >&2; exit 2; }
marker= installer= plan= target=
while (($#)); do
  case "$1" in
    --marker|--installer|--plan|--target)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in --marker) marker=$2;; --installer) installer=$2;; --plan) plan=$2;; --target) target=$2;; esac
      shift 2;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument $1";;
  esac
done
[[ $EUID == 0 ]] || die "root is required"
[[ -n $marker && -n $installer && -n $plan && -n $target ]] || { usage >&2; exit 2; }
[[ -f $marker && $(cat "$marker") == JSTK_DISPOSABLE_UBUNTU_REFUSAL_VM_V1 ]] || die "disposable VM marker missing or invalid"
virt=$(systemd-detect-virt --vm 2>/dev/null || true)
case "$virt" in qemu|kvm) ;; *) die "refusing non-QEMU/KVM environment (detected '${virt:-none}')";; esac
[[ -x $installer && -f $plan && -b $target ]] || die "installer, plan, or block target is invalid"
installer=$(readlink -f "$installer"); plan=$(readlink -f "$plan"); target=$(readlink -f "$target")
state=$(dirname "$plan")
[[ $state != / && -f $state/initialized.json ]] || die "plan parent is not initialized state"
[[ -f $state/.jstk-disposable-refusal-state && $(cat "$state/.jstk-disposable-refusal-state") == JSTK_DISPOSABLE_REFUSAL_STATE_V1 ]] || die "state is not explicitly marked disposable"
command -v python3 >/dev/null || die "python3 is required"
command -v sha256sum >/dev/null || die "sha256sum is required"
readarray -t identity < <(python3 - "$plan" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); print(x['body']['target']['stable_serial']); print(x['body']['target'].get('stable_wwn') or '')
PY
)
[[ ${identity[0]} == JSTACK_TARGET_01 ]] || die "plan target serial is not dedicated JSTACK_TARGET_01"
observed_serial=$(lsblk -dn -o SERIAL "$target" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
[[ $observed_serial == JSTACK_TARGET_01 ]] || die "observed target serial does not match dedicated plan identity"
# Probe the same transaction lock used by the public controller. Release it
# immediately because refusal cases must enter the controller far enough to
# exercise their intended validation rather than being masked by our own lock.
lock_path=$(python3 - "${identity[0]}" "${identity[1]}" <<'PY'
import hashlib,json,sys
serial,wwn=sys.argv[1:]
opt='Some('+json.dumps(wwn,separators=(',',':'))+')' if wwn else 'None'
print('/run/lock/jstack-ubuntu-'+hashlib.sha256(f'{serial}:{opt}'.encode()).hexdigest()+'.lock')
PY
)
exec {transaction_lock}>"$lock_path"
flock -n "$transaction_lock" || die "active target deployment detected"
flock -u "$transaction_lock"

work=$(mktemp -d "$(dirname "$state")/.jstk-refusal-probes.XXXXXX")
mountpoint=
restore_artifact= restore_hex= restore_hash=
restore_retained_artifact() {
  python3 - "$restore_artifact" "$restore_hex" <<'PY'
import os,sys
with open(sys.argv[1],'r+b') as f:
    f.seek(0); f.write(bytes.fromhex(sys.argv[2])); f.flush(); os.fsync(f.fileno())
PY
  [[ $(sha256sum "$restore_artifact" | awk '{print $1}') == "$restore_hash" ]]
}
cleanup() {
  local restoration_failed=0
  if [[ -n $mountpoint ]] && mountpoint -q "$mountpoint"; then umount "$mountpoint" || true; fi
  if [[ -n $restore_artifact && -n $restore_hex ]]; then
    if ! restore_retained_artifact; then
      restoration_failed=1
      printf 'HARNESS_REFUSAL: artifact restoration full digest mismatch; retaining recovery evidence at %s\n' "$work" >&2
    fi
  fi
  (( restoration_failed != 0 )) || rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Content, relative path, type, mode, uid, gid, and symlink target. Reading does not
# include atime, so harmless reads cannot hide writes or metadata changes.
tree_digest() {
  python3 - "$1" <<'PY'
import hashlib, os, stat, sys
root=os.path.realpath(sys.argv[1]); h=hashlib.sha256()
for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
    dirs.sort(); files.sort()
    for name in dirs+files:
        p=os.path.join(base,name); rel=os.path.relpath(p,root).encode(); st=os.lstat(p)
        h.update(rel+b'\0'+str(stat.S_IFMT(st.st_mode)).encode()+b':'+oct(stat.S_IMODE(st.st_mode)).encode()+b':'+str(st.st_uid).encode()+b':'+str(st.st_gid).encode()+b'\0')
        if stat.S_ISREG(st.st_mode):
            with open(p,'rb') as f:
                for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
        elif stat.S_ISLNK(st.st_mode): h.update(os.readlink(p).encode())
print(h.hexdigest())
PY
}
target_digest() { sha256sum "$target" | awk '{print $1}'; }

pass=0 fail=0 skip=0 inconclusive=0
emit() { printf '%s case=%s expected=%q observed=%q target_before=%s target_after=%s state_before=%s state_after=%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"; }
run_case() {
  local name=$1 expected=$2 state_watch=$3; shift 3
  local tb ta sb sa rc out verdict
  tb=$(target_digest); sb=$(tree_digest "$state_watch")
  set +e; out=$("$@" 2>&1); rc=$?; set -e
  ta=$(target_digest); sa=$(tree_digest "$state_watch")
  if [[ $tb != "$ta" || $sb != "$sa" ]]; then verdict=FAIL; ((fail+=1))
  elif [[ $rc -eq 0 ]]; then verdict=FAIL; ((fail+=1))
  elif grep -Fqi -- "$expected" <<<"$out"; then verdict=PASS; ((pass+=1))
  else verdict=INCONCLUSIVE; ((inconclusive+=1))
  fi
  emit "$verdict" "$name" "nonzero + $expected" "rc=$rc ${out//$'\n'/ | }" "$tb" "$ta" "$sb" "$sa"
}
positive_status() {
  local tb ta sb sa rc out verdict
  tb=$(target_digest); sb=$(tree_digest "$state")
  set +e; out=$("$installer" status --plan "$plan" 2>&1); rc=$?; set -e
  ta=$(target_digest); sa=$(tree_digest "$state")
  if [[ $rc -eq 0 && $out == *STATE=* && $out == *NEXT_OFFSET=* && $tb == "$ta" && $sb == "$sa" ]]; then verdict=PASS; ((pass+=1)); else verdict=FAIL; ((fail+=1)); fi
  emit "$verdict" status-positive 'zero + STATE/NEXT_OFFSET' "rc=$rc ${out//$'\n'/ | }" "$tb" "$ta" "$sb" "$sa"
}
plan_hash() { python3 - "$plan" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['plan_hash'])
PY
}
# Copy only inputs needed by status. Copying the entire state can duplicate a
# target-sized artifact and artifact-build workspace on non-reflink filesystems.
copy_status_state() {
  local d=$1 hash
  hash=$(plan_hash); mkdir "$d" "$d/journal"
  cp -a "$plan" "$d/$(basename "$plan")"
  cp -a "$state/journal/$hash.wal" "$d/journal/$hash.wal"
}
flip_first_byte() { python3 - "$1" <<'PY'
import sys
p=sys.argv[1]
with open(p,'r+b') as f:
    b=f.read(1)
    if not b: raise SystemExit('cannot flip byte in empty file')
    f.seek(0); f.write(bytes([b[0]^0xff])); f.flush()
PY
}
mutate_json() { python3 - "$@" <<'PY'
import json,sys
p,kind=sys.argv[1:]; x=json.load(open(p))
if kind=='plan-hash': x['plan_hash']='0'*64
elif kind=='confirmation': x['confirmation']['confirmed_plan_hash']='f'*64
json.dump(x,open(p,'w'),separators=(',',':'))
PY
}

positive_status
run_case duplicate-cli-argument 'duplicate argument --plan' "$state" "$installer" status --plan "$plan" --plan "$plan"
run_case invalid-cli-argument 'unknown or unsupported argument --bogus' "$state" "$installer" status --plan "$plan" --bogus value

c=$work/corrupt-plan; copy_status_state "$c"; cp_plan=$c/$(basename "$plan"); mutate_json "$cp_plan" plan-hash
run_case corrupt-plan-hash 'exact plan authorization does not match' "$c" "$installer" status --plan "$cp_plan"

c=$work/unauthorized; copy_status_state "$c"; cp_plan=$c/$(basename "$plan"); mutate_json "$cp_plan" confirmation
run_case unauthorized-confirmation 'exact plan authorization does not match' "$c" "$installer" status --plan "$cp_plan"

c=$work/corrupt-journal; copy_status_state "$c"; cp_plan=$c/$(basename "$plan")
wal=$c/journal/$(plan_hash).wal
if [[ -n $wal && -s $wal ]]; then
  flip_first_byte "$wal"
run_case corrupt-journal-copy 'journal chain corruption' "$c" "$installer" status --plan "$cp_plan"
else
  printf 'SKIP case=corrupt-journal-copy reason=%q\n' 'isolated state has no nonempty journal'; ((skip+=1))
fi

c=$work/torn-journal; copy_status_state "$c"; cp_plan=$c/$(basename "$plan"); wal=$c/journal/$(plan_hash).wal
printf 'TORN' >>"$wal"
run_case torn-journal-tail-copy 'torn journal tail' "$c" "$installer" status --plan "$cp_plan"

# This state is separately and explicitly marked disposable. Reversibly mutate
# only its retained artifact because copying a target-sized image can exhaust the
# recovery disk. The trap restores on signals; the normal path restores and
# verifies the exact full digest before reporting success.
source_artifact=$(python3 - "$plan" "$state" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1])); print(os.path.join(sys.argv[2],x['body']['artifact']['relative_store_path']))
PY
)
if [[ -f $source_artifact && -s $source_artifact ]]; then
  restore_artifact=$source_artifact; restore_hash=$(sha256sum "$source_artifact" | awk '{print $1}')
  restore_hex=$(python3 - "$source_artifact" <<'PY'
import sys
with open(sys.argv[1],'rb') as f: print(f.read(1).hex())
PY
)
  printf '%s\n' "$restore_hex" >"$work/artifact-original-byte.hex"
  printf '%s\n' "$restore_hash" >"$work/artifact-original-sha256"
  printf '%s\n' "$restore_artifact" >"$work/artifact-path"
  flip_first_byte "$source_artifact"
  run_case artifact-tamper-disposable-state 'retained artifact no longer matches the authorized plan' "$state" "$installer" resume --plan "$plan"
  restored=$(sha256sum "$restore_artifact" | awk '{print $1}')
  if restore_retained_artifact; then
    restored=$(sha256sum "$restore_artifact" | awk '{print $1}')
    printf 'PASS case=artifact-restore expected=%q observed=%q\n' 'exact full digest restored' "$restored"; ((pass+=1))
    restore_artifact= restore_hex=
  else
    printf 'FAIL case=artifact-restore expected=%q observed=%q recovery_evidence=%s\n' "$restore_hash" "$restored" "$work"; ((fail+=1))
  fi
else
  printf 'SKIP case=artifact-tamper-disposable-state reason=%q\n' 'retained artifact unavailable'; ((skip+=1))
fi

# Public inspect overlap probes do not create state because an existing initialized
# state is supplied. They must refuse before any target write.
recovery_source=$(findmnt -n -o SOURCE --target "$state" 2>/dev/null || true)
recovery_disk=
if [[ $recovery_source == /dev/* ]]; then recovery_disk=$(lsblk -ndo PKNAME "$recovery_source" 2>/dev/null || true); [[ -n $recovery_disk ]] && recovery_disk=/dev/$recovery_disk || recovery_disk=$recovery_source; fi
if [[ -b ${recovery_disk:-} ]]; then
  run_case root-recovery-overlap 'overlaps' "$state" "$installer" inspect --disk "$recovery_disk" --state-dir "$state"
else
  printf 'SKIP case=root-recovery-overlap reason=%q\n' 'state filesystem has no simple block backing disk'; ((skip+=1))
fi

part=$(lsblk -lnpo NAME,TYPE "$target" | awk '$2=="part"{print $1;exit}')
fstype=$([[ -n $part ]] && blkid -o value -s TYPE "$part" 2>/dev/null || true)
if [[ -n $part && -b $part && $fstype == vfat ]]; then
  setup_before=$(target_digest)
  mountpoint=$work/target-mounted; mkdir "$mountpoint"
  if mount -o ro "$part" "$mountpoint" 2>/dev/null; then
    run_case target-mounted 'mounted' "$state" "$installer" inspect --disk "$target" --state-dir "$state"
    umount "$mountpoint"; mountpoint=
    setup_after=$(target_digest)
    if [[ $setup_before != "$setup_after" ]]; then
      printf 'FAIL case=target-mounted-setup expected=%q observed=%q target_before=%s target_after=%s\n' 'read-only mount setup preserves full target' 'target changed across mount+unmount' "$setup_before" "$setup_after"
      ((fail+=1))
    else
      printf 'PASS case=target-mounted-setup expected=%q observed=%q target_before=%s target_after=%s\n' 'read-only mount setup preserves full target' 'unchanged' "$setup_before" "$setup_after"
      ((pass+=1))
    fi
  else
    printf 'SKIP case=target-mounted reason=%q\n' 'existing target partition could not be mounted read-only'; ((skip+=1))
  fi
else
  printf 'SKIP case=target-mounted reason=%q\n' 'target has no existing vfat partition safe for read-only mount'; ((skip+=1))
fi

printf 'SUMMARY pass=%d fail=%d skip=%d inconclusive=%d\n' "$pass" "$fail" "$skip" "$inconclusive"
((fail == 0 && inconclusive == 0))
