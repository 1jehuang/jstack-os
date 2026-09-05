#!/usr/bin/env bash
# Real public-CLI refusal probes for an explicitly disposable Ubuntu QEMU/KVM guest.
# This script is destructive-test tooling: never run it on a host or valuable disks.
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
usage: ubuntu-refusal-probes.sh --marker FILE --installer FILE --plan FILE --target BLOCKDEV

FILE must contain exactly: JSTK_DISPOSABLE_UBUNTU_REFUSAL_VM_V1
The initialized state directory is the canonical parent of PLAN. The script only
mutates private sibling copies on the same recovery filesystem, except optional
read-only mount setup on an already existing target partition. It never writes the supplied target or state.
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
command -v python3 >/dev/null || die "python3 is required"
command -v sha256sum >/dev/null || die "sha256sum is required"

work=$(mktemp -d "$(dirname "$state")/.jstk-refusal-probes.XXXXXX")
mountpoint=
cleanup() {
  if [[ -n $mountpoint ]] && mountpoint -q "$mountpoint"; then umount "$mountpoint" || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

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
copy_state() { local d=$1; mkdir "$d"; cp -a --reflink=auto "$state"/. "$d"/; }
mutate_json() { python3 - "$@" <<'PY'
import json,sys
p,kind=sys.argv[1:]; x=json.load(open(p))
if kind=='plan-hash': x['plan_hash']='0'*64
elif kind=='confirmation': x['confirmation']['confirmed_plan_hash']='f'*64
json.dump(x,open(p,'w'),separators=(',',':'))
PY
}

positive_status

c=$work/corrupt-plan; copy_state "$c"; cp_plan=$c/$(basename "$plan"); mutate_json "$cp_plan" plan-hash
run_case corrupt-plan-hash 'exact plan authorization does not match' "$c" "$installer" status --plan "$cp_plan"

c=$work/unauthorized; copy_state "$c"; cp_plan=$c/$(basename "$plan"); mutate_json "$cp_plan" confirmation
run_case unauthorized-confirmation 'exact plan authorization does not match' "$c" "$installer" status --plan "$cp_plan"

c=$work/corrupt-journal; copy_state "$c"; cp_plan=$c/$(basename "$plan")
wal=$(find "$c/journal" -maxdepth 1 -type f -name '*.wal' -print -quit 2>/dev/null || true)
if [[ -n $wal && -s $wal ]]; then
  printf '\377' | dd of="$wal" bs=1 seek=0 conv=notrunc status=none
  run_case corrupt-journal-copy 'journal chain corruption' "$c" "$installer" status --plan "$cp_plan"
else
  printf 'SKIP case=corrupt-journal-copy reason=%q\n' 'isolated state has no nonempty journal'; ((skip+=1))
fi

# Tamper only the isolated promoted artifact. Identity or host-scope checks can
# precede artifact verification after copying, so only the intended error passes.
c=$work/artifact-tamper; copy_state "$c"; cp_plan=$c/$(basename "$plan")
artifact=$(python3 - "$cp_plan" "$c" <<'PY'
import json,os,sys
x=json.load(open(sys.argv[1])); print(os.path.join(sys.argv[2],x['body']['artifact']['relative_store_path']))
PY
)
if [[ -f $artifact && -s $artifact ]]; then
  printf '\377' | dd of="$artifact" bs=1 seek=0 conv=notrunc status=none
  run_case artifact-tamper-copy 'retained artifact no longer matches the authorized plan' "$c" "$installer" resume --plan "$cp_plan"
else
  printf 'SKIP case=artifact-tamper-copy reason=%q\n' 'isolated promoted artifact unavailable'; ((skip+=1))
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
if [[ -n $part && -b $part ]]; then
  mountpoint=$work/target-mounted; mkdir "$mountpoint"
  if mount -o ro "$part" "$mountpoint" 2>/dev/null; then
    run_case target-mounted 'mounted' "$state" "$installer" inspect --disk "$target" --state-dir "$state"
    umount "$mountpoint"; mountpoint=
  else
    printf 'SKIP case=target-mounted reason=%q\n' 'existing target partition could not be mounted read-only'; ((skip+=1))
  fi
else
  printf 'SKIP case=target-mounted reason=%q\n' 'target has no existing partition'; ((skip+=1))
fi

printf 'SUMMARY pass=%d fail=%d skip=%d inconclusive=%d\n' "$pass" "$fail" "$skip" "$inconclusive"
((fail == 0 && inconclusive == 0))
