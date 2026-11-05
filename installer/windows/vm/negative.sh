#!/usr/bin/env bash
# Failure-path tests of the Windows installer in a disposable Secure Boot VM.
#
#   installer/windows/vm/negative.sh /abs/payload-dir [--base base]
#
# 1. Bad arguments are refused before anything changes.
# 2. A corrupt local payload (-PayloadDir) fails the checksum, nothing changes.
# 3. Download self-repair: a truncated part resumes, a full-size damaged part is fetched
#    again, then the install succeeds.
# 4. Running the installer again refuses (already installed). Uninstall restores everything.
# 5. The installer is killed mid-write (like a crash): Uninstall-JStack cleans up the half
#    install and restores C:.
set -euo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
LAB=${JSTACK_WIN_LAB:-${JCODE_SCRATCH_DIR:-$HOME/.cache}/jstack-windows-vm}
PAYLOAD=${1:?payload dir}; shift
BASE=base
while (($#)); do case $1 in
  --base) BASE=$2; shift 2;;
  *) echo "unknown $1"; exit 2;; esac; done
NAME=neg-$BASE
PORT=8765
lab() { python3 "$HERE/lab.py" "$@"; }
log() { printf '[neg %(%H:%M:%S)T] %s\n' -1 "$*"; }
fail() { log "FAIL: $*"; exit 1; }

WWWD=$LAB/$NAME-www
mkdir -p "$WWWD"; find "$WWWD" -maxdepth 1 -type f -delete
find "$PAYLOAD" -path "$PAYLOAD/work" -prune -o -type f -print0 | xargs -0 -I{} ln -f {} "$WWWD/"
cp "$HERE/../Install-JStack.ps1" "$HERE/../Uninstall-JStack.ps1" "$LAB/"
for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "qemu-system.* -name $NAME " >/dev/null || break; sleep 3; done
pgrep -f "qemu-system.* -name $NAME " >/dev/null && { echo "$NAME is already running"; exit 1; }
setsid python3 "$HERE/rangehttp.py" 8799 "$WWWD" > "$LAB/$NAME-www.log" 2>&1 < /dev/null &
WWW=$!
setsid python3 "$HERE/lab.py" up "$NAME" --base "$BASE" --fresh --persist --port $PORT \
  > "$LAB/$NAME.up.log" 2>&1 < /dev/null &
UP=$!
trap 'kill $WWW 2>/dev/null; touch "$LAB/$NAME.stop"; lab hmp "$NAME" quit >/dev/null 2>&1 || true; kill $UP 2>/dev/null || true' EXIT

wait_agent() {
  local end=$((SECONDS + $1))
  while ((SECONDS < end)); do
    if out=$(lab ps "$NAME" 'Write-Output alive' --timeout 20 2>/dev/null) && [[ $out == *alive* ]]; then return 0; fi
    sleep 5
  done
  return 1
}
# Runs PowerShell in the guest, saves output to $LAB/$NAME-$1.log, echoes it.
run() { local tag=$1; shift; lab ps "$NAME" "$1" --timeout "${2:-2400}" | tee "$LAB/$NAME-$tag.log"; }
expect() { grep -q -- "$2" "$LAB/$NAME-$1.log" || fail "$1: expected '$2'"; }

INST='& C:\lab\Install-JStack.ps1'
PW='$pw = ConvertTo-SecureString "jstack-e2e" -AsPlainText -Force;'
SNAP='"CSIZE=" + (Get-Partition -DriveLetter C).Size
"LINUXPARTS=" + @(Get-Partition | Where-Object GptType -eq "{0fc63daf-8483-4772-8e79-3d69d8477de4}").Count
"FWENTRY=" + [bool](bcdedit /enum firmware | Select-String "Jstack OS")
"STATE=" + (Test-Path "$env:ProgramData\JStack\state.json")
mountvol.exe S: /S | Out-Null; "ESPDIR=" + (Test-Path S:\EFI\jstack); mountvol.exe S: /D | Out-Null'
clean() { # tag: the machine looks exactly like before any install
  run "$1" "$SNAP" >/dev/null
  [[ $(grep -o 'CSIZE=[0-9]*' "$LAB/$NAME-$1.log") == "$CSIZE0" ]] || fail "$1: C: size changed"
  for w in LINUXPARTS=0 FWENTRY=False STATE=False ESPDIR=False; do expect "$1" "$w"; done
}

log "booting Windows ($BASE)"
wait_agent 900 || fail 'Windows agent did not come up'
URL_I=$(lab put "$NAME" "$LAB/Install-JStack.ps1"); URL_U=$(lab put "$NAME" "$LAB/Uninstall-JStack.ps1")
run setup "
\$wc = New-Object Net.WebClient
New-Item -ItemType Directory -Force C:\\lab\\pl\\boot | Out-Null
\$wc.DownloadFile('$URL_I', 'C:\\lab\\Install-JStack.ps1')
\$wc.DownloadFile('$URL_U', 'C:\\lab\\Uninstall-JStack.ps1')
\$m = \$wc.DownloadString('http://10.0.2.2:8799/manifest.json'); Set-Content C:\\lab\\pl\\manifest.json \$m -NoNewline
foreach (\$n in (\$m | ConvertFrom-Json).files.PSObject.Properties.Name) {
  \$wc.DownloadFile('http://10.0.2.2:8799/' + (Split-Path \$n -Leaf), 'C:\\lab\\pl\\' + (\$n -replace '/','\\'))
}
'done'
" >/dev/null
run snap0 "$SNAP" >/dev/null
CSIZE0=$(grep -o 'CSIZE=[0-9]*' "$LAB/$NAME-snap0.log"); [[ -n $CSIZE0 ]] || fail 'no C: size'

log '1. bad arguments are refused'
run badargs "
foreach (\$a in @(@{Username='root'}, @{Username='Bad User'}, @{Username='ok'; Hostname='bad_host'}, @{Username='ok'; SizeGB=5}, @{Username='ok'; SizeGB=9999})) {
  try { & C:\\lab\\Install-JStack.ps1 -PayloadDir C:\\lab\\pl -NoPassword -Yes -NoReboot @a *>&1 | Out-Null; 'ACCEPTED ' + (\$a | Out-String) }
  catch { 'REFUSED: ' + \$_.Exception.Message }
}" 600
grep -q ACCEPTED "$LAB/$NAME-badargs.log" && fail 'a bad argument was accepted'
[[ $(grep -c REFUSED "$LAB/$NAME-badargs.log") == 5 ]] || fail 'expected 5 refusals'
clean badargs-after

log '2. corrupt local payload fails the checksum, nothing changes'
FLIP='function Flip($f, [long]$off) { $s = [IO.File]::Open($f, "Open", "ReadWrite"); $s.Position = $off; $b = $s.ReadByte(); $s.Position = $off; $s.WriteByte($b -bxor 0xff); $s.Close() }'
run corrupt "$FLIP; Flip C:\\lab\\pl\\jstack-root.img.gz.part001 1000000
try { $PW $INST -PayloadDir C:\\lab\\pl -Username tester -Password \$pw -SizeGB 24 -Yes -NoReboot *>&1 | Out-String -Width 300 } catch { 'ERROR: ' + \$_.Exception.Message }"
expect corrupt 'checksum mismatch for jstack-root.img.gz.part001'
clean corrupt-after

log '3. download: truncated part resumes, damaged full-size part is fetched again'
run heal "
New-Item -ItemType Directory -Force C:\\JStackInstall | Out-Null
Copy-Item C:\\lab\\pl\\jstack-root.img.gz.part00* C:\\JStackInstall\\
\$s = [IO.File]::Open('C:\\JStackInstall\\jstack-root.img.gz.part000', 'Open', 'ReadWrite'); \$s.SetLength(100MB); \$s.Close()
Remove-Item C:\\lab\\pl -Recurse -Force
$PW $INST -PayloadUrl http://10.0.2.2:8799 -Username tester -Password \$pw -Hostname neghost -SizeGB 24 -DefaultOS windows -Yes -NoReboot *>&1 | Out-String -Width 300
'LEFTOVER=' + (Test-Path C:\\JStackInstall)"
expect heal 'jstack-root.img.gz.part001 is damaged, downloading it again'
expect heal 'Jstack OS is installed'
expect heal 'LEFTOVER=False'
grep -q 'part000 HTTP/1.1" 206' "$LAB/$NAME-www.log" || fail 'part000 was not resumed (no 206 range request)'

log '4. installing twice is refused, uninstall restores everything'
run twice "try { $PW $INST -PayloadUrl http://10.0.2.2:8799 -Username tester -Password \$pw -SizeGB 24 -Yes -NoReboot *>&1 | Out-String } catch { 'ERROR: ' + \$_.Exception.Message }"
expect twice 'already looks installed'
run uninstall '& C:\lab\Uninstall-JStack.ps1 -Yes *>&1 | Out-String'
expect uninstall 'Jstack OS removed'
clean uninstall-after

log '5. installer killed while writing, then Uninstall-JStack'
run kill "
Remove-Item C:\\ProgramData\\JStack\\install.log -ErrorAction SilentlyContinue
\$p = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"\$pw = ConvertTo-SecureString jstack-e2e -AsPlainText -Force; & C:\\lab\\Install-JStack.ps1 -PayloadUrl http://10.0.2.2:8799 -Username tester -Password \$pw -SizeGB 24 -Yes -NoReboot\"'
\$t = 0; while (\$t -lt 900 -and -not (Select-String -Quiet -Path C:\\ProgramData\\JStack\\install.log -Pattern 'Writing Jstack OS' -ErrorAction SilentlyContinue)) { Start-Sleep 2; \$t += 2 }
Start-Sleep 15
Stop-Process -Id \$p.Id -Force
Start-Sleep 3
'STATE=' + (Test-Path C:\\ProgramData\\JStack\\state.json)
'LINUXPARTS=' + @(Get-Partition | Where-Object GptType -eq '{0fc63daf-8483-4772-8e79-3d69d8477de4}').Count"
expect kill 'STATE=True'
expect kill 'LINUXPARTS=1'
run uninstall2 '& C:\lab\Uninstall-JStack.ps1 -Yes *>&1 | Out-String'
expect uninstall2 'Jstack OS removed'
clean uninstall2-after
run uninstall3 '& C:\lab\Uninstall-JStack.ps1 -Yes *>&1 | Out-String'
expect uninstall3 'not installed'

log 'PASS'
