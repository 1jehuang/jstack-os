#!/usr/bin/env bash
# End-to-end test of the Windows installer in a disposable Secure Boot VM.
#
#   installer/windows/vm/e2e.sh /abs/payload-dir [--base base] [--bitlocker] [--download]
#
# 1. Boots a fresh overlay of the Windows base image (Secure Boot on, MS keys only, TPM).
# 2. Copies the payload and installer in over the lab agent, runs Install-JStack.ps1 -Yes.
# 3. Windows restarts; firmware BootNext starts shim -> GRUB -> signed kernel -> JStack.
# 4. Checks on the serial console: Secure Boot enabled, firstboot done, user created.
# 5. Requests BootNext back to Windows from JStack, and checks the agent returns
#    (Windows still boots, and with BitLocker: no recovery prompt).
set -euo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
LAB=${JSTACK_WIN_LAB:-${JCODE_SCRATCH_DIR:-$HOME/.cache}/jstack-windows-vm}
PAYLOAD=${1:?payload dir}; shift
BASE=base
BITLOCKER=0
DOWNLOAD=0
while (($#)); do case $1 in
  --download) DOWNLOAD=1; shift;;   # fetch over HTTP (curl + resume + split parts) like a release
  --base) BASE=$2; shift 2;;
  --bitlocker) BITLOCKER=1; shift;;
  *) echo "unknown $1"; exit 2;; esac; done
NAME=e2e-$BASE$( ((BITLOCKER)) && echo -bl)
# Without BitLocker JStack becomes the default; with it the installer's auto choice is
# Windows (JStack still starts once via firmware BootNext right after install).
DEFAULT_OS=$( ((BITLOCKER)) && echo auto || echo jstack)
PORT=8765  # guest agent always polls 10.0.2.2:8765
lab() { python3 "$HERE/lab.py" "$@"; }
log() { printf '[e2e %(%H:%M:%S)T] %s\n' -1 "$*"; }
fail() { log "FAIL: $*"; lab screenshot "$NAME" "$LAB/$NAME-fail.ppm" >/dev/null 2>&1 || true; exit 1; }

# Payload is served to the guest as one tar (agent fetches files by name).
TAR=$LAB/$NAME-payload.tar
if ((DOWNLOAD)); then
  # Release-style: the guest downloads every asset from a flat HTTP directory.
  mkdir -p "$LAB/$NAME-www"; rm -f "$LAB/$NAME-www"/*
  find "$PAYLOAD" -path "$PAYLOAD/work" -prune -o -type f -print0 | xargs -0 -I{} ln -f {} "$LAB/$NAME-www/"
  ls -la "$LAB/$NAME-www"
  setsid python3 -m http.server 8799 -d "$LAB/$NAME-www" > "$LAB/$NAME-www.log" 2>&1 < /dev/null &
  WWW=$!
  SRC='-PayloadUrl http://10.0.2.2:8799'
else
  tar -C "$PAYLOAD" -cf "$TAR" --exclude=work .
  SRC='-PayloadDir C:\\lab\\payload'
fi
cp "$HERE/../Install-JStack.ps1" "$HERE/../Uninstall-JStack.ps1" "$LAB/"

rm -f "$LAB/$NAME.serial"
for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "qemu-system.* -name $NAME " >/dev/null || break; sleep 3; done
pgrep -f "qemu-system.* -name $NAME " >/dev/null && { echo "$NAME is already running (lab.py down $NAME --hard)"; exit 1; }
setsid python3 "$HERE/lab.py" up "$NAME" --base "$BASE" --fresh --persist --port $PORT \
  > "$LAB/$NAME.up.log" 2>&1 < /dev/null &
UP=$!
trap '[[ -n ${WWW:-} ]] && kill $WWW; touch "$LAB/$NAME.stop"; lab hmp "$NAME" quit >/dev/null 2>&1 || true; kill $UP 2>/dev/null || true' EXIT

wait_agent() { # seconds
  local end=$((SECONDS + $1))
  while ((SECONDS < end)); do
    if out=$(lab ps "$NAME" 'Write-Output alive' --timeout 20 2>/dev/null) && [[ $out == *alive* ]]; then return 0; fi
    sleep 5
  done
  return 1
}
log "booting Windows ($BASE)"
wait_agent 900 || fail 'Windows agent did not come up'
lab ps "$NAME" 'Confirm-SecureBootUEFI; (Get-BitLockerVolume C:).ProtectionStatus' || true

if ((BITLOCKER)); then
  # Real BitLocker with a TPM protector (what laptops ship with), then reboot once so the
  # TPM has sealed against a normal Windows boot before the installer runs.
  log 'turning on BitLocker (TPM protector, used-space only)'
  lab ps "$NAME" '
    $v = Get-BitLockerVolume C:
    if ($v.ProtectionStatus -ne "On") {
      Enable-BitLocker -MountPoint C: -TpmProtector -UsedSpaceOnly -SkipHardwareTest -EncryptionMethod XtsAes128 | Out-Null
      Add-BitLockerKeyProtector -MountPoint C: -RecoveryPasswordProtector | Out-Null
    }
    while ((Get-BitLockerVolume C:).VolumeStatus -eq "EncryptionInProgress") { Start-Sleep 5 }
    Get-BitLockerVolume C: | Format-List VolumeStatus,ProtectionStatus,EncryptionPercentage,KeyProtector | Out-String
  ' --timeout 1800 || fail 'could not enable BitLocker'
  lab ps "$NAME" 'shutdown.exe /r /t 2' --timeout 30 || true
  sleep 30
  wait_agent 900 || fail 'Windows did not come back after enabling BitLocker'
  # Status reads Off for a short while after boot, and Windows Update may suspend it: poll.
  lab ps "$NAME" '$i = 0; while ((Get-BitLockerVolume C:).ProtectionStatus -ne "On" -and $i -lt 24) { if ($i -eq 12) { Resume-BitLocker -MountPoint C: | Out-Null }; Start-Sleep 5; $i++ }; "BL=" + (Get-BitLockerVolume C:).ProtectionStatus' --timeout 300 | tee "$LAB/$NAME-bl.log"
  grep -q 'BL=On' "$LAB/$NAME-bl.log" || fail 'BitLocker protection is not on'
fi

URL_T=; ((DOWNLOAD)) || URL_T=$(lab put "$NAME" "$TAR")
URL_I=$(lab put "$NAME" "$LAB/Install-JStack.ps1"); URL_U=$(lab put "$NAME" "$LAB/Uninstall-JStack.ps1")
log 'copying payload into the guest'
lab ps "$NAME" "
\$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force C:\\lab\\payload | Out-Null
\$wc = New-Object Net.WebClient
\$wc.DownloadFile('$URL_I', 'C:\\lab\\Install-JStack.ps1')
\$wc.DownloadFile('$URL_U', 'C:\\lab\\Uninstall-JStack.ps1')
if ('$URL_T') {
  \$wc.DownloadFile('$URL_T', 'C:\\lab\\payload.tar')
  tar.exe -xf C:\\lab\\payload.tar -C C:\\lab\\payload
  if (\$LASTEXITCODE) { throw 'tar failed' }
}
Get-ChildItem -Recurse C:\\lab\\payload | Select-Object FullName,Length | Format-Table -Auto
" --timeout 1200 || fail 'copy failed'

log 'running Install-JStack.ps1 -DryRun'
lab ps "$NAME" "\$pw = ConvertTo-SecureString 'jstack-e2e' -AsPlainText -Force; & C:\\lab\\Install-JStack.ps1 $SRC -Username tester -Password \$pw -SizeGB 24 -DryRun *>&1 | Out-String -Width 300" --timeout 600 \
  | tee "$LAB/$NAME-dryrun.log"
grep -q 'Dry run: all checks passed' "$LAB/$NAME-dryrun.log" || fail 'dry run failed'

log 'running Install-JStack.ps1 for real'
lab ps "$NAME" "
\$pw = ConvertTo-SecureString 'jstack-e2e' -AsPlainText -Force
& C:\\lab\\Install-JStack.ps1 $SRC -Username tester -Password \$pw -Hostname e2ehost -SizeGB 24 -DefaultOS $DEFAULT_OS -NoReboot -Yes *>&1 | Out-String -Width 300
bcdedit /enum firmware | Out-String
Get-Partition | Format-Table -Auto | Out-String
" --timeout 2400 | tee "$LAB/$NAME-install.log"
grep -q 'Jstack OS is installed' "$LAB/$NAME-install.log" || fail 'installer did not finish'

log 'restarting into JStack'
lab ps "$NAME" 'shutdown.exe /r /t 2' --timeout 30 || true
sleep 20
# Log in on the serial getty as the account the installer created and run checks.
python3 "$HERE/serial.py" "$LAB/$NAME.serial.sock" tester jstack-e2e 600 \
  'echo SB=$(cat /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | od -An -tu1 | awk "{print \$NF}")' \
  'echo FB=$(cat /var/lib/jstack/firstboot.done) HOST=$(cat /etc/hostname) KERNEL=$(uname -r)' \
  'echo jstack-e2e | sudo -S -p "" dmesg | grep -i "secure boot" | head -3' \
  'echo ANSWERS=$(echo jstack-e2e | sudo -S -p "" ls /efi/EFI/jstack/)' \
  'findmnt -no SOURCE,FSTYPE / ; df -h / | tail -1' \
  'systemctl is-system-running; systemctl --failed --no-legend | head' \
  'sleep 5; loginctl list-sessions; echo TTY1=$(ps -o user= -t tty1 | grep -vx " *root" | tr -d " " | sort -u | head -1)' \
  'echo jstack-e2e | sudo -S -p "" efibootmgr' \
  'echo jstack-e2e | sudo -S -p "" jstack-boot-windows --reboot' \
  | tee "$LAB/$NAME-jstack.log" || fail 'serial login/checks failed'
grep -q 'SB=1' "$LAB/$NAME-jstack.log" || fail 'Secure Boot not enabled in JStack'
grep -q 'FB=tester HOST=e2ehost' "$LAB/$NAME-jstack.log" || fail 'first boot did not apply answers'
grep -q 'TTY1=tester' "$LAB/$NAME-jstack.log" || fail 'tty1 autologin did not log in the account'
grep -q 'firstboot.json' "$LAB/$NAME-jstack.log" && fail 'answer file was not erased'
log 'JStack: Secure Boot on, account and hostname applied, answers erased'

log 'JStack requested BootNext=Windows; waiting for Windows'
wait_agent 900 || fail 'Windows did not come back after JStack (BitLocker recovery screen?)'
lab ps "$NAME" '"SB=" + (Confirm-SecureBootUEFI); "BL=" + (Get-BitLockerVolume C:).ProtectionStatus; bcdedit /enum firmware | Select-String description' | tee -a "$LAB/$NAME-windows.log"
if ((BITLOCKER)); then
  # Reaching the agent means no recovery-key screen. The installer suspends BitLocker for
  # two reboots only, so after one more Windows reboot protection must be on again.
  lab ps "$NAME" 'shutdown.exe /r /t 2' --timeout 30 || true
  sleep 30
  wait_agent 900 || fail 'Windows did not come back on the second reboot'
  lab ps "$NAME" '$i = 0; while ((Get-BitLockerVolume C:).ProtectionStatus -ne "On" -and $i -lt 24) { Start-Sleep 5; $i++ }; "BL2=" + (Get-BitLockerVolume C:).ProtectionStatus' --timeout 300 | tee -a "$LAB/$NAME-windows.log"
  grep -q 'BL2=On' "$LAB/$NAME-windows.log" || fail 'BitLocker protection did not resume'
  log 'BitLocker: no recovery prompt, protection resumed'
fi
lab screenshot "$NAME" "$LAB/$NAME-windows.ppm" >/dev/null || true

log 'Uninstall-JStack.ps1'
lab ps "$NAME" '& C:\lab\Uninstall-JStack.ps1 -Yes *>&1 | Out-String; Get-Partition | Format-Table -Auto | Out-String; bcdedit /enum firmware | Select-String description' --timeout 600 \
  | tee "$LAB/$NAME-uninstall.log"
grep -q 'Jstack OS removed' "$LAB/$NAME-uninstall.log" || fail 'uninstall failed'
log "PASS ($BASE)"
