# Disposable test VM only. Runs once at first logon from the answer media.
# Installs a tiny HTTP polling agent so the Linux host can drive the guest
# through QEMU user networking (host is 10.0.2.2), no SSH or WinRM required.
$ErrorActionPreference = 'Continue'
powercfg /hibernate off
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
$src = Join-Path $PSScriptRoot 'lab-agent.ps1'
Copy-Item $src C:\lab-agent.ps1 -Force
schtasks /create /f /tn JStackLabAgent /sc onstart /ru SYSTEM /rl HIGHEST /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\lab-agent.ps1"
schtasks /run /tn JStackLabAgent
