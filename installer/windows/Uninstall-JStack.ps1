<#
.SYNOPSIS
  Remove Jstack OS that Install-JStack.ps1 put next to Windows, and give the space back to C:.
.DESCRIPTION
  Deletes the JStack firmware boot entry, \EFI\jstack on the EFI partition, the JStack
  partition (identified by the GPT partition GUID recorded at install time, never by
  number alone), the "Restart into JStack" shortcut, then grows C: back.
  Also finishes the cleanup of an install that was interrupted.
#>
[CmdletBinding()]
param([switch]$Yes)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$StateDir = Join-Path $env:ProgramData 'JStack'
$StatePath = Join-Path $StateDir 'state.json'
$LinuxGuid = '{0fc63daf-8483-4772-8e79-3d69d8477de4}'

$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Yes) { $a += '-Yes' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a; exit 0
}
if (-not (Test-Path $StatePath)) { Write-Host "JStack is not installed (no $StatePath)."; exit 0 }
$s = Get-Content -Raw $StatePath | ConvertFrom-Json

$part = $null
if ($s.partition_guid) {
    $part = Get-Partition -DiskNumber $s.disk | Where-Object { $_.Guid -eq $s.partition_guid -and $_.GptType -eq $LinuxGuid }
}
Write-Host 'This removes Jstack OS and all files in it:'
if ($part) { Write-Host ("  partition #{0} on disk {1} ({2:N1} GB)" -f $part.PartitionNumber, $s.disk, ($part.Size / 1GB)) }
Write-Host '  \EFI\jstack on the EFI partition, the JStack boot entry, the Restart into JStack shortcut'
Write-Host '  and gives the space back to C:.'
if (-not $Yes -and (Read-Host 'Type YES to remove') -cne 'YES') { Write-Host 'Cancelled.'; exit 1 }

if ($s.fw_entry) { & bcdedit.exe /delete $s.fw_entry /f 2>&1 | Out-Null }
foreach ($l in 'S', 'T', 'U', 'V', 'W', 'Y', 'Z') {
    if (-not (Test-Path "${l}:\")) {
        & mountvol.exe "${l}:" /S 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            try { Remove-Item -LiteralPath "${l}:\EFI\jstack" -Recurse -Force -ErrorAction SilentlyContinue }
            finally { & mountvol.exe "${l}:" /D | Out-Null }
            break
        }
    }
}
if ($part) { Remove-Partition -DiskNumber $s.disk -PartitionNumber $part.PartitionNumber -Confirm:$false }
$max = (Get-PartitionSupportedSize -DiskNumber $s.disk -PartitionNumber $s.c_partition).SizeMax
$cur = (Get-Partition -DiskNumber $s.disk -PartitionNumber $s.c_partition).Size
if ($max -gt $cur) { Resize-Partition -DiskNumber $s.disk -PartitionNumber $s.c_partition -Size $max }
if ($s.PSObject.Properties['shortcut'] -and $s.shortcut) { Remove-Item -LiteralPath $s.shortcut -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath (Join-Path $StateDir 'Restart-Into-JStack.ps1') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $StatePath -Force
Write-Host 'Jstack OS removed. C: has its space back.' -ForegroundColor Green
