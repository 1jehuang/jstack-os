# PH-08 Windows mutation adapters.
#
# Each adapter performs exactly one graph action against the *local* Windows
# machine and prints one canonical JSON observation. Adapters are gated so they
# can only ever run inside a disposable VM:
#
#   * JSTACK_DISPOSABLE_VM must be the exact attestation token minted by the
#     harness for this run. It is never present on a real user machine.
#   * The target disk GUID and every partition GUID must come from the confirmed
#     plan supplied on stdin. No adapter discovers a target on its own.
#   * Every adapter re-observes the machine after mutating and emits a
#     postcondition observation, so the controller never has to trust a return
#     code.
#
# The adapters use only the storage, BitLocker, and scheduled-task primitives
# the architecture document names. Each is invoked with -Action so the static
# allowlist validator can enumerate the entire mutation surface in one file.
#
# Firmware boot variables (Boot####, BootOrder, BootNext) and the reboot request
# are deliberately NOT here: Windows exposes no cmdlet for them, and shelling out
# to bcdedit is forbidden. They live in the Rust adapter in
# `src/windows_firmware.rs`, which calls the documented Win32
# Get/SetFirmwareEnvironmentVariableExW API directly.

param(
    [Parameter(Mandatory = $true)][string]$Action
)

$ErrorActionPreference = 'Stop'

$runningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

# ---------------------------------------------------------------------------
# Disposable-VM gate
# ---------------------------------------------------------------------------

function Assert-JStackDisposableVm {
    # The harness mints this token per run and records it in the evidence
    # bundle. Without it, every adapter refuses before observing anything.
    $token = [string]$env:JSTACK_DISPOSABLE_VM
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Refusing to mutate: JSTACK_DISPOSABLE_VM attestation is absent'
    }
    if ($token.Length -lt 32) {
        throw 'Refusing to mutate: JSTACK_DISPOSABLE_VM attestation is malformed'
    }
    $expected = [string]$env:JSTACK_DISPOSABLE_VM_EXPECTED
    if ([string]::IsNullOrWhiteSpace($expected)) {
        throw 'Refusing to mutate: no expected attestation was provided by the controller'
    }
    if ($token -cne $expected) {
        throw 'Refusing to mutate: disposable-VM attestation does not match this run'
    }
}

function Assert-JStackCapability {
    # The controller passes the capability digest it issued for this exact
    # action. An adapter invoked without one is refused, so a stray adapter run
    # cannot mutate even inside the VM.
    param([string]$Action, [object]$Request)
    if ($null -eq $Request.capability) {
        throw "Refusing to run ${Action}: no controller capability was presented"
    }
    if ([string]$Request.capability.action -cne $Action) {
        throw "Refusing to run ${Action}: capability authorizes $($Request.capability.action)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$Request.capability.plan_hash)) {
        throw "Refusing to run ${Action}: capability is not bound to a plan"
    }
    if ([string]$Request.capability.plan_hash -cne [string]$Request.plan_hash) {
        throw "Refusing to run ${Action}: capability is bound to a different plan"
    }
}

function Read-JStackRequest {
    # The request is the confirmed plan projection. It is the only source of
    # disk and partition identity; nothing is discovered.
    param([string]$Action)
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Refusing to run ${Action}: no plan-bound request was supplied"
    }
    $request = $raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$request.disk_guid)) {
        throw "Refusing to run ${Action}: request names no disk"
    }
    Assert-JStackCapability -Action $Action -Request $request
    return $request
}

# ---------------------------------------------------------------------------
# Plan-bound target resolution
# ---------------------------------------------------------------------------

function Resolve-JStackDisk {
    # Resolve by GPT disk GUID only. A disk number is a positional identity that
    # can change between boots, so it is never accepted from the request.
    param([string]$DiskGuid)
    $matches = @(Storage\Get-Disk -ErrorAction Stop | Microsoft.PowerShell.Core\Where-Object {
        [string]$_.Guid -ieq $DiskGuid -and [string]$_.PartitionStyle -eq 'GPT'
    })
    if ($matches.Count -ne 1) {
        throw "Plan disk $DiskGuid does not resolve to exactly one GPT disk"
    }
    return $matches[0]
}

function Resolve-JStackPartition {
    param([uint32]$DiskNumber, [string]$PartitionGuid)
    $matches = @(Storage\Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop |
        Microsoft.PowerShell.Core\Where-Object { [string]$_.Guid -ieq $PartitionGuid })
    if ($matches.Count -ne 1) {
        throw "Plan partition $PartitionGuid does not resolve to exactly one partition"
    }
    return $matches[0]
}

function Get-JStackPartitionObservation {
    param([object]$Partition)
    return [ordered]@{
        guid = [string]$Partition.Guid
        type_guid = [string]$Partition.GptType
        offset_bytes = [uint64]$Partition.Offset
        size_bytes = [uint64]$Partition.Size
    }
}

# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

function Invoke-JStackShrinkWindows {
    # graph action: shrink_windows_ntfs
    param([object]$Request)
    $disk = Resolve-JStackDisk -DiskGuid ([string]$Request.disk_guid)
    $partition = Resolve-JStackPartition -DiskNumber $disk.Number -PartitionGuid ([string]$Request.windows_partition_guid)

    $target = [uint64]$Request.target_size_bytes
    $supported = Storage\Get-PartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -ErrorAction Stop
    if ($target -lt [uint64]$supported.SizeMin -or $target -gt [uint64]$supported.SizeMax) {
        throw "Plan target $target is outside the supported resize range"
    }
    if ([uint64]$partition.Size -eq $target) {
        # Idempotent: the shrink already happened before a crash.
        $observed = Resolve-JStackPartition -DiskNumber $disk.Number -PartitionGuid ([string]$partition.Guid)
        return [ordered]@{ already_satisfied = $true; partition = Get-JStackPartitionObservation -Partition $observed }
    }
    if ($target -gt [uint64]$partition.Size) {
        throw 'Refusing to grow the Windows partition during a shrink action'
    }

    Storage\Resize-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -Size $target -ErrorAction Stop

    $observed = Resolve-JStackPartition -DiskNumber $disk.Number -PartitionGuid ([string]$partition.Guid)
    if ([uint64]$observed.Size -ne $target) {
        throw "Postcondition failed: Windows partition is $($observed.Size), expected $target"
    }
    return [ordered]@{ already_satisfied = $false; partition = Get-JStackPartitionObservation -Partition $observed }
}

function Invoke-JStackExpandWindows {
    # graph action: expand_windows_ntfs (rollback)
    param([object]$Request)
    $disk = Resolve-JStackDisk -DiskGuid ([string]$Request.disk_guid)
    $partition = Resolve-JStackPartition -DiskNumber $disk.Number -PartitionGuid ([string]$Request.windows_partition_guid)

    $target = [uint64]$Request.original_size_bytes
    $supported = Storage\Get-PartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -ErrorAction Stop
    if ($target -gt [uint64]$supported.SizeMax) {
        throw "Rollback target $target exceeds the supported maximum"
    }
    if ([uint64]$partition.Size -eq $target) {
        return [ordered]@{ already_satisfied = $true; partition = Get-JStackPartitionObservation -Partition $partition }
    }

    Storage\Resize-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -Size $target -ErrorAction Stop

    $observed = Resolve-JStackPartition -DiskNumber $disk.Number -PartitionGuid ([string]$partition.Guid)
    if ([uint64]$observed.Size -ne $target) {
        throw "Postcondition failed: Windows partition is $($observed.Size), expected $target"
    }
    return [ordered]@{ already_satisfied = $false; partition = Get-JStackPartitionObservation -Partition $observed }
}

function Invoke-JStackCreatePartition {
    # graph actions: create_xbootldr_partition, create_root_partition
    param([object]$Request)
    $disk = Resolve-JStackDisk -DiskGuid ([string]$Request.disk_guid)

    $offset = [uint64]$Request.offset_bytes
    $size = [uint64]$Request.size_bytes
    $intervalStart = [uint64]$Request.allocation_start_bytes
    $intervalEnd = [uint64]$Request.allocation_end_bytes
    if ($offset -lt $intervalStart -or ($offset + $size) -gt $intervalEnd) {
        throw 'Refusing to create a partition outside the confirmed allocation interval'
    }

    $existing = @(Storage\Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Microsoft.PowerShell.Core\Where-Object { [uint64]$_.Offset -eq $offset })
    if ($existing.Count -eq 1) {
        return [ordered]@{ already_satisfied = $true; partition = Get-JStackPartitionObservation -Partition $existing[0] }
    }

    # Every existing partition must be disjoint from the planned interval.
    $overlapping = @(Storage\Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Microsoft.PowerShell.Core\Where-Object {
            [uint64]$_.Offset -lt ($offset + $size) -and $offset -lt ([uint64]$_.Offset + [uint64]$_.Size)
        })
    if ($overlapping.Count -ne 0) {
        throw 'Refusing to create a partition overlapping an existing partition'
    }

    Storage\New-Partition -DiskNumber $disk.Number -Offset $offset -Size $size -GptType ([string]$Request.type_guid) -ErrorAction Stop

    $observed = @(Storage\Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
        Microsoft.PowerShell.Core\Where-Object { [uint64]$_.Offset -eq $offset })
    if ($observed.Count -ne 1) {
        throw 'Postcondition failed: the planned partition is not present exactly once'
    }
    if ([uint64]$observed[0].Size -ne $size) {
        throw "Postcondition failed: partition size is $($observed[0].Size), expected $size"
    }
    return [ordered]@{ already_satisfied = $false; partition = Get-JStackPartitionObservation -Partition $observed[0] }
}

function Invoke-JStackSuspendBitLocker {
    # graph action: suspend_bitlocker
    param([object]$Request)
    $mountPoint = [string]$Request.system_drive
    $volume = BitLocker\Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
    if ([string]$volume.ProtectionStatus -eq 'Off') {
        return [ordered]@{ already_satisfied = $true; protection_status = 'Off' }
    }

    # RebootCount 0 keeps protection suspended across an unbounded number of
    # reboots. The installer restores protection explicitly in the finalizer, so
    # a rearm loop must not silently re-enable it mid-install.
    BitLocker\Suspend-BitLocker -MountPoint $mountPoint -RebootCount 0 -ErrorAction Stop

    $observed = BitLocker\Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
    if ([string]$observed.ProtectionStatus -ne 'Off') {
        throw "Postcondition failed: BitLocker protection is $($observed.ProtectionStatus)"
    }
    return [ordered]@{ already_satisfied = $false; protection_status = [string]$observed.ProtectionStatus }
}

function Invoke-JStackRestoreBitLocker {
    # graph action: restore_bitlocker
    param([object]$Request)
    $mountPoint = [string]$Request.system_drive
    $volume = BitLocker\Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
    if ([string]$Request.original_protection_status -eq 'Off') {
        # The volume was never protected. Restoring must not newly encrypt it.
        return [ordered]@{ already_satisfied = $true; protection_status = [string]$volume.ProtectionStatus }
    }
    if ([string]$volume.ProtectionStatus -eq 'On') {
        return [ordered]@{ already_satisfied = $true; protection_status = 'On' }
    }

    BitLocker\Resume-BitLocker -MountPoint $mountPoint -ErrorAction Stop

    $observed = BitLocker\Get-BitLockerVolume -MountPoint $mountPoint -ErrorAction Stop
    if ([string]$observed.ProtectionStatus -ne 'On') {
        throw "Postcondition failed: BitLocker protection is $($observed.ProtectionStatus), expected On"
    }
    return [ordered]@{ already_satisfied = $false; protection_status = [string]$observed.ProtectionStatus }
}

function Invoke-JStackRegisterFinalizer {
    # graph action: register_windows_finalizer
    param([object]$Request)
    $taskPath = [string]$Request.finalizer_task_path
    $taskName = [string]$Request.finalizer_task_name
    if ([string]::IsNullOrWhiteSpace($taskPath) -or [string]::IsNullOrWhiteSpace($taskName)) {
        throw 'Refusing to register a finalizer without a plan-bound task identity'
    }

    $existing = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($existing.Count -eq 1) {
        return [ordered]@{ already_satisfied = $true; task = "$taskPath$taskName" }
    }

    $action = ScheduledTasks\New-ScheduledTaskAction -Execute ([string]$Request.finalizer_executable) -Argument ([string]$Request.finalizer_arguments)
    $trigger = ScheduledTasks\New-ScheduledTaskTrigger -AtStartup
    $principal = ScheduledTasks\New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    ScheduledTasks\Register-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -ErrorAction Stop | Microsoft.PowerShell.Core\Out-Null

    $observed = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop)
    if ($observed.Count -ne 1) {
        throw 'Postcondition failed: the finalizer task is not registered exactly once'
    }
    return [ordered]@{ already_satisfied = $false; task = "$taskPath$taskName" }
}

function Invoke-JStackUnregisterFinalizer {
    # graph action: unregister_windows_finalizer
    param([object]$Request)
    $taskPath = [string]$Request.finalizer_task_path
    $taskName = [string]$Request.finalizer_task_name
    $existing = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($existing.Count -eq 0) {
        return [ordered]@{ already_satisfied = $true; task = "$taskPath$taskName" }
    }

    ScheduledTasks\Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false -ErrorAction Stop

    $observed = @(ScheduledTasks\Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue)
    if ($observed.Count -ne 0) {
        throw 'Postcondition failed: the finalizer task still exists'
    }
    return [ordered]@{ already_satisfied = $false; task = "$taskPath$taskName" }
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

Assert-JStackDisposableVm
$request = Read-JStackRequest -Action $Action

$result = switch ($Action) {
    'shrink_windows_ntfs' { Invoke-JStackShrinkWindows -Request $request }
    'expand_windows_ntfs' { Invoke-JStackExpandWindows -Request $request }
    'create_xbootldr_partition' { Invoke-JStackCreatePartition -Request $request }
    'create_root_partition' { Invoke-JStackCreatePartition -Request $request }
    'suspend_bitlocker' { Invoke-JStackSuspendBitLocker -Request $request }
    'restore_bitlocker' { Invoke-JStackRestoreBitLocker -Request $request }
    'register_windows_finalizer' { Invoke-JStackRegisterFinalizer -Request $request }
    'unregister_windows_finalizer' { Invoke-JStackUnregisterFinalizer -Request $request }
    default { throw "Unknown adapter action: $Action" }
}

[ordered]@{
    schema_version = 1
    action = $Action
    plan_hash = [string]$request.plan_hash
    observed_at_unix_ms = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    result = $result
} | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress
