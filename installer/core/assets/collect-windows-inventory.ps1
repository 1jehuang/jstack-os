$ErrorActionPreference = 'Stop'

$runningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
if ($runningOnWindows) {
    $moduleRoot = [string]$env:JSTACK_WINDOWS_MODULE_ROOT
    if ([string]::IsNullOrWhiteSpace($moduleRoot)) { throw 'Trusted Windows module root was not provided' }
    $env:PSModulePath = $moduleRoot
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\Storage\Storage.psd1') -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\BitLocker\BitLocker.psd1') -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\SecureBoot\SecureBoot.psd1') -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1') -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name ($moduleRoot + '\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
}

function Get-JStackDisk {
    if ($script:runningOnWindows) { return @(Storage\Get-Disk -ErrorAction Stop) }
    return @(Get-Disk -ErrorAction Stop)
}

function Get-JStackPartition {
    param([uint32]$DiskNumber)
    if ($script:runningOnWindows) { return @(Storage\Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop) }
    return @(Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop)
}

function Get-JStackVolume {
    param([object]$Partition)
    if ($script:runningOnWindows) { return @(Storage\Get-Volume -Partition $Partition -ErrorAction Stop) }
    return @(Get-Volume -Partition $Partition -ErrorAction Stop)
}

function Get-JStackPartitionSupportedSize {
    param([uint32]$DiskNumber, [uint32]$PartitionNumber)
    if ($script:runningOnWindows) {
        return Storage\Get-PartitionSupportedSize -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -ErrorAction Stop
    }
    return Get-PartitionSupportedSize -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -ErrorAction Stop
}

function Get-JStackBitLockerVolume {
    param([string]$MountPoint)
    if ($script:runningOnWindows) { return BitLocker\Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop }
    return Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
}

function Get-JStackSecureBoot {
    if ($script:runningOnWindows) { return SecureBoot\Confirm-SecureBootUEFI -ErrorAction Stop }
    return Confirm-SecureBootUEFI -ErrorAction Stop
}

function Get-JStackRegistryValue {
    param([string]$LiteralPath)
    if ($script:runningOnWindows) {
        return Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop
    }
    return Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop
}

function Get-JStackBattery {
    if ($script:runningOnWindows) { return @(CimCmdlets\Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop) }
    return @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
}

function Test-JStackPath {
    param([string]$LiteralPath)
    if ($script:runningOnWindows) {
        return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
    }
    return Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
}

function Convert-VolumeObservation {
    param([object]$Partition)

    $volumes = @(Get-JStackVolume -Partition $Partition)
    if ($volumes.Count -eq 0) {
        return $null
    }
    if ($volumes.Count -ne 1) {
        throw "Partition $($Partition.DiskNumber)/$($Partition.PartitionNumber) has ambiguous volume metadata"
    }
    $volume = $volumes[0]
    return [ordered]@{
        unique_id = [string]$volume.UniqueId
        filesystem = [string]$volume.FileSystem
        size_bytes = [uint64]$volume.Size
        size_remaining_bytes = [uint64]$volume.SizeRemaining
        health_status = [string]$volume.HealthStatus
    }
}

$systemDrive = if ($runningOnWindows) { [string]$env:JSTACK_SYSTEM_DRIVE } else { [string]$env:SystemDrive }
if ($systemDrive -notmatch '^[A-Za-z]:$') { throw 'Trusted Windows system drive was not provided' }
$systemDrive = $systemDrive.TrimEnd(':')
if ($runningOnWindows) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} else {
    # The Rust binary never performs live collection off Windows. This branch
    # exists only so the exact embedded script can run against Linux CI mocks.
    $elevated = $true
}

$firmware = 'unknown'
$secureBootEnabled = $null
$firmwareEnvironmentReadable = $false
try {
    $secureBootEnabled = [bool](Get-JStackSecureBoot)
    $firmware = 'uefi'
    $firmwareEnvironmentReadable = $true
} catch {
    if ($_.Exception.Message -match 'not supported') {
        $firmware = 'legacy'
    }
}

$rebootPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)
$pendingReboot = $false
foreach ($path in $rebootPaths) {
    if (Test-JStackPath -LiteralPath $path) {
        $pendingReboot = $true
    }
}
$sessionManager = Get-JStackRegistryValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
if ($null -ne $sessionManager.PendingFileRenameOperations) {
    $pendingReboot = $true
}

$batteries = @(Get-JStackBattery)
$batteryPresent = $batteries.Count -gt 0
$onAcPower = $null
$chargePercent = $null
if ($batteryPresent) {
    $acStatuses = @(2, 6, 7, 8, 9)
    $onAcPower = @($batteries | Where-Object { $acStatuses -contains [int]$_.BatteryStatus }).Count -eq $batteries.Count
    $chargeValues = @($batteries | ForEach-Object { [int]$_.EstimatedChargeRemaining })
    $chargePercent = [int](($chargeValues | Microsoft.PowerShell.Utility\Measure-Object -Minimum).Minimum)
}

$disks = @(Get-JStackDisk | Microsoft.PowerShell.Utility\Sort-Object -Property Number | Microsoft.PowerShell.Core\ForEach-Object {
    $disk = $_
    $partitions = @(Get-JStackPartition -DiskNumber $disk.Number | Microsoft.PowerShell.Utility\Sort-Object -Property Offset | Microsoft.PowerShell.Core\ForEach-Object {
        $partition = $_
        $partitionGuid = [string]$partition.Guid
        if ([string]::IsNullOrWhiteSpace($partitionGuid)) { $partitionGuid = $null }
        $partitionTypeGuid = [string]$partition.GptType
        if ([string]::IsNullOrWhiteSpace($partitionTypeGuid)) { $partitionTypeGuid = $null }
        $isWindowsVolume = $null -ne $partition.DriveLetter -and [string]$partition.DriveLetter -ieq $systemDrive
        $resize = $null
        $bitlocker = $null
        if ($isWindowsVolume) {
            $supported = Get-JStackPartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber
            $resize = [ordered]@{
                minimum_bytes = [uint64]$supported.SizeMin
                maximum_bytes = [uint64]$supported.SizeMax
            }
            $bitlockerVolume = Get-JStackBitLockerVolume -MountPoint ($systemDrive + ':')
            $recoveryPresent = @($bitlockerVolume.KeyProtector | Microsoft.PowerShell.Core\Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
            $bitlocker = [ordered]@{
                protection_status = [string]$bitlockerVolume.ProtectionStatus
                volume_status = [string]$bitlockerVolume.VolumeStatus
                recovery_password_protector_present = $recoveryPresent
            }
        }
        [ordered]@{
            number = [uint32]$partition.PartitionNumber
            guid = $partitionGuid
            type_guid = $partitionTypeGuid
            offset_bytes = [uint64]$partition.Offset
            size_bytes = [uint64]$partition.Size
            is_boot = [bool]$partition.IsBoot
            is_system = [bool]$partition.IsSystem
            drive_letter = if ($null -eq $partition.DriveLetter) { $null } else { [string]$partition.DriveLetter }
            name = if ([string]::IsNullOrWhiteSpace([string]$partition.Type)) { $null } else { [string]$partition.Type }
            volume = Convert-VolumeObservation -Partition $partition
            resize = $resize
            bitlocker = $bitlocker
        }
    })
    $diskGuid = [string]$disk.Guid
    if ([string]::IsNullOrWhiteSpace($diskGuid)) { $diskGuid = $null }
    [ordered]@{
        number = [uint32]$disk.Number
        guid = $diskGuid
        partition_style = [string]$disk.PartitionStyle
        size_bytes = [uint64]$disk.Size
        logical_sector_bytes = [uint32]$disk.LogicalSectorSize
        physical_sector_bytes = [uint32]$disk.PhysicalSectorSize
        health_status = [string]$disk.HealthStatus
        operational_status = @($disk.OperationalStatus | Microsoft.PowerShell.Core\ForEach-Object { [string]$_ })
        partitions = $partitions
    }
})

[ordered]@{
    schema_version = 1
    collected_at_unix_ms = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    windows_version = [Environment]::OSVersion.VersionString
    architecture = [string]$env:PROCESSOR_ARCHITECTURE
    firmware = $firmware
    secure_boot_enabled = $secureBootEnabled
    elevated = $elevated
    firmware_environment_readable = $firmwareEnvironmentReadable
    windows_servicing_idle = -not $pendingReboot
    system_drive = $systemDrive + ':'
    power = [ordered]@{
        battery_present = $batteryPresent
        on_ac_power = $onAcPower
        charge_percent = $chargePercent
    }
    disks = $disks
} | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 12 -Compress
