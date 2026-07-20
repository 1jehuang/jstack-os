$env:SystemDrive = 'C:'
$env:PROCESSOR_ARCHITECTURE = 'AMD64'

function Confirm-SecureBootUEFI { return $true }
function Test-Path { param([string]$LiteralPath) return $false }
function Get-ItemProperty { param([string]$LiteralPath, $ErrorAction) return [pscustomobject]@{} }
function Get-CimInstance {
    param([string]$ClassName, $ErrorAction)
    if ($env:JSTACK_FAIL_BATTERY -eq '1') { throw 'mock battery observation failed' }
    return [pscustomobject]@{ BatteryStatus = 2; EstimatedChargeRemaining = 80 }
}
function Get-Disk {
    return @(
        [pscustomobject]@{
            Number = 1
            Guid = $null
            PartitionStyle = 'MBR'
            Size = [uint64]68719476736
            LogicalSectorSize = 512
            PhysicalSectorSize = 4096
            HealthStatus = 'Healthy'
            OperationalStatus = @('Online')
        },
        [pscustomobject]@{
            Number = 0
            Guid = '{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}'
            PartitionStyle = 'GPT'
            Size = [uint64]431126216704
            LogicalSectorSize = 512
            PhysicalSectorSize = 4096
            HealthStatus = 'Healthy'
            OperationalStatus = @('Online')
        }
    )
}
function Get-Partition {
    param([uint32]$DiskNumber)
    if ($DiskNumber -eq 1) {
        return @(
            [pscustomobject]@{
                DiskNumber = 1; PartitionNumber = 1
                Guid = $null; GptType = $null
                Offset = [uint64]1048576; Size = [uint64]33554432
                IsBoot = $false; IsSystem = $false; DriveLetter = 'D'; Type = 'Unrelated MBR data'
            }
        )
    }
    if ($DiskNumber -ne 0) { return @() }
    return @(
        [pscustomobject]@{
            DiskNumber = 0; PartitionNumber = 4
            Guid = '{44444444-4444-4444-8444-444444444444}'
            GptType = '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
            Offset = [uint64]430051426304; Size = [uint64]1073741824
            IsBoot = $false; IsSystem = $false; DriveLetter = $null; Type = 'Windows RE'
        },
        [pscustomobject]@{
            DiskNumber = 0; PartitionNumber = 3
            Guid = '{33333333-3333-4333-8333-333333333333}'
            GptType = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
            Offset = [uint64]554696704; Size = [uint64]429496729600
            IsBoot = $true; IsSystem = $false; DriveLetter = 'C'; Type = 'Windows'
        },
        [pscustomobject]@{
            DiskNumber = 0; PartitionNumber = 2
            Guid = '{22222222-2222-4222-8222-222222222222}'
            GptType = '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
            Offset = [uint64]537919488; Size = [uint64]16777216
            IsBoot = $false; IsSystem = $false; DriveLetter = $null; Type = $null
        },
        [pscustomobject]@{
            DiskNumber = 0; PartitionNumber = 1
            Guid = '{11111111-1111-4111-8111-111111111111}'
            GptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
            Offset = [uint64]1048576; Size = [uint64]536870912
            IsBoot = $false; IsSystem = $true; DriveLetter = $null; Type = 'EFI'
        }
    )
}
function Get-Volume {
    param([object]$Partition, $ErrorAction)
    if ($Partition.DiskNumber -eq 1) { return @() }
    switch ($Partition.PartitionNumber) {
        1 { return [pscustomobject]@{ UniqueId = 'volume-esp'; FileSystem = 'FAT32'; Size = [uint64]536870912; SizeRemaining = [uint64]209715200; HealthStatus = 'Healthy' } }
        2 { return @() }
        3 { return [pscustomobject]@{ UniqueId = 'volume-c'; FileSystem = 'NTFS'; Size = [uint64]429496729600; SizeRemaining = [uint64]180000000000; HealthStatus = 'Healthy' } }
        4 { return [pscustomobject]@{ UniqueId = 'winre'; FileSystem = 'NTFS'; Size = [uint64]1073741824; SizeRemaining = [uint64]536870912; HealthStatus = 'Healthy' } }
    }
}
function Get-PartitionSupportedSize {
    param([uint32]$DiskNumber, [uint32]$PartitionNumber)
    return [pscustomobject]@{ SizeMin = [uint64]268435456000; SizeMax = [uint64]429496729600 }
}
function Get-BitLockerVolume {
    param([string]$MountPoint)
    return [pscustomobject]@{
        ProtectionStatus = 'On'
        VolumeStatus = 'FullyEncrypted'
        KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword' })
    }
}
