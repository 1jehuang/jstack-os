<#
.SYNOPSIS
  Install Jstack OS next to Windows. No USB stick, no BIOS settings, Secure Boot stays on.

.DESCRIPTION
  1. Checks the PC: UEFI, GPT system disk, 64-bit, admin, free space, BitLocker state.
  2. Downloads the JStack payload and verifies every file against manifest.json (SHA256).
  3. Shrinks C: and creates a Linux partition in the freed space.
  4. Writes the JStack root filesystem image into that partition, then reads it back to verify.
  5. Copies the boot loaders (about 4 MB) into \EFI\jstack\ on the existing EFI partition:
       shimx64.efi (signed by Microsoft) -> grubx64.efi -> kernel (both signed by Canonical).
     Firmware that trusts Microsoft (practically every Windows PC) boots it with Secure Boot ON.
  6. Leaves first-boot answers (account, hostname, time zone, Wi-Fi) in \EFI\jstack\firstboot.json.
     JStack reads and erases them on its first boot.
  7. Suspends BitLocker protection for two restarts, adds a firmware boot entry, and restarts into JStack.

  Windows is never modified apart from shrinking C:, one firmware boot entry and the
  \EFI\jstack folder. Uninstall-JStack.ps1 removes all three and gives the space back.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Install-JStack.ps1
.EXAMPLE
  .\Install-JStack.ps1 -SizeGB 120 -Username jeremy -Hostname laptop -Yes
#>
[CmdletBinding()]
param(
    [int]$SizeGB = 0,                 # 0 = pick automatically (64 GB, less if the disk is small)
    [string]$Username,
    [string]$FullName,
    [securestring]$Password,
    [switch]$NoPassword,              # empty login password (matches the USB installer option)
    [string]$Hostname = 'jstack',
    [string]$PayloadDir,              # local folder with manifest.json (skips the download)
    [string]$PayloadUrl = 'https://github.com/1jehuang/jstack-os/releases/latest/download',
    [ValidateSet('auto', 'jstack', 'windows')][string]$DefaultOS = 'auto',
    [switch]$NoWifi,                  # do not copy saved Wi-Fi networks to JStack
    [switch]$NoReboot,
    [switch]$Yes,                     # do not ask for confirmation
    [switch]$DryRun                   # run every check, change nothing
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$MinGB = 24
$LinuxGuid = '{0fc63daf-8483-4772-8e79-3d69d8477de4}'
$EspGuid = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
$StateDir = Join-Path $env:ProgramData 'JStack'
$StatePath = Join-Path $StateDir 'state.json'
$LogPath = Join-Path $StateDir 'install.log'
$EspFolder = 'EFI\jstack'
# Only the small signed loaders go on the EFI partition (Windows makes it 100 MB). GRUB
# reads the signed kernel and the initramfs from /boot inside the JStack Btrfs root.
$BootFiles = @('shimx64.efi', 'mmx64.efi', 'grubx64.efi', 'grub.cfg')

# ---------------------------------------------------------------- helpers ---
function Say([string]$m, [string]$color = 'Gray') {
    Write-Host $m -ForegroundColor $color
    try { Add-Content -Path $LogPath -Value ("{0:u} {1}" -f (Get-Date), $m) } catch { }
}
function Step([string]$m) { Say ''; Say "==> $m" 'Cyan' }
function Fail([string]$m) { throw [System.InvalidOperationException]::new($m) }
function Exe([string]$file, [string[]]$argv) {
    # Windows PowerShell 5.1 turns native stderr into errors under 'Stop', so relax it here.
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $file @argv 2>&1 | Out-String } finally { $ErrorActionPreference = $old }
    if ($LASTEXITCODE -ne 0) { Fail "$file $($argv -join ' ') failed ($LASTEXITCODE): $out" }
    return $out
}

function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    if (-not $PSCommandPath) { Fail 'Run this from an administrator PowerShell window.' }
    Say 'Asking for administrator rights...'
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v) { $argv += "-$k" } }
        elseif ($v -is [securestring]) { Fail 'Pass -Password only from an administrator window.' }
        else { $argv += "-$k"; $argv += "`"$v`"" }
    }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argv
    exit 0
}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class JStackRaw {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa,
                                            uint disposition, uint flags, IntPtr template);
    // Raw handle to a partition device. FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH:
    // data is on the disk when Write returns. Callers use sector-aligned 4 MiB blocks.
    public static FileStream Open(string path, bool write) {
        uint access = write ? 0xC0000000u : 0x80000000u;      // GENERIC_READ (| GENERIC_WRITE)
        SafeFileHandle h = CreateFile(path, access, 3u, IntPtr.Zero, 3u, 0x20000000u | 0x80000000u, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException("open " + path + " failed, error " + Marshal.GetLastWin32Error());
        return new FileStream(h, write ? FileAccess.ReadWrite : FileAccess.Read, 4096, false);
    }
}
'@

function Get-FileSha256([string]$path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() }

function Get-IanaTimeZone {
    $map = @{
        'Pacific Standard Time' = 'America/Los_Angeles'; 'Mountain Standard Time' = 'America/Denver'
        'US Mountain Standard Time' = 'America/Phoenix'; 'Central Standard Time' = 'America/Chicago'
        'Eastern Standard Time' = 'America/New_York'; 'Alaskan Standard Time' = 'America/Anchorage'
        'Hawaiian Standard Time' = 'Pacific/Honolulu'; 'Atlantic Standard Time' = 'America/Halifax'
        'GMT Standard Time' = 'Europe/London'; 'W. Europe Standard Time' = 'Europe/Berlin'
        'Romance Standard Time' = 'Europe/Paris'; 'Central Europe Standard Time' = 'Europe/Budapest'
        'Central European Standard Time' = 'Europe/Warsaw'; 'E. Europe Standard Time' = 'Europe/Chisinau'
        'FLE Standard Time' = 'Europe/Kiev'; 'GTB Standard Time' = 'Europe/Bucharest'
        'Russian Standard Time' = 'Europe/Moscow'; 'India Standard Time' = 'Asia/Kolkata'
        'China Standard Time' = 'Asia/Shanghai'; 'Tokyo Standard Time' = 'Asia/Tokyo'
        'Korea Standard Time' = 'Asia/Seoul'; 'Singapore Standard Time' = 'Asia/Singapore'
        'Taipei Standard Time' = 'Asia/Taipei'; 'AUS Eastern Standard Time' = 'Australia/Sydney'
        'E. Australia Standard Time' = 'Australia/Brisbane'; 'W. Australia Standard Time' = 'Australia/Perth'
        'New Zealand Standard Time' = 'Pacific/Auckland'; 'SA Pacific Standard Time' = 'America/Bogota'
        'E. South America Standard Time' = 'America/Sao_Paulo'; 'Argentina Standard Time' = 'America/Argentina/Buenos_Aires'
        'Central Standard Time (Mexico)' = 'America/Mexico_City'; 'Israel Standard Time' = 'Asia/Jerusalem'
        'Arabian Standard Time' = 'Asia/Dubai'; 'South Africa Standard Time' = 'Africa/Johannesburg'
        'UTC' = 'UTC'
    }
    $id = (Get-TimeZone).Id
    if ($map.ContainsKey($id)) { return $map[$id] }
    return 'UTC'
}

function Get-WifiProfiles {
    # netsh export gives XML (not localized text), so parsing works in any Windows language.
    $tmp = Join-Path $env:TEMP ("jstack-wifi-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $list = @()
    try {
        & netsh.exe wlan export profile key=clear "folder=$tmp" 2>&1 | Out-Null
        foreach ($f in Get-ChildItem -LiteralPath $tmp -Filter *.xml) {
            try {
                [xml]$x = Get-Content -LiteralPath $f.FullName -Raw
                $ssid = $x.WLANProfile.SSIDConfig.SSID.name
                $auth = $x.WLANProfile.MSM.security.authEncryption.authentication
                $psk = $null
                if ($auth -match '^WPA2?PSK$|^WPA3SAE$') { $psk = $x.WLANProfile.MSM.security.sharedKey.keyMaterial }
                elseif ($auth -ne 'open') { continue }   # enterprise networks need manual setup
                if ($ssid) { $list += @{ ssid = [string]$ssid; psk = $psk } }
            } catch { }
        }
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    return , $list
}

function Get-Payload([string]$dest) {
    # Returns the manifest. Every file listed in it is present in $dest with a matching SHA256.
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $src = $PayloadDir
    function Fetch([string]$rel, [long]$bytes) {
        $out = Join-Path $dest ($rel -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
        if ($src) { Copy-Item -LiteralPath (Join-Path $src ($rel -replace '/', '\')) -Destination $out -Force; return }
        if ((Test-Path -LiteralPath $out) -and (Get-Item -LiteralPath $out).Length -eq $bytes) { return }
        $url = "$PayloadUrl/$(Split-Path $rel -Leaf)"
        $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
        Say ("    downloading {0} ({1:N0} MB)" -f $rel, ($bytes / 1MB))
        if (Test-Path $curl) {
            & $curl -fL --retry 5 --retry-delay 3 -C - -o $out $url
            if ($LASTEXITCODE -ne 0) { Fail "download failed: $url" }
        } else { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out }
    }
    Fetch 'manifest.json' 0
    if (-not $src) { Remove-Item (Join-Path $dest 'manifest.json'); Fetch 'manifest.json' 0 }
    $m = Get-Content -Raw -LiteralPath (Join-Path $dest 'manifest.json') | ConvertFrom-Json
    if ($m.schema -ne 1) { Fail "unsupported payload schema $($m.schema)" }
    foreach ($p in $m.files.PSObject.Properties) {
        Fetch $p.Name ([long]$p.Value.bytes)
        $got = Get-FileSha256 (Join-Path $dest ($p.Name -replace '/', '\'))
        if ($got -ne $p.Value.sha256) { Fail "checksum mismatch for $($p.Name). Delete $dest and try again." }
    }
    return $m
}

function Open-RootImageStream([string]$dir, $manifest) {
    # The image is gzip (Windows decompresses it without extra tools). Large payloads are
    # split into parts for GitHub's 2 GB release asset limit, concatenated here in order.
    $names = @($manifest.files.PSObject.Properties.Name | Where-Object { $_ -like 'jstack-root.img.gz*' } | Sort-Object)
    if (-not $names) { Fail 'payload has no jstack-root.img.gz' }
    $streams = @(foreach ($n in $names) { [System.IO.File]::OpenRead((Join-Path $dir $n)) })
    if ($streams.Count -eq 1) { $raw = $streams[0] } else {
        Add-Type -TypeDefinition @'
using System.IO;
public class JStackConcat : Stream {
    readonly Stream[] parts; int i;
    public JStackConcat(Stream[] p) { parts = p; }
    public override int Read(byte[] b, int o, int c) {
        while (i < parts.Length) { int n = parts[i].Read(b, o, c); if (n > 0) return n; parts[i++].Dispose(); }
        return 0;
    }
    public override bool CanRead { get { return true; } } public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } } public override long Length { get { throw new System.NotSupportedException(); } }
    public override long Position { get { throw new System.NotSupportedException(); } set { throw new System.NotSupportedException(); } }
    public override void Flush() { } public override long Seek(long a, SeekOrigin b) { throw new System.NotSupportedException(); }
    public override void SetLength(long a) { throw new System.NotSupportedException(); }
    public override void Write(byte[] b, int o, int c) { throw new System.NotSupportedException(); }
}
'@ -ErrorAction SilentlyContinue
        $raw = New-Object JStackConcat (, [System.IO.Stream[]]$streams)
    }
    return New-Object System.IO.Compression.GZipStream($raw, [System.IO.Compression.CompressionMode]::Decompress)
}

function Write-RootImage([string]$device, $src, [long]$expectBytes, [long]$partBytes) {
    $block = 4MB
    $buf = New-Object byte[] $block
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $dst = [JStackRaw]::Open($device, $true)
    [long]$done = 0
    $t0 = Get-Date
    try {
        while ($true) {
            $fill = 0
            while ($fill -lt $block) { $n = $src.Read($buf, $fill, $block - $fill); if ($n -le 0) { break }; $fill += $n }
            if ($fill -eq 0) { break }
            $len = [int]([math]::Ceiling($fill / 4096.0) * 4096)       # unbuffered I/O needs whole sectors
            if ($len -gt $fill) { [Array]::Clear($buf, $fill, $len - $fill) }
            if ($done + $len -gt $partBytes) { Fail 'image is larger than the new partition' }
            $null = $sha.TransformBlock($buf, 0, $len, $null, 0)
            $dst.Write($buf, 0, $len)
            $done += $len
            if (($done % 512MB) -eq 0) {
                $rate = $done / 1MB / [math]::Max(1, ((Get-Date) - $t0).TotalSeconds)
                Say ("    {0:N1} / {1:N1} GB  ({2:N0} MB/s)" -f ($done / 1GB), ($expectBytes / 1GB), $rate)
            }
            if ($fill -lt $block) { break }
        }
        $dst.Flush()
    } finally { $dst.Dispose(); $src.Dispose() }
    $null = $sha.TransformFinalBlock($buf, 0, 0)
    if ($done -lt $expectBytes) { Fail "image ended early ($done of $expectBytes bytes)" }
    return @{ bytes = $done; sha256 = [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant() }
}

function Test-RootImage([string]$device, [long]$bytes, [string]$expect) {
    $block = 4MB
    $buf = New-Object byte[] $block
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $s = [JStackRaw]::Open($device, $false)
    try {
        [long]$left = $bytes
        while ($left -gt 0) {
            $want = [int][math]::Min([long]$block, $left)
            $got = 0
            while ($got -lt $want) { $n = $s.Read($buf, $got, $want - $got); if ($n -le 0) { Fail 'short read while verifying' }; $got += $n }
            $null = $sha.TransformBlock($buf, 0, $want, $null, 0)
            $left -= $want
        }
    } finally { $s.Dispose() }
    $null = $sha.TransformFinalBlock($buf, 0, 0)
    $h = [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
    if ($h -ne $expect) { Fail 'verification failed: data read back from the disk does not match what was written' }
}

function Mount-Esp {
    foreach ($l in 'S', 'T', 'U', 'V', 'W', 'Y', 'Z') {
        if (-not (Test-Path "${l}:\")) {
            & mountvol.exe "${l}:" /S | Out-Null
            if ($LASTEXITCODE -eq 0 -and (Test-Path "${l}:\EFI")) { return "${l}:" }
        }
    }
    Fail 'could not mount the EFI system partition (mountvol /S)'
}
function Dismount-Esp([string]$d) { if ($d) { & mountvol.exe $d /D | Out-Null } }

function Save-State($s) {
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    ($s | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

# ------------------------------------------------------------------ main ---
Assert-Admin
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
Say "Jstack OS installer for Windows  (log: $LogPath)" 'White'
if (Test-Path $StatePath) {
    Fail "JStack already looks installed ($StatePath). Run Uninstall-JStack.ps1 first to reinstall."
}

Step 'Checking this PC'
if (-not [Environment]::Is64BitOperatingSystem) { Fail 'JStack needs 64-bit Windows.' }
$fw = $env:firmware_type
if (-not $fw) { $fw = if ((Exe bcdedit.exe @('/enum', '{current}')) -match '\\winload\.efi') { 'UEFI' } else { 'Legacy' } }
if ($fw -ne 'UEFI') { Fail 'This PC boots Windows in legacy BIOS mode. JStack needs UEFI.' }
$sb = $false
try { $sb = Confirm-SecureBootUEFI } catch { }
Say ("    UEFI: yes   Secure Boot: {0}" -f $(if ($sb) { 'on (stays on)' } else { 'off' }))

$cPart = Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':'))
$disk = Get-Disk -Number $cPart.DiskNumber
if ($disk.PartitionStyle -ne 'GPT') { Fail 'The Windows disk is not GPT.' }
$esp = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.GptType -eq $EspGuid } | Select-Object -First 1
if (-not $esp) {
    $esp = Get-Partition | Where-Object { $_.GptType -eq $EspGuid } | Select-Object -First 1
    if (-not $esp) { Fail 'No EFI system partition found.' }
}
Say ("    Windows disk: #{0} {1} ({2:N0} GB, {3})" -f $disk.Number, $disk.FriendlyName, ($disk.Size / 1GB), $disk.BusType)

$bl = $null
try { $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { }
$bitlocker = [bool]($bl -and $bl.ProtectionStatus -eq 'On')
$encrypting = [bool]($bl -and $bl.VolumeStatus -match 'Progress')
if ($encrypting) { Fail "BitLocker is still encrypting or decrypting C: ($($bl.EncryptionPercentage)%). Try again when it finishes." }
Say ("    BitLocker on C: {0}" -f $(if ($bitlocker) { 'on (will be paused for 2 restarts, then resumes by itself)' } else { 'off' }))
if ($bitlocker) {
    $rp = @($bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
    if (-not $rp) { Say '    Warning: C: has no BitLocker recovery password. Consider adding one first.' 'Yellow' }
}

$sizes = Get-PartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber $cPart.PartitionNumber
$freeBytes = (Get-Volume -DriveLetter $cPart.DriveLetter).SizeRemaining
$shrinkable = $cPart.Size - $sizes.SizeMin
$payloadBytes = 8GB          # downloaded payload on C: (deleted after install)
$keepFree = 20GB             # left free for Windows after the shrink
$maxGB = [math]::Floor([math]::Min($shrinkable, $freeBytes - $payloadBytes - $keepFree) / 1GB)
if ($SizeGB -eq 0) { $SizeGB = [int][math]::Min(64, $maxGB) }
Say ("    C: free {0:N0} GB, can give JStack up to {1} GB" -f ($freeBytes / 1GB), $maxGB)
if ($maxGB -lt $MinGB) {
    Fail ("Not enough room: JStack needs {0} GB and Windows must keep 20 GB free. Free up space on C: (or run 'defrag C: /X' to move files that block shrinking)." -f $MinGB)
}
if ($SizeGB -lt $MinGB -or $SizeGB -gt $maxGB) { Fail "-SizeGB must be between $MinGB and $maxGB." }

Step 'Your JStack account'
if (-not $Username) {
    $def = ($env:USERNAME.ToLowerInvariant() -replace '[^a-z0-9_-]', '')
    if ($def -notmatch '^[a-z_]') { $def = 'jstack' }
    $Username = Read-Host "    Username [$def]"
    if (-not $Username) { $Username = $def }
}
if ($Username -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or $Username -in @('root', 'bin', 'daemon', 'nobody')) {
    Fail "Invalid username '$Username' (lowercase letters, digits, - and _)."
}
if ($Hostname -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { Fail "Invalid hostname '$Hostname'." }
$plain = ''
if (-not $NoPassword) {
    if (-not $Password) {
        while ($true) {
            $a = Read-Host '    Password (empty = no password)' -AsSecureString
            $b = Read-Host '    Password again' -AsSecureString
            $pa = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
            $pb = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
            if ($pa -ceq $pb) { $plain = $pa; break }
            Say '    Passwords do not match.' 'Yellow'
        }
    } else {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    }
}
if (-not $FullName) { $FullName = $Username }
$wifi = @()
if (-not $NoWifi) { $wifi = Get-WifiProfiles }
$tz = Get-IanaTimeZone
if ($DefaultOS -eq 'auto') { $DefaultOS = if ($bitlocker) { 'windows' } else { 'jstack' } }

Step 'Plan'
Say ("    Shrink C: by {0} GB and put Jstack OS there (disk #{1})" -f $SizeGB, $disk.Number)
Say "    Boot files go to \EFI\jstack on the EFI partition. Windows boot files are not touched."
Say ("    Account '{0}', hostname '{1}', time zone {2}, {3} Wi-Fi network(s) copied" -f $Username, $Hostname, $tz, $wifi.Count)
Say ("    Starts by default: {0}. The other one is in the boot menu{1}." -f $DefaultOS, $(if ($DefaultOS -eq 'windows') { ' and via the "Restart into JStack" shortcut' } else { '' }))
if ($bitlocker -and $DefaultOS -eq 'jstack') {
    Say '    Warning: with BitLocker on, picking Windows from the JStack menu asks for the recovery key. Use "Restart into Windows" in JStack instead.' 'Yellow'
}
if ($DryRun) { Say ''; Say 'Dry run: all checks passed, nothing changed.' 'Green'; exit 0 }
if (-not $Yes) {
    $ok = Read-Host '    Type YES to install'
    if ($ok -cne 'YES') { Say 'Cancelled. Nothing changed.'; exit 1 }
}

$work = Join-Path $env:SystemDrive 'JStackInstall'
Step 'Getting the JStack payload'
$manifest = Get-Payload $work
$imgBytes = [long]$manifest.root_image_bytes
if ($imgBytes -gt ($SizeGB * 1GB)) { Fail "payload needs $([math]::Ceiling($imgBytes / 1GB)) GB, more than -SizeGB $SizeGB" }
foreach ($f in $BootFiles) { if (-not (Test-Path (Join-Path $work "boot\$f"))) { Fail "payload is missing boot\$f" } }

$state = [ordered]@{ schema = 1; version = $manifest.source_iso; root_uuid = $manifest.root_uuid
    disk = $disk.Number; disk_id = $disk.UniqueId; c_partition = $cPart.PartitionNumber; c_size_before = $cPart.Size
    partition = $null; partition_guid = $null; fw_entry = $null; esp_folder = $EspFolder; default = $DefaultOS
    installed = (Get-Date).ToString('o') }
$newPart = $null; $espDrive = $null
try {
    Step "Shrinking C: by $SizeGB GB"
    Save-State $state                                   # lets Uninstall-JStack undo a half install
    Resize-Partition -DiskNumber $disk.Number -PartitionNumber $cPart.PartitionNumber -Size ($cPart.Size - [long]$SizeGB * 1GB)
    $newPart = New-Partition -DiskNumber $disk.Number -UseMaximumSize -GptType $LinuxGuid
    $state.partition = $newPart.PartitionNumber; $state.partition_guid = $newPart.Guid
    Save-State $state
    Say ("    new partition #{0}, {1:N1} GB" -f $newPart.PartitionNumber, ($newPart.Size / 1GB))
    if ($newPart.Size -lt $imgBytes) { Fail 'new partition is smaller than the image' }

    Step 'Writing Jstack OS to the new partition'
    $device = "\\?\GLOBALROOT\Device\Harddisk$($disk.Number)\Partition$($newPart.PartitionNumber)"
    $w = Write-RootImage $device (Open-RootImageStream $work $manifest) $imgBytes $newPart.Size
    Say '    verifying...'
    Test-RootImage $device $w.bytes $w.sha256
    Say '    written and verified' 'Green'

    Step 'Installing boot files (Secure Boot signed chain)'
    $espDrive = Mount-Esp
    $dst = Join-Path $espDrive $EspFolder
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    $needed = 0; foreach ($f in $BootFiles) { $needed += (Get-Item (Join-Path $work "boot\$f")).Length }
    $espFree = (Get-PSDrive $espDrive.TrimEnd(':')).Free
    if ($espFree -and $espFree -lt $needed + 1MB) {
        Fail ("The EFI partition has only {0:N0} MB free, JStack boot files need {1:N0} MB." -f ($espFree / 1MB), ($needed / 1MB))
    }
    foreach ($f in $BootFiles) { Copy-Item -LiteralPath (Join-Path $work "boot\$f") -Destination (Join-Path $dst $f) -Force }
    foreach ($f in $BootFiles) {
        if ((Get-FileSha256 (Join-Path $dst $f)) -ne $manifest.files."boot/$f".sha256) { Fail "copy of $f to the EFI partition is corrupt" }
    }
    $answers = [ordered]@{ username = $Username; fullname = $FullName; password = $plain; hostname = $Hostname
        timezone = $tz; wifi = $wifi; default_os = $DefaultOS }
    $json = $answers | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText((Join-Path $dst 'firstboot.json'), $json, (New-Object Text.UTF8Encoding($false)))
    $plain = $null; $answers = $null; $json = $null

    Step 'Adding the boot entry'
    if ($bitlocker) {
        Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 2 | Out-Null
        Say '    BitLocker paused for 2 restarts'
    }
    $out = Exe bcdedit.exe @('/copy', '{bootmgr}', '/d', 'Jstack OS')
    if ($out -notmatch '\{[0-9a-fA-F-]{36}\}') { Fail "bcdedit /copy gave no id: $out" }
    $id = $Matches[0]
    $state.fw_entry = $id; Save-State $state
    Exe bcdedit.exe @('/set', $id, 'path', '\EFI\jstack\shimx64.efi') | Out-Null
    if ($DefaultOS -eq 'jstack') { Exe bcdedit.exe @('/set', '{fwbootmgr}', 'displayorder', $id, '/addfirst') | Out-Null }
    else { Exe bcdedit.exe @('/set', '{fwbootmgr}', 'displayorder', $id, '/addlast') | Out-Null }
    Exe bcdedit.exe @('/set', '{fwbootmgr}', 'bootsequence', $id) | Out-Null   # next restart: JStack (once)

    # "Restart into JStack" for Windows: one-shot firmware BootNext, so the TPM sees a normal
    # firmware boot of each OS and BitLocker never needs the recovery key.
    $restart = Join-Path $StateDir 'Restart-Into-JStack.ps1'
    @"
`$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not `$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "$restart"'; exit }
if ((Get-BitLockerVolume -MountPoint `$env:SystemDrive -ErrorAction SilentlyContinue).ProtectionStatus -eq 'On') {
  Suspend-BitLocker -MountPoint `$env:SystemDrive -RebootCount 1 | Out-Null }
bcdedit.exe /set '{fwbootmgr}' bootsequence '$id' | Out-Null
shutdown.exe /r /t 0
"@ | Set-Content -LiteralPath $restart -Encoding UTF8
    $lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Restart into JStack.lnk'
    $sh = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $sh.TargetPath = 'powershell.exe'
    $sh.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$restart`""
    $sh.IconLocation = 'shell32.dll,27'
    $sh.Save()
    $state.shortcut = $lnk
    Save-State $state
} catch {
    $err = $_
    Say ''
    Say "Install failed: $($err.Exception.Message)" 'Red'
    Say 'Undoing changes...' 'Yellow'
    try {
        if ($state.fw_entry) { & bcdedit.exe /delete $state.fw_entry /f | Out-Null }
        if ($espDrive) { Remove-Item -LiteralPath (Join-Path $espDrive $EspFolder) -Recurse -Force -ErrorAction SilentlyContinue }
        if ($newPart) { Remove-Partition -DiskNumber $disk.Number -PartitionNumber $newPart.PartitionNumber -Confirm:$false }
        $max = (Get-PartitionSupportedSize -DiskNumber $disk.Number -PartitionNumber $cPart.PartitionNumber).SizeMax
        if ($max -gt (Get-Partition -DiskNumber $disk.Number -PartitionNumber $cPart.PartitionNumber).Size) {
            Resize-Partition -DiskNumber $disk.Number -PartitionNumber $cPart.PartitionNumber -Size $max
        }
        if ($bitlocker) { Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null }
        Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
        Say 'Undone. Windows is as it was.' 'Yellow'
    } catch { Say "Could not fully undo: $($_.Exception.Message). Run Uninstall-JStack.ps1." 'Red' }
    throw $err
} finally {
    Dismount-Esp $espDrive
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Step 'Done'
Say 'Jstack OS is installed. The PC will restart into it now (first start takes about a minute).' 'Green'
Say 'To get back to Windows: pick "Windows" in the menu at startup, or "Restart into Windows" in JStack.'
Say 'To remove JStack later: run Uninstall-JStack.ps1 in Windows.'
if (-not $NoReboot) {
    if (-not $Yes) { Read-Host '    Press Enter to restart' | Out-Null }
    Restart-Computer -Force
}
