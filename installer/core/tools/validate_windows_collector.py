#!/usr/bin/env python3
"""Statically enforce the allowlist for the embedded Windows collector."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "assets" / "collect-windows-inventory.ps1"
LAUNCHER = ROOT / "src" / "bin" / "jstack-inventory.rs"
COMMAND_PATTERN = re.compile(r"\b([A-Z][A-Za-z]+-[A-Z][A-Za-z]+)\b")
ALLOWED_COMMANDS = {
    "Confirm-SecureBootUEFI",
    "Convert-VolumeObservation",
    "ConvertTo-Json",
    "ForEach-Object",
    "Get-BitLockerVolume",
    "Get-CimInstance",
    "Get-Disk",
    "Get-ItemProperty",
    "Get-Partition",
    "Get-PartitionSupportedSize",
    "Get-Volume",
    "Get-JStackBattery",
    "Get-JStackBitLockerVolume",
    "Get-JStackDisk",
    "Get-JStackPartition",
    "Get-JStackPartitionSupportedSize",
    "Get-JStackRegistryValue",
    "Get-JStackSecureBoot",
    "Get-JStackVolume",
    "Import-Module",
    "Measure-Object",
    "Sort-Object",
    "Test-Path",
    "Test-JStackPath",
    "Where-Object",
}
FORBIDDEN_TEXT = {
    "add-partitionaccesspath",
    "bcdedit",
    "clear-disk",
    "disable-bitlocker",
    "diskpart",
    "dismount-diskimage",
    "enable-bitlocker",
    "format-securebootuefi",
    "format-volume",
    "initialize-disk",
    "invoke-cimmethod",
    "invoke-expression",
    "manage-bde",
    "mount-diskimage",
    "mountvol",
    "new-partition",
    "optimize-volume",
    "reagentc",
    "remove-partition",
    "repair-volume",
    "resize-partition",
    "restart-computer",
    "resume-bitlocker",
    "set-bitlockervolume",
    "set-ciminstance",
    "set-disk",
    "set-partition",
    "set-securebootuefi",
    "set-volume",
    "shutdown.exe",
    "start-job",
    "start-process",
    "suspend-bitlocker",
}


def main() -> int:
    source = COLLECTOR.read_text(encoding="utf-8")
    launcher = LAUNCHER.read_text(encoding="utf-8")
    commands = set(COMMAND_PATTERN.findall(source))
    unexpected = sorted(commands - ALLOWED_COMMANDS)
    forbidden = sorted(term for term in FORBIDDEN_TEXT if term in source.lower())
    errors: list[str] = []
    if unexpected:
        errors.append(f"collector uses non-allowlisted commands: {', '.join(unexpected)}")
    if forbidden:
        errors.append(f"collector contains mutation-capable primitives: {', '.join(forbidden)}")
    if "System.IO" in source or "Microsoft.Win32" in source:
        errors.append("collector may not use direct filesystem or registry mutation classes")
    if "&" in source or "`" in source:
        errors.append("collector may not use dynamic invocation or PowerShell escape syntax")
    if re.search(
        r"(?im)^\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|iex)(?:\s|$)",
        source,
    ):
        errors.append("collector may not launch a shell or use an expression alias")

    required_launcher_provenance = {
        "GetSystemDirectoryW",
        'Command::new(&powershell)',
        '.env("JSTACK_WINDOWS_MODULE_ROOT", &module_root)',
        '.env("JSTACK_SYSTEM_DRIVE", &system_drive)',
    }
    missing_launcher_provenance = sorted(
        item for item in required_launcher_provenance if item not in launcher
    )
    if missing_launcher_provenance:
        errors.append(
            "launcher is missing native Windows path provenance: "
            + ", ".join(missing_launcher_provenance)
        )
    if 'Command::new("powershell.exe")' in launcher:
        errors.append("launcher may not resolve powershell.exe through PATH")
    if r"C:\Windows" in launcher or r"C:\Windows" in source:
        errors.append("launcher and collector may not assume a fixed Windows directory")

    required_provenance = {
        r"$moduleRoot = [string]$env:JSTACK_WINDOWS_MODULE_ROOT",
        r"$env:PSModulePath = $moduleRoot",
        r"$env:JSTACK_SYSTEM_DRIVE",
        r"\Storage\Storage.psd1",
        r"\BitLocker\BitLocker.psd1",
        r"\SecureBoot\SecureBoot.psd1",
        r"\CimCmdlets\CimCmdlets.psd1",
        r"\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1",
        r"\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1",
        r"Storage\Get-Disk",
        r"Storage\Get-Partition",
        r"Storage\Get-Volume",
        r"Storage\Get-PartitionSupportedSize",
        r"BitLocker\Get-BitLockerVolume",
        r"SecureBoot\Confirm-SecureBootUEFI",
        r"CimCmdlets\Get-CimInstance",
        r"Microsoft.PowerShell.Management\Get-ItemProperty",
        r"Microsoft.PowerShell.Management\Test-Path",
        r"Microsoft.PowerShell.Utility\Measure-Object",
        r"Microsoft.PowerShell.Utility\Sort-Object",
        r"Microsoft.PowerShell.Utility\ConvertTo-Json",
        r"Microsoft.PowerShell.Core\ForEach-Object",
        r"Microsoft.PowerShell.Core\Where-Object",
    }
    missing_provenance = sorted(item for item in required_provenance if item not in source)
    if missing_provenance:
        errors.append(
            "collector is missing trusted module provenance: "
            + ", ".join(missing_provenance)
        )
    if "SilentlyContinue" in source:
        errors.append("collector may not suppress observation errors")
    if re.search(r"(?m)^\s*\.\s+", source):
        errors.append("collector may not dot-source external code")
    if "System.Diagnostics" in source:
        errors.append("collector may not use direct process-launch classes")

    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if powershell:
        parser = (
            "$tokens=$null; $errors=$null; "
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            "$env:JSTACK_COLLECTOR,[ref]$tokens,[ref]$errors); "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { "
            "[Console]::Error.WriteLine($_.Message) }; exit 1 }; "
            "$ast.FindAll({param($node) $node -is "
            "[System.Management.Automation.Language.CommandAst]},$true) | "
            "ForEach-Object { $name=$_.GetCommandName(); "
            "if ($null -eq $name) { '<dynamic>' } else { $name } } | "
            "Sort-Object -Unique | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser],
            env={**__import__("os").environ, "JSTACK_COLLECTOR": str(COLLECTOR)},
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"PowerShell parser rejected collector: {result.stderr.strip()}")
        else:
            try:
                parsed = json.loads(result.stdout)
                ast_commands = {parsed} if isinstance(parsed, str) else set(parsed)
            except (json.JSONDecodeError, TypeError) as error:
                errors.append(f"could not decode PowerShell command AST: {error}")
            else:
                ast_basenames = {command.rsplit("\\", 1)[-1] for command in ast_commands}
                unexpected_ast = sorted(ast_basenames - ALLOWED_COMMANDS)
                if unexpected_ast:
                    errors.append(
                        "collector AST uses non-allowlisted commands: "
                        + ", ".join(unexpected_ast)
                    )
                required_qualified_commands = {
                    r"BitLocker\Get-BitLockerVolume",
                    r"CimCmdlets\Get-CimInstance",
                    r"Microsoft.PowerShell.Core\ForEach-Object",
                    r"Microsoft.PowerShell.Core\Import-Module",
                    r"Microsoft.PowerShell.Core\Where-Object",
                    r"Microsoft.PowerShell.Management\Get-ItemProperty",
                    r"Microsoft.PowerShell.Management\Test-Path",
                    r"Microsoft.PowerShell.Utility\ConvertTo-Json",
                    r"Microsoft.PowerShell.Utility\Measure-Object",
                    r"Microsoft.PowerShell.Utility\Sort-Object",
                    r"SecureBoot\Confirm-SecureBootUEFI",
                    r"Storage\Get-Disk",
                    r"Storage\Get-Partition",
                    r"Storage\Get-PartitionSupportedSize",
                    r"Storage\Get-Volume",
                }
                missing_qualified = sorted(required_qualified_commands - ast_commands)
                if missing_qualified:
                    errors.append(
                        "collector AST is missing module-qualified commands: "
                        + ", ".join(missing_qualified)
                    )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"validated read-only collector allowlist: {len(commands)} commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
