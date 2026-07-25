#!/usr/bin/env python3
"""Statically bound the PH-08 Windows mutation surface.

The mutation adapters are the only place the installer changes a real Windows
machine, so their whole command surface must be enumerable and reviewable. This
validator enforces, without running any mutation:

* every command the adapters invoke is on an explicit allowlist,
* every allowlisted mutation cmdlet is module-qualified, so PATH or a hijacked
  function cannot substitute a different implementation,
* the forbidden primitives (diskpart, bcdedit, format, clear-disk, shells,
  dynamic invocation) never appear,
* the disposable-VM gate and the capability check run before dispatch,
* the firmware surface is limited to BootNext in the Rust adapter, and nothing
  writes BootOrder or a Secure Boot key.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = ROOT / "assets" / "windows-mutation-adapters.ps1"
FIRMWARE = ROOT / "src" / "windows_firmware.rs"
FIRMWARE_BIN = ROOT / "src" / "bin" / "jstack-firmware.rs"

# Every command the adapters may name. Mutation cmdlets must additionally appear
# in REQUIRED_QUALIFIED below.
ALLOWED_COMMANDS = {
    # Local helpers defined in the adapter file itself.
    "Assert-JStackCapability",
    "Assert-JStackDisposableVm",
    "Get-JStackPartitionObservation",
    "Invoke-JStackCreatePartition",
    "Invoke-JStackExpandWindows",
    "Invoke-JStackRegisterFinalizer",
    "Invoke-JStackRestoreBitLocker",
    "Invoke-JStackShrinkWindows",
    "Invoke-JStackSuspendBitLocker",
    "Invoke-JStackUnregisterFinalizer",
    "Read-JStackRequest",
    "Resolve-JStackDisk",
    "Resolve-JStackPartition",
    # Read-only observation.
    "Get-BitLockerVolume",
    "Get-Disk",
    "Get-Partition",
    "Get-PartitionSupportedSize",
    "Get-ScheduledTask",
    # The complete mutation surface.
    "New-Partition",
    "Register-ScheduledTask",
    "Resize-Partition",
    "Resume-BitLocker",
    "Suspend-BitLocker",
    "Unregister-ScheduledTask",
    # Scheduled-task construction (creates in-memory objects only).
    "New-ScheduledTaskAction",
    "New-ScheduledTaskPrincipal",
    "New-ScheduledTaskTrigger",
    # Utility.
    "ConvertFrom-Json",
    "ConvertTo-Json",
    "Out-Null",
    "Where-Object",
}

# The exact module-qualified spelling required for each mutation and observation
# cmdlet. An unqualified call would be resolvable through PSModulePath.
REQUIRED_QUALIFIED = {
    r"Storage\Get-Disk",
    r"Storage\Get-Partition",
    r"Storage\Get-PartitionSupportedSize",
    r"Storage\New-Partition",
    r"Storage\Resize-Partition",
    r"BitLocker\Get-BitLockerVolume",
    r"BitLocker\Suspend-BitLocker",
    r"BitLocker\Resume-BitLocker",
    r"ScheduledTasks\Get-ScheduledTask",
    r"ScheduledTasks\Register-ScheduledTask",
    r"ScheduledTasks\Unregister-ScheduledTask",
    r"Microsoft.PowerShell.Utility\ConvertFrom-Json",
    r"Microsoft.PowerShell.Utility\ConvertTo-Json",
    r"Microsoft.PowerShell.Core\Where-Object",
}

# Cmdlets that must never appear anywhere in the adapters. These are either
# destructive beyond the installer's contract or bypass the state graph.
FORBIDDEN_TEXT = {
    "bcdedit",
    "clear-disk",
    "cmd.exe",
    "disable-bitlocker",
    "diskpart",
    "dismount-diskimage",
    "enable-bitlocker",
    "format-securebootuefi",
    "format-volume",
    "initialize-disk",
    "invoke-expression",
    "manage-bde",
    "mount-diskimage",
    "mountvol",
    "optimize-volume",
    "reagentc",
    "remove-item",
    "remove-partition",
    "repair-volume",
    "restart-computer",
    "set-bitlockervolume",
    "set-ciminstance",
    "set-disk",
    "set-securebootuefi",
    "set-volume",
    "shutdown.exe",
    "start-job",
    "start-process",
    "stop-computer",
    "wmic",
}

# The adapters must gate themselves before dispatching anything.
REQUIRED_GATES = (
    "Assert-JStackDisposableVm",
    "JSTACK_DISPOSABLE_VM",
    "JSTACK_DISPOSABLE_VM_EXPECTED",
    "Assert-JStackCapability -Action $Action -Request $request",
)

# Each dispatched action must be a real graph action id.
GRAPH_ACTIONS = {
    "shrink_windows_ntfs",
    "expand_windows_ntfs",
    "create_xbootldr_partition",
    "create_root_partition",
    "suspend_bitlocker",
    "restore_bitlocker",
    "register_windows_finalizer",
    "unregister_windows_finalizer",
}

COMMAND_PATTERN = re.compile(r"\b([A-Z][A-Za-z]*-[A-Z][A-Za-z]+)\b")


def strip_powershell_comments(source: str) -> str:
    """Remove comment lines so prose cannot trip the code checks.

    The adapters document *why* forbidden primitives are excluded, so the
    forbidden-text scan must look only at executable lines.
    """
    lines = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Trailing comments: a '#' outside a quoted string starts a comment.
        in_single = False
        in_double = False
        for index, character in enumerate(line):
            if character == "'" and not in_double:
                in_single = not in_single
            elif character == '"' and not in_single:
                in_double = not in_double
            elif character == "#" and not in_single and not in_double:
                line = line[:index]
                break
        lines.append(line)
    return "\n".join(lines)


def strip_rust_comments(source: str) -> str:
    """Remove Rust line comments, including doc comments."""
    lines = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)


def check_adapters(source: str) -> list[str]:
    errors: list[str] = []
    code = strip_powershell_comments(source)

    commands = set(COMMAND_PATTERN.findall(code))
    unexpected = sorted(commands - ALLOWED_COMMANDS)
    if unexpected:
        errors.append(f"adapters use non-allowlisted commands: {', '.join(unexpected)}")

    forbidden = sorted(term for term in FORBIDDEN_TEXT if term in code.lower())
    if forbidden:
        errors.append(f"adapters contain forbidden primitives: {', '.join(forbidden)}")

    missing = sorted(item for item in REQUIRED_QUALIFIED if item not in source)
    if missing:
        errors.append(f"adapters call unqualified cmdlets; missing: {', '.join(missing)}")

    for gate in REQUIRED_GATES:
        if gate not in source:
            errors.append(f"adapters are missing the required gate: {gate}")

    # The gate must run before the dispatch switch, or an action could mutate
    # before being authorized.
    gate_index = source.find("Assert-JStackDisposableVm\n")
    dispatch_index = source.find("$result = switch ($Action)")
    if gate_index < 0 or dispatch_index < 0 or gate_index > dispatch_index:
        errors.append("the disposable-VM gate must run before action dispatch")

    dispatched = set(re.findall(r"^\s*'([a-z_]+)' \{", source, re.MULTILINE))
    unknown = sorted(dispatched - GRAPH_ACTIONS)
    if unknown:
        errors.append(f"adapters dispatch non-graph actions: {', '.join(unknown)}")
    uncovered = sorted(GRAPH_ACTIONS - dispatched)
    if uncovered:
        errors.append(f"adapters do not dispatch graph actions: {', '.join(uncovered)}")

    if "SilentlyContinue" in source:
        # One exception: probing for an absent scheduled task legitimately uses
        # SilentlyContinue, because "not present" is the expected answer. Every
        # other use would suppress a real observation error.
        allowed = source.count("Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue")
        if source.count("SilentlyContinue") != allowed:
            errors.append("adapters may only use SilentlyContinue when probing for an absent task")

    if re.search(r"(?m)^\s*\.\s+", code):
        errors.append("adapters may not dot-source external code")
    if "Invoke-Expression" in code or "iex " in code:
        errors.append("adapters may not use dynamic invocation")
    if "System.Diagnostics" in code:
        errors.append("adapters may not use direct process-launch classes")
    if r"C:\Windows" in code:
        errors.append("adapters may not assume a fixed Windows directory")

    # Positional disk numbers must never come from the request; identity is by
    # GPT GUID only.
    if "$Request.disk_number" in source or "$request.disk_number" in source:
        errors.append("adapters may not accept a positional disk number from the request")

    return errors


def check_firmware(module: str, binary: str) -> list[str]:
    errors: list[str] = []
    module_code = strip_rust_comments(module)
    binary_code = strip_rust_comments(binary)

    # BootNext is the only writable firmware variable, and that decision must be
    # expressed once, in the pure module.
    # `is_writable` must be exactly the single BootNext equality and nothing
    # more, so no variable can be added to the write surface without editing
    # this validator too.
    writable = re.search(
        r"pub fn is_writable\(name: &str\) -> bool \{(.*?)\n\}", module_code, re.DOTALL
    )
    if not writable:
        errors.append("the firmware module must define is_writable")
    else:
        body = " ".join(writable.group(1).split())
        if body != 'name == "BootNext"':
            errors.append(
                f"is_writable must be exactly 'name == \"BootNext\"', found: {body}"
            )

    if "FirmwareMutationCapability" not in module_code:
        errors.append("the firmware module must gate mutation behind a capability")
    if "from_disposable_vm_attestation" not in module_code:
        errors.append("the firmware capability must require a disposable-VM attestation")

    # The pure module must contain no unsafe code; the binary is the only
    # unsafe boundary.
    if "unsafe" in module_code:
        errors.append("the pure firmware module must contain no unsafe code")

    # The binary must only reference the two documented firmware APIs.
    api_calls = set(re.findall(r"\b(\w*FirmwareEnvironmentVariable\w*)\b", binary_code))
    allowed_api = {
        "GetFirmwareEnvironmentVariableExW",
        "SetFirmwareEnvironmentVariableExW",
    }
    unexpected_api = sorted(api_calls - allowed_api)
    if unexpected_api:
        errors.append(f"the firmware binary uses unexpected APIs: {', '.join(unexpected_api)}")

    # `std::process::ExitCode` is a return type, not process creation, so the
    # check targets the actual spawn APIs.
    for term in ("bcdedit", "diskpart", "Command::new", "std::process::Command"):
        if term in binary_code:
            errors.append(f"the firmware binary may not use {term}")

    if "JSTACK_DISPOSABLE_VM" not in binary_code:
        errors.append("the firmware binary must require a disposable-VM attestation")

    # Every unsafe block must carry a SAFETY comment.
    unsafe_blocks = binary_code.count("unsafe {")
    safety_comments = binary.count("// SAFETY:")
    if unsafe_blocks == 0:
        errors.append("the firmware binary should contain the live unsafe calls")
    if safety_comments < unsafe_blocks:
        errors.append(
            f"every unsafe block needs a SAFETY comment: {unsafe_blocks} blocks, "
            f"{safety_comments} comments"
        )

    return errors


def check_powershell_ast(errors: list[str]) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        errors.append("PowerShell is required for adapter AST validation")
        return

    parser = (
        "$tokens=$null; $errors=$null; "
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$env:JSTACK_ADAPTERS,[ref]$tokens,[ref]$errors); "
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
        env={**os.environ, "JSTACK_ADAPTERS": str(ADAPTERS)},
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        errors.append(f"PowerShell parser rejected the adapters: {result.stderr.strip()}")
        return

    try:
        parsed = json.loads(result.stdout)
        ast_commands = {parsed} if isinstance(parsed, str) else set(parsed)
    except (json.JSONDecodeError, TypeError) as error:
        errors.append(f"could not decode the adapter command AST: {error}")
        return

    if "<dynamic>" in ast_commands:
        errors.append("adapters may not invoke a dynamically named command")

    basenames = {command.rsplit("\\", 1)[-1] for command in ast_commands}
    unexpected = sorted(basenames - ALLOWED_COMMANDS)
    if unexpected:
        errors.append(f"adapter AST uses non-allowlisted commands: {', '.join(unexpected)}")

    # Every mutation cmdlet observed in the AST must be module-qualified.
    mutations = {
        "New-Partition",
        "Resize-Partition",
        "Suspend-BitLocker",
        "Resume-BitLocker",
        "Register-ScheduledTask",
        "Unregister-ScheduledTask",
    }
    for command in ast_commands:
        base = command.rsplit("\\", 1)[-1]
        if base in mutations and "\\" not in command:
            errors.append(f"mutation cmdlet {base} must be module-qualified")


def main() -> int:
    errors: list[str] = []
    errors.extend(check_adapters(ADAPTERS.read_text(encoding="utf-8")))
    errors.extend(
        check_firmware(
            FIRMWARE.read_text(encoding="utf-8"),
            FIRMWARE_BIN.read_text(encoding="utf-8"),
        )
    )
    check_powershell_ast(errors)

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("windows mutation adapter surface is bounded and gated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
