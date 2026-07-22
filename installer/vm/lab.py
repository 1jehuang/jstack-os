#!/usr/bin/env python3
"""Safe, file-only host checks for the disposable Windows VM laboratory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_LAB_NAME = "jstack-windows-vm"
OVMF_CODE = Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd")
OVMF_SECURE_CODE = Path("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd")
OVMF_VARS = Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")
# The pinned profiles allocate 4 GiB to one VM. Keep at least 2 GiB available
# for the host and never run more than one profile VM concurrently.
MIN_AVAILABLE_MEMORY_BYTES = 6 * 1024**3
MIN_AVAILABLE_DISK_BYTES = 20 * 1024**3
SYSTEM_PATH = "/usr/bin:/bin"
FINDMNT = "/usr/bin/findmnt"


class LabSafetyError(RuntimeError):
    """Raised when the VM lab could reach something outside its file sandbox."""


def open_directory_nofollow(path: Path, *, create: bool = False) -> int:
    """Open an absolute directory path one component at a time without symlinks."""
    absolute = Path(os.path.abspath(path.expanduser()))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags | nofollow, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, flags | nofollow, dir_fd=descriptor)
            metadata = os.fstat(child)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                raise LabSafetyError(f"path component is not a directory: {absolute}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_regular_nofollow(path: Path, *, writable: bool = False) -> int:
    """Open a regular file through pinned, non-symlink directory components."""
    absolute = Path(os.path.abspath(path.expanduser()))
    if absolute.name in {"", ".", ".."}:
        raise LabSafetyError(f"regular-file path is invalid: {absolute}")
    parent_fd = open_directory_nofollow(absolute.parent)
    flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            named = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode):
                raise LabSafetyError(f"path must be a non-symlink regular file: {absolute}")
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise LabSafetyError(f"path changed while it was being opened: {absolute}")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(parent_fd)


def sha256_fd(descriptor: int) -> str:
    """Hash an open file without changing its shared file offset."""
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(descriptor, 1024 * 1024, offset):
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a regular file without following any symlink component."""
    descriptor = open_regular_nofollow(path)
    try:
        return sha256_fd(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically replace JSON and durably sync both the file and its directory."""
    absolute = Path(os.path.abspath(path.expanduser()))
    directory_fd = open_directory_nofollow(absolute.parent, create=True)
    temporary_name: str | None = None
    try:
        temporary_name = (
            f".{absolute.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.fchmod(descriptor, 0o600)
            payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
            with os.fdopen(descriptor, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(
                temporary_name,
                absolute.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = None
            os.fsync(directory_fd)
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_fd)


def require_scratch_root(value: str | None = None) -> Path:
    raw = value or os.environ.get("JCODE_SCRATCH_DIR")
    if not raw:
        raise LabSafetyError("JCODE_SCRATCH_DIR is required")
    root = Path(raw).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise LabSafetyError(f"scratch root is not a directory: {root}")
    return root


def safe_workspace(value: str | Path, scratch_root: Path) -> Path:
    root = scratch_root.resolve(strict=True)
    lexical = Path(os.path.abspath(Path(value).expanduser()))
    candidate = lexical.resolve(strict=False)
    if lexical == root or root not in lexical.parents:
        raise LabSafetyError(f"workspace path must be a child of {root}: {lexical}")
    if candidate == root or root not in candidate.parents:
        raise LabSafetyError(f"workspace must be a child of {root}: {candidate}")

    current = root
    for component in lexical.relative_to(root).parts:
        current /= component
        if current.is_symlink():
            raise LabSafetyError(f"workspace path contains a symlink: {current}")
    return candidate


def reject_unsafe_entries(workspace: Path) -> None:
    if not workspace.exists():
        return
    for root, directories, files in os.walk(workspace, followlinks=False):
        for name in [*directories, *files]:
            path = Path(root) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise LabSafetyError(f"symlink is forbidden in VM workspace: {path}")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise LabSafetyError(f"special file is forbidden in VM workspace: {path}")


def require_private_workspace(workspace: Path) -> None:
    metadata = workspace.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise LabSafetyError(f"workspace must be a non-symlink directory: {workspace}")
    if metadata.st_uid != os.geteuid():
        raise LabSafetyError(f"workspace must be owned by the effective user: {workspace}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LabSafetyError(f"workspace must not grant group or other access: {workspace}")


def reject_nested_mounts(workspace: Path) -> None:
    try:
        result = subprocess.run(
            [FINDMNT, "--json", "--list", "--output", "TARGET,SOURCE"],
            text=True,
            capture_output=True,
            check=True,
            env=subprocess_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LabSafetyError("cannot enumerate mounts with trusted findmnt") from error

    if type(result.stdout) is not str:
        raise LabSafetyError("findmnt returned a non-text JSON document")

    def object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        document = json.loads(
            result.stdout, object_pairs_hook=object_without_duplicate_keys
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise LabSafetyError("findmnt returned malformed JSON") from error

    if type(document) is not dict or set(document) != {"filesystems"}:
        raise LabSafetyError("findmnt returned an invalid top-level JSON object")
    filesystems = document["filesystems"]
    if type(filesystems) is not list:
        raise LabSafetyError("findmnt returned an invalid filesystems list")

    normalized_workspace = Path(
        "/" + os.path.normpath(os.path.abspath(workspace)).lstrip("/")
    )
    for index, filesystem in enumerate(filesystems):
        if type(filesystem) is not dict or set(filesystem) != {"target", "source"}:
            raise LabSafetyError(f"findmnt returned invalid filesystem entry {index}")
        target_value = filesystem["target"]
        source = filesystem["source"]
        if (
            type(target_value) is not str
            or not target_value
            or "\0" in target_value
            or not Path(target_value).is_absolute()
            or type(source) is not str
        ):
            raise LabSafetyError(f"findmnt returned invalid filesystem entry {index}")

        target = Path("/" + os.path.normpath(target_value).lstrip("/"))
        try:
            target.relative_to(normalized_workspace)
        except ValueError:
            continue
        raise LabSafetyError(
            f"mounts are forbidden inside VM workspace: {target} from {source}"
        )


def command_version(command: str, *arguments: str) -> str:
    executable = shutil.which(command, path=SYSTEM_PATH)
    if not executable:
        raise LabSafetyError(f"required command is unavailable: {command}")
    result = subprocess.run(
        [executable, *arguments],
        text=True,
        capture_output=True,
        check=True,
        env=subprocess_environment(),
    )
    output = result.stdout.strip() or result.stderr.strip()
    return output.splitlines()[0] if output else "unknown"


def command_output(command: str, *arguments: str) -> str:
    executable = shutil.which(command, path=SYSTEM_PATH)
    if not executable:
        raise LabSafetyError(f"required command is unavailable: {command}")
    result = subprocess.run(
        [executable, *arguments],
        text=True,
        capture_output=True,
        check=True,
        env=subprocess_environment(),
    )
    return result.stdout.strip() or result.stderr.strip()


def command_facts(command: str, *version_arguments: str) -> dict[str, Any]:
    """Return a version string bound to the exact executable bytes observed."""
    found = shutil.which(command, path=SYSTEM_PATH)
    if not found:
        raise LabSafetyError(f"required command is unavailable: {command}")
    executable = Path(found).resolve(strict=True)
    descriptor = open_regular_nofollow(executable)
    try:
        before = os.fstat(descriptor)
        if not os.access(executable, os.X_OK):
            raise LabSafetyError(f"required command is not executable: {executable}")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise LabSafetyError(f"set-id command is forbidden: {executable}")
        digest = sha256_fd(descriptor)
        result = subprocess.run(
            [str(executable), *version_arguments],
            text=True,
            capture_output=True,
            check=True,
            env=subprocess_environment(),
        )
        output = result.stdout.strip() or result.stderr.strip()
        version = output.splitlines()[0] if output else "unknown"
        after = executable.stat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise LabSafetyError(f"command changed while collecting evidence: {executable}")
        return {
            "version": version,
            "binary_path": str(executable),
            "binary_sha256": digest,
            "binary_size": before.st_size,
            "binary_device": before.st_dev,
            "binary_inode": before.st_ino,
            "binary_mode": stat.S_IMODE(before.st_mode),
        }
    finally:
        os.close(descriptor)


def readable_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return "unavailable"


def subprocess_environment(home: Path | None = None) -> dict[str, str]:
    """Return a deterministic environment without loader or QEMU injection knobs."""
    safe_home = Path("/") if home is None else Path(os.path.abspath(home))
    return {
        "HOME": str(safe_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(safe_home),
    }


def available_memory_bytes() -> int:
    try:
        kibibytes = next(
            line.split()[1]
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines()
            if line.startswith("MemAvailable:")
        )
    except (FileNotFoundError, StopIteration, ValueError) as error:
        raise LabSafetyError("cannot determine MemAvailable from /proc/meminfo") from error
    try:
        return int(kibibytes) * 1024
    except ValueError as error:
        raise LabSafetyError("invalid MemAvailable value in /proc/meminfo") from error


def kernel_cpu_kvm_facts() -> dict[str, Any]:
    uname = platform.uname()
    cpuinfo_path = Path("/proc/cpuinfo")
    cpuinfo = readable_text(cpuinfo_path)
    processors: list[dict[str, str]] = []
    for section in cpuinfo.split("\n\n"):
        fields: dict[str, str] = {}
        for line in section.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        if fields:
            processors.append(fields)
    first = processors[0] if processors else {}
    flags = set(first.get("flags", first.get("Features", "")).split())
    kvm = Path("/dev/kvm")
    kvm_metadata = kvm.stat()
    if not stat.S_ISCHR(kvm_metadata.st_mode):
        raise LabSafetyError(f"KVM path is not a character device: {kvm}")
    return {
        "kernel": {
            "system": uname.system,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "proc_version": readable_text(Path("/proc/version")),
            "cmdline": readable_text(Path("/proc/cmdline")),
            "proc_version_sha256": sha256_file(Path("/proc/version")),
            "cmdline_sha256": sha256_file(Path("/proc/cmdline")),
        },
        "cpu": {
            "architecture": platform.machine(),
            "logical_processors": os.cpu_count(),
            "vendor_id": first.get("vendor_id", first.get("CPU implementer", "unknown")),
            "model_name": first.get("model name", first.get("Processor", "unknown")),
            "virtualization_flags": sorted(flags.intersection({"vmx", "svm"})),
            "cpuinfo_sha256": sha256_file(cpuinfo_path),
        },
        "kvm": {
            "path": str(kvm),
            "readable": os.access(kvm, os.R_OK),
            "writable": os.access(kvm, os.W_OK),
            "major": os.major(kvm_metadata.st_rdev),
            "minor": os.minor(kvm_metadata.st_rdev),
            "module_version": readable_text(Path("/sys/module/kvm/version")),
            "module_parameters": {
                name: readable_text(path)
                for name, path in {
                    "ignore_msrs": Path("/sys/module/kvm/parameters/ignore_msrs"),
                    "report_ignored_msrs": Path(
                        "/sys/module/kvm/parameters/report_ignored_msrs"
                    ),
                }.items()
            },
        },
    }


def validate_qcow2(path: str | Path, workspace: Path) -> dict[str, Any]:
    candidate = safe_workspace(path, workspace.parent)
    if workspace not in candidate.parents:
        raise LabSafetyError(f"disk must remain inside workspace: {candidate}")
    metadata = candidate.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise LabSafetyError(f"disk must be a regular file: {candidate}")
    if metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
        raise LabSafetyError(f"disk must be owned and singly linked: {candidate}")

    qemu_img = shutil.which("qemu-img", path=SYSTEM_PATH)
    if not qemu_img:
        raise LabSafetyError("qemu-img is required")
    chain: list[dict[str, Any]] = []
    current = candidate
    validated_paths: list[str] = []
    seen: set[tuple[int, int]] = set()
    while True:
        if len(chain) >= 16:
            raise LabSafetyError("qcow2 backing chain exceeds 16 images")
        descriptor = open_regular_nofollow(current)
        try:
            before = os.fstat(descriptor)
            identity = (before.st_dev, before.st_ino)
            if identity in seen:
                raise LabSafetyError(f"qcow2 backing chain contains a cycle: {current}")
            seen.add(identity)
            result = subprocess.run(
                [
                    qemu_img,
                    "info",
                    "--output=json",
                    "--force-share",
                    f"/proc/self/fd/{descriptor}",
                ],
                text=True,
                capture_output=True,
                check=True,
                pass_fds=(descriptor,),
                env=subprocess_environment(workspace),
            )
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise LabSafetyError(f"qcow2 changed during validation: {current}")
            information = json.loads(result.stdout)
        finally:
            os.close(descriptor)
        if information.get("format") != "qcow2":
            raise LabSafetyError(
                f"disk format must be qcow2, got {information.get('format')!r}: {current}"
            )
        if information.get("dirty-flag"):
            raise LabSafetyError(f"qcow2 image has a dirty flag: {current}")
        format_data = information.get("format-specific", {}).get("data", {})
        if format_data.get("corrupt"):
            raise LabSafetyError(f"qcow2 image reports corruption: {current}")
        if "data-file" in format_data or "data-file-raw" in format_data:
            raise LabSafetyError(f"external qcow2 data files are forbidden: {current}")
        chain.append(information)
        validated_paths.append(str(current))

        backing = information.get("backing-filename")
        if not backing:
            break
        raw_backing = Path(backing)
        if not raw_backing.is_absolute():
            raw_backing = current.parent / raw_backing
        next_path = safe_workspace(raw_backing, workspace.parent)
        if workspace not in next_path.parents:
            raise LabSafetyError(f"qcow2 backing file escapes workspace: {next_path}")
        next_metadata = next_path.lstat()
        if not stat.S_ISREG(next_metadata.st_mode):
            raise LabSafetyError(f"qcow2 backing file must be a regular file: {next_path}")
        if next_metadata.st_uid != os.geteuid() or next_metadata.st_nlink != 1:
            raise LabSafetyError(f"qcow2 backing file must be owned and singly linked: {next_path}")
        current = next_path

    result = dict(chain[0])
    result["validated-backing-chain"] = validated_paths
    return result


def host_evidence(workspace: Path) -> dict[str, Any]:
    require_private_workspace(workspace)
    reject_unsafe_entries(workspace)
    reject_nested_mounts(workspace)

    firmware_facts: dict[str, dict[str, Any]] = {}
    for name, path in {
        "ovmf_code": OVMF_CODE,
        "ovmf_secure_code": OVMF_SECURE_CODE,
        "ovmf_vars": OVMF_VARS,
    }.items():
        try:
            descriptor = open_regular_nofollow(path)
        except (LabSafetyError, OSError) as error:
            raise LabSafetyError(f"invalid OVMF firmware {path}: {error}") from error
        try:
            metadata = os.fstat(descriptor)
            firmware_facts[name] = {
                "path": str(path),
                "sha256": sha256_fd(descriptor),
                "size": metadata.st_size,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        finally:
            os.close(descriptor)

    kvm = Path("/dev/kvm")
    if not kvm.exists() or not os.access(kvm, os.R_OK | os.W_OK):
        raise LabSafetyError("read/write access to /dev/kvm is required")

    memory_available = available_memory_bytes()
    disk_available = shutil.disk_usage(workspace).free
    if memory_available < MIN_AVAILABLE_MEMORY_BYTES:
        raise LabSafetyError(
            f"at least {MIN_AVAILABLE_MEMORY_BYTES} available memory bytes are required; "
            f"found {memory_available}"
        )
    if disk_available < MIN_AVAILABLE_DISK_BYTES:
        raise LabSafetyError(
            f"at least {MIN_AVAILABLE_DISK_BYTES} free disk bytes are required; "
            f"found {disk_available}"
        )

    versions = {
        "qemu": command_facts("qemu-system-x86_64", "--version"),
        "qemu_img": command_facts("qemu-img", "--version"),
        "swtpm": command_facts("swtpm", "--version"),
        "xorriso": command_facts("xorriso", "-version"),
        "curl": command_facts("curl", "--version"),
        "sha256sum": command_facts("sha256sum", "--version"),
    }
    qemu_machines = command_output("qemu-system-x86_64", "-machine", "help")
    host_facts = kernel_cpu_kvm_facts()
    return {
        "schema_version": 2,
        "workspace": str(workspace),
        "memory_available_bytes": memory_available,
        "disk_available_bytes": disk_available,
        "firmware": firmware_facts,
        **host_facts,
        "qemu_machine": {
            "required": "pc-q35-11.0",
            "available": "pc-q35-11.0" in qemu_machines,
            "machine_help_sha256": hashlib.sha256(qemu_machines.encode()).hexdigest(),
        },
        "versions": versions,
    }


def initialize(workspace: Path) -> dict[str, Any]:
    workspace_fd = open_directory_nofollow(workspace, create=True)
    try:
        metadata = os.fstat(workspace_fd)
        if metadata.st_uid != os.geteuid():
            raise LabSafetyError(f"workspace must be owned by the effective user: {workspace}")
        os.fchmod(workspace_fd, 0o700)
    finally:
        os.close(workspace_fd)
    for name in ("media", "images", "runs", "evidence", "logs"):
        child = workspace / name
        child_fd = open_directory_nofollow(child, create=True)
        try:
            os.fchmod(child_fd, 0o700)
        finally:
            os.close(child_fd)
    evidence = host_evidence(workspace)
    output = workspace / "evidence" / "host.json"
    atomic_write_json(output, evidence)
    return evidence


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "command", choices=("check-host", "init", "validate-disk")
    )
    result.add_argument(
        "--workspace",
        help="lab path below JCODE_SCRATCH_DIR",
    )
    result.add_argument("--disk", help="qcow2 disk path for validate-disk")
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        scratch = require_scratch_root()
        workspace = safe_workspace(
            arguments.workspace or scratch / DEFAULT_LAB_NAME, scratch
        )
        if arguments.command == "init":
            evidence = initialize(workspace)
        elif arguments.command == "check-host":
            workspace_fd = open_directory_nofollow(workspace, create=True)
            os.close(workspace_fd)
            evidence = host_evidence(workspace)
        else:
            if not arguments.disk:
                raise LabSafetyError("--disk is required for validate-disk")
            evidence = validate_qcow2(arguments.disk, workspace)
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    except (LabSafetyError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
