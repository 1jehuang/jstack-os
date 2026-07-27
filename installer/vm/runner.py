#!/usr/bin/env python3
"""Profile-bound, file-only direct-QEMU launcher for the Windows VM lab.

Each preparation resolves one exact immutable support profile, scenario, and
official ISO record, then exclusively creates a run directory containing a fresh
writable overlay, OVMF variables, evidence directory, and TPM state when required.
The overlay's immutable qcow2 backing chain, firmware, and ISO are opened before
QEMU starts. QEMU receives those exact open file descriptions through ``-add-fd``
and generated ``/dev/fdset`` block graphs, so renaming or replacing those paths
cannot redirect block I/O after validation.

Residual TOCTOU boundary: Python cannot portably exec QEMU or swtpm from an
already-open executable descriptor, and swtpm/QMP Unix sockets are named paths.
Their resolved executable identities and every socket parent are checked before
spawn, but a privileged actor able to mutate system binaries or the private
workspace concurrently remains outside this unprivileged harness's threat
model. Post-spawn QMP and /proc FD audits fail closed before QMP ``cont``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

import lab


MACHINE = "pc-q35-11.0"
MEMORY_MIB = 4096
VCPUS = 4
MAX_BACKING_DEPTH = 16
QMP_TIMEOUT_SECONDS = 10.0
PROFILE_DIRECTORY = Path(__file__).resolve().parent / "profiles"
PROFILE_SCHEMA = PROFILE_DIRECTORY / "profile.schema.json"
MEDIA_SCHEMA = PROFILE_DIRECTORY / "media.schema.json"
PROFILE_FILES = {
    "windows-10-pro-22h2-en-us-x64-q35-11.0": (
        PROFILE_DIRECTORY / "windows-10-pro-22h2-en-us.profile.json"
    ),
    "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0": (
        PROFILE_DIRECTORY / "windows-11-enterprise-25h2-en-us-eval.profile.json"
    ),
}
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise lab.LabSafetyError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise lab.LabSafetyError(f"non-finite JSON number is forbidden: {value}")


class PinnedFile:
    def __init__(self, path: Path, descriptor: int, writable: bool, label: str):
        self.path = path
        self.descriptor = descriptor
        self.writable = writable
        self.label = label
        self.fdset: int | None = None
        self.metadata = os.fstat(descriptor)
        self.sha256: str | None = None

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    @property
    def inode_identity(self) -> tuple[int, int]:
        return (self.metadata.st_dev, self.metadata.st_ino)

    def facts(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "fd": self.descriptor,
            "fdset": self.fdset,
            "writable": self.writable,
            "label": self.label,
            "device": self.metadata.st_dev,
            "inode": self.metadata.st_ino,
            "size": self.metadata.st_size,
            "mode": stat.S_IMODE(self.metadata.st_mode),
            **({"sha256": self.sha256} if self.sha256 is not None else {}),
        }


class LaunchPlan:
    def __init__(
        self,
        workspace: Path,
        qemu_argv: list[str],
        swtpm_argv: list[str],
        pins: list[PinnedFile],
        disk_chain: list[Path],
        iso: Path | None,
        qmp_socket: Path,
        swtpm_socket: Path | None,
        executable_facts: dict[str, dict[str, Any]],
        firmware_copy: dict[str, Any],
        block_nodes: set[str],
        run_id: str = "legacy",
        run_directory: Path | None = None,
        evidence_directory: Path | None = None,
        profile: dict[str, Any] | None = None,
        media: dict[str, Any] | None = None,
        scenario: dict[str, Any] | None = None,
        tpm_required: bool = True,
        resolved_inputs: dict[str, str] | None = None,
        input_file_facts: dict[str, dict[str, Any]] | None = None,
    ):
        self.workspace = workspace
        self.qemu_argv = qemu_argv
        self.swtpm_argv = swtpm_argv
        self.pins = pins
        self.disk_chain = disk_chain
        self.iso = iso
        self.qmp_socket = qmp_socket
        self.swtpm_socket = swtpm_socket
        self.executable_facts = executable_facts
        self.firmware_copy = firmware_copy
        self.block_nodes = block_nodes
        self.run_id = run_id
        self.run_directory = run_directory or workspace / "runs" / "direct-qemu"
        self.evidence_directory = evidence_directory or workspace / "evidence"
        self.profile = profile or {}
        self.media = media or {}
        self.scenario = scenario or {}
        self.tpm_required = tpm_required
        self.resolved_inputs = resolved_inputs or {}
        self.input_file_facts = input_file_facts or {}

    def close(self) -> None:
        for pinned in self.pins:
            pinned.close()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "mode": "fixed-direct-qemu",
            "workspace": str(self.workspace),
            "run_id": self.run_id,
            "run_directory": str(self.run_directory),
            "evidence_directory": str(self.evidence_directory),
            "profile_id": self.profile.get("profile_id"),
            "media_record_id": self.media.get("record_id"),
            "scenario": self.scenario,
            "resolved_profile_inputs": dict(sorted(self.resolved_inputs.items())),
            "profile_input_files": self.input_file_facts,
            "machine": MACHINE,
            "disk_chain": [str(path) for path in self.disk_chain],
            "read_only_iso_allowlist": [str(self.iso)] if self.iso else [],
            "qemu": self.qemu_argv,
            "swtpm": self.swtpm_argv,
            "executables": self.executable_facts,
            "firmware_copy": self.firmware_copy,
            "preopened": [item.facts() for item in self.pins],
            "expected_block_nodes": sorted(self.block_nodes),
            "launch_identity": {
                "uid": os.getuid(),
                "euid": os.geteuid(),
                "gid": os.getgid(),
                "egid": os.getegid(),
                "supplementary_groups": sorted(os.getgroups()),
            },
            "residual_toctou": (
                "QEMU/swtpm executable lookup and named Unix-socket creation cannot "
                "be pinned with add-fd; identities and private parents are checked "
                "immediately before spawn, then QMP and /proc FDs are audited while "
                "the VM remains paused."
            ),
        }


class QMPClient:
    def __init__(self, path: Path, timeout: float = QMP_TIMEOUT_SECONDS):
        self.path = path
        self.timeout = timeout
        self.connection: socket.socket | None = None
        self.stream: Any = None
        self.sequence = 0

    def __enter__(self) -> "QMPClient":
        deadline = time.monotonic() + self.timeout
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                connection.connect(str(self.path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    connection.close()
                    raise lab.LabSafetyError(f"QMP socket did not become ready: {self.path}")
                time.sleep(0.05)
        connection.settimeout(self.timeout)
        self.connection = connection
        self.stream = connection.makefile("rwb", buffering=0)
        greeting = self._read_message()
        if "QMP" not in greeting:
            raise lab.LabSafetyError("invalid QMP greeting")
        self.execute("qmp_capabilities")
        return self

    def __exit__(self, *_: object) -> None:
        if self.stream is not None:
            self.stream.close()
        if self.connection is not None:
            self.connection.close()

    def _read_message(self) -> dict[str, Any]:
        while True:
            line = self.stream.readline()
            if not line:
                raise lab.LabSafetyError("QMP connection closed unexpectedly")
            message = json.loads(line)
            if "event" not in message:
                return message

    def execute(self, command: str) -> Any:
        self.sequence += 1
        identifier = f"jstack-{self.sequence}"
        request = json.dumps({"execute": command, "id": identifier}).encode() + b"\r\n"
        self.stream.write(request)
        while True:
            response = self._read_message()
            if response.get("id") != identifier:
                continue
            if "error" in response:
                raise lab.LabSafetyError(f"QMP {command} failed: {response['error']}")
            if "return" not in response:
                raise lab.LabSafetyError(f"QMP {command} returned no result")
            return response["return"]


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _reject_symlink_components(path: Path, stop: Path | None = None) -> None:
    absolute = Path(os.path.abspath(path.expanduser()))
    parts = absolute.parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if stop is not None and not _inside(current, stop) and current != stop:
            continue
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise lab.LabSafetyError(f"symlink path component is forbidden: {current}")


def _regular_path(
    value: str | Path,
    *,
    label: str,
    suffix: str | None = None,
    workspace: Path | None = None,
) -> Path:
    lexical = Path(os.path.abspath(Path(value).expanduser()))
    if workspace is not None:
        candidate = lab.safe_workspace(lexical, workspace.parent)
        if not _inside(candidate, workspace) or candidate == workspace:
            raise lab.LabSafetyError(f"{label} must remain below workspace: {candidate}")
        _reject_symlink_components(lexical, workspace)
    else:
        _reject_symlink_components(lexical)
        candidate = lexical.resolve(strict=True)
    if suffix is not None and candidate.suffix.lower() != suffix:
        raise lab.LabSafetyError(f"{label} must have a {suffix} suffix: {candidate}")
    metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise lab.LabSafetyError(f"{label} must be a non-symlink regular file: {candidate}")
    if stat.S_ISBLK(metadata.st_mode) or stat.S_ISCHR(metadata.st_mode):
        raise lab.LabSafetyError(f"host device paths are forbidden for {label}: {candidate}")
    if workspace is not None:
        if metadata.st_uid != os.geteuid():
            raise lab.LabSafetyError(f"{label} must be owned by the effective user: {candidate}")
        if metadata.st_nlink != 1:
            raise lab.LabSafetyError(
                f"hard-linked workspace files are forbidden for {label}: {candidate}"
            )
    return candidate


def _open_pinned(path: Path, *, writable: bool, label: str) -> PinnedFile:
    try:
        descriptor = lab.open_regular_nofollow(path, writable=writable)
    except (lab.LabSafetyError, OSError) as error:
        raise lab.LabSafetyError(f"cannot safely open {label}: {path}: {error}") from error
    return PinnedFile(path, descriptor, writable, label)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    pinned = _open_pinned(path, writable=False, label=label)
    try:
        try:
            offset = 0
            chunks: list[bytes] = []
            while offset < pinned.metadata.st_size:
                chunk = os.pread(
                    pinned.descriptor,
                    min(1024 * 1024, pinned.metadata.st_size - offset),
                    offset,
                )
                if not chunk:
                    raise lab.LabSafetyError(f"short read while loading {label}: {path}")
                chunks.append(chunk)
                offset += len(chunk)
            value = json.loads(
                b"".join(chunks),
                object_pairs_hook=_object_without_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise lab.LabSafetyError(f"{label} is not valid JSON: {path}") from error
    finally:
        pinned.close()
    if not isinstance(value, dict):
        raise lab.LabSafetyError(f"{label} must be a JSON object: {path}")
    return value


def _schema_const(schema: dict[str, Any], identity_key: str, identity: str) -> dict[str, Any]:
    matches = [
        definition["const"]
        for definition in schema.get("$defs", {}).values()
        if isinstance(definition, dict)
        and isinstance(definition.get("const"), dict)
        and definition["const"].get(identity_key) == identity
    ]
    if len(matches) != 1:
        raise lab.LabSafetyError(f"unsupported or ambiguous {identity_key}: {identity}")
    return matches[0]


def _resolve_profile(
    profile_id: str, scenario_id: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    profile_path = PROFILE_FILES.get(profile_id)
    if profile_path is None:
        raise lab.LabSafetyError(f"unsupported VM support profile: {profile_id}")
    profile = _load_json(profile_path, "VM support profile")
    expected_profile = _schema_const(
        _load_json(PROFILE_SCHEMA, "VM support profile schema"), "profile_id", profile_id
    )
    if profile != expected_profile:
        raise lab.LabSafetyError(f"VM support profile is not the exact immutable record: {profile_id}")
    scenarios = [
        scenario
        for scenario in profile.get("security", {}).get("scenario_matrix", [])
        if isinstance(scenario, dict) and scenario.get("id") == scenario_id
    ]
    if len(scenarios) != 1:
        raise lab.LabSafetyError(
            f"scenario {scenario_id!r} does not resolve exactly in profile {profile_id}"
        )
    relative_media = Path(profile["media"]["record_path"])
    if relative_media.is_absolute() or ".." in relative_media.parts:
        raise lab.LabSafetyError("support profile media record path is unsafe")
    media_path = (PROFILE_DIRECTORY.parent / relative_media).resolve(strict=True)
    if not _inside(media_path, PROFILE_DIRECTORY):
        raise lab.LabSafetyError("support profile media record escapes the profile directory")
    media_pin = _open_pinned(media_path, writable=False, label="official media record")
    try:
        media_digest = lab.sha256_fd(media_pin.descriptor)
    finally:
        media_pin.close()
    if media_digest != profile["media"]["record_sha256"]:
        raise lab.LabSafetyError("official media record digest does not match support profile")
    media = _load_json(media_path, "official media record")
    expected_media = _schema_const(
        _load_json(MEDIA_SCHEMA, "official media schema"), "record_id", media["record_id"]
    )
    if media != expected_media or media.get("availability") != "available":
        raise lab.LabSafetyError("official media record is not an exact available record")
    return profile, scenarios[0], media


def _resolve_required_inputs(
    profile: dict[str, Any], supplied: dict[str, str] | None
) -> dict[str, str]:
    if not isinstance(supplied, dict):
        raise lab.LabSafetyError("all required profile inputs must be supplied")
    declarations = profile.get("required_inputs")
    if not isinstance(declarations, list):
        raise lab.LabSafetyError("support profile has no required input declarations")
    expected = {
        item.get("id")
        for item in declarations
        if isinstance(item, dict)
        and item.get("type") == "sha256"
        and item.get("state") == "required-unresolved"
        and item.get("value") is None
    }
    if len(expected) != len(declarations) or None in expected or set(supplied) != expected:
        missing = sorted(str(item) for item in expected - set(supplied))
        extra = sorted(set(supplied) - expected)
        raise lab.LabSafetyError(
            f"required profile inputs are unresolved or unexpected; missing={missing}, extra={extra}"
        )
    resolved: dict[str, str] = {}
    for input_id, value in supplied.items():
        if (
            not isinstance(value, str)
            or SHA256_PATTERN.fullmatch(value) is None
            or value == "0" * 64
        ):
            raise lab.LabSafetyError(f"required profile input is not a resolved SHA256: {input_id}")
        resolved[input_id] = value
    return resolved


def _verify_resolved_digest(
    resolved: dict[str, str], input_id: str, actual: str, label: str
) -> None:
    if resolved.get(input_id) != actual:
        raise lab.LabSafetyError(f"{label} SHA256 does not match resolved profile input")


def _verify_external_input_files(
    profile: dict[str, Any],
    resolved: dict[str, str],
    input_files: dict[str, str | Path] | None,
) -> dict[str, dict[str, Any]]:
    directly_verified = {
        profile["qemu"]["binary_sha256_input"],
        profile["firmware"]["code"]["sha256_input"],
        profile["firmware"]["nonsecure_code"]["sha256_input"],
        profile["security"]["tpm"]["emulator_sha256_input"],
        profile["storage"]["base_image_sha256_input"],
    }
    expected = set(resolved) - directly_verified
    try:
        role_inputs = {
            "ovmf-enrolled-vars": profile["firmware"]["enrolled_vars"]["sha256_input"],
            "ovmf-fixed-vars": profile["firmware"]["fixed_vars"]["sha256_input"],
            "base-image-gpt": profile["storage"]["base_image_gpt_sha256_input"],
            "installer": profile["artifacts"]["installer_sha256_input"],
            "installer-graph": profile["artifacts"]["installer_graph_sha256_input"],
            "release-manifest": profile["artifacts"]["release_manifest_sha256_input"],
            "boot-artifacts": profile["artifacts"]["boot_artifacts_sha256_input"],
        }
    except (KeyError, TypeError) as error:
        raise lab.LabSafetyError(
            "support profile does not bind every external artifact role"
        ) from error
    if (
        any(not isinstance(input_id, str) for input_id in role_inputs.values())
        or len(set(role_inputs.values())) != len(role_inputs)
        or set(role_inputs.values()) != expected
    ):
        raise lab.LabSafetyError(
            "support profile external artifact role bindings do not match required inputs"
        )
    if not isinstance(input_files, dict) or set(input_files) != set(role_inputs):
        supplied = set(input_files) if isinstance(input_files, dict) else set()
        raise lab.LabSafetyError(
            "profile input files do not resolve every canonical artifact role; "
            f"missing={sorted(set(role_inputs) - supplied)}, "
            f"extra={sorted(supplied - set(role_inputs))}"
        )
    facts: dict[str, dict[str, Any]] = {}
    identities: set[tuple[int, int]] = set()
    for role in sorted(role_inputs):
        input_id = role_inputs[role]
        path = _regular_path(input_files[role], label=f"profile artifact {role}")
        pinned = _open_pinned(path, writable=False, label=f"profile artifact {role}")
        try:
            if pinned.metadata.st_mode & 0o222:
                raise lab.LabSafetyError(
                    f"profile artifact must be read-only: {role}: {path}"
                )
            if pinned.inode_identity in identities:
                raise lab.LabSafetyError("canonical profile artifact roles must use distinct files")
            identities.add(pinned.inode_identity)
            pinned.sha256 = lab.sha256_fd(pinned.descriptor)
            _verify_resolved_digest(resolved, input_id, pinned.sha256, role)
            record = pinned.facts()
            record.pop("fd", None)
            record.pop("fdset", None)
            record["artifact_role"] = role
            facts[input_id] = record
        finally:
            pinned.close()
    return facts


def _verify_version_constraint(
    executable: Path, constraint: dict[str, str], label: str, workspace: Path
) -> None:
    result = subprocess.run(
        [str(executable), "--version"],
        text=True,
        capture_output=True,
        check=True,
        env=lab.subprocess_environment(workspace),
    )
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", result.stdout + result.stderr)
    if match is None:
        raise lab.LabSafetyError(f"cannot determine {label} version")
    actual = tuple(int(component) for component in match.groups())

    def parsed(name: str) -> tuple[int, int, int]:
        value = constraint.get(name)
        if not isinstance(value, str) or re.fullmatch(r"\d+\.\d+\.\d+", value) is None:
            raise lab.LabSafetyError(f"support profile has invalid {label} version constraint")
        major, minor, patch = value.split(".")
        return (int(major), int(minor), int(patch))

    if not parsed("minimum_inclusive") <= actual < parsed("maximum_exclusive"):
        raise lab.LabSafetyError(f"{label} version is outside the exact support profile range")


def _validate_iso(pinned: PinnedFile, media: dict[str, Any]) -> None:
    expected = media.get("iso", {})
    if pinned.metadata.st_size != expected.get("size_bytes"):
        raise lab.LabSafetyError("installation ISO size does not match official media record")
    pinned.sha256 = lab.sha256_fd(pinned.descriptor)
    if pinned.sha256 != expected.get("sha256"):
        raise lab.LabSafetyError("installation ISO SHA256 does not match official media record")
    # ISO-9660 primary volume descriptors carry CD001 at sector 16, byte 1.
    if os.pread(pinned.descriptor, 5, 16 * 2048 + 1) != b"CD001":
        raise lab.LabSafetyError(f"installation media is not an ISO-9660 image: {pinned.path}")


def _create_run_directory(workspace: Path, requested: str | None) -> tuple[str, Path, Path]:
    runs = workspace / "runs"
    runs_fd = lab.open_directory_nofollow(runs)
    try:
        attempts = 1 if requested is not None else 32
        for _ in range(attempts):
            run_id = requested or f"run-{time.time_ns()}-{secrets.token_hex(8)}"
            if RUN_ID_PATTERN.fullmatch(run_id) is None or run_id in {".", ".."}:
                raise lab.LabSafetyError(f"invalid VM run ID: {run_id!r}")
            try:
                os.mkdir(run_id, 0o700, dir_fd=runs_fd)
            except FileExistsError:
                if requested is not None:
                    raise lab.LabSafetyError(f"VM run ID or state already exists: {run_id}")
                continue
            os.fsync(runs_fd)
            run_directory = runs / run_id
            evidence_directory = run_directory / "evidence"
            os.mkdir(evidence_directory, mode=0o700)
            return run_id, run_directory, evidence_directory
    finally:
        os.close(runs_fd)
    raise lab.LabSafetyError("could not allocate a unique VM run ID")


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _qcow2_info(pinned: PinnedFile, qemu_img: Path) -> dict[str, Any]:
    before = os.fstat(pinned.descriptor)
    result = subprocess.run(
        [
            str(qemu_img),
            "info",
            "--output=json",
            "--force-share",
            f"/proc/self/fd/{pinned.descriptor}",
        ],
        text=True,
        capture_output=True,
        check=True,
        pass_fds=(pinned.descriptor,),
        env=lab.subprocess_environment(pinned.path.parent),
    )
    after = os.fstat(pinned.descriptor)
    if _identity(before) != _identity(after):
        raise lab.LabSafetyError(f"qcow2 changed during validation: {pinned.path}")
    try:
        information = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise lab.LabSafetyError(f"qemu-img returned invalid JSON for {pinned.path}") from error
    if information.get("format") != "qcow2":
        raise lab.LabSafetyError(
            f"disk format must be qcow2, got {information.get('format')!r}: {pinned.path}"
        )
    if information.get("dirty-flag"):
        raise lab.LabSafetyError(f"qcow2 image has a dirty flag: {pinned.path}")
    format_data = information.get("format-specific", {}).get("data", {})
    if format_data.get("corrupt"):
        raise lab.LabSafetyError(f"qcow2 image reports corruption: {pinned.path}")
    if "data-file" in format_data or "data-file-raw" in format_data:
        raise lab.LabSafetyError(f"external qcow2 data files are forbidden: {pinned.path}")
    return information


def validate_and_pin_qcow2(
    disk: str | Path,
    workspace: Path,
    qemu_img: Path,
    *,
    require_backing: bool = True,
) -> list[PinnedFile]:
    """Validate and pin the top image and every metadata-declared backing image."""
    current = _regular_path(
        disk, label="VM disk", suffix=".qcow2", workspace=workspace
    )
    chain: list[PinnedFile] = []
    seen: set[tuple[int, int]] = set()
    try:
        while True:
            if len(chain) >= MAX_BACKING_DEPTH:
                raise lab.LabSafetyError(
                    f"qcow2 backing chain exceeds {MAX_BACKING_DEPTH} images"
                )
            pinned = _open_pinned(
                current, writable=not chain, label="VM disk" if not chain else "backing file"
            )
            if not chain and os.fstat(pinned.descriptor).st_nlink != 1:
                pinned.close()
                raise lab.LabSafetyError("top writable qcow2 overlay must have exactly one link")
            if chain and os.fstat(pinned.descriptor).st_mode & 0o222:
                pinned.close()
                raise lab.LabSafetyError(f"qcow2 base/backing file must be read-only: {current}")
            identity = os.fstat(pinned.descriptor)
            inode = (identity.st_dev, identity.st_ino)
            if inode in seen:
                pinned.close()
                raise lab.LabSafetyError(f"qcow2 backing chain contains a cycle: {current}")
            seen.add(inode)
            chain.append(pinned)
            information = _qcow2_info(pinned, qemu_img)
            raw_backing = information.get("backing-filename")
            if not raw_backing:
                break
            backing = Path(raw_backing)
            if not backing.is_absolute():
                backing = current.parent / backing
            current = _regular_path(
                backing,
                label="qcow2 backing file",
                suffix=".qcow2",
                workspace=workspace,
            )
        if require_backing and len(chain) != 2:
            if len(chain) < 2:
                raise lab.LabSafetyError("standalone writable qcow2 disks are forbidden")
            raise lab.LabSafetyError(
                "qcow2 must be exactly one fresh overlay over one immutable base"
            )
        if os.fstat(chain[0].descriptor).st_nlink != 1:
            raise lab.LabSafetyError("top writable qcow2 overlay was hard-linked after pinning")
        for backing in chain[1:]:
            if os.fstat(backing.descriptor).st_mode & 0o222:
                raise lab.LabSafetyError(
                    f"qcow2 base/backing file became writable after pinning: {backing.path}"
                )
        return chain
    except BaseException:
        for item in chain:
            item.close()
        raise


def _create_overlay(base: Path, overlay: Path, qemu_img: Path, workspace: Path) -> None:
    base = _regular_path(base, label="immutable base image", suffix=".qcow2", workspace=workspace)
    if base.stat().st_mode & 0o222:
        raise lab.LabSafetyError(f"immutable base image must be read-only: {base}")
    if overlay.exists() or overlay.is_symlink():
        raise lab.LabSafetyError(f"refusing to reuse writable overlay state: {overlay}")
    subprocess.run(
        [
            str(qemu_img),
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            str(base),
            str(overlay),
        ],
        text=True,
        capture_output=True,
        check=True,
        env=lab.subprocess_environment(overlay.parent),
    )
    overlay = _regular_path(overlay, label="fresh writable overlay", suffix=".qcow2", workspace=workspace)
    os.chmod(overlay, 0o600)
    if overlay.stat().st_nlink != 1:
        raise lab.LabSafetyError("fresh writable overlay must have exactly one link")


def _validate_immutable_base(
    base: Path,
    qemu_img: Path,
    expected_virtual_size: int,
    resolved: dict[str, str],
    input_id: str,
) -> None:
    pinned = _open_pinned(base, writable=False, label="immutable base image")
    try:
        information = _qcow2_info(pinned, qemu_img)
        if information.get("backing-filename"):
            raise lab.LabSafetyError("immutable base image must not have a backing file")
        if information.get("virtual-size") != expected_virtual_size:
            raise lab.LabSafetyError("base image virtual size does not match support profile")
        pinned.sha256 = lab.sha256_fd(pinned.descriptor)
        _verify_resolved_digest(resolved, input_id, pinned.sha256, "base image")
    finally:
        pinned.close()


def _require_executable(name: str) -> Path:
    found = shutil.which(name, path=lab.SYSTEM_PATH)
    if not found:
        raise lab.LabSafetyError(f"required executable is unavailable: {name}")
    path = Path(found).resolve(strict=True)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise lab.LabSafetyError(f"executable is not a runnable regular file: {path}")
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise lab.LabSafetyError(f"set-id executables are forbidden: {path}")
    return path


def _executable_facts(path: Path) -> dict[str, Any]:
    descriptor = lab.open_regular_nofollow(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise lab.LabSafetyError(f"set-id executables are forbidden: {path}")
        return {
            "path": str(path),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "sha256": lab.sha256_fd(descriptor),
        }
    finally:
        os.close(descriptor)


def _assert_executable_identity(facts: dict[str, Any]) -> None:
    path = Path(facts["path"])
    current = _executable_facts(path)
    for key in ("device", "inode", "size", "mtime_ns", "sha256"):
        if current[key] != facts[key]:
            raise lab.LabSafetyError(f"executable changed after validation: {path}")


def _verify_machine(qemu: Path, workspace: Path) -> None:
    result = subprocess.run(
        [str(qemu), "-machine", "help"],
        text=True,
        capture_output=True,
        check=True,
        env=lab.subprocess_environment(workspace),
    )
    if MACHINE not in result.stdout:
        raise lab.LabSafetyError(f"QEMU does not provide required machine {MACHINE}")


def _copy_firmware_vars(template: Path, destination: Path) -> dict[str, Any]:
    source = _open_pinned(template, writable=False, label="OVMF variables template")
    source.sha256 = lab.sha256_fd(source.descriptor)
    template_facts = source.facts()
    template_facts.pop("fd", None)
    template_facts.pop("fdset", None)
    if destination.exists() or destination.is_symlink():
        source.close()
        raise lab.LabSafetyError(f"refusing to reuse OVMF variable state: {destination}")
    directory_fd = lab.open_directory_nofollow(destination.parent)
    temporary_name = f".{destination.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
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
        while chunk := os.read(source.descriptor, 1024 * 1024):
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write while copying OVMF variables")
                remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(
            temporary_name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_name = ""
        os.fsync(directory_fd)
        copied = _open_pinned(destination, writable=False, label="copied OVMF variables")
        try:
            copied.sha256 = lab.sha256_fd(copied.descriptor)
            if copied.metadata.st_size != source.metadata.st_size or copied.sha256 != source.sha256:
                raise lab.LabSafetyError("copied OVMF variables do not match the template")
            copy_facts = copied.facts()
            copy_facts.pop("fd", None)
            copy_facts.pop("fdset", None)
            return {"created": True, "template": template_facts, "copy": copy_facts}
        finally:
            copied.close()
    finally:
        source.close()
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _json_option(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _add_pin(argv: list[str], pinned: PinnedFile, fdset: int) -> str:
    pinned.fdset = fdset
    argv.extend(
        ["-add-fd", f"fd={pinned.descriptor},set={fdset},opaque={pinned.label}"]
    )
    return f"/dev/fdset/{fdset}"


def _block_graph(
    argv: list[str], chain: list[PinnedFile], first_fdset: int
) -> tuple[str, int]:
    paths: list[str] = []
    next_fdset = first_fdset
    for pinned in chain:
        paths.append(_add_pin(argv, pinned, next_fdset))
        next_fdset += 1
    for index in reversed(range(len(chain))):
        file_node = f"disk-file-{index}"
        qcow_node = f"disk-qcow-{index}"
        argv.extend(
            [
                "-blockdev",
                _json_option(
                    {
                        "driver": "file",
                        "filename": paths[index],
                        "node-name": file_node,
                        "auto-read-only": index != 0,
                    }
                ),
                "-blockdev",
                _json_option(
                    {
                        "driver": "qcow2",
                        "file": file_node,
                        "node-name": qcow_node,
                        **(
                            {"backing": f"disk-qcow-{index + 1}"}
                            if index + 1 < len(chain)
                            else {"backing": None}
                        ),
                        "read-only": index != 0,
                    }
                ),
            ]
        )
    return "disk-qcow-0", next_fdset


def prepare_launch(
    workspace_value: str | Path,
    disk: str | Path,
    iso: str | Path,
    *,
    profile_id: str,
    scenario_id: str,
    resolved_inputs: dict[str, str] | None,
    input_files: dict[str, str | Path] | None,
    run_id: str | None = None,
    control_media: str | Path | None = None,
) -> LaunchPlan:
    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(workspace_value, scratch)
    if not workspace.is_dir():
        raise lab.LabSafetyError(f"workspace must already exist: {workspace}")
    lab.require_private_workspace(workspace)
    lab.reject_unsafe_entries(workspace)
    lab.reject_nested_mounts(workspace)

    profile, scenario, media = _resolve_profile(profile_id, scenario_id)
    resolved = _resolve_required_inputs(profile, resolved_inputs)
    input_file_facts = _verify_external_input_files(profile, resolved, input_files)
    if profile["qemu"]["machine"]["type"] != MACHINE:
        raise lab.LabSafetyError("support profile QEMU machine does not match fixed runner")
    if profile["compute"]["ram_bytes"] != MEMORY_MIB * 1024 * 1024:
        raise lab.LabSafetyError("support profile memory does not match fixed runner")
    if profile["compute"]["cpu"]["vcpus"] != VCPUS:
        raise lab.LabSafetyError("support profile vCPU count does not match fixed runner")
    if profile["storage"]["virtual_size_bytes"] <= 0:
        raise lab.LabSafetyError("support profile virtual disk size is invalid")
    if (
        profile["storage"]["controller"] != "nvme"
        or profile["storage"]["serial"] != "JSTACKLAB0001"
        or profile["storage"]["logical_sector_bytes"] != 512
        or profile["storage"]["physical_sector_bytes"] != 4096
        or profile["network"]["controller"] != "e1000e"
        or profile["network"]["backend"] != "user"
        or profile["network"]["mac_address"] != "52:54:00:4a:53:01"
        or profile["network"]["host_forwarding"] != "disabled"
    ):
        raise lab.LabSafetyError("support profile device topology does not match fixed runner")

    qemu = _require_executable(profile["qemu"]["binary"])
    qemu_img = _require_executable("qemu-img")
    tpm_required = scenario["tpm"] == "2.0"
    if scenario["tpm"] not in {"2.0", "absent"}:
        raise lab.LabSafetyError("support profile scenario has unsupported TPM state")
    if not tpm_required and not profile["security"]["tpm"]["absent_variant_permitted"]:
        raise lab.LabSafetyError("support profile forbids an absent TPM")
    swtpm = _require_executable(profile["security"]["tpm"]["emulator"])
    executable_facts = {
        "qemu": _executable_facts(qemu),
        "qemu_img": _executable_facts(qemu_img),
    }
    executable_facts["swtpm"] = _executable_facts(swtpm)
    _verify_resolved_digest(
        resolved,
        profile["qemu"]["binary_sha256_input"],
        executable_facts["qemu"]["sha256"],
        "QEMU binary",
    )
    _verify_resolved_digest(
        resolved,
        profile["security"]["tpm"]["emulator_sha256_input"],
        executable_facts["swtpm"]["sha256"],
        "swtpm binary",
    )
    _verify_version_constraint(qemu, profile["qemu"]["version_constraint"], "QEMU", workspace)
    _verify_version_constraint(
        swtpm,
        profile["security"]["tpm"]["emulator_version_constraint"],
        "swtpm",
        workspace,
    )
    _verify_machine(qemu, workspace)

    secure_boot = scenario["secure_boot"] == "enabled"
    if scenario["secure_boot"] not in {"enabled", "disabled"}:
        raise lab.LabSafetyError("support profile scenario has unsupported Secure Boot state")
    code_declaration = profile["firmware"]["code" if secure_boot else "nonsecure_code"]
    vars_declaration = profile["firmware"]["enrolled_vars" if secure_boot else "fixed_vars"]
    vars_role = "ovmf-enrolled-vars" if secure_boot else "ovmf-fixed-vars"
    code_candidates: dict[str, Path] = {
        "OVMF_CODE.secboot.4m.fd": lab.OVMF_SECURE_CODE,
        "OVMF_CODE.4m.fd": lab.OVMF_CODE,
    }
    firmware_code_value = code_candidates.get(code_declaration["canonical_name"])
    if firmware_code_value is None:
        raise lab.LabSafetyError("support profile selected an unsupported OVMF code image")
    firmware_code = _regular_path(firmware_code_value, label="OVMF code")
    if not isinstance(input_files, dict):
        raise lab.LabSafetyError("resolved firmware variable inputs are required")
    firmware_vars_template = _regular_path(
        input_files[vars_role],
        label="OVMF variables template",
    )
    for declaration_name in ("code", "nonsecure_code"):
        declaration = profile["firmware"][declaration_name]
        candidate = code_candidates.get(declaration["canonical_name"])
        if candidate is None:
            raise lab.LabSafetyError("support profile selected an unsupported OVMF code image")
        candidate_path = _regular_path(candidate, label=f"OVMF {declaration_name}")
        _verify_resolved_digest(
            resolved,
            declaration["sha256_input"],
            lab.sha256_file(candidate_path),
            f"OVMF {declaration_name}",
        )
    for declaration_name in ("enrolled_vars", "fixed_vars"):
        declaration = profile["firmware"][declaration_name]
        role = f"ovmf-{declaration_name.replace('_', '-')}"
        candidate_path = _regular_path(
            input_files[role],
            label=f"OVMF {declaration_name}",
        )
        _verify_resolved_digest(
            resolved,
            declaration["sha256_input"],
            lab.sha256_file(candidate_path),
            f"OVMF {declaration_name}",
        )

    base = _regular_path(disk, label="immutable base image", suffix=".qcow2", workspace=workspace)
    if base.stat().st_mode & 0o222:
        raise lab.LabSafetyError(f"immutable base image must be read-only: {base}")
    _validate_immutable_base(
        base,
        qemu_img,
        profile["storage"]["virtual_size_bytes"],
        resolved,
        profile["storage"]["base_image_sha256_input"],
    )
    iso_path = _regular_path(iso, label="installation ISO", suffix=".iso")
    iso_pin = _open_pinned(iso_path, writable=False, label="installation ISO")
    try:
        _validate_iso(iso_pin, media)
    except BaseException:
        iso_pin.close()
        raise

    # An optional read-only control medium carrying one authorised action. It is
    # attached exactly as the ISO is -- opened read-only, pinned by descriptor,
    # never bootable -- because it must not widen the launch surface. The guest
    # gains a file to read; the host gains nothing reachable. Without one the
    # launch is byte-identical to before, so the sealed default is unchanged.
    control_pin: PinnedFile | None = None
    if control_media is not None:
        try:
            control_path = _regular_path(
                control_media, label="control medium", workspace=workspace
            )
            control_pin = _open_pinned(
                control_path, writable=False, label="control medium"
            )
            if control_pin.metadata.st_mode & 0o222:
                control_pin.close()
                raise lab.LabSafetyError(
                    f"control medium must be read-only: {control_path}"
                )
        except BaseException:
            iso_pin.close()
            raise

    try:
        allocated_run_id, run_directory, evidence_directory = _create_run_directory(
            workspace, run_id
        )
        firmware_vars = run_directory / "ovmf-vars.fd"
        firmware_copy = _copy_firmware_vars(firmware_vars_template, firmware_vars)
        firmware_vars = _regular_path(
            firmware_vars, label="OVMF variables", workspace=workspace
        )

        qmp_socket = run_directory / "qmp.sock"
        swtpm_socket = run_directory / "swtpm.sock" if tpm_required else None
        tpm_state = run_directory / "swtpm-state"
        if tpm_required:
            os.mkdir(tpm_state, mode=0o700)
        overlay = run_directory / "disk-overlay.qcow2"
        _create_overlay(base, overlay, qemu_img, workspace)
    except BaseException:
        iso_pin.close()
        if control_pin is not None:
            control_pin.close()
        raise

    pins: list[PinnedFile] = [iso_pin]
    if control_pin is not None:
        pins.append(control_pin)
    try:
        disk_chain = validate_and_pin_qcow2(
            overlay, workspace, qemu_img, require_backing=True
        )
        pins[0:0] = disk_chain
        if len(disk_chain) != 2 or disk_chain[1].path != base:
            raise lab.LabSafetyError(
                "fresh overlay must have exactly one selected immutable base"
            )
        code_pin = _open_pinned(firmware_code, writable=False, label="OVMF code")
        vars_pin = _open_pinned(firmware_vars, writable=True, label="OVMF variables")
        code_pin.sha256 = lab.sha256_fd(code_pin.descriptor)
        vars_pin.sha256 = lab.sha256_fd(vars_pin.descriptor)
        pins.extend([code_pin, vars_pin])
        base_pin = disk_chain[1]
        base_pin.sha256 = lab.sha256_fd(base_pin.descriptor)
        _verify_resolved_digest(
            resolved,
            profile["storage"]["base_image_sha256_input"],
            base_pin.sha256,
            "base image",
        )
        _verify_resolved_digest(
            resolved, code_declaration["sha256_input"], code_pin.sha256, "OVMF code"
        )
        _verify_resolved_digest(
            resolved,
            vars_declaration["sha256_input"],
            firmware_copy["template"]["sha256"],
            "OVMF variables template",
        )

        qemu_argv = [
            str(qemu),
            "-name",
            "jstack-windows-vm",
            "-nodefaults",
            "-no-user-config",
            "-S",
            "-machine",
            f"{MACHINE},accel=kvm,pflash0=ovmf-code,pflash1=ovmf-vars",
            "-cpu",
            "host",
            "-smp",
            str(VCPUS),
            "-m",
            str(MEMORY_MIB),
            "-qmp",
            f"unix:{qmp_socket},server=on,wait=off",
            "-display",
            "none",
            "-device",
            "VGA",
            "-device",
            "qemu-xhci,id=xhci",
            "-device",
            "usb-tablet,bus=xhci.0",
            "-nic",
            "user,model=e1000e,mac=52:54:00:4a:53:01",
        ]
        disk_node, next_fdset = _block_graph(qemu_argv, disk_chain, 10)
        code_path = _add_pin(qemu_argv, code_pin, next_fdset)
        next_fdset += 1
        vars_path = _add_pin(qemu_argv, vars_pin, next_fdset)
        next_fdset += 1
        qemu_argv.extend(
            [
                "-blockdev",
                _json_option(
                    {
                        "driver": "file",
                        "filename": code_path,
                        "node-name": "ovmf-code-file",
                        "read-only": True,
                    }
                ),
                "-blockdev",
                _json_option(
                    {
                        "driver": "raw",
                        "file": "ovmf-code-file",
                        "node-name": "ovmf-code",
                        "read-only": True,
                    }
                ),
                "-blockdev",
                _json_option(
                    {
                        "driver": "file",
                        "filename": vars_path,
                        "node-name": "ovmf-vars-file",
                    }
                ),
                "-blockdev",
                _json_option(
                    {
                        "driver": "raw",
                        "file": "ovmf-vars-file",
                        "node-name": "ovmf-vars",
                    }
                ),
                "-device",
                (
                    f"nvme,drive={disk_node},serial=JSTACKLAB0001,bootindex=1,"
                    "logical_block_size=512,physical_block_size=4096"
                ),
            ]
        )
        iso_fd_path = _add_pin(qemu_argv, iso_pin, next_fdset)
        qemu_argv.extend(
            [
                "-blockdev",
                _json_option(
                    {
                        "driver": "file",
                        "filename": iso_fd_path,
                        "node-name": "install-iso-file",
                        "read-only": True,
                    }
                ),
                "-blockdev",
                _json_option(
                    {
                        "driver": "raw",
                        "file": "install-iso-file",
                        "node-name": "install-iso",
                        "read-only": True,
                    }
                ),
                "-device",
                "ide-cd,drive=install-iso,bootindex=2",
            ]
        )
        if control_pin is not None:
            control_fd_path = _add_pin(qemu_argv, control_pin, next_fdset)
            next_fdset += 1
            qemu_argv.extend(
                [
                    "-blockdev",
                    _json_option(
                        {
                            "driver": "file",
                            "filename": control_fd_path,
                            "node-name": "control-media-file",
                            "read-only": True,
                        }
                    ),
                    "-blockdev",
                    _json_option(
                        {
                            "driver": "raw",
                            "file": "control-media-file",
                            "node-name": "control-media",
                            "read-only": True,
                        }
                    ),
                    # Deliberately no bootindex: the medium carries an action for
                    # an already-running guest and must never become a boot
                    # source, or a malformed one could change what the machine
                    # runs rather than only what it is asked to do.
                    "-device",
                    "usb-storage,bus=xhci.0,drive=control-media,removable=on",
                ]
            )
        if secure_boot:
            qemu_argv.extend(
                ["-global", "driver=cfi.pflash01,property=secure,value=on"]
            )
        if tpm_required:
            assert swtpm_socket is not None
            qemu_argv.extend(
                [
                    "-chardev",
                    f"socket,id=chrtpm,path={swtpm_socket}",
                    "-tpmdev",
                    "emulator,id=tpm0,chardev=chrtpm",
                    "-device",
                    "tpm-crb,tpmdev=tpm0",
                ]
            )
        swtpm_argv = (
            [
                str(swtpm),
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={tpm_state}",
                "--ctrl",
                f"type=unixio,path={swtpm_socket}",
                "--flags",
                "not-need-init,startup-clear",
                "--terminate",
            ]
            if tpm_required
            else []
        )
        block_nodes = {
            *(f"disk-file-{index}" for index in range(len(disk_chain))),
            *(f"disk-qcow-{index}" for index in range(len(disk_chain))),
            "ovmf-code-file",
            "ovmf-code",
            "ovmf-vars-file",
            "ovmf-vars",
        }
        block_nodes.update({"install-iso-file", "install-iso"})
        if control_pin is not None:
            block_nodes.update({"control-media-file", "control-media"})
        return LaunchPlan(
            workspace,
            qemu_argv,
            swtpm_argv,
            pins,
            [item.path for item in disk_chain],
            iso_path,
            qmp_socket,
            swtpm_socket,
            executable_facts,
            firmware_copy,
            block_nodes,
            allocated_run_id,
            run_directory,
            evidence_directory,
            profile,
            media,
            scenario,
            tpm_required,
            resolved,
            input_file_facts,
        )
    except BaseException:
        for item in pins:
            item.close()
        raise


def _path_from_fd_target(target: str) -> Path | None:
    if target.startswith(("socket:[", "pipe:[", "anon_inode:", "memfd:", "/memfd:")):
        return None
    if target.endswith(" (deleted)"):
        raise lab.LabSafetyError(f"open FD points at a deleted object: {target}")
    if target.startswith("/"):
        return Path(os.path.abspath(target))
    raise lab.LabSafetyError(f"unrecognized open FD target: {target}")


def audit_proc_fds(
    pid: int,
    pins: Iterable[PinnedFile],
    proc_root: Path = Path("/proc"),
) -> list[dict[str, Any]]:
    """Require every QEMU regular-file FD to match an exact preopened identity."""
    approved: dict[tuple[int, int], PinnedFile] = {}
    for pinned in pins:
        if pinned.inode_identity in approved:
            raise lab.LabSafetyError(
                f"duplicate pinned file identity: {pinned.path} and "
                f"{approved[pinned.inode_identity].path}"
            )
        approved[pinned.inode_identity] = pinned
    observed: set[tuple[int, int]] = set()
    evidence: list[dict[str, Any]] = []
    fd_directory = proc_root / str(pid) / "fd"
    try:
        entries = list(fd_directory.iterdir())
    except OSError as error:
        raise lab.LabSafetyError(f"cannot audit QEMU file descriptors: {error}") from error
    for entry in sorted(entries, key=lambda item: int(item.name)):
        try:
            target = os.readlink(entry)
        except OSError as error:
            raise lab.LabSafetyError(f"cannot read QEMU FD {entry}: {error}") from error
        path = _path_from_fd_target(target)
        if path is None:
            evidence.append({"fd": int(entry.name), "target": target, "kind": "anonymous"})
            continue
        try:
            metadata = entry.stat()
        except OSError as error:
            raise lab.LabSafetyError(f"QEMU FD target cannot be verified: {path}: {error}") from error
        if (
            stat.S_ISCHR(metadata.st_mode)
            and path == Path("/dev/null")
            and entry.name in {"0", "1", "2"}
        ):
            evidence.append(
                {"fd": int(entry.name), "target": str(path), "kind": "fixed-stdio"}
            )
            continue
        if stat.S_ISCHR(metadata.st_mode) and path == Path("/dev/kvm"):
            evidence.append({"fd": int(entry.name), "target": str(path), "kind": "kvm"})
            continue
        if stat.S_ISBLK(metadata.st_mode) or stat.S_ISCHR(metadata.st_mode):
            raise lab.LabSafetyError(f"QEMU opened a forbidden host device: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise lab.LabSafetyError(f"QEMU opened an unapproved file descriptor: {path}")
        identity = (metadata.st_dev, metadata.st_ino)
        pinned = approved.get(identity)
        if pinned is None:
            raise lab.LabSafetyError(f"QEMU opened an unpinned regular file: {path}")
        if not pinned.writable and _identity(metadata) != _identity(pinned.metadata):
            raise lab.LabSafetyError(
                f"read-only pinned file changed after validation: {pinned.path}"
            )
        expected_path = Path(os.path.abspath(pinned.path))
        if path != expected_path:
            raise lab.LabSafetyError(
                f"QEMU pinned identity moved from {expected_path} to {path}"
            )
        observed.add(identity)
        evidence.append(
            {
                "fd": int(entry.name),
                "target": str(path),
                "kind": "pinned-regular",
                "label": pinned.label,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            }
        )
    missing = [approved[identity].path for identity in approved.keys() - observed]
    if missing:
        raise lab.LabSafetyError(
            "QEMU did not retain every required pinned file: "
            + ", ".join(str(path) for path in sorted(missing))
        )
    return evidence


def _qmp_paths(value: Any, key: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _qmp_paths(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from _qmp_paths(child, key)
    elif isinstance(value, str) and key in {
        "file",
        "filename",
        "backing_file",
        "backing-filename",
        "full-backing-filename",
    }:
        yield value


def _qmp_node_names(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "node-name" and isinstance(child, str):
                yield child
            else:
                yield from _qmp_node_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from _qmp_node_names(child)


def _qmp_open_option_paths(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "filename" and isinstance(child, str):
                yield child
            else:
                yield from _qmp_open_option_paths(child)
    elif isinstance(value, list):
        for child in value:
            yield from _qmp_open_option_paths(child)


def _qmp_backend_paths(nodes: Any) -> Iterable[str]:
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key in ("file", "backing_file"):
            value = node.get(key)
            if not isinstance(value, str):
                continue
            if not value.startswith("json:"):
                yield value
                continue
            try:
                options = json.loads(
                    value.removeprefix("json:"),
                    object_pairs_hook=_object_without_duplicate_keys,
                    parse_constant=_reject_json_constant,
                )
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise lab.LabSafetyError(
                    "QMP returned invalid serialized block open options"
                ) from error
            yield from _qmp_open_option_paths(options)


def audit_qmp_block(
    query_block: Any,
    query_named_nodes: Any,
    pins: Iterable[PinnedFile],
    expected_nodes: set[str],
) -> dict[str, Any]:
    pinned_files = list(pins)
    if not isinstance(query_block, list) or not query_block:
        raise lab.LabSafetyError("QMP query-block returned no attached block devices")
    if not isinstance(query_named_nodes, list) or not query_named_nodes:
        raise lab.LabSafetyError("QMP query-named-block-nodes returned no block graph")
    approved_fdsets = {
        f"/dev/fdset/{pinned.fdset}"
        for pinned in pinned_files
        if pinned.fdset is not None
    }
    if len(approved_fdsets) != len(pinned_files):
        raise lab.LabSafetyError("every pinned file must have one unique QEMU fdset")
    # Image metadata contains informational host paths even when the live backend
    # was opened exclusively through an inherited fdset. Inspect only each live
    # node's top-level file/backing_file fields, strictly decoding QEMU's json:
    # open-options form. The independent /proc audit below still rejects every
    # unpinned file descriptor and host block/character device before cont.
    observed_paths = set(_qmp_backend_paths(query_named_nodes))
    if not observed_paths:
        raise lab.LabSafetyError("QMP query-block exposed no auditable backend paths")
    unexpected_paths = observed_paths - approved_fdsets
    if unexpected_paths:
        raise lab.LabSafetyError(
            "QMP exposed unapproved block backends: " + ", ".join(sorted(unexpected_paths))
        )
    missing_paths = approved_fdsets - observed_paths
    if missing_paths:
        raise lab.LabSafetyError(
            "QMP block graph omitted pinned fdsets: " + ", ".join(sorted(missing_paths))
        )
    observed_nodes = set(_qmp_node_names(query_named_nodes))
    if observed_nodes != expected_nodes:
        raise lab.LabSafetyError(
            "QMP block-node mismatch; missing="
            f"{sorted(expected_nodes - observed_nodes)}, unexpected="
            f"{sorted(observed_nodes - expected_nodes)}"
        )
    return {
        "fdsets": sorted(observed_paths),
        "nodes": sorted(observed_nodes),
        "attached_devices": len(query_block),
    }


def _terminate(process: subprocess.Popen[Any] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _assert_pinned_disk_invariants(plan: LaunchPlan) -> None:
    overlays = [item for item in plan.pins if item.label == "VM disk"]
    if len(overlays) != 1 or os.fstat(overlays[0].descriptor).st_nlink != 1:
        raise lab.LabSafetyError("top writable qcow2 overlay must retain exactly one link")
    backings = [item for item in plan.pins if item.label == "backing file"]
    if not backings:
        raise lab.LabSafetyError("writable qcow2 overlay has no immutable backing file")
    for backing in backings:
        if os.fstat(backing.descriptor).st_mode & 0o222:
            raise lab.LabSafetyError(f"qcow2 base/backing file is writable: {backing.path}")


def launch(plan: LaunchPlan) -> int:
    if os.getuid() == 0 or os.geteuid() == 0:
        raise lab.LabSafetyError("refusing to launch QEMU as root")
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise lab.LabSafetyError("refusing to launch from a set-id process identity")
    swtpm_process: subprocess.Popen[Any] | None = None
    qemu_process: subprocess.Popen[Any] | None = None
    environment = lab.subprocess_environment(plan.run_directory)
    try:
        _assert_pinned_disk_invariants(plan)
        if plan.tpm_required:
            if plan.swtpm_socket is None or not plan.swtpm_argv:
                raise lab.LabSafetyError("TPM scenario has no fresh swtpm state")
            _assert_executable_identity(plan.executable_facts["swtpm"])
            swtpm_process = subprocess.Popen(
                plan.swtpm_argv,
                close_fds=True,
                cwd=plan.run_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            deadline = time.monotonic() + QMP_TIMEOUT_SECONDS
            while not plan.swtpm_socket.exists():
                if swtpm_process.poll() is not None:
                    raise lab.LabSafetyError("swtpm exited before creating its socket")
                if time.monotonic() >= deadline:
                    raise lab.LabSafetyError("swtpm socket did not become ready")
                time.sleep(0.05)
        _assert_executable_identity(plan.executable_facts["qemu"])
        qemu_process = subprocess.Popen(
            plan.qemu_argv,
            close_fds=True,
            cwd=plan.run_directory,
            env=environment,
            pass_fds=tuple(item.descriptor for item in plan.pins),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        with QMPClient(plan.qmp_socket) as qmp:
            block_state = qmp.execute("query-block")
            named_block_nodes = qmp.execute("query-named-block-nodes")
            qmp_evidence = audit_qmp_block(
                block_state,
                named_block_nodes,
                plan.pins,
                plan.block_nodes,
            )
            proc_evidence = audit_proc_fds(
                qemu_process.pid,
                plan.pins,
            )
            _assert_pinned_disk_invariants(plan)
            lab.atomic_write_json(
                plan.evidence_directory / "direct-qemu-launch.json",
                {
                    "schema_version": 1,
                    "audited_while_paused": True,
                    "qemu_pid": qemu_process.pid,
                    "recorded_at_unix_ns": time.time_ns(),
                    "plan": plan.as_dict(),
                    "qmp_block_graph": qmp_evidence,
                    "proc_fds": proc_evidence,
                },
            )
            qmp.execute("cont")
        return qemu_process.wait()
    except BaseException:
        _terminate(qemu_process)
        _terminate(swtpm_process)
        raise
    finally:
        if qemu_process is not None and qemu_process.poll() is not None:
            _terminate(swtpm_process)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("dry-run", "launch"))
    result.add_argument("--workspace", required=True, help="private VM workspace")
    result.add_argument("--disk", required=True, help="immutable read-only qcow2 base image")
    result.add_argument("--iso", required=True, help="official installation ISO")
    result.add_argument("--profile", required=True, choices=sorted(PROFILE_FILES))
    result.add_argument("--scenario", required=True, help="exact profile scenario ID")
    result.add_argument(
        "--resolved-inputs",
        required=True,
        help="JSON object resolving every required profile SHA256 input",
    )
    result.add_argument(
        "--input-files",
        required=True,
        help="JSON object mapping canonical artifact roles to immutable files",
    )
    result.add_argument("--run-id", help="unique caller-owned run ID; generated if omitted")
    result.add_argument(
        "--control-media",
        help=(
            "optional read-only image carrying one authorised action. Attached "
            "without a bootindex, so it can never become a boot source"
        ),
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    plan: LaunchPlan | None = None
    try:
        resolved_inputs = _load_json(
            _regular_path(arguments.resolved_inputs, label="resolved profile inputs", suffix=".json"),
            "resolved profile inputs",
        )
        input_files = _load_json(
            _regular_path(arguments.input_files, label="profile input files", suffix=".json"),
            "profile input files",
        )
        plan = prepare_launch(
            arguments.workspace,
            arguments.disk,
            arguments.iso,
            profile_id=arguments.profile,
            scenario_id=arguments.scenario,
            resolved_inputs=resolved_inputs,
            input_files=input_files,
            run_id=arguments.run_id,
            control_media=arguments.control_media,
        )
        if arguments.command == "dry-run":
            print(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
            return 0
        return launch(plan)
    except (lab.LabSafetyError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    finally:
        if plan is not None:
            plan.close()


if __name__ == "__main__":
    raise SystemExit(main())
