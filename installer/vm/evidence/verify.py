#!/usr/bin/env python3
"""Fail-closed verifier for canonical JStack Windows VM evidence bundles."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable


CONTRACT = "jstack.vm.run-evidence"
CAMPAIGN_RUN_CONTRACT = "jstack.vm.campaign-run-bundle"
SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_WINDOWS_ISO_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_RECORDS_PER_COLLECTION = 10000

RELEASE_SIGNATURE_DOMAIN = b"JSTACK-RELEASE-MANIFEST-V1\0"
MUTATING_ACTION_RISKS = frozenset(
    {
        "staging_mutation",
        "filesystem_mutation",
        "security_mutation",
        "disk_mutation",
        "boot_mutation",
        "reboot",
    }
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RFC3339_UTC_RE = re.compile(
    r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$"
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
UEFI_BOOT_ID_RE = re.compile(r"^uefi:Boot[0-9A-F]{4}$")

INSTALLER_ROOT = Path(__file__).resolve().parents[2]
CORE_SCHEMA_DIR = INSTALLER_ROOT / "core" / "schemas"
TRACE_SCHEMA_PATH = INSTALLER_ROOT / "model" / "trace-schema.json"
STATE_MODEL_TOOL_PATH = INSTALLER_ROOT / "tools" / "state_model.py"

HANDOFF_BINDINGS = {
    "windows.reboot_to_installer_pending": ("installer", "windows_handoff"),
}

_VERIFIED_CAMPAIGN_RUNS: set[tuple[str, str, str, str]] = set()

INTERRUPTION_BOUNDARIES = (
    "before-intent-persistence",
    "after-intent-flush-before-mutation",
    "during-mutation-before-visible-effect",
    "during-mutation-after-partial-effect",
    "after-mutation-before-observation",
    "after-observation-before-commit",
    "after-commit-before-state-advance",
    "before-and-after-reboot-or-firmware-handoff",
)

REQUIRED_WITNESS_KINDS = (
    "windows-pre-install",
    "windows-post-deploy",
    "jstack-first-boot",
    "cold-boot-windows",
    "cold-boot-jstack",
)

SUPPORTED_PROFILES = {
    "windows-10-pro-22h2-en-us-x64-q35-11.0.nosecureboot-notpm-bitlocker-off": {
        "id": "windows-10-pro-22h2-en-us-x64-q35-11.0.nosecureboot-notpm-bitlocker-off",
        "support_profile_id": "windows-10-pro-22h2-en-us-x64-q35-11.0",
        "scenario_id": "nosecureboot-notpm-bitlocker-off",
        "windows_family": "windows-10",
        "windows_release": "22h2",
        "windows_edition": "pro",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": False,
        "tpm": "absent",
        "bitlocker": False,
    },
    "windows-10-pro-22h2-en-us-x64-q35-11.0.nosecureboot-tpm-bitlocker-off": {
        "id": "windows-10-pro-22h2-en-us-x64-q35-11.0.nosecureboot-tpm-bitlocker-off",
        "support_profile_id": "windows-10-pro-22h2-en-us-x64-q35-11.0",
        "scenario_id": "nosecureboot-tpm-bitlocker-off",
        "windows_family": "windows-10",
        "windows_release": "22h2",
        "windows_edition": "pro",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": False,
        "tpm": "2.0",
        "bitlocker": False,
    },
    "windows-10-pro-22h2-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-off": {
        "id": "windows-10-pro-22h2-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-off",
        "support_profile_id": "windows-10-pro-22h2-en-us-x64-q35-11.0",
        "scenario_id": "secureboot-tpm-bitlocker-off",
        "windows_family": "windows-10",
        "windows_release": "22h2",
        "windows_edition": "pro",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": True,
        "tpm": "2.0",
        "bitlocker": False,
    },
    "windows-10-pro-22h2-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-on": {
        "id": "windows-10-pro-22h2-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-on",
        "support_profile_id": "windows-10-pro-22h2-en-us-x64-q35-11.0",
        "scenario_id": "secureboot-tpm-bitlocker-on",
        "windows_family": "windows-10",
        "windows_release": "22h2",
        "windows_edition": "pro",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": True,
        "tpm": "2.0",
        "bitlocker": True,
    },
    "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.nosecureboot-tpm-bitlocker-off": {
        "id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.nosecureboot-tpm-bitlocker-off",
        "support_profile_id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0",
        "scenario_id": "nosecureboot-tpm-bitlocker-off",
        "windows_family": "windows-11",
        "windows_release": "25h2",
        "windows_edition": "enterprise-evaluation",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": False,
        "tpm": "2.0",
        "bitlocker": False,
    },
    "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-off": {
        "id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-off",
        "support_profile_id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0",
        "scenario_id": "secureboot-tpm-bitlocker-off",
        "windows_family": "windows-11",
        "windows_release": "25h2",
        "windows_edition": "enterprise-evaluation",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": True,
        "tpm": "2.0",
        "bitlocker": False,
    },
    "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-on": {
        "id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0.secureboot-tpm-bitlocker-on",
        "support_profile_id": "windows-11-enterprise-25h2-eval-en-us-x64-q35-11.0",
        "scenario_id": "secureboot-tpm-bitlocker-on",
        "windows_family": "windows-11",
        "windows_release": "25h2",
        "windows_edition": "enterprise-evaluation",
        "architecture": "x86-64",
        "firmware": "uefi",
        "partition_table": "gpt",
        "secure_boot": True,
        "tpm": "2.0",
        "bitlocker": True,
    },
}

POST_MUTATION_CHECKPOINTS = (
    "gpt-written",
    "esp-written",
    "firmware-written",
    "root-deployed",
    "handoff-committed",
)

HAPPY_JOURNAL_STATES = (
    "run.created",
    "preflight.verified",
    "plan.confirmed",
    "mutation.started",
    "mutation.completed",
    "observation.completed",
    "handoff.committed",
    "terminal.completed",
)

JOURNAL_TRANSITIONS = {
    ("run.created", "preflight.verified"): "verify-preconditions",
    ("preflight.verified", "plan.confirmed"): "confirm-plan",
    ("plan.confirmed", "mutation.started"): "begin-mutation",
    ("mutation.started", "mutation.completed"): "finish-mutation",
    ("mutation.completed", "observation.completed"): "verify-mutation",
    ("observation.completed", "handoff.committed"): "commit-handoff",
    ("handoff.committed", "terminal.completed"): "complete-run",
}

JOURNAL_OBSERVATIONS = {
    "run.created": (("bundle-created",), ("run-identity-bound",)),
    "preflight.verified": (("run-identity-bound",), ("preconditions-verified",)),
    "plan.confirmed": (("preconditions-verified",), ("plan-confirmed",)),
    "mutation.started": (("plan-confirmed",), ("mutation-intent-persisted",)),
    "mutation.completed": (("mutation-intent-persisted",), ("mutation-visible",)),
    "observation.completed": (("mutation-visible",), ("postconditions-verified",)),
    "handoff.committed": (("postconditions-verified",), ("handoff-durable",)),
    "terminal.completed": (("handoff-durable",), ("dual-boot-verified",)),
    "recovery.started": (("recovery-required",), ("recovery-entered",)),
    "recovery.completed": (("recovery-entered",), ("dual-boot-verified",)),
    "terminal.rolled_back": (
        ("recovery-entered",),
        ("initial-state-restored", "jstack-artifacts-absent"),
    ),
    "recovery.manual": (("recovery-entered",), ("manual-recovery-required",)),
}

REQUIRED_ARTIFACT_ROLES = (
    "source-tree",
    "state-model",
    "release-manifest",
    "release-acceptance",
    "staging-evidence",
    "confirmed-plan",
    "disk-identity",
    "windows-iso-hash-document",
    "windows-iso",
    "qemu-command-line",
    "base-image-identity",
    "overlay-identity",
    "ovmf-code-identity",
    "ovmf-vars-identity",
    "tpm-state-identity",
    "windows-inventory-initial",
    "windows-inventory-final",
    "gpt-initial",
    "gpt-final",
    "esp-initial",
    "esp-final",
    "firmware-initial",
    "firmware-final",
    "tpm-initial",
    "tpm-final",
    "bitlocker-initial",
    "bitlocker-final",
    "boot-data-initial",
    "boot-data-final",
    "journal",
    "handoff",
    "windows-pre-install-boot-witness",
    "windows-post-deploy-boot-witness",
    "jstack-first-boot-witness",
    "cold-boot-windows-witness",
    "cold-boot-jstack-witness",
    "log",
    "screenshot",
    "serial-output",
    "guest-output",
    "disk-inspection-initial",
    "disk-inspection-final",
    "runtime",
    "adapters",
    "release-policy",
    "resolved-profile-record",
    "official-media-record",
    "boot-artifacts",
    "vm-harness",
    "evidence-verifier",
    "campaign-index",
)

MANDATORY_FAULT_CLASSES = (
    "enospc-staging",
    "enospc-journal",
    "enospc-esp-xbootldr",
    "enospc-destination-temporary-object",
    "enospc-root-deployment",
    "windows-sharing-violation",
    "windows-locked-file",
    "symlink-substitution",
    "reparse-point-substitution",
    "artifact-tamper",
    "staging-evidence-tamper",
    "handoff-tamper",
    "journal-tamper",
    "gpt-tamper",
    "esp-tamper",
    "destination-tamper",
    "stale-disk-identity",
    "stale-partition-identity",
    "stale-plan-identity",
    "stale-release-identity",
    "stale-graph-identity",
    "stale-boot-entry-identity",
    "torn-record",
    "duplicated-record",
    "reordered-record",
    "equivocated-record",
    "oversized-record",
    "corrupted-record",
    "invalid-signature",
    "expired-release",
    "rollback-attempt",
    "clock-rollback",
    "missing-bitlocker-recovery-confirmation",
    "insufficient-bitlocker-recovery-confirmation",
    "secure-boot-valid-chain",
    "secure-boot-invalid-chain",
    "secure-boot-incomplete-chain",
    "bootnext-failure",
    "bootnext-bounded-rearm",
    "bootnext-exhausted-rearm",
    "firmware-variable-write-failure",
    "cancel-before-mutation",
    "rollback-request",
    "windows-resume-failure",
    "finalizer-failure",
    "jstack-first-boot-failure",
    "repeated-recovery-boots",
    "rollback-interruption",
)


class EvidenceError(RuntimeError):
    """Raised when evidence is unsafe, ambiguous, incomplete, or inconsistent."""


def _reject_float(value: str) -> Any:
    raise EvidenceError(f"floating-point JSON numbers are forbidden: {value}")


def _reject_constant(value: str) -> Any:
    raise EvidenceError(f"non-finite JSON number is forbidden: {value}")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize the contract's canonical JSON form: UTF-8, sorted, compact, LF."""
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeError) as error:
        raise EvidenceError(f"value cannot be canonically serialized: {error}") from error
    return (text + "\n").encode("utf-8")


def canonical_json_document_bytes(value: Any) -> bytes:
    """Serialize core canonical JSON without a trailing line feed."""
    return canonical_json_bytes(value)[:-1]


def _decode_json_bytes(raw: bytes, where: str) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvidenceError(f"{where} has a forbidden UTF-8 BOM")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{where} is not valid UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except EvidenceError:
        raise
    except json.JSONDecodeError as error:
        raise EvidenceError(f"{where} is not valid JSON: {error}") from error


def _load_json_artifact(
    root: Path,
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
    role: str,
    *,
    canonical: str | None,
) -> tuple[Any, bytes]:
    record = artifacts[by_role[role]]
    path = root.joinpath(*PurePosixPath(record["path"]).parts)
    raw = path.read_bytes()
    value = _decode_json_bytes(raw, f"{role} artifact")
    expected = {
        "compact": canonical_json_document_bytes,
        "compact-lf": canonical_json_bytes,
    }
    if canonical is not None and raw != expected[canonical](value):
        raise EvidenceError(f"{role} artifact is not canonical JSON")
    return value, raw


def load_canonical_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise EvidenceError(f"manifest may not be a symlink: {path}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"manifest must be a regular file: {path}")
    if metadata.st_size > MAX_MANIFEST_BYTES:
        raise EvidenceError(
            f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {metadata.st_size}"
        )
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvidenceError("UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("manifest is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except EvidenceError:
        raise
    except json.JSONDecodeError as error:
        raise EvidenceError(f"manifest is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError("manifest root must be an object")
    if raw != canonical_json_bytes(value):
        raise EvidenceError("manifest is not canonical JSON")
    return value, raw


@lru_cache(maxsize=1)
def _core_contract_validators() -> dict[str, Any]:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
    except ImportError as error:  # pragma: no cover - packaging gate
        raise EvidenceError(
            "python-jsonschema and referencing are required for core contract validation"
        ) from error

    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Any]] = []
    try:
        paths = sorted(CORE_SCHEMA_DIR.glob("*.schema.json"))
        if not paths:
            raise OSError("no core contract schemas found")
        for path in paths:
            schema = _decode_json_bytes(path.read_bytes(), f"checked-in schema {path.name}")
            if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
                raise EvidenceError(f"checked-in schema {path.name} lacks a canonical $id")
            schemas[path.name] = schema
            resources.append((schema["$id"], Resource.from_contents(schema)))
    except OSError as error:
        raise EvidenceError("checked-in core contract schemas cannot be read") from error

    registry = Registry().with_resources(resources)
    validators: dict[str, Any] = {}
    for name in (
        "install-plan.schema.json",
        "plan-display.schema.json",
        "confirmation.schema.json",
        "journal-chain.schema.json",
        "handoff.schema.json",
    ):
        schema = schemas.get(name)
        if schema is None:
            raise EvidenceError(f"required checked-in core schema is missing: {name}")
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
    return validators


def _validate_core_contract(value: Any, schema_name: str, where: str) -> None:
    validator = _core_contract_validators()[schema_name]
    errors = sorted(
        validator.iter_errors(value),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path)
        suffix = f" at {location}" if location else ""
        raise EvidenceError(
            f"{where} violates checked-in {schema_name}{suffix}: {error.message}"
        )


@lru_cache(maxsize=1)
def _state_model_tool() -> Any:
    spec = importlib.util.spec_from_file_location(
        "jstack_vm_evidence_state_model", STATE_MODEL_TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise EvidenceError("checked-in state-model validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, ImportError, RuntimeError) as error:
        raise EvidenceError("checked-in state-model validator cannot be loaded") from error
    return module


@lru_cache(maxsize=1)
def _trace_schema() -> tuple[dict[str, Any], str]:
    try:
        raw = TRACE_SCHEMA_PATH.read_bytes()
    except OSError as error:
        raise EvidenceError("checked-in graph trace schema cannot be read") from error
    schema = _decode_json_bytes(raw, "checked-in graph trace schema")
    if not isinstance(schema, dict):
        raise EvidenceError("checked-in graph trace schema must be an object")
    return schema, hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=1)
def _trace_validator() -> Any:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as error:  # pragma: no cover - packaging gate
        raise EvidenceError("python-jsonschema is required for graph trace validation") from error
    schema, _ = _trace_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_document_bytes(value)).hexdigest()


def _plan_display(plan: dict[str, Any]) -> dict[str, Any]:
    body = plan["body"]
    resize = body["windows_resize"]
    return {
        "schema_version": 1,
        "plan_hash": plan["plan_hash"],
        "disk_guid": body["disk_guid"],
        "windows_partition_guid": resize["partition_guid"],
        "windows_original_size_bytes": resize["original_size_bytes"],
        "windows_target_size_bytes": resize["target_size_bytes"],
        "allocation_interval": body["allocation_interval"],
        "created_partitions": body["created_partitions"],
    }


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{where} must be an object")
    return value


def _array(value: Any, where: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{where} must be an array")
    if nonempty and not value:
        raise EvidenceError(f"{where} must not be empty")
    if len(value) > MAX_RECORDS_PER_COLLECTION:
        raise EvidenceError(f"{where} exceeds {MAX_RECORDS_PER_COLLECTION} records")
    return value


def _exact_keys(
    value: dict[str, Any], required: Iterable[str], where: str, optional: Iterable[str] = ()
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise EvidenceError(f"{where} is missing fields: {', '.join(missing)}")
    if unknown:
        raise EvidenceError(f"{where} has unknown fields: {', '.join(unknown)}")


def _require_keys(value: dict[str, Any], required: Iterable[str], where: str) -> None:
    missing = sorted(set(required) - value.keys())
    if missing:
        raise EvidenceError(f"{where} is missing fields: {', '.join(missing)}")


def _string(value: Any, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{where} must be a string")
    if nonempty and not value:
        raise EvidenceError(f"{where} must not be empty")
    if any(ord(character) < 0x20 for character in value):
        raise EvidenceError(f"{where} contains a control character")
    return value


def _boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise EvidenceError(f"{where} must be a boolean")
    return value


def _integer(
    value: Any, where: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if type(value) is not int or value < minimum or (
        maximum is not None and value > maximum
    ):
        bound = f" and <= {maximum}" if maximum is not None else ""
        raise EvidenceError(f"{where} must be an integer >= {minimum}{bound}")
    return value


def _identifier(value: Any, where: str) -> str:
    result = _string(value, where)
    if not ID_RE.fullmatch(result):
        raise EvidenceError(f"{where} is not a canonical lowercase identifier: {result!r}")
    return result


def _digest(value: Any, where: str) -> str:
    result = _string(value, where)
    if not SHA256_RE.fullmatch(result):
        raise EvidenceError(f"{where} must be a lowercase SHA-256 digest")
    return result


def _hex_bytes(value: Any, where: str, length: int) -> bytes:
    text = _string(value, where)
    if len(text) != length * 2 or not re.fullmatch(r"[0-9a-f]+", text):
        raise EvidenceError(f"{where} must be {length} lowercase hexadecimal bytes")
    return bytes.fromhex(text)


def _timestamp(value: Any, where: str) -> str:
    result = _string(value, where)
    if not RFC3339_UTC_RE.fullmatch(result):
        raise EvidenceError(f"{where} must be second-precision RFC3339 UTC")
    try:
        datetime.strptime(result, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise EvidenceError(f"{where} is not a real UTC timestamp") from error
    return result


def _uuid(value: Any, where: str) -> str:
    result = _string(value, where)
    if not UUID_RE.fullmatch(result):
        raise EvidenceError(f"{where} must be a canonical lowercase UUID")
    return result


def _unique(values: Iterable[Any], where: str) -> None:
    seen: set[Any] = set()
    for value in values:
        if value in seen:
            raise EvidenceError(f"duplicate logical record in {where}: {value!r}")
        seen.add(value)


def _sorted_unique_strings(value: Any, where: str) -> list[str]:
    values = [_identifier(item, f"{where}[]") for item in _array(value, where)]
    _unique(values, where)
    if values != sorted(values):
        raise EvidenceError(f"{where} must be sorted")
    return values


def _safe_artifact_path(root: Path, raw_path: Any, where: str) -> Path:
    value = _string(raw_path, where)
    if "\\" in value or "\x00" in value:
        raise EvidenceError(f"{where} is not a canonical POSIX relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise EvidenceError(f"{where} must be a normalized relative path without escape")
    if value != pure.as_posix():
        raise EvidenceError(f"{where} must be a byte-normalized POSIX path")
    if pure.parts[0] != "artifacts":
        raise EvidenceError(f"{where} must be below artifacts/")

    candidate = root.joinpath(*pure.parts)
    current = root
    for component in pure.parts:
        current /= component
        if current.is_symlink():
            raise EvidenceError(f"artifact path contains a symlink: {value}")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise EvidenceError(f"artifact path does not resolve safely: {value}") from error
    if resolved_root not in resolved.parents:
        raise EvidenceError(f"artifact path escapes bundle: {value}")
    try:
        metadata = resolved.stat()
    except OSError as error:
        raise EvidenceError(f"artifact cannot be inspected safely: {value}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceError(f"artifact is not a regular file: {value}")
    if metadata.st_nlink != 1:
        raise EvidenceError(f"artifact may not be hard-linked: {value}")
    return resolved


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise EvidenceError(f"artifact cannot be read safely: {path}") from error
    return digest.hexdigest()


def _verify_artifacts(root: Path, value: Any) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    records = _array(value, "artifacts")
    by_id: dict[str, dict[str, Any]] = {}
    by_role: dict[str, str] = {}
    paths: list[str] = []
    digests: list[str] = []
    bounded_total_size = 0
    for index, raw in enumerate(records):
        where = f"artifacts[{index}]"
        record = _object(raw, where)
        _exact_keys(record, ("id", "role", "path", "size", "sha256"), where)
        artifact_id = _identifier(record["id"], f"{where}.id")
        role = _identifier(record["role"], f"{where}.role")
        if role not in REQUIRED_ARTIFACT_ROLES:
            raise EvidenceError(f"{where}.role is unknown: {role}")
        path_text = _string(record["path"], f"{where}.path")
        declared_size = _integer(record["size"], f"{where}.size")
        declared_digest = _digest(record["sha256"], f"{where}.sha256")
        size_limit = MAX_WINDOWS_ISO_BYTES if role == "windows-iso" else MAX_ARTIFACT_BYTES
        if declared_size > size_limit:
            raise EvidenceError(f"{where} exceeds the per-artifact size limit")
        path = _safe_artifact_path(root, path_text, f"{where}.path")
        actual_size = path.stat().st_size
        if actual_size > size_limit:
            raise EvidenceError(f"{where} actual file exceeds the per-artifact size limit")
        if actual_size != declared_size:
            raise EvidenceError(
                f"artifact size mismatch for {artifact_id}: declared {declared_size}, actual {actual_size}"
            )
        actual_digest = _hash_file(path)
        if actual_digest != declared_digest:
            raise EvidenceError(
                f"artifact hash mismatch for {artifact_id}: declared {declared_digest}, actual {actual_digest}"
            )
        if artifact_id in by_id:
            raise EvidenceError(f"duplicate logical artifact id: {artifact_id}")
        if role in by_role:
            raise EvidenceError(f"duplicate logical artifact role: {role}")
        by_id[artifact_id] = record
        by_role[role] = artifact_id
        paths.append(path_text)
        digests.append(declared_digest)
        if role != "windows-iso":
            bounded_total_size += actual_size
        if bounded_total_size > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceError("artifacts exceed the aggregate size limit")
    _unique(paths, "artifact paths")
    _unique(digests, "artifact content digests")
    missing_roles = sorted(set(REQUIRED_ARTIFACT_ROLES) - by_role.keys())
    if missing_roles:
        raise EvidenceError(f"missing required artifact roles: {', '.join(missing_roles)}")
    return by_id, by_role


def _artifact_digest(
    artifacts: dict[str, dict[str, Any]], by_role: dict[str, str], role: str
) -> str:
    return artifacts[by_role[role]]["sha256"]


def _verify_profiles(value: Any) -> dict[str, dict[str, Any]]:
    records = _array(value, "profiles")
    profiles: dict[str, dict[str, Any]] = {}
    expected_keys = tuple(next(iter(SUPPORTED_PROFILES.values())).keys())
    for index, raw in enumerate(records):
        where = f"profiles[{index}]"
        record = _object(raw, where)
        _exact_keys(record, expected_keys, where)
        profile_id = _identifier(record["id"], f"{where}.id")
        if profile_id in profiles:
            raise EvidenceError(f"duplicate logical profile id: {profile_id}")
        for field in (
            "support_profile_id",
            "scenario_id",
            "windows_family",
            "windows_release",
            "windows_edition",
            "architecture",
            "firmware",
            "partition_table",
            "tpm",
        ):
            _string(record[field], f"{where}.{field}")
        _boolean(record["secure_boot"], f"{where}.secure_boot")
        _boolean(record["bitlocker"], f"{where}.bitlocker")
        expected = SUPPORTED_PROFILES.get(profile_id)
        if expected is None or record != expected:
            raise EvidenceError(f"{where} is not an immutable supported profile")
        profiles[profile_id] = record
    if list(profiles) != sorted(SUPPORTED_PROFILES):
        raise EvidenceError("profiles must be the complete immutable supported set in order")
    return profiles


IDENTITY_FIELDS = (
    "graph_digest",
    "release_digest",
    "release_acceptance_digest",
    "staging_evidence_digest",
    "plan_digest",
    "disk_identity",
    "release_policy_digest",
    "profile_digest",
    "media_digest",
    "journal_digest",
    "handoff_digest",
)
VM_IDENTITY_FIELDS = ("vm_id", "machine_uuid", "smbios_uuid", "disk_serial")


def _identity_tuple(value: dict[str, Any], where: str) -> tuple[str, ...]:
    _exact_keys(value, IDENTITY_FIELDS, where)
    return tuple(_digest(value[field], f"{where}.{field}") for field in IDENTITY_FIELDS)  # type: ignore[return-value]


def _vm_identity_tuple(value: dict[str, Any], where: str) -> tuple[str, str, str, str]:
    _exact_keys(value, VM_IDENTITY_FIELDS, where)
    vm_id = _identifier(value["vm_id"], f"{where}.vm_id")
    machine_uuid = _uuid(value["machine_uuid"], f"{where}.machine_uuid")
    smbios_uuid = _uuid(value["smbios_uuid"], f"{where}.smbios_uuid")
    disk_serial = _identifier(value["disk_serial"], f"{where}.disk_serial")
    if machine_uuid != smbios_uuid:
        raise EvidenceError(f"{where} machine_uuid and smbios_uuid disagree")
    return vm_id, machine_uuid, smbios_uuid, disk_serial


def _artifact_reference(
    value: Any,
    where: str,
    expected_role: str,
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
) -> str:
    reference = _identifier(value, where)
    if reference not in artifacts or reference != by_role[expected_role]:
        raise EvidenceError(f"{where} does not reference the {expected_role} artifact")
    return reference


def _verify_run(value: Any, profiles: dict[str, dict[str, Any]]) -> dict[str, Any]:
    run = _object(value, "run")
    _exact_keys(
        run,
        (
            "id",
            "scenario_id",
            "profile_id",
            "started_at",
            "finished_at",
            "final_outcome",
            "source_commit",
            "clean_tree_digest",
        ),
        "run",
    )
    _identifier(run["id"], "run.id")
    _identifier(run["scenario_id"], "run.scenario_id")
    profile_id = _identifier(run["profile_id"], "run.profile_id")
    if profile_id not in profiles:
        raise EvidenceError(f"run.profile_id is unknown: {profile_id}")
    started = _timestamp(run["started_at"], "run.started_at")
    finished = _timestamp(run["finished_at"], "run.finished_at")
    if finished < started:
        raise EvidenceError("run.finished_at precedes run.started_at")
    if run["final_outcome"] not in (
        "terminal.completed",
        "terminal.rolled_back",
        "recovery.completed",
        "recovery.manual",
    ):
        raise EvidenceError("run.final_outcome is unknown")
    _digest(run["source_commit"], "run.source_commit")
    _digest(run["clean_tree_digest"], "run.clean_tree_digest")
    return run


def _verify_identity(
    value: Any,
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
) -> tuple[str, ...]:
    identity = _object(value, "identity")
    _exact_keys(
        identity,
        IDENTITY_FIELDS,
        "identity",
    )
    expected_roles = {
        "graph_digest": "state-model",
        "release_acceptance_digest": "release-acceptance",
        "staging_evidence_digest": "staging-evidence",
        "disk_identity": "disk-identity",
        "release_policy_digest": "release-policy",
        "profile_digest": "resolved-profile-record",
        "media_digest": "official-media-record",
        "journal_digest": "journal",
        "handoff_digest": "handoff",
    }
    for field, role in expected_roles.items():
        digest = _digest(identity[field], f"identity.{field}")
        if digest != _artifact_digest(artifacts, by_role, role):
            raise EvidenceError(f"identity.{field} disagrees with {role} artifact")
    for field in ("release_digest", "plan_digest"):
        _digest(identity[field], f"identity.{field}")
    return tuple(identity[field] for field in IDENTITY_FIELDS)


def _derive_mutation_transitions(
    value: Any,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    graph = _object(value, "state-model artifact")
    _exact_keys(
        graph,
        (
            "schema_version",
            "model_id",
            "initial_state",
            "scope",
            "actors",
            "actor_platforms",
            "guards",
            "actions",
            "invariants",
            "states",
            "transitions",
        ),
        "state-model artifact",
    )
    if _integer(graph["schema_version"], "state-model.schema_version", minimum=1) != 1:
        raise EvidenceError("state-model.schema_version is unsupported")
    model_id = _identifier(graph["model_id"], "state-model.model_id")
    actions: dict[str, str] = {}
    for index, raw in enumerate(_array(graph["actions"], "state-model.actions")):
        where = f"state-model.actions[{index}]"
        action = _object(raw, where)
        _require_keys(action, ("id", "risk"), where)
        action_id = _identifier(action["id"], f"{where}.id")
        if action_id in actions:
            raise EvidenceError(f"duplicate state-model action id: {action_id}")
        actions[action_id] = _identifier(action["risk"], f"{where}.risk")

    transition_ids: list[str] = []
    mutation_ids: list[str] = []
    failure_edge_ids: list[str] = []
    for index, raw in enumerate(_array(graph["transitions"], "state-model.transitions")):
        where = f"state-model.transitions[{index}]"
        transition = _object(raw, where)
        _require_keys(transition, ("id", "actions"), where)
        transition_id = _identifier(transition["id"], f"{where}.id")
        transition_ids.append(transition_id)
        action_ids = [
            _identifier(item, f"{where}.actions[]")
            for item in _array(transition["actions"], f"{where}.actions", nonempty=False)
        ]
        _unique(action_ids, f"{where}.actions")
        unknown = [action_id for action_id in action_ids if action_id not in actions]
        if unknown:
            raise EvidenceError(f"{where} references unknown actions: {', '.join(unknown)}")
        if any(actions[action_id] in MUTATING_ACTION_RISKS for action_id in action_ids):
            mutation_ids.append(transition_id)
        if "failure_to" in transition:
            _identifier(transition["failure_to"], f"{where}.failure_to")
            failure_edge_ids.append(transition_id)
    _unique(transition_ids, "state-model transition ids")
    if not mutation_ids:
        raise EvidenceError("state-model has no production mutating transitions")
    if not failure_edge_ids:
        raise EvidenceError("state-model has no modeled failure edges")
    return model_id, tuple(mutation_ids), tuple(failure_edge_ids)


def _verify_release_policy(value: Any, graph_id: str, graph_digest: str) -> dict[str, Any]:
    policy = _object(value, "release-policy artifact")
    _exact_keys(
        policy,
        (
            "schema_version",
            "channel",
            "architecture",
            "state_model_id",
            "state_model_sha256",
            "installer_protocol_version",
            "trusted_time_unix_secs",
            "maximum_future_skew_secs",
            "maximum_manifest_lifetime_secs",
            "signature_threshold",
            "trusted_keys",
        ),
        "release-policy artifact",
    )
    if _integer(policy["schema_version"], "release-policy.schema_version", minimum=1) != 1:
        raise EvidenceError("release-policy.schema_version is unsupported")
    if policy["channel"] not in ("stable", "beta"):
        raise EvidenceError("release-policy.channel is unknown")
    if policy["architecture"] != "x86_64":
        raise EvidenceError("release-policy.architecture is unsupported")
    if _identifier(policy["state_model_id"], "release-policy.state_model_id") != graph_id:
        raise EvidenceError("release policy is bound to a different state model id")
    if _digest(policy["state_model_sha256"], "release-policy.state_model_sha256") != graph_digest:
        raise EvidenceError("release policy is bound to a different state model digest")
    _integer(policy["installer_protocol_version"], "release-policy.installer_protocol_version", minimum=1)
    _integer(policy["trusted_time_unix_secs"], "release-policy.trusted_time_unix_secs")
    _integer(policy["maximum_future_skew_secs"], "release-policy.maximum_future_skew_secs")
    _integer(policy["maximum_manifest_lifetime_secs"], "release-policy.maximum_manifest_lifetime_secs", minimum=1)
    threshold = _integer(policy["signature_threshold"], "release-policy.signature_threshold", minimum=1)
    trusted: list[dict[str, Any]] = []
    key_ids: list[str] = []
    for index, raw in enumerate(_array(policy["trusted_keys"], "release-policy.trusted_keys")):
        where = f"release-policy.trusted_keys[{index}]"
        key = _object(raw, where)
        _exact_keys(key, ("key_id", "public_key_hex", "channels"), where)
        public_key = _hex_bytes(key["public_key_hex"], f"{where}.public_key_hex", 32)
        key_id = _digest(key["key_id"], f"{where}.key_id")
        if hashlib.sha256(public_key).hexdigest() != key_id:
            raise EvidenceError(f"{where}.key_id does not identify its Ed25519 public key")
        channels = _sorted_unique_strings(key["channels"], f"{where}.channels")
        if not set(channels) <= {"stable", "beta"}:
            raise EvidenceError(f"{where}.channels contains an unknown channel")
        key_ids.append(key_id)
        trusted.append({"key_id": key_id, "public_key": public_key, "channels": set(channels)})
    _unique(key_ids, "release-policy trusted key ids")
    if key_ids != sorted(key_ids):
        raise EvidenceError("release-policy trusted keys must be sorted by key id")
    eligible = sum(policy["channel"] in key["channels"] for key in trusted)
    if threshold > eligible:
        raise EvidenceError("release-policy signature threshold exceeds eligible trusted keys")
    return {**policy, "trusted_keys": trusted}


def _verify_signed_release(value: Any, policy: dict[str, Any], graph_id: str, graph_digest: str) -> tuple[str, dict[str, Any]]:
    envelope = _object(value, "release-manifest artifact")
    _exact_keys(envelope, ("signed", "signatures"), "release-manifest artifact")
    signed = _object(envelope["signed"], "release-manifest.signed")
    _exact_keys(
        signed,
        (
            "schema_version",
            "product",
            "release_id",
            "release_version",
            "release_sequence",
            "channel",
            "architecture",
            "issued_at_unix_secs",
            "expires_at_unix_secs",
            "state_model_id",
            "state_model_sha256",
            "installer_protocol_min",
            "installer_protocol_max",
            "planner",
            "artifacts",
        ),
        "release-manifest.signed",
    )
    if _integer(signed["schema_version"], "release-manifest.signed.schema_version", minimum=1) != 1:
        raise EvidenceError("release manifest schema version is unsupported")
    if signed["product"] != "jstack-os" or signed["architecture"] != policy["architecture"]:
        raise EvidenceError("release manifest product or architecture is unsupported")
    _identifier(signed["release_id"], "release-manifest.signed.release_id")
    _string(signed["release_version"], "release-manifest.signed.release_version")
    _integer(signed["release_sequence"], "release-manifest.signed.release_sequence", minimum=1)
    if signed["channel"] != policy["channel"]:
        raise EvidenceError("release manifest channel disagrees with release policy")
    if _identifier(signed["state_model_id"], "release-manifest.signed.state_model_id") != graph_id:
        raise EvidenceError("signed release is bound to a different state model id")
    if _digest(signed["state_model_sha256"], "release-manifest.signed.state_model_sha256") != graph_digest:
        raise EvidenceError("signed release is bound to a different state model digest")
    protocol_min = _integer(signed["installer_protocol_min"], "release-manifest.signed.installer_protocol_min", minimum=1)
    protocol_max = _integer(signed["installer_protocol_max"], "release-manifest.signed.installer_protocol_max", minimum=1)
    if not protocol_min <= policy["installer_protocol_version"] <= protocol_max:
        raise EvidenceError("release manifest excludes the policy installer protocol")
    issued = _integer(signed["issued_at_unix_secs"], "release-manifest.signed.issued_at_unix_secs")
    expires = _integer(signed["expires_at_unix_secs"], "release-manifest.signed.expires_at_unix_secs", minimum=1)
    trusted_time = policy["trusted_time_unix_secs"]
    if expires <= issued or expires - issued > policy["maximum_manifest_lifetime_secs"]:
        raise EvidenceError("release manifest lifetime is invalid")
    if issued > trusted_time + policy["maximum_future_skew_secs"] or trusted_time > expires:
        raise EvidenceError("release manifest is not valid at the trusted policy time")

    planner = _object(signed["planner"], "release-manifest.signed.planner")
    _exact_keys(
        planner,
        (
            "alignment_bytes",
            "xbootldr_size_bytes",
            "minimum_root_size_bytes",
            "safety_margin_bytes",
            "minimum_total_allocation_bytes",
            "esp_loader_required_bytes",
        ),
        "release-manifest.signed.planner",
    )
    for field, item in planner.items():
        _integer(item, f"release-manifest.signed.planner.{field}", minimum=0 if field == "safety_margin_bytes" else 1)

    expected_roles = ("esp_loader", "installer_uki", "offline_system_image", "recovery_uki")
    release_artifacts: list[dict[str, Any]] = []
    for index, raw in enumerate(_array(signed["artifacts"], "release-manifest.signed.artifacts")):
        where = f"release-manifest.signed.artifacts[{index}]"
        artifact = _object(raw, where)
        _exact_keys(artifact, ("role", "size_bytes", "sha256", "chunk_size_bytes", "chunk_sha256"), where)
        if artifact["role"] != expected_roles[index] if index < len(expected_roles) else True:
            raise EvidenceError("release artifact roles are not the closed canonical ordered set")
        _integer(artifact["size_bytes"], f"{where}.size_bytes", minimum=1)
        _digest(artifact["sha256"], f"{where}.sha256")
        _integer(artifact["chunk_size_bytes"], f"{where}.chunk_size_bytes", minimum=1)
        chunks = [_digest(item, f"{where}.chunk_sha256[]") for item in _array(artifact["chunk_sha256"], f"{where}.chunk_sha256")]
        release_artifacts.append({**artifact, "chunk_sha256": chunks})
    if len(release_artifacts) != len(expected_roles):
        raise EvidenceError("release manifest does not contain the exact release artifact set")

    body = canonical_json_document_bytes(signed)
    message = RELEASE_SIGNATURE_DOMAIN + len(body).to_bytes(8, "big") + body
    release_digest = hashlib.sha256(message).hexdigest()
    trusted = {key["key_id"]: key for key in policy["trusted_keys"]}
    signature_key_ids: list[str] = []
    valid = 0
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise EvidenceError("Python cryptography Ed25519 support is required") from error
    for index, raw in enumerate(_array(envelope["signatures"], "release-manifest.signatures")):
        where = f"release-manifest.signatures[{index}]"
        signature = _object(raw, where)
        _exact_keys(signature, ("key_id", "signature_hex"), where)
        key_id = _digest(signature["key_id"], f"{where}.key_id")
        signature_key_ids.append(key_id)
        key = trusted.get(key_id)
        if key is None or signed["channel"] not in key["channels"]:
            raise EvidenceError(f"{where} uses an untrusted or wrong-channel key")
        signature_bytes = _hex_bytes(signature["signature_hex"], f"{where}.signature_hex", 64)
        try:
            Ed25519PublicKey.from_public_bytes(key["public_key"]).verify(signature_bytes, message)
        except InvalidSignature as error:
            raise EvidenceError(f"{where} has an invalid Ed25519 signature") from error
        valid += 1
    _unique(signature_key_ids, "release manifest signature key ids")
    if signature_key_ids != sorted(signature_key_ids):
        raise EvidenceError("release manifest signatures must be sorted by key id")
    if valid < policy["signature_threshold"]:
        raise EvidenceError("release manifest has insufficient valid trusted signatures")
    return release_digest, {**signed, "artifacts": release_artifacts}


def _verify_acceptance(value: Any, signed: dict[str, Any], release_digest: str, graph_digest: str) -> None:
    acceptance = _object(value, "release-acceptance artifact")
    _exact_keys(
        acceptance,
        (
            "schema_version",
            "channel",
            "state_model_sha256",
            "highest_sequence",
            "manifest_digest",
            "issued_at_unix_secs",
            "trusted_time_unix_secs",
        ),
        "release-acceptance artifact",
    )
    if acceptance["schema_version"] != 1:
        raise EvidenceError("release acceptance schema version is unsupported")
    expected = (
        acceptance["channel"],
        acceptance["state_model_sha256"],
        acceptance["highest_sequence"],
        acceptance["manifest_digest"],
        acceptance["issued_at_unix_secs"],
    )
    actual = (
        signed["channel"],
        graph_digest,
        signed["release_sequence"],
        release_digest,
        signed["issued_at_unix_secs"],
    )
    if expected != actual:
        raise EvidenceError("durable release acceptance is stale or bound to another release/graph")
    trusted_time = _integer(acceptance["trusted_time_unix_secs"], "release-acceptance.trusted_time_unix_secs")
    if not signed["issued_at_unix_secs"] <= trusted_time <= signed["expires_at_unix_secs"]:
        raise EvidenceError("durable release acceptance trusted time is outside the release lifetime")


def _verify_staging(value: Any, signed: dict[str, Any], release_digest: str, acceptance_digest: str) -> None:
    staging = _object(value, "staging-evidence artifact")
    _exact_keys(staging, ("schema_version", "acceptance_state_hash", "manifest_digest", "artifacts"), "staging-evidence artifact")
    if staging["schema_version"] != 1:
        raise EvidenceError("staging evidence schema version is unsupported")
    if _digest(staging["acceptance_state_hash"], "staging-evidence.acceptance_state_hash") != acceptance_digest:
        raise EvidenceError("staging evidence is bound to a different durable release acceptance")
    if _digest(staging["manifest_digest"], "staging-evidence.manifest_digest") != release_digest:
        raise EvidenceError("staging evidence is bound to a different signed release")
    observed: list[dict[str, Any]] = []
    for index, raw in enumerate(_array(staging["artifacts"], "staging-evidence.artifacts")):
        where = f"staging-evidence.artifacts[{index}]"
        item = _object(raw, where)
        _exact_keys(item, ("role", "sha256", "size_bytes"), where)
        observed.append(
            {
                "role": _identifier(item["role"], f"{where}.role"),
                "sha256": _digest(item["sha256"], f"{where}.sha256"),
                "size_bytes": _integer(item["size_bytes"], f"{where}.size_bytes", minimum=1),
            }
        )
    expected = [
        {"role": item["role"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}
        for item in signed["artifacts"]
    ]
    if observed != expected:
        raise EvidenceError("staging evidence does not bind the exact signed release artifact set")


def _verify_confirmed_plan(
    value: Any, release_digest: str, graph_id: str
) -> tuple[dict[str, Any], str, str]:
    confirmed = _object(value, "confirmed-plan artifact")
    _exact_keys(confirmed, ("schema_version", "plan", "confirmation"), "confirmed-plan artifact")
    if confirmed["schema_version"] != 1:
        raise EvidenceError("confirmed-plan schema version is unsupported")
    plan = _object(confirmed["plan"], "confirmed-plan.plan")
    _validate_core_contract(plan, "install-plan.schema.json", "confirmed-plan.plan")
    body = _object(plan["body"], "confirmed-plan.plan.body")
    plan_hash = _digest(plan["plan_hash"], "confirmed-plan.plan.plan_hash")
    if _canonical_sha256(body) != plan_hash:
        raise EvidenceError("confirmed plan hash does not match its canonical body")
    if _digest(body["release_manifest_hash"], "confirmed-plan.plan.body.release_manifest_hash") != release_digest:
        raise EvidenceError("confirmed plan is bound to a different signed release")
    if _identifier(body["state_model_id"], "confirmed-plan.plan.body.state_model_id") != graph_id:
        raise EvidenceError("confirmed plan is bound to a different state model")
    disk_guid = _uuid(body["disk_guid"], "confirmed-plan.plan.body.disk_guid")
    for field in ("alignment_bytes",):
        _integer(body[field], f"confirmed-plan.plan.body.{field}", maximum=2**64 - 1)
    for field in ("original_size_bytes", "target_size_bytes", "released_bytes"):
        _integer(
            body["windows_resize"][field],
            f"confirmed-plan.plan.body.windows_resize.{field}",
            maximum=2**64 - 1,
        )
    for field in ("start_bytes", "end_bytes"):
        _integer(
            body["allocation_interval"][field],
            f"confirmed-plan.plan.body.allocation_interval.{field}",
            maximum=2**64 - 1,
        )
    for collection in ("before_layout", "after_layout", "created_partitions"):
        for index, partition in enumerate(body[collection]):
            for field in ("offset_bytes", "size_bytes"):
                _integer(
                    partition[field],
                    f"confirmed-plan.plan.body.{collection}[{index}].{field}",
                    maximum=2**64 - 1,
                )

    display = _plan_display(plan)
    _validate_core_contract(display, "plan-display.schema.json", "derived plan display")
    confirmation = _object(confirmed["confirmation"], "confirmed-plan.confirmation")
    _validate_core_contract(
        confirmation, "confirmation.schema.json", "confirmed-plan.confirmation"
    )
    if _digest(confirmation["plan_hash"], "confirmed-plan.confirmation.plan_hash") != plan_hash:
        raise EvidenceError("plan confirmation is stale or bound to another plan")
    if _digest(
        confirmation["display_digest"], "confirmed-plan.confirmation.display_digest"
    ) != _canonical_sha256(display):
        raise EvidenceError("plan confirmation display digest does not match the exact derived plan display")
    _integer(
        confirmation["confirmed_at_unix_ms"],
        "confirmed-plan.confirmation.confirmed_at_unix_ms",
        maximum=2**64 - 1,
    )
    if _string(confirmation["authorization"], "confirmed-plan.confirmation.authorization") != "explicit_user_confirmation":
        raise EvidenceError("confirmed plan lacks explicit user authorization")
    return plan, plan_hash, disk_guid


def _verify_core_journal(
    value: Any,
    plan: dict[str, Any],
    graph: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], str]:
    _validate_core_contract(value, "journal-chain.schema.json", "journal artifact")
    records = _array(value, "journal artifact")
    plan_hash = plan["plan_hash"]
    actors = set(graph["actors"])
    states = {state["id"]: state for state in graph["states"]}
    transitions = {
        transition["id"]: transition for transition in graph["transitions"]
    }
    for transition_id, transition in transitions.items():
        if (
            transition.get("actor") not in actors
            or transition.get("from") not in states
            or transition.get("to") not in states
        ):
            raise EvidenceError(
                f"signed graph transition {transition_id} is outside actor/state membership"
            )
    rollback_objects = {
        (item["kind"], item["stable_id"])
        for item in plan["body"]["rollback_objects"]
    }
    previous_hash: str | None = None
    previous_record: dict[str, Any] | None = None
    resulting_state = ""
    for index, raw in enumerate(records):
        where = f"journal artifact[{index}]"
        record = _object(raw, where)
        if _integer(record["sequence"], f"{where}.sequence", maximum=2**64 - 1) != index:
            raise EvidenceError("journal artifact sequence is not canonical and contiguous")
        if record["previous_record_hash"] != previous_hash:
            raise EvidenceError("journal artifact hash chain is broken")
        if _digest(record["plan_hash"], f"{where}.plan_hash") != plan_hash:
            raise EvidenceError("journal artifact is bound to a different confirmed plan")
        transition_id = record["transition_id"]
        transition = transitions.get(transition_id)
        if transition is None:
            raise EvidenceError(f"{where}.transition_id is not a transition in the signed graph")
        if record["actor"] != transition["actor"]:
            raise EvidenceError(f"{where}.actor does not own transition {transition_id}")
        created = _array(record["created_objects"], f"{where}.created_objects", nonempty=False)
        created_keys: list[tuple[str, str]] = []
        for object_index, raw_object in enumerate(created):
            rollback_object = _object(raw_object, f"{where}.created_objects[{object_index}]")
            key = (rollback_object["kind"], rollback_object["stable_id"])
            created_keys.append(key)
            if key[0] == "boot_entry":
                if transition_id not in ("create_installer_entry", "install_jstack_boot") or not UEFI_BOOT_ID_RE.fullmatch(key[1]):
                    raise EvidenceError(f"{where} contains an unowned UEFI boot entry")
            elif key not in rollback_objects:
                raise EvidenceError(f"{where} contains a created object outside the confirmed rollback set")
        _unique(created_keys, f"{where}.created_objects ownership keys")

        if previous_record is None:
            if record["record_type"] != "action_intent":
                raise EvidenceError("journal artifact must begin with an action_intent")
        else:
            phase = (previous_record["record_type"], record["record_type"])
            if phase == ("action_intent", "action_committed"):
                if (
                    record["actor"] != previous_record["actor"]
                    or transition_id != previous_record["transition_id"]
                    or record["precondition_hash"] != previous_record["precondition_hash"]
                ):
                    raise EvidenceError("journal intent and commit do not describe one owned transition")
            elif phase == ("action_committed", "state_advanced"):
                if (
                    record["actor"] != previous_record["actor"]
                    or transition_id != previous_record["transition_id"]
                    or previous_record["postcondition_hash"] != record["precondition_hash"]
                ):
                    raise EvidenceError("journal commit and state advance do not describe one owned transition")
            elif phase == ("state_advanced", "action_intent"):
                previous_transition = transitions[previous_record["transition_id"]]
                state_owner = states[previous_transition["to"]]["actor"]
                if record["actor"] != state_owner:
                    raise EvidenceError(
                        "journal next intent actor does not own the previously advanced graph state"
                    )
            else:
                raise EvidenceError("journal phases must repeat intent, commit, state_advanced")

        if record["record_type"] == "state_advanced":
            resulting_state = transition["to"]
            if record["postcondition_hash"] != _canonical_sha256(resulting_state):
                raise EvidenceError(
                    f"{where}.postcondition_hash does not bind graph state {resulting_state}"
                )
        previous_hash = _canonical_sha256(record)
        previous_record = record

    assert previous_hash is not None and previous_record is not None
    if previous_record["record_type"] != "state_advanced":
        raise EvidenceError("journal artifact ends before durable state advancement")
    return previous_hash, records, resulting_state


def _verify_handoff(
    value: Any,
    graph_id: str,
    release_digest: str,
    staging_digest: str,
    plan: dict[str, Any],
    journal_head_hash: str,
    journal_records: list[dict[str, Any]],
    journal_control_state: str,
) -> None:
    handoff = _object(value, "handoff artifact")
    _validate_core_contract(handoff, "handoff.schema.json", "handoff artifact")
    plan_hash = plan["plan_hash"]
    disk_guid = plan["body"]["disk_guid"]
    observed = (
        handoff["graph_model_id"],
        handoff["control_state"],
        handoff["journal_head_hash"],
        handoff["release_manifest_hash"],
        handoff["staging_evidence_hash"],
        handoff["plan_hash"],
        handoff["disk_guid"],
    )
    expected = (
        graph_id,
        journal_control_state,
        journal_head_hash,
        release_digest,
        staging_digest,
        plan_hash,
        disk_guid,
    )
    if observed != expected:
        raise EvidenceError(
            "handoff is stale or mixed across graph/state/release/staging/plan/disk/journal identities"
        )
    expected_binding = HANDOFF_BINDINGS.get(journal_control_state)
    if expected_binding is None:
        raise EvidenceError(f"handoff control state is not an authorized cross-OS handoff: {journal_control_state}")
    expected_boot_target, expected_phase = expected_binding
    if handoff["intended_boot_target"] != expected_boot_target:
        raise EvidenceError("handoff intended boot target disagrees with its control state")
    if handoff["partition_phase"] != expected_phase:
        raise EvidenceError("handoff partition phase disagrees with its control state")
    expected_fingerprint = plan["body"]["partition_fingerprints"][expected_phase]
    if handoff["partition_fingerprint"] != expected_fingerprint:
        raise EvidenceError("handoff partition fingerprint disagrees with the confirmed plan phase")
    head = journal_records[-1]
    if head["postcondition_hash"] != _canonical_sha256(handoff["control_state"]):
        raise EvidenceError("handoff control state is not bound by the journal head")


def _verify_profile_and_media(
    profile_value: Any,
    media_value: Any,
    media_digest: str,
    run_profile: dict[str, Any],
    iso_record: dict[str, Any],
    environment: dict[str, Any],
) -> None:
    profile = _object(profile_value, "resolved-profile-record artifact")
    _require_keys(
        profile,
        ("schema_version", "kind", "profile_id", "status", "guest", "media", "security", "required_inputs"),
        "resolved-profile-record artifact",
    )
    if profile["schema_version"] != 1 or profile["kind"] != "vm-support-profile" or profile["status"] != "resolved":
        raise EvidenceError("resolved profile artifact is a placeholder or unresolved profile")
    if profile["profile_id"] != run_profile["support_profile_id"]:
        raise EvidenceError("resolved profile artifact is stale for the selected support profile")
    media_ref = _object(profile["media"], "resolved-profile-record.media")
    _exact_keys(media_ref, ("record_path", "record_sha256"), "resolved-profile-record.media")
    if _digest(media_ref["record_sha256"], "resolved-profile-record.media.record_sha256") != media_digest:
        raise EvidenceError("resolved profile is bound to a different official media record")
    _string(media_ref["record_path"], "resolved-profile-record.media.record_path")
    guest = _object(profile["guest"], "resolved-profile-record.guest")
    _require_keys(guest, ("name", "edition", "release", "architecture", "language", "installed_build"), "resolved-profile-record.guest")
    expected_guest = {
        "windows_family": _string(guest["name"], "resolved-profile-record.guest.name").lower().replace(" ", "-"),
        "windows_release": _string(guest["release"], "resolved-profile-record.guest.release").lower(),
        "windows_edition": _string(guest["edition"], "resolved-profile-record.guest.edition").lower().replace(" ", "-"),
        "architecture": _string(guest["architecture"], "resolved-profile-record.guest.architecture").lower().replace("_", "-"),
    }
    if _string(guest["language"], "resolved-profile-record.guest.language") != "en-US":
        raise EvidenceError("resolved profile guest language is unsupported")
    if any(run_profile[field] != expected_guest[field] for field in expected_guest):
        raise EvidenceError("resolved profile guest identity disagrees with the selected immutable profile")
    installed = _object(guest["installed_build"], "resolved-profile-record.guest.installed_build")
    if installed.get("state") != "resolved" or not isinstance(installed.get("value"), str) or not installed["value"]:
        raise EvidenceError("resolved profile lacks a concrete installed Windows build")
    required_ids: list[str] = []
    for index, raw in enumerate(_array(profile["required_inputs"], "resolved-profile-record.required_inputs")):
        where = f"resolved-profile-record.required_inputs[{index}]"
        item = _object(raw, where)
        _require_keys(item, ("id", "type", "state", "value"), where)
        required_ids.append(_identifier(item["id"], f"{where}.id"))
        if item["type"] != "sha256" or item["state"] != "resolved":
            raise EvidenceError(f"{where} is not a resolved SHA-256 input")
        _digest(item["value"], f"{where}.value")
    _unique(required_ids, "resolved profile required input ids")
    security = _object(profile["security"], "resolved-profile-record.security")
    _require_keys(security, ("scenario_matrix",), "resolved-profile-record.security")
    matrix = _array(security["scenario_matrix"], "resolved-profile-record.security.scenario_matrix")
    scenarios = [item for item in matrix if isinstance(item, dict) and item.get("id") == run_profile["scenario_id"]]
    if len(scenarios) != 1:
        raise EvidenceError("resolved profile does not contain the selected scenario")
    scenario = scenarios[0]
    expected_scenario = (
        "enabled" if run_profile["secure_boot"] else "disabled",
        run_profile["tpm"],
        "enabled" if run_profile["bitlocker"] else "disabled",
    )
    if (scenario.get("secure_boot"), scenario.get("tpm"), scenario.get("bitlocker")) != expected_scenario:
        raise EvidenceError("resolved profile scenario security state is stale")

    media = _object(media_value, "official-media-record artifact")
    _require_keys(media, ("schema_version", "kind", "record_id", "availability", "publisher", "product", "iso", "acquisition", "authentication"), "official-media-record artifact")
    if media["schema_version"] != 1 or media["kind"] != "windows-install-media" or media["availability"] != "available" or media["publisher"] != "Microsoft":
        raise EvidenceError("official media artifact is a placeholder or unavailable record")
    product = _object(media["product"], "official-media-record.product")
    _require_keys(product, ("edition", "release", "architecture", "language"), "official-media-record.product")
    if (
        _string(product["edition"], "official-media-record.product.edition").lower().replace(" ", "-") != run_profile["windows_edition"]
        or _string(product["release"], "official-media-record.product.release").lower() != run_profile["windows_release"]
        or _string(product["architecture"], "official-media-record.product.architecture").lower().replace("_", "-") != run_profile["architecture"]
        or _string(product["language"], "official-media-record.product.language") != "en-US"
    ):
        raise EvidenceError("official media product is stale for the selected profile")
    iso = _object(media["iso"], "official-media-record.iso")
    _exact_keys(iso, ("filename", "size_bytes", "sha256"), "official-media-record.iso")
    if _string(iso["filename"], "official-media-record.iso.filename") != PurePosixPath(iso_record["path"]).name:
        raise EvidenceError("official media filename disagrees with the ISO artifact path")
    if _integer(iso["size_bytes"], "official-media-record.iso.size_bytes", minimum=1) != iso_record["size"]:
        raise EvidenceError("Windows ISO exact byte size disagrees with official media")
    if _digest(iso["sha256"], "official-media-record.iso.sha256") != iso_record["sha256"]:
        raise EvidenceError("Windows ISO SHA-256 disagrees with official media")
    authentication = _object(media["authentication"], "official-media-record.authentication")
    if _digest(authentication.get("published_iso_sha256"), "official-media-record.authentication.published_iso_sha256") != iso["sha256"]:
        raise EvidenceError("official media publication hash disagrees with its ISO declaration")
    acquisition = _object(media["acquisition"], "official-media-record.acquisition")
    source_url = _string(acquisition.get("source_page_url"), "official-media-record.acquisition.source_page_url")
    if acquisition.get("resolved_download_url_retention") != "forbidden" or environment["windows_iso_source_url"] != source_url:
        raise EvidenceError("environment is not bound to the official stable media source")


def _verify_semantic_chain(
    root: Path,
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
    identity: tuple[str, ...],
    run: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
    environment: dict[str, Any],
    vm_identity: tuple[str, str, str, str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    identity_map = dict(zip(IDENTITY_FIELDS, identity))
    graph, _ = _load_json_artifact(root, artifacts, by_role, "state-model", canonical=None)
    graph_id, mutation_ids, failure_edge_ids = _derive_mutation_transitions(graph)
    graph_digest = _artifact_digest(artifacts, by_role, "state-model")

    policy_value, _ = _load_json_artifact(root, artifacts, by_role, "release-policy", canonical="compact-lf")
    policy = _verify_release_policy(policy_value, graph_id, graph_digest)
    release_value, _ = _load_json_artifact(root, artifacts, by_role, "release-manifest", canonical="compact")
    release_digest, signed = _verify_signed_release(release_value, policy, graph_id, graph_digest)
    if identity_map["release_digest"] != release_digest:
        raise EvidenceError("identity.release_digest disagrees with the canonical signed release digest")

    acceptance_value, _ = _load_json_artifact(root, artifacts, by_role, "release-acceptance", canonical="compact")
    acceptance_digest = _artifact_digest(artifacts, by_role, "release-acceptance")
    _verify_acceptance(acceptance_value, signed, release_digest, graph_digest)
    staging_value, _ = _load_json_artifact(root, artifacts, by_role, "staging-evidence", canonical="compact-lf")
    staging_digest = _artifact_digest(artifacts, by_role, "staging-evidence")
    _verify_staging(staging_value, signed, release_digest, acceptance_digest)

    confirmed_value, _ = _load_json_artifact(root, artifacts, by_role, "confirmed-plan", canonical="compact-lf")
    plan, plan_hash, disk_guid = _verify_confirmed_plan(
        confirmed_value, release_digest, graph_id
    )
    if identity_map["plan_digest"] != plan_hash:
        raise EvidenceError("identity.plan_digest disagrees with the canonical confirmed plan hash")
    disk_value, _ = _load_json_artifact(root, artifacts, by_role, "disk-identity", canonical="compact-lf")
    disk = _object(disk_value, "disk-identity artifact")
    _exact_keys(disk, ("schema_version", "disk_guid", "disk_serial"), "disk-identity artifact")
    if disk["schema_version"] != 1 or _uuid(disk["disk_guid"], "disk-identity.disk_guid") != disk_guid:
        raise EvidenceError("disk identity artifact disagrees with the confirmed plan")
    if _identifier(disk["disk_serial"], "disk-identity.disk_serial") != vm_identity[3]:
        raise EvidenceError("disk identity artifact disagrees with the canonical VM disk serial")

    journal_value, _ = _load_json_artifact(root, artifacts, by_role, "journal", canonical="compact-lf")
    journal_head, journal_records, journal_control_state = _verify_core_journal(
        journal_value, plan, graph
    )
    handoff_value, _ = _load_json_artifact(root, artifacts, by_role, "handoff", canonical="compact-lf")
    _verify_handoff(
        handoff_value,
        graph_id,
        release_digest,
        staging_digest,
        plan,
        journal_head,
        journal_records,
        journal_control_state,
    )

    profile_value, _ = _load_json_artifact(root, artifacts, by_role, "resolved-profile-record", canonical="compact-lf")
    media_value, _ = _load_json_artifact(root, artifacts, by_role, "official-media-record", canonical="compact-lf")
    _verify_profile_and_media(
        profile_value,
        media_value,
        _artifact_digest(artifacts, by_role, "official-media-record"),
        profiles[run["profile_id"]],
        artifacts[by_role["windows-iso"]],
        environment,
    )
    return mutation_ids, failure_edge_ids


def _verify_environment(
    value: Any,
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
) -> None:
    environment = _object(value, "environment")
    _exact_keys(
        environment,
        (
            "windows_iso_source_url",
            "windows_hash_document_digest",
            "verified_iso_digest",
            "qemu_command_line_artifact_id",
            "base_image_artifact_id",
            "overlay_artifact_id",
            "ovmf_code_artifact_id",
            "ovmf_vars_artifact_id",
            "tpm_state_artifact_id",
        ),
        "environment",
    )
    url = _string(environment["windows_iso_source_url"], "environment.windows_iso_source_url")
    if not url.startswith("https://"):
        raise EvidenceError("environment.windows_iso_source_url must use https")
    digest_fields = {
        "windows_hash_document_digest": "windows-iso-hash-document",
        "verified_iso_digest": "windows-iso",
    }
    for field, role in digest_fields.items():
        if _digest(environment[field], f"environment.{field}") != _artifact_digest(artifacts, by_role, role):
            raise EvidenceError(f"environment.{field} disagrees with {role} artifact")
    reference_fields = {
        "qemu_command_line_artifact_id": "qemu-command-line",
        "base_image_artifact_id": "base-image-identity",
        "overlay_artifact_id": "overlay-identity",
        "ovmf_code_artifact_id": "ovmf-code-identity",
        "ovmf_vars_artifact_id": "ovmf-vars-identity",
        "tpm_state_artifact_id": "tpm-state-identity",
    }
    for field, role in reference_fields.items():
        reference = _identifier(environment[field], f"environment.{field}")
        if reference != by_role[role] or reference not in artifacts:
            raise EvidenceError(f"environment.{field} does not reference the {role} artifact")


def _verify_observation_snapshot(
    raw: Any,
    label: str,
    expected_vm_identity: tuple[str, str, str, str],
    expected_identity: tuple[str, ...],
    profile: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
) -> tuple[dict[str, Any], set[str]]:
    snapshot = _object(raw, f"observations.{label}")
    _exact_keys(
        snapshot,
        ("observed_at", *VM_IDENTITY_FIELDS, "disk_identity", "firmware", "tpm", "bitlocker", "disk", "gpt", "esp"),
        f"observations.{label}",
    )
    _timestamp(snapshot["observed_at"], f"observations.{label}.observed_at")
    if _vm_identity_tuple(
        {field: snapshot[field] for field in VM_IDENTITY_FIELDS}, f"observations.{label}"
    ) != expected_vm_identity:
        raise EvidenceError(f"observations.{label} VM identity disagrees")
    if _digest(snapshot["disk_identity"], f"observations.{label}.disk_identity") != expected_identity[IDENTITY_FIELDS.index("disk_identity")]:
        raise EvidenceError(f"observations.{label}.disk_identity disagrees")

    references: set[str] = set()
    firmware = _object(snapshot["firmware"], f"observations.{label}.firmware")
    _exact_keys(firmware, ("artifact_id", "uefi", "secure_boot", "setup_mode"), f"observations.{label}.firmware")
    references.add(_artifact_reference(firmware["artifact_id"], f"observations.{label}.firmware.artifact_id", f"firmware-{label}", artifacts, by_role))
    if not _boolean(firmware["uefi"], f"observations.{label}.firmware.uefi"):
        raise EvidenceError(f"observations.{label} did not boot through UEFI")
    if _boolean(firmware["secure_boot"], f"observations.{label}.firmware.secure_boot") != profile["secure_boot"]:
        raise EvidenceError(f"observations.{label} Secure Boot state disagrees with profile")
    if _boolean(firmware["setup_mode"], f"observations.{label}.firmware.setup_mode"):
        raise EvidenceError(f"observations.{label} firmware remained in setup mode")

    tpm = _object(snapshot["tpm"], f"observations.{label}.tpm")
    _exact_keys(tpm, ("artifact_id", "present", "version", "ready"), f"observations.{label}.tpm")
    references.add(_artifact_reference(tpm["artifact_id"], f"observations.{label}.tpm.artifact_id", f"tpm-{label}", artifacts, by_role))
    present = _boolean(tpm["present"], f"observations.{label}.tpm.present")
    ready = _boolean(tpm["ready"], f"observations.{label}.tpm.ready")
    version = _string(tpm["version"], f"observations.{label}.tpm.version")
    expected_present = profile["tpm"] == "2.0"
    if (present, version, ready) != (expected_present, profile["tpm"], expected_present):
        raise EvidenceError(f"observations.{label} TPM state disagrees with profile")

    bitlocker = _object(snapshot["bitlocker"], f"observations.{label}.bitlocker")
    _exact_keys(bitlocker, ("artifact_id", "enabled", "protection_on", "recovery_key_confirmed"), f"observations.{label}.bitlocker")
    references.add(_artifact_reference(bitlocker["artifact_id"], f"observations.{label}.bitlocker.artifact_id", f"bitlocker-{label}", artifacts, by_role))
    enabled = _boolean(bitlocker["enabled"], f"observations.{label}.bitlocker.enabled")
    protected = _boolean(bitlocker["protection_on"], f"observations.{label}.bitlocker.protection_on")
    recovery_confirmed = _boolean(bitlocker["recovery_key_confirmed"], f"observations.{label}.bitlocker.recovery_key_confirmed")
    if enabled != profile["bitlocker"] or protected != enabled or recovery_confirmed != enabled:
        raise EvidenceError(f"observations.{label} BitLocker state disagrees with profile")

    disk = _object(snapshot["disk"], f"observations.{label}.disk")
    _exact_keys(disk, ("artifact_id", "partition_table", "logical_sector_size", "total_bytes", "serial"), f"observations.{label}.disk")
    references.add(_artifact_reference(disk["artifact_id"], f"observations.{label}.disk.artifact_id", f"disk-inspection-{label}", artifacts, by_role))
    if disk["partition_table"] != "gpt":
        raise EvidenceError(f"observations.{label}.disk.partition_table must be gpt")
    if _integer(disk["logical_sector_size"], f"observations.{label}.disk.logical_sector_size", minimum=1) not in (512, 4096):
        raise EvidenceError(f"observations.{label}.disk.logical_sector_size is unsupported")
    _integer(disk["total_bytes"], f"observations.{label}.disk.total_bytes", minimum=1)
    if _identifier(disk["serial"], f"observations.{label}.disk.serial") != expected_vm_identity[3]:
        raise EvidenceError(f"observations.{label}.disk.serial disagrees with VM identity")

    gpt = _object(snapshot["gpt"], f"observations.{label}.gpt")
    _exact_keys(gpt, ("artifact_id", "primary_header_valid", "backup_header_valid", "partition_guids"), f"observations.{label}.gpt")
    references.add(_artifact_reference(gpt["artifact_id"], f"observations.{label}.gpt.artifact_id", f"gpt-{label}", artifacts, by_role))
    if not _boolean(gpt["primary_header_valid"], f"observations.{label}.gpt.primary_header_valid") or not _boolean(gpt["backup_header_valid"], f"observations.{label}.gpt.backup_header_valid"):
        raise EvidenceError(f"observations.{label} has an invalid GPT header")
    partition_guids = [_uuid(item, f"observations.{label}.gpt.partition_guids[]") for item in _array(gpt["partition_guids"], f"observations.{label}.gpt.partition_guids")]
    _unique(partition_guids, f"observations.{label}.gpt.partition_guids")
    if partition_guids != sorted(partition_guids):
        raise EvidenceError(f"observations.{label}.gpt.partition_guids must be sorted")

    esp = _object(snapshot["esp"], f"observations.{label}.esp")
    _exact_keys(esp, ("artifact_id", "filesystem", "windows_loader_present", "jstack_loader_present"), f"observations.{label}.esp")
    references.add(_artifact_reference(esp["artifact_id"], f"observations.{label}.esp.artifact_id", f"esp-{label}", artifacts, by_role))
    if esp["filesystem"] != "fat32":
        raise EvidenceError(f"observations.{label}.esp.filesystem must be fat32")
    if not _boolean(esp["windows_loader_present"], f"observations.{label}.esp.windows_loader_present"):
        raise EvidenceError(f"observations.{label} is missing the Windows ESP loader")
    _boolean(esp["jstack_loader_present"], f"observations.{label}.esp.jstack_loader_present")
    return snapshot, references


def _verify_observations(
    value: Any,
    expected_vm_identity: tuple[str, str, str, str],
    expected_identity: tuple[str, ...],
    profile: dict[str, Any],
    run: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
) -> set[str]:
    observations = _object(value, "observations")
    _exact_keys(observations, ("initial", "final"), "observations")
    initial, initial_refs = _verify_observation_snapshot(observations["initial"], "initial", expected_vm_identity, expected_identity, profile, artifacts, by_role)
    final, final_refs = _verify_observation_snapshot(observations["final"], "final", expected_vm_identity, expected_identity, profile, artifacts, by_role)
    if initial_refs & final_refs:
        raise EvidenceError("initial and final observations reuse evidence artifacts")
    if not (run["started_at"] <= initial["observed_at"] < final["observed_at"] <= run["finished_at"]):
        raise EvidenceError("observation timestamps are outside the ordered run interval")
    initial_guids = set(initial["gpt"]["partition_guids"])
    final_guids = set(final["gpt"]["partition_guids"])
    if initial["esp"]["jstack_loader_present"]:
        raise EvidenceError("initial ESP unexpectedly contains the JStack loader")
    if run["final_outcome"] == "terminal.rolled_back":
        def restored(snapshot: dict[str, Any]) -> dict[str, Any]:
            return {
                section: {
                    key: value
                    for key, value in snapshot[section].items()
                    if key != "artifact_id"
                }
                for section in ("firmware", "tpm", "bitlocker", "disk", "gpt", "esp")
            }

        if restored(final) != restored(initial):
            raise EvidenceError(
                "rolled-back final observations do not restore the complete initial platform and disk state"
            )
        if final_guids != initial_guids or final["esp"]["jstack_loader_present"]:
            raise EvidenceError("rolled-back final state retains JStack partitions or loader artifacts")
    else:
        if not initial_guids < final_guids:
            raise EvidenceError("final GPT must preserve initial partitions and add a deployment partition")
        if run["final_outcome"] != "recovery.manual" and not final["esp"]["jstack_loader_present"]:
            raise EvidenceError("successful outcome is missing the final JStack ESP loader")
    return initial_refs | final_refs


def _verify_journal(
    value: Any,
    expected_identity: tuple[str, ...],
    expected_vm_identity: tuple[str, str, str, str],
    run: dict[str, Any],
) -> dict[str, str]:
    records = _array(value, "journal")
    ids: list[str] = []
    sequences: list[int] = []
    states: list[str] = []
    timestamps: list[str] = []
    transition_ids: list[str] = []
    for index, raw in enumerate(records):
        where = f"journal[{index}]"
        record = _object(raw, where)
        _exact_keys(
            record,
            (
                "id",
                "sequence",
                "state",
                "transition_id",
                "observed_at",
                *IDENTITY_FIELDS,
                *VM_IDENTITY_FIELDS,
                "observed_preconditions",
                "observed_postconditions",
            ),
            where,
        )
        ids.append(_identifier(record["id"], f"{where}.id"))
        sequences.append(_integer(record["sequence"], f"{where}.sequence"))
        state = _identifier(record["state"], f"{where}.state")
        if state not in JOURNAL_OBSERVATIONS:
            raise EvidenceError(f"{where}.state is unknown: {state}")
        states.append(state)
        transition_ids.append(_identifier(record["transition_id"], f"{where}.transition_id"))
        timestamps.append(_timestamp(record["observed_at"], f"{where}.observed_at"))
        if _identity_tuple({field: record[field] for field in IDENTITY_FIELDS}, where) != expected_identity:
            raise EvidenceError(f"{where} identity disagrees with the canonical identity")
        if _vm_identity_tuple({field: record[field] for field in VM_IDENTITY_FIELDS}, where) != expected_vm_identity:
            raise EvidenceError(f"{where} VM identity disagrees with the canonical VM identity")
        expected_pre, expected_post = JOURNAL_OBSERVATIONS[state]
        for field, expected in (
            ("observed_preconditions", expected_pre),
            ("observed_postconditions", expected_post),
        ):
            observations = tuple(
                _identifier(item, f"{where}.{field}[]")
                for item in _array(record[field], f"{where}.{field}")
            )
            _unique(observations, f"{where}.{field}")
            if observations != expected:
                raise EvidenceError(f"{where}.{field} is not canonical for state {state}")
    _unique(ids, "journal ids")
    _unique(sequences, "journal sequences")
    _unique(transition_ids, "journal transition ids")
    if sequences != list(range(len(sequences))):
        raise EvidenceError("journal sequences must be ordered and contiguous from zero")
    if timestamps != sorted(timestamps) or len(set(timestamps)) != len(timestamps):
        raise EvidenceError("journal timestamps must be strictly increasing")
    if not (run["started_at"] <= timestamps[0] and timestamps[-1] <= run["finished_at"]):
        raise EvidenceError("journal timestamps are outside the run interval")
    if states[0] != "run.created" or transition_ids[0] != "run-created":
        raise EvidenceError("journal must begin with the canonical run.created record")

    expected_terminal = {
        "terminal.completed": "terminal.completed",
        "terminal.rolled_back": "terminal.rolled_back",
        "recovery.completed": "recovery.completed",
        "recovery.manual": "recovery.manual",
    }[run["final_outcome"]]
    if states[-1] != expected_terminal:
        raise EvidenceError("journal terminal state disagrees with run.final_outcome")
    if expected_terminal == "terminal.completed":
        if tuple(states) != HAPPY_JOURNAL_STATES:
            raise EvidenceError("completed journal does not follow the canonical state order")
    else:
        if states.count("recovery.started") != 1:
            raise EvidenceError("recovery journal must enter recovery exactly once")
        recovery_index = states.index("recovery.started")
        if recovery_index < 3 or tuple(states[:recovery_index]) != HAPPY_JOURNAL_STATES[:recovery_index]:
            raise EvidenceError("recovery journal has an impossible pre-recovery state order")
        if states[recovery_index:] != ["recovery.started", expected_terminal]:
            raise EvidenceError("recovery journal has records after its terminal outcome")

    for index in range(1, len(states)):
        pair = (states[index - 1], states[index])
        if states[index] == "recovery.started":
            expected_transition = "enter-recovery"
        elif states[index - 1] == "recovery.started":
            expected_transition = {
                "recovery.completed": "finish-recovery",
                "terminal.rolled_back": "complete-rollback",
                "recovery.manual": "require-manual-recovery",
            }.get(states[index])
        else:
            expected_transition = JOURNAL_TRANSITIONS.get(pair)
        if expected_transition is None or transition_ids[index] != expected_transition:
            raise EvidenceError(f"journal transition {pair!r} is impossible or mislabeled")
    return dict(zip(states, timestamps))


def _verify_witnesses(
    value: Any,
    expected_identity: tuple[str, ...],
    expected_vm_identity: tuple[str, str, str, str],
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
    run: dict[str, Any],
    already_used_artifacts: set[str],
    observation_times: dict[str, str],
    journal_times: dict[str, str],
) -> set[str]:
    records = _array(value, "witnesses")
    ids: list[str] = []
    kinds: list[str] = []
    boot_ids: list[str] = []
    artifact_ids: list[str] = []
    timestamps: list[str] = []
    expected = {
        "windows-pre-install": ("windows", False, "\\efi\\microsoft\\boot\\bootmgfw.efi", "windows-pre-install-boot-witness"),
        "windows-post-deploy": ("windows", False, "\\efi\\microsoft\\boot\\bootmgfw.efi", "windows-post-deploy-boot-witness"),
        "jstack-first-boot": ("jstack", False, "\\efi\\jstack\\jstack.efi", "jstack-first-boot-witness"),
        "cold-boot-windows": ("windows", True, "\\efi\\microsoft\\boot\\bootmgfw.efi", "cold-boot-windows-witness"),
        "cold-boot-jstack": ("jstack", True, "\\efi\\jstack\\jstack.efi", "cold-boot-jstack-witness"),
    }
    for index, raw in enumerate(records):
        where = f"witnesses[{index}]"
        record = _object(raw, where)
        _exact_keys(
            record,
            (
                "id",
                "kind",
                "artifact_id",
                "observed_at",
                "boot_id",
                "os",
                "os_version",
                "cold_boot",
                "loader_path",
                "boot_volume_uuid",
                *IDENTITY_FIELDS,
                *VM_IDENTITY_FIELDS,
            ),
            where,
        )
        ids.append(_identifier(record["id"], f"{where}.id"))
        kind = _identifier(record["kind"], f"{where}.kind")
        if kind not in expected:
            raise EvidenceError(f"{where}.kind is unknown: {kind}")
        kinds.append(kind)
        expected_os, expected_cold, expected_loader, expected_role = expected[kind]
        if record["os"] != expected_os:
            raise EvidenceError(f"{where}.os disagrees with witness kind")
        _string(record["os_version"], f"{where}.os_version")
        if _boolean(record["cold_boot"], f"{where}.cold_boot") != expected_cold:
            raise EvidenceError(f"{where}.cold_boot disagrees with witness kind")
        if _string(record["loader_path"], f"{where}.loader_path").lower() != expected_loader:
            raise EvidenceError(f"{where}.loader_path is not the concrete expected EFI loader")
        _uuid(record["boot_volume_uuid"], f"{where}.boot_volume_uuid")
        boot_ids.append(_uuid(record["boot_id"], f"{where}.boot_id"))
        artifact_ids.append(
            _artifact_reference(record["artifact_id"], f"{where}.artifact_id", expected_role, artifacts, by_role)
        )
        timestamps.append(_timestamp(record["observed_at"], f"{where}.observed_at"))
        if _identity_tuple({field: record[field] for field in IDENTITY_FIELDS}, where) != expected_identity:
            raise EvidenceError(f"{where} identity disagrees with the canonical identity")
        if _vm_identity_tuple({field: record[field] for field in VM_IDENTITY_FIELDS}, where) != expected_vm_identity:
            raise EvidenceError(f"{where} VM identity disagrees with the canonical VM identity")
    _unique(ids, "witness ids")
    _unique(kinds, "witness kinds")
    _unique(boot_ids, "witness boot ids")
    _unique(artifact_ids, "witness artifact ids")
    if set(artifact_ids) & already_used_artifacts:
        raise EvidenceError("boot witnesses reuse platform observation evidence")
    required = list(REQUIRED_WITNESS_KINDS)
    if run["final_outcome"] == "recovery.manual":
        if kinds != required[: len(kinds)]:
            raise EvidenceError("manual-recovery witnesses must be an ordered prefix")
    elif run["final_outcome"] == "terminal.rolled_back":
        if kinds != ["windows-pre-install", "cold-boot-windows"]:
            raise EvidenceError(
                "rolled-back runs require only ordered pre-install and post-rollback Windows boot witnesses"
            )
    elif kinds != required:
        raise EvidenceError("claimed success is missing or reorders required boot witnesses")
    if timestamps != sorted(timestamps) or len(set(timestamps)) != len(timestamps):
        raise EvidenceError("witness timestamps must be strictly increasing")
    if not (run["started_at"] <= timestamps[0] and timestamps[-1] <= run["finished_at"]):
        raise EvidenceError("witness timestamps are outside the run interval")
    if run["final_outcome"] == "terminal.completed":
        by_kind = dict(zip(kinds, timestamps))
        if not observation_times["initial"] < by_kind["windows-pre-install"] < journal_times["mutation.started"]:
            raise EvidenceError(
                "Windows pre-install witness must follow initial observation and precede mutation"
            )
        if by_kind["windows-post-deploy"] <= max(
            observation_times["final"], journal_times["observation.completed"]
        ):
            raise EvidenceError("Windows post-deploy witness must follow mutation observation")
        if by_kind["jstack-first-boot"] <= journal_times["handoff.committed"]:
            raise EvidenceError("JStack first-boot witness must follow committed handoff")
        if (
            by_kind["cold-boot-windows"] <= journal_times["terminal.completed"]
            or by_kind["cold-boot-jstack"] <= journal_times["terminal.completed"]
        ):
            raise EvidenceError("cold-boot witnesses must follow terminal completion")
    elif run["final_outcome"] == "terminal.rolled_back":
        by_kind = dict(zip(kinds, timestamps))
        if not observation_times["initial"] < by_kind["windows-pre-install"] < journal_times["recovery.started"]:
            raise EvidenceError("pre-install Windows witness is not ordered before rollback")
        if by_kind["cold-boot-windows"] <= max(
            observation_times["final"], journal_times["terminal.rolled_back"]
        ):
            raise EvidenceError("post-rollback Windows witness must follow restored observations and terminal rollback")
    return set(artifact_ids)

def _verify_fault(
    value: Any,
    artifacts: dict[str, dict[str, Any]],
    run: dict[str, Any],
    already_used_artifacts: set[str],
    mutation_transitions: tuple[str, ...],
) -> set[str]:
    fault = _object(value, "fault")
    mode = fault.get("mode")
    if mode == "none":
        _exact_keys(fault, ("mode",), "fault")
        if run["final_outcome"] != "terminal.completed":
            raise EvidenceError("a recovery outcome requires an injected fault record")
        return set()
    if mode != "injected":
        raise EvidenceError("fault.mode is unknown")
    _exact_keys(
        fault,
        (
            "mode",
            "class",
            "trigger",
            "exact_boundary",
            "transition_id",
            "checkpoint",
            "boundary_observation_artifact_id",
            "process_exit_cause",
            "recovery_outcome",
            "recovery_observation_artifact_ids",
        ),
        "fault",
    )
    fault_class = _identifier(fault["class"], "fault.class")
    if fault_class not in MANDATORY_FAULT_CLASSES:
        raise EvidenceError(f"fault.class is unknown: {fault_class}")
    _string(fault["trigger"], "fault.trigger")
    boundary = _identifier(fault["exact_boundary"], "fault.exact_boundary")
    if boundary not in INTERRUPTION_BOUNDARIES:
        raise EvidenceError("fault.exact_boundary is unknown")
    transition_id = _identifier(fault["transition_id"], "fault.transition_id")
    if transition_id not in mutation_transitions:
        raise EvidenceError("fault.transition_id is not a graph-derived production mutation transition")
    checkpoint = _identifier(fault["checkpoint"], "fault.checkpoint")
    if fault_class in ("rollback-request", "rollback-interruption"):
        if checkpoint not in POST_MUTATION_CHECKPOINTS:
            raise EvidenceError("rollback fault checkpoint is unknown")
    elif checkpoint != "campaign":
        raise EvidenceError("non-rollback faults must use the campaign checkpoint")
    boundary_reference = _identifier(
        fault["boundary_observation_artifact_id"],
        "fault.boundary_observation_artifact_id",
    )
    if boundary_reference not in artifacts:
        raise EvidenceError("fault boundary observation artifact is unknown")
    if artifacts[boundary_reference]["role"] not in ("serial-output", "guest-output"):
        raise EvidenceError("fault boundary must reference concrete serial or guest output")
    if boundary_reference in already_used_artifacts:
        raise EvidenceError("fault boundary reuses observation or boot witness evidence")
    _string(fault["process_exit_cause"], "fault.process_exit_cause")
    if fault["recovery_outcome"] not in ("retry", "advance", "rollback", "manual-recovery"):
        raise EvidenceError("fault.recovery_outcome is unknown")
    expected_outcome = {
        "retry": "recovery.completed",
        "advance": "recovery.completed",
        "rollback": "terminal.rolled_back",
        "manual-recovery": "recovery.manual",
    }[fault["recovery_outcome"]]
    if run["final_outcome"] != expected_outcome:
        raise EvidenceError("fault recovery_outcome disagrees with run.final_outcome")
    references = [_identifier(item, "fault.recovery_observation_artifact_ids[]") for item in _array(fault["recovery_observation_artifact_ids"], "fault.recovery_observation_artifact_ids")]
    _unique(references, "fault.recovery_observation_artifact_ids")
    if boundary_reference in references:
        raise EvidenceError("fault boundary and recovery reuse the same evidence")
    if set(references) & already_used_artifacts:
        raise EvidenceError("fault recovery reuses observation or boot witness evidence")
    for reference in references:
        if reference not in artifacts:
            raise EvidenceError(f"fault recovery observation artifact is unknown: {reference}")
        if artifacts[reference]["role"] not in ("log", "serial-output", "guest-output"):
            raise EvidenceError("fault recovery observations must reference concrete log output")
    return {boundary_reference, *references}


def _coverage_run(
    raw: Any,
    where: str,
    profile_ids: set[str],
    expected_input_digest: str,
    *,
    extra_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    record = _object(raw, where)
    _exact_keys(
        record,
        (
            "run_id",
            "profile_id",
            "input_digest",
            "evidence_bundle_digest",
            *extra_fields,
        ),
        where,
    )
    _identifier(record["run_id"], f"{where}.run_id")
    profile_id = _identifier(record["profile_id"], f"{where}.profile_id")
    if profile_id not in profile_ids:
        raise EvidenceError(f"{where}.profile_id is unknown: {profile_id}")
    if _digest(record["input_digest"], f"{where}.input_digest") != expected_input_digest:
        raise EvidenceError(f"{where}.input_digest is stale")
    evidence_digest = _digest(
        record["evidence_bundle_digest"], f"{where}.evidence_bundle_digest"
    )
    if evidence_digest == expected_input_digest:
        raise EvidenceError(f"{where}.evidence_bundle_digest aliases the campaign input")
    return record


def _combined_input_digest(inputs: dict[str, Any]) -> str:
    material = {
        key: inputs[key]
        for key in sorted(inputs)
        if key not in {"combined_digest", "campaign_index_digest"}
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


CAMPAIGN_RUN_SECTIONS = (
    "happy_path_runs",
    "interruption_runs",
    "failure_edge_runs",
    "mandatory_fault_runs",
    "fresh_base_reconstruction_runs",
)


def _campaign_index_value(
    coverage: dict[str, Any],
    bundles: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "input_digest": coverage["inputs"]["combined_digest"],
        "runs": [
            {"category": section, "bundle": bundles[(section, record["run_id"])]}
            for section in CAMPAIGN_RUN_SECTIONS
            for record in coverage[section]
        ],
    }


def _campaign_claim(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in {"evidence_bundle_digest", "passed"}
    }


def _trace_steps(trace: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (step, "success")
        if isinstance(step, str)
        else (step["transition"], step.get("outcome", "success"))
        for step in trace["steps"]
    ]


def _verify_campaign_run_bundle(
    raw: Any,
    where: str,
    category: str,
    record: dict[str, Any],
    inputs: dict[str, Any],
    graph: dict[str, Any],
) -> str:
    bundle = _object(raw, where)
    _exact_keys(
        bundle,
        (
            "contract",
            "schema_version",
            "category",
            "run",
            "identity",
            "trace",
            "rollback",
            "verification",
        ),
        where,
    )
    if bundle["contract"] != CAMPAIGN_RUN_CONTRACT or bundle["schema_version"] != 1:
        raise EvidenceError(f"{where} uses an unsupported campaign run contract")
    if bundle["category"] != category:
        raise EvidenceError(f"{where}.category disagrees with its campaign section")
    claim = _object(bundle["run"], f"{where}.run")
    if claim != _campaign_claim(record):
        raise EvidenceError(f"{where}.run identity or claim disagrees with its campaign row")

    identity = _object(bundle["identity"], f"{where}.identity")
    _exact_keys(
        identity,
        (
            "run_id",
            "profile_id",
            "input_digest",
            "graph_digest",
            "evidence_verifier_digest",
        ),
        f"{where}.identity",
    )
    expected_identity = {
        "run_id": record["run_id"],
        "profile_id": record["profile_id"],
        "input_digest": inputs["combined_digest"],
        "graph_digest": inputs["graph_digest"],
        "evidence_verifier_digest": inputs["evidence_verifier_digest"],
    }
    if identity != expected_identity:
        raise EvidenceError(f"{where}.identity is stale or belongs to another run")

    verification = _object(bundle["verification"], f"{where}.verification")
    _exact_keys(
        verification,
        ("verifier_digest", "trace_schema_digest"),
        f"{where}.verification",
    )
    _, trace_schema_digest = _trace_schema()
    if verification != {
        "verifier_digest": inputs["evidence_verifier_digest"],
        "trace_schema_digest": trace_schema_digest,
    }:
        raise EvidenceError(f"{where}.verification is not bound to the pinned external verifier and trace schema")

    digest = hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()
    if digest != record["evidence_bundle_digest"]:
        raise EvidenceError(f"{where} canonical digest disagrees with its campaign row")
    cache_key = (
        digest,
        inputs["graph_digest"],
        inputs["evidence_verifier_digest"],
        trace_schema_digest,
    )
    if cache_key in _VERIFIED_CAMPAIGN_RUNS:
        return digest

    trace = _object(bundle["trace"], f"{where}.trace")
    tool = _state_model_tool()
    schema_errors = sorted(
        _trace_validator().iter_errors(trace),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if schema_errors:
        error = schema_errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise EvidenceError(
            f"{where}.trace violates the checked-in trace schema at {location}: {error.message}"
        )
    try:
        terminal = tool.simulate_trace(graph, trace)
    except AssertionError as error:
        raise EvidenceError(f"{where}.trace cannot execute in the signed graph: {error}") from error
    if terminal != trace["expected_terminal"]:
        raise EvidenceError(f"{where}.trace terminal does not match its simulated graph result")
    if trace["id"] != record["run_id"]:
        raise EvidenceError(f"{where}.trace id disagrees with its campaign run id")

    if category in ("happy_path_runs", "fresh_base_reconstruction_runs"):
        allowed_terminals = {"terminal.completed"}
    else:
        recovery_outcome = record["recovery_outcome"]
        allowed_terminals = {
            "retry": {"terminal.completed"},
            "advance": {"terminal.completed"},
            "rollback": {"terminal.rolled_back"},
            "manual-recovery": {"terminal.manual_recovery"},
            "rejected": {
                "terminal.cancelled",
                "terminal.unsupported",
                "terminal.manual_recovery",
            },
        }[recovery_outcome]
    if terminal not in allowed_terminals:
        raise EvidenceError(f"{where}.trace terminal disagrees with the claimed recovery outcome")

    steps = _trace_steps(trace)
    if category == "interruption_runs" and not any(
        transition_id == record["transition_id"] and outcome.startswith("interrupted_")
        for transition_id, outcome in steps
    ):
        raise EvidenceError(f"{where}.trace does not execute the claimed interrupted transition")
    if category == "failure_edge_runs" and (
        record["edge_id"], "failure"
    ) not in steps:
        raise EvidenceError(f"{where}.trace does not execute the claimed modeled failure edge")

    rollback = bundle["rollback"]
    if terminal == "terminal.rolled_back":
        rollback_record = _object(rollback, f"{where}.rollback")
        _exact_keys(
            rollback_record,
            (
                "initial_state_digest",
                "restored_state_digest",
                "retained_jstack_objects",
                "windows_security_restored",
            ),
            f"{where}.rollback",
        )
        initial_digest = _digest(
            rollback_record["initial_state_digest"],
            f"{where}.rollback.initial_state_digest",
        )
        if _digest(
            rollback_record["restored_state_digest"],
            f"{where}.rollback.restored_state_digest",
        ) != initial_digest:
            raise EvidenceError(f"{where}.rollback does not restore the initial state digest")
        if _array(
            rollback_record["retained_jstack_objects"],
            f"{where}.rollback.retained_jstack_objects",
            nonempty=False,
        ):
            raise EvidenceError(f"{where}.rollback retains JStack-created objects")
        if not _boolean(
            rollback_record["windows_security_restored"],
            f"{where}.rollback.windows_security_restored",
        ):
            raise EvidenceError(f"{where}.rollback does not restore Windows security")
    elif rollback is not None:
        raise EvidenceError(f"{where}.rollback is present for a non-rollback terminal")

    _VERIFIED_CAMPAIGN_RUNS.add(cache_key)
    return digest


def _verify_campaign_index(
    value: Any,
    coverage: dict[str, Any],
    inputs: dict[str, Any],
    graph: dict[str, Any],
) -> None:
    index = _object(value, "campaign-index artifact")
    _exact_keys(index, ("schema_version", "input_digest", "runs"), "campaign-index artifact")
    if index["schema_version"] != 1 or index["input_digest"] != inputs["combined_digest"]:
        raise EvidenceError("campaign-index artifact is stale or uses an unsupported schema")
    entries = _array(index["runs"], "campaign-index.runs")
    expected = [
        (section, record)
        for section in CAMPAIGN_RUN_SECTIONS
        for record in coverage[section]
    ]
    if len(entries) != len(expected):
        raise EvidenceError("campaign-index does not contain exactly one bundle for every campaign row")
    digests: list[str] = []
    for offset, (raw_entry, (section, record)) in enumerate(zip(entries, expected)):
        where = f"campaign-index.runs[{offset}]"
        entry = _object(raw_entry, where)
        _exact_keys(entry, ("category", "bundle"), where)
        if entry["category"] != section:
            raise EvidenceError(f"{where}.category does not preserve canonical campaign ordering")
        digests.append(
            _verify_campaign_run_bundle(
                entry["bundle"], f"{where}.bundle", section, record, inputs, graph
            )
        )
    _unique(digests, "externally verified campaign run bundle digests")


def _reject_symlink_components(path: Path, where: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            raise EvidenceError(f"{where} contains a symlink component: {current}")


def _verify_coverage(
    root: Path,
    value: Any,
    profiles: dict[str, dict[str, Any]],
    run: dict[str, Any],
    identity: tuple[str, ...],
    artifacts: dict[str, dict[str, Any]],
    by_role: dict[str, str],
    fault: dict[str, Any],
    mutation_transitions: tuple[str, ...],
    failure_edge_ids: tuple[str, ...],
) -> None:
    coverage = _object(value, "coverage")
    _exact_keys(
        coverage,
        (
            "supported_profile_ids",
            "inputs",
            "happy_path_runs",
            "production_transitions",
            "interruption_runs",
            "modeled_failure_edges",
            "failure_edge_runs",
            "post_mutation_checkpoints",
            "mandatory_fault_cases",
            "mandatory_fault_runs",
            "fresh_base_reconstruction_runs",
        ),
        "coverage",
    )
    profile_ids = set(profiles)
    declared_profiles = _sorted_unique_strings(coverage["supported_profile_ids"], "coverage.supported_profile_ids")
    if set(declared_profiles) != profile_ids:
        raise EvidenceError("coverage.supported_profile_ids must exactly match profiles")

    inputs = _object(coverage["inputs"], "coverage.inputs")
    input_fields = (
        "runtime_digest",
        "adapters_digest",
        "graph_digest",
        "release_policy_digest",
        "boot_artifacts_digest",
        "vm_harness_digest",
        "evidence_verifier_digest",
        "campaign_index_digest",
        "combined_digest",
    )
    _exact_keys(inputs, input_fields, "coverage.inputs")
    for field in input_fields:
        _digest(inputs[field], f"coverage.inputs.{field}")
    role_for_input = {
        "runtime_digest": "runtime",
        "adapters_digest": "adapters",
        "graph_digest": "state-model",
        "release_policy_digest": "release-policy",
        "boot_artifacts_digest": "boot-artifacts",
        "vm_harness_digest": "vm-harness",
        "evidence_verifier_digest": "evidence-verifier",
        "campaign_index_digest": "campaign-index",
    }
    for field, role in role_for_input.items():
        if inputs[field] != _artifact_digest(artifacts, by_role, role):
            raise EvidenceError(f"coverage.inputs.{field} disagrees with {role} artifact")
    if inputs["graph_digest"] != identity[0]:
        raise EvidenceError("coverage graph identity disagrees with run identity")
    combined_digest = _combined_input_digest(inputs)
    if inputs["combined_digest"] != combined_digest:
        raise EvidenceError("coverage.inputs.combined_digest is not canonical")
    campaign_index, _ = _load_json_artifact(
        root,
        artifacts,
        by_role,
        "campaign-index",
        canonical="compact-lf",
    )

    happy_records = _array(coverage["happy_path_runs"], "coverage.happy_path_runs")
    happy_keys: list[tuple[str, str]] = []
    happy_run_ids: list[str] = []
    happy_counts = {profile_id: 0 for profile_id in profile_ids}
    current_happy_present = False
    for index, raw in enumerate(happy_records):
        where = f"coverage.happy_path_runs[{index}]"
        record = _coverage_run(raw, where, profile_ids, combined_digest, extra_fields=("fresh_overlay",))
        if not _boolean(record["fresh_overlay"], f"{where}.fresh_overlay"):
            raise EvidenceError(f"{where} does not use a fresh overlay")
        key = (record["profile_id"], record["run_id"])
        happy_keys.append(key)
        happy_run_ids.append(record["run_id"])
        happy_counts[record["profile_id"]] += 1
        if record["run_id"] == run["id"] and record["profile_id"] == run["profile_id"]:
            current_happy_present = True
    _unique(happy_keys, "happy-path coverage")
    _unique(happy_run_ids, "happy-path run ids")
    for profile_id, count in sorted(happy_counts.items()):
        if count < 10:
            raise EvidenceError(f"profile {profile_id} has only {count} fresh happy-path runs; 10 required")
    if run["final_outcome"] == "terminal.completed" and not current_happy_present:
        raise EvidenceError("completed current run is absent from happy-path coverage")

    transitions: dict[str, set[str]] = {}
    for index, raw in enumerate(_array(coverage["production_transitions"], "coverage.production_transitions")):
        where = f"coverage.production_transitions[{index}]"
        record = _object(raw, where)
        _exact_keys(record, ("transition_id", "applicable_profile_ids", "boundaries"), where)
        transition_id = _identifier(record["transition_id"], f"{where}.transition_id")
        if transition_id in transitions:
            raise EvidenceError(f"duplicate logical production transition: {transition_id}")
        applicable = set(_sorted_unique_strings(record["applicable_profile_ids"], f"{where}.applicable_profile_ids"))
        if applicable != profile_ids:
            raise EvidenceError(f"{where} must apply to every immutable supported profile")
        boundaries = [_identifier(item, f"{where}.boundaries[]") for item in _array(record["boundaries"], f"{where}.boundaries")]
        _unique(boundaries, f"{where}.boundaries")
        if tuple(boundaries) != INTERRUPTION_BOUNDARIES:
            raise EvidenceError(f"{where}.boundaries must contain every canonical interruption boundary in order")
        transitions[transition_id] = applicable
    if tuple(transitions) != mutation_transitions:
        raise EvidenceError("production_transitions must exactly match graph-derived mutations in order")

    interruption_keys: list[tuple[str, str, str]] = []
    interruption_run_ids: list[str] = []
    for index, raw in enumerate(_array(coverage["interruption_runs"], "coverage.interruption_runs")):
        where = f"coverage.interruption_runs[{index}]"
        record = _coverage_run(
            raw,
            where,
            profile_ids,
            combined_digest,
            extra_fields=("transition_id", "boundary", "abrupt_qemu_termination", "recovery_outcome"),
        )
        transition_id = _identifier(record["transition_id"], f"{where}.transition_id")
        boundary = _identifier(record["boundary"], f"{where}.boundary")
        if transition_id not in transitions or record["profile_id"] not in transitions[transition_id]:
            raise EvidenceError(f"{where} is not applicable to its transition/profile")
        if boundary not in INTERRUPTION_BOUNDARIES:
            raise EvidenceError(f"{where}.boundary is unknown")
        if not _boolean(record["abrupt_qemu_termination"], f"{where}.abrupt_qemu_termination"):
            raise EvidenceError(f"{where} did not abruptly terminate QEMU")
        if record["recovery_outcome"] not in ("retry", "advance", "rollback", "manual-recovery"):
            raise EvidenceError(f"{where}.recovery_outcome is unknown")
        interruption_keys.append((transition_id, record["profile_id"], boundary))
        interruption_run_ids.append(record["run_id"])
    _unique(interruption_keys, "interruption coverage")
    _unique(interruption_run_ids, "interruption run ids")
    expected_interruptions = {
        (transition_id, profile_id, boundary)
        for transition_id, applicable in transitions.items()
        for profile_id in applicable
        for boundary in INTERRUPTION_BOUNDARIES
    }
    if set(interruption_keys) != expected_interruptions:
        missing = sorted(expected_interruptions - set(interruption_keys))
        extra = sorted(set(interruption_keys) - expected_interruptions)
        raise EvidenceError(f"incomplete interruption coverage; missing={missing[:3]}, extra={extra[:3]}")

    edges: dict[str, set[str]] = {}
    for index, raw in enumerate(_array(coverage["modeled_failure_edges"], "coverage.modeled_failure_edges")):
        where = f"coverage.modeled_failure_edges[{index}]"
        record = _object(raw, where)
        _exact_keys(record, ("edge_id", "applicable_profile_ids"), where)
        edge_id = _identifier(record["edge_id"], f"{where}.edge_id")
        if edge_id in edges:
            raise EvidenceError(f"duplicate logical modeled failure edge: {edge_id}")
        applicable = set(_sorted_unique_strings(record["applicable_profile_ids"], f"{where}.applicable_profile_ids"))
        if applicable != profile_ids:
            raise EvidenceError(f"{where} must apply to every immutable supported profile")
        edges[edge_id] = applicable
    if tuple(edges) != failure_edge_ids:
        raise EvidenceError(
            "modeled_failure_edges must exactly match graph-derived failure edges in order"
        )

    failure_edge_keys: list[tuple[str, str]] = []
    failure_edge_run_ids: list[str] = []
    for index, raw in enumerate(_array(coverage["failure_edge_runs"], "coverage.failure_edge_runs")):
        where = f"coverage.failure_edge_runs[{index}]"
        record = _coverage_run(raw, where, profile_ids, combined_digest, extra_fields=("edge_id", "recovery_outcome"))
        edge_id = _identifier(record["edge_id"], f"{where}.edge_id")
        if edge_id not in edges or record["profile_id"] not in edges[edge_id]:
            raise EvidenceError(f"{where} is not applicable to its edge/profile")
        if record["recovery_outcome"] not in ("retry", "advance", "rollback", "manual-recovery"):
            raise EvidenceError(f"{where}.recovery_outcome is unknown")
        failure_edge_keys.append((edge_id, record["profile_id"]))
        failure_edge_run_ids.append(record["run_id"])
    _unique(failure_edge_keys, "modeled failure-edge coverage")
    _unique(failure_edge_run_ids, "modeled failure-edge run ids")
    expected_failure_edges = {
        (edge_id, profile_id)
        for edge_id, applicable in edges.items()
        for profile_id in applicable
    }
    if set(failure_edge_keys) != expected_failure_edges:
        raise EvidenceError("incomplete modeled failure-edge coverage")

    checkpoints = _sorted_unique_strings(coverage["post_mutation_checkpoints"], "coverage.post_mutation_checkpoints")
    if tuple(checkpoints) != tuple(sorted(POST_MUTATION_CHECKPOINTS)):
        raise EvidenceError("post_mutation_checkpoints must be the immutable checkpoint set")
    cases: dict[str, tuple[set[str], tuple[str, ...]]] = {}
    for index, raw in enumerate(_array(coverage["mandatory_fault_cases"], "coverage.mandatory_fault_cases")):
        where = f"coverage.mandatory_fault_cases[{index}]"
        record = _object(raw, where)
        _exact_keys(record, ("class", "applicable_profile_ids", "checkpoints"), where)
        fault_class = _identifier(record["class"], f"{where}.class")
        if fault_class not in MANDATORY_FAULT_CLASSES:
            raise EvidenceError(f"{where}.class is unknown: {fault_class}")
        if fault_class in cases:
            raise EvidenceError(f"duplicate logical mandatory fault class: {fault_class}")
        applicable = set(_sorted_unique_strings(record["applicable_profile_ids"], f"{where}.applicable_profile_ids"))
        if applicable != profile_ids:
            raise EvidenceError(f"{where} must apply to every immutable supported profile")
        case_checkpoints = tuple(_sorted_unique_strings(record["checkpoints"], f"{where}.checkpoints"))
        if fault_class in ("rollback-request", "rollback-interruption"):
            if set(case_checkpoints) != set(checkpoints):
                raise EvidenceError(f"{where} must cover every post-mutation checkpoint")
        elif case_checkpoints != ("campaign",):
            raise EvidenceError(f"{where} must use the canonical campaign checkpoint")
        cases[fault_class] = (applicable, case_checkpoints)
    if set(cases) != set(MANDATORY_FAULT_CLASSES):
        missing = sorted(set(MANDATORY_FAULT_CLASSES) - set(cases))
        raise EvidenceError(f"missing mandatory fault classes: {', '.join(missing)}")

    mandatory_keys: list[tuple[str, str, str]] = []
    mandatory_run_ids: list[str] = []
    for index, raw in enumerate(_array(coverage["mandatory_fault_runs"], "coverage.mandatory_fault_runs")):
        where = f"coverage.mandatory_fault_runs[{index}]"
        record = _coverage_run(raw, where, profile_ids, combined_digest, extra_fields=("class", "checkpoint", "recovery_outcome"))
        fault_class = _identifier(record["class"], f"{where}.class")
        checkpoint = _identifier(record["checkpoint"], f"{where}.checkpoint")
        if fault_class not in cases:
            raise EvidenceError(f"{where}.class is not declared")
        applicable, case_checkpoints = cases[fault_class]
        if record["profile_id"] not in applicable or checkpoint not in case_checkpoints:
            raise EvidenceError(f"{where} is not applicable to its fault/profile/checkpoint")
        if record["recovery_outcome"] not in ("retry", "advance", "rollback", "manual-recovery", "rejected"):
            raise EvidenceError(f"{where}.recovery_outcome is unknown")
        mandatory_keys.append((fault_class, record["profile_id"], checkpoint))
        mandatory_run_ids.append(record["run_id"])
    _unique(mandatory_keys, "mandatory fault coverage")
    _unique(mandatory_run_ids, "mandatory fault run ids")
    expected_mandatory = {
        (fault_class, profile_id, checkpoint)
        for fault_class, (applicable, case_checkpoints) in cases.items()
        for profile_id in applicable
        for checkpoint in case_checkpoints
    }
    if set(mandatory_keys) != expected_mandatory:
        raise EvidenceError("incomplete mandatory fault coverage")

    base_keys: list[str] = []
    base_run_ids: list[str] = []
    for index, raw in enumerate(_array(coverage["fresh_base_reconstruction_runs"], "coverage.fresh_base_reconstruction_runs")):
        where = f"coverage.fresh_base_reconstruction_runs[{index}]"
        record = _coverage_run(raw, where, profile_ids, combined_digest, extra_fields=("base_image_reconstructed",))
        if not _boolean(record["base_image_reconstructed"], f"{where}.base_image_reconstructed"):
            raise EvidenceError(f"{where} did not reconstruct the base image")
        base_keys.append(record["profile_id"])
        base_run_ids.append(record["run_id"])
    _unique(base_keys, "fresh base reconstruction coverage")
    _unique(base_run_ids, "fresh base reconstruction run ids")
    if set(base_keys) != profile_ids:
        raise EvidenceError("fresh base-image reconstruction is incomplete")
    all_campaign_run_ids = (
        happy_run_ids
        + interruption_run_ids
        + failure_edge_run_ids
        + mandatory_run_ids
        + base_run_ids
    )
    _unique(all_campaign_run_ids, "all campaign run ids")
    all_campaign_evidence_digests = [
        record["evidence_bundle_digest"]
        for section in (
            "happy_path_runs",
            "interruption_runs",
            "failure_edge_runs",
            "mandatory_fault_runs",
            "fresh_base_reconstruction_runs",
        )
        for record in coverage[section]
    ]
    _unique(all_campaign_evidence_digests, "all campaign evidence bundle digests")
    if fault["mode"] == "injected":
        current_fault_runs = [
            record
            for record in coverage["mandatory_fault_runs"]
            if record["run_id"] == run["id"]
            and record["profile_id"] == run["profile_id"]
            and record["class"] == fault["class"]
            and record["checkpoint"] == fault["checkpoint"]
            and record["recovery_outcome"] == fault["recovery_outcome"]
        ]
        if len(current_fault_runs) != 1:
            raise EvidenceError("injected current run is absent from matching mandatory fault coverage")
    graph, _ = _load_json_artifact(
        root, artifacts, by_role, "state-model", canonical=None
    )
    _verify_campaign_index(campaign_index, coverage, inputs, graph)


def verify_bundle(
    path: str | os.PathLike[str],
    *,
    trusted_release_policy_digest: str,
    trusted_profile_digest: str,
    trusted_media_digest: str,
    trusted_campaign_index_digest: str,
) -> dict[str, Any]:
    supplied = Path(path)
    manifest = supplied / "evidence.json" if supplied.is_dir() else supplied
    if not manifest.exists():
        raise EvidenceError(f"manifest does not exist: {manifest}")
    root = manifest.parent
    _reject_symlink_components(root, "bundle root")
    if not root.is_dir():
        raise EvidenceError(f"bundle root must be a directory: {root}")
    root.resolve(strict=True)
    value, _ = load_canonical_json(manifest)
    _exact_keys(
        value,
        (
            "contract",
            "schema_version",
            "run",
            "profiles",
            "identity",
            "vm_identity",
            "environment",
            "artifacts",
            "observations",
            "journal",
            "witnesses",
            "fault",
            "coverage",
        ),
        "manifest",
    )
    if value["contract"] != CONTRACT:
        raise EvidenceError(f"unknown contract: {value['contract']!r}")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise EvidenceError(f"unsupported schema_version: {value['schema_version']!r}")

    trust_roots = {
        "release-policy": _digest(
            trusted_release_policy_digest, "trusted_release_policy_digest"
        ),
        "resolved-profile-record": _digest(
            trusted_profile_digest, "trusted_profile_digest"
        ),
        "official-media-record": _digest(
            trusted_media_digest, "trusted_media_digest"
        ),
        "campaign-index": _digest(
            trusted_campaign_index_digest, "trusted_campaign_index_digest"
        ),
    }
    artifacts, by_role = _verify_artifacts(root, value["artifacts"])
    for role, expected_digest in trust_roots.items():
        if _artifact_digest(artifacts, by_role, role) != expected_digest:
            raise EvidenceError(
                f"{role} artifact does not match its external trusted digest"
            )
    profiles = _verify_profiles(value["profiles"])
    run = _verify_run(value["run"], profiles)
    if run["clean_tree_digest"] != _artifact_digest(artifacts, by_role, "source-tree"):
        raise EvidenceError("run.clean_tree_digest disagrees with source-tree artifact")
    identity = _verify_identity(value["identity"], artifacts, by_role)
    vm_identity = _vm_identity_tuple(_object(value["vm_identity"], "vm_identity"), "vm_identity")
    environment = _object(value["environment"], "environment")
    _verify_environment(environment, artifacts, by_role)
    mutation_transitions, failure_edge_ids = _verify_semantic_chain(
        root,
        artifacts,
        by_role,
        identity,
        run,
        profiles,
        environment,
        vm_identity,
    )
    observation_artifacts = _verify_observations(
        value["observations"],
        vm_identity,
        identity,
        profiles[run["profile_id"]],
        run,
        artifacts,
        by_role,
    )
    observation_times = {
        label: value["observations"][label]["observed_at"] for label in ("initial", "final")
    }
    journal_times = _verify_journal(value["journal"], identity, vm_identity, run)
    witness_artifacts = _verify_witnesses(
        value["witnesses"],
        identity,
        vm_identity,
        artifacts,
        by_role,
        run,
        observation_artifacts,
        observation_times,
        journal_times,
    )
    _verify_fault(
        value["fault"],
        artifacts,
        run,
        observation_artifacts | witness_artifacts,
        mutation_transitions,
    )
    _verify_coverage(
        root,
        value["coverage"],
        profiles,
        run,
        identity,
        artifacts,
        by_role,
        value["fault"],
        mutation_transitions,
        failure_edge_ids,
    )
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("bundle", help="bundle directory or canonical evidence.json path")
    result.add_argument("--trusted-release-policy-sha256", required=True)
    result.add_argument("--trusted-profile-sha256", required=True)
    result.add_argument("--trusted-media-sha256", required=True)
    result.add_argument("--trusted-campaign-index-sha256", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        manifest = Path(arguments.bundle)
        evidence_path = manifest / "evidence.json" if manifest.is_dir() else manifest
        value = verify_bundle(
            manifest,
            trusted_release_policy_digest=arguments.trusted_release_policy_sha256,
            trusted_profile_digest=arguments.trusted_profile_sha256,
            trusted_media_digest=arguments.trusted_media_sha256,
            trusted_campaign_index_digest=arguments.trusted_campaign_index_sha256,
        )
        evidence_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        print(f"OK run={value['run']['id']} evidence_sha256={evidence_digest}")
        return 0
    except (EvidenceError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
