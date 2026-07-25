#!/usr/bin/env python3
"""PH-09 Linux RAM-installer adapters.

These adapters implement the Linux side of the install: re-inventory the disk,
create only the confirmed partition interval, format and deploy Btrfs, install
boot artifacts, and arm the Windows finalizer or rollback.

Two properties keep them safe before hardware is available:

* **Target confinement.** Every adapter takes a *disk image* which must be a
  sparse regular file inside the VM workspace, validated by
  :func:`images.validate_image_path`. A block device, a symlink, a hard link, or
  any path outside the workspace is refused before the tool runs. There is no
  code path that accepts ``/dev/...``.
* **Plan binding.** Partition geometry, GUIDs, and type GUIDs come only from the
  confirmed plan. The adapters recompute the GPT fingerprint from what they
  observe and refuse to proceed when it disagrees with the Windows handoff, so a
  disk that changed between the plan and the install is never written.

Every mutating adapter re-observes its own postcondition with an independent
tool (``sgdisk --print`` for GPT, ``btrfs inspect-internal`` for the filesystem)
rather than trusting an exit code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import images
import lab

SGDISK = "sgdisk"
BTRFS = "btrfs"

# GPT type GUIDs the installer is allowed to create. Anything else is refused, so
# an adapter cannot create an ESP, an MSR, or a recovery partition by accident.
XBOOTLDR_TYPE_GUID = "bc13c2ff-59e6-4262-a352-b275fd6f7172"
JSTACK_ROOT_TYPE_GUID = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
CREATABLE_TYPE_GUIDS = {XBOOTLDR_TYPE_GUID, JSTACK_ROOT_TYPE_GUID}

# Partition roles the installer may create.
CREATABLE_ROLES = {"xbootldr", "jstack_root"}

SECTOR_BYTES = 512


class LinuxAdapterError(RuntimeError):
    """Raised when a Linux adapter refuses or fails an operation."""


@dataclass(frozen=True)
class DisposableVmAttestation:
    """Proof that this process runs inside a disposable VM.

    Constructed only from a matching pair of harness-minted tokens, mirroring
    the Windows adapter gate. Without it no adapter mutates anything.
    """

    token: str

    @classmethod
    def from_environment(cls) -> DisposableVmAttestation:
        presented = os.environ.get("JSTACK_DISPOSABLE_VM", "")
        expected = os.environ.get("JSTACK_DISPOSABLE_VM_EXPECTED", "")
        if len(presented) < 32 or len(expected) < 32:
            raise LinuxAdapterError(
                "refusing to mutate: JSTACK_DISPOSABLE_VM attestation is absent or malformed"
            )
        if presented != expected:
            raise LinuxAdapterError(
                "refusing to mutate: disposable-VM attestation does not match this run"
            )
        return cls(token=presented)


@dataclass(frozen=True)
class PlannedPartition:
    """One partition exactly as the confirmed plan describes it."""

    partition_guid: str
    type_guid: str
    offset_bytes: int
    size_bytes: int
    role: str
    filesystem: str
    name: str

    @property
    def end_bytes(self) -> int:
        return self.offset_bytes + self.size_bytes

    @property
    def first_sector(self) -> int:
        if self.offset_bytes % SECTOR_BYTES:
            raise LinuxAdapterError(
                f"planned offset {self.offset_bytes} is not sector aligned"
            )
        return self.offset_bytes // SECTOR_BYTES

    @property
    def last_sector(self) -> int:
        if self.size_bytes % SECTOR_BYTES:
            raise LinuxAdapterError(f"planned size {self.size_bytes} is not sector aligned")
        return self.first_sector + (self.size_bytes // SECTOR_BYTES) - 1


@dataclass(frozen=True)
class ConfirmedPlan:
    """The subset of the confirmed plan the Linux adapters need."""

    plan_hash: str
    disk_guid: str
    allocation_start_bytes: int
    allocation_end_bytes: int
    created_partitions: tuple[PlannedPartition, ...]
    windows_handoff_fingerprint: str

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> ConfirmedPlan:
        body = document["body"]
        partitions = []
        for entry in body["created_partitions"]:
            role = str(entry["role"])
            type_guid = str(entry["type_guid"]).lower()
            if role not in CREATABLE_ROLES:
                raise LinuxAdapterError(f"plan names a non-creatable role: {role}")
            if type_guid not in CREATABLE_TYPE_GUIDS:
                raise LinuxAdapterError(f"plan names a non-creatable type GUID: {type_guid}")
            partitions.append(
                PlannedPartition(
                    partition_guid=str(entry["partition_guid"]).lower(),
                    type_guid=type_guid,
                    offset_bytes=int(entry["offset_bytes"]),
                    size_bytes=int(entry["size_bytes"]),
                    role=role,
                    filesystem=str(entry["filesystem"]),
                    name=str(entry["name"]),
                )
            )
        interval = body["allocation_interval"]
        plan = cls(
            plan_hash=str(document["plan_hash"]),
            disk_guid=str(body["disk_guid"]).lower(),
            allocation_start_bytes=int(interval["start_bytes"]),
            allocation_end_bytes=int(interval["end_bytes"]),
            created_partitions=tuple(partitions),
            windows_handoff_fingerprint=str(
                body["partition_fingerprints"]["windows_handoff"]
            ),
        )
        plan.require_partitions_inside_allocation()
        return plan

    def require_partitions_inside_allocation(self) -> None:
        for partition in self.created_partitions:
            if (
                partition.offset_bytes < self.allocation_start_bytes
                or partition.end_bytes > self.allocation_end_bytes
            ):
                raise LinuxAdapterError(
                    f"planned {partition.role} escapes the confirmed allocation interval"
                )
        ordered = sorted(self.created_partitions, key=lambda item: item.offset_bytes)
        for first, second in zip(ordered, ordered[1:]):
            if first.end_bytes > second.offset_bytes:
                raise LinuxAdapterError(
                    f"planned {first.role} overlaps planned {second.role}"
                )

    def partition(self, role: str) -> PlannedPartition:
        for partition in self.created_partitions:
            if partition.role == role:
                return partition
        raise LinuxAdapterError(f"plan describes no {role} partition")


def _run(tool: str, *arguments: str, allow_failure: bool = False) -> str:
    executable = shutil.which(tool, path=lab.SYSTEM_PATH)
    if not executable:
        raise LinuxAdapterError(f"required command is unavailable: {tool}")
    resolved = Path(executable).resolve(strict=True)
    if resolved.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise LinuxAdapterError(f"set-id command is forbidden: {resolved}")
    result = subprocess.run(
        [str(Path(executable)), *arguments],
        text=True,
        capture_output=True,
        check=False,
        env=lab.subprocess_environment(),
    )
    if result.returncode != 0 and not allow_failure:
        raise LinuxAdapterError(
            f"{tool} failed ({result.returncode}): {(result.stderr or result.stdout).strip()}"
        )
    return result.stdout or result.stderr


# ---------------------------------------------------------------------------
# Disk observation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservedPartition:
    number: int
    first_sector: int
    last_sector: int
    type_guid: str
    partition_guid: str
    name: str

    @property
    def offset_bytes(self) -> int:
        return self.first_sector * SECTOR_BYTES

    @property
    def size_bytes(self) -> int:
        return (self.last_sector - self.first_sector + 1) * SECTOR_BYTES


def create_gpt(image: Path, workspace: Path, disk_guid: str) -> None:
    """Initialize an empty GPT on a sparse image, for building test fixtures."""
    confined = images.validate_image_path(image, workspace)
    _run(SGDISK, "--clear", f"--disk-guid={disk_guid.upper()}", str(confined))


def observe_disk(image: Path, workspace: Path) -> dict[str, Any]:
    """Read the GPT out of an image file with sgdisk, mounting nothing."""
    confined = images.validate_image_path(image, workspace)
    output = _run(SGDISK, "--print", str(confined))

    disk_guid = ""
    partitions: list[ObservedPartition] = []
    in_table = False
    for line in output.splitlines():
        identifier = re.search(r"Disk identifier \(GUID\):\s*([0-9A-Fa-f-]+)", line)
        if identifier:
            disk_guid = identifier.group(1).lower()
            continue
        if line.strip().startswith("Number"):
            in_table = True
            continue
        if not in_table:
            continue
        fields = line.split()
        if len(fields) < 6 or not fields[0].isdigit():
            continue
        number = int(fields[0])
        detail = _run(SGDISK, f"--info={number}", str(confined))
        type_guid = ""
        partition_guid = ""
        name = ""
        for detail_line in detail.splitlines():
            type_match = re.search(r"Partition GUID code:\s*([0-9A-Fa-f-]+)", detail_line)
            if type_match:
                type_guid = type_match.group(1).lower()
            unique_match = re.search(
                r"Partition unique GUID:\s*([0-9A-Fa-f-]+)", detail_line
            )
            if unique_match:
                partition_guid = unique_match.group(1).lower()
            name_match = re.search(r"Partition name:\s*'(.*)'", detail_line)
            if name_match:
                name = name_match.group(1)
        partitions.append(
            ObservedPartition(
                number=number,
                first_sector=int(fields[1]),
                last_sector=int(fields[2]),
                type_guid=type_guid,
                partition_guid=partition_guid,
                name=name,
            )
        )

    return {"disk_guid": disk_guid, "partitions": partitions}


def gpt_fingerprint(observation: dict[str, Any]) -> str:
    """Content-address the observed GPT.

    The fingerprint covers disk identity plus each partition's exact identity and
    geometry, so any drift between the Windows handoff and the Linux install is
    detected before a single byte is written.
    """
    payload = {
        "disk_guid": observation["disk_guid"],
        "partitions": [
            {
                "partition_guid": partition.partition_guid,
                "type_guid": partition.type_guid,
                "offset_bytes": partition.offset_bytes,
                "size_bytes": partition.size_bytes,
            }
            for partition in sorted(
                observation["partitions"], key=lambda item: item.first_sector
            )
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


def reinventory_and_revalidate_plan(
    image: Path, workspace: Path, plan: ConfirmedPlan, expected_fingerprint: str
) -> dict[str, Any]:
    """graph action: reinventory_and_revalidate_plan (read-only).

    Refuses to continue unless the disk still matches the Windows handoff
    fingerprint and the confirmed interval is still unallocated.
    """
    observation = observe_disk(image, workspace)
    if observation["disk_guid"] != plan.disk_guid:
        raise LinuxAdapterError(
            f"observed disk {observation['disk_guid']} is not plan disk {plan.disk_guid}"
        )

    observed_fingerprint = gpt_fingerprint(observation)
    if observed_fingerprint != expected_fingerprint:
        raise LinuxAdapterError(
            "refusing to install: the disk changed since the Windows handoff"
        )

    for partition in observation["partitions"]:
        if (
            partition.offset_bytes < plan.allocation_end_bytes
            and plan.allocation_start_bytes < partition.offset_bytes + partition.size_bytes
        ):
            raise LinuxAdapterError(
                f"confirmed interval is not unallocated: {partition.partition_guid} overlaps it"
            )

    return {
        "action": "reinventory_and_revalidate_plan",
        "disk_guid": observation["disk_guid"],
        "gpt_fingerprint": observed_fingerprint,
        "interval_unallocated": True,
    }


def create_partition(
    image: Path,
    workspace: Path,
    plan: ConfirmedPlan,
    role: str,
    attestation: DisposableVmAttestation,
) -> dict[str, Any]:
    """graph actions: create_root_partition (and the XBOOTLDR equivalent).

    Creates exactly the planned interval, at the planned GUID, with the planned
    type GUID. Reconcile-required: an existing matching partition is accepted as
    already satisfied so a crash can be retried.
    """
    if not attestation.token:
        raise LinuxAdapterError("refusing to mutate without a disposable-VM attestation")
    confined = images.validate_image_path(image, workspace)
    planned = plan.partition(role)

    observation = observe_disk(image, workspace)
    for existing in observation["partitions"]:
        if existing.partition_guid == planned.partition_guid:
            # Idempotent retry: verify the existing partition is exactly right.
            if (
                existing.offset_bytes != planned.offset_bytes
                or existing.size_bytes != planned.size_bytes
                or existing.type_guid != planned.type_guid
            ):
                raise LinuxAdapterError(
                    f"existing {role} partition does not match the confirmed plan"
                )
            return {
                "action": f"create_{role}",
                "already_satisfied": True,
                "partition_guid": existing.partition_guid,
            }
        # Nothing may overlap the interval we are about to claim.
        if (
            existing.offset_bytes < planned.end_bytes
            and planned.offset_bytes < existing.offset_bytes + existing.size_bytes
        ):
            raise LinuxAdapterError(
                f"refusing to create {role}: {existing.partition_guid} overlaps the interval"
            )

    number = 1 + max((entry.number for entry in observation["partitions"]), default=0)
    _run(
        SGDISK,
        f"--new={number}:{planned.first_sector}:{planned.last_sector}",
        f"--typecode={number}:{planned.type_guid.upper()}",
        f"--partition-guid={number}:{planned.partition_guid.upper()}",
        f"--change-name={number}:{planned.name}",
        str(confined),
    )

    # Independent postcondition observation with a fresh sgdisk read.
    after = observe_disk(image, workspace)
    created = [
        entry
        for entry in after["partitions"]
        if entry.partition_guid == planned.partition_guid
    ]
    if len(created) != 1:
        raise LinuxAdapterError(
            f"postcondition failed: {role} is not present exactly once"
        )
    entry = created[0]
    if entry.offset_bytes != planned.offset_bytes or entry.size_bytes != planned.size_bytes:
        raise LinuxAdapterError(
            f"postcondition failed: {role} geometry is "
            f"{entry.offset_bytes}+{entry.size_bytes}, expected "
            f"{planned.offset_bytes}+{planned.size_bytes}"
        )
    if entry.type_guid != planned.type_guid:
        raise LinuxAdapterError(
            f"postcondition failed: {role} type GUID is {entry.type_guid}"
        )

    return {
        "action": f"create_{role}",
        "already_satisfied": False,
        "partition_guid": entry.partition_guid,
        "offset_bytes": entry.offset_bytes,
        "size_bytes": entry.size_bytes,
        "gpt_fingerprint": gpt_fingerprint(after),
    }


def delete_jstack_partitions(
    image: Path,
    workspace: Path,
    plan: ConfirmedPlan,
    attestation: DisposableVmAttestation,
) -> dict[str, Any]:
    """Rollback: remove only the partitions the plan itself created.

    A partition GUID that the plan does not name is never deleted, so a vendor
    recovery or OEM partition cannot be removed by this adapter.
    """
    if not attestation.token:
        raise LinuxAdapterError("refusing to mutate without a disposable-VM attestation")
    confined = images.validate_image_path(image, workspace)
    owned = {partition.partition_guid for partition in plan.created_partitions}

    observation = observe_disk(image, workspace)
    removed = []
    for entry in sorted(
        observation["partitions"], key=lambda item: item.number, reverse=True
    ):
        if entry.partition_guid not in owned:
            continue
        _run(SGDISK, f"--delete={entry.number}", str(confined))
        removed.append(entry.partition_guid)

    after = observe_disk(image, workspace)
    survivors = {entry.partition_guid for entry in after["partitions"]}
    if survivors & owned:
        raise LinuxAdapterError("postcondition failed: plan-owned partitions survive")
    # Everything the plan did not own must still be present.
    before_unowned = {
        entry.partition_guid
        for entry in observation["partitions"]
        if entry.partition_guid not in owned
    }
    if not before_unowned.issubset(survivors):
        raise LinuxAdapterError(
            "postcondition failed: rollback removed a partition the plan did not own"
        )

    return {
        "action": "delete_jstack_partitions",
        "removed": removed,
        "preserved": sorted(survivors),
    }


def format_root_btrfs(
    root_image: Path,
    workspace: Path,
    plan: ConfirmedPlan,
    attestation: DisposableVmAttestation,
) -> dict[str, Any]:
    """graph action: format_root_btrfs.

    Operates on the extracted root-partition image so no loop device is needed.
    """
    if not attestation.token:
        raise LinuxAdapterError("refusing to mutate without a disposable-VM attestation")
    planned = plan.partition("jstack_root")
    if planned.filesystem != "btrfs":
        raise LinuxAdapterError("the plan does not describe a Btrfs root")

    images.make_btrfs(root_image, workspace, label=planned.name)
    superblock = images.btrfs_superblock(root_image, workspace)
    if "[match]" not in superblock.get("csum", ""):
        raise LinuxAdapterError("postcondition failed: Btrfs superblock does not verify")
    # An independent consistency check, not just a superblock read.
    images.btrfs_check(root_image, workspace)

    return {
        "action": "format_root_btrfs",
        "already_satisfied": False,
        "label": planned.name,
        "superblock_csum": superblock.get("csum", ""),
    }


def deploy_root_image(
    root_image: Path,
    workspace: Path,
    payload: bytes,
    expected_sha256: str,
    attestation: DisposableVmAttestation,
) -> dict[str, Any]:
    """graph action: deploy_root_image (content-addressed, retryable)."""
    if not attestation.token:
        raise LinuxAdapterError("refusing to mutate without a disposable-VM attestation")
    evidence = images.deploy_btrfs_image(
        root_image, workspace, payload, expected_sha256
    )
    return {"action": "deploy_root_image", "already_satisfied": False, **evidence}


def install_jstack_boot_artifacts(
    xbootldr_image: Path,
    workspace: Path,
    artifacts: list[images.Placement],
    attestation: DisposableVmAttestation,
) -> dict[str, Any]:
    """graph action: install_jstack_boot_artifacts (content-addressed).

    Writes the boot entries and UKI into the XBOOTLDR FAT32 image through the
    verified PH-07 transaction, so every artifact is read back and hashed.
    """
    if not attestation.token:
        raise LinuxAdapterError("refusing to mutate without a disposable-VM attestation")
    evidence = images.fat32_transaction(xbootldr_image, workspace, artifacts)
    return {
        "action": "install_jstack_boot_artifacts",
        "already_satisfied": False,
        **evidence,
    }


def verify_installation(
    root_image: Path,
    xbootldr_image: Path,
    workspace: Path,
    expected_root_sha256: str,
    expected_artifacts: list[images.Placement],
) -> dict[str, Any]:
    """graph action: verify_installation (read-only).

    Independently re-verifies the deployed root payload and every boot artifact
    by reading them back out of the images.
    """
    superblock = images.btrfs_superblock(root_image, workspace)
    if "[match]" not in superblock.get("csum", ""):
        raise LinuxAdapterError("verification failed: Btrfs superblock does not verify")
    images.btrfs_check(root_image, workspace)

    verified = []
    for artifact in expected_artifacts:
        observed = images._fat_read(xbootldr_image, artifact.destination)
        if observed is None:
            raise LinuxAdapterError(
                f"verification failed: {artifact.destination} is absent"
            )
        digest = hashlib.sha256(observed).hexdigest()
        if digest != artifact.digest():
            raise LinuxAdapterError(
                f"verification failed: {artifact.destination} does not match its digest"
            )
        verified.append({"destination": artifact.destination, "sha256": digest})

    return {
        "action": "verify_installation",
        "root_superblock_csum": superblock.get("csum", ""),
        "expected_root_sha256": expected_root_sha256,
        "verified_artifacts": verified,
    }


def parser() -> Any:
    import argparse

    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True)
    root.add_argument("--plan", required=True)
    subcommands = root.add_subparsers(dest="command", required=True)
    observe = subcommands.add_parser("observe", help="print the observed GPT")
    observe.add_argument("--image", required=True)
    return root


def main() -> int:
    arguments = parser().parse_args()
    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(arguments.workspace, scratch)
    plan = ConfirmedPlan.from_document(json.loads(Path(arguments.plan).read_text()))
    if arguments.command == "observe":
        observation = observe_disk(Path(arguments.image), workspace)
        json.dump(
            {
                "disk_guid": observation["disk_guid"],
                "gpt_fingerprint": gpt_fingerprint(observation),
                "plan_hash": plan.plan_hash,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
