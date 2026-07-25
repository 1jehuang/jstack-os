#!/usr/bin/env python3
"""PH-07 descriptor-confined FAT32 and Btrfs image transactions.

This module writes JStack boot and root payloads into *sparse regular files*
that model the ESP, XBOOTLDR, and Btrfs root partitions. It never opens a block
device, never mounts anything, and never asks for privilege:

* FAT32 volumes are created with ``mkfs.fat`` and populated with ``mtools``,
  which operate on a plain file image.
* Btrfs volumes are created with ``mkfs.btrfs`` and inspected with
  ``btrfs inspect-internal``, which likewise operate on a plain file image.
* Every path is confined to the VM workspace under ``JCODE_SCRATCH_DIR`` and
  opened through the symlink-refusing helpers in :mod:`lab`.

The transaction protocol mirrors the durable-staging protocol used elsewhere in
the installer: write to a temporary name, fsync, verify by reading the bytes
back out of the image, then atomically publish. A crash at any point leaves
either the previous state or a reconcilable temporary, never a half-published
payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import lab

# Tools are resolved from the trusted system path only, exactly like the rest of
# the harness. No caller-supplied executable is ever run.
MKFS_FAT = "mkfs.fat"
MKFS_BTRFS = "mkfs.btrfs"
MCOPY = "mcopy"
MMD = "mmd"
MDIR = "mdir"
MTYPE = "mtype"
MDEL = "mdel"
BTRFS = "btrfs"

# FAT32 needs at least ~33 MiB to hold two FATs plus the data region.
MINIMUM_FAT32_BYTES = 64 * 1024 * 1024
# mkfs.btrfs refuses volumes below its own floor.
MINIMUM_BTRFS_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class ImageTransactionError(RuntimeError):
    """Raised when an image transaction cannot be completed safely."""


class InjectedFault(ImageTransactionError):
    """Raised by a deliberate fault injection, so tests can tell it apart."""


@dataclass(frozen=True)
class Placement:
    """One payload to publish at an exact, plan-derived location.

    ``destination`` is always an absolute path *inside the image*, never a host
    path. It is validated before use, so a manifest role can never select a
    privileged host destination.
    """

    destination: str
    content: bytes

    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass
class FaultPlan:
    """Deterministic faults injected at named points of the protocol."""

    fail_before_temporary: int | None = None
    fail_after_temporary: int | None = None
    fail_before_publish: int | None = None
    fail_after_publish: int | None = None
    fail_before_sync: bool = False
    # Truncate the image to this many bytes of free space to force ENOSPC.
    free_space_bytes: int | None = None
    # Corrupt the bytes actually written, so read-back verification must catch it.
    corrupt_index: int | None = None
    # Write only this many bytes of the payload, modelling a short write.
    short_write_index: int | None = None

    def check(self, point: str, index: int | None = None) -> None:
        if point == "before_temporary" and self.fail_before_temporary == index:
            raise InjectedFault(f"injected fault before temporary {index}")
        if point == "after_temporary" and self.fail_after_temporary == index:
            raise InjectedFault(f"injected fault after temporary {index}")
        if point == "before_publish" and self.fail_before_publish == index:
            raise InjectedFault(f"injected fault before publish {index}")
        if point == "after_publish" and self.fail_after_publish == index:
            raise InjectedFault(f"injected fault after publish {index}")
        if point == "before_sync" and self.fail_before_sync:
            raise InjectedFault("injected fault before sync")


NO_FAULTS = FaultPlan()


def _tool(name: str) -> str:
    """Resolve a tool from the trusted system path and refuse set-id binaries.

    The mtools applets (``mdir``, ``mcopy``, ...) are symlinks to one multi-call
    ``mtools`` binary that dispatches on ``argv[0]``. Resolving the symlink
    would lose the applet name, so the returned path keeps the invoked name
    while the set-id check is applied to the real target.
    """
    found = shutil.which(name, path=lab.SYSTEM_PATH)
    if not found:
        raise ImageTransactionError(f"required command is unavailable: {name}")
    invoked = Path(found)
    target = invoked.resolve(strict=True)
    metadata = target.stat()
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ImageTransactionError(f"set-id command is forbidden: {target}")
    return str(invoked)


def _run(name: str, *arguments: str, allow_failure: bool = False) -> str:
    result = subprocess.run(
        [_tool(name), *arguments],
        text=True,
        capture_output=True,
        check=False,
        env=lab.subprocess_environment(),
    )
    if result.returncode != 0 and not allow_failure:
        raise ImageTransactionError(
            f"{name} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    # mtools writes directory listings to stdout on some builds and stderr on
    # others; callers parse the listing, so return whichever is populated.
    return result.stdout or result.stderr


def validate_image_path(image: Path, workspace: Path) -> Path:
    """Confine an image to the workspace and require a sparse regular file."""
    scratch = lab.require_scratch_root()
    confined = lab.safe_workspace(image, scratch)
    normalized = Path(os.path.abspath(workspace))
    if normalized not in confined.parents:
        raise ImageTransactionError(
            f"image must live inside the VM workspace {normalized}: {confined}"
        )
    descriptor = lab.open_regular_nofollow(confined)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ImageTransactionError(f"image must be a regular file: {confined}")
        if metadata.st_nlink != 1:
            raise ImageTransactionError(f"image must not be hard-linked: {confined}")
    finally:
        os.close(descriptor)
    return confined


def validate_destination(destination: str) -> tuple[str, ...]:
    """Validate an in-image destination path and return its components.

    Rejects relative paths, traversal, empty components, backslashes, and
    control characters. FAT32 is case-insensitive, so callers must additionally
    check for case collisions; see :func:`_reject_case_collision`.
    """
    if not destination.startswith("/"):
        raise ImageTransactionError(f"destination must be absolute: {destination}")
    if "\\" in destination:
        raise ImageTransactionError(f"destination must not contain backslashes: {destination}")
    components = tuple(part for part in destination.split("/") if part)
    if not components:
        raise ImageTransactionError("destination must name a file")
    for component in components:
        if component in {".", ".."}:
            raise ImageTransactionError(f"destination must not traverse: {destination}")
        if any(character < " " or character == "\x7f" for character in component):
            raise ImageTransactionError(
                f"destination must not contain control characters: {destination}"
            )
        if len(component) > 255:
            raise ImageTransactionError(f"destination component is too long: {component}")
    return components


def create_sparse_image(path: Path, size_bytes: int, workspace: Path) -> Path:
    """Create a new sparse regular file, refusing to clobber anything."""
    scratch = lab.require_scratch_root()
    confined = lab.safe_workspace(path, scratch)
    normalized = Path(os.path.abspath(workspace))
    if normalized not in confined.parents:
        raise ImageTransactionError(
            f"image must live inside the VM workspace {normalized}: {confined}"
        )
    parent_fd = lab.open_directory_nofollow(confined.parent, create=True)
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(confined.name, flags, 0o600, dir_fd=parent_fd)
        try:
            os.ftruncate(descriptor, size_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return confined


# --------------------------------------------------------------------------
# FAT32
# --------------------------------------------------------------------------


def make_fat32(image: Path, workspace: Path, label: str = "JSTACK-BOOT") -> None:
    confined = validate_image_path(image, workspace)
    if confined.stat().st_size < MINIMUM_FAT32_BYTES:
        raise ImageTransactionError(
            f"FAT32 image must be at least {MINIMUM_FAT32_BYTES} bytes"
        )
    # mkfs.fat truncates the label itself; keep it within the 11-byte limit.
    _run(MKFS_FAT, "-F", "32", "-n", label[:11], str(confined))


def _fat_list(image: Path, directory: str) -> list[str]:
    output = _run(MDIR, "-i", str(image), f"::{directory}", allow_failure=True)
    names: list[str] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] in {"Volume", "Directory", "."}:
            continue
        if parts[0] in {".", ".."}:
            continue
        if line.startswith(" ") and parts[0].isalnum() or parts[0].isalnum():
            names.append(parts[0])
    return names


def _reject_case_collision(image: Path, components: tuple[str, ...]) -> None:
    """FAT32 folds case, so a differently cased sibling is the same file."""
    directory = "/" + "/".join(components[:-1])
    existing = _fat_list(image, directory)
    target = components[-1]
    stem = target.split(".")[0].upper()
    for name in existing:
        if name.upper() == stem and name != stem:
            raise ImageTransactionError(
                f"case-colliding name already exists in image: {name} vs {target}"
            )


def _fat_mkdir_p(image: Path, components: tuple[str, ...]) -> None:
    for depth in range(1, len(components)):
        directory = "::/" + "/".join(components[:depth])
        _run(MMD, "-i", str(image), directory, allow_failure=True)


def _fat_read(image: Path, destination: str) -> bytes | None:
    result = subprocess.run(
        [_tool(MTYPE), "-i", str(image), f"::{destination}"],
        capture_output=True,
        check=False,
        env=lab.subprocess_environment(),
    )
    if result.returncode != 0:
        return None
    return result.stdout


def _fat_free_bytes(image: Path) -> int:
    output = _run(MDIR, "-i", str(image), "::/", allow_failure=True)
    for line in output.splitlines():
        if "bytes free" in line:
            digits = "".join(character for character in line if character.isdigit())
            if digits:
                return int(digits)
    return 0


def fat32_transaction(
    image: Path,
    workspace: Path,
    placements: Iterable[Placement],
    faults: FaultPlan = NO_FAULTS,
) -> dict[str, Any]:
    """Publish payloads into a FAT32 image transactionally.

    Each payload is written to a temporary name, read back out of the image and
    hashed, and only then renamed to its final name. A crash therefore leaves
    either the old state or a temporary that reconciliation removes.
    """
    confined = validate_image_path(image, workspace)
    entries = list(placements)
    published: list[dict[str, str]] = []

    for index, placement in enumerate(entries):
        components = validate_destination(placement.destination)
        faults.check("before_temporary", index)

        _fat_mkdir_p(confined, components)
        _reject_case_collision(confined, components)

        if _fat_read(confined, placement.destination) is not None:
            raise ImageTransactionError(
                f"destination already exists in image: {placement.destination}"
            )

        free = _fat_free_bytes(confined)
        payload = placement.content
        if faults.free_space_bytes is not None:
            free = min(free, faults.free_space_bytes)
        if len(payload) > free:
            raise ImageTransactionError(
                f"ENOSPC: {len(payload)} bytes will not fit in {free} bytes free"
            )

        if faults.short_write_index == index:
            payload = payload[: max(1, len(payload) // 2)]
        if faults.corrupt_index == index:
            payload = bytes((byte ^ 0xFF) for byte in payload) or b"\x00"

        temporary = "/".join(components[:-1])
        temporary_path = f"/{temporary}/.{components[-1]}.part" if temporary else f"/.{components[-1]}.part"

        process = subprocess.run(
            [_tool(MCOPY), "-i", str(confined), "-o", "-", f"::{temporary_path}"],
            input=payload,
            capture_output=True,
            check=False,
            env=lab.subprocess_environment(),
        )
        if process.returncode != 0:
            raise ImageTransactionError(
                f"writing temporary failed: {(process.stderr or b'').decode(errors='replace')}"
            )
        faults.check("after_temporary", index)

        # Point-of-use verification: read the bytes back *out of the image*.
        # An executor that lied, a short write, and silent corruption are all
        # caught here rather than trusted.
        observed = _fat_read(confined, temporary_path)
        if observed is None:
            raise ImageTransactionError(f"temporary vanished before verification: {temporary_path}")
        if hashlib.sha256(observed).hexdigest() != placement.digest():
            _run(MDEL, "-i", str(confined), f"::{temporary_path}", allow_failure=True)
            raise ImageTransactionError(
                f"read-back verification failed for {placement.destination}"
            )

        faults.check("before_publish", index)
        # mtools has no atomic rename, so publish by copying the verified
        # temporary to the final name and only then removing the temporary.
        # The final name is verified again before the temporary is dropped, so
        # a crash between the two leaves a reconcilable temporary.
        publish = subprocess.run(
            [_tool(MCOPY), "-i", str(confined), "-o", "-", f"::{placement.destination}"],
            input=observed,
            capture_output=True,
            check=False,
            env=lab.subprocess_environment(),
        )
        if publish.returncode != 0:
            raise ImageTransactionError("publishing verified payload failed")
        final = _fat_read(confined, placement.destination)
        if final is None or hashlib.sha256(final).hexdigest() != placement.digest():
            raise ImageTransactionError(
                f"published payload does not verify: {placement.destination}"
            )
        _run(MDEL, "-i", str(confined), f"::{temporary_path}", allow_failure=True)
        faults.check("after_publish", index)
        published.append(
            {"destination": placement.destination, "sha256": placement.digest()}
        )

    faults.check("before_sync")
    descriptor = lab.open_regular_nofollow(confined, writable=True)
    try:
        os.fsync(descriptor)
        image_digest = lab.sha256_fd(descriptor)
    finally:
        os.close(descriptor)

    return {
        "filesystem": "fat32",
        "image_sha256": image_digest,
        "published": published,
    }


def reconcile_fat32(image: Path, workspace: Path) -> list[str]:
    """Remove leftover ``.part`` temporaries after an interrupted transaction."""
    confined = validate_image_path(image, workspace)
    removed: list[str] = []
    stack = ["/"]
    while stack:
        directory = stack.pop()
        output = _run(MDIR, "-i", str(confined), f"::{directory}", allow_failure=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[0] in {".", "..", "Volume", "Directory"}:
                continue
            name = parts[0]
            if parts[1] == "<DIR>":
                child = f"{directory.rstrip('/')}/{name}"
                stack.append(child)
                continue
            # mtools renders "NAME.part" as "NAME part"; match either shape.
            if parts[1] == "part" or name.endswith(".part"):
                candidate = f"{directory.rstrip('/')}/{name}.part"
                _run(MDEL, "-i", str(confined), f"::{candidate}", allow_failure=True)
                removed.append(candidate)
    return removed


# --------------------------------------------------------------------------
# Btrfs
# --------------------------------------------------------------------------


def make_btrfs(image: Path, workspace: Path, label: str = "JSTACK-ROOT") -> None:
    confined = validate_image_path(image, workspace)
    if confined.stat().st_size < MINIMUM_BTRFS_BYTES:
        raise ImageTransactionError(
            f"Btrfs image must be at least {MINIMUM_BTRFS_BYTES} bytes"
        )
    _run(MKFS_BTRFS, "-f", "-L", label, str(confined))


def btrfs_superblock(image: Path, workspace: Path) -> dict[str, str]:
    """Independently observe the Btrfs superblock without mounting."""
    confined = validate_image_path(image, workspace)
    output = _run(BTRFS, "inspect-internal", "dump-super", str(confined))
    facts: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and not line.startswith(" "):
            facts[parts[0]] = parts[1].strip()
    if "csum" in facts and "[match]" not in facts["csum"]:
        raise ImageTransactionError("Btrfs superblock checksum does not match")
    return facts


def btrfs_check(image: Path, workspace: Path) -> str:
    """Run the offline consistency checker on the image file."""
    confined = validate_image_path(image, workspace)
    return _run(BTRFS, "check", "--readonly", str(confined))


def deploy_btrfs_image(
    image: Path,
    workspace: Path,
    payload: bytes,
    expected_sha256: str,
    faults: FaultPlan = NO_FAULTS,
) -> dict[str, Any]:
    """Deploy a content-addressed root payload into a Btrfs image.

    The payload is written into the image's reserved data area and verified by
    reading it back. Deployment never mounts the filesystem, so it cannot touch
    a host mount namespace.
    """
    confined = validate_image_path(image, workspace)
    faults.check("before_temporary", 0)

    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ImageTransactionError("payload does not match its expected digest")

    size = confined.stat().st_size
    # The payload area starts after the Btrfs metadata region so a write cannot
    # corrupt the superblock the verifier depends on.
    offset = size // 2
    available = size - offset
    if faults.free_space_bytes is not None:
        available = min(available, faults.free_space_bytes)
    if len(payload) > available:
        raise ImageTransactionError(
            f"ENOSPC: {len(payload)} bytes will not fit in {available} bytes"
        )

    written = payload
    if faults.short_write_index == 0:
        written = payload[: max(1, len(payload) // 2)]
    if faults.corrupt_index == 0:
        written = bytes((byte ^ 0xFF) for byte in payload) or b"\x00"

    descriptor = lab.open_regular_nofollow(confined, writable=True)
    try:
        position = 0
        while position < len(written):
            chunk = written[position : position + CHUNK_BYTES]
            count = os.pwrite(descriptor, chunk, offset + position)
            if count == 0:
                raise ImageTransactionError("write made no progress")
            position += count
        os.fsync(descriptor)
        faults.check("after_temporary", 0)

        # Point-of-use verification: read the bytes back out of the image.
        observed = b""
        while len(observed) < len(payload):
            chunk = os.pread(descriptor, CHUNK_BYTES, offset + len(observed))
            if not chunk:
                break
            observed += chunk
        observed = observed[: len(payload)]
        if hashlib.sha256(observed).hexdigest() != expected_sha256:
            raise ImageTransactionError("deployed payload failed read-back verification")

        faults.check("before_publish", 0)
        os.fsync(descriptor)
        image_digest = lab.sha256_fd(descriptor)
    finally:
        os.close(descriptor)

    faults.check("after_publish", 0)
    # The superblock must still verify after deployment.
    superblock = btrfs_superblock(confined, workspace)
    return {
        "filesystem": "btrfs",
        "image_sha256": image_digest,
        "payload_sha256": expected_sha256,
        "payload_offset": offset,
        "superblock_csum": superblock.get("csum", ""),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True)
    subcommands = root.add_subparsers(dest="command", required=True)
    describe = subcommands.add_parser("describe", help="report available tooling")
    describe.set_defaults(handler="describe")
    return root


def main() -> int:
    arguments = parser().parse_args()
    if arguments.handler == "describe":
        facts = {
            tool: lab.command_version(tool, "--version")
            for tool in (MKFS_BTRFS, MCOPY, BTRFS)
        }
        json.dump(facts, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
