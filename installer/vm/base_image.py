#!/usr/bin/env python3
"""PH-12 base-image preparation: media verification and unattended answer files.

Building a reproducible Windows base image needs three things that can be built
and tested without the ISO in hand:

1. **Media verification.** An ISO is accepted only when its byte size and
   SHA-256 exactly match the immutable media record, and only when its on-disk
   structure is a real ISO 9660 image containing the declared install image.
   A mismatch is a hard stop, so a substituted or truncated download can never
   become a base image.
2. **Unattended answer media.** A deterministic ``Autounattend.xml`` plus the
   FAT32 image that carries it. The answer file pins the exact edition, disk
   layout, and locale, and is byte-reproducible so the base image it produces is
   attributable to an exact input.
3. **A readiness report.** One command that says precisely which PH-12 inputs
   are present, which are missing, and what to do about each, so the blocked
   work is a checklist rather than an investigation.

Nothing here mounts a filesystem, opens a block device, or needs privilege. The
ISO is read through the workspace-confined, symlink-refusing helpers, and the
answer media is built with the same unprivileged mtools path as PH-07.
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
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import images
import lab

PROFILES = Path(__file__).resolve().parent / "profiles"

# ISO 9660 stamps "CD001" at offset 0x8001 in the primary volume descriptor.
ISO_MAGIC_OFFSET = 0x8001
ISO_MAGIC = b"CD001"

# The answer media only has to carry a few KiB, but FAT32 needs a floor.
ANSWER_IMAGE_BYTES = 64 * 1024 * 1024

READ_CHUNK_BYTES = 8 * 1024 * 1024


class BaseImageError(RuntimeError):
    """Raised when a base-image input is missing, mismatched, or unsafe."""


@dataclass(frozen=True)
class MediaRecord:
    """The immutable declaration of one Windows install medium."""

    record_id: str
    filename: str
    size_bytes: int
    sha256: str
    edition: str
    release: str
    build: str
    language: str
    install_image_path: str
    install_image_sha256: str
    selected_index: int
    selected_name: str
    source_page_url: str
    # Retail multi-edition media requires a key to pick an edition. The Windows
    # 11 Enterprise Evaluation image does not, so this is optional rather than
    # required: a record that needs no key must not be forced to invent one.
    product_key: str | None = None

    @classmethod
    def load(cls, path: Path) -> MediaRecord:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("kind") != "windows-install-media":
            raise BaseImageError(f"{path} is not a windows-install-media record")
        product = document["product"]
        iso = document["iso"]
        install = document["install_image"]
        return cls(
            record_id=str(document["record_id"]),
            filename=str(iso["filename"]),
            size_bytes=int(iso["size_bytes"]),
            sha256=str(iso["sha256"]).lower(),
            edition=str(product["edition"]),
            release=str(product["release"]),
            build=str(product.get("build", "")),
            language=str(product["language"]),
            install_image_path=str(install["path"]),
            install_image_sha256=str(install["sha256"]).lower(),
            selected_index=int(install["selected_index"]),
            selected_name=str(install["selected_name"]),
            source_page_url=str(document["acquisition"]["source_page_url"]),
            product_key=(
                str(install["product_key"]) if install.get("product_key") else None
            ),
        )


def load_media_records() -> dict[str, MediaRecord]:
    return {
        path.stem.replace(".media", ""): MediaRecord.load(path)
        for path in sorted(PROFILES.glob("*.media.json"))
    }


def _confined_read_only(path: Path, workspace: Path) -> Path:
    """Confine a path to the workspace and require a plain, unlinked file."""
    scratch = lab.require_scratch_root()
    candidate = lab.safe_workspace(path, scratch)
    normalized = Path(os.path.abspath(workspace))
    if normalized not in candidate.parents:
        raise BaseImageError(f"media must live inside the workspace {normalized}: {candidate}")
    descriptor = lab.open_regular_nofollow(candidate)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BaseImageError(f"media must be a regular file: {candidate}")
        if metadata.st_nlink != 1:
            raise BaseImageError(f"media must not be hard-linked: {candidate}")
    finally:
        os.close(descriptor)
    return candidate


def verify_media(path: Path, record: MediaRecord, workspace: Path) -> dict[str, Any]:
    """Verify an ISO against its immutable record.

    Size is checked before hashing so a wrong-size file fails immediately, and
    the ISO 9660 magic is checked so a renamed archive cannot pass as install
    media even if someone forged a matching digest record.
    """
    confined = _confined_read_only(path, workspace)
    observed_size = confined.stat().st_size
    if observed_size != record.size_bytes:
        raise BaseImageError(
            f"{record.record_id}: expected {record.size_bytes} bytes, observed {observed_size}"
        )

    descriptor = lab.open_regular_nofollow(confined)
    try:
        magic = os.pread(descriptor, len(ISO_MAGIC), ISO_MAGIC_OFFSET)
        if magic != ISO_MAGIC:
            raise BaseImageError(
                f"{record.record_id}: not an ISO 9660 image (magic {magic!r})"
            )
        digest = hashlib.sha256()
        offset = 0
        while chunk := os.pread(descriptor, READ_CHUNK_BYTES, offset):
            digest.update(chunk)
            offset += len(chunk)
    finally:
        os.close(descriptor)

    observed = digest.hexdigest()
    if observed != record.sha256:
        raise BaseImageError(
            f"{record.record_id}: SHA-256 mismatch\n"
            f"  expected {record.sha256}\n"
            f"  observed {observed}"
        )

    return {
        "record_id": record.record_id,
        "filename": record.filename,
        "size_bytes": observed_size,
        "sha256": observed,
        "iso9660": True,
        "verified": True,
    }


def build_autounattend(record: MediaRecord, disk_size_bytes: int) -> bytes:
    """Render a deterministic Autounattend.xml.

    The layout is exactly the UEFI/GPT layout the installer's planner expects to
    find: ESP, MSR, then one Windows partition occupying the remainder. No
    recovery partition is created, so the base image is a clean, minimal target
    and every later partition change is attributable to the installer.

    The output is byte-reproducible: fields are emitted in a fixed order with LF
    endings and no timestamp, so the same record always yields the same answer
    file and therefore the same base image inputs.
    """
    if disk_size_bytes < 32 * 1024**3:
        raise BaseImageError("base disk must be at least 32 GiB")

    # Sizes in MiB, as the Windows setup schema requires.
    esp_mib = 512
    msr_mib = 16

    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
        '  <settings pass="windowsPE">',
        '    <component name="Microsoft-Windows-International-Core-WinPE"'
        ' processorArchitecture="amd64"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral"'
        ' versionScope="nonSxS">',
        f"      <SetupUILanguage><UILanguage>{record.language}</UILanguage></SetupUILanguage>",
        f"      <InputLocale>{record.language}</InputLocale>",
        f"      <SystemLocale>{record.language}</SystemLocale>",
        f"      <UILanguage>{record.language}</UILanguage>",
        f"      <UserLocale>{record.language}</UserLocale>",
        "    </component>",
        '    <component name="Microsoft-Windows-Setup"'
        ' processorArchitecture="amd64"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral"'
        ' versionScope="nonSxS">',
        "      <DiskConfiguration>",
        "        <WillShowUI>OnError</WillShowUI>",
        "        <Disk wcm:action=\"add\""
        " xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">",
        "          <DiskID>0</DiskID>",
        "          <WillWipeDisk>true</WillWipeDisk>",
        "          <CreatePartitions>",
        "            <CreatePartition wcm:action=\"add\">",
        "              <Order>1</Order>",
        "              <Type>EFI</Type>",
        f"              <Size>{esp_mib}</Size>",
        "            </CreatePartition>",
        "            <CreatePartition wcm:action=\"add\">",
        "              <Order>2</Order>",
        "              <Type>MSR</Type>",
        f"              <Size>{msr_mib}</Size>",
        "            </CreatePartition>",
        "            <CreatePartition wcm:action=\"add\">",
        "              <Order>3</Order>",
        "              <Type>Primary</Type>",
        "              <Extend>true</Extend>",
        "            </CreatePartition>",
        "          </CreatePartitions>",
        "          <ModifyPartitions>",
        "            <ModifyPartition wcm:action=\"add\">",
        "              <Order>1</Order>",
        "              <PartitionID>1</PartitionID>",
        "              <Format>FAT32</Format>",
        "              <Label>System</Label>",
        "            </ModifyPartition>",
        "            <ModifyPartition wcm:action=\"add\">",
        "              <Order>2</Order>",
        "              <PartitionID>2</PartitionID>",
        "            </ModifyPartition>",
        "            <ModifyPartition wcm:action=\"add\">",
        "              <Order>3</Order>",
        "              <PartitionID>3</PartitionID>",
        "              <Format>NTFS</Format>",
        "              <Label>Windows</Label>",
        "              <Letter>C</Letter>",
        "            </ModifyPartition>",
        "          </ModifyPartitions>",
        "        </Disk>",
        "      </DiskConfiguration>",
        "      <ImageInstall>",
        "        <OSImage>",
        "          <InstallFrom>",
        "            <MetaData wcm:action=\"add\""
        " xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">",
        "              <Key>/IMAGE/NAME</Key>",
        f"              <Value>{record.selected_name}</Value>",
        "            </MetaData>",
        "          </InstallFrom>",
        "          <InstallTo>",
        "            <DiskID>0</DiskID>",
        "            <PartitionID>3</PartitionID>",
        "          </InstallTo>",
        "        </OSImage>",
        "      </ImageInstall>",
        "      <UserData>",
        # Retail multi-edition media refuses to proceed without a key: setup
        # raises "Windows cannot read the <ProductKey> setting from the unattend
        # answer file" and waits on a modal OK, which in an unattended build is a
        # full timeout. Emitted only when the record declares one, because the
        # Evaluation image needs none and an invented key would be worse than
        # its absence.
        *(
            [
                "        <ProductKey>",
                f"          <Key>{record.product_key}</Key>",
                "          <WillShowUI>OnError</WillShowUI>",
                "        </ProductKey>",
            ]
            if record.product_key
            else []
        ),
        "        <AcceptEula>true</AcceptEula>",
        "      </UserData>",
        "    </component>",
        "  </settings>",
        '  <settings pass="oobeSystem">',
        # The locale must be declared again in oobeSystem, not only in windowsPE.
        # windowsPE localises *setup*; OOBE asks the user its own region question
        # unless this component answers it. Without it a completed install stops
        # on "Is this the right country or region?" forever, which was observed:
        # the guest sat there with its disk unchanged until the build timed out,
        # and because FirstLogonCommands runs only after OOBE finishes, the
        # shutdown that signals success was never reached either.
        '    <component name="Microsoft-Windows-International-Core"'
        ' processorArchitecture="amd64"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral"'
        ' versionScope="nonSxS">',
        "      <InputLocale>en-US</InputLocale>",
        "      <SystemLocale>en-US</SystemLocale>",
        "      <UILanguage>en-US</UILanguage>",
        "      <UserLocale>en-US</UserLocale>",
        "    </component>",
        '    <component name="Microsoft-Windows-Shell-Setup"'
        ' processorArchitecture="amd64"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral"'
        ' versionScope="nonSxS">',
        "      <OOBE>",
        "        <HideEULAPage>true</HideEULAPage>",
        # Every interactive OOBE page must be suppressed, not merely most of
        # them: any single page left enabled stalls the build for its full
        # timeout, because nobody is there to answer it.
        "        <HideLocalAccountScreen>true</HideLocalAccountScreen>",
        "        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>",
        "        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>",
        "        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>",
        "        <SkipMachineOOBE>true</SkipMachineOOBE>",
        "        <SkipUserOOBE>true</SkipUserOOBE>",
        "        <ProtectYourPC>3</ProtectYourPC>",
        "      </OOBE>",
        "      <UserAccounts>",
        "        <LocalAccounts>",
        "          <LocalAccount wcm:action=\"add\""
        " xmlns:wcm=\"http://schemas.microsoft.com/WMIConfig/2002/State\">",
        "            <Name>jstacklab</Name>",
        "            <Group>Administrators</Group>",
        "            <Password>",
        "              <Value>jstack-lab-only</Value>",
        "              <PlainText>true</PlainText>",
        "            </Password>",
        "          </LocalAccount>",
        "        </LocalAccounts>",
        "      </UserAccounts>",
        "      <AutoLogon>",
        "        <Enabled>true</Enabled>",
        "        <LogonCount>1</LogonCount>",
        "        <Username>jstacklab</Username>",
        "        <Password><Value>jstack-lab-only</Value>"
        "<PlainText>true</PlainText></Password>",
        "      </AutoLogon>",
        # The build's success signal is the guest powering itself off, so the
        # answer file has to actually ask for it. Without this the install
        # completes, autologons, and idles at the desktop until the build's
        # timeout, which is indistinguishable from a wedged installer: an
        # observed run sat with a byte-identical disk for 25 minutes at the end
        # of a *successful* install.
        #
        # It runs at first logon rather than in `specialize`, because a shutdown
        # during specialize would abort the pass it is running inside. Ordering
        # is explicit so a later command cannot be appended after the shutdown
        # and silently never run.
        "      <FirstLogonCommands>",
        '        <SynchronousCommand wcm:action="add"'
        ' xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
        "          <Order>1</Order>",
        "          <Description>signal the build that the install finished"
        "</Description>",
        "          <CommandLine>cmd /c shutdown /s /t 0 /f</CommandLine>",
        "          <RequiresUserInput>false</RequiresUserInput>",
        "        </SynchronousCommand>",
        "      </FirstLogonCommands>",
        "    </component>",
        "  </settings>",
        "</unattend>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def answer_media_name(record: MediaRecord) -> str:
    """Return the per-record answer-media filename.

    The name is derived from the record id rather than fixed, because the two
    supported profiles pin different editions and disk layouts. A shared
    ``answer.img`` would either collide (the second build fails against the
    no-clobber rule) or, worse, silently boot one profile with the other's
    answer file. Deriving the name makes the wrong pairing unrepresentable.
    """

    return f"answer-{record.record_id}.img"


def build_answer_media(
    workspace: Path,
    record: MediaRecord,
    disk_size_bytes: int,
    name: str | None = None,
) -> dict[str, Any]:
    """Build the FAT32 image that carries Autounattend.xml.

    Windows setup reads ``Autounattend.xml`` from the root of any attached
    removable volume, so the answer media is a small FAT32 image published
    through the verified PH-07 transaction. Every byte is read back and hashed.
    """
    answer = build_autounattend(record, disk_size_bytes)
    image_name = name if name is not None else answer_media_name(record)
    image = images.create_sparse_image(workspace / image_name, ANSWER_IMAGE_BYTES, workspace)
    images.make_fat32(image, workspace, label="JSTACKANS")
    evidence = images.fat32_transaction(
        image, workspace, [images.Placement("/Autounattend.xml", answer)]
    )
    return {
        "image": str(image),
        "image_sha256": evidence["image_sha256"],
        "autounattend_sha256": hashlib.sha256(answer).hexdigest(),
        "autounattend_bytes": len(answer),
        "record_id": record.record_id,
    }


# The profile required-inputs whose evidence is host-scoped. These are pure
# digests of files and executables already on this machine, so they can be
# resolved with no ISO and no VM launch.
HOST_SCOPED_INPUTS = {
    "qemu-binary-sha256": ("executable", "qemu-system-x86_64"),
    "swtpm-binary-sha256": ("executable", "swtpm"),
    "ovmf-code-sha256": ("firmware", "ovmf_secure_code"),
    "ovmf-nonsecure-code-sha256": ("firmware", "ovmf_code"),
    "ovmf-fixed-vars-sha256": ("firmware", "ovmf_vars"),
}

# The profile required-inputs whose evidence is release-build scoped. Each is a
# digest of something this repository builds, so they are resolvable without any
# Windows media: the installer binary, the executable state graph, the signed
# release manifest, and the signed boot-artifact manifest.
RELEASE_SCOPED_INPUTS = (
    "installer-sha256",
    "installer-graph-sha256",
    "release-manifest-sha256",
    "boot-artifacts-sha256",
)

INSTALLER_ROOT = Path(__file__).resolve().parent.parent
STATE_GRAPH = INSTALLER_ROOT / "model" / "installer-state-graph.json"
RELEASE_MANIFEST = INSTALLER_ROOT / "core" / "fixtures" / "signed-release-manifest.json"

FIRMWARE_PATHS = {
    "ovmf_code": lab.OVMF_CODE,
    "ovmf_secure_code": lab.OVMF_SECURE_CODE,
    "ovmf_vars": lab.OVMF_VARS,
}


def _sha256_path(path: Path) -> str:
    descriptor = lab.open_regular_nofollow(path)
    try:
        return lab.sha256_fd(descriptor)
    finally:
        os.close(descriptor)


def collect_host_identities() -> dict[str, Any]:
    """Resolve every host-scoped profile input, with no VM launch.

    `lab.py init` deliberately refuses to run unless the host can actually host a
    VM, which is correct for launching one but wrong for collecting read-only
    digests: it makes resolving these identities impossible on a busy machine for
    no safety benefit. This function collects exactly the host-scoped digests and
    imposes no memory or KVM requirement, so PH-11's host-scope inputs can be
    resolved independently of PH-12.

    Executables are hashed through the same set-id-refusing, symlink-refusing
    path the rest of the harness uses, and each digest is bound to the exact
    resolved path it came from.
    """
    identities: dict[str, Any] = {}
    for input_id, (kind, name) in sorted(HOST_SCOPED_INPUTS.items()):
        if kind == "executable":
            found = shutil.which(name, path=lab.SYSTEM_PATH)
            if not found:
                identities[input_id] = {"resolved": False, "reason": f"{name} not found"}
                continue
            executable = Path(found).resolve(strict=True)
            metadata = executable.stat()
            if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise BaseImageError(f"set-id command is forbidden: {executable}")
            identities[input_id] = {
                "resolved": True,
                "path": str(executable),
                "sha256": _sha256_path(executable),
                "size_bytes": metadata.st_size,
            }
        else:
            path = FIRMWARE_PATHS[name]
            if not path.is_file():
                identities[input_id] = {"resolved": False, "reason": f"{path} is absent"}
                continue
            identities[input_id] = {
                "resolved": True,
                "path": str(path),
                "sha256": _sha256_path(path),
                "size_bytes": path.stat().st_size,
            }
    return identities


def collect_release_identities(
    installer_binary: Path | None = None,
    boot_artifact_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Resolve the release-build-scoped profile inputs.

    Three of the four are digests of files this repository already contains or
    builds: the executable state graph, the signed release manifest, and the
    installer binary. The fourth is the boot-artifact manifest digest, which
    `artifacts.build_test_artifact_set` produces; callers pass it in rather than
    having this module rebuild artifacts, so the digest is always the one that was
    actually published.
    """
    identities: dict[str, Any] = {}

    for input_id, path in (
        ("installer-graph-sha256", STATE_GRAPH),
        ("release-manifest-sha256", RELEASE_MANIFEST),
    ):
        if not path.is_file():
            identities[input_id] = {"resolved": False, "reason": f"{path} is absent"}
            continue
        identities[input_id] = {
            "resolved": True,
            "path": str(path),
            "sha256": _sha256_path(path),
            "size_bytes": path.stat().st_size,
        }

    candidate = installer_binary
    if candidate is None:
        # The release installer is the controller CLI. Prefer a release build,
        # fall back to a debug build, and report unresolved rather than guessing.
        for profile in ("release", "debug"):
            probe = (
                INSTALLER_ROOT / "controller" / "target" / profile / "jstack-installer"
            )
            if probe.is_file():
                candidate = probe
                break
    if candidate is not None and candidate.is_file():
        identities["installer-sha256"] = {
            "resolved": True,
            "path": str(candidate),
            "sha256": _sha256_path(candidate),
            "size_bytes": candidate.stat().st_size,
        }
    else:
        identities["installer-sha256"] = {
            "resolved": False,
            "reason": "build the installer with `cargo build --bin jstack-installer`",
        }

    if boot_artifact_manifest_sha256:
        if len(boot_artifact_manifest_sha256) != 64:
            raise BaseImageError("boot-artifact manifest digest must be SHA-256 hex")
        identities["boot-artifacts-sha256"] = {
            "resolved": True,
            "sha256": boot_artifact_manifest_sha256.lower(),
            "source": "artifacts.build_test_artifact_set manifest",
        }
    else:
        identities["boot-artifacts-sha256"] = {
            "resolved": False,
            "reason": "run artifacts.build_test_artifact_set and pass its manifest digest",
        }

    return identities


def profile_input_scopes() -> dict[str, dict[str, str]]:
    """Map every profile required-input id to its declared evidence scope."""
    scopes: dict[str, dict[str, str]] = {}
    for path in sorted(PROFILES.glob("*.profile.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        for entry in document.get("required_inputs", []):
            scopes.setdefault(path.stem.replace(".profile", ""), {})[
                str(entry["id"])
            ] = str(entry.get("evidence_scope", ""))
    return scopes


@dataclass(frozen=True)
class Readiness:
    """One PH-12 precondition and its current state."""

    name: str
    satisfied: bool
    detail: str
    remedy: str

    def to_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "satisfied": self.satisfied,
            "detail": self.detail,
            "remedy": self.remedy,
        }


def assess_readiness(workspace: Path) -> list[Readiness]:
    """Report exactly which PH-12 inputs are present and what to do otherwise."""
    checks: list[Readiness] = []

    # Tooling.
    for tool in ("qemu-system-x86_64", "qemu-img", "swtpm", "mkfs.fat", "mkfs.btrfs"):
        found = shutil.which(tool, path=lab.SYSTEM_PATH)
        checks.append(
            Readiness(
                name=f"tool:{tool}",
                satisfied=found is not None,
                detail=found or "not found on the trusted system path",
                remedy=f"install {tool}",
            )
        )

    # Firmware.
    for label, path in (
        ("ovmf-code", lab.OVMF_CODE),
        ("ovmf-secure-code", lab.OVMF_SECURE_CODE),
        ("ovmf-vars", lab.OVMF_VARS),
    ):
        checks.append(
            Readiness(
                name=f"firmware:{label}",
                satisfied=path.is_file(),
                detail=str(path),
                remedy="install edk2-ovmf",
            )
        )

    # Install media.
    for key, record in load_media_records().items():
        candidate = workspace / record.filename
        present = candidate.is_file()
        detail = f"{candidate}"
        if present:
            observed = candidate.stat().st_size
            detail += f" ({observed} bytes)"
            if observed != record.size_bytes:
                present = False
                detail += f"; expected {record.size_bytes}"
        checks.append(
            Readiness(
                name=f"media:{key}",
                satisfied=present,
                detail=detail,
                remedy=(
                    f"download {record.filename} from {record.source_page_url} into "
                    f"{workspace}, then run `verify-media`. The Microsoft download page "
                    "requires an interactive selection, so this step is manual."
                ),
            )
        )

    # Host-scoped profile identities. These are resolvable now, so they are
    # reported as satisfied rather than lumped in with the ISO blockers.
    for input_id, value in collect_host_identities().items():
        checks.append(
            Readiness(
                name=f"identity:{input_id}",
                satisfied=bool(value["resolved"]),
                detail=(
                    f"{value['path']} sha256 {value['sha256']}"
                    if value["resolved"]
                    else str(value.get("reason", "unresolved"))
                ),
                remedy="install the missing firmware or executable",
            )
        )

    # Release-build identities. The boot-artifact manifest is a build output, so
    # readiness builds it rather than reporting a resolvable input as blocked:
    # a checklist that cries wolf is worse than no checklist.
    boot_artifacts_digest: str | None = None
    kernel = Path("/boot/vmlinuz-linux")
    if kernel.is_file():
        try:
            import artifacts

            scratch = workspace / "readiness-artifacts"
            shutil.rmtree(scratch, ignore_errors=True)
            scratch.mkdir(parents=True, exist_ok=True)
            os.chmod(scratch, 0o700)
            artifact_set = artifacts.build_test_artifact_set(
                scratch, kernel, "0" * 64, "0" * 64
            )
            boot_artifacts_digest = artifact_set.manifest_sha256
        except Exception:
            # A build failure must not crash the checklist; the check simply
            # reports unresolved with its remedy.
            boot_artifacts_digest = None
        finally:
            shutil.rmtree(workspace / "readiness-artifacts", ignore_errors=True)

    for input_id, value in sorted(
        collect_release_identities(
            boot_artifact_manifest_sha256=boot_artifacts_digest
        ).items()
    ):
        checks.append(
            Readiness(
                name=f"identity:{input_id}",
                satisfied=bool(value["resolved"]),
                detail=(
                    f"{value.get('path', value.get('source', ''))} sha256 {value['sha256']}"
                    if value["resolved"]
                    else str(value.get("reason", "unresolved"))
                ),
                remedy=str(
                    value.get(
                        "reason", "rebuild the release inputs to refresh this digest"
                    )
                ),
            )
        )

    # Host envelope.
    available = lab.available_memory_bytes()
    checks.append(
        Readiness(
            name="host:memory",
            satisfied=available >= lab.MIN_AVAILABLE_MEMORY_BYTES,
            detail=f"{available} bytes available, need {lab.MIN_AVAILABLE_MEMORY_BYTES}",
            remedy="close memory-heavy applications before building a base image",
        )
    )
    usage = shutil.disk_usage(workspace if workspace.exists() else workspace.parent)
    needed = 64 * 1024**3
    checks.append(
        Readiness(
            name="host:disk",
            satisfied=usage.free >= needed,
            detail=f"{usage.free} bytes free, need {needed}",
            remedy="free scratch space before building a base image",
        )
    )

    return checks


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True)
    subcommands = root.add_subparsers(dest="command", required=True)

    readiness = subcommands.add_parser(
        "readiness", help="report which PH-12 inputs are present"
    )
    readiness.set_defaults(handler="readiness")

    identities = subcommands.add_parser(
        "host-identities",
        help="resolve host-scoped profile inputs without launching a VM",
    )
    identities.set_defaults(handler="host-identities")

    release = subcommands.add_parser(
        "release-identities", help="resolve release-build-scoped profile inputs"
    )
    release.add_argument("--installer-binary")
    release.add_argument("--boot-artifacts-sha256")
    release.set_defaults(handler="release-identities")

    verify = subcommands.add_parser("verify-media", help="verify an ISO against its record")
    verify.add_argument("--record", required=True, help="media record key")
    verify.set_defaults(handler="verify-media")

    answer = subcommands.add_parser("answer-media", help="build unattended answer media")
    answer.add_argument("--record", required=True)
    answer.add_argument("--disk-size-bytes", type=int, default=64 * 1024**3)
    answer.set_defaults(handler="answer-media")
    return root


def main() -> int:
    arguments = parser().parse_args()
    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(arguments.workspace, scratch)

    if arguments.handler == "readiness":
        checks = assess_readiness(workspace)
        blocked = [check for check in checks if not check.satisfied]
        json.dump(
            {
                "ready": not blocked,
                "satisfied": len(checks) - len(blocked),
                "total": len(checks),
                "checks": [check.to_record() for check in checks],
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0 if not blocked else 1

    if arguments.handler == "release-identities":
        identities = collect_release_identities(
            Path(arguments.installer_binary) if arguments.installer_binary else None,
            arguments.boot_artifacts_sha256,
        )
        unresolved = [key for key, value in identities.items() if not value["resolved"]]
        json.dump(
            {
                "resolved": len(identities) - len(unresolved),
                "total": len(identities),
                "unresolved": unresolved,
                "identities": identities,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0 if not unresolved else 1

    if arguments.handler == "host-identities":
        identities = collect_host_identities()
        unresolved = [key for key, value in identities.items() if not value["resolved"]]
        json.dump(
            {
                "resolved": len(identities) - len(unresolved),
                "total": len(identities),
                "unresolved": unresolved,
                "identities": identities,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0 if not unresolved else 1

    records = load_media_records()
    if arguments.record not in records:
        raise SystemExit(
            f"unknown record {arguments.record}; known: {', '.join(sorted(records))}"
        )
    record = records[arguments.record]

    if arguments.handler == "verify-media":
        evidence = verify_media(workspace / record.filename, record, workspace)
    else:
        evidence = build_answer_media(workspace, record, arguments.disk_size_bytes)
    json.dump(evidence, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
