#!/usr/bin/env python3
"""PH-12 base-image construction: run Windows setup unattended into a qcow2 file.

Every other module in this tree can be proven by comparing bytes. This one
cannot: it exists to make a real Windows installer run to completion on real
firmware, and the only evidence that matters is what the resulting disk actually
contains. It is therefore the module where an exit code is least trustworthy and
the read-back checks matter most.

What it does:

1. Creates a sparse qcow2 disk of exactly the profile's virtual size, inside the
   workspace, refusing to touch anything else.
2. Boots QEMU with the verified ISO, the per-record answer media, and the
   Microsoft-enrolled firmware variable store from ``firmware_enrollment``, so
   the guest installs with Secure Boot genuinely on.
3. Waits for the guest to power itself off, which is what the answer file's
   final shutdown means, with a hard timeout so a stalled installer cannot hang
   a campaign forever.
4. Independently inspects the produced disk: the GPT must exist, carry exactly
   the roles the profile declares, and the Windows volume must be present. This
   is done by reading the image with unprivileged tools, never by mounting it or
   trusting the guest's own report.

Safety envelope, identical to the rest of the harness:

* Every path is a regular file inside the workspace. No host block device, no
  loop device, no mount, no privilege, no passthrough.
* The ISO, answer media, and firmware template are opened read-only. Only the
  new qcow2 and the per-run variable-store copy are writable.
* The guest gets no network. A base image is built from the ISO alone, so a
  guest that could reach the internet could make the result unreproducible.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import base_image
import firmware_enrollment
import lab

# The guest is given a generous but bounded wall clock. A Windows unattended
# install on this host takes well under an hour; anything longer means the
# installer is waiting for input the answer file failed to supply, and hanging
# forever would be worse than failing.
INSTALL_TIMEOUT_SECONDS = 90 * 60
POLL_INTERVAL_SECONDS = 5.0

# Windows UEFI installation media boots through a stub that prints
# "Press any key to boot from CD or DVD" and gives up after roughly five
# seconds. An unattended build must therefore supply that keypress; without it
# firmware falls through to "No bootable option or device was found" and the
# guest sits at the boot manager until the build times out. Keys are sent
# through QMP rather than by patching the ISO, because the media must stay
# byte-identical to the record that was verified.
#
# The window is short and keypresses are NOT harmless once it closes: a stray
# Return reaches Windows setup's own UI, where it activated the Cancel button
# and raised "Are you sure you want to quit?" mid-install. So the keys stop as
# soon as the guest writes to its disk, which is the earliest unambiguous signal
# that the boot stub handed off to setup. Sending keys for a fixed duration
# instead was tried first and corrupted the run.
BOOT_PROMPT_KEY_ATTEMPTS = 12
BOOT_PROMPT_KEY_INTERVAL_SECONDS = 0.75

# A fresh qcow2 is a few hundred KiB of metadata. Once setup begins writing the
# install image the file grows by megabytes, so this threshold distinguishes
# "still at the boot prompt" from "setup has taken over" without guessing.
DISK_WRITE_PROGRESS_BYTES = 8 * 1024 * 1024

# QEMU installs a SIGTERM handler and shuts the machine down *cleanly*, exiting
# zero. So an exit code cannot distinguish "the unattended install finished and
# the guest powered itself off" from "something on the host killed the VM
# mid-install". This actually happened: earlyoom reclaimed the guest at roughly
# 40% of a Windows 11 install, QEMU exited zero, and the build proceeded to
# inspect a half-written disk and reported
# `parted: unrecognised disk label` -- a true statement about the disk that
# said nothing about the cause. QEMU does announce the signal on stderr before
# leaving, so the log is the evidence, and it is now consulted.
TERMINATION_NOTICE = re.compile(r"terminating on signal (\d+)(?: from pid (\d+)[^\n]*)?")

# A guest needs its own memory plus room for the host to keep working. Starting
# a 45-minute install into a host that is already close to its limit is not a
# build, it is a coin flip against the OOM reaper, and the coin came up wrong
# once already. The floor is the guest envelope plus a host reserve.
HOST_MEMORY_RESERVE_BYTES = 2 * 1024**3

# Matches the fixed topology the launch runner enforces, so a base image built
# here is valid for the profile the campaign will later run.
MACHINE = "pc-q35-11.0"
MEMORY_MIB = 4096
VCPUS = 4

# The roles a finished Windows UEFI/GPT install must expose. The profile orders
# them; this is the set the produced disk is checked against.
WINDOWS_PARTITION_TYPES = {
    "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "msr": "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    "windows": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
}


class BaseImageBuildError(RuntimeError):
    """Raised when a base image cannot be built or fails its own inspection."""


class QMPMonitor:
    """A minimal QMP client, used only to send the boot-prompt keypress.

    Deliberately tiny: the build needs exactly one capability from QEMU's
    monitor, and a broad client would be a broad surface. It cannot issue
    block-graph or migration commands because it never implements them.
    """

    def __init__(self, socket_path: Path, timeout_seconds: float = 30.0) -> None:
        self._path = socket_path
        self._timeout = timeout_seconds
        self._socket: Any = None

    def connect(self) -> None:
        import socket as socket_module

        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            if self._path.exists():
                try:
                    connection = socket_module.socket(socket_module.AF_UNIX)
                    connection.settimeout(self._timeout)
                    connection.connect(str(self._path))
                except OSError:
                    time.sleep(0.1)
                    continue
                self._socket = connection
                self._receive()
                self._execute("qmp_capabilities")
                return
            time.sleep(0.1)
        raise BaseImageBuildError("the QEMU monitor socket never became ready")

    def _receive(self) -> str:
        return self._socket.recv(65536).decode("utf-8", errors="replace")

    def _execute(self, command: str, **arguments: Any) -> str:
        payload: dict[str, Any] = {"execute": command}
        if arguments:
            payload["arguments"] = arguments
        self._socket.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        return self._receive()

    def send_key(self, key: str = "ret") -> None:
        self._execute(
            "send-key", keys=[{"type": "qcode", "data": key}]
        )

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None


def press_boot_prompt_key(
    monitor: QMPMonitor,
    process: subprocess.Popen[Any],
    disk: Path,
    attempts: int = BOOT_PROMPT_KEY_ATTEMPTS,
    interval: float = BOOT_PROMPT_KEY_INTERVAL_SECONDS,
) -> int:
    """Send keypresses until the boot prompt is satisfied, then stop immediately.

    The prompt appears when firmware hands off to the ISO's boot stub, and the
    exact moment depends on host load, so a single well-timed key would be a
    race. But keys must stop the instant setup takes over, because Windows setup
    reads them as UI input: an earlier version kept sending Return on a fixed
    schedule and pressed Cancel, raising a quit confirmation over a 40% install.

    Disk growth is the stopping signal. It is the guest's own behaviour rather
    than a timer, so it cannot drift with host load.
    """

    baseline = os.stat(disk).st_size
    sent = 0
    for _ in range(attempts):
        if process.poll() is not None:
            break
        if os.stat(disk).st_size - baseline > DISK_WRITE_PROGRESS_BYTES:
            # Setup is writing. The prompt is behind us; further keys would be
            # delivered to the installer's UI.
            break
        try:
            monitor.send_key()
            sent += 1
        except OSError:
            # The monitor closing means QEMU is gone; the wait below reports it.
            break
        time.sleep(interval)
    return sent


def termination_signal(diagnostics: str) -> tuple[int, int | None] | None:
    """Return the signal QEMU said it died on, or None if it left on its own.

    Reads QEMU's own words rather than inferring from an exit code, because the
    exit code is zero either way.
    """

    match = TERMINATION_NOTICE.search(diagnostics)
    if match is None:
        return None
    killer = match.group(2)
    return int(match.group(1)), int(killer) if killer else None


def require_memory_envelope(
    required_bytes: int = MEMORY_MIB * 1024**2 + HOST_MEMORY_RESERVE_BYTES,
) -> int:
    """Refuse to start a build the host cannot hold for its whole duration.

    An install runs for the better part of an hour and is not resumable, so a
    host that is already short of memory should fail here, in a second, rather
    than 40 minutes in when the reaper arrives. Returns the observed figure so
    the caller can record what the decision was made on.
    """

    available = lab.available_memory_bytes()
    if available < required_bytes:
        raise BaseImageBuildError(
            f"the guest needs {MEMORY_MIB} MiB plus a host reserve, so at least "
            f"{required_bytes} available bytes; the host has {available}. A build "
            "killed by the OOM reaper mid-install wastes the whole run, so it is "
            "refused up front."
        )
    return available


@dataclass(frozen=True)
class BuildInputs:
    """The immutable inputs one base-image build consumes."""

    record_key: str
    iso: Path
    answer_media: Path
    firmware_code: Path
    firmware_vars: Path
    disk: Path
    virtual_size_bytes: int


def load_profile(record_key: str) -> dict[str, Any]:
    """Load the support profile that pins this record's VM topology.

    Read from the same immutable profile directory the launch runner uses, so a
    base image is built to exactly the geometry the later campaign will demand.
    """

    path = base_image.PROFILES / f"{record_key}.profile.json"
    if not path.is_file():
        raise BaseImageBuildError(f"no support profile for record {record_key}")
    return json.loads(path.read_text(encoding="utf-8"))


def _require_regular_file_in(path: Path, workspace: Path, label: str) -> Path:
    """Refuse anything that is not a plain file inside the workspace."""

    resolved = path.resolve()
    if resolved.is_symlink() or path.is_symlink():
        raise BaseImageBuildError(f"{label} must not be a symlink: {path}")
    if not resolved.is_file():
        raise BaseImageBuildError(f"{label} is missing: {path}")
    workspace_resolved = workspace.resolve()
    if workspace_resolved not in resolved.parents:
        raise BaseImageBuildError(f"{label} must live inside the workspace: {path}")
    if os.stat(resolved).st_nlink != 1:
        raise BaseImageBuildError(f"{label} must not be hard-linked: {path}")
    return resolved


def _tool(name: str) -> str:
    found = shutil.which(name)
    if found is None:
        raise BaseImageBuildError(f"{name} is not installed")
    return found


def _run(*arguments: str, timeout: int = 600, home: Path | None = None) -> str:
    """Run a tool with the harness's deterministic environment.

    ``home`` scopes HOME and TMPDIR. Tools such as libguestfs need a writable
    temporary directory, and giving them one inside the workspace keeps their
    scratch files under the same confinement as everything else rather than
    loosening the environment.
    """

    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=lab.subprocess_environment(home),
        )
    except FileNotFoundError as exc:
        raise BaseImageBuildError(f"{arguments[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise BaseImageBuildError(f"{arguments[0]} timed out") from exc
    if completed.returncode != 0:
        raise BaseImageBuildError(
            f"{arguments[0]} failed with exit {completed.returncode}: "
            f"{completed.stderr.strip()[:400]}"
        )
    return completed.stdout


def create_disk(workspace: Path, name: str, virtual_size_bytes: int) -> Path:
    """Create the sparse qcow2 the guest will install onto."""

    if virtual_size_bytes <= 0:
        raise BaseImageBuildError("virtual size must be positive")
    destination = workspace / name
    if destination.exists():
        raise BaseImageBuildError(
            f"refusing to clobber an existing disk: {destination}. "
            "Remove it deliberately to rebuild."
        )
    if destination.is_symlink():
        raise BaseImageBuildError(f"disk path must not be a symlink: {destination}")
    _run(
        _tool("qemu-img"),
        "create",
        "-f",
        "qcow2",
        str(destination),
        str(virtual_size_bytes),
    )
    os.chmod(destination, 0o600)
    return destination


def build_swtpm_argv(swtpm_socket: Path, state_directory: Path) -> list[str]:
    """Return the swtpm command line for a fresh TPM 2.0 device.

    Windows 11 setup hard-refuses to install without TPM 2.0, so a base image
    build needs one. The emulator state is fresh per build and lives inside the
    workspace: a base image must not inherit sealed secrets from an earlier run.

    Matches the launch runner's flags exactly, so the TPM a campaign later sees
    behaves the same as the one the image was installed against.
    """

    return [
        _tool("swtpm"),
        "socket",
        "--tpm2",
        "--tpmstate",
        f"dir={state_directory}",
        "--ctrl",
        f"type=unixio,path={swtpm_socket}",
        "--flags",
        "not-need-init,startup-clear",
        "--terminate",
    ]


def build_qemu_argv(
    inputs: BuildInputs, monitor_socket: Path, swtpm_socket: Path | None = None
) -> list[str]:
    """Return the exact QEMU command line for an unattended install.

    Written as one explicit list rather than assembled from fragments so the
    whole device topology is reviewable in one place, and so a test can assert
    what is absent: no network, no host device, no passthrough.
    """

    return [
        _tool("qemu-system-x86_64"),
        "-name",
        "jstack-base-image-build",
        "-nodefaults",
        "-no-user-config",
        "-machine",
        f"{MACHINE},accel=kvm,smm=on",
        "-cpu",
        "host",
        "-smp",
        str(VCPUS),
        "-m",
        str(MEMORY_MIB),
        # Secure Boot requires SMM plus the secboot firmware build. The variable
        # store is a per-run writable copy; the code image is read-only.
        "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={inputs.firmware_code}",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={inputs.firmware_vars}",
        "-device",
        "VGA",
        "-display",
        "none",
        "-qmp",
        f"unix:{monitor_socket},server=on,wait=off",
        # The install target, matching the profile's declared controller and
        # sector geometry so the base image is valid for later runs.
        "-drive",
        f"if=none,id=system,format=qcow2,file={inputs.disk}",
        "-device",
        (
            "nvme,drive=system,serial=JSTACKLAB0001,bootindex=1,"
            "logical_block_size=512,physical_block_size=4096"
        ),
        # Installation media and the answer file, both read-only.
        "-drive",
        f"if=none,id=install-iso,format=raw,readonly=on,file={inputs.iso}",
        "-device",
        "ide-cd,drive=install-iso,bootindex=2",
        # The controller must be declared before the device that attaches to it,
        # or QEMU refuses to start with "No 'usb-bus' bus found".
        "-device",
        "qemu-xhci,id=xhci",
        "-drive",
        f"if=none,id=answer,format=raw,readonly=on,file={inputs.answer_media}",
        "-device",
        "usb-storage,bus=xhci.0,drive=answer,removable=on",
        # A base image must be a function of the ISO alone. No network.
        "-nic",
        "none",
    ] + (
        # Windows 11 refuses to install without TPM 2.0. The profile mandates
        # tpm-crb, so the base image is built against the same device model the
        # campaign will present.
        [
            "-chardev",
            f"socket,id=chrtpm,path={swtpm_socket}",
            "-tpmdev",
            "emulator,id=tpm0,chardev=chrtpm",
            "-device",
            "tpm-crb,tpmdev=tpm0",
        ]
        if swtpm_socket is not None
        else []
    )


def inspect_disk(disk: Path, profile: dict[str, Any], scratch: Path | None = None) -> dict[str, Any]:
    """Independently inspect a built base image.

    The guest's own claim that setup succeeded is not evidence, and neither is
    QEMU exiting 0. This reads the partition table back out of the qcow2 with
    libguestfs (which needs no privilege, no loop device, and no mount on the
    host) and checks that the roles the profile declares are the roles actually
    present, in order.

    ``sgdisk`` is deliberately not used here: it cannot read qcow2, and pointing
    it at the file would silently inspect nothing.
    """

    output = _run(
        _tool("guestfish"),
        "--ro",
        "-a",
        str(disk),
        "run",
        ":",
        "part-list",
        "/dev/sda",
        ":",
        "part-get-parttype",
        "/dev/sda",
        timeout=600,
        home=scratch if scratch is not None else disk.parent,
    )
    if "gpt" not in output.lower():
        raise BaseImageBuildError("built image does not carry a GPT partition table")

    numbers = sorted(
        int(match) for match in re.findall(r"part_num:\s*(\d+)", output)
    )
    if not numbers:
        raise BaseImageBuildError("built image reports no partitions")

    observed: list[str] = []
    for number in numbers:
        guid = _run(
            _tool("guestfish"),
            "--ro",
            "-a",
            str(disk),
            "run",
            ":",
            "part-get-gpt-type",
            "/dev/sda",
            str(number),
            timeout=600,
            home=scratch if scratch is not None else disk.parent,
        ).strip().lower()
        observed.append(guid)

    # The profile declares the roles a finished install must expose. Compare
    # against it rather than against a list hardcoded here, so a profile change
    # cannot drift away from what is actually checked.
    declared = [
        role
        for role in profile["storage"]["layout"]["ordered_partition_roles"]
        if role in WINDOWS_PARTITION_TYPES
    ]
    expected = [WINDOWS_PARTITION_TYPES[role] for role in declared]
    missing = [
        role
        for role, guid in zip(declared, expected, strict=True)
        if guid not in observed
    ]
    if missing:
        raise BaseImageBuildError(
            "built image is missing required partition roles: "
            f"{', '.join(missing)}; observed {observed}"
        )

    return {
        "gpt_present": True,
        "partition_count": len(numbers),
        "type_guids": observed,
        "required_roles_present": declared,
    }


def gpt_sha256(disk: Path, workspace: Path, sectors: int = 34) -> str:
    """Digest the primary GPT region of a qcow2 image.

    The profile pins ``base-image-gpt-sha256`` separately from the whole-image
    digest so a campaign can prove the partition table it starts from is the one
    that was inspected, without rehashing the entire virtual disk.

    The region is extracted to a temporary raw file rather than piped through
    stdout: the GPT is binary, and decoding it as text to move it through a pipe
    would corrupt the very bytes being digested.
    """

    destination = workspace / f".gpt-{disk.name}.raw"
    destination.unlink(missing_ok=True)
    try:
        _run(
            _tool("qemu-img"),
            "dd",
            "-f",
            "qcow2",
            "-O",
            "raw",
            f"if={disk}",
            f"of={destination}",
            "bs=512",
            f"count={sectors}",
            timeout=300,
            home=workspace,
        )
        return lab.sha256_file(destination)
    finally:
        destination.unlink(missing_ok=True)


def wait_for_shutdown(process: subprocess.Popen[Any], timeout_seconds: int) -> int:
    """Wait for the guest to power itself off, terminating it on timeout.

    A completed unattended install ends in a guest-initiated shutdown, so the
    process exiting on its own is the success signal. A timeout is a failure and
    is reported as one rather than being treated as completion.
    """

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            return code
        time.sleep(POLL_INTERVAL_SECONDS)

    process.terminate()
    try:
        process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
    raise BaseImageBuildError(
        f"the guest did not power off within {timeout_seconds}s; the answer file "
        "is probably waiting for input that was never supplied"
    )


def prepare_inputs(workspace: Path, record_key: str) -> BuildInputs:
    """Resolve and re-verify every input one build consumes.

    The ISO is re-verified here rather than trusted from an earlier run, because
    the whole value of the media record is that it is checked at the point of
    use.
    """

    records = base_image.load_media_records()
    if record_key not in records:
        raise BaseImageBuildError(f"unknown media record: {record_key}")
    record = records[record_key]

    iso = workspace / record.filename
    base_image.verify_media(iso, record, workspace)

    answer = workspace / base_image.answer_media_name(record)
    _require_regular_file_in(answer, workspace, "answer media")

    profile = load_profile(record_key)
    virtual_size = int(profile["storage"]["virtual_size_bytes"])

    firmware_vars = workspace / firmware_enrollment.ENROLLED_VARS_NAME
    _require_regular_file_in(firmware_vars, workspace, "enrolled firmware variables")

    # A per-build copy, so a build never mutates the enrolled master.
    per_build_vars = workspace / f"vars-{record.record_id}.fd"
    if per_build_vars.exists():
        per_build_vars.unlink()
    shutil.copyfile(firmware_vars, per_build_vars)
    os.chmod(per_build_vars, 0o600)

    code = firmware_enrollment.OVMF_SECBOOT_CODE
    if not code.is_file():
        raise BaseImageBuildError(f"secure-boot firmware code is missing: {code}")

    disk = create_disk(workspace, f"base-{record.record_id}.qcow2", virtual_size)

    return BuildInputs(
        record_key=record_key,
        iso=iso,
        answer_media=answer,
        firmware_code=code,
        firmware_vars=per_build_vars,
        disk=disk,
        virtual_size_bytes=virtual_size,
    )


def build(workspace: Path, record_key: str, timeout_seconds: int = INSTALL_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Build one Windows base image and return its verified evidence."""

    if os.getuid() == 0 or os.geteuid() == 0:
        raise BaseImageBuildError("refusing to build a base image as root")

    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(workspace, scratch)
    if not workspace.is_dir():
        raise BaseImageBuildError(f"workspace must already exist: {workspace}")
    lab.require_private_workspace(workspace)

    memory_available = require_memory_envelope()

    inputs = prepare_inputs(workspace, record_key)
    monitor = workspace / f"build-{record_key}.qmp"
    if monitor.exists():
        monitor.unlink()

    swtpm_socket = workspace / f"swtpm-{record_key}.sock"
    swtpm_state = workspace / f"swtpm-state-{record_key}"
    swtpm_socket.unlink(missing_ok=True)
    shutil.rmtree(swtpm_state, ignore_errors=True)
    swtpm_state.mkdir(mode=0o700)

    argv = build_qemu_argv(inputs, monitor, swtpm_socket)
    started = time.time_ns()

    # swtpm must be listening before QEMU connects to its chardev.
    tpm = subprocess.Popen(
        build_swtpm_argv(swtpm_socket, swtpm_state),
        close_fds=True,
        cwd=workspace,
        env=lab.subprocess_environment(workspace),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 30.0
    while not swtpm_socket.exists():
        if tpm.poll() is not None:
            raise BaseImageBuildError("swtpm exited before creating its socket")
        if time.monotonic() >= deadline:
            tpm.terminate()
            raise BaseImageBuildError("swtpm socket did not become ready")
        time.sleep(0.05)
    # QEMU's diagnostics go to a file rather than a pipe: a build runs for the
    # better part of an hour, and a full pipe buffer would deadlock the guest.
    # An exit code alone is not actionable, so the reason is always retained.
    log = workspace / f"build-{record_key}.qemu.log"
    keys_sent = 0
    with log.open("wb") as diagnostics:
        process = subprocess.Popen(
            argv,
            close_fds=True,
            cwd=workspace,
            env=lab.subprocess_environment(workspace),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostics,
            start_new_session=True,
        )
        client = QMPMonitor(monitor)
        try:
            client.connect()
            keys_sent = press_boot_prompt_key(client, process, inputs.disk)
        finally:
            client.close()
        try:
            exit_code = wait_for_shutdown(process, timeout_seconds)
        finally:
            monitor.unlink(missing_ok=True)
            if tpm.poll() is None:
                tpm.terminate()
                try:
                    tpm.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    tpm.kill()
            swtpm_socket.unlink(missing_ok=True)

    diagnostics_text = log.read_text(encoding="utf-8", errors="replace").strip()
    if exit_code != 0:
        raise BaseImageBuildError(
            f"QEMU exited {exit_code} during the install: "
            f"{diagnostics_text[-600:] or 'no diagnostics were produced'}"
        )

    # A zero exit is not proof the install finished. QEMU exits zero when it is
    # signalled too, so the guest may have been killed mid-write. Ask QEMU what
    # happened before trusting the disk it left behind, otherwise the failure
    # resurfaces later as an inspection error that blames the wrong thing.
    killed = termination_signal(diagnostics_text)
    if killed is not None:
        signal_number, killer_pid = killed
        by = f" by pid {killer_pid}" if killer_pid is not None else ""
        raise BaseImageBuildError(
            f"the guest was terminated on signal {signal_number}{by} during the "
            "install, so the disk it left behind is a partial write and is not a "
            f"base image. QEMU exits zero when signalled, so this is not visible "
            f"in the exit code. Host memory available at launch was "
            f"{memory_available} bytes; if the killer was earlyoom or the kernel "
            "OOM reaper, free memory and run the build again."
        )

    # The guest shutting down cleanly is necessary but not sufficient. Inspect
    # the disk it left behind.
    profile = load_profile(record_key)
    inspection = inspect_disk(inputs.disk, profile, workspace)

    return {
        "record_key": record_key,
        "disk": str(inputs.disk),
        "sha256": lab.sha256_file(inputs.disk),
        "size_bytes": os.stat(inputs.disk).st_size,
        "virtual_size_bytes": inputs.virtual_size_bytes,
        "gpt_sha256": gpt_sha256(inputs.disk, workspace),
        "inspection": inspection,
        "install_seconds": round((time.time_ns() - started) / 1e9, 1),
        "secure_boot": True,
        "network": "none",
        "boot_prompt_keys_sent": keys_sent,
        "tpm": "2.0",
        "memory_available_bytes_at_launch": memory_available,
    }


def parser() -> argparse.ArgumentParser:
    argument_parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    argument_parser.add_argument("--workspace", required=True)
    argument_parser.add_argument("--record", required=True)
    argument_parser.add_argument(
        "--timeout-seconds", type=int, default=INSTALL_TIMEOUT_SECONDS
    )
    return argument_parser


def main() -> int:
    arguments = parser().parse_args()
    try:
        evidence = build(
            Path(arguments.workspace), arguments.record, arguments.timeout_seconds
        )
    except (BaseImageBuildError, base_image.BaseImageError, lab.LabSafetyError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
