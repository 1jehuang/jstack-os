#!/usr/bin/env python3
"""PH-10 boot proof: the signed artifacts really boot, and Secure Boot enforces.

Every other check on the boot artifacts is a *claim about bytes*: ``sbverify``
agrees with ``sbsign``, and a digest matches a manifest. None of that establishes
what the row actually asserts, which is that the artifact **boots** and that
firmware **refuses** it once tampered. A UKI can pass every digest check and
still be unbootable, and a signature can verify in userspace while real firmware
rejects the image.

So this module boots the artifact in QEMU on OVMF and reads the outcome off the
serial console:

* **signed, Secure Boot on** must reach the in-guest marker,
* **tampered, Secure Boot on** must be refused by firmware and never reach it,
* **unsigned, Secure Boot on** must likewise be refused.

The third case is the control. Without it, an ``Access Denied`` in the second
case could equally mean the harness is broken as that tamper detection works.

The guest is a real Linux kernel plus a freestanding static PID 1 that prints one
marker and powers off. None of this needs Windows media, so it runs long before
the base-image work is unblocked.

Safety: every path is a regular file inside the VM workspace, the guest gets no
network and no host device, firmware variables are a per-run writable copy of the
distribution template, and every boot has a hard wall-clock timeout so a refused
boot cannot hang the caller.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifacts
import lab

QEMU = "qemu-system-x86_64"
VIRT_FW_VARS = "virt-fw-vars"
RUSTC = "rustc"
CPIO = "cpio"
GZIP = "gzip"

OVMF_SECURE_CODE = Path("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd")
OVMF_VARS = Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")
DEFAULT_KERNEL = Path("/boot/vmlinuz-linux")

# The guest prints exactly this and nothing else on success. It is deliberately
# distinctive so it cannot be confused with firmware or kernel chatter.
BOOT_MARKER = "JSTACK-UKI-BOOTED-OK"

# Firmware refusal strings emitted by OVMF when image authentication fails.
REFUSAL_MARKERS = ("Access Denied", "Security Violation")

# A refused boot never powers itself off, so every boot needs a hard cap.
BOOT_TIMEOUT_SECONDS = 45

GUEST_CMDLINE = "console=ttyS0 panic=-1 jstack.selftest=1"

# A freestanding PID 1. It issues three raw syscalls (write, reboot, pause) so it
# needs no libc runtime, no /proc, and no /dev, which keeps the guest minimal
# enough that a successful boot is unambiguous evidence about the UKI itself
# rather than about a userspace image.
INIT_SOURCE = r"""
#![no_main]
use std::arch::asm;

const MARKER: &[u8] = b"__MARKER__\n";

unsafe fn sys(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let mut r = n;
    unsafe {
        asm!("syscall", inout("rax") r, in("rdi") a, in("rsi") b, in("rdx") c,
             out("rcx") _, out("r11") _, options(nostack));
    }
    r as i64
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    unsafe {
        // write(1, MARKER, len)
        sys(1, 1, MARKER.as_ptr() as u64, MARKER.len() as u64);
        // reboot(magic1, magic2, LINUX_REBOOT_CMD_POWER_OFF)
        sys(169, 0xfee1dead, 672274793, 0x4321fedc);
        // PID 1 must never return, even if the power-off is refused.
        loop {
            sys(35, 0, 0, 0);
        }
    }
}
"""


class BootProofError(RuntimeError):
    """Raised when the boot proof cannot be set up or produces no verdict."""


def _tool(name: str) -> str:
    found = shutil.which(name, path=lab.SYSTEM_PATH) or shutil.which(name)
    if not found:
        raise BootProofError(f"required command is unavailable: {name}")
    invoked = Path(found)
    target = invoked.resolve(strict=True)
    if target.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise BootProofError(f"set-id command is forbidden: {target}")
    return str(invoked)


def _run(name: str, *arguments: str) -> str:
    result = subprocess.run(
        [_tool(name), *arguments],
        text=True,
        capture_output=True,
        check=False,
        env=lab.subprocess_environment(),
    )
    if result.returncode != 0:
        raise BootProofError(
            f"{name} failed ({result.returncode}): "
            f"{(result.stderr or result.stdout).strip()}"
        )
    return result.stdout or result.stderr


def available() -> tuple[bool, str]:
    """Whether this host can run the boot proof, and why not if it cannot."""
    if not Path("/dev/kvm").exists():
        return False, "/dev/kvm is absent"
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        return False, "/dev/kvm is not readable and writable"
    for path in (OVMF_SECURE_CODE, OVMF_VARS, DEFAULT_KERNEL):
        if not path.is_file():
            return False, f"{path} is absent"
    for tool in (QEMU, VIRT_FW_VARS, RUSTC, CPIO, GZIP):
        if not (shutil.which(tool, path=lab.SYSTEM_PATH) or shutil.which(tool)):
            return False, f"{tool} is unavailable"
    return True, "ready"


def build_guest_initrd(workspace: Path) -> bytes:
    """Compile the static PID 1 and pack it into a newc cpio archive."""
    source = workspace / "init.rs"
    source.write_text(INIT_SOURCE.replace("__MARKER__", BOOT_MARKER), encoding="utf-8")
    binary = workspace / "init"
    _run(
        RUSTC,
        "-O",
        "-C",
        "panic=abort",
        "-C",
        "target-feature=+crt-static",
        "-o",
        str(binary),
        str(source),
    )

    root = workspace / "initrd-root"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    shutil.copyfile(binary, root / "init")
    os.chmod(root / "init", 0o755)

    # cpio and gzip both emit binary, so this pipeline stays in bytes end to end.
    listing = subprocess.run(
        [_tool(CPIO), "-o", "-H", "newc"],
        cwd=root,
        input=b"init\n",
        capture_output=True,
        check=False,
    )
    if listing.returncode != 0:
        raise BootProofError(
            f"cpio failed: {listing.stderr.decode('utf-8', errors='replace').strip()}"
        )
    archive = subprocess.run(
        [_tool(GZIP), "-9", "-c"],
        input=listing.stdout,
        capture_output=True,
        check=False,
    )
    if archive.returncode != 0:
        raise BootProofError("gzip failed while packing the initrd")
    return archive.stdout


def enroll_secure_boot(workspace: Path, certificate: Path) -> Path:
    """Create a per-run firmware variable store trusting only `certificate`.

    The distribution template is copied, never modified, and the certificate is
    enrolled as PK, KEK, and db so the guest trusts exactly the one key that
    signed the artifact under test. Secure Boot is then enabled and custom mode
    disabled, which is what makes a refusal meaningful.
    """
    variables = workspace / "secure-boot-vars.fd"
    shutil.copyfile(OVMF_VARS, variables)
    os.chmod(variables, 0o600)
    owner = "11111111-2222-3333-4444-555555555555"
    _run(
        VIRT_FW_VARS,
        "--input",
        str(variables),
        "--output",
        str(variables),
        "--set-pk",
        owner,
        str(certificate),
        "--add-kek",
        owner,
        str(certificate),
        "--add-db",
        owner,
        str(certificate),
        "--secure-boot",
    )
    return variables


def stage_esp(workspace: Path, image: Path, name: str) -> Path:
    """Place one EFI image at the removable-media default boot path."""
    esp = workspace / name
    shutil.rmtree(esp, ignore_errors=True)
    boot = esp / "EFI" / "BOOT"
    boot.mkdir(parents=True)
    shutil.copyfile(image, boot / "BOOTX64.EFI")
    return esp


@dataclass(frozen=True)
class BootVerdict:
    """What the firmware and guest actually did."""

    booted: bool
    refused: bool
    timed_out: bool
    log: str

    def summary(self) -> str:
        if self.booted:
            return "booted"
        if self.refused:
            return "refused by firmware"
        return "no verdict"


def boot(workspace: Path, esp: Path, variables: Path) -> BootVerdict:
    """Boot one ESP under Secure Boot and read the verdict off the console.

    The guest is given no network device and no host block device: its only
    storage is the FAT image QEMU synthesizes from `esp`, and its only firmware
    state is the per-run variable copy.
    """
    log = workspace / f"{esp.name}.log"
    command = [
        _tool(QEMU),
        "-machine",
        "q35,accel=kvm,smm=on",
        "-m",
        "1024",
        "-smp",
        "2",
        "-nographic",
        "-no-reboot",
        "-nodefaults",
        "-nic",
        "none",
        "-global",
        "driver=cfi.pflash01,property=secure,value=on",
        "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_SECURE_CODE}",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={variables}",
        "-drive",
        f"file=fat:rw:{esp},format=raw,media=disk",
        "-serial",
        "stdio",
    ]
    # QEMU's synthesized-FAT driver writes a temporary file, and the harness's
    # default environment points TMPDIR at "/", which is not writable. Give it the
    # workspace instead so the temporary stays inside the sandbox.
    environment = lab.subprocess_environment(home=workspace)
    environment["TMPDIR"] = str(workspace)

    timed_out = False
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=BOOT_TIMEOUT_SECONDS,
            env=environment,
        )
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired as expired:
        timed_out = True
        output = ""
        for stream in (expired.stdout, expired.stderr):
            if stream:
                output += (
                    stream.decode("utf-8", errors="replace")
                    if isinstance(stream, bytes)
                    else stream
                )

    log.write_text(output, encoding="utf-8", errors="replace")
    return BootVerdict(
        booted=BOOT_MARKER in output,
        refused=any(marker in output for marker in REFUSAL_MARKERS),
        timed_out=timed_out,
        log=output,
    )


def run_boot_proof(workspace: Path, kernel: Path = DEFAULT_KERNEL) -> dict[str, Any]:
    """Build a signed UKI, then prove boot, tamper refusal, and unsigned refusal.

    Returns one evidence record per case. The caller asserts the verdicts; this
    function deliberately does not, so a partial result is still inspectable.
    """
    ready, reason = available()
    if not ready:
        raise BootProofError(f"host cannot run the boot proof: {reason}")

    initrd = build_guest_initrd(workspace)
    unsigned = artifacts.build_uki(
        workspace,
        artifacts.ROLE_INSTALLER_UKI,
        kernel,
        initrd,
        GUEST_CMDLINE,
        "boot-proof",
    )
    key = artifacts.TestSigningKey.generate(workspace, "JStack Boot Proof")
    signed = artifacts.sign_artifact(unsigned, key, workspace)
    if not artifacts.verify_signature(signed, key):
        raise BootProofError("the signed artifact does not verify before booting")

    variables = enroll_secure_boot(workspace, key.certificate_path)

    # Case 1: the signed artifact must boot.
    signed_esp = stage_esp(workspace, signed.path, "esp-signed")
    signed_verdict = boot(workspace, signed_esp, variables)

    # Case 2: one flipped byte deep inside the PE must be refused by firmware.
    tampered_esp = stage_esp(workspace, signed.path, "esp-tampered")
    target = tampered_esp / "EFI" / "BOOT" / "BOOTX64.EFI"
    payload = bytearray(target.read_bytes())
    offset = len(payload) // 2
    payload[offset] ^= 0xFF
    target.write_bytes(bytes(payload))
    tampered_verdict = boot(workspace, tampered_esp, variables)

    # Case 3: control. An unsigned image must also be refused, which is what
    # shows case 2's refusal came from the tamper rather than a broken harness.
    unsigned_esp = stage_esp(workspace, unsigned.path, "esp-unsigned")
    unsigned_verdict = boot(workspace, unsigned_esp, variables)

    return {
        "signed_sha256": signed.sha256,
        "unsigned_sha256": unsigned.sha256,
        "certificate_sha256": key.certificate_sha256,
        "tampered_byte_offset": offset,
        "cases": {
            "signed": {
                "booted": signed_verdict.booted,
                "refused": signed_verdict.refused,
                "summary": signed_verdict.summary(),
            },
            "tampered": {
                "booted": tampered_verdict.booted,
                "refused": tampered_verdict.refused,
                "summary": tampered_verdict.summary(),
            },
            "unsigned": {
                "booted": unsigned_verdict.booted,
                "refused": unsigned_verdict.refused,
                "summary": unsigned_verdict.summary(),
            },
        },
    }


def parser() -> Any:
    import argparse

    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--workspace", required=True)
    root.add_argument("--kernel", default=str(DEFAULT_KERNEL))
    return root


def main() -> int:
    import json

    arguments = parser().parse_args()
    scratch = lab.require_scratch_root()
    workspace = lab.safe_workspace(arguments.workspace, scratch)
    workspace.mkdir(parents=True, exist_ok=True)
    os.chmod(workspace, 0o700)

    ready, reason = available()
    if not ready:
        json.dump({"ready": False, "reason": reason}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 1

    evidence = run_boot_proof(workspace, Path(arguments.kernel))
    json.dump(evidence, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    cases = evidence["cases"]
    passed = (
        cases["signed"]["booted"]
        and not cases["tampered"]["booted"]
        and cases["tampered"]["refused"]
        and not cases["unsigned"]["booted"]
        and cases["unsigned"]["refused"]
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
