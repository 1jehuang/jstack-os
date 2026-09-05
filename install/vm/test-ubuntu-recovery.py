#!/usr/bin/env python3
"""Non-destructive Ubuntu recovery VM fault-campaign supervisor.

This program only operates on qcow2 overlays created beneath a new campaign
work directory.  It never opens a baseline for writing.  QEMU is detached, so
an observation timeout leaves it running for an operator to inspect or stop.

The guest must write controller output to the configured serial log and emit an
evidence frame immediately after observing each durable boundary:

  JSTK_VM_EVIDENCE {"marker":"JSTK_UBUNTU_INTENT ...","journal_sha256":"...",
    "journal_bytes":123,"journal_last_kind":"Intent","target_sha256":"..."}

The marker must already occur in the serial stream. Evidence frames are an
observation aid only. Every subsequent boot must use the production controller
CLI, whose validation remains authoritative.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Any

MARKERS = {
    "intent": r"^JSTK_UBUNTU_INTENT ",
    "write": r"^JSTK_UBUNTU_WRITE_BEGIN ",
    "readback": r"^JSTK_UBUNTU_READBACK_OK ",
    "commit": r"^JSTK_UBUNTU_COMMIT ",
    "advance": r"^JSTK_UBUNTU_ADVANCE ",
    "verified": r"^JSTK_UBUNTU_VERIFIED(?: |$)",
    "complete": r"^JSTK_UBUNTU_COMPLETE ",
}
SCENARIOS = [
    "before-intent", "after-intent", "during-write", "after-readback",
    "after-commit", "after-advance", "after-verified", "after-complete",
    "identity-drift", "duplicate-identity", "source-tamper", "plan-tamper",
    "journal-tamper", "committed-target-corruption", "concurrent-writers",
    "completed-noop",
]
EVIDENCE_PREFIX = "JSTK_VM_EVIDENCE "
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def die(message: str) -> "NoReturn":
    raise SystemExit(f"REFUSED: {message}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def exclusive_json(path: Path, obj: Any) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, sort_keys=True, indent=2)
        f.write("\n")
        f.flush(); os.fsync(f.fileno())


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    required = {"schema", "source_revision", "binary", "graph", "host_base", "target_base", "qemu"}
    if data.get("schema") != "jstack.ubuntu-recovery-campaign.v1" or not required <= data.keys():
        die("invalid campaign manifest")
    for name in ("binary", "graph", "host_base", "target_base"):
        item = data[name]
        p = Path(item["path"])
        if not p.is_absolute() or not p.is_file() or not HEX64.fullmatch(item.get("sha256", "")):
            die(f"invalid {name} binding")
        if sha256(p) != item["sha256"]:
            die(f"{name} digest changed")
    return data


def prepare(args: argparse.Namespace) -> None:
    work = args.work.resolve()
    if work.exists(): die("work directory already exists")
    inputs = [args.binary, args.graph, args.host_base, args.target_base]
    for p in inputs:
        if not p.resolve().is_file(): die(f"missing input: {p}")
    work.mkdir(mode=0o700, parents=False)
    manifest = {
        "schema": "jstack.ubuntu-recovery-campaign.v1",
        "created_unix": int(time.time()),
        "source_revision": args.source_revision,
        "defaults": {"memory_mib": 64, "network": "none", "simultaneous_vms": 1},
        "binary": {"path": str(args.binary.resolve()), "sha256": sha256(args.binary.resolve())},
        "graph": {"path": str(args.graph.resolve()), "sha256": sha256(args.graph.resolve())},
        "host_base": {"path": str(args.host_base.resolve()), "sha256": sha256(args.host_base.resolve())},
        "target_base": {"path": str(args.target_base.resolve()), "sha256": sha256(args.target_base.resolve())},
        "qemu": args.qemu,
        "scenarios": SCENARIOS,
        "contract": "UR-01..UR-14",
    }
    exclusive_json(work / "manifest.json", manifest)
    print(work / "manifest.json")


def format_command(parts: list[str], values: dict[str, str]) -> list[str]:
    allowed = set(values)
    out = []
    for part in parts:
        fields = set(re.findall(r"\{([a-z_]+)\}", part))
        if not fields <= allowed: die(f"unsupported qemu template field: {fields - allowed}")
        out.append(part.format(**values))
    return out


def create_overlay(base: Path, output: Path, qemu_img: str) -> None:
    if output.exists(): die(f"overlay already exists: {output}")
    subprocess.run([qemu_img, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(output)], check=True)


def lock_campaign(work: Path):
    lock = (work / "campaign.lock").open("a+")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: die("another campaign VM is active")
    return lock


def start(args: argparse.Namespace) -> None:
    manifest_path = args.manifest.resolve(); m = load_manifest(manifest_path)
    work = manifest_path.parent
    lock = lock_campaign(work)
    scenario = args.scenario
    if scenario not in m["scenarios"]: die("unknown scenario")
    run = work / scenario
    if run.exists(): die("scenario artifacts already exist")
    run.mkdir(mode=0o700)
    host = run / "host.qcow2"; target = run / "target.qcow2"
    create_overlay(Path(m["host_base"]["path"]), host, args.qemu_img)
    create_overlay(Path(m["target_base"]["path"]), target, args.qemu_img)
    serial = run / "serial.log"; qmp = run / "qmp.sock"
    serial.touch(mode=0o600, exist_ok=False)
    values = {"host": str(host), "target": str(target), "serial": str(serial),
              "qmp": str(qmp), "scenario": scenario, "memory_mib": "64"}
    command = format_command(m["qemu"], values)
    network_disabled = any(
        command[i] == "-nic" and i + 1 < len(command) and command[i + 1] == "none"
        for i in range(len(command))
    )
    if not command or not network_disabled or "-net" in command or any("netdev" in x for x in command):
        die("QEMU command must be present and explicitly use -nic none")
    log = (run / "qemu.log").open("xb")
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    # Keep the advisory lock alive in a detached guardian for the VM lifetime.
    guardian = os.fork()
    if guardian == 0:
        try:
            while True:
                try: os.kill(proc.pid, 0)
                except ProcessLookupError: break
                time.sleep(1)
        finally: lock.close()
        os._exit(0)
    exclusive_json(run / "process.json", {"pid": proc.pid, "guardian_pid": guardian,
                   "command": command, "started_unix": int(time.time())})
    lock.close()
    print(run)


def read_lines(path: Path) -> list[str]:
    try: return path.read_text(errors="replace").splitlines()
    except FileNotFoundError: return []


def observe(args: argparse.Namespace) -> None:
    run = args.run.resolve(); procdata = json.loads((run / "process.json").read_text())
    pid = int(procdata["pid"]); pattern = re.compile(MARKERS[args.boundary])
    deadline = time.monotonic() + args.timeout
    marker_line = None; evidence = None
    while time.monotonic() < deadline:
        lines = read_lines(run / "serial.log")
        for i, line in enumerate(lines):
            if pattern.search(line):
                marker_line = line
                for later in lines[i + 1:]:
                    if later.startswith(EVIDENCE_PREFIX):
                        candidate = json.loads(later[len(EVIDENCE_PREFIX):])
                        if candidate.get("marker") == marker_line:
                            evidence = candidate; break
                if evidence: break
        if evidence: break
        try: os.kill(pid, 0)
        except ProcessLookupError: die("VM exited before observed evidence boundary")
        time.sleep(0.2)
    if not evidence:
        # Deliberately do not stop QEMU. A tool timeout must not become a fault.
        die("observation timed out; VM remains running")
    for key in ("journal_sha256", "target_sha256"):
        if not HEX64.fullmatch(str(evidence.get(key, ""))): die(f"invalid evidence {key}")
    if not isinstance(evidence.get("journal_bytes"), int): die("invalid evidence journal_bytes")
    if args.kill:
        os.killpg(pid, signal.SIGKILL)
    record = {"boundary": args.boundary, "actual_marker": marker_line, "evidence": evidence,
              "observed_unix": int(time.time()), "action": "sigkill" if args.kill else "none"}
    exclusive_json(run / f"observed-{args.boundary}.json", record)
    print(json.dumps(record, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--work", type=Path, required=True); p.add_argument("--source-revision", required=True)
    p.add_argument("--binary", type=Path, required=True); p.add_argument("--graph", type=Path, required=True)
    p.add_argument("--host-base", type=Path, required=True); p.add_argument("--target-base", type=Path, required=True)
    p.add_argument("--qemu", action="append", required=True, help="one argv item, placeholders: host,target,serial,qmp,scenario,memory_mib")
    p.set_defaults(func=prepare)
    p = sub.add_parser("start")
    p.add_argument("--manifest", type=Path, required=True); p.add_argument("--scenario", required=True)
    p.add_argument("--qemu-img", default="qemu-img"); p.set_defaults(func=start)
    p = sub.add_parser("observe")
    p.add_argument("--run", type=Path, required=True); p.add_argument("--boundary", choices=MARKERS, required=True)
    p.add_argument("--timeout", type=float, default=600); p.add_argument("--kill", action="store_true")
    p.set_defaults(func=observe)
    args = parser.parse_args(); args.func(args)

if __name__ == "__main__": main()
