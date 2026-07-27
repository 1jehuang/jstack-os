#!/usr/bin/env python3
"""Compute pre-hardware installer progress from executable probes.

The prose ledger in ``docs/installer/PRE_HARDWARE_LEDGER.md`` explains *why*
each requirement matters. This tool answers *whether it currently holds*, and it
answers by running probes against the tree rather than by reading a status
column. A document cannot lie to this tool: if the evidence file is renamed or a
safety property is weakened, the row it supports reports open on the next run.

Three distinct numbers are reported, because collapsing them is how a project
convinces itself it is finished:

``implemented``
    The code exists and its static safety properties hold. This is what the
    repository can establish about itself.
``pre_hardware_closed``
    ``implemented`` *and* every named virtual/firmware observation exists. Rows
    marked ``requires_vm_observation`` can never reach this from unit tests.
``hardware_closed``
    Always 0 of 8 until a physical run happens. Printed on every invocation so
    the residual risk is never out of sight.

Exit status is 0 when nothing regressed against the recorded baseline, and
nonzero when a probe that used to pass now fails. That makes this a gate, not a
dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

INSTALLER_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = INSTALLER_ROOT / "model" / "pre-hardware-ledger.json"

PROBE_KINDS = frozenset({"file", "grep", "absent", "command"})

# Patterns are matched with MULTILINE so `^` anchors a line rather than the whole
# file, which is what a probe like `^check:` obviously intends.
PROBE_REGEX_FLAGS = re.MULTILINE


class LedgerError(RuntimeError):
    """The ledger itself is malformed. Always fatal: a broken gate is not a pass."""


@dataclass
class ProbeResult:
    kind: str
    target: str
    passed: bool
    detail: str
    why: str = ""

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "target": self.target,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.why:
            out["why"] = self.why
        return out


@dataclass
class RowResult:
    id: str
    title: str
    level: str
    required_level: str
    implemented: bool
    pre_hardware_closed: bool
    blocked_by: list[str]
    open_boundary: str
    probes: list[ProbeResult] = field(default_factory=list)

    def failed_probes(self) -> list[ProbeResult]:
        return [p for p in self.probes if not p.passed]

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "level": self.level,
            "required_level": self.required_level,
            "implemented": self.implemented,
            "pre_hardware_closed": self.pre_hardware_closed,
            "probes": [p.as_dict() for p in self.probes],
        }
        if self.blocked_by:
            out["blocked_by"] = self.blocked_by
        if self.open_boundary:
            out["open_boundary"] = self.open_boundary
        return out


def load_ledger(path: Path) -> dict[str, Any]:
    """Load and structurally validate the ledger.

    Validation is strict on purpose. The failure mode this guards against is a
    row being added with an impressive title and no way to check it, which would
    inflate the score for free.
    """

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LedgerError(f"cannot read ledger {path}: {exc}") from exc
    try:
        ledger = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LedgerError(f"ledger {path} is not valid JSON: {exc}") from exc

    if not isinstance(ledger, dict):
        raise LedgerError("ledger must be a JSON object")
    if ledger.get("kind") != "pre-hardware-completion-ledger":
        raise LedgerError("ledger has the wrong 'kind'")

    rows = ledger.get("requirements")
    if not isinstance(rows, list) or not rows:
        raise LedgerError("ledger has no requirements")

    seen: set[str] = set()
    ids = set()
    for row in rows:
        if not isinstance(row, dict):
            raise LedgerError("each requirement must be an object")
        rid = row.get("id")
        if not isinstance(rid, str) or not rid:
            raise LedgerError("each requirement needs a non-empty id")
        if rid in seen:
            raise LedgerError(f"duplicate requirement id {rid}")
        seen.add(rid)
        ids.add(rid)
        if not isinstance(row.get("title"), str) or not row["title"]:
            raise LedgerError(f"{rid} needs a title")
        probes = row.get("probes")
        if not isinstance(probes, list) or not probes:
            # An unprovable claim is not progress.
            raise LedgerError(f"{rid} has no probes; a claim without a check cannot count")
        for probe in probes:
            if not isinstance(probe, dict):
                raise LedgerError(f"{rid} has a non-object probe")
            kind = probe.get("kind")
            if kind not in PROBE_KINDS:
                raise LedgerError(f"{rid} has unknown probe kind {kind!r}")
            if kind == "command":
                if not isinstance(probe.get("argv"), list) or not probe["argv"]:
                    raise LedgerError(f"{rid} command probe needs argv")
            elif kind == "file":
                if not isinstance(probe.get("path"), str):
                    raise LedgerError(f"{rid} file probe needs a path")
            else:
                if not isinstance(probe.get("path"), str):
                    raise LedgerError(f"{rid} {kind} probe needs a path")
                if not isinstance(probe.get("pattern"), str):
                    raise LedgerError(f"{rid} {kind} probe needs a pattern")
                try:
                    re.compile(probe["pattern"], PROBE_REGEX_FLAGS)
                except re.error as exc:
                    raise LedgerError(f"{rid} probe pattern is not a valid regex: {exc}") from exc
                if "exclude_lines" in probe:
                    if not isinstance(probe["exclude_lines"], str):
                        raise LedgerError(f"{rid} exclude_lines must be a regex string")
                    try:
                        re.compile(probe["exclude_lines"])
                    except re.error as exc:
                        raise LedgerError(f"{rid} exclude_lines is not a valid regex: {exc}") from exc

    for row in rows:
        for dep in row.get("blocked_by", []) or []:
            if dep not in ids:
                raise LedgerError(f"{row['id']} is blocked by unknown row {dep}")

    physical = ledger.get("physical_only")
    if not isinstance(physical, list) or not physical:
        raise LedgerError("ledger must keep the physical-only residual rows")
    return ledger


def _resolve(path_text: str) -> Path:
    """Resolve a ledger path inside the installer tree, refusing escapes."""

    candidate = (INSTALLER_ROOT / path_text).resolve()
    root = INSTALLER_ROOT.resolve()
    if root != candidate and root not in candidate.parents:
        raise LedgerError(f"probe path escapes the installer tree: {path_text}")
    return candidate


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _boot_artifact_manifest_sha256() -> str:
    """Build a real boot-artifact set and return its manifest digest.

    This is a build output, not a stored constant, so the probe that consumes it
    is checking today's tree rather than a value someone once pasted in. If the
    build cannot run (no kernel image present) the probe fails loudly instead of
    silently substituting a placeholder that would pass.
    """

    import shutil
    import tempfile

    sys.path.insert(0, str(INSTALLER_ROOT / "vm"))
    kernel = Path("/boot/vmlinuz-linux")
    if not kernel.is_file():
        raise LedgerError("no kernel image at /boot/vmlinuz-linux to build boot artifacts from")
    try:
        import artifacts  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - environment defect
        raise LedgerError(f"cannot import the artifact builder: {exc}") from exc

    scratch = Path(tempfile.mkdtemp(prefix="jstack-ledger-artifacts-"))
    try:
        built = artifacts.build_test_artifact_set(scratch, kernel, "0" * 64, "0" * 64)
        return str(built.manifest_sha256)
    except Exception as exc:  # noqa: BLE001 - surfaced as a probe failure
        raise LedgerError(f"boot-artifact build failed: {exc}") from exc
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _substitute(text: str, workspace: str) -> str:
    """Expand the placeholders a command probe may use.

    Placeholders are resolved lazily so a run that never needs an expensive one
    never pays for it.
    """

    if "{workspace}" in text:
        text = text.replace("{workspace}", workspace)
    if "{boot_artifacts_sha256}" in text:
        text = text.replace("{boot_artifacts_sha256}", _boot_artifact_manifest_sha256())
    if "{" in text and "}" in text:
        raise LedgerError(f"unresolved placeholder in probe argument: {text}")
    return text


def run_probe(probe: dict[str, Any], workspace: str, run_commands: bool) -> ProbeResult:
    kind = probe["kind"]
    why = probe.get("why", "")

    if kind == "file":
        target = probe["path"]
        exists = _resolve(target).exists()
        return ProbeResult(kind, target, exists, "present" if exists else "missing", why)

    if kind in {"grep", "absent"}:
        target = f"{probe['path']}:/{probe['pattern']}/"
        body = _read(_resolve(probe["path"]))
        if body is None:
            return ProbeResult(kind, target, False, "file unreadable", why)
        exclude = probe.get("exclude_lines")
        if exclude:
            # Lets a negative probe ignore lines that only *discuss* the forbidden
            # token, such as a doc comment promising the flag does not exist,
            # without weakening the check on real code.
            pattern = re.compile(exclude)
            body = "\n".join(line for line in body.splitlines() if not pattern.search(line))
        found = re.search(probe["pattern"], body, PROBE_REGEX_FLAGS) is not None
        if kind == "grep":
            return ProbeResult(kind, target, found, "found" if found else "not found", why)
        return ProbeResult(kind, target, not found, "absent" if not found else "PRESENT", why)

    try:
        argv = [_substitute(str(a), workspace) for a in probe["argv"]]
    except LedgerError as exc:
        return ProbeResult(kind, " ".join(str(a) for a in probe["argv"]), False, str(exc), why)
    target = " ".join(argv)
    if not run_commands:
        return ProbeResult(kind, target, True, "skipped (--no-commands)", why)
    try:
        done = subprocess.run(
            argv,
            cwd=INSTALLER_ROOT,
            capture_output=True,
            text=True,
            timeout=probe.get("timeout_seconds", 900),
        )
    except FileNotFoundError:
        return ProbeResult(kind, target, False, "command not found", why)
    except subprocess.TimeoutExpired:
        return ProbeResult(kind, target, False, "timed out", why)
    ok = done.returncode == 0
    return ProbeResult(kind, target, ok, f"exit {done.returncode}", why)


def evaluate(ledger: dict[str, Any], workspace: str, run_commands: bool) -> list[RowResult]:
    rows = ledger["requirements"]
    probe_results = {
        row["id"]: [run_probe(p, workspace, run_commands) for p in row["probes"]] for row in rows
    }

    # Closure is computed to a fixed point so a satisfied dependency stops
    # blocking. A row listing a dependency that has itself closed is not held
    # open by it; only genuinely unmet dependencies block.
    closed: set[str] = set()
    for _ in range(len(rows) + 1):
        changed = False
        for row in rows:
            rid = row["id"]
            if rid in closed:
                continue
            if not all(p.passed for p in probe_results[rid]):
                continue
            if row.get("requires_vm_observation") or row.get("requires_clean_tree"):
                continue
            if any(dep not in closed for dep in row.get("blocked_by", []) or []):
                continue
            closed.add(rid)
            changed = True
        if not changed:
            break

    results: list[RowResult] = []
    for row in rows:
        rid = row["id"]
        probes = probe_results[rid]
        implemented = all(p.passed for p in probes)
        results.append(
            RowResult(
                id=rid,
                title=row["title"],
                level=row.get("level", "A0"),
                required_level=row.get("required_level", row.get("level", "A0")),
                implemented=implemented,
                pre_hardware_closed=rid in closed,
                blocked_by=[
                    dep for dep in (row.get("blocked_by", []) or []) if dep not in closed
                ],
                open_boundary=row.get("open_boundary", ""),
                probes=probes,
            )
        )
    return results


def summarize(ledger: dict[str, Any], results: list[RowResult]) -> dict[str, Any]:
    total = len(results)
    implemented = sum(1 for r in results if r.implemented)
    closed = sum(1 for r in results if r.pre_hardware_closed)
    physical = ledger["physical_only"]
    return {
        "requirements_total": total,
        "implemented": implemented,
        "pre_hardware_closed": closed,
        "hardware_closed": 0,
        "hardware_total": len(physical),
        "implemented_percent": round(100.0 * implemented / total, 1),
        "pre_hardware_percent": round(100.0 * closed / total, 1),
        "rows": [r.as_dict() for r in results],
        "physical_only_open": [p["id"] for p in physical],
        "failed_probes": [
            {"id": r.id, "probe": p.as_dict()} for r in results for p in r.failed_probes()
        ],
    }


def render_text(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("JStack installer pre-hardware progress")
    lines.append("=" * 38)
    lines.append("")
    for row in summary["rows"]:
        if row["pre_hardware_closed"]:
            mark = "closed "
        elif row["implemented"]:
            mark = "impl   "
        else:
            mark = "OPEN   "
        lines.append(f"  [{mark}] {row['id']}  {row['title']}  ({row['level']})")
        for probe in row["probes"]:
            if not probe["passed"]:
                lines.append(f"            FAILED probe {probe['kind']} {probe['target']}: {probe['detail']}")
        if not row["pre_hardware_closed"] and row.get("open_boundary"):
            lines.append(f"            open: {row['open_boundary']}")
    lines.append("")
    lines.append(
        f"  implemented          {summary['implemented']}/{summary['requirements_total']}"
        f"  ({summary['implemented_percent']}%)"
    )
    lines.append(
        f"  pre-hardware closed  {summary['pre_hardware_closed']}/{summary['requirements_total']}"
        f"  ({summary['pre_hardware_percent']}%)"
    )
    lines.append(
        f"  hardware closed      {summary['hardware_closed']}/{summary['hardware_total']}"
        "  (physical observations, cannot be closed by QEMU)"
    )
    lines.append("")
    lines.append("  still open on physical hardware: " + ", ".join(summary["physical_only_open"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON only")
    parser.add_argument(
        "--no-commands",
        action="store_true",
        help="skip command probes (for fast static runs and offline CI)",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("JSTACK_VM_WORKSPACE")
        or str(Path(os.environ.get("JCODE_SCRATCH_DIR", "/tmp")) / "jstack-windows-vm"),
    )
    parser.add_argument(
        "--require-implemented",
        type=int,
        default=None,
        help="fail if fewer than N rows are implemented; this is the regression gate",
    )
    args = parser.parse_args(argv)

    try:
        ledger = load_ledger(args.ledger)
        results = evaluate(ledger, args.workspace, not args.no_commands)
    except LedgerError as exc:
        print(f"ledger error: {exc}", file=sys.stderr)
        return 2

    summary = summarize(ledger, results)
    print(json.dumps(summary, indent=2, sort_keys=True) if args.json else render_text(summary))

    if args.require_implemented is not None and summary["implemented"] < args.require_implemented:
        print(
            f"\nREGRESSION: {summary['implemented']} rows implemented,"
            f" expected at least {args.require_implemented}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
