#!/usr/bin/env python3
"""Inspect explicit reference-launcher decisions without copying personal commands."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs" / "launcher-entries.json"


def load_policy(path=POLICY):
    policy = json.loads(Path(path).read_text())
    if policy.get("schema_version") != 1 or policy.get("default_audience") != "personal":
        raise ValueError("unsupported policy schema or unsafe default audience")
    entries = policy["entries"]
    seen = set()
    for entry in entries:
        ident = entry["id"]
        if not ident.endswith(".desktop") or Path(ident).name != ident or ident in seen:
            raise ValueError(f"invalid or duplicate desktop identity: {ident}")
        seen.add(ident)
        if entry["audience"] not in ("shared", "personal"):
            raise ValueError(f"invalid audience: {ident}")
        if entry["kind"] != "desktop" or not entry["name"] or not entry["reason"]:
            raise ValueError(f"incomplete classification: {ident}")
        if any(char in entry["name"] for char in "\t\r\n"):
            raise ValueError(f"invalid display name: {ident}")
    if sum(entry["audience"] == "shared" for entry in entries) > policy["shared_limit"]:
        raise ValueError("shared entry budget exceeded, review the minimal default policy")
    return policy


def check_inventory(entries, text):
    """Compare full visible name/desktop-ID pairs. Never launch an entry."""
    known = {(entry["id"], entry["name"]) for entry in entries}
    current = set()
    errors = []
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 3 or fields[1] != "desktop":
            errors.append("unclassified or malformed non-desktop inventory record")
            continue
        name, _, source = fields
        current.add((Path(source).name, name))
    for ident, name in sorted(current - known):
        errors.append(f"unclassified: {ident} ({name}), keep personal until explicitly reviewed")
    for ident, name in sorted(known - current):
        errors.append(f"not in current launcher: {ident} ({name})")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audience", choices=("shared", "personal", "all"), default="all")
    parser.add_argument("--check-current", action="store_true", help="read jofi list and check exact inventory coverage")
    parser.add_argument("--inventory", type=Path, help="check saved jofi list TSV instead of running jofi")
    args = parser.parse_args(argv)
    try:
        policy = load_policy()
        if args.check_current or args.inventory:
            text = args.inventory.read_text() if args.inventory else subprocess.run(
                ["jofi", "list"], check=True, capture_output=True, text=True, timeout=30
            ).stdout
            errors = check_inventory(policy["entries"], text)
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
            print(f"All {len(policy['entries'])} visible entries have an explicit audience.")
        else:
            for entry in policy["entries"]:
                if args.audience in ("all", entry["audience"]):
                    print(f"{entry['audience']}\t{entry['name']}\t{entry['id']}")
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"launcher policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
