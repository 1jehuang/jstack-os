#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT.parent / "core"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    schema = load(ROOT / "schemas" / "staging-evidence.schema.json")
    fixture_path = ROOT / "fixtures" / "staging-evidence.json"
    fixture_bytes = fixture_path.read_bytes()
    fixture = json.loads(fixture_bytes)
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator_class(schema).validate(fixture)
    if fixture_bytes != canonical(fixture) + b"\n":
        raise SystemExit("staging evidence fixture is not unique canonical JSON")

    acceptance = load(CORE / "fixtures" / "release-acceptance-state.json")
    manifest = load(CORE / "fixtures" / "signed-release-manifest.json")
    expected = {
        "schema_version": 1,
        "manifest_digest": acceptance["manifest_digest"],
        "acceptance_state_hash": hashlib.sha256(canonical(acceptance)).hexdigest(),
        "artifacts": sorted(
            (
                {
                    "role": artifact["role"],
                    "size_bytes": artifact["size_bytes"],
                    "sha256": artifact["sha256"],
                }
                for artifact in manifest["signed"]["artifacts"]
            ),
            key=lambda artifact: artifact["role"],
        ),
    }
    if fixture != expected:
        raise SystemExit("staging evidence fixture diverges from signed core fixtures")
    digest = hashlib.sha256(canonical(fixture)).hexdigest()
    if digest != "fa20e93dec1c8d282b7611f33a476540e08b3ffc80afcae3f30c598bb131b95f":
        raise SystemExit("staging evidence known-answer digest changed")
    print("validated staging evidence schema, canonical fixture, and known-answer digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
