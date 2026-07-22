#!/usr/bin/env python3
"""Validate contract schemas, fixtures, and the generated example plan."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import FormatChecker
from jsonschema.validators import validator_for
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    schemas = {path.name: load(path) for path in SCHEMA_DIR.glob("*.json")}
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    errors: list[str] = []
    for name, schema in sorted(schemas.items()):
        try:
            validator_for(schema).check_schema(schema)
        except Exception as error:  # schema diagnostics need the original detail
            errors.append(f"schema {name}: {error}")

    documents = [
        ("windows-storage-snapshot.schema.json", ROOT / "fixtures" / "windows-storage-snapshot.json"),
        ("inventory.schema.json", ROOT / "fixtures" / "windows-11-basic-gpt.json"),
        ("inventory.schema.json", ROOT / "generated" / "example-observed-inventory.json"),
        ("release-requirements.schema.json", ROOT / "fixtures" / "release-requirements.json"),
        ("signed-release-manifest.schema.json", ROOT / "fixtures" / "signed-release-manifest.json"),
        ("release-acceptance-state.schema.json", ROOT / "fixtures" / "release-acceptance-state.json"),
        ("install-plan.schema.json", ROOT / "generated" / "example-plan.json"),
        ("plan-display.schema.json", ROOT / "generated" / "example-plan-display.json"),
        ("confirmation.schema.json", ROOT / "generated" / "example-confirmation.json"),
        ("journal-record.schema.json", ROOT / "generated" / "example-journal-record.json"),
        ("journal-chain.schema.json", ROOT / "generated" / "example-journal-chain.json"),
        ("handoff.schema.json", ROOT / "generated" / "example-handoff.json"),
        ("destination-evidence.schema.json", ROOT / "generated" / "example-destination-intent.json"),
        ("destination-evidence.schema.json", ROOT / "generated" / "example-destination-commit.json"),
    ]
    for schema_name, path in documents:
        schema = schemas[schema_name]
        validator = validator_for(schema)(
            schema, registry=registry, format_checker=FormatChecker()
        )
        for error in sorted(validator.iter_errors(load(path)), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            errors.append(f"{path.name} {location}: {error.message}")

    journal_validator = validator_for(schemas["journal-record.schema.json"])(
        schemas["journal-record.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    )
    intent = load(ROOT / "generated" / "example-journal-record.json")
    chain_validator = validator_for(schemas["journal-chain.schema.json"])(
        schemas["journal-chain.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    )
    if not chain_validator.is_valid([intent]):
        errors.append("journal chain schema rejected a valid interrupted intent-only chain")
    invalid_phase_examples = []
    intent_with_postcondition = dict(intent)
    intent_with_postcondition["postcondition_hash"] = "11" * 32
    invalid_phase_examples.append(("intent with postcondition", intent_with_postcondition))
    intent_with_created_object = dict(intent)
    intent_with_created_object["created_objects"] = [
        {"kind": "boot_entry", "stable_id": "uefi:Boot0007"}
    ]
    invalid_phase_examples.append(("intent with created object", intent_with_created_object))
    state_without_postcondition = dict(intent)
    state_without_postcondition["record_type"] = "state_advanced"
    invalid_phase_examples.append(("state advanced without postcondition", state_without_postcondition))
    for label, document in invalid_phase_examples:
        if journal_validator.is_valid(document):
            errors.append(f"journal schema accepted invalid {label}")

    destination_validator = validator_for(schemas["destination-evidence.schema.json"])(
        schemas["destination-evidence.schema.json"],
        registry=registry,
        format_checker=FormatChecker(),
    )
    destination_intent = load(ROOT / "generated" / "example-destination-intent.json")
    invalid_destinations = []
    reordered = json.loads(json.dumps(destination_intent))
    reordered["artifacts"][0], reordered["artifacts"][1] = (
        reordered["artifacts"][1],
        reordered["artifacts"][0],
    )
    invalid_destinations.append(("reordered destination artifacts", reordered))
    wrong_actor = json.loads(json.dumps(destination_intent))
    wrong_actor["actor"] = "linux_installer"
    invalid_destinations.append(("transition actor mismatch", wrong_actor))
    wrong_phase = json.loads(json.dumps(destination_intent))
    wrong_phase["partition_phase"] = "installed"
    invalid_destinations.append(("transition partition phase mismatch", wrong_phase))
    missing_artifact = json.loads(json.dumps(destination_intent))
    missing_artifact["artifacts"].pop()
    invalid_destinations.append(("missing destination artifact", missing_artifact))
    for label, document in invalid_destinations:
        if destination_validator.is_valid(document):
            errors.append(f"destination schema accepted invalid {label}")
    destination_commit = load(ROOT / "generated" / "example-destination-commit.json")
    reordered_commit = json.loads(json.dumps(destination_commit))
    reordered_commit["artifacts"][0], reordered_commit["artifacts"][1] = (
        reordered_commit["artifacts"][1],
        reordered_commit["artifacts"][0],
    )
    if destination_validator.is_valid(reordered_commit):
        errors.append("destination schema accepted reordered commit artifacts")
    wrong_commit_transition = json.loads(json.dumps(destination_commit))
    wrong_commit_transition["transition_id"] = "deploy_jstack_image"
    if destination_validator.is_valid(wrong_commit_transition):
        errors.append("destination schema accepted commit transition/artifact mismatch")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"validated {len(schemas)} schemas and {len(documents)} contract documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
