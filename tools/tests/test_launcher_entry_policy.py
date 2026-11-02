#!/usr/bin/env python3
"""Launcher audience policy tests, independent of the reference desktop."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("entry_policy", ROOT / "tools/launcher-entry-policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class EntryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = POLICY.load_policy()
        self.entries = self.policy["entries"]

    def test_every_snapshot_entry_has_exactly_one_decision(self):
        self.assertEqual(len(self.entries), 132)
        self.assertEqual(len({entry["id"] for entry in self.entries}), 132)
        self.assertEqual(sum(entry["audience"] == "personal" for entry in self.entries), 125)
        self.assertTrue(all(entry["reason"] for entry in self.entries))

    def test_shared_list_is_only_the_minimal_core(self):
        self.assertEqual(self.policy["shared_limit"], 7)
        self.assertEqual(
            {entry["name"] for entry in self.entries if entry["audience"] == "shared"},
            {"Files", "Firefox", "Jcode", "Network Login", "Screenshot (Area)",
             "Screenshot (Fullscreen)", "Screenshot (Window)"},
        )

    def test_optional_services_and_maintainer_tools_remain_personal(self):
        audience = {entry["name"]: entry["audience"] for entry in self.entries}
        for name in ["Gmail", "GitHub", "Bitwarden", "Vesktop", "Jcode Config",
                     "justrust", "Connect AirPods Pro 3", "Pitch Deck", "YouTube"]:
            self.assertEqual(audience[name], "personal", name)

    def inventory(self):
        return "\n".join(f"{entry['name']}\tdesktop\t/example/applications/{entry['id']}" for entry in self.entries)

    def test_complete_inventory_matches_without_reference_home_paths(self):
        self.assertEqual(POLICY.check_inventory(self.entries, self.inventory()), [])

    def test_new_removed_renamed_and_non_desktop_entries_are_not_silent(self):
        for text in [self.inventory() + "\nNew Tool\tdesktop\t/tmp/new.desktop",
                     "\n".join(self.inventory().splitlines()[1:]),
                     self.inventory().replace("Firefox\tdesktop", "Renamed Firefox\tdesktop"),
                     self.inventory() + "\nNew Script\tscript\t/tmp/new.rs",
                     self.inventory() + "\nbroken"]:
            self.assertTrue(POLICY.check_inventory(self.entries, text))

    def test_policy_cannot_leak_reference_commands_or_home_paths(self):
        for entry in self.entries:
            self.assertEqual(set(entry), {"id", "name", "kind", "audience", "reason"})
        text = json.dumps(self.policy)
        for forbidden in ["/home/", "Exec=", "https://", "http://", "token=", "password="]:
            self.assertNotIn(forbidden, text)

    def test_readable_inventory_covers_every_decision(self):
        document = (ROOT / "docs/LAUNCHER_ENTRIES.md").read_text()
        for entry in self.entries:
            prefix = f"| {entry['name']} | `{entry['id']}` | "
            self.assertEqual(document.count(prefix), 1, entry["id"])
            if entry["audience"] == "personal":
                self.assertIn(prefix + "personal |", document)

    def test_bad_policy_is_rejected(self):
        variants = []
        duplicate = copy.deepcopy(self.policy)
        duplicate["entries"].append(duplicate["entries"][0])
        variants.append(duplicate)
        unknown = copy.deepcopy(self.policy)
        unknown["entries"][0]["audience"] = "maybe"
        variants.append(unknown)
        unsafe_default = copy.deepcopy(self.policy)
        unsafe_default["default_audience"] = "shared"
        variants.append(unsafe_default)
        too_many = copy.deepcopy(self.policy)
        too_many["entries"][0]["audience"] = "shared"
        variants.append(too_many)
        traversal = copy.deepcopy(self.policy)
        traversal["entries"][0]["id"] = "../outside.desktop"
        variants.append(traversal)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            for variant in variants:
                path.write_text(json.dumps(variant))
                with self.assertRaises(ValueError):
                    POLICY.load_policy(path)

    def test_cli_outputs_shared_only_and_checks_saved_inventory(self):
        command = [sys.executable, str(ROOT / "tools/launcher-entry-policy.py")]
        result = subprocess.run(command + ["--audience", "shared"], check=True, capture_output=True, text=True)
        self.assertEqual(len(result.stdout.splitlines()), 7)
        self.assertTrue(all(line.startswith("shared\t") for line in result.stdout.splitlines()))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.tsv"
            path.write_text(self.inventory())
            result = subprocess.run(command + ["--inventory", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            path.write_text(self.inventory() + "\nNew\tdesktop\t/tmp/new.desktop")
            result = subprocess.run(command + ["--inventory", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("unclassified", result.stderr)


if __name__ == "__main__":
    unittest.main()
