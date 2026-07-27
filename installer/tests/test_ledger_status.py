"""Tests for the pre-hardware progress tracker.

A progress tracker is a tempting place to cheat, so these tests attack it from
the direction of a person trying to inflate the number: add a row with no probe,
weaken a safety check, rename an evidence file, or mark a VM-gated row closed
from unit tests. Each of those must be refused or reported honestly.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import ledger_status  # noqa: E402
from ledger_status import (  # noqa: E402
    DEFAULT_LEDGER,
    LedgerError,
    evaluate,
    load_ledger,
    render_text,
    summarize,
)


def write_ledger(body: dict) -> Path:
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(body, handle)
    handle.close()
    return Path(handle.name)


class LedgerStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = load_ledger(DEFAULT_LEDGER)

    def test_the_real_ledger_loads_and_keeps_the_physical_rows(self) -> None:
        self.assertEqual(self.ledger["kind"], "pre-hardware-completion-ledger")
        self.assertEqual(len(self.ledger["requirements"]), 19)
        # HW-01..HW-08 must survive every refactor: they are the permanent
        # residual risk, and dropping them would silently claim more than is true.
        self.assertEqual(
            [row["id"] for row in self.ledger["physical_only"]],
            [f"HW-0{n}" for n in range(1, 9)],
        )

    def test_every_requirement_names_at_least_one_probe(self) -> None:
        for row in self.ledger["requirements"]:
            with self.subTest(row=row["id"]):
                self.assertTrue(row["probes"], f"{row['id']} has no probe")

    def test_a_row_without_probes_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"].append({"id": "PH-99", "title": "free points", "probes": []})
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_a_row_with_no_probes_key_at_all_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"].append({"id": "PH-99", "title": "free points"})
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_duplicate_requirement_ids_are_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"].append(copy.deepcopy(body["requirements"][0]))
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_dropping_the_physical_rows_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["physical_only"] = []
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_an_unknown_dependency_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"][0]["blocked_by"] = ["PH-404"]
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_an_unknown_probe_kind_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"][0]["probes"] = [{"kind": "vibes", "path": "x"}]
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_an_invalid_regex_is_rejected(self) -> None:
        body = copy.deepcopy(self.ledger)
        body["requirements"][0]["probes"] = [
            {"kind": "grep", "path": "Makefile", "pattern": "("}
        ]
        with self.assertRaises(LedgerError):
            load_ledger(write_ledger(body))

    def test_malformed_json_is_fatal_rather_than_an_empty_pass(self) -> None:
        path = Path(tempfile.mkdtemp()) / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(LedgerError):
            load_ledger(path)


class ProbeBehaviourTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = load_ledger(DEFAULT_LEDGER)

    def evaluate_static(self, ledger: dict) -> dict[str, ledger_status.RowResult]:
        results = evaluate(ledger, "/nonexistent-workspace", run_commands=False)
        return {row.id: row for row in results}

    def test_all_static_probes_pass_on_the_current_tree(self) -> None:
        rows = self.evaluate_static(self.ledger)
        for rid, row in rows.items():
            with self.subTest(row=rid):
                self.assertTrue(
                    row.implemented,
                    f"{rid} failed: {[p.detail for p in row.failed_probes()]}",
                )

    def test_a_missing_evidence_file_reopens_its_row(self) -> None:
        """Renaming an evidence file must not go unnoticed."""

        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-01")
        row["probes"] = [{"kind": "file", "path": "controller/src/does-not-exist.rs"}]
        self.assertFalse(self.evaluate_static(body)["PH-01"].implemented)

    def test_an_absent_probe_fails_when_the_forbidden_token_appears(self) -> None:
        """The negative safety probes must actually have teeth."""

        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-06")
        # platform.rs certainly contains the word "partition"; if `absent` were
        # implemented backwards this would pass.
        row["probes"] = [
            {"kind": "absent", "path": "controller/src/platform.rs", "pattern": "partition"}
        ]
        self.assertFalse(self.evaluate_static(body)["PH-06"].implemented)

    def test_a_grep_probe_fails_when_the_pattern_is_absent(self) -> None:
        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-02")
        row["probes"] = [
            {
                "kind": "grep",
                "path": "controller/tests/selection_totality.rs",
                "pattern": "this_string_is_not_in_the_file_xyzzy",
            }
        ]
        self.assertFalse(self.evaluate_static(body)["PH-02"].implemented)

    def test_patterns_anchor_per_line(self) -> None:
        """`^check:` must match a Makefile target, not fail on the whole file."""

        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-18")
        row["probes"] = [{"kind": "grep", "path": "Makefile", "pattern": "^check:"}]
        self.assertTrue(self.evaluate_static(body)["PH-18"].implemented)

    def test_exclude_lines_ignores_comments_but_not_code(self) -> None:
        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-17")
        # The doc comment mentions --production; excluding comment lines makes
        # the probe pass, and not excluding them makes it fail. Both directions
        # are asserted so the exclusion cannot silently swallow real code.
        row["probes"] = [
            {
                "kind": "absent",
                "path": "controller/src/bin/jstack-installer.rs",
                "pattern": "--production",
                "exclude_lines": r"^\s*(//|\*)",
            }
        ]
        self.assertTrue(self.evaluate_static(body)["PH-17"].implemented)
        del row["probes"][0]["exclude_lines"]
        self.assertFalse(self.evaluate_static(body)["PH-17"].implemented)

    def test_a_probe_path_cannot_escape_the_installer_tree(self) -> None:
        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-01")
        row["probes"] = [{"kind": "file", "path": "../../../../etc/passwd"}]
        with self.assertRaises(LedgerError):
            evaluate(body, "/nonexistent-workspace", run_commands=False)

    def test_an_unresolved_placeholder_fails_the_probe(self) -> None:
        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-12")
        row["probes"] = [{"kind": "command", "argv": ["true", "{no_such_placeholder}"]}]
        result = self.evaluate_static(body)["PH-12"]
        # Command probes are skipped in static mode, so this must be checked with
        # commands enabled or the placeholder bug would hide.
        result = {
            r.id: r for r in evaluate(body, "/nonexistent", run_commands=True)
        }["PH-12"]
        self.assertFalse(result.implemented)

    def test_a_failing_command_probe_opens_its_row(self) -> None:
        body = copy.deepcopy(self.ledger)
        row = next(r for r in body["requirements"] if r["id"] == "PH-12")
        row["probes"] = [{"kind": "command", "argv": ["false"]}]
        rows = {r.id: r for r in evaluate(body, "/nonexistent", run_commands=True)}
        self.assertFalse(rows["PH-12"].implemented)


class ClosureHonestyTests(unittest.TestCase):
    """The central property: passing code checks must not close a VM-gated row."""

    def setUp(self) -> None:
        self.ledger = load_ledger(DEFAULT_LEDGER)
        self.rows = {r.id: r for r in evaluate(self.ledger, "/nonexistent", False)}

    def test_vm_gated_rows_are_never_closed_by_source_probes(self) -> None:
        for rid in ("PH-13", "PH-14", "PH-15"):
            with self.subTest(row=rid):
                self.assertTrue(self.rows[rid].implemented)
                self.assertFalse(
                    self.rows[rid].pre_hardware_closed,
                    f"{rid} requires a real VM observation and must not close from unit tests",
                )

    def test_rows_awaiting_a_live_guest_are_not_closed_even_when_implemented(self) -> None:
        for rid in ("PH-08", "PH-09", "PH-11", "PH-12", "PH-16", "PH-19"):
            with self.subTest(row=rid):
                self.assertFalse(self.rows[rid].pre_hardware_closed)

    def test_the_frozen_tree_row_cannot_close_from_a_probe(self) -> None:
        self.assertFalse(self.rows["PH-18"].pre_hardware_closed)

    def test_hardware_closure_is_always_zero(self) -> None:
        summary = summarize(self.ledger, list(self.rows.values()))
        self.assertEqual(summary["hardware_closed"], 0)
        self.assertEqual(summary["hardware_total"], 8)

    def test_closed_never_exceeds_implemented(self) -> None:
        summary = summarize(self.ledger, list(self.rows.values()))
        self.assertLessEqual(summary["pre_hardware_closed"], summary["implemented"])

    def test_marking_a_vm_row_closed_requires_removing_its_gate(self) -> None:
        """Mutation test: the gate is what holds PH-13 open, not an accident."""

        body = copy.deepcopy(self.ledger)
        for r in body["requirements"]:
            # PH-13 transitively depends on rows that are themselves gated, so
            # the whole chain must be released to isolate PH-13's own gate.
            r["requires_vm_observation"] = False
            r["requires_clean_tree"] = False
        row = next(r for r in body["requirements"] if r["id"] == "PH-13")
        row["blocked_by"] = []
        rows = {r.id: r for r in evaluate(body, "/nonexistent", False)}
        self.assertTrue(rows["PH-13"].pre_hardware_closed)

    def test_the_report_always_names_the_open_physical_rows(self) -> None:
        summary = summarize(self.ledger, list(self.rows.values()))
        text = render_text(summary)
        for n in range(1, 9):
            self.assertIn(f"HW-0{n}", text)


class ProseAgreementTests(unittest.TestCase):
    """The prose ledger and the executable ledger must describe the same rows.

    Documentation drifting away from the computed status is the exact failure this
    whole tool exists to prevent, so it is itself checked.
    """

    def test_every_executable_row_appears_in_the_prose_ledger(self) -> None:
        prose = (ROOT.parent / "docs" / "installer" / "PRE_HARDWARE_LEDGER.md").read_text(
            encoding="utf-8"
        )
        for row in load_ledger(DEFAULT_LEDGER)["requirements"]:
            with self.subTest(row=row["id"]):
                self.assertIn(row["id"], prose)

    def test_every_prose_row_appears_in_the_executable_ledger(self) -> None:
        import re

        prose = (ROOT.parent / "docs" / "installer" / "PRE_HARDWARE_LEDGER.md").read_text(
            encoding="utf-8"
        )
        prose_ids = set(re.findall(r"\bPH-\d\d\b", prose))
        ledger_ids = {row["id"] for row in load_ledger(DEFAULT_LEDGER)["requirements"]}
        self.assertEqual(prose_ids - ledger_ids, set())


class CliTests(unittest.TestCase):
    def test_the_static_run_exits_zero_and_prints_all_three_numbers(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = ledger_status.main(["--no-commands"])
        self.assertEqual(code, 0)
        text = buffer.getvalue()
        self.assertIn("implemented", text)
        self.assertIn("pre-hardware closed", text)
        self.assertIn("hardware closed", text)

    def test_json_output_is_valid_and_complete(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            ledger_status.main(["--no-commands", "--json"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["requirements_total"], 19)
        self.assertEqual(len(payload["rows"]), 19)
        self.assertEqual(payload["hardware_closed"], 0)

    def test_the_regression_gate_fails_below_the_recorded_baseline(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            code = ledger_status.main(["--no-commands", "--require-implemented", "999"])
        self.assertEqual(code, 1)

    def test_the_regression_gate_passes_at_the_current_baseline(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = ledger_status.main(["--no-commands", "--require-implemented", "19"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
