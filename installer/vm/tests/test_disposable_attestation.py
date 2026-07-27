#!/usr/bin/env python3
"""Tests for the disposable-VM attestation minter.

This is the gate that stands between the mutation adapters and a real machine,
so the tests are written against the property that matters: minting must make a
*disposable VM* runnable without making a real machine reachable.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import mint_disposable_attestation as minter  # noqa: E402

PLAN = "f" * 64


class MintingTests(unittest.TestCase):
    def test_a_token_satisfies_the_adapters_length_floor(self) -> None:
        """Both adapter families refuse anything shorter than 32 characters."""

        token = minter.mint("run-1", PLAN)
        self.assertGreaterEqual(len(token), 32)

    def test_two_runs_never_share_a_token(self) -> None:
        """A shared token would let one run's attestation authorise another."""

        tokens = {minter.mint(f"run-{n}", PLAN) for n in range(50)}
        self.assertEqual(len(tokens), 50)

    def test_the_same_run_and_plan_still_mint_differently(self) -> None:
        """A token must not be predictable from values in the evidence bundle.

        The run id and plan hash are both recorded in evidence, so a token that
        was a pure function of them could be recomputed by anyone holding it.
        """

        self.assertNotEqual(minter.mint("run-1", PLAN), minter.mint("run-1", PLAN))

    def test_a_token_names_the_run_that_minted_it(self) -> None:
        """A token found in evidence must be traceable to one run."""

        self.assertIn("run-abc", minter.mint("run-abc", PLAN))

    def test_an_unbound_attestation_is_refused(self) -> None:
        for run_id, plan in (("", PLAN), ("run-1", ""), ("", "")):
            with self.subTest(run_id=run_id, plan=plan):
                with self.assertRaises(minter.AttestationError):
                    minter.mint(run_id, plan)


class RecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="attest-"))
        import shutil

        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)

    def test_the_record_supplies_both_variables_the_adapters_compare(self) -> None:
        """The adapters require presented and expected to match exactly."""

        record = minter.write(self.directory, "run-1", PLAN)
        environment = record["environment"]
        self.assertEqual(
            environment["JSTACK_DISPOSABLE_VM"],
            environment["JSTACK_DISPOSABLE_VM_EXPECTED"],
        )
        self.assertEqual(environment["JSTACK_DISPOSABLE_VM"], record["token"])

    def test_the_record_is_owner_only(self) -> None:
        """One run's attestation must not be readable as another run's expected."""

        minter.write(self.directory, "run-1", PLAN)
        path = self.directory / "disposable-vm-attestation.json"
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_the_record_binds_the_run_and_plan_it_was_minted_for(self) -> None:
        record = minter.write(self.directory, "run-7", PLAN)
        written = json.loads(
            (self.directory / "disposable-vm-attestation.json").read_text()
        )
        self.assertEqual(written["run_id"], "run-7")
        self.assertEqual(written["plan_hash"], PLAN)
        self.assertEqual(written, record)

    def test_a_missing_run_directory_is_refused(self) -> None:
        with self.assertRaises(minter.AttestationError):
            minter.write(self.directory / "absent", "run-1", PLAN)


class GateIntegrityTests(unittest.TestCase):
    """Minting must not weaken the gate that protects a real machine.

    The attestation exists so adapters can run in a disposable VM. It must never
    become sufficient on its own, because the same adapters are what will
    eventually run against real hardware.
    """

    def adapters(self) -> str:
        return (
            ROOT.parent / "core" / "assets" / "windows-mutation-adapters.ps1"
        ).read_text(encoding="utf-8")

    def test_the_adapters_still_require_a_matching_pair(self) -> None:
        body = self.adapters()
        self.assertIn("JSTACK_DISPOSABLE_VM_EXPECTED", body)
        self.assertIn("attestation does not match this run", body)

    def test_the_adapters_still_require_a_plan_bound_capability(self) -> None:
        """A token alone must not authorise a mutation."""

        body = self.adapters()
        self.assertIn("no controller capability was presented", body)
        self.assertIn("capability is bound to a different plan", body)

    def test_the_minter_never_writes_outside_the_run_directory(self) -> None:
        body = (ROOT / "tools" / "mint_disposable_attestation.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("resolved / \"disposable-vm-attestation.json\"", body)
        for forbidden in ("/etc", "os.environ[", "setenv"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
