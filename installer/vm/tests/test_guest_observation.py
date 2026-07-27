#!/usr/bin/env python3
"""Tests for reading a guest adapter's observation.

The observation is produced inside a machine that is being deliberately mutated,
so the tests are written against the assumption that it may be wrong, late, or
hostile. What must hold is that a wrong observation is rejected rather than
believed, and that reading one never opens a channel from the guest to the host.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import read_guest_observation as reader  # noqa: E402

PLAN = "b" * 64
OTHER_PLAN = "c" * 64
ACTION = "shrink_windows_ntfs"


def request(action: str = ACTION, plan: str = PLAN) -> dict:
    return {"action": action, "plan_hash": plan}


def observation(**overrides) -> bytes:
    document = {
        "action": ACTION,
        "plan_hash": PLAN,
        "postcondition": {"partition_size_bytes": 386547056640},
    }
    document.update(overrides)
    return json.dumps(document).encode("utf-8")


class VerificationTests(unittest.TestCase):
    def test_a_matching_observation_is_accepted(self) -> None:
        result = reader.verify_observation(observation(), request())
        self.assertIn("postcondition", result)

    def test_an_observation_for_another_action_is_refused(self) -> None:
        """A report about something nobody authorised is worse than no report."""

        with self.assertRaises(reader.ObservationError) as raised:
            reader.verify_observation(
                observation(action="expand_windows_ntfs"), request()
            )
        self.assertIn("authorised", str(raised.exception))

    def test_an_observation_for_another_plan_is_refused(self) -> None:
        with self.assertRaises(reader.ObservationError):
            reader.verify_observation(observation(plan_hash=OTHER_PLAN), request())

    def test_an_observation_without_a_postcondition_is_refused(self) -> None:
        """Success without a postcondition reports only that nothing crashed."""

        document = json.loads(observation())
        del document["postcondition"]
        with self.assertRaises(reader.ObservationError) as raised:
            reader.verify_observation(json.dumps(document).encode(), request())
        self.assertIn("postcondition", str(raised.exception))

    def test_malformed_bytes_are_refused_rather_than_guessed_at(self) -> None:
        for raw in (b"", b"not json", b"\xff\xfe\x00", b"[]", b'"a string"'):
            with self.subTest(raw=raw[:8]):
                with self.assertRaises(reader.ObservationError):
                    reader.verify_observation(raw, request())


class BoundsTests(unittest.TestCase):
    def test_the_size_cap_is_declared_and_enforced(self) -> None:
        """A compromised guest must not be able to exhaust host memory."""

        body = (ROOT / "tools" / "read_guest_observation.py").read_text(encoding="utf-8")
        self.assertIn("MAX_OBSERVATION_BYTES", body)
        self.assertIn("over the", body)
        self.assertLessEqual(reader.MAX_OBSERVATION_BYTES, 1024 * 1024)


class SealIntegrityTests(unittest.TestCase):
    """Reading a result must not become a channel into the host."""

    def body(self) -> str:
        """Return the module's code with comments and docstrings stripped.

        The first version of this check scanned the raw file and failed on the
        word "listening" inside a sentence explaining that nothing listens. A
        check that a comment can trip is a check that gets weakened to make it
        pass, so it reads the code instead.
        """

        import io
        import tokenize

        source = (ROOT / "tools" / "read_guest_observation.py").read_text(
            encoding="utf-8"
        )
        kept: list[str] = []
        previous = tokenize.INDENT
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                continue
            # A string that is the whole statement is a docstring, not a value.
            if token.type == tokenize.STRING and previous in (
                tokenize.INDENT,
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.DEDENT,
            ):
                previous = token.type
                continue
            kept.append(token.string)
            if token.type not in (tokenize.NL, tokenize.COMMENT):
                previous = token.type
        return " ".join(kept)

    def test_the_read_is_offline_and_read_only(self) -> None:
        body = self.body()
        self.assertIn("--ro", body)
        for forbidden in ("hostfwd", "guest-exec", "qemu-ga", "socket", "listen"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_the_read_needs_no_privilege_or_device(self) -> None:
        """The same constraint the base-image inspection already honours."""

        body = self.body()
        for forbidden in ("sudo", "losetup", "mount(", "kpartx", "/dev/sd", "/dev/nvme"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)


if __name__ == "__main__":
    unittest.main()
