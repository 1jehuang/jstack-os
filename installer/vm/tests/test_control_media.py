#!/usr/bin/env python3
"""Tests for the guest control medium.

The medium is the only channel into a sealed guest, so the tests are written
against what must remain true of it: it carries exactly one authorised action,
it cannot be replayed into another run or plan, and it does not become a general
transport that would undermine the topology seal.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import build_control_media as control  # noqa: E402
import images  # noqa: E402

PLAN = "b" * 64
OTHER_PLAN = "c" * 64
ATTESTATION = "jstack-disposable-vm-run-1-" + "d" * 40
ACTION = "shrink_windows_ntfs"


def capability(action: str = ACTION, plan: str = PLAN) -> dict:
    return {"action": action, "plan_hash": plan, "issued_by": "controller"}


class RequestBindingTests(unittest.TestCase):
    """One medium authorises one action against one plan."""

    def test_a_capability_for_another_action_is_refused(self) -> None:
        with self.assertRaises(control.ControlMediaError) as raised:
            control.build_request(
                ACTION, PLAN, capability(action="expand_windows_ntfs"), ATTESTATION, {}
            )
        self.assertIn("authorises", str(raised.exception))

    def test_a_capability_for_another_plan_is_refused(self) -> None:
        """Replaying a medium against a different plan must be impossible."""

        with self.assertRaises(control.ControlMediaError):
            control.build_request(
                ACTION, PLAN, capability(plan=OTHER_PLAN), ATTESTATION, {}
            )

    def test_a_missing_attestation_is_refused(self) -> None:
        for token in ("", "short"):
            with self.subTest(token=token):
                with self.assertRaises(control.ControlMediaError):
                    control.build_request(ACTION, PLAN, capability(), token, {})

    def test_an_unbound_request_is_refused(self) -> None:
        for action, plan in ((ACTION, ""), ("", PLAN)):
            with self.subTest(action=action, plan=plan):
                with self.assertRaises(control.ControlMediaError):
                    control.build_request(
                        action, plan, capability(action=action, plan=plan), ATTESTATION, {}
                    )

    def test_the_request_is_byte_reproducible(self) -> None:
        """The medium's digest is only an identity if its bytes are stable."""

        first = control.build_request(ACTION, PLAN, capability(), ATTESTATION, {"a": 1})
        second = control.build_request(ACTION, PLAN, capability(), ATTESTATION, {"a": 1})
        self.assertEqual(first, second)

    def test_the_request_carries_the_attestation_and_capability(self) -> None:
        document = json.loads(
            control.build_request(ACTION, PLAN, capability(), ATTESTATION, {})
        )
        self.assertEqual(document["attestation"], ATTESTATION)
        self.assertEqual(document["capability"]["action"], ACTION)
        self.assertEqual(document["plan_hash"], PLAN)


class MediumTests(unittest.TestCase):
    def setUp(self) -> None:
        scratch = Path(__import__("os").environ.get("JCODE_SCRATCH_DIR", "/tmp"))
        self.workspace = Path(tempfile.mkdtemp(prefix="ctlmedia-", dir=scratch))
        self.addCleanup(shutil.rmtree, self.workspace, ignore_errors=True)

    @unittest.skipUnless(shutil.which("mkfs.fat"), "mkfs.fat is unavailable")
    def test_the_adapter_reaches_the_guest_byte_identically(self) -> None:
        """What runs in the guest must be what was reviewed in the repository."""

        evidence = control.build(
            self.workspace,
            self.workspace / "control.img",
            ACTION,
            PLAN,
            capability(),
            ATTESTATION,
        )
        source = control.ADAPTER_SOURCE.read_bytes()
        self.assertEqual(evidence["adapter_sha256"], hashlib.sha256(source).hexdigest())
        observed = images._fat_read(Path(evidence["image"]), "/jstack-adapters.ps1")
        self.assertEqual(observed, source)


class DispatchEquivalenceTests(unittest.TestCase):
    """The medium must carry exactly what the controller authorised.

    The controller decides what may happen and the medium carries it to a guest.
    If those two can disagree, the authorisation is decorative: the guest acts on
    the medium, so the medium is what actually decides. Re-specifying the action
    or the targets by hand would be a second, unauthorised source of truth.
    """

    def dispatched(self) -> dict:
        return {
            "action": ACTION,
            "plan_hash": PLAN,
            "actor": "windows_bootstrap",
            "capability": capability(),
            "targets": {
                "disk_guid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "target_size_bytes": 386547056640,
            },
        }

    def test_the_request_reproduces_the_dispatch_document(self) -> None:
        source = self.dispatched()
        rendered = json.loads(
            control.build_request(
                source["action"],
                source["plan_hash"],
                source["capability"],
                ATTESTATION,
                source["targets"],
            )
        )
        self.assertEqual(rendered["action"], source["action"])
        self.assertEqual(rendered["plan_hash"], source["plan_hash"])
        self.assertEqual(rendered["capability"], source["capability"])
        for name, value in source["targets"].items():
            with self.subTest(target=name):
                self.assertEqual(rendered[name], value)

    def test_targets_are_carried_verbatim_rather_than_recomputed(self) -> None:
        """A target the medium derives itself is a target nobody authorised."""

        body = (ROOT / "tools" / "build_control_media.py").read_text(encoding="utf-8")
        # Targets are spread into the document unchanged; nothing recomputes a
        # size or a GUID on the way through.
        self.assertIn("**targets", body)
        for forbidden in ("target_size_bytes =", "disk_guid =", "//", "* 1024**3"):
            with self.subTest(token=forbidden):
                self.assertNotIn(f"{forbidden} ", body)


class SealIntegrityTests(unittest.TestCase):
    """The channel must not become a way to reach the host.

    The sealed topology is why a controller cannot mutate the machine it runs on.
    A transport built to talk to a guest is exactly the thing that would erode
    that, so the constraints are asserted rather than assumed.
    """

    def body(self) -> str:
        return (ROOT / "tools" / "build_control_media.py").read_text(encoding="utf-8")

    def test_the_medium_is_a_disk_image_not_an_execution_channel(self) -> None:
        body = self.body()
        for forbidden in ("subprocess.Popen", "guest-exec", "hostfwd", "ssh"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_the_medium_carries_a_fixed_payload_set(self) -> None:
        """A general file-transfer medium would be an unbounded surface."""

        body = self.body()
        self.assertIn("/jstack-adapters.ps1", body)
        self.assertIn("/jstack-request.json", body)
        # No caller-supplied path may be placed onto the medium.
        self.assertNotIn("--payload", body)

    def test_the_adapter_source_is_the_repository_copy(self) -> None:
        """A caller-selected script would defeat review entirely."""

        self.assertIn("core", str(control.ADAPTER_SOURCE))
        self.assertTrue(str(control.ADAPTER_SOURCE).endswith("windows-mutation-adapters.ps1"))


if __name__ == "__main__":
    unittest.main()
