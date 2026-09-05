#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HARNESS = Path(__file__).with_name("test-ubuntu-recovery.py")
spec = importlib.util.spec_from_file_location("ubuntu_recovery_harness", HARNESS)
h = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(h)


class RecoveryHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.inputs = []
        for name in ("binary", "graph", "host.qcow2", "target.qcow2"):
            p = self.root / name; p.write_bytes((name + "\n").encode()); self.inputs.append(p)

    def tearDown(self): self.tmp.cleanup()

    def run_harness(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(HARNESS), *map(str, args)], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ok and result.returncode != 0: self.fail(result.stderr)
        if not ok: self.assertNotEqual(result.returncode, 0)
        return result

    def prepare(self):
        work = self.root / "campaign"
        self.run_harness("prepare", "--work", work, "--source-revision", "dce4b67",
                         "--binary", self.inputs[0], "--graph", self.inputs[1],
                         "--host-base", self.inputs[2], "--target-base", self.inputs[3],
                         "--qemu", "/bin/true", "--qemu=-nic", "--qemu", "none")
        return work

    def test_prepare_binds_inputs_defaults_and_refuses_overwrite(self):
        work = self.prepare(); m = json.loads((work / "manifest.json").read_text())
        self.assertEqual(m["defaults"], {"memory_mib": 64, "network": "none", "simultaneous_vms": 1})
        self.assertEqual(m["source_revision"], "dce4b67")
        self.assertIn("committed-target-corruption", m["scenarios"])
        result = self.run_harness("prepare", "--work", work, "--source-revision", "dce4b67",
                         "--binary", self.inputs[0], "--graph", self.inputs[1],
                         "--host-base", self.inputs[2], "--target-base", self.inputs[3],
                         "--qemu", "/bin/true", ok=False)
        self.assertIn("already exists", result.stderr)

    def test_manifest_digest_drift_fails_closed(self):
        work = self.prepare(); self.inputs[1].write_bytes(b"changed")
        with self.assertRaises(SystemExit) as error: h.load_manifest(work / "manifest.json")
        self.assertIn("graph digest changed", str(error.exception))

    def test_observe_requires_exact_marker_followed_by_hash_evidence(self):
        run = self.root / "run"; run.mkdir()
        (run / "process.json").write_text(json.dumps({"pid": subprocess.os.getpid()}))
        marker = "JSTK_UBUNTU_COMMIT seq=2 offset=64 length=64"
        evidence = {"marker": marker, "journal_sha256": "a" * 64, "journal_bytes": 81,
                    "journal_last_kind": "Commit", "target_sha256": "b" * 64}
        (run / "serial.log").write_text(marker + "\nJSTK_VM_EVIDENCE " + json.dumps(evidence) + "\n")
        result = self.run_harness("observe", "--run", run, "--boundary", "commit", "--timeout", "0.1")
        record = json.loads(result.stdout)
        self.assertEqual(record["actual_marker"], marker)
        self.assertEqual(record["evidence"]["journal_last_kind"], "Commit")
        self.assertTrue((run / "observed-commit.json").exists())

    def test_missed_boundary_does_not_kill_process_or_write_observation(self):
        run = self.root / "run"; run.mkdir()
        (run / "process.json").write_text(json.dumps({"pid": subprocess.os.getpid()}))
        wrong = {"marker": "JSTK_UBUNTU_INTENT seq=0 offset=0 length=1",
                 "journal_sha256": "a" * 64, "journal_bytes": 1, "target_sha256": "b" * 64}
        (run / "serial.log").write_text("JSTK_UBUNTU_COMMIT seq=0 offset=0 length=1\nJSTK_VM_EVIDENCE " + json.dumps(wrong))
        result = self.run_harness("observe", "--run", run, "--boundary", "commit", "--timeout", "0.05", ok=False)
        self.assertIn("VM remains running", result.stderr)
        self.assertFalse((run / "observed-commit.json").exists())

    def test_template_rejects_unknown_fields(self):
        with self.assertRaises(SystemExit): h.format_command(["{unsafe}"], {"host": "/x"})


if __name__ == "__main__": unittest.main()
