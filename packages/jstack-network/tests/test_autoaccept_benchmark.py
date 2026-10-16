#!/usr/bin/env python3
"""Deterministic injected-delay benchmark, not a real captive Wi-Fi measurement.

Run from any directory. Compares checked-in HEAD against the working script.
Each active NM check costs 20ms, cached NM reads 1ms, redirect GETs 15ms.
"""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
REL = "packages/jstack-network/files/bin/captive-portal-autoaccept"


def load(name, source):
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(compile(source, name, "exec"), module.__dict__)
    return module


def response(url, text):
    return types.SimpleNamespace(url=url, text=text, status_code=200, headers={}, history=[])


def measure(module, scenario):
    state = {"online": False, "nm": 0, "active_nm": 0, "redirects": 0}

    def nm(command, **kwargs):
        state["nm"] += 1
        active = command[-1] == "check"
        state["active_nm"] += int(active)
        time.sleep(0.020 if active else 0.001)
        return "full" if state["online"] else "portal"

    class Session:
        def get(self, url, **kwargs):
            if "/r" in url:
                state["redirects"] += 1
                time.sleep(0.015)
                return response(url, "<script>location='/r%d'</script>" % state["redirects"])
            return response(url, '<form method="post" action="/accept"><button>Accept and connect</button></form>')

        def post(self, url, **kwargs):
            state["online"] = True
            return response(url, "<script>location='/r0'</script>")

    with patch.dict(os.environ, {}, clear=True), patch.object(module.subprocess, "check_output", side_effect=nm), patch.object(module, "probe_online", side_effect=lambda sess=None: state["online"]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        start = time.perf_counter()
        if scenario == "slow_nm":
            for _ in range(5):
                assert not module.is_online(Session())
        else:
            assert module.run_accept(Session(), "http://portal/start") == 0
        elapsed = time.perf_counter() - start
    return elapsed, state


class BeforeAfterBenchmark(unittest.TestCase):
    def test_injected_delays(self):
        before_source = subprocess.check_output(["git", "show", "HEAD:" + REL], cwd=ROOT, text=True)
        after_source = (ROOT / REL).read_text()
        for scenario in ("slow_nm", "post_success_redirects"):
            before = measure(load("autoaccept_before_" + scenario, before_source), scenario)
            after = measure(load("autoaccept_after_" + scenario, after_source), scenario)
            print(f"INJECTED {scenario}: HEAD {before[0]*1000:.2f}ms {before[1]}, working {after[0]*1000:.2f}ms {after[1]}")
            self.assertEqual(after[1]["active_nm"], 0)
            self.assertEqual(after[1]["nm"], 1)
            if scenario == "post_success_redirects":
                self.assertEqual(after[1]["redirects"], 0)
                # HEAD should exhibit the reported defect. Once committed,
                # it is valid for HEAD itself to have no remaining defect.
                self.assertIn(before[1]["redirects"], (0, 4))


if __name__ == "__main__":
    unittest.main()
