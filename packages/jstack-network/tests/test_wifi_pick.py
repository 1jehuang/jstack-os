#!/usr/bin/env python3
"""Connection-flow regressions, with no real nmcli/tofi or profile changes."""
import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "files/bin/wifi-pick"
loader = importlib.machinery.SourceFileLoader("wifi_pick", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
wifi = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wifi
loader.exec_module(wifi)


def result(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class ConnectionTests(unittest.TestCase):
    def exercise(self, answers, attempts, *, known=False, security="WPA2", menu=None):
        answers = iter(answers)
        attempts = iter(attempts)
        self.commands = []
        self.events = []
        self.prompt_count = 0

        def run(cmd, *, input=None, timeout=20):
            if cmd[0] == "tofi":
                if "--prompt-text" not in cmd:
                    self.assertNotIn("--print-index", cmd)
                    if menu is None:
                        # Pick the first line tofi was given, by text.
                        return result(stdout=input.split("\n")[0])
                    return result(stdout=menu)
                self.prompt_count += 1
                self.events.append("prompt")
                self.assertEqual(cmd[cmd.index("--prompt-newline") + 1], "true")
                self.assertEqual(cmd[cmd.index("--prompt-padding") + 1], "18")
                self.assertEqual(cmd[cmd.index("--history") + 1], "false")
                answer = next(answers)  # Unexpected retry fails, never loops forever.
                return result(1 if answer is None else 0, answer or "")
            self.assertEqual(cmd[0], "nmcli")
            self.commands.append(cmd[1:])
            self.events.append("connect")
            outcome = next(attempts)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        net = wifi.Net("", "Test WiFi", security, 80, known)
        with (patch.object(wifi, "run", side_effect=run),
              patch.object(wifi, "shutil_which", return_value=True),
              patch.object(wifi, "wifi_enabled", return_value=True),
              patch.object(wifi, "rescan_wifi"),
              patch.object(wifi.time, "sleep"),
              patch.object(wifi, "get_networks", return_value=(
                  [net], {net.ssid: "Renamed profile"} if known else {})),
              patch.object(wifi, "wifi_history_file", return_value="/unused/history"),
              patch.dict(wifi.os.environ, {"WIFI_PICK_DUMP": ""}),
              patch.object(wifi, "notify") as notifications,
              patch.object(wifi, "trigger_captive_portal_check") as captive,
              patch.object(wifi, "trigger_post_connect_verification") as verify):
            code = wifi.main()
        self.notifications = notifications.call_args_list
        self.success_count = captive.call_count
        self.assertEqual(captive.call_count, verify.call_count)
        self.assertFalse(any("delete" in cmd for cmd in self.commands))
        return code

    def test_menu_cancel(self):
        self.assertEqual(self.exercise([], [], menu=""), 0)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.prompt_count, 0)

    def test_initial_password_cancel_or_empty(self):
        for answer in (None, ""):
            with self.subTest(answer=answer):
                self.assertEqual(self.exercise([answer], []), 0)
                self.assertEqual(self.commands, [])
                self.assertEqual(self.prompt_count, 1)
                self.assertEqual(self.success_count, 0)

    def test_wrong_initial_password_then_success(self):
        self.assertEqual(self.exercise(
            ["wrong-secret", "correct-secret"],
            [result(4, stderr="Authentication failed: wrong-secret"), result()]), 0)
        self.assertEqual(self.events, ["prompt", "connect", "prompt", "connect"])
        self.assertEqual(self.commands, [
            ["dev", "wifi", "connect", "Test WiFi", "password", "wrong-secret"],
            ["dev", "wifi", "connect", "Test WiFi", "password", "correct-secret"],
        ])
        self.assertEqual(self.success_count, 1)
        self.assertIn("Authentication failed: [redacted]", str(self.notifications))
        self.assertNotIn("wrong-secret", str(self.notifications))
        self.assertNotIn("correct-secret", str(self.notifications))

    def test_saved_failure_then_password_success(self):
        self.assertEqual(self.exercise(["replacement"], [
            result(4, stderr="Saved activation failed"), result()], known=True), 0)
        self.assertEqual(self.events, ["connect", "prompt", "connect"])
        self.assertEqual(self.commands, [
            ["con", "up", "id", "Renamed profile"],
            ["dev", "wifi", "connect", "Test WiFi", "password", "replacement",
             "name", "Renamed profile"],
        ])
        self.assertIn("Saved activation failed", str(self.notifications))
        self.assertEqual(self.success_count, 1)

    def test_cancel_after_failure_does_not_reactivate(self):
        for known in (False, True):
            with self.subTest(known=known):
                answers = [None] if known else ["wrong-secret", None]
                self.assertEqual(self.exercise(answers, [result(4, stderr="Rejected")],
                                               known=known), 0)
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(self.success_count, 0)
                self.assertIn("Rejected", str(self.notifications))

    def test_repeated_failures_each_require_new_input(self):
        self.assertEqual(self.exercise(["first-secret", "second-secret", None], [
            result(4), result(4, stdout="Rejected first-secret and second-secret")]), 0)
        self.assertEqual(self.events, ["prompt", "connect", "prompt", "connect", "prompt"])
        self.assertNotIn("first-secret", str(self.notifications))
        self.assertNotIn("second-secret", str(self.notifications))
        self.assertIn("Rejected [redacted] and [redacted]", str(self.notifications))

    def test_open_failure_never_prompts(self):
        for known in (False, True):
            for security in ("--", "", "open"):
                with self.subTest(known=known, security=security):
                    self.assertEqual(self.exercise([], [result(10, stderr="No device")],
                                                   known=known, security=security), 10)
                    self.assertEqual(self.prompt_count, 0)
                    self.assertEqual(len(self.commands), 1)
                    self.assertEqual(self.success_count, 0)
                    self.assertIn("No device", str(self.notifications))

    def test_saved_success_does_not_prompt(self):
        self.assertEqual(self.exercise([], [result()], known=True), 0)
        self.assertEqual(self.prompt_count, 0)
        self.assertEqual(self.success_count, 1)

    def test_saved_timeout_prompts_then_succeeds(self):
        self.assertEqual(self.exercise(["replacement"], [
            subprocess.TimeoutExpired(["nmcli", "con", "up"], 45), result()],
            known=True), 0)
        self.assertEqual(self.events, ["connect", "prompt", "connect"])
        self.assertIn("Saved connection activation timed out", str(self.notifications))

    def test_timeout_can_retry_without_exception_leaking_password(self):
        self.assertEqual(self.exercise(["private-secret", "replacement"], [
            subprocess.TimeoutExpired(["nmcli", "password", "private-secret"], 60),
            result()]), 0)
        self.assertEqual(self.prompt_count, 2)
        self.assertIn("timed out", str(self.notifications))
        self.assertNotIn("private-secret", str(self.notifications))


class SelectionMappingTests(unittest.TestCase):
    def test_history_reordered_pick_connects_to_chosen_network(self):
        # Regression: tofi's history sort reorders lines, and --print-index
        # reported the sorted position, so picking a history-favored network
        # connected to whatever was first on stdin (the active one).
        active = wifi.Net("*", "xfinitywifi", "WPA2", 90, True, True)
        target = wifi.Net("", "borgorai 1G", "WPA2", 60, True)
        commands = []

        def run(cmd, *, input=None, timeout=20):
            if cmd[0] == "tofi":
                lines = input.rstrip("\n").split("\n")
                # Simulate tofi floating the history favorite to the top and
                # the user choosing it.
                return result(stdout=next(l for l in lines if "borgorai" in l))
            commands.append(cmd[1:])
            return result()

        with (patch.object(wifi, "run", side_effect=run),
              patch.object(wifi, "shutil_which", return_value=True),
              patch.object(wifi, "wifi_enabled", return_value=True),
              patch.object(wifi, "rescan_wifi"),
              patch.object(wifi.time, "sleep"),
              patch.object(wifi, "get_networks", return_value=(
                  [active, target],
                  {active.ssid: active.ssid, target.ssid: target.ssid})),
              patch.object(wifi, "wifi_history_file", return_value="/unused/history"),
              patch.dict(wifi.os.environ, {"WIFI_PICK_DUMP": ""}),
              patch.object(wifi, "notify"),
              patch.object(wifi, "trigger_captive_portal_check"),
              patch.object(wifi, "trigger_post_connect_verification")):
            self.assertEqual(wifi.main(), 0)
        self.assertEqual(commands, [["con", "up", "id", "borgorai 1G"]])

    def test_duplicate_display_lines_are_disambiguated(self):
        lines = wifi.unique_lines(["a", "b", "a"])
        self.assertEqual(len(set(lines)), 3)
        self.assertEqual(wifi.selected_index(lines[2], lines), 2)


if __name__ == "__main__":
    unittest.main()
