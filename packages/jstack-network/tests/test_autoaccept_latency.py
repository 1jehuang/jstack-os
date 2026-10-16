#!/usr/bin/env python3
"""Offline regressions for connectivity latency and conservative acceptance."""
import contextlib
import importlib.machinery
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "files/bin/captive-portal-autoaccept"
PUBLIC_SCRIPT = Path(os.environ.get("CAPTIVE_AUTOACCEPT_TEST_SCRIPT", str(SCRIPT)))
loader = importlib.machinery.SourceFileLoader("autoaccept_under_test", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
portal = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = portal
loader.exec_module(portal)


def response(url="http://portal/a", body="", history=None, status=200):
    return type("Response", (), {"url": url, "text": body, "history": history or [],
                                  "status_code": status, "headers": {}})()


class AutoacceptTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        portal._nm_status = (float("-inf"), "unknown")

    def test_direct_success_does_not_invoke_nm(self):
        with patch.object(portal, "probe_online", return_value=True), patch.object(portal, "nm_connectivity") as nm:
            self.assertTrue(portal.is_online(Mock()))
            nm.assert_not_called()

    def test_negative_cache_invalidates_after_submission(self):
        sess = Mock()
        sess.post.return_value = response()
        with patch.object(portal, "probe_online", side_effect=[False, True]) as probe, patch.object(portal, "nm_connectivity", return_value="portal"):
            self.assertFalse(portal.is_online(sess))
            self.assertFalse(portal.is_online(sess))
            self.assertEqual(probe.call_count, 1)
            portal.submit_candidate(sess, portal.Candidate("post", portal.PROD_PROBE_URL, {}, 1, "form"))
            self.assertTrue(portal.is_online(sess))
            self.assertEqual(probe.call_count, 2)

    def test_negative_cache_expires(self):
        sess = Mock()
        with patch.object(portal.time, "monotonic", return_value=10), patch.object(portal, "probe_online", return_value=False) as probe, patch.object(portal, "nm_connectivity", return_value="portal"):
            self.assertFalse(portal.is_online(sess))
            with patch.object(portal.time, "monotonic", return_value=12):
                self.assertFalse(portal.is_online(sess))
            self.assertEqual(probe.call_count, 2)

    def test_probe_uses_short_timeout_without_redirects(self):
        sess = Mock()
        with patch.object(portal.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "204\n")) as run:
            self.assertTrue(portal.probe_online(sess))
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[:2], ["curl", "--disable"])
        for flag, value in (("--max-time", "3"), ("--connect-timeout", "2"), ("--output", os.devnull), ("--url", portal.PROD_PROBE_URL)):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertNotIn("--location", command)
        self.assertNotIn("-L", command)
        self.assertEqual(kwargs["timeout"], 4)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        sess.get.assert_not_called()
        sess.close.assert_not_called()

    def test_probe_fails_closed_for_errors_redirects_and_missing_curl(self):
        for status, code in (("302\nhttp://portal/", 0), ("200\n", 0), ("204\nhttp://portal/", 0), ("204\n", 28), ("000\n", 6)):
            with self.subTest(status=status, code=code), patch.object(portal.subprocess, "run", return_value=subprocess.CompletedProcess([], code, status)):
                self.assertFalse(portal.probe_online())
        for failure in (FileNotFoundError("curl"), subprocess.TimeoutExpired("curl", 4)):
            err = io.StringIO()
            with patch.object(portal.subprocess, "run", side_effect=failure), contextlib.redirect_stderr(err):
                self.assertFalse(portal.probe_online())
            self.assertIn("probe start", err.getvalue())
            self.assertIn("probe end", err.getvalue())

    def test_stalled_resolver_child_is_killed_and_reaped(self):
        # A deterministic resolver stand-in, not a claim about which phase of
        # the real Stanford request stalled. Exercise the actual run timeout.
        real_run, real_popen = subprocess.run, subprocess.Popen
        children = []

        def popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def stalled_resolver(command, **kwargs):
            self.assertEqual(kwargs["timeout"], 4)
            kwargs["timeout"] = 0.2
            try:
                return real_run([sys.executable, "-c", "import socket,time; socket.getaddrinfo=lambda *a: time.sleep(30); print('resolver started', flush=True); socket.getaddrinfo('test.invalid',80)"], **kwargs)
            except subprocess.TimeoutExpired as exc:
                self.assertIn(b"resolver started", exc.output)
                raise

        err = io.StringIO()
        started = time.monotonic()
        with patch.object(portal.subprocess, "run", side_effect=stalled_resolver), patch.object(portal.subprocess, "Popen", side_effect=popen), contextlib.redirect_stderr(err):
            self.assertFalse(portal.probe_online())
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertLess(children[0].returncode, 0)
        self.assertIn("probe timeout", err.getvalue())
        self.assertIn("probe end", err.getvalue())

    def test_real_curl_stalled_body_has_absolute_deadline(self):
        release = threading.Event()
        state = {"online": False}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path == "/start":
                    # The portal navigation grants access. Only the first
                    # probe stalls, so total CLI latency measures one deadline.
                    state["online"] = True
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"no safe portal action")
                    return
                if state["online"]:
                    self.send_response(204)
                    self.end_headers()
                    return
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.send_header("Content-Length", "100000")
                self.end_headers()
                self.wfile.write(b"private response body")
                self.wfile.flush()
                release.wait(10)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        started = time.monotonic()
        try:
            env = dict(os.environ, CAPTIVE_SKIP_NM="1", CAPTIVE_PROBE_URL=base + "/probe", CAPTIVE_CANARY_URL=base + "/start")
            result = subprocess.run([str(PUBLIC_SCRIPT)], env=env, capture_output=True, text=True, timeout=8)
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertGreater(elapsed, 2.5)
            self.assertLess(elapsed, 5)
            self.assertIn("status=302 returncode=28", result.stderr)
            probe_end = re.search(r"probe end .* elapsed=([\d.]+)s", result.stderr)
            self.assertIsNotNone(probe_end, result.stderr)
            probe_elapsed = float(probe_end.group(1))
            self.assertGreater(probe_elapsed, 2.5)
            self.assertLess(probe_elapsed, 4.5)
            self.assertNotIn("private response body", result.stdout + result.stderr)
            print(f"REAL_CURL_DEADLINE script={PUBLIC_SCRIPT} elapsed={elapsed:.3f}s probe_elapsed={probe_elapsed:.3f}s")
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join()

    def test_failed_request_logs_elapsed_without_query_secrets(self):
        sess = Mock()
        sess.get.side_effect = RuntimeError("failure")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(RuntimeError):
            portal.timed_request(sess, "get", "http://portal/path?token=secret")
        self.assertIn("request start", err.getvalue())
        self.assertIn("request end", err.getvalue())
        self.assertIn("elapsed=", err.getvalue())
        self.assertNotIn("secret", err.getvalue())

    def test_cached_full_does_not_override_failed_probe(self):
        with patch.object(portal, "probe_online", return_value=False), patch.object(portal, "nm_connectivity", return_value="full"):
            self.assertFalse(portal.is_online(Mock()))

    def test_nm_status_is_cached_and_never_active(self):
        with patch.object(portal.time, "monotonic", return_value=10), patch.object(portal.subprocess, "check_output", return_value="portal\n") as call:
            self.assertEqual(portal.nm_connectivity(), "portal")
            self.assertEqual(portal.nm_connectivity(), "portal")
            call.assert_called_once_with(["nmcli", "-t", "networking", "connectivity"], text=True, timeout=1)
        with patch.object(portal.time, "monotonic", return_value=16), patch.object(portal.subprocess, "check_output", return_value="full") as call:
            self.assertEqual(portal.nm_connectivity(), "full")
            call.assert_called_once()

    def test_nm_timeout_is_cached(self):
        with patch.object(portal.subprocess, "check_output", side_effect=subprocess.TimeoutExpired("nmcli", 1)) as call:
            self.assertEqual(portal.nm_connectivity(), "unknown")
            self.assertEqual(portal.nm_connectivity(), "unknown")
            self.assertEqual(call.call_count, 1)

    def test_force_and_skip_controls(self):
        with patch.dict(os.environ, {"CAPTIVE_FORCE_ONLINE": "0"}), patch.object(portal, "probe_online") as probe:
            self.assertFalse(portal.is_online())
            probe.assert_not_called()
        with patch.dict(os.environ, {"CAPTIVE_SKIP_NM": "1"}), patch.object(portal, "probe_online", return_value=False), patch.object(portal, "nm_connectivity") as nm:
            self.assertFalse(portal.is_online())
            nm.assert_not_called()

    def test_submission_online_stops_before_redirect(self):
        candidate = portal.Candidate("post", "http://portal/accept", {}, 100, "form")
        sess = Mock()
        sess.post.return_value = response(body='<meta http-equiv="refresh" content="0;url=/marketing">')
        with patch.object(portal, "is_online", side_effect=[False, False, True]) as online, patch.object(portal, "fetch_portal", return_value=response()), patch.object(portal, "candidates_for", return_value=[candidate]), patch.object(portal, "follow_redirects") as follow:
            self.assertEqual(portal.run_accept(sess), 0)
            follow.assert_not_called()
            self.assertEqual(online.call_count, 3)
            sess.post.assert_called_once()
            sess.get.assert_not_called()

    def test_redirect_cycle_stops_before_revisit(self):
        start = response(body="<script>location='/b'</script>")
        sess = Mock()
        sess.get.return_value = response("http://portal/b", '<meta http-equiv="refresh" content="0;url=/a#again">')
        with patch.object(portal, "is_online", return_value=False):
            result = portal.follow_redirects(sess, start)
        self.assertEqual(result.url, "http://portal/b")
        sess.get.assert_called_once()

    def test_redirect_history_cycle(self):
        sess = Mock()
        start = response("http://portal/b", "<script>location='/a'</script>", [response()])
        self.assertIs(portal.follow_redirects(sess, start), start)
        sess.get.assert_not_called()

    def test_online_after_redirect_stops_further_navigation(self):
        sess = Mock()
        sess.get.return_value = response("http://portal/b", "<script>location='/c'</script>")
        with patch.object(portal, "is_online", return_value=True):
            portal.follow_redirects(sess, response(body="<script>location='/b'</script>"))
        sess.get.assert_called_once()

    def test_redirect_chain_is_still_bounded(self):
        sess = Mock()
        sess.get.side_effect = [response(f"http://portal/{n}", f"<script>location='/{n+1}'</script>") for n in range(1, 5)]
        with patch.object(portal, "is_online", return_value=False):
            portal.follow_redirects(sess, response(body="<script>location='/1'</script>"))
        self.assertEqual(sess.get.call_count, 4)

    def test_credential_payment_and_personal_fields_stay_refused(self):
        for field in ('<input type="password" name="secret">', '<input required name="credit_card">', '<input type="email" required name="email">', '<input required name="room">', '<input required name="voucher">'):
            with self.subTest(field=field):
                parser = portal.Parser()
                parser.feed(f'<form action="/accept">{field}<button>Accept and connect</button></form>')
                parser.close()
                self.assertIsNone(portal.build_submission(parser.forms[0], "http://portal/"))

    def test_timestamp_diagnostic_does_not_change_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            portal.diagnostic("test")
        self.assertEqual(out.getvalue(), "")
        self.assertRegex(err.getvalue(), r"^\d{4}-\d{2}-\d{2}T.*\+00:00 test\n$")

    def test_real_http_accept_skips_success_redirect_cycle(self):
        paths = []
        state = {"online": False}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                paths.append(self.path)
                if self.path == "/probe":
                    self.send_response(204 if state["online"] else 200)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<form method="post" action="/accept"><button>Accept and connect</button></form>')

            def do_POST(self):
                paths.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                state["online"] = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<script>location="/unnecessary"</script>')

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            env = dict(os.environ, CAPTIVE_SKIP_NM="1", CAPTIVE_PROBE_URL=base + "/probe", CAPTIVE_CANARY_URL=base + "/start")
            result = subprocess.run([str(PUBLIC_SCRIPT)], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("online after submit", result.stdout)
            self.assertIn("probe response", result.stderr)
            self.assertNotIn("/unnecessary", paths)
            self.assertEqual(paths.count("/accept"), 1)
            self.assertEqual(paths[-1], "/probe")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_public_script_real_curl_rejects_redirect_and_204_location(self):
        paths = []
        state = {"status": 302}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                paths.append(self.path)
                self.send_response(state["status"] if self.path == "/probe" else 200)
                if self.path == "/probe":
                    self.send_header("Location", "/must-not-follow?token=secret")
                self.end_headers()
                if self.path != "/probe" or state["status"] != 204:
                    self.wfile.write(b"no safe portal action")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with tempfile.TemporaryDirectory() as home:
                # Ignoring curlrc must prevent user-configured redirect following.
                Path(home, ".curlrc").write_text("location\n")
                env = dict(os.environ, CURL_HOME=home, CAPTIVE_SKIP_NM="1", CAPTIVE_PROBE_URL=base + "/probe", CAPTIVE_CANARY_URL=base + "/start")
                for status in (302, 204, 200):
                    state["status"] = status
                    paths.clear()
                    with self.subTest(status=status):
                        result = subprocess.run([str(PUBLIC_SCRIPT)], env=env, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertTrue(paths)
                        self.assertFalse(any(path.startswith("/must-not-follow") for path in paths))
                        self.assertNotIn("token=secret", result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
