#!/usr/bin/env python3
"""Offline regressions for connectivity latency and conservative acceptance."""
import contextlib
import importlib.machinery
import importlib.util
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "files/bin/captive-portal-autoaccept"
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
        sess.get.return_value = response(status=204)
        self.assertTrue(portal.probe_online(sess))
        sess.get.assert_called_once_with(portal.PROD_PROBE_URL, timeout=(2, 2), allow_redirects=False)

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
            with portal.requests.Session() as sess, patch.object(portal, "PROD_PROBE_URL", base + "/probe"), patch.dict(os.environ, {"CAPTIVE_SKIP_NM": "1"}):
                self.assertEqual(portal.run_accept(sess, base + "/start"), 0)
            self.assertNotIn("/unnecessary", paths)
            self.assertEqual(paths.count("/accept"), 1)
            self.assertEqual(paths[-1], "/probe")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
