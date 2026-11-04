"""Tests for OmaDeck mobile remote PIN lock and session security."""

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice.local_engine import get_provider_status
from omarchy_voice.mobile_bridge import (
    BridgeHandler,
    _PWA_HTML,
    _is_allowed_host,
    _dispatch,
    _type_text,
    _load_or_create_token,
    _save_token,
    TOKEN_FILE,
    _HISTORY,
    _HISTORY_LOCK,
)


class MobileBridgePinTests(unittest.TestCase):
    def setUp(self):
        from omarchy_voice.mobile_bridge import (
            _AUTH_FAILURES, _GLOBAL_AUTH_FAILURES, _AUTH_LOCK,
            _SESSION_TOKENS, _SESSION_LOCK,
        )
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
            _GLOBAL_AUTH_FAILURES.clear()
        with _SESSION_LOCK:
            _SESSION_TOKENS.clear()
        self.orig_pin = BridgeHandler.pin
        self.orig_token = BridgeHandler.token
        BridgeHandler.pin = "1234"
        BridgeHandler.token = "test-token-123"

        # Strictly isolate test suite from touching real host configuration files
        self.save_local_config_patch = mock.patch("omarchy_voice.local_engine.save_local_config")
        self.mock_save_local_config = self.save_local_config_patch.start()

        self.save_token_patch = mock.patch("omarchy_voice.mobile_bridge._save_token")
        self.mock_save_token = self.save_token_patch.start()

    def tearDown(self):
        from omarchy_voice.mobile_bridge import (
            _AUTH_FAILURES, _GLOBAL_AUTH_FAILURES, _AUTH_LOCK,
            _SESSION_TOKENS, _SESSION_LOCK,
        )
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
            _GLOBAL_AUTH_FAILURES.clear()
        with _SESSION_LOCK:
            _SESSION_TOKENS.clear()
        self.save_local_config_patch.stop()
        self.save_token_patch.stop()
        BridgeHandler.pin = self.orig_pin
        BridgeHandler.token = self.orig_token

    def _call_post(self, path: str, payload: dict, token: str | None = None, extra_headers: dict | None = None):
        if token is None:
            token = BridgeHandler.token
        body = json.dumps(payload).encode("utf-8")

        rfile = io.BytesIO(body)
        wfile = io.BytesIO()

        handler = BridgeHandler.__new__(BridgeHandler)
        handler.rfile = rfile
        handler.wfile = wfile
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Token": token,
            "Host": "127.0.0.1:8765",
        }
        if extra_headers:
            headers.update(extra_headers)
        handler.headers = headers
        handler.path = path
        handler.command = "POST"
        handler.requestline = f"POST {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.log_message = lambda *args: None

        handler.do_POST()

        wfile.seek(0)
        response_data = wfile.read()
        header_part, _, body_part = response_data.partition(b"\r\n\r\n")
        status_line = header_part.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        try:
            parsed_json = json.loads(body_part.decode("utf-8")) if body_part else {}
        except Exception:
            parsed_json = {}
        return status_line, parsed_json

    def test_provider_status_reports_pin_set(self):
        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"pin": "5678"}):
            status = get_provider_status()
            self.assertTrue(status.get("pin_set"))
            self.assertTrue(status.get("has_pin"))

        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"pin": ""}):
            status = get_provider_status()
            self.assertFalse(status.get("pin_set"))
            self.assertFalse(status.get("has_pin"))

    def test_auth_endpoint_validates_pin(self):
        # Correct PIN
        status_line, data = self._call_post("/auth", {"pin": "1234"}, token="")
        self.assertIn("200", status_line)
        self.assertTrue(data.get("ok"))
        session_tok = data.get("token")
        self.assertTrue(session_tok)
        # Verify the issued session token works for subsequent calls
        status_line2, data2 = self._call_post("/clear", {}, token=session_tok)
        self.assertIn("200", status_line2)
        self.assertTrue(data2.get("ok"))

        # Incorrect PIN
        status_line3, data3 = self._call_post("/auth", {"pin": "9999"}, token="")
        self.assertIn("401", status_line3)
        self.assertFalse(data3.get("ok"))
        self.assertEqual(data3.get("error"), "Incorrect PIN")

    def test_pin_endpoint_requires_auth(self):
        # Without valid token, /pin is rejected with 401
        status_line, data = self._call_post("/pin", {"action": "set", "pin": "4321"}, token="bad-token")
        self.assertIn("401", status_line)
        self.assertFalse(data.get("ok"))

    def test_set_pin_validates_length_and_digits(self):
        with mock.patch("omarchy_voice.local_engine.save_local_config") as mock_save:
            # Too short (< 4 digits)
            status_line, data = self._call_post("/pin", {"action": "set", "pin": "123"})
            self.assertIn("400", status_line)
            self.assertFalse(data.get("ok"))

            # Too long (> 8 digits)
            status_line, data = self._call_post("/pin", {"action": "set", "pin": "123456789"})
            self.assertIn("400", status_line)
            self.assertFalse(data.get("ok"))

            # Non-numeric
            status_line, data = self._call_post("/pin", {"action": "set", "pin": "abcd"})
            self.assertIn("400", status_line)
            self.assertFalse(data.get("ok"))

            mock_save.assert_not_called()

    def test_set_and_disable_pin(self):
        saved = {}

        def fake_save(d):
            saved.update(d)

        self.mock_save_local_config.side_effect = fake_save

        # Set new PIN rotates token and updates pin
        status_line, data = self._call_post("/pin", {"action": "set", "pin": "8765"})
        self.assertIn("200", status_line)
        self.assertTrue(data.get("ok"))
        self.assertTrue(data.get("pin_set"))
        self.assertIn("token", data)
        self.assertEqual(BridgeHandler.token, data["token"])
        self.assertEqual(BridgeHandler.pin, "8765")
        self.assertEqual(saved.get("pin"), "8765")
        self.mock_save_token.assert_called_with(data["token"])

        # Disable PIN clears pin but keeps existing token so paired devices are not stranded
        curr_token = BridgeHandler.token
        status_line, data = self._call_post("/pin", {"action": "disable"})
        self.assertIn("200", status_line)
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("pin_set"))
        self.assertEqual(data.get("token"), curr_token)
        self.assertEqual(BridgeHandler.token, curr_token)
        self.assertEqual(BridgeHandler.pin, "")
        self.assertEqual(saved.get("pin"), "")

    def test_pwa_html_contains_security_elements(self):
        self.assertIn("settings-panel-security", _PWA_HTML)
        self.assertIn("tab-security", _PWA_HTML)
        self.assertIn("pin-keypad", _PWA_HTML)
        self.assertIn("app-lock-btn", _PWA_HTML)
        self.assertIn("setting-autolock-app-switch", _PWA_HTML)
        self.assertIn("lockSession", _PWA_HTML)
        # Verify updateToken is called on PIN set/disable so client is not locked out
        self.assertIn("if (data.token) updateToken(data.token);", _PWA_HTML)

    def test_pin_rotation_persists_to_token_file(self):
        status_line, data = self._call_post("/pin", {"action": "set", "pin": "9999"})
        self.assertIn("200", status_line)
        new_tok = data.get("token")
        self.assertTrue(new_tok)
        self.mock_save_token.assert_called_with(new_tok)
        self.mock_save_local_config.assert_called_with({"pin": "9999"})

    def test_delete_mobile_token_generates_fresh_token(self):
        with mock.patch("omarchy_voice.mobile_bridge.TOKEN_FILE") as mock_token_file:
            mock_token_file.exists.return_value = False
            tok = _load_or_create_token()
            self.assertTrue(tok)
            self.mock_save_token.assert_called_with(tok)

    def test_is_allowed_host_validation(self):
        # Localhost and private LAN
        self.assertTrue(_is_allowed_host("localhost:8765"))
        self.assertTrue(_is_allowed_host("127.0.0.1:8765"))
        self.assertTrue(_is_allowed_host("192.168.1.100:8765"))
        self.assertTrue(_is_allowed_host("10.0.0.5:8765"))

        # Tailscale CGNAT IP (100.64.0.0/10)
        self.assertTrue(_is_allowed_host("100.80.1.2:8765"))
        self.assertTrue(_is_allowed_host("100.115.92.10:8765"))

        # Tailscale MagicDNS and mDNS domains
        self.assertTrue(_is_allowed_host("my-laptop.ts.net:8765"))
        self.assertTrue(_is_allowed_host("mymachine.tailscale.ts.net"))
        self.assertTrue(_is_allowed_host("myhost.local:8765"))

        # Public IPs and external domains must be rejected
        self.assertFalse(_is_allowed_host("8.8.8.8:8765"))
        self.assertFalse(_is_allowed_host("1.1.1.1"))
        self.assertFalse(_is_allowed_host("evil.com:8765"))
        self.assertFalse(_is_allowed_host("attacker.example.org"))

    def test_dispatch_timeout_does_not_execute_locally(self):
        import socket
        with mock.patch("omarchy_voice.mobile_bridge.send_control", side_effect=socket.timeout("timed out")):
            with mock.patch("omarchy_voice.mobile_bridge._local_think") as mock_local:
                reply = _dispatch("run a slow command")
                mock_local.assert_not_called()
                self.assertIn("timed out", reply)

    def test_type_text_allows_normal_words_and_code_buttons(self):
        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/wtype"):
            with mock.patch("omarchy_voice.mobile_bridge.subprocess.run") as mock_run:
                mock_run.return_value = mock.Mock(returncode=0, stderr="")
                # Normal chat text mentioning reboot or ssh
                ok, err = _type_text("Hey, did you reboot the ssh server?", enter=True)
                self.assertTrue(ok)
                self.assertEqual(err, "")

                # Code profile button "git push"
                ok2, err2 = _type_text("git push", enter=True)
                self.assertTrue(ok2)
                self.assertEqual(err2, "")

    def test_spoken_git_push_refused_while_button_push_allowed(self):
        with mock.patch("omarchy_voice.mobile_bridge._type_text", return_value=(True, "")) as mock_type:
            # Voice command "git push" is refused
            res_voice = _dispatch("git push", voice=True)
            self.assertIn("Refused by safety policy", res_voice)
            mock_type.assert_not_called()

            # Deck button click "git push" is permitted
            res_button = _dispatch("git push", voice=False)
            self.assertIn("Ran `git push` in active terminal", res_button)
            mock_type.assert_called_with("git push", enter=True)

    def test_auth_endpoint_rejects_cross_site_requests(self):
        # Sec-Fetch-Site: cross-site is rejected with 403
        status_line, _ = self._call_post(
            "/auth", {"pin": "1234"}, token="",
            extra_headers={"Sec-Fetch-Site": "cross-site"}
        )
        self.assertIn("403", status_line)

        # Mismatching Origin is rejected with 403
        status_line2, _ = self._call_post(
            "/auth", {"pin": "1234"}, token="",
            extra_headers={"Origin": "http://evil.com"}
        )
        self.assertIn("403", status_line2)

        # Origin: null is rejected with 403
        status_line_null, _ = self._call_post(
            "/auth", {"pin": "1234"}, token="",
            extra_headers={"Origin": "null"}
        )
        self.assertIn("403", status_line_null)

        # Same origin / matching Host is permitted
        status_line3, data3 = self._call_post(
            "/auth", {"pin": "1234"}, token="",
            extra_headers={"Origin": "http://127.0.0.1:8765"}
        )
        self.assertIn("200", status_line3)
        self.assertTrue(data3.get("ok"))

    def test_auth_rate_limit_lockout_after_five_attempts(self):
        from omarchy_voice.mobile_bridge import _AUTH_FAILURES, _AUTH_LOCK
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
        with mock.patch("time.sleep"):
            # 5 incorrect attempts
            for _ in range(5):
                status_line, data = self._call_post("/auth", {"pin": "wrong"}, token="")
                self.assertIn("401", status_line)
            # 6th attempt locked out with 429
            status_line6, data6 = self._call_post("/auth", {"pin": "wrong"}, token="")
            self.assertIn("429", status_line6)
            self.assertIn("Too many failed attempts", data6.get("error", ""))

    def test_parallel_auth_attempts_strictly_rate_limited(self):
        """Concurrent requests arriving in parallel cannot race past the 5-attempt rate limit."""
        import concurrent.futures

        # With 20 parallel attempts with a wrong PIN, exactly 5 must be evaluated (HTTP 401)
        # and the remaining 15 must be rejected with 429 Too Many Requests.
        def do_attempt():
            status_line, _ = self._call_post("/auth", {"pin": "wrong"}, token="")
            if "401" in status_line:
                return 401
            if "429" in status_line:
                return 429
            return 0

        with mock.patch("time.sleep", side_effect=lambda s: None):
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(do_attempt) for _ in range(20)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(results.count(401), 5)
        self.assertEqual(results.count(429), 15)

    def test_voice_endpoint_passes_voice_guard(self):
        with mock.patch("omarchy_voice.mobile_bridge._transcribe_wav", return_value="git push"):
            status_line, data = self._call_post(
                "/voice", {"audio_b64": "UklGRg=="}
            )
            self.assertIn("200", status_line)
            self.assertIn("Refused by safety policy", data.get("reply", ""))

    def test_voice_endpoint_allows_audio_larger_than_json_body_limit(self):
        # 200 KB audio payload (> 128 KB JSON limit) should not return 413
        large_audio = "A" * (200 * 1024)
        with mock.patch("omarchy_voice.mobile_bridge._transcribe_wav", return_value="hello"):
            with mock.patch("omarchy_voice.mobile_bridge._dispatch", return_value="hi"):
                status_line, data = self._call_post("/voice", {"audio_b64": large_audio})
                self.assertNotIn("413", status_line)
                self.assertIn("200", status_line)

    def test_unauthenticated_audio_rejected_before_processing(self):
        status_line, data = self._call_post("/voice", {"audio_b64": "AAAA"}, token="wrong-token")
        self.assertIn("401", status_line)
        self.assertEqual(data.get("error"), "unauthorized")

    def test_why_did_you_kill_port_does_not_kill_port(self):
        with mock.patch("subprocess.run") as mock_sub:
            res = _dispatch("why did you kill 3000")
            # Should not call fuser on 3000/tcp
            called_cmds = [call.args[0] for call in mock_sub.call_args_list if call.args]
            self.assertFalse(any("3000/tcp" in cmd for cmd in called_cmds))

            res2 = _dispatch("kill port 3000")
            self.assertIn("Killed processes on port 3000", res2)

    def test_global_auth_rate_limit_lockout(self):
        from omarchy_voice.mobile_bridge import _AUTH_FAILURES, _GLOBAL_AUTH_FAILURES, _AUTH_LOCK
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
            _GLOBAL_AUTH_FAILURES.clear()

        # Simulate 15 failed attempts across different IP addresses
        with mock.patch("time.sleep"):
            for i in range(15):
                handler = BridgeHandler.__new__(BridgeHandler)
                handler.client_address = (f"10.0.0.{i+1}", 12345)
                handler.rfile = io.BytesIO(b'{"pin":"wrong"}')
                handler.wfile = io.BytesIO()
                handler.headers = {"Content-Type": "application/json", "Content-Length": "15", "Host": "127.0.0.1:8765"}
                handler.path = "/auth"
                handler.command = "POST"
                handler.requestline = "POST /auth HTTP/1.1"
                handler.request_version = "HTTP/1.1"
                handler.log_message = lambda *args: None
                handler.do_POST()

            # 16th attempt from a brand-new IP address should be blocked by global limit (429)
            handler = BridgeHandler.__new__(BridgeHandler)
            handler.client_address = ("10.0.1.99", 12345)
            handler.rfile = io.BytesIO(b'{"pin":"wrong"}')
            handler.wfile = io.BytesIO()
            handler.headers = {"Content-Type": "application/json", "Content-Length": "15", "Host": "127.0.0.1:8765"}
            handler.path = "/auth"
            handler.command = "POST"
            handler.requestline = "POST /auth HTTP/1.1"
            handler.request_version = "HTTP/1.1"
            handler.log_message = lambda *args: None
            handler.do_POST()

            handler.wfile.seek(0)
            resp = handler.wfile.read()
            self.assertIn(b"429", resp)
            self.assertIn(b"globally", resp)


if __name__ == "__main__":
    unittest.main()
