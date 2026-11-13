"""Tests for OmaDeck mobile remote PIN lock and session security."""

import contextlib
import io
import json
import ssl
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice.local_engine import get_provider_status
from omarchy_voice.mobile_bridge import (
    BridgeHandler,
    _PWA_HTML,
    _press_key,
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

        # Commands write to session.log; keep that out of the real home.
        self.log_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.log_dir.name) / "session.log"
        self.log_patch = mock.patch("omarchy_voice.feedback.LOG_FILE", self.log_file)
        self.log_patch.start()

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
        self.log_patch.stop()
        self.log_dir.cleanup()
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

    def _call_get(self, path: str, token: str | None = None, extra_headers: dict | None = None):
        if token is None:
            token = BridgeHandler.token
        wfile = io.BytesIO()
        handler = BridgeHandler.__new__(BridgeHandler)
        handler.rfile = io.BytesIO()
        handler.wfile = wfile
        headers = {
            "X-Token": token,
            "Host": "127.0.0.1:8765",
        }
        if extra_headers:
            headers.update(extra_headers)
        handler.headers = headers
        handler.path = path
        handler.command = "GET"
        handler.requestline = f"GET {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.log_message = lambda *args: None

        handler.do_GET()

        wfile.seek(0)
        response_data = wfile.read()
        header_part, _, body_part = response_data.partition(b"\r\n\r\n")
        status_line = header_part.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        try:
            parsed_json = json.loads(body_part.decode("utf-8")) if body_part else {}
        except Exception:
            parsed_json = {}
        return status_line, parsed_json

    def _get_bytes(self, path: str) -> tuple[str, bytes]:
        """GET `path` without a token; return (status line, body bytes)."""
        wfile = io.BytesIO()
        handler = BridgeHandler.__new__(BridgeHandler)
        handler.rfile = io.BytesIO()
        handler.wfile = wfile
        handler.headers = {"Host": "127.0.0.1:8765"}
        handler.path = path
        handler.command = "GET"
        handler.requestline = f"GET {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.log_message = lambda *args: None
        handler.do_GET()
        head, _, body = wfile.getvalue().partition(b"\r\n\r\n")
        return head.split(b"\r\n")[0].decode(), body

    def test_the_logo_is_served_at_every_icon_size(self):
        import struct
        from omarchy_voice.mobile_bridge import ASSETS_DIR
        sizes = {"/icon.png": 192, "/icon-192.png": 192, "/icon-512.png": 512,
                 "/icon-maskable-512.png": 512, "/apple-touch-icon.png": 180,
                 "/favicon.ico": 192}
        for path, size in sizes.items():
            status, body = self._get_bytes(path)
            self.assertIn("200", status, path)
            self.assertEqual(body[:8], b"\x89PNG\r\n\x1a\n", path)
            width, height = struct.unpack(">II", body[16:24])
            self.assertEqual((width, height), (size, size), path)
        # The real logo, not the generated fallback circle.
        _, body = self._get_bytes("/icon-512.png")
        self.assertEqual(body, (ASSETS_DIR / "icon-512.png").read_bytes())

    def test_the_manifest_lists_any_and_maskable_icons(self):
        from omarchy_voice.mobile_bridge import ICON_FILES, _manifest_json
        icons = json.loads(_manifest_json("/"))["icons"]
        self.assertEqual({i["purpose"] for i in icons}, {"any", "maskable"})
        for icon in icons:
            self.assertIn(icon["src"], ICON_FILES)
        self.assertIn('rel="apple-touch-icon" href="/apple-touch-icon.png"', _PWA_HTML)

    def _start_url(self, path: str) -> str:
        return json.loads(self._page(path).partition("\r\n\r\n")[2])["start_url"]

    def _page(self, path: str) -> str:
        wfile = io.BytesIO()
        handler = BridgeHandler.__new__(BridgeHandler)
        handler.wfile = wfile
        handler.headers = {"Host": "127.0.0.1:8765"}
        handler.path = path
        handler.command = "GET"
        handler.requestline = f"GET {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.do_GET()
        return wfile.getvalue().decode("utf-8")

    def test_manifest_hands_the_token_to_the_home_screen_app(self):
        BridgeHandler.pin = ""
        self.assertEqual(self._start_url("/manifest.webmanifest?token=test-token-123"), "/#token=test-token-123")
        self.assertIn('href="/manifest.webmanifest?token=test-token-123"', self._page("/?token=test-token-123"))

    def test_manifest_keeps_the_token_without_a_valid_request(self):
        BridgeHandler.pin = ""
        for path in ("/manifest.webmanifest", "/manifest.webmanifest?token=wrong", "/manifest.webmanifest?token=%C3%A9"):
            self.assertEqual(self._start_url(path), "/")
        for path in ("/", "/?token=wrong"):
            self.assertNotIn("test-token-123", self._page(path))

    def test_manifest_keeps_the_token_when_a_pin_is_set(self):
        self.assertEqual(self._start_url("/manifest.webmanifest?token=test-token-123"), "/")
        self.assertNotIn("test-token-123", self._page("/?token=test-token-123"))

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
        # Patch kill_port itself: it finds listeners with ss where ss exists
        # (Linux, CI) and fuser elsewhere, so mocking either command alone
        # passed on one platform and failed on the other.
        with mock.patch("omarchy_voice.mobile_bridge.kill_port",
                        return_value="Killed python3 on port 3000.") as kp, \
             mock.patch("omarchy_voice.mobile_bridge.send_control",
                        return_value="I stopped it because you asked."):
            _dispatch("why did you kill 3000")
            kp.assert_not_called()

            res2 = _dispatch("kill port 3000")
        kp.assert_called_once_with(3000)
        self.assertEqual(res2, "Killed python3 on port 3000.")

    def test_global_auth_rate_limit_lockout(self):
        from omarchy_voice.mobile_bridge import _AUTH_FAILURES, _GLOBAL_AUTH_FAILURES, _AUTH_LOCK, MAX_GLOBAL_AUTH_FAILURES
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
            _GLOBAL_AUTH_FAILURES.clear()

        # Simulate MAX_GLOBAL_AUTH_FAILURES failed attempts across different IP addresses
        with mock.patch("time.sleep"):
            for i in range(MAX_GLOBAL_AUTH_FAILURES):
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

            # Next attempt from a brand-new IP address should be blocked by global limit (429)
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

    def test_successful_auth_does_not_consume_global_failure_allowance(self):
        from omarchy_voice.mobile_bridge import _AUTH_FAILURES, _GLOBAL_AUTH_FAILURES, _AUTH_LOCK
        with _AUTH_LOCK:
            _AUTH_FAILURES.clear()
            _GLOBAL_AUTH_FAILURES.clear()

        with mock.patch("time.sleep"):
            # 10 successful auths across different IPs
            for i in range(10):
                status, data = self._call_post("/auth", {"pin": "1234"}, token="")
                self.assertIn("200", status)
                self.assertTrue(data.get("ok"))

            # Global failure list must be completely empty
            with _AUTH_LOCK:
                self.assertEqual(len(_GLOBAL_AUTH_FAILURES), 0)

    def test_pin_session_token_requires_current_pin(self):
        # 1. Login with correct PIN to obtain session token
        status, data = self._call_post("/auth", {"pin": "1234"}, token="")
        self.assertIn("200", status)
        session_token = data["token"]

        # 2. Try disabling PIN using session token without current_pin -> must fail 403
        status_dis, data_dis = self._call_post("/pin", {"action": "disable"}, token=session_token)
        self.assertIn("403", status_dis)
        self.assertIn("Current PIN is required", data_dis.get("error", ""))

        # 3. Try disabling PIN with wrong current_pin -> must fail 403
        status_dis_wrong, _ = self._call_post("/pin", {"action": "disable", "current_pin": "9999"}, token=session_token)
        self.assertIn("403", status_dis_wrong)

        # 4. Try setting new PIN using session token without current_pin -> must fail 403
        status_set, data_set = self._call_post("/pin", {"action": "set", "pin": "5678"}, token=session_token)
        self.assertIn("403", status_set)
        self.assertIn("Current PIN is required", data_set.get("error", ""))

        # 5. Setting new PIN with valid current_pin succeeds, but does NOT rotate master token
        orig_master = BridgeHandler.token
        status_set_ok, data_set_ok = self._call_post("/pin", {"action": "set", "pin": "5678", "current_pin": "1234"}, token=session_token)
        self.assertIn("200", status_set_ok)
        self.assertTrue(data_set_ok.get("ok"))
        self.assertEqual(BridgeHandler.token, orig_master)
        self.assertNotIn("token", data_set_ok)

        # Re-authenticate with new PIN "5678" because old session tokens were revoked
        status_reauth, data_reauth = self._call_post("/auth", {"pin": "5678"}, token="")
        self.assertIn("200", status_reauth)
        new_session_token = data_reauth["token"]

        # 6. Disabling PIN with valid current_pin succeeds, but does NOT return master token to session token
        status_dis_ok, data_dis_ok = self._call_post("/pin", {"action": "disable", "current_pin": "5678"}, token=new_session_token)
        self.assertIn("200", status_dis_ok)
        self.assertTrue(data_dis_ok.get("ok"))
        self.assertNotIn("token", data_dis_ok)

        # 7. Crucial check: phone session is NOT cut off after disabling PIN!
        status_state, data_state = self._call_get("/state", token=new_session_token)
        self.assertIn("200", status_state)

    def test_denylist_catches_all_interpreter_and_pipe_bypasses(self):
        from omarchy_voice.config import DEFAULT_DENY, DEFAULT_SHELL_DENY
        import re

        bypasses = [
            'bash -c "echo hi"',
            'sh -c whoami',
            'perl -e "print 1"',
            'ruby -e "puts 1"',
            'node -e "console.log(1)"',
            'node --eval "console.log(1)"',
            'python3.11 -c "import os"',
            'python3 -u -c "print(1)"',
            'bash <(curl x)',
            'eval "$(curl x)"',
            'curl x -o y; sh y',
            'curl x | node',
            'xxd -r p | sh',
        ]
        for cmd in bypasses:
            matched = any(re.search(pat, cmd, re.IGNORECASE)
                          for pat in [*DEFAULT_DENY, *DEFAULT_SHELL_DENY])
            self.assertTrue(matched, f"Denylist failed to catch: {cmd}")

    def test_terminal_enter_blocked_when_allow_shell_is_false(self):
        from omarchy_voice.config import Config
        from omarchy_voice.tools import Executor

        cfg = Config(allow_shell=False)
        executor = Executor(cfg)

        with mock.patch.object(executor, "_is_terminal_window", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/wtype"):
            res = executor.call("send_shortcut", {"mods": "", "key": "Return", "window": "activewindow"})
            self.assertFalse(res.ok)
            self.assertIn("terminal", res.output.lower())

            res2 = executor.call("type_text", {"text": "whoami\n"})
            self.assertFalse(res2.ok)
            self.assertIn("terminal", res2.output.lower())

    def test_current_pin_on_pin_endpoint_is_rate_limited(self):
        # Set a PIN
        BridgeHandler.pin = "1234"
        # Authenticate with session token
        status_auth, data_auth = self._call_post("/auth", {"pin": "1234"}, token="")
        session_token = data_auth["token"]

        with mock.patch("time.sleep"):
            # 5 failed attempts with wrong current_pin
            for _ in range(5):
                status, data = self._call_post(
                    "/pin",
                    {"action": "set", "pin": "9999", "current_pin": "0000"},
                    token=session_token,
                )
                self.assertIn("403", status)

            # 6th attempt should be rate-limited with 429
            status, data = self._call_post(
                "/pin",
                {"action": "set", "pin": "9999", "current_pin": "0000"},
                token=session_token,
            )
            self.assertIn("429", status)
            self.assertIn("Too many failed attempts", data.get("error", ""))

    def _plain_http_status(self, path, client_ip, tls_context=object(), connection=None):
        handler = BridgeHandler.__new__(BridgeHandler)
        handler.server = SimpleNamespace(tls_context=tls_context, server_name="")
        handler.connection = connection if connection is not None else object()
        handler.client_address = (client_ip, 12345)
        handler.https_url = "https://192.168.1.50:8765"
        body = b'{"pin":"1234"}'
        handler.rfile = io.BytesIO(body)
        handler.wfile = io.BytesIO()
        handler.headers = {"Content-Type": "application/json",
                           "Content-Length": str(len(body)),
                           "X-Token": BridgeHandler.token,
                           "Host": "127.0.0.1:8765"}
        handler.path = path
        handler.command = "POST"
        handler.requestline = f"POST {path} HTTP/1.1"
        handler.request_version = "HTTP/1.1"
        handler.log_message = lambda *args: None
        with mock.patch("time.sleep"):
            handler.do_POST()
        return handler.wfile.getvalue().split(b"\r\n", 1)[0].decode()

    def test_secrets_are_refused_over_plain_http_when_https_is_available(self):
        for path in ("/auth", "/pin", "/settings"):
            with self.subTest(path=path):
                self.assertIn("426", self._plain_http_status(path, "192.168.1.20"))

    def test_plain_http_refusal_has_the_right_exceptions(self):
        # Ordinary touch control keeps working, for phones without the CA.
        self.assertIn("200", self._plain_http_status("/clear", "192.168.1.20"))
        # Already private transports.
        self.assertIn("200", self._plain_http_status("/auth", "127.0.0.1"))
        self.assertIn("200", self._plain_http_status("/auth", "100.100.1.1"))
        # Nothing better to offer when HTTPS could not start.
        self.assertIn("200", self._plain_http_status("/auth", "192.168.1.20", tls_context=None))
        # Already encrypted.
        tls = mock.MagicMock(spec=ssl.SSLSocket)
        self.assertIn("200", self._plain_http_status("/auth", "192.168.1.20", connection=tls))

    def test_pairing_link_shows_in_a_terminal_started_from_a_systemd_session(self):
        from omarchy_voice.mobile_bridge import _can_show_pairing_link
        inherited = {"JOURNAL_STREAM": "8:1234", "INVOCATION_ID": "abc123"}
        with mock.patch.dict("os.environ", inherited), mock.patch("sys.stdout") as stdout:
            stdout.isatty.return_value = True
            self.assertTrue(_can_show_pairing_link())
            stdout.isatty.return_value = False
            self.assertFalse(_can_show_pairing_link())

    def _logged(self) -> str:
        return self.log_file.read_text() if self.log_file.exists() else ""

    def test_a_phone_button_is_logged_with_its_reply(self):
        with mock.patch("omarchy_voice.mobile_bridge._quick_command", return_value="Killed processes on port 3000."):
            _dispatch("kill port 3000")
        self.assertIn("phone   kill port 3000 -> Killed processes on port 3000.", self._logged())

    def test_a_daemon_timeout_is_logged(self):
        with mock.patch("omarchy_voice.mobile_bridge._quick_command", return_value=None),              mock.patch("omarchy_voice.mobile_bridge.send_control", side_effect=TimeoutError):
            _dispatch("open the news")
        self.assertIn("error   phone open the news: [command timed out", self._logged())

    def test_the_phone_waits_for_a_slow_model(self):
        from omarchy_voice.mobile_bridge import DAEMON_REPLY_TIMEOUT
        with mock.patch("omarchy_voice.mobile_bridge._quick_command", return_value=None), \
             mock.patch("omarchy_voice.mobile_bridge.send_control",
                        return_value="Done.") as send:
            _dispatch("open the news")
        self.assertGreaterEqual(DAEMON_REPLY_TIMEOUT, 30)
        self.assertEqual(send.call_args.kwargs["timeout"], DAEMON_REPLY_TIMEOUT)

    def test_open_chrome_on_a_workspace_skips_the_model(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor, Result
        with mock.patch.object(Executor, "call",
                               return_value=Result(True, "opened on workspace 5")) as call:
            reply = _quick_command("Open new chrome window in workspace five.")
        self.assertEqual(reply, "Opened Chrome on workspace 5.")
        call.assert_called_once_with("launch_app", {"app": "google-chrome:new-window",
                                                    "workspace": "5"})

    def test_open_a_known_app_on_a_workspace_moves_its_window(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor, Result
        with mock.patch.object(Executor, "call", return_value=Result(True, "")), \
             mock.patch.object(Executor, "window_addresses", return_value={"0x1"}), \
             mock.patch.object(Executor, "place_new_window",
                               return_value=Result(True, "opened on workspace 3")) as place:
            reply = _quick_command("open files on workspace 3")
        self.assertEqual(reply, "Opened Files on workspace 3.")
        self.assertEqual(place.call_args.args, ({"0x1"}, "3"))

    def test_an_unknown_app_on_a_workspace_goes_to_the_model(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor
        with mock.patch.object(Executor, "window_addresses", return_value=set()), \
             mock.patch.object(Executor, "place_new_window") as place, \
             mock.patch("omarchy_voice.tools.find_desktop_app", return_value=None):
            reply = _quick_command("open blender on workspace 2")
        self.assertIsNone(reply)
        place.assert_not_called()

    def test_an_installed_app_on_a_workspace_skips_the_model(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor, Result
        with mock.patch.object(Executor, "window_addresses", return_value=set()), \
             mock.patch("omarchy_voice.tools.find_desktop_app",
                        return_value=("com.obsproject.Studio", "OBS Studio")), \
             mock.patch.object(Executor, "call",
                               return_value=Result(True, "opened on workspace 2")) as call:
            reply = _quick_command("Open OBS Studio on workspace two.")
        self.assertEqual(reply, "Opened OBS Studio on workspace 2.")
        call.assert_called_once_with("launch_app", {"app": "com.obsproject.Studio",
                                                    "workspace": "2"})

    def test_a_menu_is_not_sent_to_a_workspace(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor
        with mock.patch.object(Executor, "call") as call:
            reply = _quick_command("open the launcher on workspace 3")
        self.assertIn("isn't a window", reply)
        call.assert_not_called()

    def test_a_failed_key_is_logged_with_its_error(self):
        with mock.patch("omarchy_voice.mobile_bridge._press_key", return_value=(False, "no keymap")):
            self._call_post("/type", {"key": "ctrl+c"}, token="test-token-123")
        self.assertIn("error   key ctrl+c: no keymap", self._logged())

    def test_typed_text_never_reaches_the_log(self):
        with mock.patch("omarchy_voice.mobile_bridge._type_text", return_value=(False, "wtype failed")):
            self._call_post("/type", {"text": "hunter2"}, token="test-token-123")
        logged = self._logged()
        self.assertIn("error   typing: wtype failed", logged)
        self.assertNotIn("hunter2", logged)

    def test_code_profile_has_a_ctrl_z_key(self):
        self.assertIn('data-key="ctrl+z"', _PWA_HTML)
        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/wtype"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                        return_value=SimpleNamespace(returncode=0, stderr="", stdout="")) as run:
            ok, _ = _press_key("ctrl+z")
        self.assertTrue(ok)
        sent = run.call_args.args[0]
        self.assertEqual(sent[:5], ["wtype", "-M", "ctrl", "-k", "z"])

    def _press_in(self, key, window_class, title="", vim=False, hypr_ok=True):
        """Press `key` with a window focused; return everything sent to it."""
        sent = []

        def fake_run(argv, **kwargs):
            if argv[:3] == ["hyprctl", "-j", "activewindow"]:
                body = (json.dumps({"class": window_class, "title": title, "pid": 100})
                        if window_class else "")
                return SimpleNamespace(returncode=0, stdout=body, stderr="")
            sent.append(argv)
            if argv[:2] == ["hyprctl", "dispatch"] and not hypr_ok:
                return SimpleNamespace(returncode=1, stdout="", stderr="no")
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/x"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run", side_effect=fake_run), \
             mock.patch("omarchy_voice.mobile_bridge._terminal_runs_vim", return_value=vim):
            ok, err = _press_key(key)
        return ok, err, sent

    def test_copy_in_a_terminal_never_sends_ctrl_c(self):
        ok, _, sent = self._press_in("copy", "Alacritty")
        self.assertTrue(ok)
        self.assertEqual(sent[0], ["wtype", "-M", "ctrl", "-M", "shift", "-k", "c",
                                   "-m", "shift", "-m", "ctrl"])

    def test_app_shortcuts_go_through_hyprland(self):
        # VS Code ignored Ctrl+A from wtype; Hyprland delivers it to the window.
        for key, letter in (("select_all", "a"), ("copy", "c"), ("paste", "v")):
            ok, _, sent = self._press_in(key, "code")
            self.assertTrue(ok)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0][:2], ["hyprctl", "dispatch"])
            self.assertIn('mods = "ctrl"', sent[0][2])
            self.assertIn(f'key = "{letter}"', sent[0][2])

    def test_app_shortcuts_fall_back_to_wtype(self):
        _, _, sent = self._press_in("select_all", "code", hypr_ok=False)
        self.assertEqual(sent[1][:5], ["wtype", "-M", "ctrl", "-k", "a"])

    def test_paste_in_a_terminal_uses_ctrl_shift_v(self):
        _, _, sent = self._press_in("paste", "foot")
        self.assertIn("shift", sent[0])
        self.assertEqual(sent[0][sent[0].index("-k") + 1], "v")

    def test_copy_is_refused_when_the_window_is_unknown(self):
        ok, err, sent = self._press_in("copy", None)
        self.assertFalse(ok)
        self.assertIn("Copy was not sent", err)
        self.assertEqual(sent, [])

    def test_select_all_in_neovim_selects_every_line(self):
        ok, _, sent = self._press_in("select_all", "Alacritty", vim=True)
        self.assertTrue(ok)
        self.assertEqual(sent[0][:3], ["wtype", "-k", "Escape"])
        self.assertEqual(sent[1], ["wtype", "--", "ggVG"])

    def test_copy_in_neovim_yanks_to_the_system_clipboard(self):
        _, _, sent = self._press_in("copy", "Alacritty", vim=True)
        self.assertEqual(sent, [["wtype", "--", '"+y']])

    def test_select_all_in_a_shell_presses_nothing(self):
        ok, err, sent = self._press_in("select_all", "Alacritty")
        self.assertFalse(ok)
        self.assertIn("nothing to select", err)
        self.assertEqual(sent, [])

    def test_vim_is_recognised_from_the_title_or_its_process(self):
        from omarchy_voice.mobile_bridge import _terminal_runs_vim
        self.assertTrue(_terminal_runs_vim({"title": "nvim ~/notes.md", "pid": 1}))
        self.assertTrue(_terminal_runs_vim({"title": "notes.md - NVIM", "pid": 1}))
        self.assertFalse(_terminal_runs_vim({"title": "vivid colours", "pid": 1}))
        tree = {100: [(200, "bash")], 200: [(300, "nvim")]}
        with mock.patch("omarchy_voice.mobile_bridge._process_children", return_value=tree):
            self.assertTrue(_terminal_runs_vim({"title": "~", "pid": 100}))
        # A terminal server with several windows: another window's nvim proves nothing.
        server = {100: [(200, "bash"), (201, "bash")], 201: [(300, "nvim")]}
        with mock.patch("omarchy_voice.mobile_bridge._process_children", return_value=server):
            self.assertFalse(_terminal_runs_vim({"title": "~", "pid": 100}))

    def test_key_row_has_select_all_copy_and_paste(self):
        for key in ("enter", "backspace", "tab", "escape", "select_all", "copy", "paste"):
            self.assertIn(f'data-key="{key}"', _PWA_HTML)

    def test_key_row_has_arrow_keys_that_repeat_when_held(self):
        for key in ("left", "up", "down", "right"):
            self.assertIn(f'data-key="{key}" data-repeat', _PWA_HTML)
        # The plain click handler skips them, or a tap would press twice.
        self.assertIn(".key-chip[data-key]:not([data-repeat])", _PWA_HTML)
        self.assertIn("stopKeyRepeat", _PWA_HTML)

    def test_arrow_keys_press_the_real_keysyms(self):
        for key, keysym in (("left", "Left"), ("up", "Up"), ("down", "Down"), ("right", "Right")):
            with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/wtype"), \
                 mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                            return_value=SimpleNamespace(returncode=0, stderr="", stdout="")) as run:
                ok, _ = _press_key(key)
            self.assertTrue(ok, key)
            self.assertEqual(run.call_args.args[0][:3], ["wtype", "-k", keysym])

    def test_press_key_falls_back_to_hyprctl_when_wtype_fails(self):
        def fake_which(cmd):
            return "/usr/bin/hyprctl" if cmd == "hyprctl" else None

        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", side_effect=fake_which), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                        return_value=SimpleNamespace(returncode=0, stderr="", stdout="ok")) as run:
            ok, err = _press_key("ctrl+c")
        self.assertTrue(ok)
        sent = run.call_args.args[0]
        self.assertEqual(sent[0], "hyprctl")
        self.assertEqual(sent[1], "dispatch")
        self.assertIn('hl.dsp.send_shortcut', sent[2])
        self.assertIn('mods = "ctrl"', sent[2])
        self.assertIn('key = "c"', sent[2])

    # `ss -Hltnp` lines: python's http.server listens on [::] (IPv6), which
    # fuser missed, so the port was reported free while the server ran.
    SS_PYTHON = ('LISTEN 0 5 *:3000 *:* users:(("python3",pid=4242,fd=3))\n')
    SS_ROOT = 'LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*\n'

    def _kill(self, ss_outputs, kill_side_effect=None):
        from omarchy_voice.mobile_bridge import kill_port
        outputs = iter(ss_outputs)

        def fake_run(argv, **kwargs):
            self.assertEqual(argv[0], "ss")
            return SimpleNamespace(returncode=0, stdout=next(outputs, ""), stderr="")

        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/ss"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run", side_effect=fake_run), \
             mock.patch("omarchy_voice.mobile_bridge.os.kill",
                        side_effect=kill_side_effect) as kill, \
             mock.patch("omarchy_voice.mobile_bridge.time.sleep"):
            return kill_port(3000), kill

    def test_kill_port_finds_an_ipv6_python_server(self):
        import signal
        reply, kill = self._kill([self.SS_PYTHON, ""])
        self.assertEqual(reply, "Killed python3 on port 3000.")
        kill.assert_called_once_with(4242, signal.SIGTERM)

    def test_kill_port_with_nothing_listening(self):
        reply, kill = self._kill([""])
        self.assertEqual(reply, "No process was listening on port 3000.")
        kill.assert_not_called()

    def test_kill_port_escalates_when_the_server_ignores_sigterm(self):
        import signal
        # Still listening after SIGTERM and every re-check, then gone.
        reply, kill = self._kill([self.SS_PYTHON] * 11 + [""])
        self.assertEqual(reply, "Killed python3 on port 3000.")
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(kill.call_args_list[-1].args,
                         (4242, getattr(signal, "SIGKILL", signal.SIGTERM)))

    def test_kill_port_says_so_when_the_port_stays_busy(self):
        reply, _ = self._kill([self.SS_PYTHON] * 20)
        self.assertIn("still listening", reply)

    def test_kill_port_owned_by_another_user_is_explained(self):
        from omarchy_voice.mobile_bridge import kill_port
        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/ss"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                        return_value=SimpleNamespace(returncode=0, stdout=self.SS_ROOT,
                                                     stderr="")), \
             mock.patch("omarchy_voice.mobile_bridge.os.kill") as kill:
            reply = kill_port(3000, hand_off=False)
        self.assertIn("another user's process", reply)
        kill.assert_not_called()

    def _hidden(self, ss_after):
        """Kill a port whose process the sandbox hides, via a fake Hyprland."""
        from omarchy_voice.mobile_bridge import kill_port
        ss_outputs = iter([self.SS_ROOT] + ss_after)
        evals = []

        def fake_run(argv, **kwargs):
            if argv[0] == "hyprctl":
                evals.append(argv)
                return SimpleNamespace(returncode=0, stdout="ok", stderr="")
            return SimpleNamespace(returncode=0, stdout=next(ss_outputs, self.SS_ROOT),
                                   stderr="")

        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value="/usr/bin/x"), \
             mock.patch("omarchy_voice.mobile_bridge._launcher",
                        return_value="/home/u/.local/share/omarchy-voice/bin/omarchy-voice"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run", side_effect=fake_run), \
             mock.patch("omarchy_voice.mobile_bridge.os.kill") as kill, \
             mock.patch("omarchy_voice.mobile_bridge.time.sleep"):
            reply = kill_port(3000)
        kill.assert_not_called()  # the kill happens in the helper Hyprland starts
        return reply, evals

    def test_a_hidden_process_is_killed_through_hyprland(self):
        reply, evals = self._hidden([self.SS_ROOT, ""])
        self.assertEqual(reply, "Killed the process on port 3000.")
        self.assertEqual(len(evals), 1)
        self.assertEqual(evals[0][:2], ["hyprctl", "eval"])
        self.assertEqual(evals[0][2], 'hl.exec_cmd("/home/u/.local/share/omarchy-voice/'
                                      'bin/omarchy-voice kill-port 3000")')

    def test_a_port_that_stays_busy_after_hyprland_says_so(self):
        reply, _ = self._hidden([self.SS_ROOT] * 40)
        self.assertIn("still in use", reply)

    def test_open_on_a_workspace_as_speech_to_text_writes_it(self):
        from omarchy_voice.mobile_bridge import _quick_command
        from omarchy_voice.tools import Executor, Result
        # "Open Chromium Workspace too" in the log: no "on", and "two" as "too".
        with mock.patch.object(Executor, "call",
                               return_value=Result(True, "opened on workspace 2")) as call:
            reply = _quick_command("Open Chrome Workspace too")
        self.assertEqual(reply, "Opened Chrome on workspace 2.")
        call.assert_called_once_with("launch_app", {"app": "google-chrome:new-window",
                                                    "workspace": "2"})

    def _media(self, phrase, installed, media_plugin=False):
        from omarchy_voice.mobile_bridge import _quick_command
        plugins = json.dumps([{"id": "omarchy.media", "enabled": media_plugin}])

        def fake_run(argv, **kwargs):
            out = plugins if argv[1:] == ["shell", "listPlugins"] else ""
            return SimpleNamespace(returncode=0, stdout=out, stderr="")

        which = lambda name: f"/usr/bin/{name}" if name in installed else None
        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", side_effect=which), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run",
                        side_effect=fake_run) as run, \
             mock.patch("omarchy_voice.tools.Executor.call",
                        return_value=SimpleNamespace(ok=True, output="ok")) as key:
            reply = _quick_command(phrase)
        actions = [c.args[0] for c in run.call_args_list
                   if c.args[0][1:] != ["shell", "listPlugins"]]
        return reply, actions, key

    def test_media_buttons_use_omarchys_media_plugin_like_the_media_keys(self):
        everything = {"omarchy-shell", "swayosd-client", "playerctl"}
        for phrase, action in (("media play pause", "playPause"),
                               ("media next", "next"),
                               ("media prev", "previous"),
                               ("media stop", "pause")):
            _, actions, key = self._media(phrase, everything, media_plugin=True)
            self.assertEqual(actions, [["omarchy-shell", "media", action]])
            key.assert_not_called()

    def test_a_disabled_media_plugin_is_skipped_for_swayosd(self):
        _, actions, key = self._media("media prev",
                                      {"omarchy-shell", "swayosd-client"})
        self.assertEqual(actions, [["swayosd-client", "--playerctl", "prev"]])
        key.assert_not_called()

    def test_media_uses_playerctl_without_omarchy_or_swayosd(self):
        _, actions, key = self._media("media prev", {"playerctl"})
        self.assertEqual(actions, [["playerctl", "previous"]])
        key.assert_not_called()

    def test_media_falls_back_to_the_key_with_none_of_them(self):
        reply, actions, key = self._media("media play pause", set())
        self.assertEqual(reply, "Toggled playback.")
        self.assertEqual(actions, [])
        self.assertEqual(key.call_args.args[:2],
                         ("send_shortcut", {"mods": "", "key": "XF86AudioPlay"}))

    def test_the_phone_button_uses_kill_port(self):
        from omarchy_voice.mobile_bridge import _quick_command
        with mock.patch("omarchy_voice.mobile_bridge.kill_port",
                        return_value="Killed python3 on port 3000.") as kp:
            reply = _quick_command("kill port 3000")
        self.assertEqual(reply, "Killed python3 on port 3000.")
        kp.assert_called_once_with(3000)

    def _pairing_guide_output(self, https_url, qrencode=None):
        from omarchy_voice.mobile_bridge import _print_pairing_guide
        out = io.StringIO()
        result = SimpleNamespace(returncode=0, stdout="[qr]")
        with mock.patch("omarchy_voice.mobile_bridge.shutil.which", return_value=qrencode), \
             mock.patch("omarchy_voice.mobile_bridge._ca_fingerprint", return_value="AA:BB"), \
             mock.patch("omarchy_voice.mobile_bridge.subprocess.run", return_value=result) as run, \
             contextlib.redirect_stdout(out):
            _print_pairing_guide("http://10.0.0.5:8765", https_url, "secret-token")
        return out.getvalue(), run

    def test_pairing_guide_puts_the_certificate_before_the_https_link(self):
        text, _ = self._pairing_guide_output("https://10.0.0.5:8765")
        cert = text.index("http://10.0.0.5:8765/ca.crt")
        link = text.index("https://10.0.0.5:8765/?token=secret-token")
        home = text.index("Add to Home Screen")
        self.assertLess(cert, link)
        self.assertLess(link, home)
        self.assertIn("Certificate Trust Settings", text)
        self.assertIn("AA:BB", text)
        self.assertIn("sudo pacman -S qrencode", text)

    def test_only_the_second_qr_code_carries_the_token(self):
        text, run = self._pairing_guide_output("https://10.0.0.5:8765", qrencode="/usr/bin/qrencode")
        targets = [call.args[0][-1] for call in run.call_args_list]
        self.assertEqual(targets, ["http://10.0.0.5:8765/ca.crt",
                                   "https://10.0.0.5:8765/?token=secret-token"])
        self.assertNotIn("Install qrencode", text)

    def test_pairing_guide_without_https_says_the_mic_will_not_work(self):
        text, _ = self._pairing_guide_output("")
        self.assertIn("mic", text)
        self.assertIn("http://10.0.0.5:8765/?token=secret-token", text)
        self.assertNotIn("Step 1", text)

    def test_disabling_pin_keeps_only_the_callers_session(self):
        _, first = self._call_post("/auth", {"pin": "1234"}, token="")
        _, second = self._call_post("/auth", {"pin": "1234"}, token="")
        status, _ = self._call_post(
            "/pin", {"action": "disable", "current_pin": "1234"}, token=first["token"])
        self.assertIn("200", status)
        self.assertIn("200", self._call_get("/state", token=first["token"])[0])
        self.assertIn("401", self._call_get("/state", token=second["token"])[0])

    def test_daily_cap_locks_pin_login_even_for_the_right_pin(self):
        from omarchy_voice.mobile_bridge import (
            _GLOBAL_AUTH_FAILURES, _AUTH_LOCK, MAX_DAILY_AUTH_FAILURES,
        )
        # Spread over the day, so only the daily cap can be what refuses this.
        long_ago = time.monotonic() - 3600.0
        with _AUTH_LOCK:
            _GLOBAL_AUTH_FAILURES[:] = [long_ago] * MAX_DAILY_AUTH_FAILURES
        status, data = self._call_post("/auth", {"pin": "1234"}, token="")
        self.assertIn("429", status)
        self.assertIn("24 hours", data.get("error", ""))

    def test_pin_endpoint_respects_the_global_limit(self):
        from omarchy_voice.mobile_bridge import (
            _GLOBAL_AUTH_FAILURES, _AUTH_LOCK, MAX_GLOBAL_AUTH_FAILURES,
        )
        _, auth = self._call_post("/auth", {"pin": "1234"}, token="")
        with _AUTH_LOCK:
            _GLOBAL_AUTH_FAILURES[:] = [time.monotonic()] * MAX_GLOBAL_AUTH_FAILURES
        status, data = self._call_post(
            "/pin", {"action": "disable", "current_pin": "0000"}, token=auth["token"])
        self.assertIn("429", status)
        self.assertIn("globally", data.get("error", ""))

    def test_per_ip_connection_limit_blocks_excessive_connections(self):
        from omarchy_voice.mobile_bridge import (
            BridgeServer,
            MAX_CONNECTIONS_PER_IP,
            _IP_CONNECTIONS,
            _IP_LOCK,
        )
        server = BridgeServer.__new__(BridgeServer)
        mock_req = mock.MagicMock()
        with _IP_LOCK:
            _IP_CONNECTIONS["192.168.1.100"] = MAX_CONNECTIONS_PER_IP

        server.shutdown_request = mock.MagicMock()
        server.process_request(mock_req, ("192.168.1.100", 54321))
        server.shutdown_request.assert_called_once_with(mock_req)
        mock_req.sendall.assert_called_once()
        self.assertIn(b"429 Too Many Requests", mock_req.sendall.call_args[0][0])
        with _IP_LOCK:
            _IP_CONNECTIONS.clear()


if __name__ == "__main__":
    unittest.main()
