"""Tests for OmaDeck mobile remote PIN lock and session security."""

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice.local_engine import get_provider_status
from omarchy_voice.mobile_bridge import BridgeHandler, _PWA_HTML


class MobileBridgePinTests(unittest.TestCase):
    def setUp(self):
        self.orig_pin = BridgeHandler.pin
        self.orig_token = BridgeHandler.token
        BridgeHandler.pin = "1234"
        BridgeHandler.token = "test-token-123"

    def tearDown(self):
        BridgeHandler.pin = self.orig_pin
        BridgeHandler.token = self.orig_token

    def _call_post(self, path: str, payload: dict, token: str | None = None):
        if token is None:
            token = BridgeHandler.token
        body = json.dumps(payload).encode("utf-8")

        rfile = io.BytesIO(body)
        wfile = io.BytesIO()

        handler = BridgeHandler.__new__(BridgeHandler)
        handler.rfile = rfile
        handler.wfile = wfile
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Token": token,
        }
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
        self.assertEqual(data.get("token"), "test-token-123")

        # Incorrect PIN
        status_line, data = self._call_post("/auth", {"pin": "9999"}, token="")
        self.assertIn("401", status_line)
        self.assertFalse(data.get("ok"))
        self.assertEqual(data.get("error"), "Incorrect PIN")

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

        with mock.patch("omarchy_voice.local_engine.save_local_config", side_effect=fake_save):
            # Set new PIN
            status_line, data = self._call_post("/pin", {"action": "set", "pin": "8765"})
            self.assertIn("200", status_line)
            self.assertTrue(data.get("ok"))
            self.assertTrue(data.get("pin_set"))
            self.assertIn("token", data)
            self.assertEqual(BridgeHandler.token, data["token"])
            self.assertEqual(BridgeHandler.pin, "8765")
            self.assertEqual(saved.get("pin"), "8765")

            # Disable PIN
            status_line, data = self._call_post("/pin", {"action": "disable"})
            self.assertIn("200", status_line)
            self.assertTrue(data.get("ok"))
            self.assertFalse(data.get("pin_set"))
            self.assertIn("token", data)
            self.assertEqual(BridgeHandler.token, data["token"])
            self.assertEqual(BridgeHandler.pin, "")
            self.assertEqual(saved.get("pin"), "")

    def test_pwa_html_contains_security_elements(self):
        self.assertIn("settings-panel-security", _PWA_HTML)
        self.assertIn("tab-security", _PWA_HTML)
        self.assertIn("pin-keypad", _PWA_HTML)
        self.assertIn("app-lock-btn", _PWA_HTML)
        self.assertIn("setting-autolock-app-switch", _PWA_HTML)
        self.assertIn("lockSession", _PWA_HTML)


if __name__ == "__main__":
    unittest.main()
