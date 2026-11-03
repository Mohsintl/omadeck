"""Tests for OmaDeck smart AI dictation, speech cleaner, and review flow."""

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice.local_engine import polish_dictation, get_provider_status
from omarchy_voice.mobile_bridge import BridgeHandler, _PWA_HTML


class DictationTests(unittest.TestCase):
    def test_polish_dictation_fallback_strips_fillers(self):
        # Fallback when LLM is not called or disabled
        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"ai_dictate_polish": False}):
            res = polish_dictation("um so uh basically git status")
            self.assertEqual(res, "So basically git status")

            res2 = polish_dictation("like you know open terminal")
            self.assertEqual(res2, "Open terminal")

    def test_polish_dictation_empty_or_short(self):
        self.assertEqual(polish_dictation(""), "")
        self.assertEqual(polish_dictation("a"), "a")
        self.assertEqual(polish_dictation("  "), "")

    def test_provider_status_includes_ai_dictate_polish(self):
        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"ai_dictate_polish": True}):
            status = get_provider_status()
            self.assertIn("ai_dictate_polish", status)
            self.assertTrue(status["ai_dictate_polish"])

        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"ai_dictate_polish": False}):
            status = get_provider_status()
            self.assertIn("ai_dictate_polish", status)
            self.assertFalse(status["ai_dictate_polish"])

    def test_provider_status_includes_mic_trigger(self):
        with mock.patch("omarchy_voice.local_engine._local_config", return_value={"mic_trigger": "tap"}):
            status = get_provider_status()
            self.assertIn("mic_trigger", status)
            self.assertEqual(status["mic_trigger"], "tap")

        with mock.patch("omarchy_voice.local_engine._local_config", return_value={}):
            status = get_provider_status()
            self.assertIn("mic_trigger", status)
            self.assertEqual(status["mic_trigger"], "both")

    def test_pwa_html_contains_dictate_and_mic_trigger_elements(self):
        self.assertIn('id="dictate-btn"', _PWA_HTML)
        self.assertIn('class="cmd-input-wrap"', _PWA_HTML)
        self.assertIn('class="aux-keys" id="aux-keys"', _PWA_HTML)
        self.assertNotIn('id="aux-keys" style="display: none;"', _PWA_HTML)
        self.assertIn('data-key="enter"', _PWA_HTML)
        self.assertIn('data-key="backspace"', _PWA_HTML)
        self.assertIn('id="setting-ai-dictate-polish"', _PWA_HTML)
        self.assertIn('id="setting-mic-trigger"', _PWA_HTML)
        self.assertIn("rec-pulse-radar", _PWA_HTML)
        self.assertIn("sound-wave-bars", _PWA_HTML)
        self.assertIn("recording.latched", _PWA_HTML)
        self.assertIn("micTriggerMode", _PWA_HTML)
        self.assertIn("bindMicEvents", _PWA_HTML)
        self.assertIn("recordingTarget", _PWA_HTML)


class TranscribeEndpointTests(unittest.TestCase):
    def setUp(self):
        self.orig_token = BridgeHandler.token
        BridgeHandler.token = "test-token-123"

    def tearDown(self):
        BridgeHandler.token = self.orig_token

    def _call_post(self, path: str, payload: dict, token: str = "test-token-123"):
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

    def test_transcribe_returns_heard_and_polished(self):
        with mock.patch("omarchy_voice.mobile_bridge._transcribe_wav", return_value="um launch firefox"), \
             mock.patch("omarchy_voice.local_engine.polish_dictation", return_value="Launch Firefox"):
            status_line, data = self._call_post("/transcribe", {"audio_b64": "dGVzdA==", "polish": True})
            self.assertIn("200", status_line)
            self.assertEqual(data.get("heard"), "um launch firefox")
            self.assertEqual(data.get("polished"), "Launch Firefox")


if __name__ == "__main__":
    unittest.main()
