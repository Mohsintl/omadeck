"""Settings can delete a saved API key, not only replace it."""

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from omarchy_voice import local_engine
from omarchy_voice.mobile_bridge import BridgeHandler, _PWA_HTML

KEYS = ("GROQ_API_KEY", "STT_API_KEY", "OPENAI_API_KEY")


class RemoveApiKeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.env_file = Path(self._tmp.name) / "env"
        self.env_file.write_text(
            "# Keys for the systemd user service.\n"
            "# GROQ_API_KEY=example\n"
            "GROQ_API_KEY=gsk_live_secret_value\n"
            "STT_API_KEY=sk-speech-secret\n"
            "OPENAI_API_KEY=sk-kept\n")
        self.local = {"provider": "groq"}
        self.saved_config = {}
        self.patches = [
            mock.patch.object(local_engine, "ENV_FILE", self.env_file),
            mock.patch.object(local_engine, "_local_config", side_effect=lambda cfg: dict(self.local)),
            mock.patch.object(local_engine, "save_local_config",
                              side_effect=lambda d: (self.saved_config.update(d), self.local.update(d))),
            mock.patch.dict(os.environ, {"GROQ_API_KEY": "gsk_live_secret_value",
                                         "STT_API_KEY": "sk-speech-secret",
                                         "OPENAI_API_KEY": "sk-kept"}),
            mock.patch("omarchy_voice.mobile_bridge.write_log"),
        ]
        for p in self.patches:
            p.start()
        self.orig_token, self.orig_pin = BridgeHandler.token, BridgeHandler.pin
        BridgeHandler.token, BridgeHandler.pin = "test-token", ""

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        BridgeHandler.token, BridgeHandler.pin = self.orig_token, self.orig_pin
        self._tmp.cleanup()

    def post(self, payload, token="test-token"):
        body = json.dumps(payload).encode()
        handler = BridgeHandler.__new__(BridgeHandler)
        handler.rfile, handler.wfile = io.BytesIO(body), io.BytesIO()
        handler.headers = {"Content-Type": "application/json", "Content-Length": str(len(body)),
                           "X-Token": token, "Host": "127.0.0.1:8765"}
        handler.path = "/settings/remove-key"
        handler.command, handler.request_version = "POST", "HTTP/1.1"
        handler.requestline = "POST /settings/remove-key HTTP/1.1"
        handler.log_message = lambda *args: None
        handler.do_POST()
        head, _, body = handler.wfile.getvalue().partition(b"\r\n\r\n")
        return head.split(b"\r\n")[0].decode(), json.loads(body or b"{}")

    def test_removing_the_provider_key_deletes_only_that_line(self):
        status, data = self.post({"key": "llm"})
        self.assertIn("200", status)
        self.assertTrue(data["ok"], data)
        text = self.env_file.read_text()
        self.assertNotIn("gsk_live_secret_value", text)
        self.assertIn("# GROQ_API_KEY=example", text)   # comments stay
        self.assertIn("STT_API_KEY=sk-speech-secret", text)
        self.assertIn("OPENAI_API_KEY=sk-kept", text)
        self.assertNotIn("GROQ_API_KEY", os.environ)
        self.assertFalse(local_engine.get_provider_status()["api_key_set"])
        self.assertIn("omadeck restart", data["message"])

    def test_removing_the_speech_key_leaves_the_provider_key(self):
        status, data = self.post({"key": "stt"})
        self.assertTrue(data["ok"], data)
        text = self.env_file.read_text()
        self.assertNotIn("STT_API_KEY", text)
        self.assertIn("GROQ_API_KEY=gsk_live_secret_value", text)
        self.assertFalse(local_engine.get_provider_status()["stt_api_key_set"])

    def test_the_env_file_stays_private(self):
        self.post({"key": "llm"})
        if os.name == "posix":
            self.assertEqual(self.env_file.stat().st_mode & 0o777, 0o600)

    def test_a_key_kept_in_config_toml_is_cleared_too(self):
        self.local["api_key"] = "gsk_from_config"
        self.post({"key": "llm"})
        self.assertEqual(self.saved_config.get("api_key"), "")

    def test_removing_twice_says_nothing_was_saved(self):
        self.post({"key": "stt"})
        status, data = self.post({"key": "stt"})
        self.assertFalse(data["ok"])
        self.assertIn("No speech-to-text key", data["error"])

    def test_ollama_has_no_key_to_remove(self):
        self.local["provider"] = "ollama"
        _, data = self.post({"key": "llm"})
        self.assertFalse(data["ok"])
        self.assertIn("does not use an API key", data["error"])

    def test_a_key_still_in_the_real_environment_is_reported(self):
        # Exported by the user's shell or systemd: the file is cleaned, but say so.
        with mock.patch.object(local_engine, "remove_env_var", return_value=True):
            _, data = self.post({"key": "stt"})
        self.assertFalse(data["ok"])
        self.assertIn("still set somewhere else", data["error"])

    def test_an_unknown_key_name_is_refused(self):
        status, data = self.post({"key": "OPENAI_API_KEY"})
        self.assertIn("400", status)
        self.assertIn("OPENAI_API_KEY=sk-kept", self.env_file.read_text())

    def test_it_needs_the_token(self):
        status, _ = self.post({"key": "llm"}, token="wrong")
        self.assertIn("401", status)
        self.assertIn("GROQ_API_KEY=gsk_live_secret_value", self.env_file.read_text())

    # --- "Keys saved on this computer": every key, each removable by name ---

    def test_settings_lists_every_saved_key_masked(self):
        keys = local_engine.get_provider_status()["saved_keys"]
        self.assertEqual([k["name"] for k in keys], ["GROQ_API_KEY", "STT_API_KEY", "OPENAI_API_KEY"])
        by_name = {k["name"]: k for k in keys}
        self.assertEqual(by_name["GROQ_API_KEY"]["masked"], "gsk_••••alue")
        self.assertTrue(by_name["GROQ_API_KEY"]["in_use"])          # the provider in use
        self.assertFalse(by_name["OPENAI_API_KEY"]["in_use"])        # left over from before
        self.assertEqual(by_name["OPENAI_API_KEY"]["label"], "OpenAI")
        self.assertEqual(by_name["STT_API_KEY"]["label"], "Speech-to-text")
        for k in keys:
            self.assertNotIn("secret", k["masked"])                   # never the whole key

    def test_a_key_from_another_provider_can_be_removed(self):
        status, data = self.post({"name": "OPENAI_API_KEY"})
        self.assertIn("200", status)
        self.assertTrue(data["ok"], data)
        self.assertNotIn("in use", data["message"].lower())
        text = self.env_file.read_text()
        self.assertNotIn("OPENAI_API_KEY", text)
        self.assertIn("GROQ_API_KEY=gsk_live_secret_value", text)
        self.assertNotIn("OPENAI_API_KEY", [k["name"] for k in local_engine.saved_keys()])

    def test_removing_the_key_in_use_says_voice_needs_one(self):
        _, data = self.post({"name": "GROQ_API_KEY"})
        self.assertTrue(data["ok"], data)
        self.assertIn("voice commands need a key", data["message"])

    def test_only_listed_keys_can_be_removed(self):
        for name in ("HOME", "PATH", "NOT_SAVED_KEY", "../env"):
            _, data = self.post({"name": name})
            self.assertFalse(data["ok"], name)
        self.assertEqual(len(local_engine.saved_keys()), 3)

    def test_a_legacy_config_toml_key_is_listed_and_removable(self):
        self.local["api_key"] = "gsk_from_config_file"
        names = [k["name"] for k in local_engine.saved_keys()]
        self.assertIn(local_engine.LEGACY_CONFIG_KEY, names)
        _, data = self.post({"name": local_engine.LEGACY_CONFIG_KEY})
        self.assertTrue(data["ok"], data)
        self.assertEqual(self.saved_config.get("api_key"), "")

    def test_settings_draws_the_saved_keys_list(self):
        self.assertIn('id="saved-keys-list"', _PWA_HTML)
        self.assertIn("renderSavedKeys(data.saved_keys", _PWA_HTML)
        self.assertIn("JSON.stringify({ name: k.name })", _PWA_HTML)
        # One place to remove keys, not a second set of buttons per field.
        self.assertNotIn("data-remove-key", _PWA_HTML)


if __name__ == "__main__":
    unittest.main()
