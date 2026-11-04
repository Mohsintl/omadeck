"""Tests for universal multi-provider engine and STT resolution."""

import os
import unittest
from unittest.mock import patch

from omarchy_voice.local_engine import (
    PROVIDER_PRESETS,
    _detect_provider,
    _resolve_provider,
    _planner_backend,
    _to_openai_messages,
    _pcm_to_wav,
    LocalSTT,
)


class MultiProviderTests(unittest.TestCase):

    def test_explicit_provider_presets(self):
        for prov in ("groq", "openai", "openrouter", "deepseek", "mistral", "nvidia", "ollama"):
            cfg = {"provider": prov}
            detected = _detect_provider(cfg)
            self.assertEqual(detected, prov)

            info = _resolve_provider(cfg)
            self.assertEqual(info["name"], prov)
            self.assertTrue(info["base_url"])
            self.assertTrue(info["default_model"])

    def test_auto_detection_from_environment(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}, clear=True):
            self.assertEqual(_detect_provider({}), "groq")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk_test"}, clear=True):
            self.assertEqual(_detect_provider({}), "openai")

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-test"}, clear=True):
            self.assertEqual(_detect_provider({}), "openrouter")

        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-ds-test"}, clear=True):
            self.assertEqual(_detect_provider({}), "deepseek")

        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_detect_provider({}), "ollama")

    def test_custom_base_url(self):
        cfg = {"base_url": "http://127.0.0.1:1234/v1", "llm_model": "local-model"}
        detected = _detect_provider(cfg)
        self.assertEqual(detected, "custom")
        info = _resolve_provider(cfg)
        self.assertEqual(info["backend"], "openai")
        self.assertEqual(info["base_url"], "http://127.0.0.1:1234/v1")

    def test_to_openai_messages_rewriting(self):
        messages = [
            {"role": "user", "content": "close the window"},
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "call_123", "function": {"name": "hypr_dispatch", "arguments": {"lua": "close()"}}}
                ]
            },
            {"role": "tool", "content": "ok"},
        ]
        rewritten = _to_openai_messages(messages)
        self.assertEqual(len(rewritten), 3)
        self.assertEqual(rewritten[1]["tool_calls"][0]["id"], "call_123")
        self.assertEqual(rewritten[2]["tool_call_id"], "call_123")

    def test_pcm_to_wav(self):
        pcm = b"\x00" * 3200
        wav = _pcm_to_wav(pcm, rate=16000, channels=1)
        self.assertTrue(wav.startswith(b"RIFF"))
        self.assertIn(b"WAVE", wav[:16])
        self.assertEqual(len(wav), len(pcm) + 44)

    def test_get_provider_status(self):
        from omarchy_voice.local_engine import get_provider_status
        status = get_provider_status()
        self.assertIn("provider", status)
        self.assertIn("model", status)
        self.assertIn("presets", status)
        self.assertIn("groq", status["presets"])
        self.assertIn("stt_api_key_set", status)
        self.assertEqual(status["stt_api_key_env"], "STT_API_KEY")

    def test_get_provider_status_resolves_clean_base_url_on_switch(self):
        from omarchy_voice.local_engine import get_provider_status
        with patch("omarchy_voice.local_engine._local_config", return_value={"provider": "groq", "base_url": "http://localhost:1234/v1"}):
            status = get_provider_status()
            self.assertEqual(status["base_url"], "https://api.groq.com/openai/v1")

    def test_stt_settings_provider_mapping(self):
        from omarchy_voice.local_engine import stt_settings
        with patch.dict(os.environ, {"STT_API_KEY": "gsk_voice"}, clear=True):
            self.assertEqual(stt_settings({"stt": "faster-whisper"}), ("local", "gsk_voice"))
            self.assertEqual(stt_settings({"stt": "groq"}), ("groq", "gsk_voice"))
            self.assertEqual(stt_settings({}), ("auto", "gsk_voice"))

    def test_local_stt_explicit_local_never_falls_back(self):
        stt = LocalSTT(provider="local")
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test", "STT_API_KEY": "gsk_test"}, clear=True):
            self.assertFalse(stt._can_cloud_stt())

    def test_local_stt_auto_can_use_dedicated_key(self):
        stt = LocalSTT(provider="auto")
        with patch.dict(os.environ, {"STT_API_KEY": "gsk_test"}, clear=True):
            self.assertTrue(stt._can_cloud_stt())
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(stt._can_cloud_stt())

    def test_connection_missing_key(self):
        from omarchy_voice.local_engine import test_provider_connection
        with patch.dict(os.environ, {}, clear=True):
            ok, err = test_provider_connection("groq", api_key="")
            self.assertFalse(ok)
            self.assertIn("API key is required", err)


if __name__ == "__main__":
    unittest.main()
