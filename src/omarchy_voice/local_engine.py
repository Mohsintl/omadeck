"""Free local engine: replaces the OpenAI Realtime API with local tools.

Architecture (100% offline after model download):

    pw-record ──▶ VAD (webrtcvad) ──▶ faster-whisper ──▶ text
                                                           │
                                                    ollama (LLM) ──▶ tool calls
                                                           │
                                                    piper / espeak-ng ──▶ pw-cat

Drop-in replacement for realtime.run(config).  All tools, the policy gate,
feedback, session socket, and bar widget work identically.

Dependencies (all free / local):
    sudo pacman -S python-faster-whisper python-webrtcvad pipewire-audio
    # or: pip install faster-whisper webrtcvad
    # Ollama: https://ollama.com  (then: ollama pull qwen2.5:7b)
    # TTS (pick one):
    #   sudo pacman -S piper-tts  (best quality)
    #   sudo pacman -S espeak-ng  (lightest)

Config (~/.config/omarchy-voice/config.toml):
    [local]
    engine     = "local"            # activates this module
    stt_model  = "base.en"          # faster-whisper model size
    llm_model  = "qwen2.5:7b"       # any ollama model
    tts        = "piper"            # "piper" | "espeak" | "none"
    piper_voice = ""                # path to .onnx voice; empty = auto-detect
    vad_level  = 2                  # webrtcvad aggressiveness 0-3
"""

from __future__ import annotations

import array
import asyncio
import io
import json
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import wave
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import capabilities
from .config import Config, CONFIG_DIR, CONFIG_FILE, ENV_FILE
from .feedback import Feedback
from .persona import PERSONA
from .session import ControlServer
from .tools import TOOL_SCHEMAS, Executor

# ---------------------------------------------------------------------------
# tunables
# ---------------------------------------------------------------------------

SAMPLE_RATE   = 16000   # faster-whisper wants 16 kHz
CHANNELS      = 1
SAMPLE_WIDTH  = 2       # 16-bit PCM
FRAME_MS      = 30      # webrtcvad frame size (10 | 20 | 30 ms)
FRAME_BYTES   = SAMPLE_RATE * CHANNELS * SAMPLE_WIDTH * FRAME_MS // 1000
SILENCE_SECS  = 0.9    # speech ends after this much quiet
MIN_SPEECH_MS = 300    # ignore clips shorter than this
OLLAMA_URL    = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _find_piper_voice() -> str:
    """Return the first .onnx voice file found in standard locations."""
    search = [
        Path.home() / ".local/share/piper",
        Path("/usr/share/piper-voices"),
        Path("/usr/local/share/piper-voices"),
    ]
    for base in search:
        voices = list(base.glob("**/*.onnx")) if base.exists() else []
        if voices:
            return str(voices[0])
    return ""


def _speak(text: str, cfg_tts: str, piper_voice: str) -> None:
    """Push text to speakers via piper or espeak-ng."""
    if cfg_tts == "none" or not text.strip():
        return
    if cfg_tts == "piper" and shutil.which("piper"):
        voice = piper_voice or _find_piper_voice()
        if voice:
            try:
                proc = subprocess.run(
                    ["piper", "--model", voice, "--output-raw"],
                    input=text.encode(),
                    capture_output=True,
                    timeout=30,
                )
                # piper outputs raw 16-kHz 16-bit PCM; pipe to pw-cat
                subprocess.run(
                    ["pw-cat", "--playback", "--rate=16000",
                     "--channels=1", "--format=s16", "-"],
                    input=proc.stdout,
                    timeout=30,
                )
            except Exception:
                pass
            return
    if shutil.which("espeak-ng"):
        subprocess.run(["espeak-ng", "-v", "en", text], timeout=30)
    elif shutil.which("espeak"):
        subprocess.run(["espeak", text], timeout=30)


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 120) -> dict:
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        if body:
            try:
                err_json = json.loads(body)
                err_msg = err_json.get("error", {}).get("message") or err_json.get("message") or body
                exc.msg = f"{exc.msg} ({err_msg})"
            except Exception:
                exc.msg = f"{exc.msg} ({body[:200]})"
        raise exc


def _ollama_chat(model: str, messages: list[dict], tools: list[dict]) -> dict:
    """One round-trip to ollama /api/chat.  Returns the parsed response dict."""
    import urllib.error

    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        # Thinking models (qwen3.5 and friends) spend their whole token budget
        # reasoning and return no content, which takes ~40x longer on a small
        # iGPU.  The planner wants an answer and tool calls, not a monologue.
        "think": False,
        # A small model left alone writes essays.  Cap the answer and keep it
        # deterministic enough to pick the same tool twice in a row.
        "options": {"num_predict": 300, "temperature": 0.2},
    }

    try:
        return _post_json(f"{OLLAMA_URL}/api/chat", payload, {})
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise
        # An ollama too old to know `think` rejects the whole request; retry
        # without it rather than failing the turn.
        fallback = {k: v for k, v in payload.items() if k != "think"}
        return _post_json(f"{OLLAMA_URL}/api/chat", fallback, {})


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Rewrite the loop's ollama-shaped messages into OpenAI tool-call shape.

    An OpenAI-compatible provider wants a call id on every tool call and the
    same id on the tool result that answers it.  The loop does not track ids,
    so they are minted here and matched to the following tool messages in
    order.
    """
    out: list[dict] = []
    pending: list[str] = []
    for i, m in enumerate(messages):
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            calls, pending = [], []
            for j, tc in enumerate(m["tool_calls"]):
                fn = tc.get("function", {})
                cid = tc.get("id") or f"call_{i}_{j}"
                args = fn.get("arguments", {})
                if not isinstance(args, str):
                    args = json.dumps(args)
                calls.append({
                    "id": cid, "type": "function",
                    "function": {"name": fn.get("name", ""), "arguments": args},
                })
                pending.append(cid)
            out.append({"role": "assistant", "content": m.get("content") or "",
                        "tool_calls": calls})
        elif role == "tool":
            entry = {"role": "tool", "content": m.get("content") or ""}
            if pending:
                entry["tool_call_id"] = pending.pop(0)
            out.append(entry)
        else:
            out.append(m)
    return out


def _openai_chat(base_url: str, api_key: str, model: str,
                 messages: list[dict], tools: list[dict]) -> dict:
    """One round-trip to an OpenAI-compatible provider (Groq, OpenAI, OpenRouter...)."""
    payload = {
        "model": model,
        "messages": _to_openai_messages(messages),
        "stream": False,
        "temperature": 0.2,
        "max_tokens": 500,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    headers = {
        "HTTP-Referer": "https://github.com/omarchy-linux/omarchy-voice",
        "X-Title": "Omarchy Voice",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    raw = _post_json(f"{base_url.rstrip('/')}/chat/completions", payload, headers)
    choice = (raw.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    return {"message": {
        "content": msg.get("content") or "",
        "tool_calls": msg.get("tool_calls") or [],
    }}


def _to_ollama_tools(schemas: list[dict]) -> list[dict]:
    """Convert anthropic-style tool schemas to ollama/OpenAI function format."""
    out = []
    for s in schemas:
        out.append({
            "type": "function",
            "function": {
                "name": s["name"],
                "description": s["description"],
                "parameters": s["input_schema"],
            },
        })
    return out


# ---------------------------------------------------------------------------
# STT (Local faster-whisper + Cloud Whisper fallback)
# ---------------------------------------------------------------------------

def _pcm_to_wav(pcm_bytes: bytes, rate: int = 16000, channels: int = 1) -> bytes:
    """Pack 16-bit PCM bytes into standard WAV container."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm_bytes)
    return buf.getvalue()


def stt_settings(local_cfg: dict) -> tuple[str, str]:
    """Return (provider, api_key) for speech-to-text.

    The deck stores a dedicated STT key in ``STT_API_KEY`` so a user can mix,
    say, a local Ollama planner with Groq Whisper without duplicating keys.
    When no dedicated key is set the cloud helpers fall back to the provider
    environment variables, which keeps existing installs working.
    """
    provider = str(local_cfg.get("stt") or "auto").strip().lower()
    if provider in ("faster-whisper", "faster_whisper", "whisper", "local"):
        provider = "local"
    return provider, os.environ.get("STT_API_KEY", "").strip()


def _cloud_whisper_transcribe(wav_bytes: bytes, base_url: str = "",
                              api_key: str = "", provider: str = "auto") -> str:
    """Transcribe audio via OpenAI / Groq cloud Whisper API."""
    import secrets
    import urllib.request

    key = api_key or os.environ.get("STT_API_KEY", "").strip()
    provider = (provider or "auto").strip().lower()

    # "auto" with a dedicated key: the key prefix identifies the service.
    if provider == "auto" and key:
        if key.startswith("gsk_"):
            provider = "groq"
        elif key.startswith("sk-"):
            provider = "openai"

    if provider == "openai" or (not key and "OPENAI_API_KEY" in os.environ and "GROQ_API_KEY" not in os.environ):
        key = key or os.environ.get("OPENAI_API_KEY", "")
        url = (base_url or "https://api.openai.com/v1").rstrip("/") + "/audio/transcriptions"
        model = "whisper-1"
    else:
        key = key or os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
        url = (base_url or "https://api.groq.com/openai/v1").rstrip("/") + "/audio/transcriptions"
        model = "whisper-large-v3" if "groq.com" in url else "whisper-1"

    if not key:
        raise RuntimeError("No API key available for cloud speech transcription (set STT_API_KEY, GROQ_API_KEY or OPENAI_API_KEY)")

    boundary = f"----WebKitFormBoundary{secrets.token_hex(16)}"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="model"\r\n\r\n{model}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="audio.wav"\r\n'
        f"Content-Type: audio/wav\r\n\r\n"
    ).encode() + wav_bytes + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {key}",
            "User-Agent": "OmarchyVoice/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
        return str(data.get("text", "")).strip()


class LocalSTT:
    """Wraps faster-whisper locally with optional/fallback cloud Whisper."""

    def __init__(self, model_size: str = "base.en", provider: str = "auto",
                 api_key: str = "", base_url: str = ""):
        self.model_size = model_size
        self.provider = provider
        self.api_key = api_key
        self.base_url = base_url
        self._model = None
        self._lock = threading.Lock()

    def _can_cloud_stt(self) -> bool:
        if self.provider == "local":
            return False
        key = (self.api_key or os.environ.get("STT_API_KEY")
               or os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        return bool(key)

    def _load(self):
        with self._lock:
            if self._model is None:
                try:
                    from faster_whisper import WhisperModel
                    self._model = WhisperModel(self.model_size, device="cpu",
                                               compute_type="int8")
                except Exception as exc:
                    self._model = None
                    if not self._can_cloud_stt():
                        raise RuntimeError(
                            f"faster-whisper is not installed — run: pip install faster-whisper "
                            f"(or export GROQ_API_KEY / OPENAI_API_KEY for cloud transcription)"
                        ) from exc

    def transcribe(self, pcm_bytes: bytes) -> str:
        """Transcribe raw 16-kHz 16-bit mono PCM. Returns the transcript."""
        use_cloud = self.provider in ("groq", "openai", "cloud")
        if not use_cloud:
            try:
                self._load()
            except Exception:
                if self._can_cloud_stt():
                    use_cloud = True
                else:
                    raise

        if not use_cloud and self._model is not None:
            import numpy as np
            audio = np.frombuffer(pcm_bytes, np.int16).astype(np.float32) / 32768.0
            segments, _info = self._model.transcribe(
                audio, beam_size=5, language="en",
                vad_filter=True,
            )
            return " ".join(s.text.strip() for s in segments).strip()

        # Cloud transcription
        wav = _pcm_to_wav(pcm_bytes)
        return _cloud_whisper_transcribe(wav, base_url=self.base_url,
                                         api_key=self.api_key,
                                         provider=self.provider)


# ---------------------------------------------------------------------------
# VAD-based recorder
# ---------------------------------------------------------------------------

class VadRecorder:
    """Reads pw-record stdout and emits complete utterances via a queue."""

    def __init__(self, device: str, vad_level: int = 2):
        self.device = device
        self.vad_level = vad_level
        self._q: queue.Queue[bytes | None] = queue.Queue()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._active = False
        self._active_lock = threading.Lock()

    # ------------------------------------------------------------------
    def start(self):
        cmd = [
            "pw-record",
            "--rate", str(SAMPLE_RATE),
            "--channels", str(CHANNELS),
            "--format", "s16",
        ]
        if self.device:
            cmd += ["--target", self.device]
        cmd.append("-")          # raw PCM to stdout
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL)
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def stop(self):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._q.put(None)   # sentinel

    def set_active(self, value: bool):
        with self._active_lock:
            self._active = value

    def utterances(self):
        """Yield complete utterance PCM bytes (blocks until stop())."""
        while True:
            item = self._q.get()
            if item is None:
                return
            yield item

    # ------------------------------------------------------------------
    def _reader(self):
        try:
            import webrtcvad
            vad = webrtcvad.Vad(self.vad_level)
        except ImportError:
            vad = None

        speech_frames: list[bytes] = []
        silent_frames = 0
        silence_threshold = int(SILENCE_SECS * 1000 / FRAME_MS)
        in_speech = False
        RMS_THRESHOLD = 600

        assert self._proc and self._proc.stdout
        while True:
            frame = self._proc.stdout.read(FRAME_BYTES)
            if not frame or len(frame) < FRAME_BYTES:
                break

            with self._active_lock:
                active = self._active
            if not active:
                # drain audio silently while toggled off
                continue

            if vad is not None:
                try:
                    is_speech = vad.is_speech(frame, SAMPLE_RATE)
                except Exception:
                    is_speech = False
            else:
                samples = array.array("h", frame)
                if samples:
                    rms = math.sqrt(sum(s * s for s in samples) / len(samples))
                    is_speech = rms > RMS_THRESHOLD
                else:
                    is_speech = False

            if is_speech:
                speech_frames.append(frame)
                silent_frames = 0
                in_speech = True
            elif in_speech:
                speech_frames.append(frame)
                silent_frames += 1
                if silent_frames >= silence_threshold:
                    # end of utterance
                    pcm = b"".join(speech_frames)
                    duration_ms = len(pcm) * 1000 // (SAMPLE_RATE * SAMPLE_WIDTH)
                    if duration_ms >= MIN_SPEECH_MS:
                        self._q.put(pcm)
                    speech_frames = []
                    silent_frames = 0
                    in_speech = False

        self._q.put(None)


# ---------------------------------------------------------------------------
# LLM planner with tool loop
# ---------------------------------------------------------------------------

_manifest_cache: str | None = None


def _manifest() -> str:
    """The omarchy command manifest, built once per process (0.6 s to build)."""
    global _manifest_cache
    if _manifest_cache is None:
        _manifest_cache = capabilities.manifest()
    return _manifest_cache


PROVIDER_PRESETS: dict[str, dict[str, Any]] = {
    "groq": {
        "name": "Groq",
        "desc": "Ultra-fast (500+ tok/s), ideal for real-time voice & commands.",
        "backend": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
        "fallbacks": ["llama-3.1-8b-instant"],
    },
    "openai": {
        "name": "OpenAI",
        "desc": "Standard GPT-4o mini / GPT-4o model suite.",
        "backend": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
        "fallbacks": ["gpt-4o"],
    },
    "openrouter": {
        "name": "OpenRouter",
        "desc": "Access any open or commercial model with one unified key.",
        "backend": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": "meta-llama/llama-3.3-70b-instruct",
        "fallbacks": ["meta-llama/llama-3.1-8b-instruct"],
    },
    "deepseek": {
        "name": "DeepSeek",
        "desc": "DeepSeek V3 chat and R1 reasoning.",
        "backend": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "fallbacks": ["deepseek-reasoner"],
    },
    "mistral": {
        "name": "Mistral AI",
        "desc": "Mistral Small & Large reasoning models.",
        "backend": "openai",
        "base_url": "https://api.mistral.ai/v1",
        "api_key_env": "MISTRAL_API_KEY",
        "default_model": "mistral-small-latest",
        "fallbacks": ["mistral-large-latest"],
    },
    "nvidia": {
        "name": "NVIDIA NIM",
        "desc": "Free developer tier for Llama and Nemotron models.",
        "backend": "openai",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "api_key_env": "NVIDIA_API_KEY",
        "default_model": "nvidia/nemotron-3.5-lightning-30b-a3b",
        "fallbacks": ["nvidia/nemotron-3.5-bolt-e4b"],
    },
    "ollama": {
        "name": "Ollama (Local)",
        "desc": "100% private and offline on your computer.",
        "backend": "ollama",
        "base_url": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        "api_key_env": "",
        "default_model": "qwen2.5:7b",
        "fallbacks": ["llama3.2:3b"],
    },
    "custom": {
        "name": "Custom Endpoint",
        "desc": "Any OpenAI-compatible server (LM Studio, vLLM, LocalAI).",
        "backend": "openai",
        "base_url": "http://localhost:1234/v1",
        "api_key_env": "",
        "default_model": "local-model",
        "fallbacks": [],
    },
}


def _detect_provider(local_cfg: dict) -> str:
    """Determine the active provider from config or available API keys."""
    prov = str(local_cfg.get("provider") or local_cfg.get("planner") or "").strip().lower()
    if prov in ("nvidia", "nim"):
        return "nvidia"
    if prov in ("groq", "openai", "openrouter", "deepseek", "mistral", "ollama", "custom"):
        return prov
    if prov in ("local",):
        return "ollama"

    if local_cfg.get("base_url"):
        return "custom"

    # Auto-detection from environment variables
    for candidate in ("groq", "openai", "openrouter", "deepseek", "mistral", "nvidia"):
        env_var = PROVIDER_PRESETS[candidate]["api_key_env"]
        if os.environ.get(env_var, "").strip():
            return candidate

    return "ollama"


def _resolve_provider(local_cfg: dict) -> dict[str, Any]:
    prov_name = _detect_provider(local_cfg)
    preset = PROVIDER_PRESETS.get(prov_name, {})
    backend = preset.get("backend", "openai")
    base_url = str(local_cfg.get("base_url") or preset.get("base_url") or "").rstrip("/")
    api_key_env = str(local_cfg.get("api_key_env") or preset.get("api_key_env") or "")
    default_model = preset.get("default_model", "gpt-4o-mini")
    fallbacks = preset.get("fallbacks", [])

    return {
        "name": prov_name,
        "backend": backend,
        "base_url": base_url,
        "api_key_env": api_key_env,
        "default_model": default_model,
        "fallbacks": fallbacks,
    }


def _planner_backend(local_cfg: dict) -> tuple[str, str, str]:
    """Which backend answers planner turns: ("ollama"|"openai", base_url, key_env)."""
    res = _resolve_provider(local_cfg)
    return res["backend"], res["base_url"], res["api_key_env"]


def test_provider_connection(provider: str, api_key: str = "", model: str = "",
                             base_url: str = "") -> tuple[bool, str]:
    """Test connecting to a provider to verify credentials and response."""
    preset = PROVIDER_PRESETS.get(provider, {})
    url = (base_url or preset.get("base_url", "")).rstrip("/")
    key = api_key or os.environ.get(preset.get("api_key_env", ""), "")

    if provider == "ollama":
        import urllib.request
        try:
            with urllib.request.urlopen(f"{url}/api/tags", timeout=4) as resp:
                data = json.load(resp)
                models = [m.get("name") for m in data.get("models", [])]
                if model and not any(model in m for m in models):
                    return True, f"Ollama reachable, but model '{model}' not yet pulled (run: ollama pull {model})"
                return True, f"Connected to Ollama! Models available: {len(models)}"
        except Exception as exc:
            return False, f"Could not reach Ollama at {url}: {exc}"

    if not key and provider != "custom":
        env_var = preset.get("api_key_env", "API_KEY")
        return False, f"API key is required for {provider} ({env_var})"

    model_name = model or preset.get("default_model", "gpt-4o-mini")
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 5,
    }
    headers = {
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/omarchy-linux/omarchy-voice",
        "X-Title": "Omarchy Voice",
    }
    if key:
        headers["Authorization"] = f"Bearer {key}"

    import urllib.request, urllib.error
    req = urllib.request.Request(
        f"{url}/chat/completions",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.load(resp)
            return True, f"Connected to {preset.get('name', provider)} ({model_name}) successfully!"
    except urllib.error.HTTPError as exc:
        err_msg = str(exc)
        try:
            body = exc.read().decode("utf-8", errors="replace")
            err_json = json.loads(body)
            err_msg = err_json.get("error", {}).get("message") or err_json.get("message") or err_json.get("detail") or body
        except Exception:
            pass
        return False, f"HTTP {exc.code}: {err_msg}"
    except Exception as exc:
        return False, f"Connection failed: {exc}"


def save_env_var(var_name: str, value: str) -> None:
    """Save an environment variable to ~/.config/omarchy-voice/env securely."""
    if not var_name:
        return
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    found = False
    if ENV_FILE.exists():
        try:
            lines = ENV_FILE.read_text().splitlines()
        except Exception:
            lines = []
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, _ = stripped.partition("=")
            if k.strip() == var_name:
                new_lines.append(f"{var_name}={value}")
                found = True
                continue
        new_lines.append(line)
    if not found:
        if new_lines and new_lines[-1].strip():
            new_lines.append("")
        new_lines.append(f"{var_name}={value}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass
    os.environ[var_name] = value


def save_local_config(updates: dict[str, Any]) -> None:
    """Update [local] section in ~/.config/omarchy-voice/config.toml while preserving comments."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if CONFIG_FILE.exists():
        try:
            lines = CONFIG_FILE.read_text().splitlines()
        except Exception:
            lines = []

    sec_header = "[local]"
    sec_start = -1
    sec_end = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == sec_header:
            sec_start = i
        elif sec_start != -1 and stripped.startswith("[") and stripped.endswith("]"):
            sec_end = i
            break

    formatted_updates: dict[str, str] = {}
    for k, v in updates.items():
        if v is None:
            continue
        if isinstance(v, str):
            formatted_updates[k] = json.dumps(v)
        elif isinstance(v, bool):
            formatted_updates[k] = "true" if v else "false"
        else:
            formatted_updates[k] = str(v)

    if sec_start == -1:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(sec_header)
        for k, val in formatted_updates.items():
            lines.append(f"{k} = {val}")
        CONFIG_FILE.write_text("\n".join(lines) + "\n")
        return

    sec_lines = lines[sec_start + 1:sec_end]
    rem = dict(formatted_updates)
    new_sec_lines = []
    for line in sec_lines:
        m = re.match(r"^(\s*)([a-zA-Z0-9_-]+)(\s*=\s*)(.*)$", line)
        if m and m.group(2) in rem:
            k = m.group(2)
            val = rem.pop(k)
            new_sec_lines.append(f"{m.group(1)}{k}{m.group(3)}{val}")
        else:
            new_sec_lines.append(line)

    for k, val in rem.items():
        new_sec_lines.append(f"{k} = {val}")

    lines = lines[:sec_start + 1] + new_sec_lines + lines[sec_end:]
    CONFIG_FILE.write_text("\n".join(lines) + "\n")


def get_provider_status(config: Config | None = None) -> dict[str, Any]:
    """Return current configuration, masked keys, and provider catalog."""
    from .config import load as load_cfg
    cfg = config or load_cfg()
    lcfg = _local_config(cfg)
    prov_info = _resolve_provider(lcfg)
    prov_name = prov_info["name"]

    key_env = prov_info["api_key_env"]
    raw_key = os.environ.get(key_env, "").strip() if key_env else ""
    if not raw_key and lcfg.get("api_key"):
        raw_key = str(lcfg.get("api_key", "")).strip()

    masked_key = ""
    if raw_key:
        if len(raw_key) > 8:
            masked_key = raw_key[:4] + "••••" + raw_key[-4:]
        else:
            masked_key = "••••••••"

    presets_data = {}
    for k, p in PROVIDER_PRESETS.items():
        presets_data[k] = {
            "name": p.get("name", k.title()),
            "desc": p.get("desc", ""),
            "backend": p.get("backend", "openai"),
            "default_model": p.get("default_model", ""),
            "fallbacks": p.get("fallbacks", []),
            "api_key_env": p.get("api_key_env", ""),
            "base_url": p.get("base_url", ""),
        }

    stt_raw = os.environ.get("STT_API_KEY", "").strip()
    if len(stt_raw) > 8:
        stt_masked = stt_raw[:4] + "••••" + stt_raw[-4:]
    elif stt_raw:
        stt_masked = "••••••••"
    else:
        stt_masked = ""

    return {
        "provider": prov_name,
        "model": lcfg.get("llm_model") or prov_info["default_model"],
        "api_key_env": key_env,
        "api_key_set": bool(raw_key),
        "api_key_masked": masked_key,
        "base_url": lcfg.get("base_url") or prov_info["base_url"],
        "stt": lcfg.get("stt", "auto"),
        "stt_api_key_set": bool(stt_raw),
        "stt_api_key_masked": stt_masked,
        "stt_api_key_env": "STT_API_KEY",
        "presets": presets_data,
    }


class LocalPlanner:
    """Calls ollama with the same tool schemas and runs the tool loop."""

    # The full persona + manifest is ~21k characters — three thousand tokens
    # before the user has said anything.  A small model on a phone's request
    # path cannot afford that, so compact mode keeps the job and the command
    # list and drops the prose.
    COMPACT_PERSONA = (
        "You are OMA, the voice control layer of an Omarchy Linux desktop. "
        "You operate the machine for the user; you are not a chat assistant.\n"
        "Use one tool only when the request needs the machine to change or to "
        "be inspected. A question you can answer yourself (time, maths, "
        "wording) gets a short answer with no tool at all.\n"
        "Act, do not inspect: when the request already names the action "
        "(close, mute, open, switch), call the dispatching tool at once. Do "
        "not query state first — a read-only answer does nothing for the "
        'user. "Close the window" is hypr_dispatch hl.dsp.window.close().\n'
        "omarchy_cli runs an `omarchy` subcommand and nothing else: mute is "
        "`audio output volume mute-toggle`, a terminal is `launch terminal`. "
        "It is never a bare program name (`omarchy firefox` does not exist); "
        "launch apps with launch_app.\n"
        "After the tool result, reply in one short sentence. Never explain how "
        "the user could do it themselves — do it, or answer."
    )

    COMPACT_TOOLS = {
        "launch_app", "omarchy_cli", "hypr_query", "hypr_dispatch",
        "type_text", "clipboard", "system_query", "web_search",
    }

    def __init__(self, config: Config, executor: Executor, feedback: Feedback,
                 compact: bool = False):
        self.config = config
        self.executor = executor
        self.feedback = feedback
        local_cfg = _local_config(config)
        self.compact = compact

        prov_info = _resolve_provider(local_cfg)
        self.provider = prov_info["backend"]
        self.provider_name = prov_info["name"]
        self.base_url = local_cfg.get("base_url") or prov_info["base_url"]
        self.api_key_env = local_cfg.get("api_key_env") or prov_info["api_key_env"]
        self.model = local_cfg.get("llm_model") or prov_info["default_model"]

        self.api_key = str(local_cfg.get("api_key") or "").strip()
        if not self.api_key and self.api_key_env:
            self.api_key = os.environ.get(self.api_key_env, "").strip()

        fallback = str(local_cfg.get("llm_fallback") or "").strip()
        self.fallbacks = [m.strip() for m in fallback.split(",") if m.strip()]
        if not self.fallbacks:
            self.fallbacks = list(prov_info["fallbacks"])
        self._model_ok = ""
        schemas = TOOL_SCHEMAS
        if compact:
            schemas = [s for s in TOOL_SCHEMAS
                       if (s.get("name") or s.get("function", {}).get("name"))
                       in self.COMPACT_TOOLS]
            self.max_turns = min(config.max_turns, 4)
            self._system = "\n\n".join([
                self.COMPACT_PERSONA,
                capabilities.essentials(),
            ])
        else:
            self.max_turns = config.max_turns
            self._system = "\n\n".join([
                PERSONA,
                _manifest(),
            ])
        self._tools = _to_ollama_tools(schemas)

    def _call(self, messages: list[dict], tools: list[dict]) -> dict:
        if self.provider == "ollama":
            return _ollama_chat(self.model, messages, tools)
        if not self.api_key:
            env_hint = f"export {self.api_key_env}" if self.api_key_env else "provide api_key in config.toml"
            raise RuntimeError(
                f"{self.api_key_env or 'API key'} is not set — "
                f"{env_hint} or put it in ~/.config/omarchy-voice/env"
            )

        import urllib.error

        # The model that worked last time goes first, so a turn never pays
        # for a retired model twice in one process.
        order = ([self._model_ok] if self._model_ok else []) + [
            m for m in [self.model, *self.fallbacks] if m != self._model_ok
        ]
        last: Exception | None = None
        for model in order:
            try:
                reply = _openai_chat(self.base_url, self.api_key, model,
                                     messages, tools)
            except urllib.error.HTTPError as exc:
                # 404/410 = gone, 429 = out of quota, 5xx = their problem.
                # A 400 is our bug and retrying just hides it.
                if exc.code not in (404, 408, 410, 429) and exc.code < 500:
                    raise
                last = exc
                self.feedback.log(f"planner {model}: HTTP {exc.code}")
                continue
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
                self.feedback.log(f"planner {model}: {exc}")
                continue
            if model != self._model_ok:
                self.feedback.log(f"planner model: {model}")
                self._model_ok = model
            return reply
        raise last if last else RuntimeError("no planner model answered")

    def think(self, text: str, history: list[dict] | None = None) -> str:
        """Run the tool loop for one utterance.  Returns the reply text."""
        # Live state goes in the user turn, not a second system message: it
        # changes every call, and putting it first would throw away the
        # provider's cached prompt for the (large, constant) persona.
        messages: list[dict] = [{"role": "system", "content": self._system}]
        # A few earlier turns, so "close it" or "again" has a referent.
        messages.extend(history or [])
        messages.append({"role": "user", "content": (
            "# Desktop state\n\n" + capabilities.live_state()
            + "\n\n# Request\n\n" + text
        )})
        reply = ""
        for _round in range(self.max_turns):
            self.feedback.state("thinking")
            try:
                resp = self._call(messages, self._tools)
            except Exception as exc:
                self.feedback.log(f"error   {self.provider}: {exc}")
                return f"I couldn't reach the model: {exc}"

            msg = resp.get("message", {})
            tool_calls = msg.get("tool_calls") or []

            if not tool_calls:
                reply = (msg.get("content") or "").strip()
                break

            messages.append({"role": "assistant", "content": None,
                              "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {}
                self.feedback.state("acting", name)
                self.feedback.log(f"action  {name}({json.dumps(args)})")
                try:
                    result = self.executor.call(name, args)
                    result_text = result.as_tool_result()
                except Exception as exc:
                    result_text = f"ERROR: {exc}"
                messages.append({
                    "role": "tool",
                    "content": result_text,
                })

            # The phone path stops after one tool round and asks for the
            # spoken sentence with the tools taken away.  Small models keep
            # calling tools forever otherwise, and every extra round is a
            # full prompt evaluation.
            if self.compact:
                break

        if self.compact and not reply:
            self.feedback.state("thinking")
            try:
                # Keep the tools offered: this model returns empty content when
                # a tool result is in the history and no tools are declared.
                # The nudge matters too — with only a tool result to go on it
                # often answers with nothing, which reads as "Done." on the
                # phone however much the action actually changed.
                ask = messages + [{
                    "role": "user",
                    "content": "Answer the user's request in one short sentence, "
                               "using the tool result above. Do not describe "
                               "what you did; give the answer.",
                }]
                final = self._call(ask, self._tools)
                reply = (final.get("message", {}).get("content") or "").strip()
            except Exception as exc:
                self.feedback.log(f"error   {self.provider}: {exc}")

        if not reply:
            # Last resort: the tool already produced the answer (a time, a
            # window list); hand that back rather than a bare "Done."
            for m in reversed(messages):
                if m.get("role") != "tool":
                    continue
                body = (m.get("content") or "").strip()
                if not body or body.startswith("ERROR") or body[0] in "{[":
                    continue  # a structured dump, not something to say aloud
                reply = body.splitlines()[0][:300]
                break
        return reply or "Done."


# ---------------------------------------------------------------------------
# config helper
# ---------------------------------------------------------------------------

def _local_config(config: Config) -> dict:
    """Read the [local] / [planner] section from config.toml."""
    try:
        from .config import load_env_file
        load_env_file()
    except Exception:
        pass
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomllib  # type: ignore[no-redef]
            except ImportError:
                import tomli as tomllib  # type: ignore[no-redef]
        cfg_file = CONFIG_DIR / "config.toml"
        if cfg_file.exists():
            with cfg_file.open("rb") as fh:
                raw = tomllib.load(fh)
            res = {}
            if "local" in raw and isinstance(raw["local"], dict):
                res.update(raw["local"])
            if "planner" in raw and isinstance(raw["planner"], dict):
                res.update(raw["planner"])
            return res
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# main session
# ---------------------------------------------------------------------------

class LocalSession:
    """Runs the listen loop using local STT + LLM + TTS."""

    def __init__(self, config: Config):
        self.config = config
        self.feedback = Feedback(config)
        self.executor = Executor(config, on_action=self._on_action)
        local_cfg = _local_config(config)
        stt_provider, stt_key = stt_settings(local_cfg)
        self.stt = LocalSTT(local_cfg.get("stt_model", "base.en"),
                            provider=stt_provider, api_key=stt_key)
        self.planner = LocalPlanner(config, self.executor, self.feedback)
        self.recorder = VadRecorder(
            config.device,
            vad_level=int(local_cfg.get("vad_level", 2)),
        )
        self._tts       = local_cfg.get("tts", "piper")
        self._piper_voice = local_cfg.get("piper_voice", "")
        self._stop      = asyncio.Event()
        self._active    = False
        self._speaking  = False
        self.control    = ControlServer(self._control)

    # ------------------------------------------------------------------
    def _on_action(self, name: str, description: str) -> None:
        self.feedback.state("acting", description)
        self.feedback.log(f"action  {description}")

    def _speak(self, text: str) -> None:
        self._speaking = True
        if not self.config.barge_in:
            self.recorder.set_active(False)
        try:
            _speak(text, self._tts, self._piper_voice)
        finally:
            self._speaking = False
            if self._active and not self.config.barge_in:
                self.recorder.set_active(True)

    # ------------------------------------------------------------------
    def _control(self, command: str) -> str:
        """Handle control socket messages from CLI, keybinding, or mobile."""
        cmd = command.strip()
        verb, _, rest = cmd.partition(" ")
        verb_norm = verb.lower()

        if verb_norm == "toggle":
            self._active = not self._active
            self.recorder.set_active(self._active)
            state = "listening" if self._active else "idle"
            self.feedback.state(state)
            self.feedback.log(f"toggle  {'on' if self._active else 'off'}")
            return "on" if self._active else "off"

        elif verb_norm == "start":
            self._active = True
            self.recorder.set_active(True)
            self.feedback.state("listening")
            self.feedback.log("toggle  on")
            return "listening"

        elif verb_norm == "stop":
            self._active = False
            self.recorder.set_active(False)
            self.feedback.state("idle")
            self.feedback.log("toggle  off")
            return "stopped"

        elif verb_norm == "status":
            return "listening" if self._active else "idle"

        elif verb_norm == "say":
            text = rest.strip()
            if not text:
                return "empty"
            self.feedback.state("thinking")
            self.feedback.log(f"heard   {text}")
            self.feedback.notify(f"🎤 {text}")
            reply = self.planner.think(text)
            self.feedback.log(f"reply   {reply}")
            self.feedback.state("listening" if self._active else "idle", reply)
            self.feedback.notify(f"Oma: {reply}")
            if self._tts != "none":
                threading.Thread(target=self._speak, args=(reply,), daemon=True).start()
            return reply

        elif verb_norm in self.config.confirm_words or verb_norm == "confirm":
            if self.executor.pending:
                res = self.executor.run_pending()
                self.feedback.state("acting")
                return res.output or "Done."
            return "nothing held"

        elif verb_norm in self.config.cancel_words or verb_norm == "cancel":
            if self.executor.pending:
                self.executor.cancel_pending()
                self.feedback.state("idle")
                return "cancelled"
            return "nothing held"

        elif verb_norm == "quit":
            self._stop.set()
            return "quitting"

        return f"unknown command: {cmd}"

    # ------------------------------------------------------------------
    def _process_utterance(self, pcm: bytes) -> None:
        """STT → planner → TTS.  Runs in a thread pool."""
        self.feedback.state("thinking")
        try:
            text = self.stt.transcribe(pcm)
        except Exception as exc:
            self.feedback.log(f"error   stt: {exc}")
            self.feedback.state("listening" if self._active else "idle")
            return
        if not text:
            self.feedback.state("listening" if self._active else "idle")
            return
        self.feedback.log(f"heard   {text}")
        self.feedback.notify(f"🎤 {text}")

        reply = self.planner.think(text)
        self.feedback.log(f"reply   {reply}")
        self.feedback.state("listening" if self._active else "idle", reply)
        self.feedback.notify(f"Oma: {reply}")

        if self._tts != "none":
            threading.Thread(target=self._speak, args=(reply,), daemon=True).start()

    # ------------------------------------------------------------------
    async def run(self) -> int:
        self.feedback.state("idle", "local engine ready")
        self.recorder.start()
        self.control.start()

        executor = ThreadPoolExecutor(max_workers=2,
                                      thread_name_prefix="omarchy-local")

        loop = asyncio.get_event_loop()
        q: asyncio.Queue[bytes | None] = asyncio.Queue()

        def feeder():
            for utt in self.recorder.utterances():
                loop.call_soon_threadsafe(q.put_nowait, utt)
            loop.call_soon_threadsafe(q.put_nowait, None)

        feed_thread = threading.Thread(target=feeder, daemon=True)
        feed_thread.start()

        try:
            while not self._stop.is_set():
                try:
                    pcm = await asyncio.wait_for(q.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                if pcm is None:
                    break
                await loop.run_in_executor(executor, self._process_utterance, pcm)
        except KeyboardInterrupt:
            pass
        finally:
            self.control.stop()
            self.recorder.stop()
            executor.shutdown(wait=False, cancel_futures=True)
            self.feedback.state("idle")

        return 0


# ---------------------------------------------------------------------------
# public entry point (mirrors realtime.run)
# ---------------------------------------------------------------------------

class LocalEngineUnavailable(RuntimeError):
    pass


def check_ready(config: Config) -> list[str]:
    problems = []
    for tool, pkg in [("pw-record", "pipewire-audio"), ("pw-cat", "pipewire-audio")]:
        if not shutil.which(tool):
            problems.append(f"{tool} is missing — install {pkg}")
    try:
        import faster_whisper  # noqa: F401
    except ImportError:
        problems.append("faster-whisper not installed — pip install faster-whisper")

    local_cfg = _local_config(config)
    provider, _, api_key_env = _planner_backend(local_cfg)
    if provider == "ollama":
        import urllib.request, urllib.error
        try:
            urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
        except Exception:
            problems.append(
                f"ollama not reachable at {OLLAMA_URL} — install from https://ollama.com"
            )
    else:
        key = os.environ.get(api_key_env, "").strip()
        if not key:
            problems.append(
                f"{api_key_env} is not set in ~/.config/omarchy-voice/env"
            )
    return problems


def run(config: Config) -> int:
    problems = check_ready(config)
    if problems:
        for p in problems:
            print(f"local engine: {p}", file=sys.stderr)
        fb = Feedback(config)
        fb.state("error", "local engine not configured — see: omarchy-voice doctor")
        # non-fatal: let it stay down without spamming restarts
        return 0
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        session = LocalSession(config)
        return loop.run_until_complete(session.run())
    except KeyboardInterrupt:
        return 0
    finally:
        loop.close()
        asyncio.set_event_loop(None)
