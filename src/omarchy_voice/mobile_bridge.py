"""Mobile remote-control bridge for omarchy-voice.

Runs a small HTTP server on your LAN so a phone browser can:
  - Stream a voice recording → STT (faster-whisper) → control socket
  - Type a command → control socket directly
  - See the current daemon state (idle / listening / thinking / acting)
  - Toggle listening on/off with a tap

Plain HTTP, not TLS: Safari on iOS hangs on a self-signed certificate, and
LAN addresses are treated as secure contexts there, so getUserMedia still
works.  A shared secret (auto-generated on first run, stored in the config
dir) keeps a random device on the network from driving your desktop.

Usage:
    omarchy-voice mobile          # start on default port 8765
    omarchy-voice mobile --port 9000

Then open  http://<your-lan-ip>:8765  on your phone.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import io
import json
import os
import secrets
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import wave
import zlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import CONFIG_DIR, STATE_FILE, load_env_file
from .session import send_control, daemon_running

# Load environment keys at startup so LAN/remote workers have access
load_env_file()

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

DEFAULT_PORT = 8765
TOKEN_FILE   = CONFIG_DIR / "mobile_token"
CERT_FILE    = CONFIG_DIR / "mobile_cert.pem"
KEY_FILE     = CONFIG_DIR / "mobile_key.pem"
CA_CERT_FILE = CONFIG_DIR / "mobile_ca.pem"
CA_KEY_FILE  = CONFIG_DIR / "mobile_ca_key.pem"
CA_DER_FILE  = CONFIG_DIR / "mobile_ca.crt"      # what the phone installs
CERT_HOST_FILE = CONFIG_DIR / "mobile_cert_host"

def _generate_icon_png(width=192, height=192) -> bytes:
    """Generate a clean 192x192 RGBA PNG icon in memory without external dependencies."""
    raw = bytearray()
    cx, cy, r2 = width // 2, height // 2, (width * 0.38) ** 2
    for y in range(height):
        raw.append(0)  # filter type 0
        for x in range(width):
            dist2 = (x - cx) ** 2 + (y - cy) ** 2
            if dist2 <= r2:
                raw.extend((228, 228, 231, 255))  # #e4e4e7 titanium accent
            else:
                raw.extend((20, 20, 26, 255))     # #14141a dark deck chassis
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_chunk = struct.pack(">I4s", len(ihdr), b"IHDR") + ihdr + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    compressed = zlib.compress(bytes(raw), 9)
    idat_chunk = struct.pack(">I4s", len(compressed), b"IDAT") + compressed + struct.pack(">I", zlib.crc32(b"IDAT" + compressed))
    iend_chunk = struct.pack(">I4s", 0, b"IEND") + struct.pack(">I", zlib.crc32(b"IEND"))
    return b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk

_ICON_PNG: bytes | None = None

def _get_icon_png() -> bytes:
    global _ICON_PNG
    if _ICON_PNG is None:
        _ICON_PNG = _generate_icon_png()
    return _ICON_PNG

_MANIFEST_JSON = json.dumps({
    "name": "Oma Remote",
    "short_name": "Oma",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0f0f13",
    "theme_color": "#0f0f13",
    "icons": [
        {
            "src": "/icon.png",
            "sizes": "192x192",
            "type": "image/png",
            "purpose": "any maskable"
        }
    ]
}).encode("utf-8")

# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------

def _load_or_create_token() -> str:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if TOKEN_FILE.exists():
        tok = TOKEN_FILE.read_text().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(16)
    TOKEN_FILE.write_text(tok)
    TOKEN_FILE.chmod(0o600)
    return tok


# ---------------------------------------------------------------------------
# TLS: a local CA the phone trusts once, so Safari allows the microphone
# ---------------------------------------------------------------------------

def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _ensure_tls(host: str) -> tuple[Path, Path] | None:
    """Create (or reuse) a leaf cert for `host`, signed by a local CA.

    An untrusted self-signed leaf is worse than no TLS here: Safari shows an
    interstitial and the media APIs stay unhappy. A CA the phone installs
    once gives a clean https:// page, which is the only way getUserMedia is
    exposed to the page at all.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if not (CA_CERT_FILE.exists() and CA_KEY_FILE.exists()):
            _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-days", "3650",
                     "-keyout", str(CA_KEY_FILE), "-out", str(CA_CERT_FILE),
                     "-subj", "/CN=Oma Remote CA",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            CA_KEY_FILE.chmod(0o600)
            _openssl("x509", "-in", str(CA_CERT_FILE), "-outform", "der",
                     "-out", str(CA_DER_FILE))
            print(f"  created a local CA: {CA_CERT_FILE}")

        # Re-issue the leaf when the LAN address changes, otherwise the SAN
        # no longer matches and the phone silently refuses the page.
        current = ""
        try:
            current = CERT_HOST_FILE.read_text().strip()
        except OSError:
            pass
        if not (current == host and CERT_FILE.exists() and KEY_FILE.exists()):
            csr = CONFIG_DIR / "mobile_csr.pem"
            ext = CONFIG_DIR / "mobile_ext.cnf"
            try:
                name = socket.gethostname()
            except Exception:
                name = "omarchy"
            ext.write_text(
                f"subjectAltName=IP:{host},IP:127.0.0.1,DNS:localhost,"
                f"DNS:{name}.local\n"
                "basicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
            )
            _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(KEY_FILE), "-out", str(csr),
                     "-subj", "/CN=Oma Remote")
            _openssl("x509", "-req", "-in", str(csr),
                     "-CA", str(CA_CERT_FILE), "-CAkey", str(CA_KEY_FILE),
                     "-CAcreateserial", "-days", "825",
                     "-extfile", str(ext), "-out", str(CERT_FILE))
            KEY_FILE.chmod(0o600)
            CERT_HOST_FILE.write_text(host + "\n")
            for tmp in (csr, ext):
                try:
                    tmp.unlink()
                except OSError:
                    pass
            print(f"  issued a certificate for {host}")
        return CERT_FILE, KEY_FILE
    except Exception as exc:
        print(f"  https unavailable ({exc})")
        print("  the page still works over http, but the phone's mic will not")
        return None


# ---------------------------------------------------------------------------
# STT helper (reuses LocalSTT from local_engine if available)
# ---------------------------------------------------------------------------

_stt_lock = threading.Lock()
_stt_model = None

# Recent exchanges from the phone, so a follow-up has something to refer to.
# Bounded: the compact prompt is cheap, but a growing history is not free and
# a small model starts echoing old answers if it has too much.
_HISTORY: list[dict] = []
_HISTORY_LOCK = threading.Lock()
_HISTORY_TURNS = 3
_HISTORY_CAP = 40   # entries kept for the page's chat log

def _transcribe_wav(wav_bytes: bytes, model_size: str = "base.en") -> str:
    global _stt_model
    try:
        from .local_engine import LocalSTT, _local_config, stt_settings
        from .config import load as load_cfg
        lcfg = _local_config(load_cfg())
        stt_provider, stt_key = stt_settings(lcfg)
        with _stt_lock:
            if _stt_model is None:
                _stt_model = LocalSTT(
                    model_size=lcfg.get("stt_model", model_size),
                    provider=stt_provider,
                    api_key=stt_key,
                )
        # wav_bytes is a proper WAV file from the browser (webm/opus decoded via ffmpeg)
        # Try ffmpeg decode first, fall back to raw
        pcm = _decode_to_pcm(wav_bytes)
        return _stt_model.transcribe(pcm)
    except Exception as exc:
        return f"[stt error: {exc}]"


def _warm_stt(model_size: str = "base.en") -> None:
    """Load the speech model before the first utterance arrives.

    The first faster-whisper call costs 10-14 s (weights plus the int8
    graph); later ones are 2-3 s. Paying that at service start keeps it out
    of the first thing the user says after a reboot.
    """
    global _stt_model
    try:
        from .local_engine import LocalSTT, _local_config, stt_settings
        from .config import load as load_cfg
        lcfg = _local_config(load_cfg())
        stt_provider, stt_key = stt_settings(lcfg)
        with _stt_lock:
            if _stt_model is None:
                _stt_model = LocalSTT(
                    model_size=lcfg.get("stt_model", model_size),
                    provider=stt_provider,
                    api_key=stt_key,
                )
        _stt_model._load()
    except Exception as exc:
        print(f"  (speech model not preloaded: {exc})")


def _decode_to_pcm(audio_bytes: bytes) -> bytes:
    """Use ffmpeg to decode any audio format to 16kHz 16-bit mono PCM."""
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as inp:
        inp.write(audio_bytes)
        inp_path = inp.name
    out_path = inp_path + ".wav"
    try:
        subprocess.run([
            "ffmpeg", "-y", "-i", inp_path,
            "-ar", "16000", "-ac", "1", "-f", "wav", out_path,
        ], capture_output=True, timeout=30)
        with open(out_path, "rb") as fh:
            wav_bytes = fh.read()
        # Strip WAV header and return raw PCM
        with wave.open(io.BytesIO(wav_bytes), "rb") as w:
            return w.readframes(w.getnframes())
    finally:
        for p in (inp_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# daemon state reader
# ---------------------------------------------------------------------------

def _read_state() -> dict:
    # With the daemon down the state file is stale — last time it said
    # "OPENAI_API_KEY is not set" and stayed that way on every page load.
    # The phone bridge works on its own now, so say what is actually true.
    if not daemon_running():
        return {"status": "idle", "icon": "󰍭",
                "text": "daemon off — text and mic from the phone still work",
                "class": "idle"}
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
    except Exception:
        pass
    return {"status": "unknown", "text": "", "icon": ""}


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

# The PWA HTML is embedded as a string so the server is self-contained.
_PWA_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#09090c">
<script>
  // Apply the saved theme before first paint so the deck never flashes the
  // default palette on a device that chose Phosphor or Amber.
  try {
    var _omaTheme = localStorage.getItem('oma-deck-theme') || 'midnight';
    document.documentElement.dataset.theme = _omaTheme;
    var _omaMeta = document.querySelector('meta[name="theme-color"]');
    if (_omaMeta) _omaMeta.setAttribute('content',
      _omaTheme === 'phosphor' ? '#020604' : _omaTheme === 'amber' ? '#0a0703' : '#09090c');
  } catch (e) {}
</script>
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.png" type="image/png">
<link rel="apple-touch-icon" href="/icon.png">
<title>Oma Deck</title>
<style>
  :root {
    --bg: #09090c;
    --chassis: #121217;
    --surface: #15151e;
    --surface-hover: #1c1c28;
    --surface-active: #242434;
    --deck-key: #14141c;
    --deck-key-hover: #1b1b26;
    --deck-key-active: #0c0c12;
    --border: #232330;
    --border-subtle: #191924;
    --border-highlight: rgba(255, 255, 255, 0.08);
    --text: #f4f4f7;
    --text-muted: #8e8e9e;
    --text-dim: #5c5c6b;
    --accent: #e4e4e7;
    --accent-fg: #09090c;
    --status-ok: #10b981;
    --status-warn: #f59e0b;
    --status-danger: #ef4444;
    --status-info: #38bdf8;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    /* Themeable component tokens (overridden by [data-theme] below) */
    --selection-bg: #343444;
    --scroll-thumb: #232330;
    --scroll-thumb-hover: #333344;
    --tag-bg: #1e1e2b;
    --reply-text: #e2e2ec;
    --profile-bar-bg: #0f0f15;
    --active-bg: #242434;
    --active-border: #3e3e52;
    --input-bg: #101016;
    --input-border: #232330;
    --input-focus: #4a4a64;
    --placeholder: #9a9aab;
    --action-bg: #242434;
    --action-border: #3c3c50;
    --action-hover: #2c2c3e;
    --action-hover-border: #4e4e68;
    --mic-bg: #222230;
    --mic-border: #38384a;
    --msg-you-bg: #262638;
    --msg-you-border: #3a3a50;
    --msg-oma-bg: #13131c;
    --btn-bg: #e4e4e7;
    --btn-fg: #09090c;
    --radius-sm: 6px;
    --radius-md: 9px;
    --radius-lg: 12px;
    --radius-xl: 18px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  ::selection { background: var(--selection-bg); color: var(--text); }
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--scroll-thumb); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--scroll-thumb-hover); }

  html, body {
    height: 100%;
    height: 100dvh;
    max-height: 100dvh;
    overflow: hidden;
    position: fixed;
    width: 100%;
    inset: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Inter', 'Segoe UI', Roboto, sans-serif;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }
  body {
    display: flex;
    justify-content: center;
    align-items: center;
    touch-action: manipulation;
  }

  /* SVG Icon Core */
  .icon-svg {
    width: 18px;
    height: 18px;
    stroke: currentColor;
    fill: none;
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
    flex-shrink: 0;
  }

  /* App Shell - Default (Portrait) */
  .app-shell {
    width: 100%;
    max-width: 460px;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 6px;
    padding: calc(env(safe-area-inset-top, 0px) + 8px) 10px max(env(safe-area-inset-bottom, 0px), 8px) 10px;
  }

  /* Cockpit / Header */
  .deck-cockpit {
    display: flex;
    flex-direction: column;
    gap: 6px;
    width: 100%;
    flex-shrink: 0;
  }
  header {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 32px;
    flex-shrink: 0;
  }
  .brand-group {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .logo {
    font-size: 0.95rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .logo .tag {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.70rem;
    font-weight: 700;
    background: var(--tag-bg);
    border: 1px solid var(--border);
    padding: 1px 5px;
    border-radius: 4px;
    color: var(--accent);
    letter-spacing: 0.05em;
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  #status-badge {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.70rem;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 99px;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    display: flex;
    align-items: center;
    gap: 5px;
    transition: all 0.2s;
  }
  #status-badge::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--text-dim);
  }
  #status-badge.listening { background: #0c2417; border-color: #105934; color: #6ee7b7; }
  #status-badge.listening::before { background: var(--status-ok); box-shadow: 0 0 6px var(--status-ok); }
  #status-badge.thinking  { background: #132238; border-color: #1d4677; color: #93c5fd; }
  #status-badge.thinking::before { background: var(--status-info); box-shadow: 0 0 6px var(--status-info); }
  #status-badge.acting    { background: #2b1f0c; border-color: #634614; color: #fde68a; }
  #status-badge.acting::before { background: var(--status-warn); box-shadow: 0 0 6px var(--status-warn); }
  #status-badge.error     { background: #291212; border-color: #5c1f1f; color: #fca5a5; }
  #status-badge.error::before { background: var(--status-danger); }
  #status-badge.idle      { color: var(--text-muted); }
  #status-badge.idle::before { background: #34d399; }

  .icon-chip {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.75rem;
    font-weight: 600;
    padding: 6px 10px;
    min-height: 30px;
    border-radius: 99px;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    gap: 4px;
    transition: all 0.15s;
    -webkit-tap-highlight-color: transparent;
  }
  .icon-chip:hover { background: var(--surface-hover); color: var(--text); border-color: var(--border-highlight); }
  .icon-chip:active { background: var(--surface-active); transform: scale(0.96); }
  .icon-chip.muted {
    border-color: rgba(239, 68, 68, 0.4);
    background: rgba(239, 68, 68, 0.08);
  }

  /* Live Single-line Feedback Strip */
  .reply-strip {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 0 10px;
    display: flex;
    align-items: center;
    gap: 8px;
    height: 28px;
    flex-shrink: 0;
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
  }
  .reply-strip:hover { border-color: var(--border-highlight); background: var(--surface-hover); }
  .reply-strip:active { background: var(--surface-active); }
  .reply-icon {
    width: 14px;
    height: 14px;
    stroke: var(--status-ok);
    flex-shrink: 0;
  }
  .reply-text {
    flex: 1;
    font-size: 0.78rem;
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--reply-text);
  }

  /* Profile Switcher Tabs */
  .deck-profile-bar {
    width: 100%;
    display: flex;
    gap: 3px;
    background: var(--profile-bar-bg);
    padding: 3px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-subtle);
    height: 40px;
    flex-shrink: 0;
  }
  .profile-pill {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text-muted);
    font-size: 0.70rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-radius: var(--radius-sm);
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    transition: all 0.15s;
    -webkit-tap-highlight-color: transparent;
  }
  .profile-pill .icon-svg { width: 14px; height: 14px; }
  .profile-pill:hover { color: var(--text); }
  .profile-pill.active {
    background: var(--active-bg);
    border: 1px solid var(--active-border);
    color: var(--text);
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.4);
  }

  /* Deck Bank (Macro Surface) */
  .deck-bank {
    width: 100%;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-height: 0;
  }

  /* Workspace Navigation Key Row */
  .workspace-row {
    width: 100%;
    display: grid;
    grid-template-columns: repeat(5, 1fr) 1.25fr;
    gap: 4px;
    height: 40px;
    flex-shrink: 0;
  }
  .move-to-row {
    width: 100%;
    display: grid;
    grid-template-columns: repeat(5, 1fr) 1.25fr;
    gap: 4px;
    height: 36px;
    flex-shrink: 0;
  }
  .ws-key {
    background: var(--deck-key);
    border: 1px solid var(--border);
    box-shadow: var(--key-shadow);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.84rem;
    font-weight: 700;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.08s;
    -webkit-tap-highlight-color: transparent;
    padding: 0;
  }
  .ws-key:hover { background: var(--deck-key-hover); border-color: var(--border-highlight); }
  .ws-key:active { background: var(--deck-key-active); transform: translateY(1.5px); box-shadow: var(--key-shadow-active); }
  .ws-key.move-btn {
    font-size: 0.72rem;
    color: var(--text-muted);
  }
  .ws-key.move-btn:hover { color: var(--text); }
  .ws-key.scratch-key {
    font-size: 0.72rem;
    color: var(--accent);
  }

  /* Control Sections & Profiles */
  .profile-view {
    width: 100%;
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 6px;
    min-height: 0;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
  }
  .control-section {
    background: var(--chassis);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 6px 7px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 4px;
    flex: 1;
    min-height: 0;
  }
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 3px;
    line-height: 1;
  }
  .section-title {
    font-size: 0.70rem;
    font-weight: 800;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .section-badge {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.70rem;
    color: var(--text-muted);
    font-weight: 600;
    letter-spacing: 0.04em;
  }
  .btn-grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 4px;
    flex: 1;
  }

  /* Tactile Deck Key Button */
  .chip {
    background: var(--deck-key);
    border: 1px solid var(--border);
    box-shadow: var(--key-shadow);
    border-radius: var(--radius-md);
    cursor: pointer;
    color: var(--text);
    touch-action: manipulation;
    -webkit-tap-highlight-color: transparent;
    padding: 4px 2px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 3px;
    text-align: center;
    height: 100%;
    min-height: 36px;
    position: relative;
    transition: background 0.1s, border-color 0.1s, transform 0.08s, box-shadow 0.08s;
  }
  .chip:hover {
    background: var(--deck-key-hover);
    border-color: var(--border-highlight);
  }
  .chip:active {
    background: var(--deck-key-active);
    transform: translateY(1.5px);
    box-shadow: var(--key-shadow-active);
  }
  .chip .icon {
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    stroke: var(--text);
  }
  .chip .label {
    font-size: 0.70rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
    line-height: 1;
  }
  .chip:active .label {
    color: var(--text);
  }
  .chip.off { opacity: 0.45; }
  .chip.chip-danger {
    border-color: rgba(239, 68, 68, 0.4);
  }
  .chip.chip-danger:hover {
    border-color: var(--status-danger);
  }
  .chip.chip-danger .icon {
    stroke: #fca5a5;
  }
  .chip.chip-danger .label {
    color: #fca5a5;
  }
  .chip.chip-danger:active {
    background: #2a1010;
  }

  /* Bottom Controls Deck (Input, Mode Switch, Mic) */
  .deck-controls-dock {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 5px;
    flex-shrink: 0;
  }

  /* Mode Switcher: Voice/Command vs Direct Typing */
  .mode-bar {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 34px;
    flex-shrink: 0;
  }
  .mode-pill {
    flex: 1;
    height: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font-size: 0.70rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    cursor: pointer;
    touch-action: manipulation;
    transition: all 0.15s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    -webkit-tap-highlight-color: transparent;
  }
  .mode-sep {
    font-size: 0.68rem;
    font-weight: 600;
    color: var(--text-muted);
    opacity: 0.65;
    user-select: none;
    letter-spacing: 0.02em;
    flex-shrink: 0;
  }
  .mode-pill:hover { color: var(--text); }
  .mode-pill.active {
    background: var(--active-bg);
    border-color: var(--active-border);
    color: var(--text);
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.4);
  }

  /* Auxiliary Keys for Direct Typing */
  .aux-keys {
    width: 100%;
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 4px;
    height: 28px;
    flex-shrink: 0;
  }
  .key-chip {
    background: var(--deck-key);
    border: 1px solid var(--border);
    box-shadow: var(--key-shadow);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 0.68rem;
    font-weight: 700;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 3px;
    transition: background 0.1s, transform 0.08s;
    -webkit-tap-highlight-color: transparent;
  }
  .key-chip:hover { background: var(--deck-key-hover); border-color: var(--border-highlight); }
  .key-chip:active { background: var(--deck-key-active); transform: translateY(1.5px); box-shadow: var(--key-shadow-active); }

  /* Command Bar */
  .cmd-bar {
    width: 100%;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 40px;
    flex-shrink: 0;
  }
  #mic-btn {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-md);
    border: 1px solid var(--mic-border);
    background: var(--mic-bg);
    box-shadow: var(--key-shadow);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    touch-action: none;
    -webkit-tap-highlight-color: transparent;
    transition: transform 0.12s, background 0.15s, border-color 0.15s, box-shadow 0.15s;
    flex-shrink: 0;
  }
  #mic-btn .icon-svg { width: 20px; height: 20px; stroke: #fff; }
  #mic-btn:hover { background: var(--action-hover); border-color: var(--action-hover-border); }
  #mic-btn:active { transform: translateY(1.5px); box-shadow: var(--key-shadow-active); }
  #mic-btn.recording {
    background: var(--status-danger);
    border-color: #f87171;
    animation: rec-pulse 1.2s infinite;
  }
  #mic-btn.thinking {
    background: #1e293b;
    border-color: #38bdf8;
    animation: spin-glow 1.5s infinite;
  }
  @keyframes rec-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }
    70%  { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
    100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
  }
  @keyframes spin-glow {
    0%   { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.6); }
    50%  { box-shadow: 0 0 0 10px rgba(56, 189, 248, 0); }
    100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.6); }
  }
  #cmd-input {
    flex: 1;
    min-width: 0;
    height: 40px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text);
    font-size: 0.86rem;
    padding: 0 12px;
    outline: none;
    transition: border-color 0.15s;
  }
  #cmd-input:focus { border-color: var(--input-focus); }
  #cmd-input::placeholder { color: var(--placeholder); opacity: 1; }
  .cmd-action-btn {
    height: 40px;
    padding: 0 12px;
    background: var(--action-bg);
    border: 1px solid var(--action-border);
    box-shadow: var(--key-shadow);
    color: #fff;
    border-radius: var(--radius-md);
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    cursor: pointer;
    touch-action: manipulation;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.1s;
    -webkit-tap-highlight-color: transparent;
  }
  .cmd-action-btn:hover { background: var(--action-hover); border-color: var(--action-hover-border); }
  .cmd-action-btn:active { transform: translateY(1.5px); box-shadow: var(--key-shadow-active); }
  #type-direct-btn {
    background: var(--deck-key);
    border-color: var(--border);
    color: var(--text-muted);
  }
  #cmd-send {
    background: var(--btn-bg);
    border-color: var(--btn-bg);
    color: var(--btn-fg);
  }
  #cmd-send:hover { filter: brightness(1.1); }

  /* Notice Banner */
  .notice {
    width: 100%;
    background: #241d10;
    border: 1px solid #5a4520;
    border-radius: var(--radius-sm);
    padding: 6px 9px;
    font-size: 0.72rem;
    line-height: 1.35;
    color: #fde68a;
  }
  .notice a { color: #93c5fd; }

  /* =========================================================================
     LANDSCAPE MODE: Ergonomic Split-Deck Architecture
     ========================================================================= */
  @media (orientation: landscape) and (min-width: 540px) {
    .app-shell {
      max-width: 100%;
      width: 100%;
      height: 100%;
      flex-direction: row;
      justify-content: stretch;
      align-items: stretch;
      gap: 12px;
      padding: max(env(safe-area-inset-top, 0px), 8px) max(env(safe-area-inset-right, 0px), 12px) max(env(safe-area-inset-bottom, 0px), 8px) max(env(safe-area-inset-left, 0px), 12px);
    }

    /* Left Control Cockpit */
    .deck-cockpit {
      width: min(340px, 38vw);
      height: 100%;
      border-right: 1px solid var(--border);
      padding-right: 12px;
      justify-content: space-between;
      gap: 8px;
    }

    /* Right Deck Action Bank */
    .deck-bank {
      flex: 1;
      height: 100%;
      min-width: 0;
      justify-content: space-between;
      gap: 8px;
    }

    /* In landscape, buttons fit comfortably */
    .profile-view {
      flex: 1;
      height: 100%;
      justify-content: flex-start;
      gap: 8px;
    }
    .control-section {
      height: 100%;
      padding: 7px 10px;
      gap: 6px;
    }
    .btn-grid-4 {
      gap: 6px;
    }
    .chip {
      min-height: 42px;
      padding: 6px 4px;
      gap: 4px;
    }
    .chip .icon {
      width: 22px;
      height: 22px;
    }
    .chip .label {
      font-size: 0.72rem;
    }
  }

  /* Modals: Conversation History & Settings */
  .modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(9, 9, 12, 0.88);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    padding: 14px;
  }
  .modal-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    width: 100%;
    max-width: 460px;
    max-height: 85dvh;
    display: flex;
    flex-direction: column;
    padding: 14px;
    gap: 10px;
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7);
  }
  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
  }
  .modal-title { font-size: 0.88rem; font-weight: 700; color: var(--text); }
  .modal-actions { display: flex; gap: 6px; }
  .chat-btn {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 0.72rem;
    font-weight: 600;
    cursor: pointer;
    padding: 4px 9px;
    border-radius: 99px;
    touch-action: manipulation;
  }
  .chat-btn:hover { background: var(--surface-hover); color: var(--text); }
  .chat-btn:active { background: var(--surface-active); }
  .chat-body {
    flex: 1;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-right: 2px;
  }
  .msg {
    max-width: 86%;
    padding: 8px 12px;
    border-radius: var(--radius-lg);
    font-size: 0.85rem;
    line-height: 1.35;
    white-space: pre-wrap;
    word-wrap: break-word;
  }
  .msg.you { align-self: flex-end; background: var(--msg-you-bg); border: 1px solid var(--msg-you-border); color: var(--text); border-bottom-right-radius: 3px; }
  .msg.oma { align-self: flex-start; background: var(--msg-oma-bg); border: 1px solid var(--border); border-bottom-left-radius: 3px; }
  .msg.sys { align-self: center; color: var(--text-muted); font-size: 0.74rem; background: transparent; }

  /* Settings Modal Styles */
  .settings-body {
    flex: 1;
    overflow-y: auto;
    -webkit-overflow-scrolling: touch;
    display: flex;
    flex-direction: column;
    gap: 11px;
    padding: 4px 2px;
  }
  .setting-group {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .setting-label {
    font-size: 0.76rem;
    font-weight: 700;
    color: var(--text);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .setting-desc {
    font-size: 0.78rem;
    color: var(--text-muted);
    line-height: 1.35;
  }
  .setting-select, .setting-input {
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: var(--radius-md);
    color: #fff;
    font-size: 0.84rem;
    padding: 8px 10px;
    outline: none;
    width: 100%;
    box-sizing: border-box;
    font-family: inherit;
    transition: border-color 0.15s;
  }
  .setting-select:focus, .setting-input:focus {
    border-color: var(--input-focus);
  }
  .setting-input::placeholder { color: var(--placeholder); opacity: 1; }
  .primary-btn {
    background: var(--btn-bg);
    color: var(--btn-fg);
    border: none;
    border-radius: var(--radius-md);
    padding: 10px;
    font-size: 0.88rem;
    font-weight: 700;
    cursor: pointer;
    touch-action: manipulation;
    transition: background 0.15s;
    text-align: center;
  }
  .primary-btn:hover { filter: brightness(1.12); }
  .primary-btn:active { transform: scale(0.98); }
  .primary-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .status-box {
    padding: 8px 10px;
    border-radius: var(--radius-md);
    font-size: 0.76rem;
    line-height: 1.35;
    word-break: break-word;
  }
  .status-box.success { background: #0d281a; border: 1px solid #165b36; color: #86efac; }
  .status-box.error   { background: #2b1414; border: 1px solid #632222; color: #fca5a5; }
  .status-box.info    { background: #122136; border: 1px solid #1d4b80; color: #93c5fd; }

  /* PIN lock overlay */
  .pin-overlay {
    position: fixed;
    inset: 0;
    background: rgba(9, 9, 12, 0.96);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    padding: 20px;
  }
  .pin-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    padding: 26px 20px;
    width: 100%;
    max-width: 300px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    text-align: center;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7);
  }
  .pin-subtitle { font-size: 0.80rem; color: var(--text-muted); }
  .pin-input-wrap input {
    background: var(--input-bg);
    border: 1px solid var(--input-border);
    border-radius: var(--radius-md);
    color: #fff;
    font-size: 1.6rem;
    letter-spacing: 0.3em;
    text-align: center;
    padding: 8px 14px;
    width: 160px;
    outline: none;
  }
  .pin-input-wrap input:focus { border-color: var(--input-focus); }
  #pin-submit-btn {
    width: 100%;
    background: var(--btn-bg);
    color: var(--btn-fg);
    border: none;
    border-radius: var(--radius-md);
    padding: 10px;
    font-size: 0.92rem;
    font-weight: 700;
    cursor: pointer;
    touch-action: manipulation;
  }
  #pin-submit-btn:hover { filter: brightness(1.12); }
  .pin-error { font-size: 0.78rem; color: var(--status-danger); min-height: 16px; }

  /* Runtime-switchable themes. Midnight is the default deck look; the other
     two are for the terminal crowd. Every rule below only sets tokens. */
  :root[data-theme="phosphor"] {
    --bg: #020604;
    --chassis: #04100a;
    --surface: #06150d;
    --surface-hover: #0a2013;
    --surface-active: #0e2b19;
    --deck-key: #05110a;
    --deck-key-hover: #0a1e11;
    --deck-key-active: #010804;
    --border: #133a20;
    --border-subtle: #0a2413;
    --border-highlight: rgba(74, 222, 128, 0.24);
    --text: #d7ffe4;
    --text-muted: #75b98c;
    --text-dim: #3f6b4f;
    --accent: #4ade80;
    --accent-fg: #03130a;
    --status-ok: #22c55e;
    --status-warn: #fbbf24;
    --status-danger: #fb7185;
    --status-info: #2dd4bf;
    --key-shadow: inset 0 1px 0 rgba(110, 231, 183, 0.10), 0 2px 4px rgba(0, 0, 0, 0.55);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.9);
    --selection-bg: #14532d;
    --scroll-thumb: #12341f;
    --scroll-thumb-hover: #1b5c35;
    --tag-bg: #0b2415;
    --reply-text: #c7f9d8;
    --profile-bar-bg: #03100a;
    --active-bg: #0c2a18;
    --active-border: #1c6b3a;
    --input-bg: #04120b;
    --input-border: #133a20;
    --input-focus: #1f7a46;
    --placeholder: #6fae86;
    --action-bg: #0c2a18;
    --action-border: #1c6b3a;
    --action-hover: #123a21;
    --action-hover-border: #2a8a50;
    --mic-bg: #0a2013;
    --mic-border: #1c6b3a;
    --msg-you-bg: #0b2a19;
    --msg-you-border: #1e6b3e;
    --msg-oma-bg: #05170e;
    --btn-bg: #4ade80;
    --btn-fg: #03130a;
  }
  :root[data-theme="amber"] {
    --bg: #0a0703;
    --chassis: #120d06;
    --surface: #171006;
    --surface-hover: #221708;
    --surface-active: #2e1f0a;
    --deck-key: #150f06;
    --deck-key-hover: #231708;
    --deck-key-active: #0c0803;
    --border: #3a2a10;
    --border-subtle: #241a09;
    --border-highlight: rgba(251, 191, 36, 0.26);
    --text: #ffedc7;
    --text-muted: #b8955c;
    --text-dim: #6b5533;
    --accent: #fbbf24;
    --accent-fg: #1a1203;
    --status-ok: #fbbf24;
    --status-warn: #f59e0b;
    --status-danger: #fb7185;
    --status-info: #fdba74;
    --key-shadow: inset 0 1px 0 rgba(251, 191, 36, 0.10), 0 2px 4px rgba(0, 0, 0, 0.55);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.9);
    --selection-bg: #4a3510;
    --scroll-thumb: #3a2a10;
    --scroll-thumb-hover: #5a4218;
    --tag-bg: #2a1c08;
    --reply-text: #ffe6b0;
    --profile-bar-bg: #0b0803;
    --active-bg: #2e1f0a;
    --active-border: #6b4e14;
    --input-bg: #120d06;
    --input-border: #3a2a10;
    --input-focus: #7a5a1e;
    --placeholder: #a8854c;
    --action-bg: #2e1f0a;
    --action-border: #6b4e14;
    --action-hover: #3d290c;
    --action-hover-border: #8a6a24;
    --mic-bg: #221708;
    --mic-border: #6b4e14;
    --msg-you-bg: #2a1c08;
    --msg-you-border: #5a4210;
    --msg-oma-bg: #140e05;
    --btn-bg: #fbbf24;
    --btn-fg: #1a1203;
  }

  /* Settings tabs (API keys / Theme) */
  #settings-panel-keys, #settings-panel-theme {
    display: flex;
    flex-direction: column;
    gap: 11px;
  }
  .settings-tabs {
    display: flex;
    gap: 4px;
    padding: 3px;
    background: var(--profile-bar-bg);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    flex-shrink: 0;
  }
  .settings-tab {
    flex: 1;
    min-height: 34px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    color: var(--text-muted);
    font-size: 0.76rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    transition: all 0.15s;
    -webkit-tap-highlight-color: transparent;
  }
  .settings-tab:hover { color: var(--text); }
  .settings-tab.active {
    background: var(--active-bg);
    border-color: var(--active-border);
    color: var(--text);
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.4);
  }

  /* Theme picker */
  .theme-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 7px;
  }
  .theme-card {
    background: var(--deck-key);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 7px 6px 8px;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    text-align: center;
    transition: all 0.15s;
    -webkit-tap-highlight-color: transparent;
  }
  .theme-card:hover { background: var(--deck-key-hover); border-color: var(--border-highlight); }
  .theme-card.active {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent) inset;
  }
  .theme-swatch {
    width: 100%;
    height: 54px;
    border-radius: var(--radius-sm);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 5px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    overflow: hidden;
  }
  .theme-swatch-bar {
    height: 6px;
    border-radius: 2px;
    width: 72%;
  }
  .theme-swatch-keys {
    display: flex;
    gap: 3px;
  }
  .theme-swatch-keys i {
    display: block;
    width: 12px;
    height: 10px;
    border-radius: 2px;
  }
  .theme-swatch-midnight { background: #09090c; }
  .theme-swatch-midnight .theme-swatch-bar { background: #e4e4e7; }
  .theme-swatch-midnight i { background: #15151e; border: 1px solid #232330; }
  .theme-swatch-phosphor { background: #020604; }
  .theme-swatch-phosphor .theme-swatch-bar { background: #4ade80; }
  .theme-swatch-phosphor i { background: #06150d; border: 1px solid #133a20; }
  .theme-swatch-amber { background: #0a0703; }
  .theme-swatch-amber .theme-swatch-bar { background: #fbbf24; }
  .theme-swatch-amber i { background: #171006; border: 1px solid #3a2a10; }
  .theme-name {
    font-size: 0.76rem;
    font-weight: 700;
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .theme-card.active .theme-name { color: var(--accent); }
  .theme-desc { font-size: 0.75rem; line-height: 1.3; color: var(--text-muted); }
  .theme-check { font-size: 0.70rem; color: var(--accent); min-height: 14px; }
</style>
</head>
<body>

<!-- PIN Overlay -->
<div id="pin-overlay" class="pin-overlay" style="display: none;">
  <div class="pin-card">
    <div class="logo">OMA <span class="tag">LOCK</span></div>
    <div class="pin-subtitle">Enter PIN to access desktop</div>
    <div class="pin-input-wrap">
      <input id="pin-input" type="password" pattern="[0-9]*" inputmode="numeric" maxlength="8" placeholder="••••" autocomplete="off">
    </div>
    <button id="pin-submit-btn">Unlock</button>
    <div id="pin-error" class="pin-error"></div>
  </div>
</div>

<!-- History Modal -->
<div class="modal-overlay" id="history-modal" style="display: none;">
  <div class="modal-card">
    <div class="modal-header">
      <div class="modal-title">Conversation History</div>
      <div class="modal-actions">
        <button class="chat-btn" id="clear-btn" title="Clear conversation">Clear</button>
        <button class="chat-btn" id="close-modal-btn">✕ Close</button>
      </div>
    </div>
    <div class="chat-body" id="chat-body"></div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal-overlay" id="settings-modal" style="display: none;">
  <div class="modal-card" style="height: auto; max-height: 85dvh;">
    <div class="modal-header">
      <div class="modal-title">Settings</div>
      <div class="modal-actions">
        <button class="chat-btn" id="close-settings-btn">✕ Close</button>
      </div>
    </div>

    <!-- Two panes: keys and theme -->
    <div class="settings-tabs" role="tablist">
      <button class="settings-tab active" id="tab-keys" role="tab" aria-selected="true" aria-controls="settings-panel-keys">
        <svg class="icon-svg" style="width:14px;height:14px;" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
        API Keys
      </button>
      <button class="settings-tab" id="tab-theme" role="tab" aria-selected="false" aria-controls="settings-panel-theme">
        <svg class="icon-svg" style="width:14px;height:14px;" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a10 10 0 0 0 0 20 5 5 0 0 1 0-10 5 5 0 0 0 0-10z"></path></svg>
        Theme
      </button>
    </div>

    <div class="settings-body">
      <!-- ===================== API KEYS PANE ===================== -->
      <div id="settings-panel-keys" role="tabpanel" aria-labelledby="tab-keys">
        <!-- Provider Select -->
        <div class="setting-group">
          <label class="setting-label" for="setting-provider">LLM Provider</label>
          <select id="setting-provider" class="setting-select">
            <option value="groq">Groq (Ultra-fast 500+ tok/s, Llama 3.3)</option>
            <option value="openai">OpenAI (GPT-4o mini / GPT-4o)</option>
            <option value="openrouter">OpenRouter (Any open/commercial model)</option>
            <option value="deepseek">DeepSeek (V3 / R1 reasoning)</option>
            <option value="mistral">Mistral AI</option>
            <option value="nvidia">NVIDIA NIM (Free developer tier)</option>
            <option value="ollama">Ollama (100% Offline / Local)</option>
            <option value="custom">Custom (LM Studio, vLLM, LocalAI)</option>
          </select>
          <div class="setting-desc" id="setting-provider-desc">Ultra-fast (~500 tok/s), ideal for real-time voice &amp; commands.</div>
        </div>

        <!-- LLM API Key Field -->
        <div class="setting-group" id="group-api-key">
          <label class="setting-label" for="setting-api-key">
            <span id="label-api-key">API Key</span>
            <span id="setting-key-badge" style="font-size: .68rem; color: var(--text-muted); font-weight: normal;"></span>
          </label>
          <div style="display: flex; gap: 6px;">
            <input type="password" id="setting-api-key" class="setting-input" placeholder="Paste your API key…" autocomplete="off" spellcheck="false" style="flex: 1;">
            <button type="button" class="chat-btn" id="toggle-key-visibility" title="Show/Hide">View</button>
          </div>
          <div class="setting-desc" id="setting-key-desc">Saved to ~/.config/omarchy-voice/env (chmod 600)</div>
        </div>

        <!-- Model Name -->
        <div class="setting-group">
          <label class="setting-label" for="setting-model">Model</label>
          <input type="text" id="setting-model" class="setting-input" placeholder="e.g. llama-3.3-70b-versatile" autocomplete="off" spellcheck="false">
          <div class="setting-desc">Primary LLM planner model for voice and commands.</div>
        </div>

        <!-- Base URL (Custom) -->
        <div class="setting-group" id="group-base-url" style="display: none;">
          <label class="setting-label" for="setting-base-url">Base URL</label>
          <input type="text" id="setting-base-url" class="setting-input" placeholder="http://localhost:1234/v1" autocomplete="off" spellcheck="false">
        </div>

        <!-- Speech-to-Text -->
        <div class="setting-group">
          <label class="setting-label" for="setting-stt">Speech-To-Text (Voice)</label>
          <select id="setting-stt" class="setting-select">
            <option value="auto">Auto (faster-whisper local + cloud fallback)</option>
            <option value="faster-whisper">Local faster-whisper (Offline on PC)</option>
            <option value="groq">Groq Cloud Whisper (Ultra-fast ~200ms)</option>
            <option value="openai">OpenAI Cloud Whisper (whisper-1)</option>
          </select>
          <div class="setting-desc">How voice audio from mic is transcribed to text.</div>
        </div>

        <!-- STT API Key Field -->
        <div class="setting-group" id="group-stt-key">
          <label class="setting-label" for="setting-stt-key">
            <span>Speech-to-Text API Key</span>
            <span id="setting-stt-key-badge" style="font-size: .68rem; color: var(--text-muted); font-weight: normal;"></span>
          </label>
          <div style="display: flex; gap: 6px;">
            <input type="password" id="setting-stt-key" class="setting-input" placeholder="Optional — Groq or OpenAI key for voice…" autocomplete="off" spellcheck="false" style="flex: 1;">
            <button type="button" class="chat-btn" id="toggle-stt-key-visibility" title="Show/Hide">View</button>
          </div>
          <div class="setting-desc" id="setting-stt-key-desc">Saved as STT_API_KEY in the same env file. Leave blank to reuse your LLM key.</div>
        </div>

        <!-- Action Button & Status -->
        <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 4px;">
          <button id="save-settings-btn" class="primary-btn">Test &amp; Save Keys</button>
          <div id="settings-status" class="status-box" style="display: none;"></div>
        </div>
      </div>

      <!-- ===================== THEME PANE ===================== -->
      <div id="settings-panel-theme" role="tabpanel" aria-labelledby="tab-theme" style="display: none;">
        <div class="setting-group">
          <label class="setting-label">Deck Theme</label>
          <div class="setting-desc">Saved on this device only. Applies instantly.</div>
        </div>
        <div class="theme-grid" id="theme-grid">
          <button class="theme-card active" data-theme-choice="midnight" title="Midnight — neutral dark">
            <div class="theme-swatch theme-swatch-midnight">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Midnight</span>
            <span class="theme-desc">Neutral dark. Original deck.</span>
            <span class="theme-check">✓</span>
          </button>
          <button class="theme-card" data-theme-choice="phosphor" title="Phosphor — green CRT terminal">
            <div class="theme-swatch theme-swatch-phosphor">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Phosphor</span>
            <span class="theme-desc">Green-on-black CRT.</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="amber" title="Amber — warm monochrome terminal">
            <div class="theme-swatch theme-swatch-amber">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Amber</span>
            <span class="theme-desc">Warm monochrome terminal.</span>
            <span class="theme-check"></span>
          </button>
        </div>
        <div class="setting-group" style="margin-top: 10px;">
          <div class="setting-desc">Phosphor and Amber swap the whole deck palette — keys, borders, input focus and status colours. Monospace readouts stay monospace.</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Main App Shell -->
<div class="app-shell">

  <!-- Left Cockpit (Top in Portrait, Left Rail in Landscape) -->
  <div class="deck-cockpit">
    <header>
      <div class="brand-group">
        <div class="logo">OMA <span class="tag">DECK</span></div>
        <div id="provider-badge" class="tag" style="display:none; text-transform:uppercase; font-size: 0.58rem;">GROQ</div>
      </div>
      <div class="header-right">
        <div id="status-badge" class="idle">READY</div>
        <button class="icon-chip" id="sound-toggle" title="Toggle OmaDeck Voice Sound">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>
        </button>
        <button class="icon-chip" id="history-toggle" title="Conversation History">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          <span>Logs</span>
        </button>
        <button class="icon-chip" id="settings-toggle" title="AI Settings">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        </button>
      </div>
    </header>

    <!-- Feedback Strip -->
    <div class="reply-strip" id="reply-strip" title="Tap to view logs">
      <svg class="reply-icon" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
      <span class="reply-text" id="latest-reply">Ready. Tap key or speak command.</span>
    </div>

    <div class="notice" id="mic-note" hidden></div>
    <div id="transcript" style="display:none;"></div>
    <div id="mic-hint" style="display:none;"></div>

    <!-- Controls Dock (Mic, Input, Mode) -->
    <div class="deck-controls-dock">
      <!-- Mode Toggle -->
      <div class="mode-bar">
        <button class="mode-pill active" id="mode-cmd">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
          <span>Command</span>
        </button>
        <span class="mode-sep">(or)</span>
        <button class="mode-pill" id="mode-type">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"></rect><line x1="6" y1="8" x2="6" y2="8"></line><line x1="10" y1="8" x2="10" y2="8"></line><line x1="14" y1="8" x2="14" y2="8"></line><line x1="18" y1="8" x2="18" y2="8"></line><line x1="6" y1="12" x2="6" y2="12"></line><line x1="10" y1="12" x2="10" y2="12"></line><line x1="14" y1="12" x2="14" y2="12"></line><line x1="18" y1="12" x2="18" y2="12"></line><line x1="7" y1="16" x2="17" y2="16"></line></svg>
          <span>Direct Type</span>
        </button>
      </div>

      <!-- Aux Keys for Typing -->
      <div class="aux-keys" id="aux-keys" style="display: none;">
        <button class="key-chip" data-key="enter">↵ Enter</button>
        <button class="key-chip" data-key="backspace">⌫ Del</button>
        <button class="key-chip" data-key="tab">Tab ⇥</button>
        <button class="key-chip" data-key="paste">📋 Paste</button>
        <button class="key-chip" data-key="escape">Esc</button>
      </div>

      <!-- Command Bar -->
      <div class="cmd-bar">
        <button id="mic-btn" title="Hold to record voice">
          <svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>
        </button>
        <input id="cmd-input" type="text" placeholder="Type a command…" autocomplete="off" autocorrect="off">
        <button id="type-direct-btn" class="cmd-action-btn" title="Type into PC">Type</button>
        <button id="cmd-send" class="cmd-action-btn">Send</button>
      </div>
    </div>
  </div>

  <!-- Right Deck Bank (Main Macro Surface) -->
  <div class="deck-bank">

    <!-- Workspace Switcher Row (Always Available Above the 4 Profiles) -->
    <div class="workspace-row">
      <button class="ws-key" data-cmd="go to workspace 1">1</button>
      <button class="ws-key" data-cmd="go to workspace 2">2</button>
      <button class="ws-key" data-cmd="go to workspace 3">3</button>
      <button class="ws-key" data-cmd="go to workspace 4">4</button>
      <button class="ws-key" data-cmd="go to workspace 5">5</button>
      <button class="ws-key scratch-key" data-cmd="toggle scratchpad" title="Toggle Scratchpad Terminal">Scratch</button>
    </div>

    <!-- Move Active Window to Workspace / Scratchpad (Always Available Above the 4 Profiles) -->
    <div class="move-to-row">
      <button class="ws-key move-btn" data-cmd="move window to workspace 1" title="Send window to WS 1">➔ 1</button>
      <button class="ws-key move-btn" data-cmd="move window to workspace 2" title="Send window to WS 2">➔ 2</button>
      <button class="ws-key move-btn" data-cmd="move window to workspace 3" title="Send window to WS 3">➔ 3</button>
      <button class="ws-key move-btn" data-cmd="move window to workspace 4" title="Send window to WS 4">➔ 4</button>
      <button class="ws-key move-btn" data-cmd="move window to workspace 5" title="Send window to WS 5">➔ 5</button>
      <button class="ws-key move-btn scratch-key" data-cmd="move window to scratchpad" title="Send window to Scratchpad">➔ Scratch</button>
    </div>

    <!-- Top Hardware Profile Switcher Bar (5 Profiles: Desk, Code, Media, Web, Custom) -->
    <div class="deck-profile-bar" id="deck-profile-bar">
      <button class="profile-pill active" data-profile="desk">
        <svg class="icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
        <span>Desk</span>
      </button>
      <button class="profile-pill" data-profile="code">
        <svg class="icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
        <span>Code</span>
      </button>
      <button class="profile-pill" data-profile="media">
        <svg class="icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>
        <span>Media</span>
      </button>
      <button class="profile-pill" data-profile="web">
        <svg class="icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
        <span>Web</span>
      </button>
      <button class="profile-pill" data-profile="custom">
        <svg class="icon-svg" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
        <span>Custom</span>
      </button>
    </div>

    <!-- PROFILE 1: HYPRLAND / DESKTOP -->
    <div class="profile-view" id="profile-desk" data-profile-section="desk">

      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Window &amp; Layout</span>
          <span class="section-badge">HYPRLAND</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="toggle fullscreen" title="Fullscreen">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="15 3 21 3 21 9"></polyline><polyline points="9 21 3 21 3 15"></polyline><polyline points="21 15 21 21 15 21"></polyline><polyline points="3 9 3 3 9 3"></polyline></svg>
            <span class="label">Fullscr</span>
          </button>
          <button class="chip" data-cmd="toggle float" title="Float / Tile">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><rect x="8" y="8" width="13" height="13" rx="2"></rect></svg>
            <span class="label">Float</span>
          </button>
          <button class="chip" data-cmd="toggle split" title="Toggle Split (H/V)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="12" y1="3" x2="12" y2="21"></line><rect x="3" y="3" width="18" height="18" rx="2"></rect></svg>
            <span class="label">Split H/V</span>
          </button>
          <button class="chip" data-cmd="swap window left" title="Swap Window Left (Super+Shift+Left)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
            <span class="label">Swap ←</span>
          </button>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="previous window" title="Previous Window">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><polyline points="13 8 9 12 13 16"></polyline></svg>
            <span class="label">Prev Win</span>
          </button>
          <button class="chip" data-cmd="next window" title="Next Window">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><polyline points="11 8 15 12 11 16"></polyline></svg>
            <span class="label">Next Win</span>
          </button>
          <button class="chip" data-cmd="swap window right" title="Swap Window Right (Super+Shift+Right)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
            <span class="label">Swap →</span>
          </button>
          <button class="chip chip-danger" data-cmd="close the active window" title="Close Window">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
            <span class="label">Close Win</span>
          </button>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="brightness down" title="Brightness Down">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"></circle><line x1="12" y1="2" x2="12" y2="4"></line><line x1="12" y1="20" x2="12" y2="22"></line><line x1="2" y1="12" x2="4" y2="12"></line><line x1="20" y1="12" x2="22" y2="12"></line></svg>
            <span class="label">Dim</span>
          </button>
          <button class="chip" data-cmd="brightness up" title="Brightness Up">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            <span class="label">Bright</span>
          </button>
          <button class="chip" data-cmd="lock screen" title="Lock Screen">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            <span class="label">Lock</span>
          </button>
          <button class="chip" data-cmd="system sleep" title="Sleep">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            <span class="label">Sleep</span>
          </button>
        </div>
      </section>
    </div>

    <!-- PROFILE 2: CODE & DEVELOPER -->
    <div class="profile-view" id="profile-code" data-profile-section="code" style="display: none;">
      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Git &amp; Version Control</span>
          <span class="section-badge">REPO</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="git status" title="Git Status in Active Terminal">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="18" r="3"></circle><circle cx="6" cy="6" r="3"></circle><circle cx="18" cy="6" r="3"></circle><path d="M18 9v2a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V9"></path><line x1="12" y1="13" x2="12" y2="15"></line></svg>
            <span class="label">Status</span>
          </button>
          <button class="chip" data-cmd="git diff" title="Git Diff in Terminal">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="9" y1="13" x2="15" y2="13"></line><line x1="12" y1="10" x2="12" y2="16"></line></svg>
            <span class="label">Diff</span>
          </button>
          <button class="chip" data-cmd="git pull" title="Git Pull">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M12 5v14"></path><path d="M19 12l-7 7-7-7"></path></svg>
            <span class="label">Pull</span>
          </button>
          <button class="chip" data-cmd="git push" title="Git Push">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M12 19V5"></path><path d="M5 12l7-7 7 7"></path></svg>
            <span class="label">Push</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Process &amp; Terminal</span>
          <span class="section-badge">KILL &amp; RUN</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip chip-danger" data-cmd="kill port 3000" title="Kill process on port 3000">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <span class="label">:3000</span>
          </button>
          <button class="chip chip-danger" data-cmd="kill port 8000" title="Kill process on port 8000">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <span class="label">:8000</span>
          </button>
          <button class="chip chip-danger" data-key="ctrl+c" title="Interrupt Process (Ctrl+C)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1"></rect></svg>
            <span class="label">Ctrl+C</span>
          </button>
          <button class="chip" data-key="ctrl+l" title="Clear Terminal (Ctrl+L)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
            <span class="label">Clear</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Workflow &amp; Clipboard</span>
          <span class="section-badge">DEV TOOLS</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="run tests" title="Run Test Suite in Terminal">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"></polyline><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path></svg>
            <span class="label">Test</span>
          </button>
          <button class="chip" data-cmd="open a new terminal" title="Open New Terminal">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            <span class="label">New Term</span>
          </button>
          <button class="chip" data-key="ctrl+shift+c" title="Terminal Copy (Ctrl+Shift+C)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            <span class="label">Copy</span>
          </button>
          <button class="chip" data-key="ctrl+shift+v" title="Terminal Paste (Ctrl+Shift+V)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect></svg>
            <span class="label">Paste</span>
          </button>
        </div>
      </section>
    </div>

    <!-- PROFILE 3: MEDIA & HARDWARE -->
    <div class="profile-view" id="profile-media" data-profile-section="media" style="display: none;">
      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Playback Controls</span>
          <span class="section-badge">AUDIO</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="previous track" title="Previous Track">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="19 20 9 12 19 4 19 20"></polygon><line x1="5" y1="19" x2="5" y2="5"></line></svg>
            <span class="label">Prev</span>
          </button>
          <button class="chip" data-cmd="media play pause" title="Play / Pause">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
            <span class="label">Play / Pause</span>
          </button>
          <button class="chip" data-cmd="next track" title="Next Track">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="5 4 15 12 5 20 5 4"></polygon><line x1="19" y1="5" x2="19" y2="19"></line></svg>
            <span class="label">Next</span>
          </button>
          <button class="chip" data-cmd="media stop" title="Stop">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1"></rect></svg>
            <span class="label">Stop</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Volume &amp; Output</span>
          <span class="section-badge">SOUND</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="volume down" title="Volume Down">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="15" y1="12" x2="19" y2="12"></line></svg>
            <span class="label">Vol −</span>
          </button>
          <button class="chip" data-cmd="volume up" title="Volume Up">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>
            <span class="label">Vol +</span>
          </button>
          <button class="chip" data-cmd="mute audio" title="Mute Desktop Speakers">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg>
            <span class="label">Mute</span>
          </button>
          <button class="chip" data-cmd="toggle audio sink" title="Switch Output Sink (Headphones / Speakers)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M3 18v-6a9 9 0 0 1 18 0v6"></path><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"></path></svg>
            <span class="label">Sink</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Hardware &amp; Voice</span>
          <span class="section-badge">DESK TOOLS</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="toggle mic mute" title="Hardware PC Mic Mute Toggle">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="1" y1="1" x2="23" y2="23"></line><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"></path><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>
            <span class="label">PC Mic</span>
          </button>
          <button class="chip" id="speak-toggle" title="Toggle Phone Voice TTS">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="22"></line></svg>
            <span class="label">Voice On</span>
          </button>
          <button class="chip" data-cmd="take screenshot" title="Capture Screenshot">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"></path><circle cx="12" cy="13" r="4"></circle></svg>
            <span class="label">Shot</span>
          </button>
          <button class="chip" data-cmd="open menu" title="App Menu Launcher">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
            <span class="label">Menu</span>
          </button>
        </div>
      </section>
    </div>

    <!-- PROFILE 4: BROWSER & WEB -->
    <div class="profile-view" id="profile-web" data-profile-section="web" style="display: none;">
      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Navigation</span>
          <span class="section-badge">HISTORY &amp; SCROLL</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="browser back" title="Back">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
            <span class="label">Back</span>
          </button>
          <button class="chip" data-cmd="browser forward" title="Forward">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
            <span class="label">Forward</span>
          </button>
          <button class="chip" data-cmd="swipe up" title="Scroll Up">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="18 15 12 9 6 15"></polyline></svg>
            <span class="label">Scroll Up</span>
          </button>
          <button class="chip" data-cmd="swipe down" title="Scroll Down">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"></polyline></svg>
            <span class="label">Scroll Dn</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Tabs &amp; URL</span>
          <span class="section-badge">CONTROLS</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="previous tab" title="Previous Tab (Ctrl+Shift+Tab)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><polyline points="13 8 9 12 13 16"></polyline></svg>
            <span class="label">Prev Tab</span>
          </button>
          <button class="chip" data-cmd="next tab" title="Next Tab (Ctrl+Tab)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><polyline points="11 8 15 12 11 16"></polyline></svg>
            <span class="label">Next Tab</span>
          </button>
          <button class="chip" data-cmd="new tab" title="New Tab (Ctrl+T)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>
            <span class="label">New Tab</span>
          </button>
          <button class="chip chip-danger" data-cmd="close the active tab" title="Close Tab (Ctrl+W)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"></rect><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="9" y2="15"></line></svg>
            <span class="label">Close Tab</span>
          </button>
        </div>

        <div class="section-header" style="margin-top: 4px;">
          <span class="section-title">Controls &amp; Zoom</span>
          <span class="section-badge">VIEW</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="address bar" title="Address Bar (Ctrl+L)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
            <span class="label">URL Bar</span>
          </button>
          <button class="chip" data-cmd="reload page" title="Reload (Ctrl+R)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
            <span class="label">Reload</span>
          </button>
          <button class="chip" data-cmd="zoom in" title="Zoom In (Ctrl +)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="11" y1="8" x2="11" y2="14"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            <span class="label">Zoom +</span>
          </button>
          <button class="chip" data-cmd="zoom out" title="Zoom Out (Ctrl -)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line><line x1="8" y1="11" x2="14" y2="11"></line></svg>
            <span class="label">Zoom −</span>
          </button>
        </div>
      </section>
    </div>

    <!-- PROFILE 5: CUSTOM & SYSTEM (Clean Custom Manager: btop, T3 Dashboard, Devices, Automations) -->
    <div class="profile-view" id="profile-custom" data-profile-section="custom" style="display: none;">
      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Dev &amp; System</span>
          <span class="section-badge">CUSTOM</span>
        </div>
        <div class="btn-grid-4">
          <button class="chip" data-cmd="open btop" title="Btop Hardware & Task Manager (CPU, RAM, Disks, Network, Processes)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
            <span class="label">Btop</span>
          </button>
          <button class="chip" data-cmd="open t3 dashboard" title="Open T3 Code Workspace Dashboard (Port 3773)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
            <span class="label">T3 Dash</span>
          </button>
          <button class="chip" data-cmd="open inspector" title="Open Ports, Devices & Servers Inspector GUI">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"></rect><rect x="2" y="14" width="20" height="8" rx="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
            <span class="label">Devices</span>
          </button>
          <button class="chip" data-cmd="open lazygit" title="Lazygit: Terminal UI for git — stage, commit, branch, rebase">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="6" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><path d="M6 9v6"></path><path d="M18 9a9 9 0 0 1-9 9"></path><circle cx="18" cy="6" r="3"></circle></svg>
            <span class="label">Lazygit</span>
          </button>
          <button class="chip" data-cmd="kill app" title="Kill App: Click crosshair on any stuck window to terminate it">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line></svg>
            <span class="label">Kill App</span>
          </button>
          <button class="chip" data-cmd="open opencode" title="OpenCode: AI coding agent terminal">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            <span class="label">OpenCode</span>
          </button>
          <button class="chip" data-cmd="toggle zen mode" title="Zen Mode: Toggle top bar on/off for distraction-free view">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>
            <span class="label">Zen Mode</span>
          </button>
          <button class="chip" data-cmd="toggle caffeine" title="Caffeine: Keep laptop display awake (inhibit sleep)">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M18 8h1a4 4 0 0 1 0 8h-1"></path><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"></path><line x1="6" y1="1" x2="6" y2="4"></line><line x1="10" y1="1" x2="10" y2="4"></line><line x1="14" y1="1" x2="14" y2="4"></line></svg>
            <span class="label">Caffeine</span>
          </button>
          <button class="chip" data-cmd="toggle nightlight" title="Night Light: Warm screen color temperature">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            <span class="label">Night Light</span>
          </button>
          <button class="chip" data-cmd="open docker tui" title="Docker: Open lazydocker to inspect containers, images and logs">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><path d="M21 8v13H3V8"></path><path d="M1 3h22v5H1z"></path><line x1="10" y1="12" x2="14" y2="12"></line><line x1="12" y1="12" x2="12" y2="16"></line></svg>
            <span class="label">Docker</span>
          </button>
          <button class="chip" data-cmd="open clipboard" title="Clipboard: Open history and paste anything you copied recently">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="8" y="2" width="8" height="4" rx="1"></rect><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><line x1="9" y1="12" x2="15" y2="12"></line><line x1="9" y1="16" x2="13" y2="16"></line></svg>
            <span class="label">Clipboard</span>
          </button>
          <button class="chip" data-cmd="system menu" title="System Menu: Toggle Omarchy system settings menu">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line></svg>
            <span class="label">Sys Menu</span>
          </button>
        </div>
      </section>
    </div>

  </div>

</div>

<script>
const HAS_PIN = HAS_PIN_PLACEHOLDER;
let TOKEN = localStorage.getItem('oma_auth_token') || "TOKEN_PLACEHOLDER";
let headers = {"X-Token": TOKEN, "Content-Type": "application/json"};

function haptic(ms = 8) {
  if (navigator.vibrate) {
    try { navigator.vibrate(ms); } catch(e) {}
  }
}

function updateToken(tok) {
  TOKEN = tok;
  localStorage.setItem('oma_auth_token', tok);
  headers = {"X-Token": TOKEN, "Content-Type": "application/json"};
}

const pinOverlay = document.getElementById('pin-overlay');
const pinInput = document.getElementById('pin-input');
const pinError = document.getElementById('pin-error');
const pinSubmit = document.getElementById('pin-submit-btn');

function showPinScreen() {
  if (pinOverlay && pinOverlay.style.display !== 'flex') {
    pinOverlay.style.display = 'flex';
    pinInput.value = '';
    pinError.textContent = '';
    setTimeout(() => pinInput.focus(), 150);
  }
}

function hidePinScreen() {
  if (pinOverlay) pinOverlay.style.display = 'none';
  loadHistory();
  pollState();
}

async function submitPin() {
  const pin = pinInput.value.trim();
  if (!pin) return;
  haptic(10);
  pinError.textContent = 'Verifying…';
  try {
    const r = await fetch('/auth', {
      method: 'POST',
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({pin})
    });
    const d = await r.json();
    if (d.ok && d.token) {
      updateToken(d.token);
      hidePinScreen();
    } else {
      pinError.textContent = d.error || 'Incorrect PIN';
      pinInput.value = '';
      pinInput.focus();
    }
  } catch(e) {
    pinError.textContent = 'Connection error';
  }
}

if (pinSubmit) pinSubmit.onclick = submitPin;
if (pinInput) {
  pinInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') submitPin();
  });
  pinInput.addEventListener('input', () => {
    if (pinInput.value.length === 4) submitPin();
  });
}

let _reloadingAuth = false;
function checkAuth(r) {
  if (r && (r.status === 401 || r.status === 403)) {
    if (!HAS_PIN) {
      if (TOKEN !== "TOKEN_PLACEHOLDER" && "TOKEN_PLACEHOLDER") {
        updateToken("TOKEN_PLACEHOLDER");
        return true;
      }
      if (!_reloadingAuth) {
        _reloadingAuth = true;
        setTimeout(() => { window.location.reload(); }, 1200);
      }
      return true;
    }
    localStorage.removeItem('oma_auth_token');
    TOKEN = "";
    headers = {"X-Token": "", "Content-Type": "application/json"};
    showPinScreen();
    return true;
  }
  return false;
}

// --- state & history ---
const badge = document.getElementById('status-badge');
const chatBody = document.getElementById('chat-body');
const historyModal = document.getElementById('history-modal');
const historyToggle = document.getElementById('history-toggle');
const replyStrip = document.getElementById('reply-strip');
const latestReply = document.getElementById('latest-reply');
const closeModalBtn = document.getElementById('close-modal-btn');
const providerBadge = document.getElementById('provider-badge');

function openHistoryModal() {
  haptic(8);
  if (historyModal) {
    historyModal.style.display = 'flex';
    chatBody.scrollTop = chatBody.scrollHeight;
  }
}

function closeHistoryModal() {
  if (historyModal) historyModal.style.display = 'none';
}

if (historyToggle) historyToggle.onclick = openHistoryModal;
if (replyStrip) replyStrip.onclick = openHistoryModal;
if (closeModalBtn) closeModalBtn.onclick = closeHistoryModal;
if (historyModal) {
  historyModal.addEventListener('click', e => {
    if (e.target === historyModal) closeHistoryModal();
  });
}

function addMsg(role, text) {
  const d = document.createElement('div');
  d.className = 'msg ' + (role === 'you' ? 'you' : (role === 'oma' ? 'oma' : 'sys'));
  d.textContent = text;
  chatBody.appendChild(d);
  chatBody.scrollTop = chatBody.scrollHeight;
  if (latestReply) {
    if (role === 'oma') latestReply.textContent = text;
    else if (role === 'you') latestReply.textContent = '▶ ' + text;
  }
}

async function loadHistory() {
  if (HAS_PIN && !TOKEN) { showPinScreen(); return; }
  try {
    const r = await fetch('/history', {headers});
    if (checkAuth(r)) return;
    if (!r.ok) return;
    const d = await r.json();
    chatBody.querySelectorAll('.msg').forEach(el => el.remove());
    (d.turns || []).forEach(t => {
      const role = t.role === 'user' ? 'you' : 'oma';
      if (t.content) addMsg(role, t.content);
    });
    if (!d.turns || !d.turns.length) {
      addMsg('sys', 'No commands yet. Tap a macro key or use voice.');
    }
  } catch (e) {}
}

const clearBtn = document.getElementById('clear-btn');
if (clearBtn) {
  clearBtn.onclick = async () => {
    haptic(10);
    try {
      const r = await fetch('/clear', {method: 'POST', headers, body: JSON.stringify({})});
      if (checkAuth(r)) return;
      chatBody.querySelectorAll('.msg').forEach(el => el.remove());
      addMsg('sys', 'Conversation cleared.');
      if (latestReply) latestReply.textContent = 'Conversation cleared.';
    } catch (e) {}
  };
}

let _pollInFlight = false;
async function pollState() {
  if (document.hidden) return;
  if (!TOKEN) return;
  if (_pollInFlight) return;
  _pollInFlight = true;
  try {
    const r = await fetch('/state', {headers});
    if (checkAuth(r)) return;
    if (!r.ok) return;
    const s = await r.json();
    const st = s.status || 'idle';
    badge.textContent = st.toUpperCase();
    badge.className = st;
  } catch {}
  finally {
    _pollInFlight = false;
  }
}
setInterval(pollState, 1000);

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && TOKEN) {
    pollState();
  }
});

if (HAS_PIN && !TOKEN) {
  showPinScreen();
} else {
  loadHistory();
  pollState();
}

// --- settings modal ---
const settingsModal = document.getElementById('settings-modal');
const settingsToggle = document.getElementById('settings-toggle');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const settingProvider = document.getElementById('setting-provider');
const settingProviderDesc = document.getElementById('setting-provider-desc');
const groupApiKey = document.getElementById('group-api-key');
const labelApiKey = document.getElementById('label-api-key');
const settingKeyBadge = document.getElementById('setting-key-badge');
const settingApiKey = document.getElementById('setting-api-key');
const toggleKeyVisibility = document.getElementById('toggle-key-visibility');
const settingModel = document.getElementById('setting-model');
const groupBaseUrl = document.getElementById('group-base-url');
const settingBaseUrl = document.getElementById('setting-base-url');
const settingStt = document.getElementById('setting-stt');
const settingSttKey = document.getElementById('setting-stt-key');
const settingSttKeyBadge = document.getElementById('setting-stt-key-badge');
const groupSttKey = document.getElementById('group-stt-key');
const toggleSttKeyVisibility = document.getElementById('toggle-stt-key-visibility');
const tabKeys = document.getElementById('tab-keys');
const tabTheme = document.getElementById('tab-theme');
const panelKeys = document.getElementById('settings-panel-keys');
const panelTheme = document.getElementById('settings-panel-theme');
const saveSettingsBtn = document.getElementById('save-settings-btn');
const settingsStatus = document.getElementById('settings-status');

let settingsCatalog = {};

// --- settings tabs ---------------------------------------------------------
function showSettingsTab(name) {
  const keys = name !== 'theme';
  if (tabKeys) { tabKeys.classList.toggle('active', keys); tabKeys.setAttribute('aria-selected', keys ? 'true' : 'false'); }
  if (tabTheme) { tabTheme.classList.toggle('active', !keys); tabTheme.setAttribute('aria-selected', keys ? 'false' : 'true'); }
  if (panelKeys) panelKeys.style.display = keys ? 'flex' : 'none';
  if (panelTheme) panelTheme.style.display = keys ? 'none' : 'flex';
}
if (tabKeys) tabKeys.onclick = () => { haptic(6); showSettingsTab('keys'); };
if (tabTheme) tabTheme.onclick = () => { haptic(6); showSettingsTab('theme'); };

// --- theme picker ----------------------------------------------------------
const THEME_META = {
  midnight: '#09090c',
  phosphor: '#020604',
  amber: '#0a0703'
};

function currentTheme() {
  return document.documentElement.dataset.theme || 'midnight';
}

function applyTheme(name) {
  if (!THEME_META[name]) name = 'midnight';
  document.documentElement.dataset.theme = name;
  try { localStorage.setItem('oma-deck-theme', name); } catch (e) {}
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', THEME_META[name]);
  document.querySelectorAll('.theme-card').forEach(card => {
    const active = card.dataset.themeChoice === name;
    card.classList.toggle('active', active);
    const check = card.querySelector('.theme-check');
    if (check) check.textContent = active ? '✓' : '';
  });
}

document.querySelectorAll('.theme-card').forEach(card => {
  card.onclick = () => {
    haptic(10);
    applyTheme(card.dataset.themeChoice);
    if (latestReply) latestReply.textContent = 'Theme: ' + card.dataset.themeChoice;
  };
});

// The inline head script already applied the saved theme; sync the UI to it.
applyTheme(currentTheme());

function openSettingsModal() {
  haptic(8);
  if (settingsModal) {
    settingsModal.style.display = 'flex';
    loadSettings();
  }
}

function closeSettingsModal() {
  if (settingsModal) settingsModal.style.display = 'none';
}

if (settingsToggle) settingsToggle.onclick = openSettingsModal;
if (closeSettingsBtn) closeSettingsBtn.onclick = closeSettingsModal;
if (settingsModal) {
  settingsModal.addEventListener('click', e => {
    if (e.target === settingsModal) closeSettingsModal();
  });
}

if (toggleKeyVisibility && settingApiKey) {
  toggleKeyVisibility.onclick = () => {
    haptic(6);
    if (settingApiKey.type === 'password') {
      settingApiKey.type = 'text';
      toggleKeyVisibility.textContent = 'Hide';
    } else {
      settingApiKey.type = 'password';
      toggleKeyVisibility.textContent = 'View';
    }
  };
}

if (toggleSttKeyVisibility && settingSttKey) {
  toggleSttKeyVisibility.onclick = () => {
    haptic(6);
    if (settingSttKey.type === 'password') {
      settingSttKey.type = 'text';
      toggleSttKeyVisibility.textContent = 'Hide';
    } else {
      settingSttKey.type = 'password';
      toggleSttKeyVisibility.textContent = 'View';
    }
  };
}

function updateSttUI() {
  if (!settingStt) return;
  const cloud = settingStt.value !== 'faster-whisper';
  if (groupSttKey) groupSttKey.style.display = cloud ? 'flex' : 'none';
  const desc = document.getElementById('setting-stt-key-desc');
  if (desc) {
    if (settingStt.value === 'groq') {
      desc.textContent = 'Groq Whisper key (gsk_…). Leave blank to reuse GROQ_API_KEY.';
    } else if (settingStt.value === 'openai') {
      desc.textContent = 'OpenAI key (sk-…). Leave blank to reuse OPENAI_API_KEY.';
    } else {
      desc.textContent = 'Saved as STT_API_KEY in the same env file. Leave blank to reuse your LLM key.';
    }
  }
}
if (settingStt) settingStt.onchange = updateSttUI;

function updateProviderUI(provKey) {
  const p = settingsCatalog[provKey] || {};
  if (settingProviderDesc) settingProviderDesc.textContent = p.desc || '';
  if (groupBaseUrl) groupBaseUrl.style.display = (provKey === 'custom') ? 'flex' : 'none';
  if (groupApiKey) groupApiKey.style.display = (provKey === 'ollama') ? 'none' : 'flex';
  if (labelApiKey) labelApiKey.textContent = p.api_key_env ? `API Key (${p.api_key_env})` : 'API Key';
  if (p.default_model && (!settingModel.value || Object.values(settingsCatalog).some(x => x.default_model === settingModel.value))) {
    settingModel.value = p.default_model;
  }
  if (providerBadge) {
    providerBadge.textContent = provKey.toUpperCase();
    providerBadge.style.display = 'inline-block';
  }
}

if (settingProvider) {
  settingProvider.onchange = () => {
    updateProviderUI(settingProvider.value);
  };
}

async function loadSettings() {
  if (HAS_PIN && !TOKEN) return;
  try {
    const r = await fetch('/settings', {headers});
    if (checkAuth(r)) return;
    if (!r.ok) return;
    const data = await r.json();
    settingsCatalog = data.presets || {};
    if (settingProvider && data.provider) {
      settingProvider.value = data.provider;
    }
    if (settingModel && data.model) {
      settingModel.value = data.model;
    }
    if (settingBaseUrl && data.base_url) {
      settingBaseUrl.value = data.base_url;
    }
    if (settingStt && data.stt) {
      settingStt.value = data.stt;
    }
    updateSttUI();
    if (settingSttKeyBadge) {
      if (data.stt_api_key_set) {
        settingSttKeyBadge.textContent = '✓ Set (' + data.stt_api_key_masked + ')';
        settingSttKeyBadge.style.color = '#86efac';
        if (settingSttKey) settingSttKey.placeholder = 'Enter new key to update…';
      } else {
        settingSttKeyBadge.textContent = 'Not set — falling back to LLM key';
        settingSttKeyBadge.style.color = 'var(--text-muted)';
        if (settingSttKey) settingSttKey.placeholder = 'Optional — Groq or OpenAI key for voice…';
      }
    }
    if (settingKeyBadge) {
      if (data.api_key_set) {
        settingKeyBadge.textContent = '✓ Configured (' + data.api_key_masked + ')';
        settingKeyBadge.style.color = '#86efac';
        if (settingApiKey) settingApiKey.placeholder = 'Enter new key to update…';
      } else {
        settingKeyBadge.textContent = 'Not configured';
        settingKeyBadge.style.color = 'var(--text-muted)';
        if (settingApiKey) settingApiKey.placeholder = 'Paste your API key…';
      }
    }
    updateProviderUI(settingProvider.value);
  } catch (e) {}
}

loadSettings();

if (saveSettingsBtn) {
  saveSettingsBtn.onclick = async () => {
    const prov = settingProvider.value;
    const key = settingApiKey.value.trim();
    const model = settingModel.value.trim();
    const baseUrl = settingBaseUrl.value.trim();
    const stt = settingStt.value;
    const sttKey = settingSttKey ? settingSttKey.value.trim() : '';

    haptic(10);
    saveSettingsBtn.disabled = true;
    saveSettingsBtn.textContent = 'Testing connection…';
    if (settingsStatus) {
      settingsStatus.style.display = 'block';
      settingsStatus.className = 'status-box info';
      settingsStatus.textContent = 'Verifying credentials with ' + (settingsCatalog[prov]?.name || prov) + '…';
    }

    try {
      const r = await fetch('/settings', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          provider: prov,
          api_key: key,
          model: model,
          base_url: baseUrl,
          stt: stt,
          stt_api_key: sttKey,
          test: true,
        }),
      });
      if (checkAuth(r)) return;
      const res = await r.json();
      if (res.ok) {
        settingsStatus.className = 'status-box success';
        settingsStatus.textContent = '✓ ' + (res.message || 'Saved successfully!');
        if (settingApiKey) settingApiKey.value = '';
        if (settingSttKey) settingSttKey.value = '';
        if (latestReply) latestReply.textContent = '✓ Keys saved · ' + (settingsCatalog[prov]?.name || prov);
        await loadSettings();
        setTimeout(() => { closeSettingsModal(); }, 1800);
      } else {
        settingsStatus.className = 'status-box error';
        settingsStatus.textContent = '✕ ' + (res.error || 'Verification failed');
      }
    } catch (e) {
      settingsStatus.className = 'status-box error';
      settingsStatus.textContent = '✕ Error: ' + e;
    } finally {
      saveSettingsBtn.disabled = false;
      saveSettingsBtn.textContent = 'Test & Save Keys';
    }
  };
}

if (window.location.hash === '#settings') {
  openSettingsModal();
}

// --- send command ---
async function sendCmd(text, fromVoice, logYou) {
  if (!text || !text.trim()) return;
  if (HAS_PIN && !TOKEN) { showPinScreen(); return; }
  haptic(8);
  if (logYou === undefined) logYou = true;
  if (latestReply) latestReply.textContent = '▶ ' + text;
  if (logYou) addMsg('you', text);
  try {
    const r = await fetch('/cmd', {
      method: 'POST',
      headers,
      body: JSON.stringify({text}),
    });
    if (checkAuth(r)) return;
    const d = await r.json();
    if (d.reply) { addMsg('oma', d.reply); speak(d.reply); }
  } catch(e) {
    addMsg('sys', 'Error: ' + e);
  }
}

// --- direct typing & mode switching ---
let activeMode = 'cmd'; // 'cmd' or 'type'
const modeCmdBtn = document.getElementById('mode-cmd');
const modeTypeBtn = document.getElementById('mode-type');
const auxKeys = document.getElementById('aux-keys');
const cmdInput = document.getElementById('cmd-input');
const cmdSend = document.getElementById('cmd-send');
const typeDirectBtn = document.getElementById('type-direct-btn');

function setMode(mode) {
  haptic(8);
  activeMode = mode;
  if (modeCmdBtn) modeCmdBtn.classList.toggle('active', mode === 'cmd');
  if (modeTypeBtn) modeTypeBtn.classList.toggle('active', mode === 'type');
  if (auxKeys) auxKeys.style.display = (mode === 'type') ? 'grid' : 'none';
  if (cmdInput) {
    cmdInput.placeholder = (mode === 'type')
      ? 'Type text into active PC app…'
      : 'Type a command…';
    cmdInput.focus();
  }
  if (cmdSend) {
    cmdSend.textContent = (mode === 'type') ? 'Type ↵' : 'Send';
  }
}

if (modeCmdBtn) modeCmdBtn.onclick = () => setMode('cmd');
if (modeTypeBtn) modeTypeBtn.onclick = () => setMode('type');

async function directType(text, enter) {
  if (!text) return;
  if (HAS_PIN && !TOKEN) { showPinScreen(); return; }
  haptic(8);
  if (latestReply) latestReply.textContent = '⌨ ' + text + (enter ? ' ↵' : '');
  try {
    const r = await fetch('/type', {
      method: 'POST',
      headers,
      body: JSON.stringify({text, enter: !!enter})
    });
    if (checkAuth(r)) return;
    const d = await r.json();
    if (d.ok) {
      if (latestReply) latestReply.textContent = '✓ Typed: ' + text;
    } else {
      if (latestReply) latestReply.textContent = '⚠ Typing failed: ' + (d.error || 'error');
    }
  } catch(e) {
    if (latestReply) latestReply.textContent = '⚠ Typing error: ' + e;
  }
}

async function sendKey(key) {
  if (!key) return;
  if (HAS_PIN && !TOKEN) { showPinScreen(); return; }
  haptic(10);
  if (latestReply) latestReply.textContent = 'Key: ' + key;
  try {
    const r = await fetch('/type', {
      method: 'POST',
      headers,
      body: JSON.stringify({key})
    });
    if (checkAuth(r)) return;
    const d = await r.json();
    if (d.ok) {
      if (latestReply) latestReply.textContent = '✓ Key: ' + key;
    } else {
      if (latestReply) latestReply.textContent = '⚠ Key failed: ' + (d.error || 'error');
    }
  } catch(e) {}
}

document.querySelectorAll('.key-chip[data-key]').forEach(b => {
  b.addEventListener('click', () => sendKey(b.dataset.key));
});

if (typeDirectBtn) {
  typeDirectBtn.onclick = () => {
    const val = cmdInput.value;
    if (val) {
      directType(val, false);
      cmdInput.value = '';
    }
  };
}

if (cmdSend) {
  cmdSend.onclick = () => {
    const val = cmdInput.value;
    if (!val) return;
    if (activeMode === 'type') {
      directType(val, true);
    } else {
      sendCmd(val);
    }
    cmdInput.value = '';
  };
}

if (cmdInput) {
  cmdInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      cmdSend.click();
    }
  });
}

// --- Deck Profile Switcher Logic ---
const profileTabs = document.querySelectorAll('.profile-pill');
const profileSections = document.querySelectorAll('.profile-view');

function setProfile(profName) {
  haptic(8);
  localStorage.setItem('oma-deck-profile', profName);
  profileTabs.forEach(p => p.classList.toggle('active', p.dataset.profile === profName));
  profileSections.forEach(s => {
    s.style.display = (s.dataset.profileSection === profName) ? 'flex' : 'none';
  });
}

profileTabs.forEach(tab => {
  tab.addEventListener('click', () => setProfile(tab.dataset.profile));
});

// Restore saved profile
const savedProfile = localStorage.getItem('oma-deck-profile') || 'desk';
setProfile(savedProfile);

// --- Chip & Key Triggers ---
document.querySelectorAll('.chip[data-cmd]').forEach(c => {
  c.addEventListener('click', () => sendCmd(c.dataset.cmd));
});
document.querySelectorAll('.chip[data-key]').forEach(c => {
  c.addEventListener('click', () => sendKey(c.dataset.key));
});
document.querySelectorAll('.ws-key[data-cmd]').forEach(c => {
  c.addEventListener('click', () => sendCmd(c.dataset.cmd));
});

// --- spoken replies ---
let speakOn = localStorage.getItem('oma-speak') !== '0';
const speakBtn = document.getElementById('speak-toggle');
const soundToggleBtn = document.getElementById('sound-toggle');

function toggleSound() {
  haptic(10);
  speakOn = !speakOn;
  localStorage.setItem('oma-speak', speakOn ? '1' : '0');
  if (!speakOn && window.speechSynthesis) speechSynthesis.cancel();
  paintSpeak();
  if (latestReply) latestReply.textContent = speakOn ? '🔊 OmaDeck voice sound unmuted' : '🔇 OmaDeck voice sound muted';
}

function paintSpeak() {
  if (speakBtn) {
    speakBtn.classList.toggle('off', !speakOn);
    speakBtn.innerHTML = speakOn
      ? '<svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg><span class="label">Voice On</span>'
      : '<svg class="icon icon-svg" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg><span class="label">Voice Off</span>';
  }
  if (soundToggleBtn) {
    soundToggleBtn.classList.toggle('muted', !speakOn);
    soundToggleBtn.title = speakOn ? 'OmaDeck Voice Sound: On (Tap to Mute)' : 'OmaDeck Voice Sound: Muted (Tap to Unmute)';
    soundToggleBtn.innerHTML = speakOn
      ? '<svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M15.54 8.46a5 5 0 0 1 0 7.07"></path><path d="M19.07 4.93a10 10 0 0 1 0 14.14"></path></svg>'
      : '<svg class="icon-svg" style="width:13px;height:13px;color:#ef4444;" viewBox="0 0 24 24"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><line x1="23" y1="9" x2="17" y2="15"></line><line x1="17" y1="9" x2="23" y2="15"></line></svg>';
  }
}
paintSpeak();
if (speakBtn) speakBtn.addEventListener('click', toggleSound);
if (soundToggleBtn) soundToggleBtn.addEventListener('click', toggleSound);
function speak(text) {
  if (!speakOn || !text || !window.speechSynthesis) return;
  try {
    speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(String(text).replace(/[*_`#]/g, ''));
    u.rate = 1.05;
    speechSynthesis.speak(u);
  } catch (e) {}
}

// --- mic recording ---
const SECURE_URL = "HTTPS_PLACEHOLDER";
const micBtn = document.getElementById('mic-btn');
const hint   = document.getElementById('mic-hint');
const trans  = document.getElementById('transcript');
const note   = document.getElementById('mic-note');

let recorder = null;
let chunks = [];
let holding = false;
let holdTimer = null;

function showNote(html) { if (note) { note.innerHTML = html; note.hidden = false; } }

function micProblem() {
  if (!window.isSecureContext) return 'insecure';
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return 'insecure';
  if (typeof MediaRecorder === 'undefined') return 'unsupported';
  return '';
}

if (micProblem() === 'insecure') {
  const link = SECURE_URL
    ? '<a href="' + SECURE_URL + '">Open HTTPS address</a>'
    : 'HTTPS not running';
  showNote('<b>Mic needs HTTPS:</b> ' + link + ' to record voice.');
} else if (micProblem() === 'unsupported') {
  showNote('Audio recording not supported in this browser.');
}

function pickMime() {
  const types = ['audio/webm;codecs=opus', 'audio/webm',
                 'audio/mp4', 'audio/mp4;codecs=mp4a.40.2', 'audio/aac'];
  for (const t of types) {
    try { if (MediaRecorder.isTypeSupported(t)) return t; } catch (e) {}
  }
  return '';
}

async function startRecording() {
  if (holding || micBtn.classList.contains('thinking')) return;
  if (micProblem()) return;
  holding = true;
  haptic(14);

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: {echoCancellation: true, noiseSuppression: true},
    });
  } catch (e) {
    holding = false;
    if (latestReply) latestReply.textContent = '⚠ Mic blocked: ' + ((e && e.name) || e);
    return;
  }
  if (!holding) { stream.getTracks().forEach(t => t.stop()); return; }

  chunks = [];
  const mime = pickMime();
  try {
    recorder = mime ? new MediaRecorder(stream, {mimeType: mime})
                    : new MediaRecorder(stream);
  } catch (e) {
    recorder = new MediaRecorder(stream);
  }
  recorder.ondataavailable = e => { if (e.data && e.data.size) chunks.push(e.data); };
  recorder.onstop = async () => {
    stream.getTracks().forEach(t => t.stop());
    const blob = new Blob(chunks, {type: recorder.mimeType || 'audio/webm'});
    recorder = null;
    await sendAudio(blob);
  };
  recorder.start();
  micBtn.classList.add('recording');
  if (latestReply) latestReply.textContent = '● Recording… release to send';
  holdTimer = setTimeout(stopRecording, 60000);
}

function stopRecording() {
  if (!holding) return;
  holding = false;
  haptic(10);
  clearTimeout(holdTimer);
  if (recorder && recorder.state === 'recording') {
    recorder.stop();
    micBtn.classList.remove('recording');
    micBtn.classList.add('thinking');
    if (latestReply) latestReply.textContent = 'Processing audio…';
  }
}

function toBase64(u8) {
  let s = '';
  const step = 0x8000;
  for (let i = 0; i < u8.length; i += step) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + step));
  }
  return btoa(s);
}

async function sendAudio(blob) {
  if (HAS_PIN && !TOKEN) { showPinScreen(); return; }
  const buf = await blob.arrayBuffer();
  const b64 = toBase64(new Uint8Array(buf));
  try {
    const r = await fetch('/transcribe', {
      method: 'POST',
      headers,
      body: JSON.stringify({audio_b64: b64, mime: blob.type}),
    });
    if (checkAuth(r)) return;
    const d = await r.json();
    const heard = (d.heard || '').trim();
    if (!heard || heard.startsWith('[stt error')) {
      if (latestReply) latestReply.textContent = '⚠ Could not understand — try again.';
      addMsg('sys', 'Could not make that out — try again.');
      return;
    }
    if (latestReply) latestReply.textContent = '▶ ' + heard;
    addMsg('you', heard);
    if (activeMode === 'type') {
      await directType(heard, true);
    } else {
      await sendCmd(heard, true, false);
    }
  } catch(e) {
    addMsg('sys', 'Error: ' + e);
  } finally {
    micBtn.classList.remove('thinking');
  }
}

micBtn.addEventListener('pointerdown',  e => { e.preventDefault(); startRecording(); });
micBtn.addEventListener('pointerup',    e => { e.preventDefault(); stopRecording(); });
micBtn.addEventListener('pointercancel', () => stopRecording());
micBtn.addEventListener('contextmenu',  e => e.preventDefault());
window.addEventListener('blur', () => stopRecording());
</script>
</body>
</html>
"""


def _type_text(text: str, enter: bool = False) -> tuple[bool, str]:
    """Type text directly into whatever input/window is currently focused on PC."""
    if not shutil.which("wtype"):
        return False, "wtype is not installed"
    try:
        res = subprocess.run(["wtype", "--", text], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return False, res.stderr.strip() or "wtype typing failed"
        if enter:
            time.sleep(0.04)
            subprocess.run(["wtype", "-k", "Return"], capture_output=True, timeout=5)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _press_key(key: str) -> tuple[bool, str]:
    """Send a single key press or key combination (e.g. Return, Backspace, Ctrl+C, Ctrl+V, Alt+Left)."""
    if not shutil.which("wtype"):
        return False, "wtype is not installed"

    k_raw = key.strip()
    k_lower = k_raw.lower()

    # Aliases
    aliases = {
        "sigint": "ctrl+c",
        "interrupt": "ctrl+c",
        "paste": "ctrl+v",
        "clear": "ctrl+l",
        "term_copy": "ctrl+shift+c",
        "term_paste": "ctrl+shift+v",
    }
    if k_lower in aliases:
        k_lower = aliases[k_lower]
        k_raw = k_lower

    key_map = {
        "enter": "Return",
        "return": "Return",
        "backspace": "BackSpace",
        "del": "BackSpace",
        "delete": "Delete",
        "tab": "Tab",
        "escape": "Escape",
        "esc": "Escape",
        "space": "space",
        "up": "Up",
        "down": "Down",
        "left": "Left",
        "right": "Right",
        "page_up": "Page_Up",
        "page_down": "Page_Down",
        "pageup": "Page_Up",
        "pagedown": "Page_Down",
        "home": "Home",
        "end": "End",
        "plus": "plus",
        "+": "plus",
        "minus": "minus",
        "-": "minus",
        "equal": "equal",
        "=": "equal",
    }

    mod_map = {
        "ctrl": "ctrl",
        "control": "ctrl",
        "shift": "shift",
        "alt": "alt",
        "super": "logo",
        "win": "logo",
        "meta": "logo",
        "logo": "logo",
        "altgr": "altgr",
    }

    if "+" in k_lower:
        parts = [p.strip() for p in k_lower.split("+") if p.strip()]
        if parts:
            mods = [mod_map.get(m, m) for m in parts[:-1]]
            final_key = parts[-1]
            mapped_key = key_map.get(final_key, final_key)

            wtype_args = ["wtype"]
            for m in mods:
                wtype_args.extend(["-M", m])
            wtype_args.extend(["-k", mapped_key])
            for m in reversed(mods):
                wtype_args.extend(["-m", m])

            try:
                res = subprocess.run(wtype_args, capture_output=True, text=True, timeout=5)
                return res.returncode == 0, res.stderr.strip() if res.returncode != 0 else ""
            except Exception as exc:
                return False, str(exc)

    k = key_map.get(k_lower, k_raw)
    try:
        res = subprocess.run(["wtype", "-k", k], capture_output=True, text=True, timeout=5)
        return res.returncode == 0, res.stderr.strip() if res.returncode != 0 else ""
    except Exception as exc:
        return False, str(exc)


class BridgeHandler(http.server.BaseHTTPRequestHandler):

    token: str = ""
    pin: str = ""
    stt_model: str = "base.en"
    https_url: str = ""

    def log_message(self, fmt, *args):
        # suppress noisy access log; errors still go to stderr
        pass

    def _check_token(self) -> bool:
        tok = self.headers.get("X-Token", "")
        if not tok or not secrets.compare_digest(tok, self.token):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return False
        return True

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str) -> None:
        enc = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(enc)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "X-Token,Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            token_in_html = "" if self.pin else self.token
            has_pin = "true" if bool(self.pin) else "false"
            html = (_PWA_HTML
                    .replace("TOKEN_PLACEHOLDER", token_in_html)
                    .replace("HAS_PIN_PLACEHOLDER", has_pin)
                    .replace("HTTPS_PLACEHOLDER", self.https_url))
            self._html(html)
        elif path in ("/ca.pem", "/ca.crt", "/oma-remote-ca.crt"):
            # Served without the token: the phone's browser has to fetch this
            # before it can trust the page. It is a public certificate.
            if not CA_DER_FILE.exists():
                self.send_response(404)
                self.end_headers()
                return
            data = CA_DER_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition",
                             'attachment; filename="oma-remote-ca.crt"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        elif path in ("/manifest.json", "/manifest.webmanifest"):
            self.send_response(200)
            self.send_header("Content-Type", "application/manifest+json")
            self.send_header("Content-Length", str(len(_MANIFEST_JSON)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(_MANIFEST_JSON)
        elif path in ("/icon.png", "/apple-touch-icon.png", "/favicon.ico"):
            icon = _get_icon_png()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(icon)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(icon)
        elif path == "/state":
            if not self._check_token():
                return
            self._json(_read_state())
        elif path == "/settings":
            if not self._check_token():
                return
            from .local_engine import get_provider_status
            self._json(get_provider_status())
        elif path == "/history":
            if not self._check_token():
                return
            with _HISTORY_LOCK:
                turns = [dict(t) for t in _HISTORY]
            self._json({"turns": turns})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            self._json({"error": "bad json"}, 400)
            return

        if path == "/auth":
            pin_attempt = str(payload.get("pin") or "").strip()
            if self.pin and secrets.compare_digest(pin_attempt, self.pin):
                self._json({"ok": True, "token": self.token})
            else:
                self._json({"ok": False, "error": "Incorrect PIN"}, 401)
            return

        if not self._check_token():
            return

        if path == "/settings":
            provider = str(payload.get("provider") or "").strip().lower()
            api_key = str(payload.get("api_key") or "").strip()
            model = str(payload.get("model") or "").strip()
            base_url = str(payload.get("base_url") or "").strip()
            stt = str(payload.get("stt") or "auto").strip()
            should_test = bool(payload.get("test", True))

            from .local_engine import (
                PROVIDER_PRESETS,
                test_provider_connection,
                save_env_var,
                save_local_config,
            )

            if provider not in PROVIDER_PRESETS:
                self._json({"ok": False, "error": f"Unknown provider: {provider}"}, 400)
                return

            preset = PROVIDER_PRESETS[provider]
            effective_key = api_key or os.environ.get(preset.get("api_key_env", ""), "")

            # STT is independent of the LLM provider: save its key first so a
            # failing LLM check never throws away a speech key the user pasted.
            stt_api_key = str(payload.get("stt_api_key") or "").strip()
            if stt not in ("auto", "faster-whisper", "groq", "openai"):
                stt = "auto"
            stt_saved = False
            if stt_api_key:
                save_env_var("STT_API_KEY", stt_api_key)
                stt_saved = True

            if should_test:
                ok, msg = test_provider_connection(
                    provider=provider,
                    api_key=effective_key,
                    model=model,
                    base_url=base_url if provider == "custom" else "",
                )
                if not ok:
                    if stt_saved:
                        msg += " (speech-to-text key was saved)"
                    self._json({"ok": False, "error": msg})
                    return

            if api_key and preset.get("api_key_env"):
                save_env_var(preset["api_key_env"], api_key)

            cfg_updates = {
                "engine": "local",
                "provider": provider,
                "planner": provider,
                "llm_model": model or preset.get("default_model", ""),
                "stt": stt,
            }
            if provider == "custom" and base_url:
                cfg_updates["base_url"] = base_url
            save_local_config(cfg_updates)

            global _stt_model
            with _stt_lock:
                _stt_model = None

            message = (f"Verified and saved {preset.get('name', provider)} "
                       f"({model or preset.get('default_model', '')})!")
            if stt_saved:
                message += " Speech-to-text key saved."
            self._json({"ok": True, "message": message})
            return

        if path == "/clear":
            with _HISTORY_LOCK:
                _HISTORY.clear()
            self._json({"ok": True})

        elif path == "/type":
            text = payload.get("text", "")
            enter = bool(payload.get("enter", False))
            key = payload.get("key", "")

            if key:
                ok, err = _press_key(key)
                self._json({"ok": ok, "error": err if not ok else None})
                return

            if text:
                ok, err = _type_text(text, enter=enter)
                self._json({"ok": ok, "error": err if not ok else None})
                return

            self._json({"error": "empty"}, 400)
            return

        elif path == "/cmd":
            text = payload.get("text", "").strip()
            if not text:
                self._json({"error": "empty"}, 400)
                return
            reply = _dispatch(text)
            self._json({"ok": True, "reply": reply})

        elif path == "/transcribe":
            # Split from /voice so the page can show what it heard while the
            # planner is still thinking: the transcript lands in 2-3 s, the
            # reply a moment later.
            audio_b64 = payload.get("audio_b64", "")
            if not audio_b64:
                self._json({"error": "no audio"}, 400)
                return
            heard = _transcribe_wav(base64.b64decode(audio_b64),
                                    self.stt_model)
            self._json({"heard": heard})

        elif path == "/voice":
            audio_b64 = payload.get("audio_b64", "")
            if not audio_b64:
                self._json({"error": "no audio"}, 400)
                return
            audio_bytes = base64.b64decode(audio_b64)
            heard = _transcribe_wav(audio_bytes, self.stt_model)
            reply = ""
            if heard and not heard.startswith("[stt error"):
                reply = _dispatch(heard)
            self._json({"heard": heard, "reply": reply})

        else:
            self.send_response(404)
            self.end_headers()


# ---------------------------------------------------------------------------
# dispatch: text → control socket or planner
# ---------------------------------------------------------------------------

_SOCKET_COMMANDS = {"toggle", "start", "stop", "quit", "confirm", "cancel"}

_WS_WORDS = {
    "one": "1", "two": "2", "three": "3", "four": "4", "five": "5",
    "six": "6", "seven": "7", "eight": "8", "nine": "9", "ten": "10",
}

_DAEMON_OFF = ("The desktop mic daemon is not running — use the mic button "
               "on this page, or type a command.")


def _quick_command(text: str) -> str | None:
    """Resolve the page's own buttons and the obvious phrasings locally.

    Every chip used to be a full model round-trip, and the planner still got
    them wrong often enough to be useless: "close the active window" became a
    read-only hypr_query, "open firefox" became `omarchy firefox` (no such
    route), "mute audio" became `omarchy audio output mute`. These are fixed
    actions with fixed arguments, so they are answered here in milliseconds
    and only the open-ended requests go to the planner.
    """
    import re

    t = " ".join(text.lower().strip().split()).rstrip(".!?")

    if t in _SOCKET_COMMANDS:
        return _DAEMON_OFF

    try:
        from .config import load as load_cfg
        from .tools import Executor
        executor = Executor(load_cfg())
    except Exception:
        return None  # no tools available: let the planner report the problem

    def run(name: str, args: dict) -> tuple[bool, str]:
        try:
            result = executor.call(name, args)
        except Exception as exc:
            return False, str(exc)
        ok = bool(getattr(result, "ok", True))
        out = (getattr(result, "output", "") or "").strip()
        return ok, out.splitlines()[0] if out else ""

    # --- workspaces -------------------------------------------------------
    if t in ("previous workspace", "prev workspace", "go to previous workspace",
             "switch to previous workspace", "last workspace", "workspace left",
             "prev desktop", "previous desktop"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ workspace = "e-1" })'})
        return "Moved to previous workspace." if ok else f"Couldn't switch workspace: {out}"

    if t in ("next workspace", "go to next workspace", "switch to next workspace",
             "workspace right", "next desktop"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ workspace = "e+1" })'})
        return "Moved to next workspace." if ok else f"Couldn't switch workspace: {out}"

    match = re.fullmatch(
        r"(?:please )?(?:(?:go to|switch to|move to|show|open) )?(?:the )?"
        r"(?:workspace|desktop|ws) ([\w+-]+)",
        t,
    )
    if match:
        target = match.group(1)
        if target in ("next", "forward", "right", "+1", "e+1"):
            ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ workspace = "e+1" })'})
            return "Moved to next workspace." if ok else f"Couldn't switch workspace: {out}"
        if target in ("previous", "prev", "back", "left", "-1", "e-1"):
            ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ workspace = "e-1" })'})
            return "Moved to previous workspace." if ok else f"Couldn't switch workspace: {out}"
        number = _WS_WORDS.get(target, target)
        if number.isdigit():
            ok, out = run("hypr_dispatch",
                          {"lua": f'hl.dsp.focus({{ workspace = "{number}" }})'})
            return (f"Moved to workspace {number}." if ok
                    else f"Couldn't switch workspace: {out}")

    # --- tab navigation (inside active workspace / window) ----------------
    if t in ("previous tab", "prev tab", "previous tab in workspace",
             "workspace previous tab", "prev workspace tab",
             "previous workspace tab", "tab left", "tab back",
             "navigate previous tab", "switch to previous tab",
             "left tab", "back tab"):
        ok, out = run("send_shortcut", {"mods": "ctrl+shift", "key": "Tab"})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "ctrl", "key": "Page_Up"})
        return "Switched to previous tab." if ok else f"Couldn't switch tab: {out}"

    if t in ("next tab", "next tab in workspace", "workspace next tab",
             "next workspace tab", "tab right", "tab forward",
             "navigate next tab", "switch to next tab",
             "right tab", "forward tab", "switch tab", "cycle tab"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "Tab"})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "ctrl", "key": "Page_Down"})
        return "Switched to next tab." if ok else f"Couldn't switch tab: {out}"

    match_tab = re.fullmatch(
        r"(?:please )?(?:(?:go to|switch to|navigate to|move to|open) )?(?:the )?"
        r"(?:(next|previous|prev|left|right)) (?:workspace )?tab",
        t,
    )
    if match_tab:
        direction = match_tab.group(1)
        if direction in ("next", "right"):
            ok, out = run("send_shortcut", {"mods": "ctrl", "key": "Tab"})
            return "Switched to next tab." if ok else f"Couldn't switch tab: {out}"
        else:
            ok, out = run("send_shortcut", {"mods": "ctrl+shift", "key": "Tab"})
            return "Switched to previous tab." if ok else f"Couldn't switch tab: {out}"

    # --- window focus (inside active workspace) ---------------------------
    if t in ("previous window", "prev window", "focus left", "window left",
             "left window", "last window", "switch window left", "focus previous window"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ direction = "l" })'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "alt+shift", "key": "Tab"})
        return "Focused left window." if ok else f"Couldn't focus window: {out}"

    if t in ("next window", "focus right", "window right",
             "right window", "switch window right", "switch window", "focus next window"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.focus({ direction = "r" })'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "alt", "key": "Tab"})
        return "Focused right window." if ok else f"Couldn't focus window: {out}"

    match_win = re.fullmatch(
        r"(?:please )?(?:(?:go to|switch to|focus|navigate to) )?(?:the )?"
        r"(?:(next|previous|prev|left|right)) window",
        t,
    )
    if match_win:
        direction = match_win.group(1)
        dir_code = "r" if direction in ("next", "right") else "l"
        ok, out = run("hypr_dispatch", {"lua": f'hl.dsp.focus({{ direction = "{dir_code}" }})'})
        if not ok:
            mods = "alt" if dir_code == "r" else "alt+shift"
            ok, out = run("send_shortcut", {"mods": mods, "key": "Tab"})
        return f"Focused {direction} window." if ok else f"Couldn't focus window: {out}"

    # --- swap window with its neighbour -----------------------------------
    if t in ("swap window left", "swap left", "swap window to the left",
             "move window left in layout"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.window.swap({ direction = "l" })'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "super+shift", "key": "left"})
        return "Swapped window left." if ok else f"Couldn't swap window: {out}"

    if t in ("swap window right", "swap right", "swap window to the right",
             "move window right in layout"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.window.swap({ direction = "r" })'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "super+shift", "key": "right"})
        return "Swapped window right." if ok else f"Couldn't swap window: {out}"

    # --- direct typing & key presses --------------------------------------
    if t.startswith("type ") or t.startswith("write "):
        to_type = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
        if to_type:
            ok, err = _type_text(to_type, enter=False)
            return f'Typed "{to_type}".' if ok else f"Couldn't type text: {err}"

    if t in ("press enter", "enter", "hit enter", "send enter", "return key"):
        ok, err = _press_key("enter")
        return "Pressed Enter." if ok else f"Couldn't press Enter: {err}"

    if t in ("press backspace", "backspace", "delete", "press delete"):
        ok, err = _press_key("backspace")
        return "Pressed Backspace." if ok else f"Couldn't press Backspace: {err}"

    if t in ("press tab", "tab", "tab key"):
        ok, err = _press_key("tab")
        return "Pressed Tab." if ok else f"Couldn't press Tab: {err}"

    if t in ("paste", "paste clipboard"):
        ok, err = _press_key("paste")
        return "Pasted." if ok else f"Couldn't paste: {err}"

    # --- close the focused window / active tab ---------------------------
    if re.fullmatch(
        r"(?:please )?(?:close|kill|quit) (?:(?:the|this|that) )?"
        r"(?:(?:active|current|focused) )?window",
        t,
    ) or t in ("close it", "close this"):
        ok, out = run("hypr_dispatch", {"lua": "hl.dsp.window.close()"})
        return "Closed the active window." if ok else f"Couldn't close it: {out}"

    if re.fullmatch(
        r"(?:please )?(?:close|kill) (?:(?:the|this|that) )?"
        r"(?:(?:active|current|focused) )?tab",
        t,
    ) or t in ("close tab", "close this tab", "close the tab", "close active tab", "close the active tab"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "w"})
        if not ok:
            ok, err = _press_key("ctrl+w")
            if ok: out = ""
        return "Closed the active tab." if ok else f"Couldn't close tab: {out}"

    # --- scroll / swipe active window / tab -----------------------------
    if t in ("scroll down", "scroll down in active tab", "scroll down active tab",
             "page down", "down", "scroll down the page", "scroll down tab",
             "swipe down", "swipe down page", "swipe down in active tab"):
        ok, out = run("scroll", {"direction": "down", "amount": 1})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "", "key": "Page_Down"})
        if not ok:
            ok, err = _press_key("Page_Down")
            if ok: out = ""
        return "Scrolled down." if ok else f"Couldn't scroll down: {out}"

    if t in ("scroll up", "scroll up in active tab", "scroll up active tab",
             "page up", "up", "scroll up the page", "scroll up tab",
             "swipe up", "swipe up page", "swipe up in active tab"):
        ok, out = run("scroll", {"direction": "up", "amount": 1})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "", "key": "Page_Up"})
        if not ok:
            ok, err = _press_key("Page_Up")
            if ok: out = ""
        return "Scrolled up." if ok else f"Couldn't scroll up: {out}"

    match_scroll = re.fullmatch(
        r"(?:please )?(?:scroll|page) (down|up)(?: (?:in|on) (?:the )?(?:active|current)? ?(?:tab|window|page))?",
        t,
    )
    if match_scroll:
        direction = match_scroll.group(1)
        key = "Page_Down" if direction == "down" else "Page_Up"
        ok, out = run("scroll", {"direction": direction, "amount": 1})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "", "key": key})
        if not ok:
            ok, err = _press_key(key)
            if ok: out = ""
        return f"Scrolled {direction}." if ok else f"Couldn't scroll {direction}: {out}"

    
    # --- workspace window movers -----------------------------------------
    match_moveto = re.fullmatch(
        r"(?:please )?(?:move|send|transfer|throw) (?:(?:the|this|active) )?(?:window )?(?:to )?(?:workspace|ws|desktop) ([\w+-]+)",
        t,
    )
    if match_moveto:
        target = match_moveto.group(1)
        ws = _WS_WORDS.get(target, target)
        if ws.isdigit():
            ok, out = run("hypr_dispatch", {"lua": f'hl.dsp.window.move({{ workspace = "{ws}" }})'})
            if not ok:
                ok, out = run("send_shortcut", {"mods": "super+shift", "key": ws})
            return f"Moved window to workspace {ws}." if ok else f"Couldn't move window: {out}"

    match_moveto_scratch = re.fullmatch(
        r"(?:please )?(?:move|send|transfer|throw) (?:(?:the|this|active) )?(?:window )?(?:to )?(?:scratchpad|special workspace|special|scratch)",
        t,
    ) or t in ("move to scratchpad", "send to scratchpad", "scratchpad window", "send window to scratchpad", "move window to scratchpad", "move window to scratch")
    if match_moveto_scratch:
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.window.move({ workspace = "special:scratchpad", follow = false })'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "super+alt", "key": "s"})
        if not ok:
            res = subprocess.run(["hyprctl", "dispatch", "movetoworkspacesilent", "special:scratchpad"],
                                 capture_output=True, text=True)
            ok = res.returncode == 0
            out = res.stderr.strip() if not ok else ""
        return "Moved window to scratchpad." if ok else f"Couldn't move to scratchpad: {out}"

    # --- layout & tiling (split / scratchpad) -----------------------------
    if t in ("toggle split", "split", "split layout", "change split", "split h/v"):
        ok, out = run("send_shortcut", {"mods": "super", "key": "j"})
        if not ok:
            ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.layout("togglesplit")'})
        return "Toggled window split orientation." if ok else f"Split error: {out}"

    if t in ("toggle scratchpad", "scratchpad", "special workspace", "dropdown terminal"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.workspace.toggle_special("scratchpad")'})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "super", "key": "s"})
        if not ok:
            res = subprocess.run(["hyprctl", "dispatch", "togglespecialworkspace", "scratchpad"],
                                 capture_output=True, text=True)
            ok = res.returncode == 0
            out = res.stderr.strip() if not ok else ""
        return "Toggled scratchpad." if ok else f"Scratchpad error: {out}"

    # --- dev & process killers -------------------------------------------
    if t in ("kill local llm", "kill ollama", "kill llama", "kill llama server", "stop ollama", "stop local llm"):
        subprocess.run(["fuser", "-k", "8080/tcp"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "llama-server"], capture_output=True, timeout=2)
        subprocess.run(["fuser", "-k", "11434/tcp"], capture_output=True, timeout=2)
        subprocess.run(["systemctl", "stop", "ollama", "--no-ask-password"], capture_output=True, timeout=2)
        return "Terminated Local LLM services (ports 11434 & 8080)."

    if t in ("kill t3 dashboard", "kill t3", "kill dashboard", "stop t3 dashboard", "stop t3"):
        subprocess.run(["fuser", "-k", "3773/tcp"], capture_output=True, timeout=2)
        return "Killed T3 Dashboard (port 3773)."

    if "kill port" in t or re.search(r"\bkill \d+\b", t):
        m = re.search(r"(\d+)", t)
        if m:
            port = m.group(1)
            if port == "11434":
                subprocess.run(["systemctl", "stop", "ollama", "--no-ask-password"], capture_output=True, timeout=2)
            subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, text=True, timeout=2)
            return f"Killed processes on port {port}."

    if t in ("git status", "git diff", "git pull", "git push", "run tests"):
        cmd_str = "pytest" if t == "run tests" and Path("tests").exists() else (
                  "cargo test" if t == "run tests" and Path("Cargo.toml").exists() else (
                  "npm test" if t == "run tests" else t))
        ok, err = _type_text(cmd_str, enter=True)
        return f"Ran `{cmd_str}` in active terminal." if ok else f"Couldn't run `{cmd_str}`: {err}"

    # --- audio sink & hardware mic mute ----------------------------------
    if t in ("toggle mic mute", "mic mute", "mute mic", "mute microphone", "unmute mic"):
        res = subprocess.run(["wpctl", "set-mute", "@DEFAULT_AUDIO_SOURCE@", "toggle"],
                             capture_output=True, text=True)
        return "Toggled PC microphone mute." if res.returncode == 0 else f"Mic mute error: {res.stderr.strip()}"

    if t in ("toggle audio sink", "switch audio sink", "switch output", "switch audio"):
        res = subprocess.run(["bash", "-c",
            "sinks=(); "
            "if [ 0 -ge 2 ]; then current=; "
            "next=; [ "" == "" ] && next=; wpctl set-default ; fi"],
            capture_output=True, text=True)
        return "Switched default audio output sink."

    # --- audio mute -------------------------------------------------------
    if re.fullmatch(
        r"(?:please )?(?:un)?mute (?:(?:the) )?(?:audio|sound|volume)?",
        t,
    ) or t in ("mute", "unmute", "toggle mute"):
        ok, out = run("omarchy_cli",
                      {"command": "audio output volume mute-toggle"})
        if not ok:
            return f"Couldn't change the volume: {out}"
        # The command prints "ok"; the OSD shows the actual state.
        return out if out and out.lower() not in ("ok", "done") else "Toggled audio mute."

    # --- brightness -------------------------------------------------------
    match_bright = re.fullmatch(
        r"(?:please )?(?:set |increase |decrease |change |turn (?:up|down) )?"
        r"(?:the )?(?:display |screen )?brightness(?: to)? (\d{1,3})%?",
        t,
    )
    if match_bright:
        pct = max(0, min(100, int(match_bright.group(1))))
        ok, out = run("omarchy_cli", {"command": f"brightness display {pct}%"})
        return f"Brightness set to {pct}%." if ok else f"Couldn't set brightness: {out}"

    if t in ("brightness up", "increase brightness", "more brightness", "turn up brightness"):
        ok, out = run("omarchy_cli", {"command": "brightness display +10%"})
        return "Increased brightness." if ok else f"Couldn't increase brightness: {out}"

    if t in ("brightness down", "decrease brightness", "lower brightness", "less brightness", "turn down brightness"):
        ok, out = run("omarchy_cli", {"command": "brightness display 10%-"})
        return "Decreased brightness." if ok else f"Couldn't decrease brightness: {out}"

    # --- volume up / down -------------------------------------------------
    if t in ("volume up", "vol up", "vol +", "increase volume", "raise volume", "louder"):
        ok, out = run("omarchy_cli", {"command": "audio output volume raise"})
        return "Volume raised." if ok else f"Couldn't raise volume: {out}"

    if t in ("volume down", "vol down", "vol -", "decrease volume", "lower volume", "quieter"):
        ok, out = run("omarchy_cli", {"command": "audio output volume lower"})
        return "Volume lowered." if ok else f"Couldn't lower volume: {out}"

    # --- media playback ---------------------------------------------------
    if t in ("media play pause", "play pause", "play/pause", "play", "pause", "toggle playback"):
        ok, out = run("send_shortcut", {"mods": "", "key": "XF86AudioPlay"})
        if not ok:
            ok, err = _press_key("XF86AudioPlay")
            if ok: out = ""
        return "Toggled playback." if ok else f"Couldn't toggle playback: {out}"

    if t in ("media next", "next track", "next song", "skip track", "skip song"):
        ok, out = run("send_shortcut", {"mods": "", "key": "XF86AudioNext"})
        if not ok:
            ok, err = _press_key("XF86AudioNext")
            if ok: out = ""
        return "Next track." if ok else f"Couldn't skip track: {out}"

    if t in ("previous track", "prev track", "media prev", "media previous",
             "previous song", "prev song", "last track", "skip back"):
        ok, out = run("send_shortcut", {"mods": "", "key": "XF86AudioPrev"})
        if not ok:
            ok, err = _press_key("XF86AudioPrev")
            if ok: out = ""
        return "Previous track." if ok else f"Couldn't skip back: {out}"

    if t in ("media stop", "stop media", "stop playback", "stop music", "stop audio"):
        ok, out = run("send_shortcut", {"mods": "", "key": "XF86AudioStop"})
        if not ok:
            ok, err = _press_key("XF86AudioStop")
            if ok: out = ""
        return "Stopped playback." if ok else f"Couldn't stop playback: {out}"

    # --- browser navigation (back / forward / reload / new tab) ----------
    if t in ("browser back", "go back", "back", "navigate back", "history back"):
        ok, out = run("send_shortcut", {"mods": "alt", "key": "Left"})
        if not ok:
            ok, err = _press_key("alt+Left")
            if ok: out = ""
        return "Navigated back." if ok else f"Couldn't navigate back: {out}"

    if t in ("browser forward", "go forward", "forward", "navigate forward", "history forward"):
        ok, out = run("send_shortcut", {"mods": "alt", "key": "Right"})
        if not ok:
            ok, err = _press_key("alt+Right")
            if ok: out = ""
        return "Navigated forward." if ok else f"Couldn't navigate forward: {out}"

    if t in ("reload page", "refresh page", "reload", "refresh", "refresh the page"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "r"})
        if not ok:
            ok, err = _press_key("ctrl+r")
            if ok: out = ""
        return "Reloaded page." if ok else f"Couldn't reload page: {out}"

    if t in ("new tab", "open new tab", "create tab", "open a new tab"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "t"})
        if not ok:
            ok, err = _press_key("ctrl+t")
            if ok: out = ""
        return "Opened a new tab." if ok else f"Couldn't open new tab: {out}"

    if t in ("address bar", "url bar", "focus address bar", "focus url", "browser url", "go to address bar"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "l"})
        if not ok:
            ok, err = _press_key("ctrl+l")
            if ok: out = ""
        return "Focused address bar." if ok else f"Couldn't focus address bar: {out}"

    # --- zoom & escape ---------------------------------------------------
    if t in ("zoom in", "increase zoom", "magnify"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "plus"})
        if not ok:
            ok, out = run("send_shortcut", {"mods": "ctrl", "key": "equal"})
        if not ok:
            ok, err = _press_key("ctrl+plus")
            if ok: out = ""
        return "Zoomed in." if ok else f"Couldn't zoom in: {out}"

    if t in ("zoom out", "decrease zoom"):
        ok, out = run("send_shortcut", {"mods": "ctrl", "key": "minus"})
        if not ok:
            ok, err = _press_key("ctrl+minus")
            if ok: out = ""
        return "Zoomed out." if ok else f"Couldn't zoom out: {out}"

    if t in ("press escape", "escape", "esc", "dismiss", "cancel"):
        ok, out = run("send_shortcut", {"mods": "", "key": "Escape"})
        if not ok:
            ok, err = _press_key("Escape")
            if ok: out = ""
        return "Pressed Escape." if ok else f"Couldn't press Escape: {out}"

    # --- window layout (fullscreen / float) -------------------------------
    if t in ("toggle fullscreen", "fullscreen", "maximize", "unfullscreen"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.window.fullscreen({ mode = "fullscreen" })'})
        return "Toggled fullscreen." if ok else f"Couldn't toggle fullscreen: {out}"

    if t in ("toggle float", "float", "unfloat", "float window", "tile window", "float / tile"):
        ok, out = run("hypr_dispatch", {"lua": 'hl.dsp.window.float({ action = "toggle" })'})
        return "Toggled window floating." if ok else f"Couldn't toggle float: {out}"

    # --- system actions (screenshot / lock / sleep) -----------------------
    if t in ("take screenshot", "screenshot", "capture screenshot", "screen capture"):
        ok, out = run("omarchy_cli", {"command": "capture screenshot fullscreen save"})
        return "Screenshot taken." if ok else f"Couldn't take screenshot: {out}"

    if t in ("lock screen", "lock", "lock the screen", "system lock"):
        ok, out = run("omarchy_cli", {"command": "system lock"})
        return "Screen locked." if ok else f"Couldn't lock screen: {out}"

    if t in ("system sleep", "sleep", "suspend", "suspend system", "system suspend"):
        ok, out = run("omarchy_cli", {"command": "system sleep"})
        if not ok:
            ok, out = run("omarchy_cli", {"command": "system lock"})
        return "System suspended." if ok else f"Couldn't suspend: {out}"

    # --- launchers / menu / clipboard -------------------------------------
    if t in ("open menu", "menu", "toggle menu", "app menu", "launcher", "open launcher"):
        ok, out = run("omarchy_cli", {"command": "menu toggle"})
        if not ok:
            ok, out = run("omarchy_cli", {"command": "menu"})
        return "Toggled menu." if ok else f"Couldn't open menu: {out}"

    if t in ("open clipboard", "clipboard menu", "clipboard history", "clipboard", "open clipboard menu"):
        ok, out = run("omarchy_cli", {"command": "menu clipboard"})
        return "Opened clipboard menu." if ok else f"Couldn't open clipboard menu: {out}"

    # --- terminal / browser / chrome -------------------------------------
    if t in ("open a new terminal", "open a terminal", "new terminal",
             "open terminal", "launch a terminal"):
        ok, out = run("omarchy_cli", {"command": "launch terminal"})
        return "Opened a terminal." if ok else f"Couldn't open a terminal: {out}"

    if t in ("open btop", "btop", "system monitor", "task manager", "open task manager", "device monitor"):
        ok, out = run("omarchy_cli", {"command": "launch terminal btop"})
        if not ok:
            res = subprocess.Popen(["foot", "btop"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return "Launched btop system & device manager."

    if t in ("open t3 dashboard", "t3 dashboard", "t3 code", "open t3", "open dashboard"):
        ok, out = run("launch_url", {"url": "http://127.0.0.1:3773"})
        if not ok:
            res = subprocess.Popen(["xdg-open", "http://127.0.0.1:3773"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return "Opened T3 Dashboard."

    if t in ("open inspector", "inspector", "system inspector", "connected devices",
             "bluetooth devices", "show devices", "bluetooth", "devices",
             "show ports", "active ports", "ports and devices", "ports", "open ports"):
        # Launch the custom GUI app on the laptop. Go through Hyprland rather
        # than spawning it as a child of this service: the service runs in its
        # own user namespace, where /proc hides other processes and `ss -p`
        # cannot resolve their PIDs, so the inspector would show ports without
        # Kill buttons.
        launched = False
        try:
            r = subprocess.run(
                ["hyprctl", "eval",
                 'hl.exec_cmd("/home/mohsin/.local/bin/omarchy-inspector")'],
                capture_output=True, text=True, timeout=3,
            )
            launched = r.returncode == 0 and r.stdout.strip().lower() == "ok"
        except Exception:
            launched = False

        if not launched:
            try:
                subprocess.Popen(
                    ["/home/mohsin/.local/bin/omarchy-inspector"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception:
                pass

        return "Opened Ports & Devices Inspector on laptop."

    if t in ("kill app", "kill active app", "force kill", "xkill", "kill window", "force close"):
        try:
            res = subprocess.run(["hyprctl", "kill"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                return "Kill mode active: Click any window on screen to terminate it."
        except Exception:
            pass
        ok, out = run("hypr_dispatch", {"lua": "hl.dsp.window.close()"})
        return "Closed active window." if ok else f"Kill failed: {out}"

    if t in ("toggle tailscale", "tailscale", "open tailscale", "tailscale panel"):
        # `omarchy-shell shell toggle` exits 0 even when a plugin is disabled,
        # so check the plugin registry first. Otherwise the deck reports success
        # while nothing opens.
        panel_enabled = False
        try:
            r = subprocess.run(["omarchy-shell", "shell", "listPlugins"],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                plugins = json.loads(r.stdout or "[]")
                panel_enabled = any(
                    p.get("id") == "omarchy.tailscale" and p.get("enabled")
                    for p in plugins
                )
        except Exception:
            panel_enabled = False

        if panel_enabled:
            try:
                r = subprocess.run(["omarchy-shell", "shell", "toggle", "omarchy.tailscale"],
                                   capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    return "Toggled Tailscale panel."
            except Exception:
                pass

        admin_url = "https://login.tailscale.com/admin/machines"

        def open_admin_console() -> bool:
            # omarchy-launch-browser goes through the desktop's own launcher and
            # returns immediately; plain xdg-open can block when Chrome is open.
            for name in ("omarchy-launch-browser", "xdg-open"):
                if not shutil.which(name):
                    continue
                try:
                    r = subprocess.run([name, admin_url], capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        return True
                except Exception:
                    continue
            return False

        # No native panel: report the CLI status if Tailscale is actually installed.
        if shutil.which("tailscale"):
            try:
                res = subprocess.run(["tailscale", "status"], capture_output=True, text=True, timeout=3)
                first = next((line.strip() for line in res.stdout.splitlines() if line.strip()), "")
                if res.returncode == 0 and first:
                    return f"Tailscale: {first}"
                opened = open_admin_console()
                return ("Tailscale is installed but not running. Start it with "
                        "`omarchy install service tailscale` or `sudo tailscale up`."
                        + (" Opened the Tailscale admin console." if opened else ""))
            except Exception:
                pass

        # Nothing local to open: send the user somewhere useful instead of
        # failing silently. The admin console is the right place to install or
        # manage machines.
        opened = open_admin_console()
        if not opened:
            return ("Tailscale isn't installed. Run `omarchy install service tailscale` "
                    f"or open {admin_url}")
        return ("Tailscale isn't installed on this PC, so the panel can't open. "
                "Opened the Tailscale admin console — install the service with "
                "`omarchy install service tailscale`.")

    if t in ("zen mode", "toggle zen mode", "toggle bar", "hide bar", "show bar", "zen"):
        try:
            subprocess.run(["omarchy-toggle-bar"], capture_output=True, text=True, timeout=3)
        except Exception:
            pass
        bar_off = os.path.exists(os.path.expanduser("~/.local/state/omarchy/toggles/bar-off"))
        state = "enabled (top bar hidden)" if bar_off else "disabled (top bar visible)"
        return f"Zen mode {state}."

    if t in ("toggle caffeine", "caffeine", "stay awake", "keep awake", "toggle idle", "disable idle"):
        try:
            res = subprocess.run(["omarchy-toggle-idle"], capture_output=True, text=True, timeout=3)
            out = (res.stdout or "").strip()
            state = "on (stay awake enabled)" if out == "disabled" else "off (normal sleep enabled)"
        except Exception:
            state = "toggled"
        return f"Caffeine mode {state}."

    if t in ("toggle nightlight", "night light", "nightlight", "toggle night light", "warm screen"):
        try:
            subprocess.run(["omarchy-toggle-nightlight"], capture_output=True, text=True, timeout=3)
            res = subprocess.run(["omarchy-toggle-nightlight", "--status"], capture_output=True, text=True, timeout=2)
            data = json.loads(res.stdout)
            state = f"on ({data.get('temperature', 4000)}K warm)" if data.get("enabled") else "off (6500K normal)"
        except Exception:
            state = "toggled"
        return f"Night light {state}."

    if t in ("open opencode", "opencode", "open code", "launch opencode", "launch open code", "code agent"):
        ok, out = run("omarchy_cli", {"command": "launch tui opencode"})
        if not ok:
            try:
                subprocess.Popen(
                    ["hyprctl", "dispatch", "exec", "[float] omarchy-launch-tui opencode"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                ok = True
            except Exception as exc:
                return f"Couldn't open OpenCode: {exc}"
        return "Opened OpenCode." if ok else f"Couldn't open OpenCode: {out}"

    if t in ("open lazygit", "lazygit", "git tui", "open git tui", "open lazy git"):
        ok, out = run("omarchy_cli", {"command": "launch tui lazygit"})
        return "Opened lazygit." if ok else f"Couldn't open lazygit: {out}"

    if t in ("open docker tui", "docker", "lazydocker", "open lazydocker",
             "docker ps", "docker dashboard", "open docker", "docker tui"):
        ok, out = run("omarchy_cli", {"command": "launch tui omarchy-launch-docker-tui"})
        if not ok:
            ok, out = run("omarchy_cli", {"command": "launch tui lazydocker"})
        if not ok:
            try:
                subprocess.Popen(
                    ["hyprctl", "dispatch", "exec", "[float] omarchy-launch-tui lazydocker"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                ok = True
            except Exception as exc:
                return f"Couldn't open Docker TUI: {exc}"
        return "Opened Docker TUI (lazydocker)." if ok else f"Couldn't open Docker TUI: {out}"

    if t in ("system menu", "open system menu", "omarchy menu", "sys menu", "settings menu"):
        try:
            subprocess.run(["omarchy", "menu", "toggle", "system"], capture_output=True, text=True, timeout=3)
            return "Opened system menu."
        except Exception:
            return "Could not open system menu."

    if t in ("open files", "files", "launch files", "file manager", "open file manager", "nautilus"):
        ok, out = run("omarchy_cli", {"command": "launch nautilus"})
        return "Opened Files." if ok else f"Couldn't open Files: {out}"

    if t in ("open chrome", "open google chrome", "open google-chrome",
             "launch chrome", "chrome"):
        ok, out = run("launch_app", {"app": "google-chrome"})
        return "Opened Chrome." if ok else f"Couldn't launch Chrome: {out}"

    if t in ("open the browser", "open browser", "open firefox",
             "launch the browser", "firefox"):
        ok, out = run("omarchy_cli", {"command": "launch browser"})
        return "Opened the browser." if ok else f"Couldn't open the browser: {out}"

    return None


def _dispatch(text: str) -> str:
    """Route the text to the daemon's control socket or the planner."""
    quick = _quick_command(text)
    if quick is not None:
        reply = quick
    else:
        try:
            reply = send_control(f"say {text}")
        except ConnectionError:
            reply = _local_think(text)

    # Keep a running chat log for the page (works for chips too, not just
    # the model path). Skip obvious errors so the log stays readable.
    if isinstance(reply, str) and reply and not reply.startswith(
            ("[", "error:", "error ")):
        with _HISTORY_LOCK:
            _HISTORY.extend([{"role": "user", "content": text},
                             {"role": "assistant", "content": reply}])
            del _HISTORY[:-_HISTORY_CAP]
    return reply


def _local_think(text: str) -> str:
    """Fallback: run the local planner in-process if daemon is down."""
    try:
        from .config import load as load_cfg
        from .tools import Executor
        from .local_engine import LocalPlanner
        from .feedback import Feedback
        cfg = load_cfg()
        executor = Executor(cfg)
        feedback = Feedback(cfg)
        planner = LocalPlanner(cfg, executor, feedback, compact=True)
        with _HISTORY_LOCK:
            history = list(_HISTORY[-6:])
        reply = planner.think(text, history=history)
        # Remember the exchange so "close it" or "again" has a referent. Only
        # successful turns, and not the failure text — that would poison the
        # next prompt with an error message it did not cause.
        if reply and not reply.startswith(("I couldn't", "[")):
            with _HISTORY_LOCK:
                _HISTORY.extend([{"role": "user", "content": text},
                                 {"role": "assistant", "content": reply}])
                del _HISTORY[:-_HISTORY_TURNS * 2]
        return reply
    except Exception as exc:
        return f"[no daemon, fallback failed: {exc}]"


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

class BridgeServer(http.server.ThreadingHTTPServer):
    """Threaded HTTP server that does not do a reverse-DNS lookup on bind.

    http.server.HTTPServer.server_bind() stores socket.getfqdn(host) in
    server_name.  For 0.0.0.0 that resolves the machine's own hostname and can
    block for seconds when DNS is slow or unavailable — the socket is not
    listening yet, so the phone sees an empty reply.  Threading also keeps a
    slow /voice turn from blocking /state polls and page loads.
    """

    daemon_threads = True
    allow_reuse_address = True

    # One port, both protocols: the first byte of a TLS ClientHello is 0x16,
    # an HTTP request starts with a method letter. Serving https on a second
    # port would be tidier, but every extra port is another firewall rule the
    # user has to add — and the phone needs https for the mic.
    tls_context: ssl.SSLContext | None = None

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is None:
            return sock, addr
        try:
            sock.settimeout(5)
            first = sock.recv(1, socket.MSG_PEEK)
        except OSError:
            return sock, addr
        if first[:1] == b"\x16":
            return self.tls_context.wrap_socket(sock, server_side=True), addr
        sock.settimeout(None)
        return sock, addr

    def handle_error(self, request, client_address) -> None:
        # A phone that navigates away mid-request is not an error worth a
        # traceback in the journal; everything else still is.
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _firewall_hint(port: int) -> str:
    """Explain "it works on the desktop but not on the phone" when ufw blocks.

    ufw drops input by default but exempts loopback, so the page loads fine
    in a desktop browser and simply times out from the phone — which looks
    like a broken server.  The ufw config files are world-readable, so this
    check needs no root; only the fix does.
    """
    import re

    try:
        if "ENABLED=yes" not in Path("/etc/ufw/ufw.conf").read_text():
            return ""
        rules = Path("/etc/ufw/user.rules").read_text()
    except OSError:
        return ""

    allowed = any(
        line.startswith("-A ufw-user-input") and "ACCEPT" in line
        and "tcp" in line and re.search(rf"--dports? \S*{port}\b", line)
        for line in rules.splitlines()
    )
    if allowed:
        return ""
    return (
        f"  heads up: ufw is on and {port}/tcp is not allowed, so this page\n"
        f"  will load here and time out on your phone.  To fix it:\n\n"
        f"    sudo ufw allow {port}/tcp\n"
    )


def run(config, port: int = DEFAULT_PORT) -> int:
    token = _load_or_create_token()

    # find LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host = s.getsockname()[0]
        s.close()
    except Exception:
        host = "0.0.0.0"

    from .local_engine import _local_config
    local_cfg = _local_config(config)
    stt_model = local_cfg.get("stt_model", "base.en")
    pin = str(local_cfg.get("pin") or "").strip()

    # Bake token, pin, and stt_model into handler class
    class Handler(BridgeHandler):
        pass
    Handler.token = token
    Handler.pin = pin
    Handler.stt_model = stt_model

    # Pay the model load now instead of on the first thing the user says.
    threading.Thread(target=_warm_stt, args=(stt_model,), daemon=True).start()

    # Plain HTTP — Safari on iOS hangs indefinitely on self-signed TLS certs.
    # LAN IPs (192.168.x.x, 10.x.x.x) are treated as secure contexts by
    # modern iOS Safari, so getUserMedia works fine over plain HTTP on LAN.
    try:
        server = BridgeServer(("0.0.0.0", port), Handler)
    except OSError as exc:
        print(f"\n  could not listen on port {port}: {exc}")
        print(f"  try: omarchy-voice mobile --port {port + 1}\n")
        return 1

    url = f"http://{host}:{port}"

    # The same port carries both: a TLS ClientHello is recognised in
    # get_request() and wrapped. Safari only exposes the microphone on a
    # secure origin, so the phone needs the https form — but it already has
    # a firewall rule for this port, and a second one would be one more thing
    # to get wrong.
    https_url = ""
    tls = _ensure_tls(host)
    if tls:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(tls[0]), str(tls[1]))
        except Exception as exc:
            print(f"  https unavailable: {exc}")
        else:
            server.tls_context = context
            Handler.https_url = f"https://{host}:{port}"
            https_url = Handler.https_url

    print(f"\n  Oma Remote  →  {url}")
    if https_url:
        print(f"  with mic    →  {https_url}")
        print(f"  certificate →  {url}/ca.pem     (install once on the phone)")
    print(f"  token: {token}")
    print(f"\n  Open that URL in Safari on your phone.\n", flush=True)
    hint = _firewall_hint(port)
    if hint:
        print(hint, flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
