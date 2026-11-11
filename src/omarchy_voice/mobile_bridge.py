"""Mobile remote-control bridge for omarchy-voice.

Runs a small HTTP server on your LAN so a phone browser can:
  - Stream a voice recording → STT (faster-whisper) → control socket
  - Type a command → control socket directly
  - See the current daemon state (idle / listening / thinking / acting)
  - Toggle listening on/off with a tap

Touch controls and keyboard macros operate over standard LAN HTTP; browser
microphone dictation (getUserMedia) requires HTTPS via the local CA certificate.
A secret token and PIN authentication keep unauthenticated devices on the network
from driving your desktop.

Usage:
    omadeck mobile                # start on default port 8765
    omadeck mobile --port 9000

Then open  http://<your-lan-ip>:8765/?token=<token>  on your phone.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import http.server
import io
import ipaddress
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
from urllib.parse import parse_qs, quote, urlparse

from .config import CONFIG_DIR, STATE_FILE, load_env_file
from .feedback import brief, write_log
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

def _manifest_json(start_url: str = "/") -> bytes:
    return json.dumps({
        "name": "Oma Remote",
        "short_name": "Oma",
        "start_url": start_url,
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

def _save_token(tok: str) -> None:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(tok)
    try:
        TOKEN_FILE.chmod(0o600)
    except OSError:
        pass


def _load_or_create_token() -> str:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if TOKEN_FILE.exists():
        tok = TOKEN_FILE.read_text().strip()
        if tok:
            return tok
    tok = secrets.token_urlsafe(16)
    _save_token(tok)
    return tok


# ---------------------------------------------------------------------------
# TLS: a local CA the phone trusts once, so Safari allows the microphone
# ---------------------------------------------------------------------------

def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def _cert_valid(cert_path: Path, min_seconds: int = 86400) -> bool:
    if not cert_path.exists():
        return False
    try:
        res = subprocess.run(
            ["openssl", "x509", "-checkend", str(min_seconds), "-noout", "-in", str(cert_path)],
            capture_output=True,
        )
        return res.returncode == 0
    except Exception:
        return False


def _ca_valid(ca_path: Path, min_seconds: int = 86400) -> bool:
    if not _cert_valid(ca_path, min_seconds):
        return False
    try:
        res = subprocess.run(
            ["openssl", "x509", "-text", "-noout", "-in", str(ca_path)],
            capture_output=True,
            text=True,
        )
        return "Name Constraints" in res.stdout and "pathlen:0" in res.stdout and "DNS:localhost" in res.stdout
    except Exception:
        return False


def _ensure_tls(host: str) -> tuple[Path, Path] | None:
    """Create (or reuse) a leaf cert for `host`, signed by a local CA.

    An untrusted self-signed leaf is worse than no TLS here: Safari shows an
    interstitial and the media APIs stay unhappy. A CA the phone installs
    once gives a clean https:// page, which is the only way getUserMedia is
    exposed to the page at all.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    try:
        ca_valid = CA_CERT_FILE.exists() and CA_KEY_FILE.exists() and _ca_valid(CA_CERT_FILE, 86400)
        ca_regenerated = False
        if not ca_valid:
            _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-days", "730",
                     "-keyout", str(CA_KEY_FILE), "-out", str(CA_CERT_FILE),
                     "-subj", "/CN=Oma Remote CA",
                     "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                     "-addext", "nameConstraints=critical,permitted;DNS:localhost,permitted;DNS:.local,permitted;DNS:.ts.net,permitted;IP:192.168.0.0/255.255.0.0,permitted;IP:10.0.0.0/255.0.0.0,permitted;IP:172.16.0.0/255.240.0.0,permitted;IP:100.64.0.0/255.192.0.0,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,permitted;IP:fe80::/ffc0::,permitted;IP:fc00::/fe00::")
            CA_KEY_FILE.chmod(0o600)
            _openssl("x509", "-in", str(CA_CERT_FILE), "-outform", "der",
                     "-out", str(CA_DER_FILE))
            print(f"  created a local CA: {CA_CERT_FILE}")
            ca_regenerated = True
            for old_f in (CERT_FILE, KEY_FILE, CERT_HOST_FILE):
                try:
                    old_f.unlink(missing_ok=True)
                except OSError:
                    pass

        # Re-issue the leaf when the LAN address changes, when the CA was regenerated,
        # or when the leaf nears expiration.
        current = ""
        try:
            current = CERT_HOST_FILE.read_text().strip()
        except OSError:
            pass
        leaf_valid = (
            not ca_regenerated
            and current == host
            and CERT_FILE.exists()
            and KEY_FILE.exists()
            and _cert_valid(CERT_FILE, 86400)
        )
        if not leaf_valid:
            csr = CONFIG_DIR / "mobile_csr.pem"
            ext = CONFIG_DIR / "mobile_ext.cnf"
            try:
                name = socket.gethostname()
            except Exception:
                name = "omarchy"
            san_items = ["IP:127.0.0.1", "DNS:localhost", f"DNS:{name}.local"]
            try:
                ipaddress.ip_address(host)
                san_items.insert(0, f"IP:{host}")
            except ValueError:
                san_items.insert(0, f"DNS:{host}")
            ext.write_text(
                f"subjectAltName={','.join(san_items)}\n"
                "basicConstraints=CA:FALSE\n"
                "keyUsage=digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\n"
            )
            _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(KEY_FILE), "-out", str(csr),
                     "-subj", "/CN=Oma Remote")
            _openssl("x509", "-req", "-in", str(csr),
                     "-CA", str(CA_CERT_FILE), "-CAkey", str(CA_KEY_FILE),
                     "-CAcreateserial", "-days", "397",
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


def _get_current_desktop_theme() -> str:
    """Read the active Omarchy desktop theme name, slugified."""
    try:
        res = subprocess.run(["omarchy", "theme", "current"], capture_output=True, text=True, timeout=1.5)
        if res.returncode == 0 and res.stdout.strip():
            slug = res.stdout.strip().lower().replace(" ", "-")
            return slug
    except Exception:
        pass
    return "gruvbox"

def _read_state() -> dict:
    # With the daemon down the state file is stale — last time it said
    # "OPENAI_API_KEY is not set" and stayed that way on every page load.
    # The phone bridge works on its own now, so say what is actually true.
    if not daemon_running():
        d = {"status": "idle", "icon": "󰍭", "text": "daemon off — text and mic from the phone still work", "class": "idle"}
        d["desktop_theme"] = _get_current_desktop_theme()
        return d
    try:
        if STATE_FILE.exists():
            d = json.loads(STATE_FILE.read_text())
            d["desktop_theme"] = _get_current_desktop_theme()
            return d
    except Exception:
        pass
    return {"status": "unknown", "text": "", "icon": "", "desktop_theme": _get_current_desktop_theme()}


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
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="theme-color" content="#09090c">
<script>
  // Apply the saved theme before first paint so the deck never flashes the
  // default palette on a device that chose Phosphor, Amber, or Tokyo Night.
  try {
    var _params = new URLSearchParams(window.location.search);
    var _urlTheme = _params.get('theme');
    if (_urlTheme) localStorage.setItem('oma-deck-theme', _urlTheme);
    var _omaTheme = _urlTheme || localStorage.getItem('oma-deck-theme') || 'midnight';
    document.documentElement.dataset.theme = _omaTheme;
    var _omaMeta = document.querySelector('meta[name="theme-color"]');
    if (_omaMeta) _omaMeta.setAttribute('content',
      _omaTheme === 'phosphor' ? '#020604' : _omaTheme === 'amber' ? '#0a0703' : _omaTheme === 'tokyo-night' ? '#13141c' : '#09090c');
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
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
    overscroll-behavior: none;
    user-select: none;
    -webkit-user-select: none;
    -webkit-touch-callout: none;
  }
  body {
    display: flex;
    justify-content: center;
    align-items: flex-start;
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
    vector-effect: non-scaling-stroke;
    shape-rendering: geometricPrecision;
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
    padding: max(calc(env(safe-area-inset-top, 0px) + 16px), 48px) 10px max(env(safe-area-inset-bottom, 0px), 8px) 10px;
    isolation: isolate;
  }

  /* Cockpit / Header */
  .deck-cockpit {
    display: contents;
  }
  header {
    order: 1;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 36px;
    flex-shrink: 0;
    position: relative;
    z-index: 10;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    text-rendering: optimizeLegibility;
  }
  .reply-strip {
    order: 2;
  }
  .notice {
    order: 2;
  }
  .brand-group {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
  .logo {
    font-size: 16px;
    font-weight: 800;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--text);
  }
  .logo .tag {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 11px;
    font-weight: 700;
    background: var(--tag-bg);
    border: 1px solid var(--border);
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--accent);
    letter-spacing: 0.05em;
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }
  #status-badge {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 11px;
    font-weight: 700;
    padding: 4px 8px;
    border-radius: 99px;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    display: flex;
    align-items: center;
    gap: 5px;
    transition: background 0.15s, border-color 0.15s, color 0.15s;
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
  #status-badge.idle      { color: var(--text); }
  #status-badge.idle::before { background: #34d399; }

  .icon-chip {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-size: 12px;
    font-weight: 600;
    padding: 5px 9px;
    min-height: 28px;
    border-radius: 99px;
    cursor: pointer;
    touch-action: manipulation;
    display: flex;
    align-items: center;
    gap: 4px;
    transition: background 0.15s, border-color 0.15s, color 0.15s;
    -webkit-tap-highlight-color: transparent;
  }
  .icon-chip:hover { background: var(--surface-hover); color: var(--text); border-color: var(--border-highlight); }
  .icon-chip:active { background: var(--surface-active); }
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
    order: 3;
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
  .btn-grid-5 {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 4px;
    flex: 1;
    min-height: 0;
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
    order: 4;
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
    animation: rec-pulse-radar 1.3s infinite cubic-bezier(0.25, 0.8, 0.25, 1);
  }
  #mic-btn.recording.latched {
    background: #dc2626;
    border-color: #fca5a5;
    animation: rec-pulse-radar 1.0s infinite cubic-bezier(0.25, 0.8, 0.25, 1);
  }
  #mic-btn.thinking {
    background: #1e293b;
    border-color: #38bdf8;
    animation: spin-glow 1.5s infinite;
  }
  @keyframes rec-pulse-radar {
    0% {
      box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.75),
                  0 0 0 0 rgba(239, 68, 68, 0.4);
      transform: scale(1.02);
    }
    50% {
      box-shadow: 0 0 0 8px rgba(239, 68, 68, 0.35),
                  0 0 0 16px rgba(239, 68, 68, 0);
      transform: scale(0.97);
    }
    100% {
      box-shadow: 0 0 0 0 rgba(239, 68, 68, 0),
                  0 0 0 20px rgba(239, 68, 68, 0);
      transform: scale(1.02);
    }
  }
  /* Sound Wave Equalizer Bars for Live Feedback Strip */
  .sound-wave-bars {
    display: inline-flex;
    align-items: center;
    gap: 2.5px;
    height: 14px;
    vertical-align: middle;
    margin-right: 5px;
    flex-shrink: 0;
  }
  .sound-wave-bars span {
    display: block;
    width: 3px;
    background: #ef4444;
    border-radius: 2px;
    animation: sound-bar-bounce 0.7s ease-in-out infinite alternate;
  }
  .sound-wave-bars span:nth-child(1) { height: 6px;  animation-delay: 0.0s; }
  .sound-wave-bars span:nth-child(2) { height: 14px; animation-delay: 0.15s; }
  .sound-wave-bars span:nth-child(3) { height: 9px;  animation-delay: 0.3s; }
  .sound-wave-bars span:nth-child(4) { height: 13px; animation-delay: 0.45s; }

  @keyframes sound-bar-bounce {
    0%   { height: 4px; opacity: 0.4; }
    100% { height: 14px; opacity: 1; }
  }
  #cmd-input.recording-glow {
    border-color: rgba(239, 68, 68, 0.8) !important;
    box-shadow: 0 0 10px rgba(239, 68, 68, 0.3) !important;
  }
  @keyframes spin-glow {
    0%   { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.6); }
    50%  { box-shadow: 0 0 0 10px rgba(56, 189, 248, 0); }
    100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.6); }
  }
  .cmd-input-wrap {
    flex: 1;
    min-width: 0;
    position: relative;
    display: flex;
    align-items: center;
    height: 40px;
  }
  .cmd-input-wrap #cmd-input {
    width: 100%;
    height: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text);
    font-size: 0.86rem;
    padding: 0 34px 0 12px;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .cmd-input-wrap #cmd-input:focus { border-color: var(--input-focus); }
  .cmd-input-wrap #cmd-input::placeholder { color: var(--placeholder); opacity: 1; }
  .input-inline-btn {
    position: absolute;
    right: 4px;
    width: 30px;
    height: 30px;
    border-radius: var(--radius-sm);
    border: none;
    background: transparent;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    touch-action: none;
    transition: color 0.15s, background 0.15s, transform 0.1s;
    -webkit-tap-highlight-color: transparent;
  }
  .input-inline-btn .icon-svg {
    width: 15px;
    height: 15px;
    stroke: currentColor;
  }
  .input-inline-btn:hover {
    color: var(--text);
    background: rgba(255, 255, 255, 0.08);
  }
  .input-inline-btn:active {
    transform: scale(0.92);
  }
  .input-inline-btn.recording {
    color: #ef4444;
    animation: rec-pulse-radar 1.2s infinite;
  }
  .input-inline-btn.thinking {
    color: #38bdf8;
    animation: spin-glow 1.5s infinite;
  }
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
      display: flex;
      flex-direction: column;
      width: min(340px, 38vw);
      height: 100%;
      border-right: 1px solid var(--border);
      padding-right: 10px;
      justify-content: space-between;
      gap: 6px;
      overflow: hidden;
    }
    header,
    .reply-strip,
    .notice,
    .deck-bank,
    .deck-controls-dock {
      order: 0;
    }

    /* Compact Header in Landscape so Lock & Settings never overlap */
    header {
      height: 32px;
      width: 100%;
      min-width: 0;
      gap: 4px;
    }
    .brand-group {
      min-width: 0;
      flex-shrink: 1;
    }
    .brand-group .logo {
      font-size: 13px;
      white-space: nowrap;
    }
    .header-right {
      gap: 4px;
      flex-shrink: 0;
      min-width: 0;
    }
    .header-right #status-badge {
      font-size: 9px;
      padding: 2px 6px;
    }
    .header-right .icon-chip {
      padding: 0;
      width: 26px;
      height: 26px;
      min-height: 26px;
      justify-content: center;
      border-radius: 6px;
    }
    .header-right .icon-chip svg {
      width: 12px !important;
      height: 12px !important;
    }
    .header-right #history-toggle span {
      display: none;
    }

    /* Left Dock Controls in Landscape */
    .deck-controls-dock {
      gap: 4px;
    }
    .aux-keys {
      height: 25px;
      gap: 3px;
    }
    .key-chip {
      font-size: 0.62rem;
      border-radius: 4px;
    }
    .mode-bar {
      height: 26px;
      gap: 4px;
    }
    .mode-pill {
      font-size: 0.62rem;
    }
    .cmd-bar {
      height: 32px;
      gap: 4px;
    }
    .cmd-input-wrap {
      height: 32px;
    }
    .cmd-input-wrap #cmd-input {
      font-size: 0.80rem;
      padding: 0 30px 0 8px;
    }
    .input-inline-btn {
      width: 26px;
      height: 26px;
      right: 2px;
    }
    .cmd-action-btn {
      height: 32px;
      padding: 0 8px;
      font-size: 0.70rem;
    }
    #mic-btn {
      width: 32px;
      height: 32px;
    }

    /* Right Deck Action Bank */
    .deck-bank {
      flex: 1;
      height: 100%;
      min-width: 0;
      justify-content: space-between;
      gap: 6px;
    }
    .workspace-row {
      height: 30px;
      gap: 3px;
    }
    .ws-key {
      font-size: 0.74rem;
    }
    .move-to-row {
      height: 26px;
      gap: 3px;
    }
    .ws-key.move-btn {
      font-size: 0.65rem;
    }
    .deck-profile-bar {
      height: 28px;
      gap: 4px;
    }
    .profile-pill {
      font-size: 0.65rem;
      padding: 0 4px;
    }

    /* In landscape, sections and chips fit without overflowing */
    .profile-view {
      flex: 1;
      height: 100%;
      min-height: 0;
      justify-content: flex-start;
      gap: 6px;
      overflow-y: auto;
      -webkit-overflow-scrolling: touch;
    }
    .control-section {
      height: auto;
      flex: 1;
      min-height: 0;
      padding: 5px 8px;
      gap: 4px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .section-header {
      line-height: 1;
    }
    .section-title {
      font-size: 0.64rem;
    }
    .section-badge {
      font-size: 0.64rem;
    }
    .btn-grid-4 {
      gap: 4px;
      flex: 1;
      min-height: 0;
    }
    .chip {
      min-height: 28px;
      height: 100%;
      padding: 2px 2px;
      gap: 2px;
      border-radius: var(--radius-sm);
    }
    .chip .icon {
      width: 17px;
      height: 17px;
    }
    .chip .label {
      font-size: 0.64rem;
    }
  }

  /* Modals: Conversation History & Settings */
  .modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(9, 9, 12, 0.94);
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
    background: rgba(9, 9, 12, 0.98);
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

  /* PIN keypad touch grid */
  .pin-keypad {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    width: 100%;
    max-width: 240px;
    margin-top: 4px;
  }
  .pin-key {
    background: var(--btn-bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text);
    font-size: 1.3rem;
    font-weight: 600;
    padding: 12px 0;
    cursor: pointer;
    touch-action: manipulation;
    user-select: none;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .pin-key:active {
    background: var(--btn-active);
    transform: scale(0.96);
  }
  .pin-key.action-key {
    font-size: 0.82rem;
    color: var(--text-muted);
  }

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

  :root[data-theme="gruvbox"] {
    --bg: #1e1e1e;
    --chassis: #161616;
    --surface: #282828;
    --surface-hover: #3c3836;
    --surface-active: #3c3836;
    --deck-key: #282828;
    --deck-key-hover: #3c3836;
    --deck-key-active: #161616;
    --border: #665c5444;
    --border-subtle: #665c5422;
    --border-highlight: #7daea355;
    --text: #d4be98;
    --text-muted: #665c54;
    --text-dim: #7c6f64;
    --accent: #7daea3;
    --accent-fg: #161616;
    --status-ok: #a9b665;
    --status-warn: #d8a657;
    --status-danger: #ea6962;
    --status-info: #7daea3;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #504945;
    --scroll-thumb: #665c5466;
    --scroll-thumb-hover: #665c54aa;
    --tag-bg: #3c3836;
    --reply-text: #d4be98;
    --profile-bar-bg: #161616;
    --active-bg: #3c3836;
    --active-border: #7daea388;
    --input-bg: #1e1e1e;
    --input-border: #665c5444;
    --input-focus: #7daea3;
    --placeholder: #7c6f64;
    --action-bg: #3c3836;
    --action-border: #665c5466;
    --action-hover: #7daea333;
    --action-hover-border: #7daea3;
    --mic-bg: #3c3836;
    --mic-border: #665c5466;
    --msg-you-bg: #3c3836;
    --msg-you-border: #665c5466;
    --msg-oma-bg: #282828;
    --btn-bg: #7daea3;
    --btn-fg: #161616;
  }
  .theme-swatch-gruvbox { background: #1e1e1e; }
  .theme-swatch-gruvbox .theme-swatch-bar { background: #7daea3; }
  .theme-swatch-gruvbox i { background: #282828; border: 1px solid #665c5455; }
  :root[data-theme="catppuccin"] {
    --bg: #161622;
    --chassis: #101019;
    --surface: #1e1e2e;
    --surface-hover: #313244;
    --surface-active: #313244;
    --deck-key: #1e1e2e;
    --deck-key-hover: #313244;
    --deck-key-active: #101019;
    --border: #585b7044;
    --border-subtle: #585b7022;
    --border-highlight: #89b4fa55;
    --text: #cdd6f4;
    --text-muted: #585b70;
    --text-dim: #6c7086;
    --accent: #89b4fa;
    --accent-fg: #101019;
    --status-ok: #a6e3a1;
    --status-warn: #f9e2af;
    --status-danger: #f38ba8;
    --status-info: #89b4fa;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #45475a;
    --scroll-thumb: #585b7066;
    --scroll-thumb-hover: #585b70aa;
    --tag-bg: #313244;
    --reply-text: #cdd6f4;
    --profile-bar-bg: #101019;
    --active-bg: #313244;
    --active-border: #89b4fa88;
    --input-bg: #161622;
    --input-border: #585b7044;
    --input-focus: #89b4fa;
    --placeholder: #6c7086;
    --action-bg: #313244;
    --action-border: #585b7066;
    --action-hover: #89b4fa33;
    --action-hover-border: #89b4fa;
    --mic-bg: #313244;
    --mic-border: #585b7066;
    --msg-you-bg: #313244;
    --msg-you-border: #585b7066;
    --msg-oma-bg: #1e1e2e;
    --btn-bg: #89b4fa;
    --btn-fg: #101019;
  }
  .theme-swatch-catppuccin { background: #161622; }
  .theme-swatch-catppuccin .theme-swatch-bar { background: #89b4fa; }
  .theme-swatch-catppuccin i { background: #1e1e2e; border: 1px solid #585b7055; }
  :root[data-theme="tokyo-night"] {
    --bg: #13141c;
    --chassis: #0e0e14;
    --surface: #1a1b26;
    --surface-hover: #24283b;
    --surface-active: #24283b;
    --deck-key: #1a1b26;
    --deck-key-hover: #24283b;
    --deck-key-active: #0e0e14;
    --border: #41486844;
    --border-subtle: #41486822;
    --border-highlight: #7aa2f755;
    --text: #a9b1d6;
    --text-muted: #414868;
    --text-dim: #565f89;
    --accent: #7aa2f7;
    --accent-fg: #0e0e14;
    --status-ok: #9ece6a;
    --status-warn: #e0af68;
    --status-danger: #f7768e;
    --status-info: #7aa2f7;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #292e42;
    --scroll-thumb: #41486866;
    --scroll-thumb-hover: #414868aa;
    --tag-bg: #24283b;
    --reply-text: #a9b1d6;
    --profile-bar-bg: #0e0e14;
    --active-bg: #24283b;
    --active-border: #7aa2f788;
    --input-bg: #13141c;
    --input-border: #41486844;
    --input-focus: #7aa2f7;
    --placeholder: #565f89;
    --action-bg: #24283b;
    --action-border: #41486866;
    --action-hover: #7aa2f733;
    --action-hover-border: #7aa2f7;
    --mic-bg: #24283b;
    --mic-border: #41486866;
    --msg-you-bg: #24283b;
    --msg-you-border: #41486866;
    --msg-oma-bg: #1a1b26;
    --btn-bg: #7aa2f7;
    --btn-fg: #0e0e14;
  }
  .theme-swatch-tokyo-night { background: #13141c; }
  .theme-swatch-tokyo-night .theme-swatch-bar { background: #7aa2f7; }
  .theme-swatch-tokyo-night i { background: #1a1b26; border: 1px solid #41486855; }
  :root[data-theme="nord"] {
    --bg: #222730;
    --chassis: #191c23;
    --surface: #2e3440;
    --surface-hover: #3b4252;
    --surface-active: #3b4252;
    --deck-key: #2e3440;
    --deck-key-hover: #3b4252;
    --deck-key-active: #191c23;
    --border: #4c566a44;
    --border-subtle: #4c566a22;
    --border-highlight: #81a1c155;
    --text: #d8dee9;
    --text-muted: #4c566a;
    --text-dim: #667080;
    --accent: #81a1c1;
    --accent-fg: #191c23;
    --status-ok: #a3be8c;
    --status-warn: #ebcb8b;
    --status-danger: #bf616a;
    --status-info: #81a1c1;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #434c5e;
    --scroll-thumb: #4c566a66;
    --scroll-thumb-hover: #4c566aaa;
    --tag-bg: #3b4252;
    --reply-text: #d8dee9;
    --profile-bar-bg: #191c23;
    --active-bg: #3b4252;
    --active-border: #81a1c188;
    --input-bg: #222730;
    --input-border: #4c566a44;
    --input-focus: #81a1c1;
    --placeholder: #667080;
    --action-bg: #3b4252;
    --action-border: #4c566a66;
    --action-hover: #81a1c133;
    --action-hover-border: #81a1c1;
    --mic-bg: #3b4252;
    --mic-border: #4c566a66;
    --msg-you-bg: #3b4252;
    --msg-you-border: #4c566a66;
    --msg-oma-bg: #2e3440;
    --btn-bg: #81a1c1;
    --btn-fg: #191c23;
  }
  .theme-swatch-nord { background: #222730; }
  .theme-swatch-nord .theme-swatch-bar { background: #81a1c1; }
  .theme-swatch-nord i { background: #2e3440; border: 1px solid #4c566a55; }
  :root[data-theme="everforest"] {
    --bg: #21272c;
    --chassis: #181d20;
    --surface: #2d353b;
    --surface-hover: #343f44;
    --surface-active: #343f44;
    --deck-key: #2d353b;
    --deck-key-hover: #343f44;
    --deck-key-active: #181d20;
    --border: #47525844;
    --border-subtle: #47525822;
    --border-highlight: #7fbbb355;
    --text: #d3c6aa;
    --text-muted: #475258;
    --text-dim: #4f585e;
    --accent: #7fbbb3;
    --accent-fg: #181d20;
    --status-ok: #a7c080;
    --status-warn: #dbbc7f;
    --status-danger: #e67e80;
    --status-info: #7fbbb3;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #3d484d;
    --scroll-thumb: #47525866;
    --scroll-thumb-hover: #475258aa;
    --tag-bg: #343f44;
    --reply-text: #d3c6aa;
    --profile-bar-bg: #181d20;
    --active-bg: #343f44;
    --active-border: #7fbbb388;
    --input-bg: #21272c;
    --input-border: #47525844;
    --input-focus: #7fbbb3;
    --placeholder: #4f585e;
    --action-bg: #343f44;
    --action-border: #47525866;
    --action-hover: #7fbbb333;
    --action-hover-border: #7fbbb3;
    --mic-bg: #343f44;
    --mic-border: #47525866;
    --msg-you-bg: #343f44;
    --msg-you-border: #47525866;
    --msg-oma-bg: #2d353b;
    --btn-bg: #7fbbb3;
    --btn-fg: #181d20;
  }
  .theme-swatch-everforest { background: #21272c; }
  .theme-swatch-everforest .theme-swatch-bar { background: #7fbbb3; }
  .theme-swatch-everforest i { background: #2d353b; border: 1px solid #47525855; }
  :root[data-theme="kanagawa"] {
    --bg: #17171e;
    --chassis: #111116;
    --surface: #1f1f28;
    --surface-hover: #223249;
    --surface-active: #223249;
    --deck-key: #1f1f28;
    --deck-key-hover: #223249;
    --deck-key-active: #111116;
    --border: #54546D44;
    --border-subtle: #54546D22;
    --border-highlight: #dcd7ba55;
    --text: #dcd7ba;
    --text-muted: #54546D;
    --text-dim: #727169;
    --accent: #dcd7ba;
    --accent-fg: #111116;
    --status-ok: #76946a;
    --status-warn: #c0a36e;
    --status-danger: #c34043;
    --status-info: #7e9cd8;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #363646;
    --scroll-thumb: #54546D66;
    --scroll-thumb-hover: #54546Daa;
    --tag-bg: #223249;
    --reply-text: #dcd7ba;
    --profile-bar-bg: #111116;
    --active-bg: #223249;
    --active-border: #dcd7ba88;
    --input-bg: #17171e;
    --input-border: #54546D44;
    --input-focus: #dcd7ba;
    --placeholder: #727169;
    --action-bg: #223249;
    --action-border: #54546D66;
    --action-hover: #dcd7ba33;
    --action-hover-border: #dcd7ba;
    --mic-bg: #223249;
    --mic-border: #54546D66;
    --msg-you-bg: #223249;
    --msg-you-border: #54546D66;
    --msg-oma-bg: #1f1f28;
    --btn-bg: #dcd7ba;
    --btn-fg: #111116;
  }
  .theme-swatch-kanagawa { background: #17171e; }
  .theme-swatch-kanagawa .theme-swatch-bar { background: #dcd7ba; }
  .theme-swatch-kanagawa i { background: #1f1f28; border: 1px solid #54546D55; }
  :root[data-theme="rose-pine"] {
    --bg: #ede7e1;
    --chassis: #e1dbd5;
    --surface: #faf4ed;
    --surface-hover: #f2e9e1;
    --surface-active: #f2e9e1;
    --deck-key: #faf4ed;
    --deck-key-hover: #f2e9e1;
    --deck-key-active: #e1dbd5;
    --border: #cecacd44;
    --border-subtle: #cecacd22;
    --border-highlight: #56949f55;
    --text: #575279;
    --text-muted: #cecacd;
    --text-dim: #9893a5;
    --accent: #56949f;
    --accent-fg: #e1dbd5;
    --status-ok: #286983;
    --status-warn: #ea9d34;
    --status-danger: #b4637a;
    --status-info: #56949f;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #dfdad9;
    --scroll-thumb: #cecacd66;
    --scroll-thumb-hover: #cecacdaa;
    --tag-bg: #f2e9e1;
    --reply-text: #575279;
    --profile-bar-bg: #e1dbd5;
    --active-bg: #f2e9e1;
    --active-border: #56949f88;
    --input-bg: #ede7e1;
    --input-border: #cecacd44;
    --input-focus: #56949f;
    --placeholder: #9893a5;
    --action-bg: #f2e9e1;
    --action-border: #cecacd66;
    --action-hover: #56949f33;
    --action-hover-border: #56949f;
    --mic-bg: #f2e9e1;
    --mic-border: #cecacd66;
    --msg-you-bg: #f2e9e1;
    --msg-you-border: #cecacd66;
    --msg-oma-bg: #faf4ed;
    --btn-bg: #56949f;
    --btn-fg: #e1dbd5;
  }
  .theme-swatch-rose-pine { background: #ede7e1; }
  .theme-swatch-rose-pine .theme-swatch-bar { background: #56949f; }
  .theme-swatch-rose-pine i { background: #faf4ed; border: 1px solid #cecacd55; }
  :root[data-theme="hackerman"] {
    --bg: #080910;
    --chassis: #06060c;
    --surface: #0B0C16;
    --surface-hover: #151828;
    --surface-active: #151828;
    --deck-key: #0B0C16;
    --deck-key-hover: #151828;
    --deck-key-active: #06060c;
    --border: #2d345044;
    --border-subtle: #2d345022;
    --border-highlight: #82FB9C55;
    --text: #ddf7ff;
    --text-muted: #2d3450;
    --text-dim: #6a6e95;
    --accent: #82FB9C;
    --accent-fg: #06060c;
    --status-ok: #4fe88f;
    --status-warn: #50f7d4;
    --status-danger: #50f872;
    --status-info: #829dd4;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #1f253a;
    --scroll-thumb: #2d345066;
    --scroll-thumb-hover: #2d3450aa;
    --tag-bg: #151828;
    --reply-text: #ddf7ff;
    --profile-bar-bg: #06060c;
    --active-bg: #151828;
    --active-border: #82FB9C88;
    --input-bg: #080910;
    --input-border: #2d345044;
    --input-focus: #82FB9C;
    --placeholder: #6a6e95;
    --action-bg: #151828;
    --action-border: #2d345066;
    --action-hover: #82FB9C33;
    --action-hover-border: #82FB9C;
    --mic-bg: #151828;
    --mic-border: #2d345066;
    --msg-you-bg: #151828;
    --msg-you-border: #2d345066;
    --msg-oma-bg: #0B0C16;
    --btn-bg: #82FB9C;
    --btn-fg: #06060c;
  }
  .theme-swatch-hackerman { background: #080910; }
  .theme-swatch-hackerman .theme-swatch-bar { background: #82FB9C; }
  .theme-swatch-hackerman i { background: #0B0C16; border: 1px solid #2d345055; }
  :root[data-theme="matte-black"] {
    --bg: #0d0d0d;
    --chassis: #090909;
    --surface: #121212;
    --surface-hover: #1e1e1e;
    --surface-active: #1e1e1e;
    --deck-key: #121212;
    --deck-key-hover: #1e1e1e;
    --deck-key-active: #090909;
    --border: #33333344;
    --border-subtle: #33333322;
    --border-highlight: #e68e0d55;
    --text: #bebebe;
    --text-muted: #333333;
    --text-dim: #555555;
    --accent: #e68e0d;
    --accent-fg: #090909;
    --status-ok: #FFC107;
    --status-warn: #b91c1c;
    --status-danger: #D35F5F;
    --status-info: #e68e0d;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #2a2a2a;
    --scroll-thumb: #33333366;
    --scroll-thumb-hover: #333333aa;
    --tag-bg: #1e1e1e;
    --reply-text: #bebebe;
    --profile-bar-bg: #090909;
    --active-bg: #1e1e1e;
    --active-border: #e68e0d88;
    --input-bg: #0d0d0d;
    --input-border: #33333344;
    --input-focus: #e68e0d;
    --placeholder: #555555;
    --action-bg: #1e1e1e;
    --action-border: #33333366;
    --action-hover: #e68e0d33;
    --action-hover-border: #e68e0d;
    --mic-bg: #1e1e1e;
    --mic-border: #33333366;
    --msg-you-bg: #1e1e1e;
    --msg-you-border: #33333366;
    --msg-oma-bg: #121212;
    --btn-bg: #e68e0d;
    --btn-fg: #090909;
  }
  .theme-swatch-matte-black { background: #0d0d0d; }
  .theme-swatch-matte-black .theme-swatch-bar { background: #e68e0d; }
  .theme-swatch-matte-black i { background: #121212; border: 1px solid #33333355; }
  :root[data-theme="osaka-jade"] {
    --bg: #0c1512;
    --chassis: #090f0d;
    --surface: #111c18;
    --surface-hover: #23372B;
    --surface-active: #23372B;
    --deck-key: #111c18;
    --deck-key-hover: #23372B;
    --deck-key-active: #090f0d;
    --border: #53685B44;
    --border-subtle: #53685B22;
    --border-highlight: #50947555;
    --text: #C1C497;
    --text-muted: #53685B;
    --text-dim: #81B8A8;
    --accent: #509475;
    --accent-fg: #090f0d;
    --status-ok: #549e6a;
    --status-warn: #459451;
    --status-danger: #FF5345;
    --status-info: #509475;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #32473B;
    --scroll-thumb: #53685B66;
    --scroll-thumb-hover: #53685Baa;
    --tag-bg: #23372B;
    --reply-text: #C1C497;
    --profile-bar-bg: #090f0d;
    --active-bg: #23372B;
    --active-border: #50947588;
    --input-bg: #0c1512;
    --input-border: #53685B44;
    --input-focus: #509475;
    --placeholder: #81B8A8;
    --action-bg: #23372B;
    --action-border: #53685B66;
    --action-hover: #50947533;
    --action-hover-border: #509475;
    --mic-bg: #23372B;
    --mic-border: #53685B66;
    --msg-you-bg: #23372B;
    --msg-you-border: #53685B66;
    --msg-oma-bg: #111c18;
    --btn-bg: #509475;
    --btn-fg: #090f0d;
  }
  .theme-swatch-osaka-jade { background: #0c1512; }
  .theme-swatch-osaka-jade .theme-swatch-bar { background: #509475; }
  .theme-swatch-osaka-jade i { background: #111c18; border: 1px solid #53685B55; }
  :root[data-theme="retro-82"] {
    --bg: #031222;
    --chassis: #020c17;
    --surface: #05182e;
    --surface-hover: #0a2540;
    --surface-active: #0a2540;
    --deck-key: #05182e;
    --deck-key-hover: #0a2540;
    --deck-key-active: #020c17;
    --border: #2a6b7844;
    --border-subtle: #2a6b7822;
    --border-highlight: #faa96855;
    --text: #f6dcac;
    --text-muted: #2a6b78;
    --text-dim: #3f8f8a;
    --accent: #faa968;
    --accent-fg: #020c17;
    --status-ok: #028391;
    --status-warn: #e97b3c;
    --status-danger: #f85525;
    --status-info: #3f8f8a;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #134e5a;
    --scroll-thumb: #2a6b7866;
    --scroll-thumb-hover: #2a6b78aa;
    --tag-bg: #0a2540;
    --reply-text: #f6dcac;
    --profile-bar-bg: #020c17;
    --active-bg: #0a2540;
    --active-border: #faa96888;
    --input-bg: #031222;
    --input-border: #2a6b7844;
    --input-focus: #faa968;
    --placeholder: #3f8f8a;
    --action-bg: #0a2540;
    --action-border: #2a6b7866;
    --action-hover: #faa96833;
    --action-hover-border: #faa968;
    --mic-bg: #0a2540;
    --mic-border: #2a6b7866;
    --msg-you-bg: #0a2540;
    --msg-you-border: #2a6b7866;
    --msg-oma-bg: #05182e;
    --btn-bg: #faa968;
    --btn-fg: #020c17;
  }
  .theme-swatch-retro-82 { background: #031222; }
  .theme-swatch-retro-82 .theme-swatch-bar { background: #faa968; }
  .theme-swatch-retro-82 i { background: #05182e; border: 1px solid #2a6b7855; }
  :root[data-theme="ristretto"] {
    --bg: #211b1b;
    --chassis: #181414;
    --surface: #2c2525;
    --surface-hover: #3d2f2a;
    --surface-active: #3d2f2a;
    --deck-key: #2c2525;
    --deck-key-hover: #3d2f2a;
    --deck-key-active: #181414;
    --border: #72696a44;
    --border-subtle: #72696a22;
    --border-highlight: #f38d7055;
    --text: #e6d9db;
    --text-muted: #72696a;
    --text-dim: #72696a;
    --accent: #f38d70;
    --accent-fg: #181414;
    --status-ok: #adda78;
    --status-warn: #f9cc6c;
    --status-danger: #fd6883;
    --status-info: #f38d70;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #403e41;
    --scroll-thumb: #72696a66;
    --scroll-thumb-hover: #72696aaa;
    --tag-bg: #3d2f2a;
    --reply-text: #e6d9db;
    --profile-bar-bg: #181414;
    --active-bg: #3d2f2a;
    --active-border: #f38d7088;
    --input-bg: #211b1b;
    --input-border: #72696a44;
    --input-focus: #f38d70;
    --placeholder: #72696a;
    --action-bg: #3d2f2a;
    --action-border: #72696a66;
    --action-hover: #f38d7033;
    --action-hover-border: #f38d70;
    --mic-bg: #3d2f2a;
    --mic-border: #72696a66;
    --msg-you-bg: #3d2f2a;
    --msg-you-border: #72696a66;
    --msg-oma-bg: #2c2525;
    --btn-bg: #f38d70;
    --btn-fg: #181414;
  }
  .theme-swatch-ristretto { background: #211b1b; }
  .theme-swatch-ristretto .theme-swatch-bar { background: #f38d70; }
  .theme-swatch-ristretto i { background: #2c2525; border: 1px solid #72696a55; }
  :root[data-theme="lumon"] {
    --bg: #101b21;
    --chassis: #0b1216;
    --surface: #16242d;
    --surface-hover: #1b2d40;
    --surface-active: #1b2d40;
    --deck-key: #16242d;
    --deck-key-hover: #1b2d40;
    --deck-key-active: #0b1216;
    --border: #30486044;
    --border-subtle: #30486022;
    --border-highlight: #8bc9eb55;
    --text: #d6e2ee;
    --text-muted: #304860;
    --text-dim: #4d86b0;
    --accent: #8bc9eb;
    --accent-fg: #0b1216;
    --status-ok: #5e95bc;
    --status-warn: #6fa4c9;
    --status-danger: #4d86b0;
    --status-info: #6fb8e3;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #243d56;
    --scroll-thumb: #30486066;
    --scroll-thumb-hover: #304860aa;
    --tag-bg: #1b2d40;
    --reply-text: #d6e2ee;
    --profile-bar-bg: #0b1216;
    --active-bg: #1b2d40;
    --active-border: #8bc9eb88;
    --input-bg: #101b21;
    --input-border: #30486044;
    --input-focus: #8bc9eb;
    --placeholder: #4d86b0;
    --action-bg: #1b2d40;
    --action-border: #30486066;
    --action-hover: #8bc9eb33;
    --action-hover-border: #8bc9eb;
    --mic-bg: #1b2d40;
    --mic-border: #30486066;
    --msg-you-bg: #1b2d40;
    --msg-you-border: #30486066;
    --msg-oma-bg: #16242d;
    --btn-bg: #8bc9eb;
    --btn-fg: #0b1216;
  }
  .theme-swatch-lumon { background: #101b21; }
  .theme-swatch-lumon .theme-swatch-bar { background: #8bc9eb; }
  .theme-swatch-lumon i { background: #16242d; border: 1px solid #30486055; }
  :root[data-theme="solitude"] {
    --bg: #0c0e10;
    --chassis: #080a0b;
    --surface: #101315;
    --surface-hover: #101315;
    --surface-active: #101315;
    --deck-key: #101315;
    --deck-key-hover: #101315;
    --deck-key-active: #080a0b;
    --border: #4b4e5544;
    --border-subtle: #4b4e5522;
    --border-highlight: #79818655;
    --text: #cacccc;
    --text-muted: #4b4e55;
    --text-dim: #4b4e55;
    --accent: #798186;
    --accent-fg: #080a0b;
    --status-ok: #9fa5a9;
    --status-warn: #d9dbdc;
    --status-danger: #565d60;
    --status-info: #798186;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #343d41;
    --scroll-thumb: #4b4e5566;
    --scroll-thumb-hover: #4b4e55aa;
    --tag-bg: #101315;
    --reply-text: #cacccc;
    --profile-bar-bg: #080a0b;
    --active-bg: #101315;
    --active-border: #79818688;
    --input-bg: #0c0e10;
    --input-border: #4b4e5544;
    --input-focus: #798186;
    --placeholder: #4b4e55;
    --action-bg: #101315;
    --action-border: #4b4e5566;
    --action-hover: #79818633;
    --action-hover-border: #798186;
    --mic-bg: #101315;
    --mic-border: #4b4e5566;
    --msg-you-bg: #101315;
    --msg-you-border: #4b4e5566;
    --msg-oma-bg: #101315;
    --btn-bg: #798186;
    --btn-fg: #080a0b;
  }
  .theme-swatch-solitude { background: #0c0e10; }
  .theme-swatch-solitude .theme-swatch-bar { background: #798186; }
  .theme-swatch-solitude i { background: #101315; border: 1px solid #4b4e5555; }
  :root[data-theme="vantablack"] {
    --bg: #090909;
    --chassis: #070707;
    --surface: #000000;
    --surface-hover: #1a1a1a;
    --surface-active: #1a1a1a;
    --deck-key: #000000;
    --deck-key-hover: #1a1a1a;
    --deck-key-active: #070707;
    --border: #7a7a7a44;
    --border-subtle: #7a7a7a22;
    --border-highlight: #8d8d8d55;
    --text: #ffffff;
    --text-muted: #7a7a7a;
    --text-dim: #505050;
    --accent: #8d8d8d;
    --accent-fg: #070707;
    --status-ok: #b6b6b6;
    --status-warn: #cecece;
    --status-danger: #a4a4a4;
    --status-info: #8d8d8d;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #1a1a1a;
    --scroll-thumb: #7a7a7a66;
    --scroll-thumb-hover: #7a7a7aaa;
    --tag-bg: #1a1a1a;
    --reply-text: #ffffff;
    --profile-bar-bg: #070707;
    --active-bg: #1a1a1a;
    --active-border: #8d8d8d88;
    --input-bg: #090909;
    --input-border: #7a7a7a44;
    --input-focus: #8d8d8d;
    --placeholder: #505050;
    --action-bg: #1a1a1a;
    --action-border: #7a7a7a66;
    --action-hover: #8d8d8d33;
    --action-hover-border: #8d8d8d;
    --mic-bg: #1a1a1a;
    --mic-border: #7a7a7a66;
    --msg-you-bg: #1a1a1a;
    --msg-you-border: #7a7a7a66;
    --msg-oma-bg: #000000;
    --btn-bg: #8d8d8d;
    --btn-fg: #070707;
  }
  .theme-swatch-vantablack { background: #090909; }
  .theme-swatch-vantablack .theme-swatch-bar { background: #8d8d8d; }
  .theme-swatch-vantablack i { background: #000000; border: 1px solid #7a7a7a55; }
  :root[data-theme="ethereal"] {
    --bg: #040816;
    --chassis: #030610;
    --surface: #060B1E;
    --surface-hover: #131a3a;
    --surface-active: #131a3a;
    --deck-key: #060B1E;
    --deck-key-hover: #131a3a;
    --deck-key-active: #030610;
    --border: #6d7db644;
    --border-subtle: #6d7db622;
    --border-highlight: #7d82d955;
    --text: #ffcead;
    --text-muted: #6d7db6;
    --text-dim: #6d7db6;
    --accent: #7d82d9;
    --accent-fg: #030610;
    --status-ok: #92a593;
    --status-warn: #E9BB4F;
    --status-danger: #ED5B5A;
    --status-info: #7d82d9;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #252e56;
    --scroll-thumb: #6d7db666;
    --scroll-thumb-hover: #6d7db6aa;
    --tag-bg: #131a3a;
    --reply-text: #ffcead;
    --profile-bar-bg: #030610;
    --active-bg: #131a3a;
    --active-border: #7d82d988;
    --input-bg: #040816;
    --input-border: #6d7db644;
    --input-focus: #7d82d9;
    --placeholder: #6d7db6;
    --action-bg: #131a3a;
    --action-border: #6d7db666;
    --action-hover: #7d82d933;
    --action-hover-border: #7d82d9;
    --mic-bg: #131a3a;
    --mic-border: #6d7db666;
    --msg-you-bg: #131a3a;
    --msg-you-border: #6d7db666;
    --msg-oma-bg: #060B1E;
    --btn-bg: #7d82d9;
    --btn-fg: #030610;
  }
  .theme-swatch-ethereal { background: #040816; }
  .theme-swatch-ethereal .theme-swatch-bar { background: #7d82d9; }
  .theme-swatch-ethereal i { background: #060B1E; border: 1px solid #6d7db655; }
  :root[data-theme="miasma"] {
    --bg: #191919;
    --chassis: #121212;
    --surface: #222222;
    --surface-hover: #2c2c2c;
    --surface-active: #2c2c2c;
    --deck-key: #222222;
    --deck-key-hover: #2c2c2c;
    --deck-key-active: #121212;
    --border: #66666644;
    --border-subtle: #66666622;
    --border-highlight: #78824b55;
    --text: #c2c2b0;
    --text-muted: #666666;
    --text-dim: #555555;
    --accent: #78824b;
    --accent-fg: #121212;
    --status-ok: #5f875f;
    --status-warn: #b36d43;
    --status-danger: #685742;
    --status-info: #78824b;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #383838;
    --scroll-thumb: #66666666;
    --scroll-thumb-hover: #666666aa;
    --tag-bg: #2c2c2c;
    --reply-text: #c2c2b0;
    --profile-bar-bg: #121212;
    --active-bg: #2c2c2c;
    --active-border: #78824b88;
    --input-bg: #191919;
    --input-border: #66666644;
    --input-focus: #78824b;
    --placeholder: #555555;
    --action-bg: #2c2c2c;
    --action-border: #66666666;
    --action-hover: #78824b33;
    --action-hover-border: #78824b;
    --mic-bg: #2c2c2c;
    --mic-border: #66666666;
    --msg-you-bg: #2c2c2c;
    --msg-you-border: #66666666;
    --msg-oma-bg: #222222;
    --btn-bg: #78824b;
    --btn-fg: #121212;
  }
  .theme-swatch-miasma { background: #191919; }
  .theme-swatch-miasma .theme-swatch-bar { background: #78824b; }
  .theme-swatch-miasma i { background: #222222; border: 1px solid #66666655; }
  :root[data-theme="last-horizon"] {
    --bg: #090809;
    --chassis: #060606;
    --surface: #0c0b0c;
    --surface-hover: #0c0b0c;
    --surface-active: #0c0b0c;
    --deck-key: #0c0b0c;
    --deck-key-hover: #0c0b0c;
    --deck-key-active: #060606;
    --border: #584e5144;
    --border-subtle: #584e5122;
    --border-highlight: #b5979055;
    --text: #FAFCFB;
    --text-muted: #584e51;
    --text-dim: #584e51;
    --accent: #b59790;
    --accent-fg: #060606;
    --status-ok: #87a9b0;
    --status-warn: #6B5E73;
    --status-danger: #c38b7b;
    --status-info: #b59790;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #584e51;
    --scroll-thumb: #584e5166;
    --scroll-thumb-hover: #584e51aa;
    --tag-bg: #0c0b0c;
    --reply-text: #FAFCFB;
    --profile-bar-bg: #060606;
    --active-bg: #0c0b0c;
    --active-border: #b5979088;
    --input-bg: #090809;
    --input-border: #584e5144;
    --input-focus: #b59790;
    --placeholder: #584e51;
    --action-bg: #0c0b0c;
    --action-border: #584e5166;
    --action-hover: #b5979033;
    --action-hover-border: #b59790;
    --mic-bg: #0c0b0c;
    --mic-border: #584e5166;
    --msg-you-bg: #0c0b0c;
    --msg-you-border: #584e5166;
    --msg-oma-bg: #0c0b0c;
    --btn-bg: #b59790;
    --btn-fg: #060606;
  }
  .theme-swatch-last-horizon { background: #090809; }
  .theme-swatch-last-horizon .theme-swatch-bar { background: #b59790; }
  .theme-swatch-last-horizon i { background: #0c0b0c; border: 1px solid #584e5155; }
  :root[data-theme="catppuccin-latte"] {
    --bg: #e3e4e8;
    --chassis: #d7d8dc;
    --surface: #eff1f5;
    --surface-hover: #dce0e8;
    --surface-active: #dce0e8;
    --deck-key: #eff1f5;
    --deck-key-hover: #dce0e8;
    --deck-key-active: #d7d8dc;
    --border: #acb0be44;
    --border-subtle: #acb0be22;
    --border-highlight: #1e66f555;
    --text: #4c4f69;
    --text-muted: #acb0be;
    --text-dim: #9ca0b0;
    --accent: #1e66f5;
    --accent-fg: #d7d8dc;
    --status-ok: #40a02b;
    --status-warn: #df8e1d;
    --status-danger: #d20f39;
    --status-info: #1e66f5;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #ccd0da;
    --scroll-thumb: #acb0be66;
    --scroll-thumb-hover: #acb0beaa;
    --tag-bg: #dce0e8;
    --reply-text: #4c4f69;
    --profile-bar-bg: #d7d8dc;
    --active-bg: #dce0e8;
    --active-border: #1e66f588;
    --input-bg: #e3e4e8;
    --input-border: #acb0be44;
    --input-focus: #1e66f5;
    --placeholder: #9ca0b0;
    --action-bg: #dce0e8;
    --action-border: #acb0be66;
    --action-hover: #1e66f533;
    --action-hover-border: #1e66f5;
    --mic-bg: #dce0e8;
    --mic-border: #acb0be66;
    --msg-you-bg: #dce0e8;
    --msg-you-border: #acb0be66;
    --msg-oma-bg: #eff1f5;
    --btn-bg: #1e66f5;
    --btn-fg: #d7d8dc;
  }
  .theme-swatch-catppuccin-latte { background: #e3e4e8; }
  .theme-swatch-catppuccin-latte .theme-swatch-bar { background: #1e66f5; }
  .theme-swatch-catppuccin-latte i { background: #eff1f5; border: 1px solid #acb0be55; }
  :root[data-theme="flexoki-light"] {
    --bg: #f2efe4;
    --chassis: #e5e2d8;
    --surface: #FFFCF0;
    --surface-hover: #E6E4D9;
    --surface-active: #E6E4D9;
    --deck-key: #FFFCF0;
    --deck-key-hover: #E6E4D9;
    --deck-key-active: #e5e2d8;
    --border: #B7B5AC44;
    --border-subtle: #B7B5AC22;
    --border-highlight: #205EA655;
    --text: #100F0F;
    --text-muted: #B7B5AC;
    --text-dim: #878580;
    --accent: #205EA6;
    --accent-fg: #e5e2d8;
    --status-ok: #879A39;
    --status-warn: #D0A215;
    --status-danger: #D14D41;
    --status-info: #205EA6;
    --key-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 2px 4px rgba(0, 0, 0, 0.45);
    --key-shadow-active: inset 0 2px 5px rgba(0, 0, 0, 0.85);
    --selection-bg: #CECDC3;
    --scroll-thumb: #B7B5AC66;
    --scroll-thumb-hover: #B7B5ACaa;
    --tag-bg: #E6E4D9;
    --reply-text: #100F0F;
    --profile-bar-bg: #e5e2d8;
    --active-bg: #E6E4D9;
    --active-border: #205EA688;
    --input-bg: #f2efe4;
    --input-border: #B7B5AC44;
    --input-focus: #205EA6;
    --placeholder: #878580;
    --action-bg: #E6E4D9;
    --action-border: #B7B5AC66;
    --action-hover: #205EA633;
    --action-hover-border: #205EA6;
    --mic-bg: #E6E4D9;
    --mic-border: #B7B5AC66;
    --msg-you-bg: #E6E4D9;
    --msg-you-border: #B7B5AC66;
    --msg-oma-bg: #FFFCF0;
    --btn-bg: #205EA6;
    --btn-fg: #e5e2d8;
  }
  .theme-swatch-flexoki-light { background: #f2efe4; }
  .theme-swatch-flexoki-light .theme-swatch-bar { background: #205EA6; }
  .theme-swatch-flexoki-light i { background: #FFFCF0; border: 1px solid #B7B5AC55; }
  .theme-swatch-auto { background: linear-gradient(135deg, #1e1e1e 0%, #161622 50%, #222730 100%); }
  .theme-swatch-auto .theme-swatch-bar { background: linear-gradient(90deg, #7daea3, #89b4fa, #81a1c1); }
  .theme-swatch-auto i { background: #282828; border: 1px solid rgba(255, 255, 255, 0.15); }

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
      <input id="pin-input" type="password" pattern="[0-9]*" inputmode="numeric" maxlength="8" placeholder="••••" autocomplete="off" readonly>
    </div>
    <div class="pin-keypad" id="pin-keypad">
      <button type="button" class="pin-key" data-digit="1">1</button>
      <button type="button" class="pin-key" data-digit="2">2</button>
      <button type="button" class="pin-key" data-digit="3">3</button>
      <button type="button" class="pin-key" data-digit="4">4</button>
      <button type="button" class="pin-key" data-digit="5">5</button>
      <button type="button" class="pin-key" data-digit="6">6</button>
      <button type="button" class="pin-key" data-digit="7">7</button>
      <button type="button" class="pin-key" data-digit="8">8</button>
      <button type="button" class="pin-key" data-digit="9">9</button>
      <button type="button" class="pin-key action-key" id="pin-clear-key">Clear</button>
      <button type="button" class="pin-key" data-digit="0">0</button>
      <button type="button" class="pin-key action-key" id="pin-backspace-key">⌫</button>
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

    <!-- Three panes: keys, theme, security -->
    <div class="settings-tabs" role="tablist">
      <button class="settings-tab active" id="tab-keys" role="tab" aria-selected="true" aria-controls="settings-panel-keys">
        <svg class="icon-svg" style="width:14px;height:14px;" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
        API Keys
      </button>
      <button class="settings-tab" id="tab-theme" role="tab" aria-selected="false" aria-controls="settings-panel-theme">
        <svg class="icon-svg" style="width:14px;height:14px;" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a10 10 0 0 0 0 20 5 5 0 0 1 0-10 5 5 0 0 0 0-10z"></path></svg>
        Theme
      </button>
      <button class="settings-tab" id="tab-security" role="tab" aria-selected="false" aria-controls="settings-panel-security">
        <svg class="icon-svg" style="width:14px;height:14px;" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
        Security
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

        <!-- AI Dictation Polish (Amical style) -->
        <div class="setting-group" id="group-ai-dictate">
          <label class="setting-label" for="setting-ai-dictate-polish" style="display: flex; align-items: center; justify-content: space-between; cursor: pointer;">
            <span>AI Dictation Polish</span>
            <input type="checkbox" id="setting-ai-dictate-polish" style="cursor: pointer;" checked>
          </label>
          <div class="setting-desc">Clean transcribed speech with AI: remove filler words ("um", "uh"), fix punctuation, and format code/chat for the active app.</div>
        </div>

        <!-- Mic Trigger Mode -->
        <div class="setting-group" id="group-mic-trigger">
          <label class="setting-label" for="setting-mic-trigger">Mic Activation</label>
          <select id="setting-mic-trigger" class="setting-select">
            <option value="both">Both (Hold to talk OR Tap to toggle)</option>
            <option value="hold">Hold to talk (Push-to-talk only)</option>
            <option value="tap">Tap to toggle (Tap to start / stop)</option>
          </select>
          <div class="setting-desc">In 'Both' mode: quick tap latches recording hands-free with animated wave, or hold to talk.</div>
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
          <button class="theme-card" data-theme-choice="auto" title="Auto Sync — Matches Omarchy desktop theme live">
            <div class="theme-swatch theme-swatch-auto">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Auto (Desktop)</span>
            <span class="theme-desc">Matches Omarchy desktop live</span>
            <span class="theme-check"></span>
          </button>
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
          <button class="theme-card" data-theme-choice="gruvbox" title="Gruvbox — Warm retro groove palette">
            <div class="theme-swatch theme-swatch-gruvbox">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Gruvbox</span>
            <span class="theme-desc">Warm retro groove palette</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="catppuccin" title="Catppuccin — Soothing pastel dark">
            <div class="theme-swatch theme-swatch-catppuccin">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Catppuccin</span>
            <span class="theme-desc">Soothing pastel dark</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="tokyo-night" title="Tokyo Night — Vibrant neon cyberpunk night">
            <div class="theme-swatch theme-swatch-tokyo-night">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Tokyo Night</span>
            <span class="theme-desc">Vibrant neon cyberpunk night</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="nord" title="Nord — Arctic north-bluish clean">
            <div class="theme-swatch theme-swatch-nord">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Nord</span>
            <span class="theme-desc">Arctic north-bluish clean</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="everforest" title="Everforest — Comforting natural green forest">
            <div class="theme-swatch theme-swatch-everforest">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Everforest</span>
            <span class="theme-desc">Comforting natural green forest</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="kanagawa" title="Kanagawa — Edo-period ink wash painting">
            <div class="theme-swatch theme-swatch-kanagawa">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Kanagawa</span>
            <span class="theme-desc">Edo-period ink wash painting</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="rose-pine" title="Rose Pine — Warm pine & soft bougainvillea">
            <div class="theme-swatch theme-swatch-rose-pine">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Rose Pine</span>
            <span class="theme-desc">Warm pine & soft bougainvillea</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="hackerman" title="Hackerman — Matrix neon terminal glow">
            <div class="theme-swatch theme-swatch-hackerman">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Hackerman</span>
            <span class="theme-desc">Matrix neon terminal glow</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="matte-black" title="Matte Black — Stealth black with amber pop">
            <div class="theme-swatch theme-swatch-matte-black">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Matte Black</span>
            <span class="theme-desc">Stealth black with amber pop</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="osaka-jade" title="Osaka Jade — Moody jade & sage reflections">
            <div class="theme-swatch theme-swatch-osaka-jade">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Osaka Jade</span>
            <span class="theme-desc">Moody jade & sage reflections</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="retro-82" title="Retro 82 — 1982 arcade navy & sunset orange">
            <div class="theme-swatch theme-swatch-retro-82">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Retro 82</span>
            <span class="theme-desc">1982 arcade navy & sunset orange</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="ristretto" title="Ristretto — Rich espresso & dark cocoa">
            <div class="theme-swatch theme-swatch-ristretto">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Ristretto</span>
            <span class="theme-desc">Rich espresso & dark cocoa</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="lumon" title="Lumon — Severance cold terminal clean">
            <div class="theme-swatch theme-swatch-lumon">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Lumon</span>
            <span class="theme-desc">Severance cold terminal clean</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="solitude" title="Solitude — Deep graphite minimal solitude">
            <div class="theme-swatch theme-swatch-solitude">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Solitude</span>
            <span class="theme-desc">Deep graphite minimal solitude</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="vantablack" title="Vantablack — True pure OLED pitch black">
            <div class="theme-swatch theme-swatch-vantablack">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Vantablack</span>
            <span class="theme-desc">True pure OLED pitch black</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="ethereal" title="Ethereal — Cosmic deep space purple">
            <div class="theme-swatch theme-swatch-ethereal">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Ethereal</span>
            <span class="theme-desc">Cosmic deep space purple</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="miasma" title="Miasma — Swamp olive & earth tones">
            <div class="theme-swatch theme-swatch-miasma">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Miasma</span>
            <span class="theme-desc">Swamp olive & earth tones</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="last-horizon" title="Last Horizon — Minimal dusk horizon">
            <div class="theme-swatch theme-swatch-last-horizon">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Last Horizon</span>
            <span class="theme-desc">Minimal dusk horizon</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="catppuccin-latte" title="Catppuccin Latte — Crisp light pastel">
            <div class="theme-swatch theme-swatch-catppuccin-latte">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Catppuccin Latte</span>
            <span class="theme-desc">Crisp light pastel</span>
            <span class="theme-check"></span>
          </button>
          <button class="theme-card" data-theme-choice="flexoki-light" title="Flexoki Light — Inky warm paper editorial">
            <div class="theme-swatch theme-swatch-flexoki-light">
              <span class="theme-swatch-bar"></span>
              <span class="theme-swatch-keys"><i></i><i></i><i></i></span>
            </div>
            <span class="theme-name">Flexoki Light</span>
            <span class="theme-desc">Inky warm paper editorial</span>
            <span class="theme-check"></span>
          </button>
        </div>
        <div class="setting-group" style="margin-top: 10px;">
          <div class="setting-desc">Phosphor and Amber swap the whole deck palette — keys, borders, input focus and status colours. Monospace readouts stay monospace.</div>
        </div>
      </div>

      <!-- ===================== SECURITY PANE ===================== -->
      <div id="settings-panel-security" role="tabpanel" aria-labelledby="tab-security" style="display: none; flex-direction: column; gap: 14px;">
        <div class="setting-group">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <label class="setting-label" style="margin: 0;">Deck Session Lock</label>
            <span id="security-pin-badge" class="tag" style="font-size: 0.65rem; padding: 2px 8px;">CHECKING...</span>
          </div>
          <div class="setting-desc" id="security-pin-desc">Protect your OmaDeck remote with a numeric PIN so unauthorized users or devices cannot trigger shortcuts or run commands on your PC.</div>
        </div>

        <!-- PIN Configuration -->
        <div class="setting-group" style="background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 12px; display: flex; flex-direction: column; gap: 8px;">
          <label class="setting-label" for="setting-new-pin">Set / Change PIN (4–8 digits)</label>
          <input type="password" id="setting-current-pin" class="setting-input" pattern="[0-9]*" inputmode="numeric" maxlength="8" placeholder="Current PIN" autocomplete="off" style="letter-spacing: 0.25em; font-size: 1.1rem; text-align: center; display: none;">
          <div style="display: flex; gap: 8px;">
            <input type="password" id="setting-new-pin" class="setting-input" pattern="[0-9]*" inputmode="numeric" maxlength="8" placeholder="Enter new PIN" autocomplete="off" style="flex: 1; letter-spacing: 0.25em; font-size: 1.1rem; text-align: center;">
            <button type="button" class="chat-btn" id="save-pin-btn" style="white-space: nowrap; padding: 0 14px; font-weight: 600;">Save PIN</button>
          </div>
          <div style="display: flex; gap: 8px; margin-top: 4px;">
            <button type="button" class="chat-btn" id="disable-pin-btn" style="color: var(--status-danger); border-color: var(--status-danger); background: transparent; display: none;">Disable PIN Lock</button>
            <button type="button" class="chat-btn" id="lock-deck-now-btn" style="display: none; margin-left: auto;">Lock Remote Now</button>
          </div>
        </div>

        <!-- Auto-lock on app switch / background -->
        <div class="setting-group" style="background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 12px;">
          <div style="display: flex; align-items: flex-start; gap: 10px;">
            <input type="checkbox" id="setting-autolock-app-switch" style="margin-top: 3px; cursor: pointer;" checked>
            <div>
              <label for="setting-autolock-app-switch" style="font-weight: 600; font-size: 0.85rem; color: var(--text); cursor: pointer; display: block;">Auto-Lock on App Switch / Background</label>
              <div class="setting-desc" style="margin-top: 3px;">Asks for PIN again when you switch away to another app, lock your phone, or reopen the remote.</div>
            </div>
          </div>
        </div>

        <div id="security-status" class="status-box" style="display: none;"></div>
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
        <button class="icon-chip" id="app-lock-btn" title="Lock Deck" style="display:none;">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
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
      <!-- Aux Keys for Typing (Always Visible) -->
      <div class="aux-keys" id="aux-keys">
        <button class="key-chip" data-key="enter" title="Send Enter to PC">↵ Enter</button>
        <button class="key-chip" data-key="backspace" title="Send Backspace to PC">⌫ Del</button>
        <button class="key-chip" data-key="tab" title="Send Tab to PC">Tab ⇥</button>
        <button class="key-chip" data-key="paste" title="Paste clipboard into PC">📋 Paste</button>
        <button class="key-chip" data-key="escape" title="Send Escape to PC">Esc</button>
      </div>

      <!-- Mode Toggle -->
      <div class="mode-bar">
        <button class="mode-pill active" id="mode-cmd" title="Instant voice & desktop commands">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
          <span>Command</span>
        </button>
        <span class="mode-sep">(or)</span>
        <button class="mode-pill" id="mode-type" title="Direct keystrokes into active PC window">
          <svg class="icon-svg" style="width:13px;height:13px;" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"></rect><line x1="6" y1="8" x2="6" y2="8"></line><line x1="10" y1="8" x2="10" y2="8"></line><line x1="14" y1="8" x2="14" y2="8"></line><line x1="18" y1="8" x2="18" y2="8"></line><line x1="6" y1="12" x2="6" y2="12"></line><line x1="10" y1="12" x2="10" y2="12"></line><line x1="14" y1="12" x2="14" y2="12"></line><line x1="18" y1="12" x2="18" y2="12"></line><line x1="7" y1="16" x2="17" y2="16"></line></svg>
          <span>Direct Type</span>
        </button>
      </div>

      <!-- Command Bar with Inline Dictation Mic -->
      <div class="cmd-bar">
        <div class="cmd-input-wrap">
          <input id="cmd-input" type="text" placeholder="Type a command…" autocomplete="off" autocorrect="off">
          <button id="dictate-btn" class="input-inline-btn" title="Dictate speech into input box">
            <svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>
          </button>
        </div>
        <button id="type-direct-btn" class="cmd-action-btn" title="Type into PC">Type</button>
        <button id="cmd-send" class="cmd-action-btn">Send</button>
        <button id="mic-btn" title="Voice command (Hold or Tap)">
          <svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>
        </button>
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
        <svg class="icon-svg" viewBox="0 0 24 24"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path></svg>
        <span>Utils</span>
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
        <div class="btn-grid-5">
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
          <button class="chip" data-key="ctrl+z" title="Suspend Process (Ctrl+Z). It stays in memory and keeps its port.">
            <svg class="icon icon-svg" viewBox="0 0 24 24"><rect x="6" y="5" width="4" height="14" rx="1"></rect><rect x="14" y="5" width="4" height="14" rx="1"></rect></svg>
            <span class="label">Ctrl+Z</span>
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

    <!-- PROFILE 5: UTILS & SYSTEM (System Tools: btop, T3 Dashboard, Lazygit, Docker, Terminator, Zen Mode) -->
    <div class="profile-view" id="profile-custom" data-profile-section="custom" style="display: none;">
      <section class="control-section">
        <div class="section-header">
          <span class="section-title">Dev &amp; System</span>
          <span class="section-badge">UTILS</span>
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
let hasPin = HAS_PIN;
let TOKEN = localStorage.getItem('oma_auth_token') || "";

// Read pairing token from URL query or hash if provided (e.g. from terminal link)
try {
  const urlParams = new URLSearchParams(window.location.search);
  const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  const queryTok = urlParams.get('token') || hashParams.get('token');
  if (queryTok && queryTok.trim()) {
    TOKEN = queryTok.trim();
    localStorage.setItem('oma_auth_token', TOKEN);
    if (window.history && window.history.replaceState) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }
} catch(e) {}

let headers = {"X-Token": TOKEN, "Content-Type": "application/json"};

function haptic(ms = 8) {
  if (navigator.vibrate) {
    try { navigator.vibrate(ms); } catch(e) {}
  }
}

function updateToken(tok) {
  TOKEN = tok;
  if (!hasPin) {
    localStorage.setItem('oma_auth_token', tok);
  } else {
    localStorage.removeItem('oma_auth_token');
  }
  headers = {"X-Token": TOKEN, "Content-Type": "application/json"};
}

const pinOverlay = document.getElementById('pin-overlay');
const pinInput = document.getElementById('pin-input');
const pinError = document.getElementById('pin-error');
const pinSubmit = document.getElementById('pin-submit-btn');

function showPinScreen() {
  if (pinOverlay && pinOverlay.style.display !== 'flex') {
    pinOverlay.style.display = 'flex';
    if (pinInput) pinInput.value = '';
    if (pinError) pinError.textContent = '';
  }
}

function hidePinScreen() {
  if (pinOverlay) pinOverlay.style.display = 'none';
  loadHistory();
  pollState();
  loadSettings();
}

function lockSession() {
  if (!hasPin) return;
  TOKEN = "";
  headers = {"X-Token": "", "Content-Type": "application/json"};
  const sm = document.getElementById('settings-modal');
  const hm = document.getElementById('history-modal');
  if (sm) sm.style.display = 'none';
  if (hm) hm.style.display = 'none';
  showPinScreen();
}

async function submitPin() {
  if (!pinInput) return;
  const pin = pinInput.value.trim();
  if (!pin) return;
  haptic(10);
  if (pinError) pinError.textContent = 'Verifying…';
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
      if (pinError) pinError.textContent = d.error || 'Incorrect PIN';
      pinInput.value = '';
    }
  } catch(e) {
    if (pinError) pinError.textContent = 'Connection error';
  }
}

if (pinSubmit) pinSubmit.onclick = submitPin;

// On-screen touch keypad
const pinKeypad = document.getElementById('pin-keypad');
if (pinKeypad) {
  pinKeypad.querySelectorAll('.pin-key[data-digit]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      haptic(10);
      if (pinInput && pinInput.value.length < 8) {
        pinInput.value += btn.getAttribute('data-digit');
        if (pinError) pinError.textContent = '';
      }
    });
  });
}
const pinClearKey = document.getElementById('pin-clear-key');
if (pinClearKey) {
  pinClearKey.addEventListener('click', (e) => {
    e.preventDefault();
    haptic(10);
    if (pinInput) pinInput.value = '';
    if (pinError) pinError.textContent = '';
  });
}
const pinBackspaceKey = document.getElementById('pin-backspace-key');
if (pinBackspaceKey) {
  pinBackspaceKey.addEventListener('click', (e) => {
    e.preventDefault();
    haptic(10);
    if (pinInput) pinInput.value = pinInput.value.slice(0, -1);
    if (pinError) pinError.textContent = '';
  });
}

// Physical keyboard listener
window.addEventListener('keydown', e => {
  if (!pinOverlay || pinOverlay.style.display !== 'flex') return;
  if (e.key >= '0' && e.key <= '9') {
    if (pinInput && pinInput.value.length < 8) {
      pinInput.value += e.key;
      if (pinError) pinError.textContent = '';
    }
  } else if (e.key === 'Backspace') {
    if (pinInput) pinInput.value = pinInput.value.slice(0, -1);
    if (pinError) pinError.textContent = '';
  } else if (e.key === 'Enter') {
    submitPin();
  }
});

let _promptingAuth = false;
function checkAuth(r) {
  if (r && (r.status === 401 || r.status === 403)) {
    if (hasPin) {
      localStorage.removeItem('oma_auth_token');
      TOKEN = "";
      headers = {"X-Token": "", "Content-Type": "application/json"};
      showPinScreen();
      return true;
    }
    if (!_promptingAuth) {
      _promptingAuth = true;
      setTimeout(() => {
        const entered = prompt("Enter Desktop Pairing Token (printed in terminal):");
        _promptingAuth = false;
        if (entered && entered.trim()) {
          updateToken(entered.trim());
          pollState();
        }
      }, 100);
    }
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
  if (hasPin && !TOKEN) { showPinScreen(); return; }
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

let _lastHiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    _lastHiddenAt = Date.now();
  } else {
    const autoLockEnabled = localStorage.getItem('oma_autolock_switch') !== '0';
    if (hasPin && autoLockEnabled) {
      if (_lastHiddenAt > 0 && (Date.now() - _lastHiddenAt > 500)) {
        lockSession();
        return;
      }
    }
    if (TOKEN) {
      pollState();
    }
  }
});

window.addEventListener('pagehide', () => {
  _lastHiddenAt = Date.now();
});

if (hasPin && !TOKEN) {
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
const tabSecurity = document.getElementById('tab-security');
const panelKeys = document.getElementById('settings-panel-keys');
const panelTheme = document.getElementById('settings-panel-theme');
const panelSecurity = document.getElementById('settings-panel-security');
const saveSettingsBtn = document.getElementById('save-settings-btn');
const settingsStatus = document.getElementById('settings-status');

// Security panel controls
const securityPinBadge = document.getElementById('security-pin-badge');
const settingCurrentPin = document.getElementById('setting-current-pin');
const settingNewPin = document.getElementById('setting-new-pin');
const savePinBtn = document.getElementById('save-pin-btn');
const disablePinBtn = document.getElementById('disable-pin-btn');
const lockDeckNowBtn = document.getElementById('lock-deck-now-btn');
const appLockBtn = document.getElementById('app-lock-btn');
const autolockToggle = document.getElementById('setting-autolock-app-switch');
const securityStatus = document.getElementById('security-status');

function showSecurityStatus(msg, type = 'info') {
  if (!securityStatus) return;
  securityStatus.className = 'status-box ' + type;
  securityStatus.textContent = msg;
  securityStatus.style.display = 'block';
  setTimeout(() => {
    if (securityStatus) securityStatus.style.display = 'none';
  }, 4000);
}

function updateSecurityUi(pinSet) {
  hasPin = Boolean(pinSet);
  if (securityPinBadge) {
    if (hasPin) {
      securityPinBadge.textContent = 'ACTIVE';
      securityPinBadge.style.background = 'var(--status-ready)';
      securityPinBadge.style.color = '#000';
    } else {
      securityPinBadge.textContent = 'DISABLED';
      securityPinBadge.style.background = 'var(--surface-raised)';
      securityPinBadge.style.color = 'var(--text-muted)';
    }
  }
  if (settingCurrentPin) {
    settingCurrentPin.style.display = hasPin ? 'block' : 'none';
    if (!hasPin) settingCurrentPin.value = '';
  }
  if (disablePinBtn) disablePinBtn.style.display = hasPin ? 'inline-block' : 'none';
  if (lockDeckNowBtn) lockDeckNowBtn.style.display = hasPin ? 'inline-block' : 'none';
  if (appLockBtn) appLockBtn.style.display = hasPin ? 'inline-flex' : 'none';
}

if (autolockToggle) {
  autolockToggle.checked = localStorage.getItem('oma_autolock_switch') !== '0';
  autolockToggle.addEventListener('change', () => {
    localStorage.setItem('oma_autolock_switch', autolockToggle.checked ? '1' : '0');
  });
}

if (savePinBtn) {
  savePinBtn.onclick = async () => {
    const pin = (settingNewPin?.value || '').trim();
    const current_pin = (settingCurrentPin?.value || '').trim();
    if (hasPin && !current_pin) {
      showSecurityStatus('Current PIN is required to change PIN.', 'error');
      return;
    }
    if (!pin || !/^\d{4,8}$/.test(pin)) {
      showSecurityStatus('New PIN must be 4 to 8 numeric digits.', 'error');
      return;
    }
    haptic(10);
    savePinBtn.disabled = true;
    savePinBtn.textContent = 'Saving…';
    try {
      const res = await fetch('/pin', {
        method: 'POST',
        headers,
        body: JSON.stringify({ action: 'set', pin, current_pin })
      });
      const data = await res.json();
      if (data.ok) {
        if (settingNewPin) settingNewPin.value = '';
        if (settingCurrentPin) settingCurrentPin.value = '';
        showSecurityStatus(data.message || 'PIN updated! Session lock active.', 'success');
        updateSecurityUi(true);
        if (data.token) updateToken(data.token);
      } else {
        showSecurityStatus(data.error || 'Failed to update PIN', 'error');
      }
    } catch (e) {
      showSecurityStatus('Error updating PIN: ' + e, 'error');
    } finally {
      savePinBtn.disabled = false;
      savePinBtn.textContent = 'Save PIN';
    }
  };
}

if (disablePinBtn) {
  disablePinBtn.onclick = async () => {
    let current_pin = (settingCurrentPin?.value || '').trim();
    if (hasPin && !current_pin) {
      current_pin = prompt('Enter your current PIN to disable lock:') || '';
      if (!current_pin) return;
    }
    if (!confirm('Disable PIN lock? Anyone on your network with the OmaDeck URL will be able to access the desktop.')) return;
    haptic(10);
    disablePinBtn.disabled = true;
    try {
      const res = await fetch('/pin', {
        method: 'POST',
        headers,
        body: JSON.stringify({ action: 'disable', current_pin })
      });
      const data = await res.json();
      if (data.ok) {
        if (settingCurrentPin) settingCurrentPin.value = '';
        showSecurityStatus('PIN lock disabled.', 'info');
        updateSecurityUi(false);
        if (data.token) updateToken(data.token);
      } else {
        showSecurityStatus(data.error || 'Failed to disable PIN', 'error');
      }
    } catch (e) {
      showSecurityStatus('Error disabling PIN: ' + e, 'error');
    } finally {
      disablePinBtn.disabled = false;
    }
  };
}

if (lockDeckNowBtn) lockDeckNowBtn.onclick = lockSession;
if (appLockBtn) appLockBtn.onclick = lockSession;

let settingsCatalog = {};

// --- settings tabs ---------------------------------------------------------
function showSettingsTab(name) {
  const isKeys = name === 'keys';
  const isTheme = name === 'theme';
  const isSecurity = name === 'security';

  if (tabKeys) { tabKeys.classList.toggle('active', isKeys); tabKeys.setAttribute('aria-selected', isKeys ? 'true' : 'false'); }
  if (tabTheme) { tabTheme.classList.toggle('active', isTheme); tabTheme.setAttribute('aria-selected', isTheme ? 'true' : 'false'); }
  if (tabSecurity) { tabSecurity.classList.toggle('active', isSecurity); tabSecurity.setAttribute('aria-selected', isSecurity ? 'true' : 'false'); }

  if (panelKeys) panelKeys.style.display = isKeys ? 'flex' : 'none';
  if (panelTheme) panelTheme.style.display = isTheme ? 'flex' : 'none';
  if (panelSecurity) panelSecurity.style.display = isSecurity ? 'flex' : 'none';
}
if (tabKeys) tabKeys.onclick = () => { haptic(6); showSettingsTab('keys'); };
if (tabTheme) tabTheme.onclick = () => { haptic(6); showSettingsTab('theme'); };
if (tabSecurity) tabSecurity.onclick = () => { haptic(6); showSettingsTab('security'); };

// --- theme picker ----------------------------------------------------------
const THEME_META = {
  "auto": "#09090c",
  "midnight": "#09090c",
  "phosphor": "#020604",
  "amber": "#0a0703",
  "gruvbox": "#1e1e1e",
  "catppuccin": "#161622",
  "tokyo-night": "#13141c",
  "nord": "#222730",
  "everforest": "#21272c",
  "kanagawa": "#17171e",
  "rose-pine": "#ede7e1",
  "hackerman": "#080910",
  "matte-black": "#0d0d0d",
  "osaka-jade": "#0c1512",
  "retro-82": "#031222",
  "ristretto": "#211b1b",
  "lumon": "#101b21",
  "solitude": "#0c0e10",
  "vantablack": "#090909",
  "ethereal": "#040816",
  "miasma": "#191919",
  "last-horizon": "#090809",
  "catppuccin-latte": "#e3e4e8",
  "flexoki-light": "#f2efe4"
};
let _desktopTheme = 'gruvbox';

function currentTheme() {
  return localStorage.getItem('oma-deck-theme') || 'auto';
}

function applyTheme(choice) {
  if (!choice) choice = 'auto';
  try { localStorage.setItem('oma-deck-theme', choice); } catch (e) {}
  
  // Resolve actual theme stylesheet name
  const effectiveTheme = (choice === 'auto') ? (_desktopTheme || 'gruvbox') : choice;
  document.documentElement.dataset.theme = effectiveTheme;
  
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta && THEME_META[effectiveTheme]) meta.setAttribute('content', THEME_META[effectiveTheme]);
  
  document.querySelectorAll('.theme-card').forEach(card => {
    const active = card.dataset.themeChoice === choice;
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
  if (hasPin && !TOKEN) return;
  try {
    const r = await fetch('/settings', {headers});
    if (checkAuth(r)) return;
    if (!r.ok) return;
    const data = await r.json();
    settingsCatalog = data.presets || {};
    if (data.pin_set !== undefined) {
      updateSecurityUi(data.pin_set);
    }
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
    const settingAiPolish = document.getElementById('setting-ai-dictate-polish');
    if (settingAiPolish && data.ai_dictate_polish !== undefined) {
      settingAiPolish.checked = !!data.ai_dictate_polish;
    }
    const settingMicTrigger = document.getElementById('setting-mic-trigger');
    const savedTrigger = localStorage.getItem('omadeck_mic_trigger') || data.mic_trigger || 'both';
    micTriggerMode = savedTrigger;
    if (settingMicTrigger) {
      settingMicTrigger.value = savedTrigger;
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
    const settingAiPolish = document.getElementById('setting-ai-dictate-polish');
    const settingMicTrigger = document.getElementById('setting-mic-trigger');
    const micTriggerVal = settingMicTrigger ? settingMicTrigger.value : 'both';
    micTriggerMode = micTriggerVal;
    localStorage.setItem('omadeck_mic_trigger', micTriggerVal);

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
          ai_dictate_polish: settingAiPolish ? settingAiPolish.checked : true,
          mic_trigger: micTriggerVal,
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

if (window.location.hash === '#settings' || (new URLSearchParams(window.location.search)).get('modal') === 'settings') {
  openSettingsModal();
  const _tabParam = (new URLSearchParams(window.location.search)).get('tab');
  if (_tabParam) showSettingsTab(_tabParam);
}

// --- send command ---
async function sendCmd(text, fromVoice, logYou) {
  if (!text || !text.trim()) return;
  if (hasPin && !TOKEN) { showPinScreen(); return; }
  haptic(8);
  if (logYou === undefined) logYou = true;
  if (latestReply) latestReply.textContent = '▶ ' + text;
  if (logYou) addMsg('you', text);
  try {
    const r = await fetch('/cmd', {
      method: 'POST',
      headers,
      body: JSON.stringify({text, voice: Boolean(fromVoice)}),
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
  if (cmdInput) {
    if (mode === 'type') {
      cmdInput.placeholder = 'Type text into active PC app…';
    } else {
      cmdInput.placeholder = 'Type a command…';
    }
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
  if (hasPin && !TOKEN) { showPinScreen(); return; }
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
  if (hasPin && !TOKEN) { showPinScreen(); return; }
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
const micBtn     = document.getElementById('mic-btn');
const dictateBtn = document.getElementById('dictate-btn');
const hint       = document.getElementById('mic-hint');
const trans      = document.getElementById('transcript');
const note       = document.getElementById('mic-note');

let recorder = null;
let chunks = [];
let holding = false;
let isLatched = false;
let holdTimer = null;
let pressStartTime = 0;
let activePointerId = null;
let activeTriggerBtn = null;
let recordingTarget = 'action'; // 'action' or 'input'
let micTriggerMode = localStorage.getItem('omadeck_mic_trigger') || 'both';

const MIC_SVG_DEFAULT = '<svg class="icon-svg" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line></svg>';
const MIC_SVG_STOP = '<svg class="icon-svg" viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2" fill="#fff" stroke="#fff"></rect></svg>';

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

function updateRecordingStatus() {
  if (!holding || !latestReply) return;
  const waves = '<span class="sound-wave-bars"><span></span><span></span><span></span><span></span></span>';
  const label = (recordingTarget === 'input') ? 'Dictating into input…' : 'Recording voice…';
  if (isLatched) {
    latestReply.innerHTML = waves + `<b>${label}</b> tap mic to stop & transcribe`;
  } else {
    latestReply.innerHTML = waves + `<b>${label}</b> release to send`;
  }
}

async function startRecording(triggerBtn, target = 'action', latched = false) {
  if (holding || (triggerBtn && triggerBtn.classList.contains('thinking'))) return;
  if (micProblem()) return;
  holding = true;
  isLatched = latched;
  activeTriggerBtn = triggerBtn || micBtn;
  recordingTarget = target;
  haptic(14);

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: {echoCancellation: true, noiseSuppression: true},
    });
  } catch (e) {
    holding = false;
    isLatched = false;
    activeTriggerBtn = null;
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
  if (activeTriggerBtn) {
    activeTriggerBtn.classList.add('recording');
    if (isLatched) {
      activeTriggerBtn.classList.add('latched');
      activeTriggerBtn.innerHTML = MIC_SVG_STOP;
      activeTriggerBtn.title = 'Tap to stop recording';
    } else {
      activeTriggerBtn.title = 'Release to finish recording';
    }
  }
  if (cmdInput) cmdInput.classList.add('recording-glow');
  updateRecordingStatus();
  holdTimer = setTimeout(stopRecording, 60000);
}

function stopRecording() {
  if (!holding) return;
  holding = false;
  isLatched = false;
  haptic(10);
  clearTimeout(holdTimer);
  if (activeTriggerBtn) {
    activeTriggerBtn.classList.remove('recording', 'latched');
    activeTriggerBtn.innerHTML = MIC_SVG_DEFAULT;
    activeTriggerBtn.title = (activeTriggerBtn === dictateBtn)
      ? 'Dictate speech into input box'
      : 'Hold to talk or tap to dictate';
  }
  if (cmdInput) cmdInput.classList.remove('recording-glow');

  if (recorder && recorder.state === 'recording') {
    recorder.stop();
    if (activeTriggerBtn) activeTriggerBtn.classList.add('thinking');
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
  if (hasPin && !TOKEN) { showPinScreen(); return; }
  const buf = await blob.arrayBuffer();
  const b64 = toBase64(new Uint8Array(buf));
  const btn = activeTriggerBtn;
  const target = recordingTarget;
  try {
    const r = await fetch('/transcribe', {
      method: 'POST',
      headers,
      body: JSON.stringify({audio_b64: b64, mime: blob.type, polish: true}),
    });
    if (checkAuth(r)) return;
    const d = await r.json();
    const heard = (d.heard || '').trim();
    const polished = (d.polished || heard).trim();
    if (!heard || heard.startsWith('[stt error')) {
      if (latestReply) latestReply.textContent = '⚠ Could not understand — try again.';
      addMsg('sys', 'Could not make that out — try again.');
      return;
    }
    const finalText = polished || heard;
    if (target === 'input') {
      if (cmdInput) {
        cmdInput.value = finalText;
        cmdInput.focus();
        cmdInput.setSelectionRange(finalText.length, finalText.length);
      }
      if (latestReply) latestReply.textContent = '✓ Dictated: ' + finalText;
      addMsg('you', 'Dictated: ' + finalText);
    } else if (activeMode === 'type') {
      if (latestReply) latestReply.textContent = '▶ ' + finalText;
      addMsg('you', finalText);
      await directType(finalText, true);
    } else {
      if (latestReply) latestReply.textContent = '▶ ' + heard;
      addMsg('you', heard);
      await sendCmd(heard, true, false);
    }
  } catch(e) {
    addMsg('sys', 'Error: ' + e);
  } finally {
    if (btn) btn.classList.remove('thinking');
    activeTriggerBtn = null;
  }
}

function bindMicEvents(btn, targetName) {
  if (!btn) return;
  btn.addEventListener('pointerdown', e => {
    e.preventDefault();
    if (btn.classList.contains('thinking')) return;

    if (holding && isLatched) {
      stopRecording();
      return;
    }
    if (holding) return;

    activePointerId = e.pointerId;
    pressStartTime = performance.now();

    if (micTriggerMode === 'tap') {
      startRecording(btn, targetName, true);
      return;
    }
    startRecording(btn, targetName, false);
  });

  btn.addEventListener('pointerup', e => {
    e.preventDefault();
    if (!holding) return;
    if (activePointerId !== null && e.pointerId !== activePointerId) return;
    activePointerId = null;

    const duration = performance.now() - pressStartTime;

    if (micTriggerMode === 'both') {
      if (duration < 350) {
        isLatched = true;
        if (activeTriggerBtn) {
          activeTriggerBtn.classList.add('latched');
          activeTriggerBtn.innerHTML = MIC_SVG_STOP;
          activeTriggerBtn.title = 'Tap to stop recording';
        }
        haptic(12);
        updateRecordingStatus();
        return;
      } else {
        stopRecording();
        return;
      }
    } else if (micTriggerMode === 'hold') {
      stopRecording();
    }
  });

  btn.addEventListener('pointercancel', () => {
    if (holding && !isLatched) stopRecording();
  });
  btn.addEventListener('contextmenu', e => e.preventDefault());
}

bindMicEvents(micBtn, 'action');
bindMicEvents(dictateBtn, 'input');
window.addEventListener('blur', () => {
  if (holding) stopRecording();
});
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
    if not shutil.which("wtype") and not shutil.which("hyprctl"):
        return False, "neither wtype nor hyprctl is available"

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

    def _hypr_send_shortcut(m_str: str, k_sym: str) -> tuple[bool, str]:
        if not shutil.which("hyprctl"):
            return False, "hyprctl is not installed"
        try:
            lua = f'hl.dsp.send_shortcut({{ mods = {json.dumps(m_str)}, key = {json.dumps(k_sym)}, window = "activewindow" }})'
            res = subprocess.run(["hyprctl", "dispatch", lua], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and "not found" not in res.stdout.lower() and "error" not in res.stdout.lower():
                return True, ""
            return False, res.stderr.strip() or res.stdout.strip() or "hyprctl dispatch failed"
        except Exception as exc:
            return False, str(exc)

    if "+" in k_lower:
        parts = [p.strip() for p in k_lower.split("+") if p.strip()]
        if parts:
            raw_mods = parts[:-1]
            mods = [mod_map.get(m, m) for m in raw_mods]
            final_key = parts[-1]
            mapped_key = key_map.get(final_key, final_key)

            if shutil.which("wtype"):
                wtype_args = ["wtype"]
                for m in mods:
                    wtype_args.extend(["-M", m])
                wtype_args.extend(["-k", mapped_key])
                for m in reversed(mods):
                    wtype_args.extend(["-m", m])

                try:
                    res = subprocess.run(wtype_args, capture_output=True, text=True, timeout=5)
                    if res.returncode == 0:
                        return True, ""
                except Exception:
                    pass

            # Fallback to Hyprland native shortcut dispatch
            hypr_mods = "+".join(raw_mods)
            ok, err = _hypr_send_shortcut(hypr_mods, mapped_key)
            if ok:
                return True, ""
            return False, err or "wtype and hyprctl dispatch both failed"

    k = key_map.get(k_lower, k_raw)
    if shutil.which("wtype"):
        try:
            res = subprocess.run(["wtype", "-k", k], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True, ""
        except Exception:
            pass

    # Fallback to Hyprland native shortcut dispatch for single keys
    ok, err = _hypr_send_shortcut("", k)
    if ok:
        return True, ""
    return False, err or "wtype and hyprctl dispatch both failed"


_AUTH_FAILURES: dict[str, list[float]] = {}
_GLOBAL_AUTH_FAILURES: list[float] = []
MAX_GLOBAL_AUTH_FAILURES = 25
# A per-minute limit alone still lets a 4-digit PIN fall in hours. This caps the
# total, at the cost that someone on the LAN can hold PIN login shut for a day.
# The pairing link keeps working, so the owner is never locked out.
MAX_DAILY_AUTH_FAILURES = 200
_AUTH_LOCK = threading.Lock()
_SESSION_TOKENS: dict[str, float] = {}  # session_token -> expiry_timestamp
_SESSION_LOCK = threading.Lock()
# Routes whose request body carries a PIN or an API key.
SECRET_ROUTES = {"/auth", "/pin", "/settings"}
MAX_JSON_BODY = 128 * 1024
MAX_AUDIO_BODY = 16 * 1024 * 1024
_TAILSCALE_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_allowed_host(host_header: str, server_host: str = "") -> bool:
    if not host_header:
        return False
    h = host_header.split("]:")[0].lstrip("[") if host_header.startswith("[") else host_header.split(":")[0]
    h = h.strip().lower()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver"):
        return True
    if server_host and h == server_host.lower():
        return True
    if h.endswith(".local") or h.endswith(".ts.net"):
        return True
    try:
        my_hostname = socket.gethostname().lower()
        if h in (my_hostname, f"{my_hostname}.local"):
            return True
    except Exception:
        pass
    try:
        addr = ipaddress.ip_address(h)
        if addr.is_private or addr.is_loopback or addr in _TAILSCALE_CGNAT:
            return True
    except ValueError:
        pass
    return False


def _reserve_auth_attempt(client_ip: str, now: float) -> str | None:
    """Count a PIN attempt before it is checked. Returns the refusal, if any.

    Counting first is what stops parallel guesses racing past the limit.
    """
    with _AUTH_LOCK:
        _GLOBAL_AUTH_FAILURES[:] = [t for t in _GLOBAL_AUTH_FAILURES if now - t < 86400.0]
        if len(_GLOBAL_AUTH_FAILURES) >= MAX_DAILY_AUTH_FAILURES:
            return ("Too many failed attempts globally. PIN login is locked for up to "
                    "24 hours; open the pairing link instead.")
        recent = sum(1 for t in _GLOBAL_AUTH_FAILURES if now - t < 60.0)
        if recent >= MAX_GLOBAL_AUTH_FAILURES:
            return "Too many failed attempts globally. Locked out for 60 seconds."

        attempts = _AUTH_FAILURES.setdefault(client_ip, [])
        attempts[:] = [t for t in attempts if now - t < 60.0]
        if len(attempts) >= 5:
            return "Too many failed attempts. Locked out for 60 seconds."
        attempts.append(now)
        _GLOBAL_AUTH_FAILURES.append(now)
    return None


def _forgive_auth_attempt(client_ip: str, now: float) -> None:
    """A correct PIN is not a failure, so it should not use up the allowance."""
    with _AUTH_LOCK:
        _AUTH_FAILURES.pop(client_ip, None)
        try:
            _GLOBAL_AUTH_FAILURES.remove(now)
        except ValueError:
            pass


class BridgeHandler(http.server.BaseHTTPRequestHandler):

    timeout = 10.0
    # The socket timeout restarts on every byte, so a client trickling a header
    # could hold a connection slot forever without this overall limit.
    header_deadline = 15.0
    token: str = ""
    pin: str = ""
    stt_model: str = "base.en"
    https_url: str = ""

    def log_message(self, fmt, *args):
        # suppress noisy access log; errors still go to stderr
        pass

    def _refuse_plain_http(self) -> bool:
        """Answer and return True when this request would send a secret in the clear.

        Only when HTTPS is actually on offer. Loopback and Tailscale addresses
        pass: the first never leaves the machine and the second is already
        encrypted. 426 rather than 403, because the page treats 403 as a dead
        session and would throw away a working token.
        """
        if getattr(getattr(self, "server", None), "tls_context", None) is None:
            return False
        if isinstance(getattr(self, "connection", None), ssl.SSLSocket):
            return False
        try:
            client = ipaddress.ip_address(self.client_address[0])
            if client.is_loopback or client in _TAILSCALE_CGNAT:
                return False
        except (AttributeError, IndexError, TypeError, ValueError):
            pass
        self._json({"ok": False,
                    "error": f"Open {self.https_url} for this: PINs and API keys "
                             "are not sent over unencrypted HTTP."}, 426)
        return True

    def _validate_host(self) -> bool:
        host_hdr = self.headers.get("Host", "")
        if host_hdr:
            server_host = getattr(self.server, "server_name", "") if hasattr(self, "server") and self.server else ""
            if not _is_allowed_host(host_hdr, server_host):
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"error":"forbidden: invalid host header"}')
                return False
        return True

    def setup(self):
        super().setup()
        self._header_timer = threading.Timer(self.header_deadline, self._abort_slow_headers)
        self._header_timer.daemon = True
        self._header_timer.start()

    def _abort_slow_headers(self) -> None:
        try:
            # The plain socket method: SSLSocket.shutdown would tear down TLS
            # state underneath the thread that is reading.
            socket.socket.shutdown(self.connection, socket.SHUT_RD)
        except OSError:
            pass

    def _cancel_header_timer(self) -> None:
        timer = getattr(self, "_header_timer", None)
        if timer is not None:
            timer.cancel()

    def parse_request(self):
        try:
            return super().parse_request()
        finally:
            self._cancel_header_timer()

    def finish(self):
        self._cancel_header_timer()
        super().finish()

    def _check_token(self) -> bool:
        tok = self.headers.get("X-Token", "")
        if not tok:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return False

        if secrets.compare_digest(tok, self.token):
            return True

        now = time.monotonic()
        with _SESSION_LOCK:
            expiry = _SESSION_TOKENS.get(tok)
            if expiry and expiry > now:
                return True
            if expiry:
                _SESSION_TOKENS.pop(tok, None)

        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b'{"error":"unauthorized"}')
        return False

    def _json(self, data: dict, code: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
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

    def _pairs_home_screen_app(self) -> bool:
        """True when this request carries the pairing token and no PIN is set.

        iOS gives a Home Screen app its own storage, so the token Safari saved
        doesn't reach it. A request that already holds the token gets a manifest
        that hands it to the app. With a PIN set, the app uses the PIN screen.
        """
        tok = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return not self.pin and bool(tok) and secrets.compare_digest(tok.encode(), self.token.encode())

    def do_OPTIONS(self):
        if not self._validate_host():
            return
        self.send_response(204)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        if not self._validate_host():
            return
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            # Never embed master token in raw HTML to unauthenticated clients
            token_in_html = ""
            has_pin = "true" if bool(self.pin) else "false"
            html = (_PWA_HTML
                    .replace("TOKEN_PLACEHOLDER", token_in_html)
                    .replace("HAS_PIN_PLACEHOLDER", has_pin)
                    .replace("HTTPS_PLACEHOLDER", self.https_url))
            if self._pairs_home_screen_app():
                html = html.replace('href="/manifest.webmanifest"',
                                    f'href="/manifest.webmanifest?token={quote(self.token, safe="")}"')
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
            # The token goes in the fragment, which the app's launch never sends
            # to the server; the page already reads it from there.
            start_url = f"/#token={quote(self.token, safe='')}" if self._pairs_home_screen_app() else "/"
            manifest = _manifest_json(start_url)
            self.send_response(200)
            self.send_header("Content-Type", "application/manifest+json")
            self.send_header("Content-Length", str(len(manifest)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(manifest)
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
        if not self._validate_host():
            return
        path = urlparse(self.path).path

        if path in SECRET_ROUTES and self._refuse_plain_http():
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            length = 0

        # Protect against unauthenticated DoS body buffering on audio/command routes
        if path != "/auth":
            if not self._check_token():
                return

        max_allowed = MAX_AUDIO_BODY if path in ("/transcribe", "/voice") else MAX_JSON_BODY
        if length < 0 or length > max_allowed:
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error":"payload too large"}')
            return

        def _read_body(expected_len: int, max_sec: float = 30.0) -> bytes:
            if expected_len <= 0:
                return b""
            deadline = time.monotonic() + max_sec
            chunks = []
            rem = expected_len
            while rem > 0:
                time_left = deadline - time.monotonic()
                if time_left <= 0:
                    raise TimeoutError("body read timeout")
                if hasattr(self, "connection") and self.connection:
                    try:
                        self.connection.settimeout(min(time_left, 10.0))
                    except (OSError, AttributeError):
                        pass
                read_size = min(rem, 65536)
                if hasattr(self.rfile, "read1"):
                    chunk = self.rfile.read1(read_size)
                else:
                    chunk = self.rfile.read(read_size)
                if not chunk:
                    break
                chunks.append(chunk)
                rem -= len(chunk)
            if rem > 0 and time.monotonic() > deadline:
                raise TimeoutError("body read timeout")
            return b"".join(chunks)

        try:
            body = _read_body(length)
        except (TimeoutError, OSError):
            self.send_response(408)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"error":"request timeout"}')
            return
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            self._json({"error": "bad json"}, 400)
            return

        if path == "/auth":
            sec_fetch_site = self.headers.get("Sec-Fetch-Site", "")
            if sec_fetch_site == "cross-site":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"error":"forbidden: cross-site request"}')
                return

            origin = self.headers.get("Origin", "")
            if origin:
                if origin.lower() == "null":
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b'{"error":"forbidden: null origin"}')
                    return
                host_hdr = self.headers.get("Host", "")
                try:
                    origin_parsed = urlparse(origin)
                    origin_host = origin_parsed.netloc or origin_parsed.hostname or ""
                    if host_hdr and origin_host:
                        if origin_host.split(":")[0].lower() != host_hdr.split(":")[0].lower():
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Connection", "close")
                            self.end_headers()
                            self.wfile.write(b'{"error":"forbidden: cross-site request"}')
                            return
                except Exception:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b'{"error":"forbidden: invalid origin"}')
                    return

            client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "127.0.0.1"
            now = time.monotonic()
            if refusal := _reserve_auth_attempt(client_ip, now):
                self._json({"ok": False, "error": refusal}, 429)
                return

            pin_attempt = str(payload.get("pin") or "").strip()
            time.sleep(0.2)
            if self.pin and secrets.compare_digest(pin_attempt, self.pin):
                _forgive_auth_attempt(client_ip, now)
                session_tok = secrets.token_urlsafe(24)
                with _SESSION_LOCK:
                    issued_at = time.monotonic()
                    for stale in [t for t, exp in _SESSION_TOKENS.items() if exp <= issued_at]:
                        del _SESSION_TOKENS[stale]
                    _SESSION_TOKENS[session_tok] = issued_at + (86400 * 30)
                self._json({"ok": True, "token": session_tok})
            else:
                self._json({"ok": False, "error": "Incorrect PIN"}, 401)
            return

        if path == "/pin":
            tok = self.headers.get("X-Token", "")
            is_master = bool(self.token and secrets.compare_digest(tok, self.token))
            action = str(payload.get("action") or "").strip().lower()
            new_pin = str(payload.get("pin") or "").strip()
            current_pin = str(payload.get("current_pin") or "").strip()

            from .local_engine import save_local_config

            if self.pin and not is_master:
                client_ip = self.client_address[0] if (hasattr(self, "client_address") and self.client_address) else "127.0.0.1"
                now = time.monotonic()
                if refusal := _reserve_auth_attempt(client_ip, now):
                    self._json({"ok": False, "error": refusal}, 429)
                    return
                time.sleep(0.2)
                if not current_pin or not secrets.compare_digest(current_pin, self.pin):
                    self._json({"ok": False, "error": "Current PIN is required to modify PIN settings."}, 403)
                    return
                _forgive_auth_attempt(client_ip, now)

            if action == "disable":
                self.__class__.pin = ""
                # Keep the phone doing this signed in, but no other session
                # should outlive the PIN that granted it.
                with _SESSION_LOCK:
                    own_expiry = _SESSION_TOKENS.get(tok)
                    _SESSION_TOKENS.clear()
                    if own_expiry:
                        _SESSION_TOKENS[tok] = own_expiry
                save_local_config({"pin": ""})
                resp = {"ok": True, "pin_set": False, "message": "PIN lock disabled."}
                if is_master:
                    resp["token"] = self.token
                self._json(resp)
                return

            if action == "set":
                if not (new_pin.isdigit() and 4 <= len(new_pin) <= 8):
                    self._json({"ok": False, "error": "PIN must be 4 to 8 digits."}, 400)
                    return
                self.__class__.pin = new_pin
                with _SESSION_LOCK:
                    _SESSION_TOKENS.clear()
                save_local_config({"pin": new_pin})
                resp = {"ok": True, "pin_set": True, "message": "PIN lock updated successfully."}
                if is_master:
                    new_token = secrets.token_urlsafe(16)
                    self.__class__.token = new_token
                    _save_token(new_token)
                    resp["token"] = new_token
                    if sys.stdout.isatty():
                        print(f"  [security] PIN updated — new pairing token: {new_token}", flush=True)
                self._json(resp)
                return

            self._json({"ok": False, "error": "Invalid action"}, 400)
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
            if "ai_dictate_polish" in payload:
                cfg_updates["ai_dictate_polish"] = bool(payload["ai_dictate_polish"])
            if "mic_trigger" in payload:
                mt = str(payload.get("mic_trigger") or "both").strip().lower()
                if mt in ("both", "hold", "tap"):
                    cfg_updates["mic_trigger"] = mt
            if provider == "custom" and base_url:
                cfg_updates["base_url"] = base_url
            else:
                cfg_updates["base_url"] = ""
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
                write_log(f"key     {key}" if ok else f"error   key {key}: {err}")
                self._json({"ok": ok, "error": err if not ok else None})
                return

            if text:
                ok, err = _type_text(text, enter=enter)
                if not ok:
                    # Never the text itself: it can be anything typed on the phone.
                    write_log(f"error   typing: {err}")
                self._json({"ok": ok, "error": err if not ok else None})
                return

            self._json({"error": "empty"}, 400)
            return

        elif path == "/cmd":
            text = payload.get("text", "").strip()
            voice = bool(payload.get("voice", False))
            if not text:
                self._json({"error": "empty"}, 400)
                return
            reply = _dispatch(text, voice=voice)
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
            should_polish = bool(payload.get("polish", True))
            polished = ""
            if heard and not heard.startswith("[stt error"):
                if should_polish:
                    try:
                        from .local_engine import polish_dictation
                        from .capabilities import active_window
                        active = active_window()
                        app_class = str(active.get("class") or "")
                        app_title = str(active.get("title") or "")
                        polished = polish_dictation(heard, app_class=app_class, app_title=app_title)
                    except Exception:
                        polished = heard
                else:
                    polished = heard
            self._json({"heard": heard, "polished": polished or heard})

        elif path == "/voice":
            audio_b64 = payload.get("audio_b64", "")
            if not audio_b64:
                self._json({"error": "no audio"}, 400)
                return
            audio_bytes = base64.b64decode(audio_b64)
            heard = _transcribe_wav(audio_bytes, self.stt_model)
            reply = ""
            if heard and not heard.startswith("[stt error"):
                reply = _dispatch(heard, voice=True)
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

_CHROME_NAMES = ("chrome", "google chrome", "google-chrome")

# How long the phone waits for the daemon's model to answer. It was 8 seconds,
# and a three-step request takes the model 20 to 30: the phone reported a
# timeout while the desktop went on and did the work.
DAEMON_REPLY_TIMEOUT = 60.0

_DAEMON_OFF = ("The desktop mic daemon is not running — use the mic button "
               "on this page, or type a command.")


def _quick_command(text: str, voice: bool = False) -> str | None:
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
        try:
            return send_control(t)
        except (ConnectionError, socket.timeout, TimeoutError, OSError):
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

    # --- open an app on a given workspace ---------------------------------
    # "Open a new chrome window in workspace five" took the planner three
    # round trips and 28 seconds, longer than the phone waited. Answered here
    # it is one launch and one move.
    match_open_on = re.fullmatch(
        r"(?:please )?(?:open|launch|start)(?: up)? (?:a |an |the )?(?:new )?"
        r"(.+?)(?: window)? (?:in|on|to|at) (?:the )?(?:workspace|desktop|ws) ([\w+-]+)",
        t,
    )
    if match_open_on:
        what, target = match_open_on.groups()
        ws = _WS_WORDS.get(target, target)
        if ws.isdigit():
            if what in _CHROME_NAMES:
                ok, out = run("launch_app", {"app": "google-chrome:new-window",
                                             "workspace": ws})
                return (f"Opened Chrome on workspace {ws}." if ok
                        else f"Couldn't open Chrome: {out}")
            # Anything else this page already knows how to open: open it the
            # usual way, then move whatever window that produced.
            try:
                before = executor.window_addresses()
            except Exception:
                return None
            opened = _quick_command(f"open {what}", voice=voice)
            if opened is None:
                return None  # not one we know; the planner can use launch_app
            if opened.startswith(("Couldn't", "Could not")):
                return opened
            placed = executor.place_new_window(before, ws)
            if not placed.ok:
                return f"{opened.rstrip('.')}, but {placed.output}."
            if placed.output.startswith("started, but"):
                return f"{opened.rstrip('.')}, but no new window appeared to move."
            return f"{opened.rstrip('.')} on workspace {ws}."

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

    kill_port_match = re.match(r"^(?:please\s+)?(?:kill|stop)\s+(?:port\s+)?(\d{2,5})\.?$", t)
    if kill_port_match and not re.search(r"\b(?:don't|do not|never|avoid|skip)\b", t):
        port = kill_port_match.group(1)
        port_num = int(port)
        if 1 <= port_num <= 65535:
            if port == "11434":
                subprocess.run(["systemctl", "stop", "ollama", "--no-ask-password"], capture_output=True, timeout=2)
            check = subprocess.run(["fuser", f"{port}/tcp"], capture_output=True, timeout=2)
            if check.returncode != 0:
                return f"No process was listening on port {port}."
            subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, text=True, timeout=2)
            return f"Killed process on port {port}."

    if t in ("git status", "git diff", "git pull", "git push", "run tests"):
        if voice and t == "git push":
            return "Refused by safety policy: spoken 'git push' requires manual confirmation."
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
        try:
            res = subprocess.run(["wpctl", "status"], capture_output=True, text=True, timeout=3)
            lines = res.stdout.splitlines()
            in_sinks = False
            sinks = []
            for line in lines:
                if "Sinks:" in line:
                    in_sinks = True
                    continue
                if in_sinks:
                    if any(term in line for term in ("Sources:", "Filters:", "Streams:")) or (sinks and not line.strip()):
                        in_sinks = False
                        continue
                    m = re.search(r'([* ])\s+(\d+)\.\s*(.*?)(?:\[vol:|$)', line)
                    if m:
                        is_curr = m.group(1) == '*'
                        s_id = int(m.group(2))
                        name = m.group(3).strip()
                        sinks.append((s_id, is_curr, name))
            if not sinks:
                return "No PipeWire audio sinks found."
            if len(sinks) == 1:
                return f"Only 1 audio sink available ({sinks[0][2]})."
            curr_idx = next((i for i, s in enumerate(sinks) if s[1]), 0)
            next_idx = (curr_idx + 1) % len(sinks)
            target = sinks[next_idx]
            subprocess.run(["wpctl", "set-default", str(target[0])], check=True, timeout=3)
            return f"Switched default audio output to {target[2]}."
        except Exception as exc:
            return f"Audio sink switch error: {exc}"

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
        inspector_bin = shutil.which("omarchy-inspector")
        if not inspector_bin:
            local_bin = Path.home() / ".local/bin/omarchy-inspector"
            if local_bin.exists():
                inspector_bin = str(local_bin)
        if not inspector_bin:
            return "omarchy-inspector is not installed on this system."

        launched = False
        try:
            r = subprocess.run(
                ["hyprctl", "eval", f'hl.exec_cmd("{inspector_bin}")'],
                capture_output=True, text=True, timeout=3,
            )
            launched = r.returncode == 0 and r.stdout.strip().lower() == "ok"
        except Exception:
            launched = False

        if not launched:
            try:
                proc = subprocess.Popen(
                    [inspector_bin],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                launched = proc.poll() is None
            except Exception:
                launched = False

        return "Opened Ports & Devices Inspector on laptop." if launched else f"Failed to launch {inspector_bin}."

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


def _dispatch(text: str, voice: bool = False) -> str:
    """Route the text to the daemon's control socket or the planner."""
    quick = _quick_command(text, voice=voice)
    if quick is not None:
        reply = quick
        # Buttons and shortcut phrasings never reach a model, so nothing
        # else logs them.
        write_log(f"phone   {text} -> {brief(reply)}")
    else:
        try:
            reply = send_control(f"say {text}", timeout=DAEMON_REPLY_TIMEOUT)
        except (socket.timeout, TimeoutError):
            reply = "[command timed out waiting for daemon response]"
            write_log(f"error   phone {text}: {reply}")
        except (ConnectionError, FileNotFoundError, OSError):
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
        return reply
    except Exception as exc:
        return f"[no daemon, fallback failed: {exc}]"


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

MAX_CONCURRENT_CONNECTIONS = 32
MAX_CONNECTIONS_PER_IP = 8
_CONNECTION_SEMAPHORE = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)
_IP_CONNECTIONS: dict[str, int] = {}
_IP_LOCK = threading.Lock()


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
        return self.socket.accept()

    def process_request(self, request, client_address):
        client_ip = client_address[0] if client_address else "127.0.0.1"
        with _IP_LOCK:
            active = _IP_CONNECTIONS.get(client_ip, 0)
            if active >= MAX_CONNECTIONS_PER_IP:
                try:
                    request.settimeout(2.0)
                    request.sendall(b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nToo many connections from your IP\r\n")
                except OSError:
                    pass
                self.shutdown_request(request)
                return
            if not _CONNECTION_SEMAPHORE.acquire(blocking=False):
                try:
                    request.settimeout(2.0)
                    request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nServer busy\r\n")
                except OSError:
                    pass
                self.shutdown_request(request)
                return
            _IP_CONNECTIONS[client_ip] = active + 1
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        client_ip = client_address[0] if client_address else "127.0.0.1"
        try:
            sock = request
            try:
                sock.settimeout(10.0)
            except OSError:
                self.shutdown_request(sock)
                return

            if self.tls_context is not None:
                is_tls = False
                try:
                    sock.settimeout(2.0)
                    first = sock.recv(1, socket.MSG_PEEK)
                    is_tls = first[:1] == b"\x16"
                except OSError:
                    self.shutdown_request(sock)
                    return
                if is_tls:
                    try:
                        sock = self.tls_context.wrap_socket(sock, server_side=True)
                    except (OSError, ssl.SSLError):
                        self.shutdown_request(sock)
                        return
                try:
                    sock.settimeout(10.0)
                except OSError:
                    self.shutdown_request(sock)
                    return
            super().process_request_thread(sock, client_address)
        finally:
            with _IP_LOCK:
                curr = _IP_CONNECTIONS.get(client_ip, 1)
                if curr <= 1:
                    _IP_CONNECTIONS.pop(client_ip, None)
                else:
                    _IP_CONNECTIONS[client_ip] = curr - 1
            _CONNECTION_SEMAPHORE.release()

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


def _can_show_pairing_link() -> bool:
    """Whether a person is reading this output, rather than a log.

    Asks about the terminal, not the environment: JOURNAL_STREAM and
    INVOCATION_ID can be inherited by terminals started from a systemd session,
    as under uwsm, which would hide the link from the person who asked for it.
    """
    return sys.stdout.isatty()


def _ca_fingerprint() -> str:
    """SHA-256 of the local CA, so a phone can check the file it downloaded."""
    if not CA_CERT_FILE.exists():
        return ""
    try:
        der = ssl.PEM_cert_to_DER_cert(CA_CERT_FILE.read_text())
    except Exception:
        return ""
    fp = hashlib.sha256(der).hexdigest().upper()
    return ":".join(fp[i:i+2] for i in range(0, len(fp), 2))


def _print_qr(target: str) -> None:
    """Draw a QR code if qrencode is installed. The link is printed either way."""
    if not shutil.which("qrencode"):
        return
    try:
        res = subprocess.run(
            ["qrencode", "-t", "ANSIUTF8", "-m", "1", "-o", "-", target],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception:
        return
    if res.returncode == 0 and res.stdout:
        print()
        for line in res.stdout.splitlines():
            print(f"    {line}")
        print()


def _print_pairing_guide(url: str, https_url: str, token: str) -> None:
    """Walk a person through setting up a phone for everyday use.

    The certificate comes first and gets its own QR code: a phone that opens
    the HTTPS link before trusting the CA only gets a certificate warning. That
    code carries no token, so only the second one needs keeping private.
    """
    if not https_url:
        print("\n  Open this on your phone. It runs without encryption, and the mic")
        print("  won't work, because HTTPS isn't available:")
        print(f"    {url}/?token={token}")
        _print_qr(f"{url}/?token={token}")
        print("  Keep this link private: anyone with it can control your desktop.\n", flush=True)
        return

    print("\n  Step 1: Install the certificate (once per phone; the mic needs it)")
    print(f"    Open in Safari or Chrome: {url}/ca.crt")
    _print_qr(f"{url}/ca.crt")
    fingerprint = _ca_fingerprint()
    if fingerprint:
        print(f"    Fingerprint: {fingerprint}")
    print("    iPhone/iPad: Settings > Profile Downloaded > Install, then")
    print("      Settings > General > About > Certificate Trust Settings,")
    print('      and turn on "Oma Remote CA"')
    print("    Android: Settings > Security > Encryption & credentials >")
    print("      Install a certificate > CA certificate")

    print("\n  Step 2: Open OmaDeck over HTTPS")
    print(f"    {https_url}/?token={token}")
    _print_qr(f"{https_url}/?token={token}")
    print("    Keep this link private: anyone with it can control your desktop.")

    print("\n  Step 3: Add it to your Home Screen for everyday use")
    print("    iPhone/iPad: in Safari, tap Share > Add to Home Screen")
    print("    Android: in Chrome, tap the menu > Install app")
    print("    Optional: set a PIN in Settings > Security")

    if not shutil.which("qrencode"):
        print("\n  Want QR codes here? Install qrencode: sudo pacman -S qrencode")
    print(f"\n  No certificate? Touch controls work without it, but the mic won't: {url}/?token={token}\n", flush=True)


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

    # Plain HTTP — Safari on iOS hangs indefinitely on self-signed TLS certs.
    # LAN IPs (192.168.x.x, 10.x.x.x) are treated as secure contexts by
    # modern iOS Safari, so getUserMedia works fine over plain HTTP on LAN.
    try:
        server = BridgeServer(("0.0.0.0", port), Handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(f"\n  OmaDeck is already running on port {port}.")
            has_tls = CERT_FILE.exists() and KEY_FILE.exists()
            _print_pairing_guide(f"http://{host}:{port}",
                                 f"https://{host}:{port}" if has_tls else "", token)
            return 0
        print(f"\n  could not listen on port {port}: {exc}")
        print(f"  try: omadeck mobile --port {port + 1}\n")
        return 1

    # Pay the model load now instead of on the first thing the user says. After
    # binding, so a run that only prints the pairing link doesn't load a model.
    threading.Thread(target=_warm_stt, args=(stt_model,), daemon=True).start()

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

    # A service's stdout is the journal, which keeps it long after the token was
    # meant to be seen. The fingerprint is public, and lets the phone check a CA
    # fetched over plain HTTP.
    if not _can_show_pairing_link():
        print(f"\n  Oma Remote is running on port {port}")
        if https_url:
            print(f"  certificate →  {url}/ca.pem     (install once on the phone)")
            fingerprint = _ca_fingerprint()
            if fingerprint:
                print(f"  fingerprint →  {fingerprint}")
        print("  To see the pairing link, run in a terminal: omadeck mobile\n", flush=True)
    else:
        print(f"\n  OmaDeck is running here on port {port}. Press Ctrl+C to stop it.")
        _print_pairing_guide(url, https_url, token)
    hint = _firewall_hint(port)
    if hint:
        print(hint, flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
