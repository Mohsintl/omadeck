# 🎮 OmaDeck

**Tactile PWA Mobile Remote Deck & Universal AI Voice Companion for Omarchy / Hyprland Linux**

OmaDeck transforms your phone or tablet into an ultra-responsive, zero-scroll touch deck and universal AI voice controller for your Omarchy desktop. Run desktop macros, switch workspaces, control media, launch apps, send terminal hotkeys, and type directly into PC windows from your couch or desk.

```
       📱 Phone / Tablet (PWA)                     💻 Omarchy Linux Desktop (PC)
  ┌────────────────────────────────┐         ┌──────────────────────────────────────┐
  │  [Desk] [Code] [Media] [Custom]│ ──LAN──▶│  • Instant Workspace & Window Switch │
  │  ⌨️ Direct PC Typing (iOS mic) │  HTTPS  │  • Terminal TUIs (OpenCode, Lazydock)│
  │  🎙️ Tactile Hold-to-Talk AI    │  (8765) │  • Audio / Media / Brightness / Apps │
  │  ⚡ Process Killer & Dev Tools │         │  • Hyprland Lua Dispatcher Engine    │
  └────────────────────────────────┘         └──────────────────────────────────────┘
```

---

## 🌟 Highlights

- **📱 Touch Remote Deck (PWA)**: Calibrated for zero-scroll viewport precision across both portrait (e.g. 390×844) and landscape (844×390). Add to iOS or Android Home Screen for an instant fullscreen hardware deck experience with tactile haptic feedback.
- **⌨️ Direct PC Typing & Hardware Keys**: Type directly into whatever browser bar, code editor, or terminal window is focused on your Linux desktop with auxiliary keys (`⏎ Enter`, `⌫ Del`, `Tab ⇥`, `📋 Paste`, `Esc`). Use iOS/Android keyboard dictation for effortless voice-to-text typing straight into your PC!
- **🤖 Universal AI Model Support**: Works with **any** modern LLM provider:
  - **Groq** (Ultra-fast 500+ tok/s with Llama 3.3 70B)
  - **Ollama** (100% offline, local & free)
  - **OpenAI** (gpt-4o / gpt-4o-mini)
  - **OpenRouter**, **DeepSeek**, **Mistral**, **NVIDIA NIM**, and **Custom OpenAI-compatible endpoints** (vLLM, LM Studio).
- **🎙️ Independent Speech-to-Text (`STT_API_KEY`)**: Decoupled voice transcription so you can run a local LLM (Ollama) while taking advantage of blazing-fast cloud Whisper (Groq/OpenAI), or keep it 100% offline with local `faster-whisper`.
- **🎨 Hacker-Grade OLED Themes**: Switch instantly between **Midnight** (true dark), **Phosphor** (green CRT glow), and **Amber** (vintage terminal warmth), remembered per device.
- **🛑 Dev Process & Port Management**: Kill stuck dev servers (`:3000`, `:8000`, Local LLM `:11434`, T3 Dash `:3773`) or use the Crosshair Window Terminator directly from your phone.
- **🔒 Secure by Design**: Runs locally over LAN HTTPS with an auto-generated authentication token, self-signed CA certificates, and an optional 4-digit PIN lock.

---

## 📱 Five Dedicated Touch Profiles

| Profile | What it Controls |
|:---|:---|
| **🪟 Desk** | Workspaces 1–5, scratchpad toggle, window swap left/right, tile/float toggle, fullscreen, split cycle, app launchers (Files, Terminal, Web, Discord). |
| **💻 Code** | Terminal shortcuts, Git status / diff / push, test runner, process kill (`:3000`, `:8000`), `Ctrl+C`, `Ctrl+L`, terminal copy/paste. |
| **🎵 Media** | Play/pause, track skip, volume slider & steps, mute, display brightness presets, audio output device switcher. |
| **🌐 Web** | Browser launch, new tab, close tab, tab switcher (next/prev), refresh, zoom in/out, bookmark search, copy active URL. |
| **⚡ Custom** | Clean system utility dashboard: Btop system monitor, T3 Code Dashboard, OpenCode AI terminal, Lazygit, Lazydocker, Kill Window, Zen Mode, Caffeine (keep awake), Night Light, and Clipboard history. |

---

## 🚀 Quick Start

### 1. Installation

Clone and install dependencies on your Omarchy machine:

```bash
git clone https://github.com/Mohsintl/omadeck.git
cd omadeck
./install.sh
```

The installer sets up:
1. The `omarchy-voice` CLI and engine.
2. The `omarchy-voice-mobile.service` systemd user service (auto-starts on boot).

### 2. Connect from Your Phone

Check your LAN URL and token:
```bash
systemctl --user status omarchy-voice-mobile
```
Or run:
```bash
journalctl --user -u omarchy-voice-mobile -n 15 | grep "Oma Remote"
```

Open `http://<your-laptop-lan-ip>:8765` in Safari or Chrome on your phone.
- For microphone access, tap the HTTPS link and install the self-signed local certificate once.
- Tap **Share ➔ Add to Home Screen** on iOS/Android for a fullscreen, standalone app experience.

---

## ⚙️ Interactive Settings & AI Configuration

Configure your AI provider from either your PC or phone:

* **On PC**: Run `omarchy-voice settings` in terminal to launch the settings panel.
* **On Phone**: Tap the **⚙️** gear icon in the top navigation bar.

In the **API Keys** pane:
- Select your provider (**Groq**, **Ollama**, **OpenAI**, **OpenRouter**, **DeepSeek**, **Mistral**, **NVIDIA**, or **Custom**).
- Paste your API key (stored in `~/.config/omarchy-voice/env` with `chmod 600`).
- Optionally add a dedicated Speech-to-Text key for Groq Whisper.
- Tap **"Test & Save Keys"** to verify connection live before saving.

---

## 🖥️ Desktop Commands & Systemd Management

The deck runs as a background user service:

```bash
# Restart the remote service
systemctl --user restart omarchy-voice-mobile.service

# View live connection logs & URLs
journalctl --user -u omarchy-voice-mobile -f

# Stop the service
systemctl --user stop omarchy-voice-mobile.service
```

---

## 🤝 Acknowledgments & Heritage

- Built for **[Omarchy](https://omarchy.org)** and the **[Hyprland](https://hyprland.org)** Wayland compositor.
- Foundations and core Hyprland Lua dispatching inspired by and developed from **[omarchy-voice](https://github.com/wombatoperator/omarchy-voice)** by Britain Eriksen.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
