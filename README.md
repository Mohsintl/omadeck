# 🎮 OmaDeck

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Client-iOS%20%7C%20Android%20(PWA)-blue)](#)
[![Compositor](https://img.shields.io/badge/Compositor-Hyprland%20%2F%20Wayland-blueviolet)](#)
[![Linux](https://img.shields.io/badge/Linux-Arch%20%2F%20Omarchy-0f94d2)](#)
[![Roadmap](https://img.shields.io/badge/Roadmap-View%20Goals-purple)](ROADMAP.md)

> **Tactile PWA Mobile Remote Deck & Universal AI Voice Companion for Omarchy / Hyprland Linux**

<div align="center">

| 📱 Mobile Touch Remote (Portrait) | 💻 Linux Desktop (Hyprland / Omarchy) |
| :---: | :---: |
| <img src="docs/images/portrait-deck-tokyo-night.png" width="310" alt="OmaDeck Mobile Remote (Tokyo Night)" /> | <img src="docs/images/pc-screen.png" width="510" alt="Omarchy Linux Desktop" /> |

*OmaDeck running in Tokyo Night theme: tactile quick keys, inline dictation mic, instant workspace switching, and direct PC typing.*

</div>

[🚀 Quick Start](#-quick-start) • [💡 Why OmaDeck?](#-why-omadeck) • [📱 Profiles](#-five-dedicated-touch-profiles) • [⚙️ AI Setup](#️-interactive-settings--ai-configuration) • [🗺️ Roadmap](ROADMAP.md) • [🤝 Contributing](CONTRIBUTING.md)

---

### ⚡ At a Glance

| Question | Details |
|:---|:---|
| **What is it?** | A self-hosted Web App (PWA) that acts like a physical Stream Deck + AI voice remote for Linux. |
| **Who is it for?** | Omarchy, Arch Linux, and Hyprland users who want tactile desk control or couch remote power. |
| **Why not a physical deck?** | Physical decks cost $150+, have fixed buttons, and lack Wayland awareness. OmaDeck uses your existing phone, has 5 context profiles, OLED themes, and direct PC voice typing. |
| **Supported Devices** | Any phone or tablet with iOS Safari (iOS 16.4+) or Android Chrome. Zero app store installs. |
| **Privacy & Connection** | 100% Local LAN HTTPS with token/PIN authentication. Fully functional offline with Ollama. |

---

## 💡 Why OmaDeck?

Most Linux remote tools are either clunky VNC viewers that eat battery, or single-purpose media remotes that can't interact with modern Wayland compositors.

| The Problem | How OmaDeck Solves It |
|:---|:---|
| Reaching for the keyboard just to switch workspaces or adjust volume while relaxing. | **One-tap touch grid**: Instant Hyprland workspace jumps, window moves, and scratchpad toggles. |
| Typing long URLs, prompts, or text on the PC from across the room. | **Direct PC Typing**: Type or dictate via your phone's native speech keyboard straight into the focused PC window. |
| A dev server or port `:3000` is hanging your system. | **One-tap Process Killer**: Kill `:3000`, `:8000`, or launch the crosshair window terminator with 1 tap. |
| Physical macro pads cost $150+ and require proprietary drivers. | **Zero Hardware Cost**: Turn any spare or current phone into an OLED macro board with haptic feedback. |
| Most AI voice assistants send everything to a proprietary cloud. | **Universal AI Engine**: Bring your own Groq, Ollama (100% local/offline), OpenAI, DeepSeek, or custom endpoint. |

```
       📱 Phone / Tablet (PWA)                     💻 Omarchy Linux Desktop (PC)
  ┌────────────────────────────────┐         ┌──────────────────────────────────────┐
  │  [Desk] [Code] [Media] [Utils] │ ──LAN──▶│  • Instant Workspace & Window Switch │
  │  ⌨️ Direct PC Typing (iOS mic) │  HTTPS  │  • Terminal TUIs (OpenCode, Lazydock)│
  │  🎙️ Tactile Hold-to-Talk AI    │  (8765) │  • Audio / Media / Brightness / Apps │
  │  ⚡ Process Killer & Dev Tools │         │  • Hyprland Lua Dispatcher Engine    │
  └────────────────────────────────┘         └──────────────────────────────────────┘
```

---

## 🌟 Highlights

- **📱 Touch Remote Deck (PWA)**: Calibrated for zero-scroll viewport precision across both portrait (e.g. 390×844) and landscape (844×390). Add to iOS or Android Home Screen for an instant fullscreen hardware deck experience with tactile haptic feedback.
- **⌨️ Direct PC Typing & Always-On Key Bar**: Type directly into whatever browser bar, code editor, or terminal window is focused on your Linux desktop with persistent auxiliary keys (`↵ Enter`, `⌫ Del`, `Tab ⇥`, `📋 Paste`, `Esc`).
- **🎙️ Inline Speech Dictation & AI Polish**: Dedicated dictation mic inside the input bar with intelligent Amical-style cleanup (strips filler words like "um", "uh", fixes punctuation, and applies context-aware formatting based on active window class).
- **🕹️ Hold, Tap, or Hybrid Mic Activation**: Choose between Push-to-talk (hold to speak), Hands-free latch (tap to start/stop), or Both (hybrid tap/hold) with radar pulse and live sound-wave visualizers.
- **🤖 Universal AI Model Support**: Works with **any** modern LLM provider:
  - **Groq** (Ultra-fast 500+ tok/s with Llama 3.3 70B)
  - **Ollama** (100% offline, local & free)
  - **OpenAI** (gpt-4o / gpt-4o-mini)
  - **OpenRouter**, **DeepSeek**, **Mistral**, **NVIDIA NIM**, and **Custom OpenAI-compatible endpoints** (vLLM, LM Studio).
- **🎙️ Independent Speech-to-Text (`STT_API_KEY`)**: Decoupled voice transcription so you can run a local LLM (Ollama) while taking advantage of blazing-fast cloud Whisper (Groq/OpenAI), or keep it 100% offline with local `faster-whisper`.
- **🎨 24 Omarchy Color Themes & Auto-Sync**: Auto-matches your active Omarchy desktop theme live (Gruvbox, Catppuccin, Tokyo Night, Nord, Everforest, Kanagawa, Rose Pine, Hackerman, etc.) or manually select your favorite OLED theme!
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
| **🛠️ Utils** | Clean system utility dashboard: Btop system monitor, T3 Code Dashboard, OpenCode AI terminal, Lazygit, Lazydocker, Kill Window, Zen Mode, Caffeine (keep awake), Night Light, and Clipboard history. |

### 🕹️ Ergonomic Landscape Split-Deck Mode
Prop your phone or tablet next to your keyboard as a dedicated physical Stream Deck alternative:

<div align="center">
  <img src="docs/images/landscape-deck-tokyo-night.png" width="760" alt="OmaDeck Landscape Split-Deck (Tokyo Night)" />
</div>

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

Configure your AI provider, mic triggers, and OLED themes from either your PC or phone:

<div align="center">

| ⚙️ AI Keys & Settings | 🎨 24 OLED Themes & Auto-Sync |
| :---: | :---: |
| <img src="docs/images/settings-tokyo-night.png" width="350" alt="OmaDeck AI Settings Modal (Tokyo Night)" /> | <img src="docs/images/themes-tokyo-night.png" width="350" alt="OmaDeck Themes Modal (Tokyo Night)" /> |

</div>

* **On PC**: Run `omarchy-voice settings` in terminal to launch the settings panel.
* **On Phone**: Tap the **⚙️** gear icon in the top navigation bar.

In the **API Keys** pane:
- Select your provider (**Groq**, **Ollama**, **OpenAI**, **OpenRouter**, **DeepSeek**, **Mistral**, **NVIDIA**, or **Custom**).
- Choose your **Mic Activation** style (**Hold to talk**, **Tap to talk**, or **Both tap & hold**).
- Enable **AI Dictation Polishing** to automatically strip filler words ("um", "uh") and fix formatting.
- Paste your API key (stored in `~/.config/omarchy-voice/env` with `chmod 600`).
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

## 🗺️ Roadmap & Contributing

- Check out the **[OmaDeck Roadmap](ROADMAP.md)** for planned features and upcoming milestones.
- Interested in contributing? Read **[CONTRIBUTING.md](CONTRIBUTING.md)** for local development and setup guidelines.
- Have ideas or issues? Open an issue on our [GitHub Issue Tracker](https://github.com/Mohsintl/omadeck/issues).

---

## 🤝 Acknowledgments & Heritage

- Built for **[Omarchy](https://omarchy.org)** and the **[Hyprland](https://hyprland.org)** Wayland compositor.
- Foundations and core Hyprland Lua dispatching inspired by and developed from **[omarchy-voice](https://github.com/wombatoperator/omarchy-voice)** by Britain Eriksen.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
