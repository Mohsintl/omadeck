<p align="center"><img src="docs/assets/omadeck-logo-256.png" width="128" alt="OmaDeck logo: a glowing purple deck of keys with a microphone key, inside segmented rings" /></p>

<h1 align="center">OmaDeck</h1>

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Client-iOS%20%7C%20Android%20(PWA)-blue)](#)
[![Compositor](https://img.shields.io/badge/Compositor-Hyprland%20%2F%20Wayland-blueviolet)](#)
[![Linux](https://img.shields.io/badge/Linux-Arch%20%2F%20Omarchy-0f94d2)](#)
[![Roadmap](https://img.shields.io/badge/Roadmap-View%20Goals-purple)](ROADMAP.md)
[![e2e community example](https://img.shields.io/badge/e2e-community%20example-b46cff)](https://e2e.com/examples/omadeck)
[![Mentioned in Awesome Omarchy](https://awesome.re/mentioned-badge.svg)](https://github.com/aorumbayev/awesome-omarchy#development-tools)
[![CI](https://github.com/Mohsintl/omadeck/actions/workflows/ci.yml/badge.svg)](https://github.com/Mohsintl/omadeck/actions/workflows/ci.yml)

> **Tactile PWA Mobile Remote Deck & Universal AI Voice Companion for Omarchy / Hyprland Linux**

<div align="center">

<img src="docs/media/omadeck-demo.gif" width="400" alt="OmaDeck demo at 2x speed: switching workspaces, a voice command opening Chrome, dictation into an editor, killing a dev server on port 3000, and copying a link from VS Code into Chrome, all from an iPad" />

*At 2x speed: workspaces, a voice command, dictation, killing `:3000`, and copy and paste across apps, all from the iPad. [Full-quality video (MP4)](docs/media/omadeck-demo.mp4).*

</div>

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
| **Supported Devices** | Tested on iPhone and iPad. Android Chrome should work but hasn't been tested yet. Zero app store installs. |
| **Privacy & Connection** | Runs on your own network, with HTTPS once the local CA is installed, and token/PIN authentication. Works offline, though cloud APIs are more accurate. |

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
- **🔒 Local First**: Runs on your own network with an auto-generated token, a local CA limited to private addresses, and an optional PIN lock. See the [security guide](#-network-security--privacy-guide) for what it does and doesn't protect against.

---

## 📱 Five Dedicated Touch Profiles

| Profile | What it Controls |
|:---|:---|
| **🪟 Desk** | Workspaces 1–5, scratchpad toggle, window swap left/right, tile/float toggle, fullscreen, split cycle, app launchers (Files, Terminal, Web, Discord). |
| **💻 Code** | Terminal shortcuts, Git status / diff / push, test runner, process kill (`:3000`, `:8000`), `Ctrl+C`, `Ctrl+Z`, `Ctrl+L`, terminal copy/paste. |
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
1. The `omadeck` command and engine.
2. Background services that start when you log in: one for the phone page, and optionally one for the voice daemon.

### 2. Connect from Your Phone

Run this in a terminal, and it walks you through setting up your phone. If the background service is running, it just shows the steps. If it isn't, it also starts the server until you press Ctrl+C:
```bash
omadeck mobile
```
You will see output similar to:
```text
  Step 1: Install the certificate (once per phone; the mic needs it)
    Open in Safari or Chrome: http://192.168.1.50:8765/ca.crt
    [QR code]
    Fingerprint: 8A:3F:B2:91:...
    iPhone/iPad: Settings > Profile Downloaded > Install, then
      Settings > General > About > Certificate Trust Settings,
      and turn on "Oma Remote CA"

  Step 2: Open OmaDeck over HTTPS
    https://192.168.1.50:8765/?token=<token>
    [QR code]
    Keep this link private: anyone with it can control your desktop.

  Step 3: Add it to your Home Screen for everyday use
    iPhone/iPad: in Safari, tap Share > Add to Home Screen
    Optional: set a PIN in Settings > Security
```
Treat the second link and QR code like a password. The service log deliberately leaves the token out and shows only the certificate fingerprint.

To get the QR codes, say yes when the installer offers `qrencode`, or install it later with `sudo pacman -S qrencode`. The links work without it.

#### Step-by-Step Connection Guide:
1. **Install CA Certificate for Encrypted HTTPS & Microphone**:
   - Modern mobile browsers (iOS Safari & Android Chrome) **strictly require HTTPS** for microphone access (`getUserMedia`).
   - On your phone connected to the same Wi-Fi, open `http://<your-laptop-lan-ip>:8765/ca.crt` (or tap the setup banner) to download OmaDeck's scoped root CA.
   - **iOS**: Open **Settings ➔ Profile Downloaded ➔ Install**, then enable **Settings ➔ General ➔ About ➔ Certificate Trust Settings ➔ Enable Full Trust for "Oma Remote CA"**.
   - **Android**: Open **Settings ➔ Security ➔ Encryption & Credentials ➔ Install a Certificate ➔ CA Certificate**.
   - *Upgrade Note*: If you are upgrading from an earlier OmaDeck version, install the new certificate profile as the CA is now restricted with strict name constraints (`.local`, `.ts.net`, and private subnets).
2. **Connect & Pair Securely (HTTPS)**:
   - Open `https://<your-laptop-lan-ip>:8765/?token=<token>` (or scan the QR code, if `qrencode` is installed).
   - HTTPS ensures your pairing token, PIN, dictation audio, and window commands are fully encrypted across your local network.
3. **PWA Standalone App**:
   - In Safari, tap **Share ➔ Add to Home Screen** (or in Chrome, tap **⋮ ➔ Install App / Add to Home Screen**).
   - This launches OmaDeck in fullscreen mode without URL address bars, providing an authentic hardware Stream Deck experience with haptic vibrations.

---

## 🔒 Network Security & Privacy Guide

> [!IMPORTANT]
> OmaDeck provides direct input execution (virtual typing and shell triggers via `hyprctl` and `wtype`) onto your Linux desktop.

- **Local Network Only**: Never port-forward port `8765` directly through your home router or expose it to the public internet.
- **PIN Session Lock**: If you share your Wi-Fi network (or use public/office networks), go to **Settings ➔ Security** and configure a 4-to-8 digit PIN lock. This prevents anyone on the subnet from controlling your desktop.
- **Remote Access Outside Home**: To control your desktop securely while away from home, use a private encrypted mesh VPN such as **[Tailscale](https://tailscale.com)** or **WireGuard** instead of public port forwarding.

### What OmaDeck does and doesn't protect against

OmaDeck is built for a network you trust, such as your home Wi-Fi. Anyone holding your pairing link can control your desktop.

**In place:**
- **Shell access is off by default** (`allow_shell = false`). The assistant can't run commands or press Enter in a recognised terminal.
- **Untrusted text is held back.** For 2 minutes after the assistant reads a screen, terminal, web page, or clipboard, commands and saved notes need your spoken confirmation.
- **Secrets stay off plain HTTP.** PINs and API keys are refused over HTTP when HTTPS is available.
- **Limits on abuse.** PIN guesses are rate limited, connections are capped per address, and slow clients are cut off.

**Known limits:**
- **Plain HTTP still works for touch controls**, so phones without the CA can use the deck. On that connection your token and commands aren't encrypted, so use HTTPS on any network you share.
- **Prompt injection is reduced, not solved.** Text on a page could still steer ordinary clicks and typing. Be careful using the assistant on pages you don't trust.
- **The command denylist isn't a sandbox.** With `allow_shell` on, a script already on disk can do anything your user can. Leave it off unless you need it.
- **The terminal guard goes by window type.** It doesn't recognise terminals built into editors, such as VS Code's.
- **Someone on your network can block PIN login** for up to 24 hours by failing it repeatedly. Your pairing link keeps working.

Found a security problem? Please see [SECURITY.md](SECURITY.md).

---

## 🧪 Tested Compatibility

| Component | Tested on |
|:---|:---|
| **Linux** | Omarchy |
| **Compositor** | Hyprland 0.56.2. Requires `hyprctl` and `wtype`. |
| **Phone and tablet** | iPhone and iPad |

Other Hyprland setups and Android Chrome may work but haven't been tested yet. Reports are welcome in the [issue tracker](https://github.com/Mohsintl/omadeck/issues).

**Offline use:** everything works offline with local models, but voice and AI results are less accurate than with a cloud API.

### Tested end to end

The phone deck has end-to-end tests built with [e2e](https://e2e.com). They open the deck in a phone-sized browser, tap the keys, and check what reached the desktop. The desktop is fake: `hyprctl` and `wtype` stand-ins log each call, so the tests run on any machine, and CI runs them on every pull request alongside 400+ unit tests.

OmaDeck is featured as a community example on e2e: **[Testing OmaDeck's phone deck with e2e](https://e2e.com/examples/omadeck)**. To run the tests yourself, see [`e2e/README.md`](e2e/README.md).

---

## ⚙️ Interactive Settings & AI Configuration

Configure your AI provider, mic triggers, and OLED themes from either your PC or phone:

<div align="center">

| ⚙️ AI Keys & Settings | 🎨 24 OLED Themes & Auto-Sync |
| :---: | :---: |
| <img src="docs/images/settings-tokyo-night.png" width="350" alt="OmaDeck AI Settings Modal (Tokyo Night)" /> | <img src="docs/images/themes-tokyo-night.png" width="350" alt="OmaDeck Themes Modal (Tokyo Night)" /> |

</div>

* **On PC**: Run `omadeck settings` in terminal to launch the settings panel.
* **On Phone**: Tap the **⚙️** gear icon in the top navigation bar.

In the **API Keys** pane:
- Select your provider (**Groq**, **Ollama**, **OpenAI**, **OpenRouter**, **DeepSeek**, **Mistral**, **NVIDIA**, or **Custom**).
- Choose your **Mic Activation** style (**Hold to talk**, **Tap to talk**, or **Both tap & hold**).
- Enable **AI Dictation Polishing** to automatically strip filler words ("um", "uh") and fix formatting.
- Paste your API key (stored in `~/.config/omarchy-voice/env` with `chmod 600`).
- Tap **"Test & Save Keys"** to verify connection live before saving.

---

## 🖥️ Desktop Commands

```bash
# Show your pairing link
omadeck mobile

# Restart everything (the voice daemon and the phone page), e.g. after an update
omadeck restart

# What it heard, what the AI did, and every phone button press, live
omadeck log -f

# Check every moving part
omadeck doctor

# Try a command without speaking
omadeck say "go to workspace 2"
```

### Updating

```bash
cd omadeck
git pull
./install.sh
omadeck restart
```

The installer copies the new code into place and keeps your settings, keys and pairing. Answer **N** to its questions on a re-install.

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

Distributed under the [Apache License 2.0](LICENSE).
