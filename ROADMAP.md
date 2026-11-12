# 🗺️ OmaDeck Roadmap

This document outlines the planned features, improvements, and architectural milestones for **OmaDeck**. 

Community feedback and contributions are highly encouraged!

---

## ✅ Shipped (up to v0.5.0)

- [x] **Universal Multi-Provider Engine**: Groq, Ollama, OpenAI, OpenRouter, DeepSeek, Mistral, NVIDIA NIM, and custom endpoints.
- [x] **Zero-Scroll PWA Mobile Deck**: Fullscreen touch deck on iOS & Android.
- [x] **Direct PC Typing**: Real-time typing from phone keyboard directly into focused PC window.
- [x] **Decoupled STT Configuration**: Support independent `STT_API_KEY` for Whisper alongside local LLMs.
- [x] **Quick Sound Mute Button**: Header toggle to instantly mute/unmute OmaDeck audio and cancel voice speech.
- [x] **Voice Commands That Open Apps**: "Open Chrome on workspace 5" works for any installed app (v0.4.0).
- [x] **Copy, Paste and Select-All Keys**: Work in normal apps, terminals and Neovim (v0.4.0).
- [x] **Two-Minute Install**: `./install.sh --quick` ends with pairing QR codes (v0.5.0).
- [x] **Arrow Keys With Hold-to-Repeat** (v0.5.0).
- [x] **Saved API Keys List**: See and remove every key saved on the computer from Settings (v0.5.0).

---

## 📌 Next Up

- [ ] **Custom Macro Builder in Web UI**: Drag-and-drop or form-based builder to define custom touch buttons with custom bash commands or key combinations.
- [ ] **Obsidian & Note Quick-Capture**: Dedicated button to dictate or type a quick note directly into your daily Obsidian vault.
- [ ] **Battery & Desktop Sensor Indicators**: Live display of PC CPU temperature, RAM usage, and laptop battery level on the top status strip.

---

## 🚀 Later

- [ ] **Local Wake-Word Detection**: Optional offline "Hey Oma" wake word powered by openWakeWord.
- [ ] **Bluetooth LE / USB WebHID Fallback**: Direct offline phone-to-PC connection when Wi-Fi/LAN is unavailable or restricted.
- [ ] **Multi-Monitor Window Director**: Dedicated interactive radar to fling windows across multiple physical monitors from your phone.
- [ ] **Media Widget with Album Art**: Real-time display of currently playing Spotify/YouTube track info and scrubbing.
- [ ] **Customizable OLED Themes**: User-defined color palettes with CSS export.

---

## 🌌 Long-Term Vision

- [ ] **Cross-Desktop Compositor Support**: Expand beyond Hyprland to Sway, River, Niri, and KDE Wayland.
- [ ] **OmaDeck Plugin Ecosystem**: Community-contributed deck packs for Blender, DaVinci Resolve, Godot, and Gaming emulators.
- [ ] **Full Offline Voice Pipeline**: Seamless bundled installation of local Whisper + local Piper TTS + Ollama for 100% air-gapped voice control.
