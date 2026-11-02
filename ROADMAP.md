# 🗺️ OmaDeck Roadmap

This document outlines the planned features, improvements, and architectural milestones for **OmaDeck**. 

Community feedback and contributions are highly encouraged!

---

## 📌 Near-Term (v0.2.0)

- [x] **Universal Multi-Provider Engine**: Groq, Ollama, OpenAI, OpenRouter, DeepSeek, Mistral, NVIDIA NIM, and custom endpoints.
- [x] **Zero-Scroll PWA Mobile Deck**: Fullscreen touch deck on iOS & Android.
- [x] **Direct PC Typing**: Real-time typing from phone keyboard directly into focused PC window.
- [x] **Decoupled STT Configuration**: Support independent `STT_API_KEY` for Whisper alongside local LLMs.
- [x] **Quick Sound Mute Button**: Header toggle to instantly mute/unmute OmaDeck audio and cancel voice speech.
- [ ] **Custom Macro Builder in Web UI**: Drag-and-drop or form-based builder to define custom touch buttons with custom bash commands or key combinations.
- [ ] **Obsidian & Note Quick-Capture**: Dedicated button to dictate or type a quick note directly into your daily Obsidian vault.
- [ ] **Battery & Desktop Sensor Indicators**: Live display of PC CPU temperature, RAM usage, and laptop battery level on the top status strip.

---

## 🚀 Medium-Term (v0.3.0)

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
