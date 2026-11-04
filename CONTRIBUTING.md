# Contributing to OmaDeck

Thank you for your interest in contributing to OmaDeck! Whether you are submitting a bug fix, proposing a new deck profile, or improving documentation, your help is welcome.

---

## 🛠️ Development Setup

OmaDeck runs locally on your Linux machine with Python 3.10+ and Hyprland.

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/omadeck.git
   cd omadeck
   ```

2. **Run Installer in Development Mode**:
   ```bash
   ./install.sh
   ```

3. **Running the Mobile Deck Directly**:
   Instead of using the background systemd service, you can run the bridge directly in your terminal to see live logs:
   ```bash
   systemctl --user stop omadeck.service
   python3 -m omarchy_voice.mobile_bridge --port 8765
   ```

4. **Testing Python Code**:
   Verify syntax and run tests before opening a pull request:
   ```bash
   pytest tests/
   python3 -m py_compile src/omarchy_voice/mobile_bridge.py
   ```

---

## 🎨 Modifying the Web Deck (PWA)

The mobile deck UI is self-contained in `src/omarchy_voice/mobile_bridge.py` inside `_PWA_HTML`. It requires no node_modules or build steps:
- **Zero external dependencies**: Clean vanilla JavaScript, CSS custom properties, and SVG icons.
- **Viewport Calibration**: All touch controls are calibrated for zero-scroll on modern phone viewports (portrait 390×844 and landscape 844×390).
- **Instant Testing**: Make your edits and restart the bridge to test immediately on your phone.

---

## 📋 Guidelines

- **Keep It Fast**: Quick actions (workspace switching, media, brightness, process kill) should execute locally in milliseconds via `_quick_command()` without requiring an LLM round-trip.
- **Respect Zero-Scroll**: Do not introduce overflow or awkward scrolling in main macro decks unless wrapped inside a dedicated profile container.
- **Safety First**: Never hardcode API keys or credentials. Use `~/.config/omarchy-voice/env` or the web Settings panel.

---

## 🔀 Submitting Pull Requests

1. Create a feature branch: `git checkout -b feat/my-new-feature`
2. Commit your changes with clear, descriptive commit messages.
3. Push to your fork: `git push origin feat/my-new-feature`
4. Open a Pull Request with a clear description and screenshots or screen recordings if UI changes are involved.
