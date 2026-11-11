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
   Instead of using the background systemd service, you can run the bridge in your terminal:
   ```bash
   systemctl --user stop omadeck.service
   omadeck mobile
   ```
   In another terminal, `omadeck log -f` shows what was heard, what the AI did, and every button press.

4. **Testing Python Code**:
   Run the same tests CI runs before opening a pull request:
   ```bash
   python -m unittest discover -s tests
   ```
   After changing installed code, `./install.sh` and then `omadeck restart` puts it live.

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

**Before you start:** for a bug fix or a small change, go ahead. For a new feature, a new profile, or anything that changes how OmaDeck works, open an issue first so we can agree on the approach before you spend time on it.

1. Create a feature branch: `git checkout -b feat/my-new-feature`
2. Commit your changes with clear, descriptive commit messages.
3. Push to your fork: `git push origin feat/my-new-feature`
4. Open a Pull Request and fill in the template: what changed, why, and how you tested it. Include screenshots or a screen recording for UI changes.

**How PRs get merged:**
- **One change per PR.** A fix and an unrelated feature belong in separate PRs.
- **CI must pass.** The tests run on Python 3.11, 3.12 and 3.13. If you're contributing for the first time, a maintainer approves the CI run first.
- **Tests come with fixes.** A bug fix should include a test that fails without it.
- **The maintainer merges.** PRs are squash-merged, so each one becomes a single commit on `main`.
- **Say what you didn't test.** If you couldn't try something on a real phone or Hyprland, say so in the PR. That's fine; claiming it was tested when it wasn't is not.

Security problems go through [private vulnerability reporting](SECURITY.md), not a public issue or PR.
