# Changelog

What changed in each OmaDeck release. The [GitHub releases](https://github.com/Mohsintl/omadeck/releases) have the full notes.

## [0.5.0] - 2026-11-12

### Added
- `./install.sh --quick`: installs just the phone deck and ends with the pairing QR codes (#26).
- Arrow keys on the deck that repeat while held (#28).
- Settings lists every API key saved on the computer, each with a Remove button (#27, #29).
- End-to-end tests for the phone deck against a fake desktop (#21).
- A home page at https://mohsintl.is-a.dev/omadeck/ (#22).

### Changed
- CI tests Python 3.11 to 3.14, CodeQL scans the code and Dependabot keeps dependencies current (#30).

## [0.4.0] - 2026-11-11

### Added
- Voice commands open any installed app on a chosen workspace ("open Chrome on workspace 5").
- All, Copy and Paste keys that work in normal apps, terminals and Neovim.
- `omadeck restart` and `omadeck log -f`.
- New logo; the Home Screen app is called OmaDeck.

### Fixed
- Kill :3000 stops dev servers, including ones listening on IPv6.
- The phone no longer shows "timed out" while a slow AI reply is on its way.
- Keyboard shortcuts work under the systemd service.
- The Home Screen app no longer asks for the token.

## [0.1.0] - 2026-11-02

First release: the phone touch deck with five profiles, typing and dictation into the PC, and voice commands with Groq, Ollama, OpenAI, OpenRouter, DeepSeek, Mistral, NVIDIA NIM or a custom endpoint.

[0.5.0]: https://github.com/Mohsintl/omadeck/releases/tag/v0.5.0
[0.4.0]: https://github.com/Mohsintl/omadeck/releases/tag/v0.4.0
[0.1.0]: https://github.com/Mohsintl/omadeck/releases/tag/v0.1.0
