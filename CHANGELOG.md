# Changelog

What changed in each OmaDeck release. The [GitHub releases](https://github.com/Mohsintl/omadeck/releases) have the full notes.

## [Unreleased]

### Added
- A dock under your thumb: Ask, a big mic and Type, each opening one panel above it (#44, #45).
- Tabs and keys of your own, including Steps that run deck keys, text, key combos and waits in order (#48).
- Edit deck: hide and reorder keys and pick the quick keys, saved on the phone (#46).
- Hold a workspace key to move the window there; one row replaces the move keys (#46).
- `omadeck update` pulls, reinstalls and restarts in one step (#47).
- One QR code sets up a phone: a setup page installs and checks the certificate, then opens the deck (#50).
- `omadeck log` shows every command run on the PC, each phone action and its result, and what a phone fetches (#40, #51, #52).

### Changed
- Tiles use plain words; the header keeps the status and moves Sound, Logs, Settings and Lock into a ⋯ menu; replies show in a bubble above the dock; quick keys are bigger and always visible (#45, #46).
- The Type panel has one Send with a remembered Press ↵ after switch (#46).

### Fixed
- Play/pause works on YouTube: media keys press YouTube's own keys in its window, and use MPRIS for other players (#39, #41, #42, #43).
- Terminals opened from the deck can use sudo: apps start through Hyprland, outside the service sandbox (#49).
- The PIN keypad digits are readable in every theme (#49).
- Android installs the deck as a full-screen app, and the iPhone Home Screen shows the logo and the name OmaDeck (#50, #51, #52).

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
