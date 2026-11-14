# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Omarchy and Hyprland Linux users, mostly developers, who want to drive their desktop from across the room: from the couch or bed, or while resting with a coding agent working on one workspace and a video playing on another. The everyday job is small and frequent: switch to a workspace to check on something, pause or skip YouTube, kill a stuck dev server, open a browser, type a reply, without walking to the keyboard.

## Product Purpose

OmaDeck turns a phone or tablet the user already owns into a Stream Deck and voice remote for their Omarchy/Hyprland desktop. It is a browser-installed PWA served by a small bridge on the PC, so there is nothing to buy and no app store. Success for the project site is a visitor copying the install command and setting up their phone; a GitHub star is the secondary action.

## Positioning

A remote built specifically for Omarchy/Hyprland: it switches and moves workspaces, drives windows and layouts, presses YouTube's own keys, runs Omarchy's own keybindings by name, and types straight into the focused window. Obvious commands run locally without an AI round trip; open-ended requests go to the user's own model (Ollama locally, or Groq, OpenAI and others). It runs on the user's own network with a local certificate and pairing.

## Operating Context

- Install: `git clone https://github.com/Mohsintl/omadeck.git && cd omadeck && ./install.sh --quick` on the Omarchy machine; one QR code opens a setup page on the phone that installs and checks the certificate, then opens the deck. Updates with `omadeck update`.
- Phone: installed as a full-screen app (iPhone/iPad via Safari's Add to Home Screen, Android via Chrome's Install app). Portrait and landscape.
- Deck: workspaces row on top; Desk, Code, Media, Web and Utils tabs plus tabs the user makes; a dock with Ask (typed command), a mic (voice) and Type (types into the PC); quick keys and arrows; Edit deck; lock with PIN.
- Desktop: Omarchy on Hyprland. Diagnostics with `omadeck log`.

## Capabilities and Constraints

- Tested on iPhone, iPad and Android (Chrome) with Omarchy on Hyprland. Other Hyprland setups may work but are untested.
- Local network only; remote use via Tailscale or WireGuard, never port forwarding. Pairing token, optional 4–8 digit PIN, HTTPS with a name-constrained local CA.
- No shell access for the assistant unless the user enables it; commands after reading a page or the clipboard wait for spoken confirmation.
- Voice is optional; tapping and typing work without any AI provider.
- The site is a single static page in `docs/` served by GitHub Pages at https://mohsintl.is-a.dev/omadeck/.

## Brand Commitments

- Name: OmaDeck. Logo: `docs/assets/omadeck-logo.svg` (keys with a microphone key inside segmented rings) and `docs/assets/omadeck-logo-256.png` are kept as they are. Everything else about the site's look is open to replacement (decided 2026-11-15).
- Voice: plain, direct, first-person where the maintainer speaks; no hype.
- Free and open source under Apache 2.0. Built on omarchy-voice by Britain Eriksen, credited in the footer.

## Evidence on Hand

- Real recordings of an iPhone driving an Omarchy laptop: `docs/media/clips/*.mp4` (13 feature clips with posters, plus `highlight.mp4`), `docs/media/omadeck-tour.mp4` (full tour), `docs/media/omadeck-tour.webp`.
- Screenshots: `docs/images/portrait-deck-dock.jpg` (current deck), `docs/images/pc-screen.jpg`, plus older theme screenshots in `docs/images/` that show an earlier layout.
- Listed in awesome-omarchy; an e2e community example.
- No testimonials, user counts, press quotes or benchmarks exist. Do not invent any.

## Product Principles

1. Show it working: real footage of the phone and the desktop together beats claims.
2. Install is the goal: the one-line command and the phone setup stay one scroll away and copyable.
3. Honest about scope: say what is tested and what is not, and what the security model does not cover.
4. Built for the couch moment: describe things as the small actions a resting user takes, not as a feature matrix.

## Accessibility & Inclusion

Autoplaying clips respect reduced motion (controls instead of autoplay), and every video has a descriptive label.
