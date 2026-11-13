#!/usr/bin/env bash
# OmaDeck installer. Safe to re-run; every step is idempotent.
#
#   ./install.sh          asks about each part
#   ./install.sh --quick  just the phone deck: installs what it needs, skips
#                         the extras, and ends by showing the pairing QR codes
#   ./install.sh --update copy in new code and refresh what is already
#                         installed, without asking (omadeck update runs this)
set -euo pipefail

QUICK=0
UPDATE=0
for arg in "$@"; do
  case "$arg" in
    -q|--quick) QUICK=1 ;;
    -u|--update) UPDATE=1 ;;
    -h|--help)
      sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown option: %s (try --help)\n' "$arg" >&2; exit 2 ;;
  esac
done

PREFIX="${PREFIX:-$HOME/.local/share/omarchy-voice}"
BINDIR="${BINDIR:-$HOME/.local/bin}"
PLUGINDIR="$HOME/.config/omarchy/plugins"
CONFIGDIR="$HOME/.config/omarchy-voice"
UNITDIR="$HOME/.config/systemd/user"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\033[1;34m::\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
ask()  { read -rp "   $1 [y/N] " reply; [[ "$reply" =~ ^[Yy] ]]; }
# What the phone deck needs: yes without asking under --quick.
need() { if (( QUICK )); then echo "   $1 yes (--quick)"; return 0; fi; ask "$1"; }
# Optional extras: skipped without asking under --quick.
extra() { if (( QUICK )); then return 1; fi; ask "$1"; }

# Install one package, checking pacman's sync databases first. A fresh or
# long-idle machine can have no databases at all, and then `pacman -S` fails
# with "database file for 'extra' does not exist". Never fatal: a missing
# optional package must not abandon a half-finished install.
pacman_install() {
  local pkg="$1"
  if ! compgen -G "/var/lib/pacman/sync/*.db" >/dev/null 2>&1 \
     || ! pacman -Sp "$pkg" >/dev/null 2>&1; then
    warn "pacman's sync databases are missing or too stale to find $pkg."
    if ask "refresh them with 'sudo pacman -Sy'?"; then
      sudo pacman -Sy || { warn "could not refresh the databases"; return 1; }
    else
      return 1
    fi
  fi
  sudo pacman -S --needed --noconfirm "$pkg"
}

if (( UPDATE )); then
  bold "OmaDeck update"
else
  bold "OmaDeck installer"
  echo "A phone remote and voice control for Omarchy."
fi
if (( QUICK )); then
  echo "Quick install: the phone deck only. Voice and AI can be added later from the deck's Settings."
fi
echo

# --- sanity ----------------------------------------------------------------
if ! command -v hyprctl >/dev/null; then
  warn "hyprctl not found — this add-on drives Hyprland and needs it."
  exit 1
fi
if ! command -v omarchy >/dev/null; then
  warn "the omarchy CLI was not found. Things will mostly work, but the"
  warn "assistant loses half of what it can do."
fi

# --- files -----------------------------------------------------------------
step "installing to $PREFIX"
mkdir -p "$PREFIX" "$BINDIR" "$CONFIGDIR" "$HOME/.local/state/omarchy-voice" "$HOME/.cache/omarchy-voice"
rm -rf "$PREFIX/src" "$PREFIX/bin" "$PREFIX/share" "$PREFIX/omarchy" "$PREFIX/.venv"
cp -r "$SOURCE/src" "$SOURCE/bin" "$SOURCE/share" "$SOURCE/omarchy" "$PREFIX/"
chmod +x "$PREFIX/bin/omarchy-voice"
ln -sf "$PREFIX/bin/omarchy-voice" "$BINDIR/omarchy-voice"
ln -sf "$PREFIX/bin/omarchy-voice" "$BINDIR/omadeck"
echo "   omadeck -> $BINDIR/omadeck (omarchy-voice also works)"
# Where this copy came from, so `omadeck update` can pull and reinstall.
printf '%s\n' "$SOURCE" > "$PREFIX/source"

if [[ ! -f "$CONFIGDIR/config.toml" ]]; then
  cp "$SOURCE/share/config.example.toml" "$CONFIGDIR/config.toml"
  echo "   wrote $CONFIGDIR/config.toml"
else
  echo "   kept your existing $CONFIGDIR/config.toml"
fi

# Empty env file, mode 600. Never copy a key out of the current shell.
ENVFILE="$CONFIGDIR/env"
if [[ ! -f "$ENVFILE" ]]; then
  umask 077
  cat > "$ENVFILE" <<'EOF'
# Keys for the systemd user service and for `omarchy-voice` run from a
# terminal. chmod 600. A key exported in your shell does not reach systemd.
# OPENAI_API_KEY=sk-...
EOF
  chmod 600 "$ENVFILE"
  if (( QUICK )); then echo "   wrote $ENVFILE (mode 600)"; else echo "   wrote $ENVFILE (mode 600) — put OPENAI_API_KEY here"; fi
else
  chmod 600 "$ENVFILE" 2>/dev/null || true
  echo "   kept your existing $ENVFILE"
fi

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) warn "$BINDIR is not on your PATH — add it, or the keybindings will not work." ;;
esac

# --- update: refresh only what is already installed, ask nothing ----------
if (( UPDATE )); then
  if [[ -d "$PLUGINDIR/voice.indicator" ]]; then
    rm -rf "$PLUGINDIR/voice.indicator"
    cp -r "$SOURCE/plugin/voice.indicator" "$PLUGINDIR/"
    echo "   refreshed the bar widget"
  fi
  refreshed=0
  for unit in omarchy-voice.service omadeck.service; do
    if [[ -f "$UNITDIR/$unit" ]]; then
      cp "$SOURCE/share/$unit" "$UNITDIR/"
      refreshed=1
    fi
  done
  if (( refreshed )) && command -v systemctl >/dev/null; then
    systemctl --user daemon-reload
    echo "   refreshed the systemd services"
  fi
  OMARCHY_BIN=$(dirname "$(command -v omarchy 2>/dev/null || echo /usr/bin/omarchy)")
  for cmd in "$SOURCE"/omarchy/bin/omarchy-voice*; do
    installed="$OMARCHY_BIN/$(basename "$cmd")"
    if [[ -f "$installed" ]] && ! cmp -s "$cmd" "$installed"; then
      warn "the 'omarchy voice ...' commands changed. They need sudo, so update them with ./install.sh"
      break
    fi
  done
  echo
  bold "installed. Restart to use it: omadeck restart"
  exit 0
fi

# --- realtime --------------------------------------------------------------
# Only the voice daemon needs this; the phone deck does not.
if (( ! QUICK )); then
echo
step "OpenAI Realtime"
if python3 -c "import websockets" 2>/dev/null; then
  echo "   python-websockets already installed"
elif ask "install python-websockets with pacman?"; then
  pacman_install python-websockets \
    || warn "not installed — the daemon cannot connect without it"
else
  warn "skipped — the daemon cannot connect without it"
fi

if grep -q "^OPENAI_API_KEY=.\+" "$ENVFILE" 2>/dev/null || [[ -n "${OPENAI_API_KEY:-}" ]]; then
  echo "   OPENAI_API_KEY is set"
else
  warn "OPENAI_API_KEY is not set. Put it in $ENVFILE as"
  warn "OPENAI_API_KEY=sk-... — a key exported in your shell does not reach"
  warn "the systemd user service."
fi
warn "while listening is on, room audio streams continuously to OpenAI."
warn "Toggling off stops the recorder, so nothing is captured while muted."
fi

# --- desktop integration ---------------------------------------------------
echo
step "desktop integration"
if [[ -d "$HOME/.config/omarchy" ]] && extra "install the bar widget plugin?"; then
  mkdir -p "$PLUGINDIR"
  cp -r "$SOURCE/plugin/voice.indicator" "$PLUGINDIR/"
  echo "   installed to $PLUGINDIR"
  if command -v omarchy >/dev/null && omarchy bar put voice.indicator --section right >/dev/null 2>&1; then
    echo "   placed on the bar, right section"
  else
    warn "could not place it automatically. Add it with:"
    echo "     omarchy bar put voice.indicator --section right"
  fi
fi

# The `omarchy voice ...` routes. Optional and off by default: they need a
# directory that `omarchy` itself scans, which is the one holding the omarchy
# binary — /usr/bin, and therefore root. Without this you still have the
# `omarchy-voice` command; you just do not get the omarchy-native spelling.
OMARCHY_BIN=$(dirname "$(command -v omarchy 2>/dev/null || echo /usr/bin/omarchy)")
if [[ -d $OMARCHY_BIN ]] && extra "also install the 'omarchy voice ...' commands into $OMARCHY_BIN (needs sudo)?"; then
  if sudo install -m 755 "$SOURCE"/omarchy/bin/omarchy-voice* "$OMARCHY_BIN/"; then
    echo "   installed. Try: omarchy voice doctor"
  else
    warn "could not install them; 'omadeck' still works on its own."
  fi
fi

if extra "install the voice daemon service (starts with your session)?"; then
  mkdir -p "$UNITDIR"
  cp "$SOURCE/share/omarchy-voice.service" "$UNITDIR/"
  systemctl --user daemon-reload
  systemctl --user enable omarchy-voice.service
  echo "   enabled. Start it now with: omadeck restart"
fi

# The phone bridge is a separate long-running process: it has to stay up even
# while the daemon is off, and restarting one should not restart the other.
OLD_MOBILE_UNIT="$UNITDIR/omarchy-voice-mobile.service"
if [[ -f "$UNITDIR/omadeck.service" || -f "$OLD_MOBILE_UNIT" ]] \
   || need "serve the phone deck (systemd user service on port 8765)?"; then
  # The service was renamed. Stop the old one, or it would keep holding the port.
  if [[ -f "$OLD_MOBILE_UNIT" ]]; then
    systemctl --user disable --now omarchy-voice-mobile.service 2>/dev/null || true
    rm -f "$OLD_MOBILE_UNIT"
  fi
  mkdir -p "$UNITDIR"
  cp "$SOURCE/share/omadeck.service" "$UNITDIR/"
  systemctl --user daemon-reload
  systemctl --user enable omadeck.service
  # restart, not start: a re-install has to pick up the new code.
  systemctl --user restart omadeck.service
  echo "   running"
  if ! command -v qrencode >/dev/null && need "install qrencode, to show a QR code for pairing?"; then
    pacman_install qrencode || warn "not installed; the pairing link still works without it"
  fi
fi

# --- keybindings -----------------------------------------------------------
# The voice toggle key. The quick install has no voice daemon, so it skips this.
BINDINGS="$HOME/.config/hypr/bindings.lua"
if (( QUICK )); then
  :
else
echo
step "keybindings"
if [[ ! -f "$BINDINGS" ]]; then
  warn "$BINDINGS does not exist. Add this by hand:"
  sed 's/^/     /' "$SOURCE/share/bindings.lua.snippet"
elif grep -q 'omarchy-voice' "$BINDINGS"; then
  echo "   already bound in $BINDINGS"
elif extra "bind SUPER + SHIFT + V in $BINDINGS?"; then
  cp "$BINDINGS" "$BINDINGS.bak-voice"
  cat >> "$BINDINGS" <<'LUA'

-- omarchy-voice ------------------------------------------------------------
-- Avoids SUPER + V (Universal paste) and SUPER + CTRL + V (clipboard manager).
-- Listening is off until this key turns it on, and off again when it does.
if o.cmd_present("omarchy-voice") then
  o.bind("SUPER + SHIFT + V", "Toggle voice control", "omarchy-voice listen toggle")
end
LUA
  echo "   appended, backup at $BINDINGS.bak-voice"
  if hyprctl reload >/dev/null 2>&1; then
    echo "   reloaded — SUPER + SHIFT + V is live"
  else
    warn "could not reload Hyprland; the binding applies on next reload"
  fi
else
  echo "   skipped. The snippet is at $SOURCE/share/bindings.lua.snippet"
fi
fi

# --- pair your phone -------------------------------------------------------
# End on the one thing a new user wants: the QR codes to scan. Wait for the
# service to listen first; if it is not up yet, `omadeck mobile` would start
# a second bridge in the foreground and the installer would never finish.
deck_listening() {
  if command -v ss >/dev/null; then
    ss -Hltn "sport = :8765" 2>/dev/null | grep -q .
  else
    (exec 3<>/dev/tcp/127.0.0.1/8765) 2>/dev/null
  fi
}

echo
if [[ -f "$UNITDIR/omadeck.service" ]]; then
  for _ in $(seq 1 40); do deck_listening && break; sleep 0.25; done
  if deck_listening; then
    bold "pair your phone"
    "$BINDIR/omadeck" mobile || warn "could not print the pairing steps; run: omadeck mobile"
  else
    warn "the deck service has not started yet. Check it with: systemctl --user status omadeck"
    echo "   then run: omadeck mobile"
  fi
else
  echo "   The phone deck service was not installed. Pair a phone with: omadeck mobile"
fi

echo
bold "next"
echo "   omadeck mobile                    show the pairing steps again"
echo "   omadeck update                    pull the latest OmaDeck, reinstall and restart"
echo "   omadeck restart                   restart everything"
echo "   omadeck doctor                    check every moving part"
if (( QUICK )); then
  echo "   ./install.sh                      add voice control and the extras later"
else
  echo "   voice control                     pick an AI provider in the deck's Settings,"
  echo "                                     or put OPENAI_API_KEY=sk-... in $ENVFILE"
fi
