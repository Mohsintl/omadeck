#!/bin/sh
# Starts the OmaDeck bridge for the tests: a throwaway config with a known
# pairing token, and fake hyprctl/wtype on PATH so no real desktop is needed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
state="$here/.deck"
rm -rf "$state"
mkdir -p "$state/config/omarchy-voice"
printf '%s' "${OMADECK_TOKEN:-e2e-pairing-token}" > "$state/config/omarchy-voice/mobile_token"
: > "$state/calls.log"

export HOME="$state" XDG_CONFIG_HOME="$state/config"
export OMADECK_E2E_CALLS="$state/calls.log"
export PATH="$here/fake-desktop:$PATH"
export PYTHONPATH="$here/../src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m omarchy_voice mobile --port "${OMADECK_PORT:-8799}"
