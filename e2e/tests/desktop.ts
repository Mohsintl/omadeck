import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// start-deck.sh puts fake hyprctl and wtype on the bridge's PATH; each call
// they get is a line here. That is what reached the desktop.
const CALLS = fileURLToPath(new URL('../.deck/calls.log', import.meta.url));

/** Every command the desktop has received since the bridge started. */
export function desktopCalls(): string[] {
  try {
    return readFileSync(CALLS, 'utf8').split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/** The pairing link the terminal prints, with the token start-deck.sh wrote. */
export const PAIRING_LINK = `/?token=${process.env.OMADECK_TOKEN ?? 'e2e-pairing-token'}`;
