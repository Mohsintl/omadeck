import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { desktopCalls, PAIRING_LINK } from './desktop';

test('the pairing link opens the deck', async ({ app, screen }) => {
  await app.open(PAIRING_LINK);

  // The status line shows the last command from any phone, so the tests check the keys instead.
  await expect(screen.getByText('Window & Layout')).toBeVisible();
  await expect(screen.getByRole('button', 'Close window')).toBeVisible();
});

test('a workspace key switches the desktop to that workspace', async ({ app, screen }) => {
  await app.open(PAIRING_LINK);

  await screen.getByRole('button', '2').click();

  await expect.poll(desktopCalls).toContain('hyprctl dispatch hl.dsp.focus({ workspace = "2" })');
});

test('Direct Type types the text into the focused PC window, then Enter', async ({ app, screen }) => {
  await app.open(PAIRING_LINK);

  await screen.getByRole('button', 'Direct Type').click();
  await screen.getByPlaceholder('Type text into active PC app…').fill('hello from the phone');
  await screen.getByRole('button', 'Send ↵').click();

  await expect.poll(desktopCalls).toContain('wtype -- hello from the phone');
  await expect.poll(desktopCalls).toContain('wtype -k Return');
});

test('the Media profile shows playback and volume keys', async ({ app, screen }) => {
  await app.open(PAIRING_LINK);

  await screen.getByRole('button', 'Media').click();

  await expect(screen.getByRole('button', 'Play / Pause')).toBeVisible();
  await expect(screen.getByRole('button', 'Volume +')).toBeVisible();
  await expect(screen.getByText('Window & Layout')).toBeHidden();
});

test('the phone stays paired after the token leaves the address bar', async ({ app, screen }) => {
  await app.open(PAIRING_LINK);
  await expect(screen.getByText('Window & Layout')).toBeVisible();

  // The page drops the token from the URL and keeps it, so a home-screen
  // shortcut saved afterwards still works.
  await app.open('/');
  await screen.getByRole('button', '4').click();

  await expect.poll(desktopCalls).toContain('hyprctl dispatch hl.dsp.focus({ workspace = "4" })');
});
