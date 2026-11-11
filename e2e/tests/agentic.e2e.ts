import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { desktopCalls, PAIRING_LINK } from './desktop';

// Agent steps call the model in e2e.config.ts. Without a key these tests are skipped.
const skip = process.env.AI_GATEWAY_API_KEY ? false : 'set AI_GATEWAY_API_KEY to run agent tests';

test('the agent moves the desktop to a workspace', { skip }, async ({ app, agent }) => {
  await app.open(PAIRING_LINK);

  await agent.act('switch the PC to workspace {n}', { params: { n: '3' } });

  // Pair each agent step with a check that does not depend on the model.
  await expect.poll(desktopCalls).toContain('hyprctl dispatch hl.dsp.focus({ workspace = "3" })');
});

test('the agent types a message on the PC', { skip }, async ({ app, agent }) => {
  await app.open(PAIRING_LINK);

  await agent.act('type {text} straight into the PC, without running it as a command', { params: { text: 'typed by the agent' } });

  await expect.poll(desktopCalls).toContain('wtype -- typed by the agent');
});
