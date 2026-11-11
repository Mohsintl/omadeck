import type { E2EConfig } from 'e2e';
import { web } from '@e2e-dev/web';
import { gateway } from 'ai';

export const TOKEN = 'e2e-pairing-token';
const PORT = 8799;

export default {
  // The Vercel AI Gateway serves the model and reads AI_GATEWAY_API_KEY.
  // Only tests/agentic.e2e.ts needs it; tests/deck.e2e.ts runs without one.
  agents: {
    default: {
      model: gateway('openai/gpt-6-luna-fast'),
      system: 'You are a thorough QA agent testing a phone remote for a Linux desktop. Verify every outcome.',
    },
  },
  targets: [
    {
      // The deck is a phone app, so the tests use a phone-sized screen.
      engine: web({ viewport: { width: 390, height: 844 } }),
      app: {
        url: `http://localhost:${PORT}`,
        command: { executable: './start-deck.sh', reuseExisting: true },
      },
    },
  ],
} satisfies E2EConfig;
