import { defineConfig, devices } from '@playwright/test';
const port = Number(process.env.ARCORA_BROWSER_PORT || 4173);
export default defineConfig({
  testDir: './tests/browser', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1,
  timeout: 65000, expect: { timeout: 5000 },
  outputDir: 'output/playwright/results',
  reporter: [['list'], ['json', { outputFile: 'output/playwright/results.json' }]],
  use: { baseURL: `http://127.0.0.1:${port}`, trace: 'off', screenshot: 'off', video: 'off' },
  projects: [{ name: 'chromium', use: devices['Desktop Chrome'] }, { name: 'webkit', use: devices['Desktop Safari'] }],
  webServer: { command: 'pnpm exec vite build --config tests/browser/vite.config.ts && node tests/browser/server.mjs', port, reuseExistingServer: false },
});
