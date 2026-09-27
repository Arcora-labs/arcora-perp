import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser', testMatch: '**/*.spec.ts', fullyParallel: false, workers: 1,
  timeout: 65000, expect: { timeout: 5000 },
  outputDir: 'output/playwright/results',
  reporter: [['list'], ['json', { outputFile: 'output/playwright/results.json' }]],
  use: { baseURL: 'http://127.0.0.1:4173', trace: 'off', screenshot: 'off', video: 'off' },
  projects: [{ name: 'chromium', use: devices['Desktop Chrome'] }, { name: 'webkit', use: devices['Desktop Safari'] }],
  webServer: { command: 'pnpm exec vite build --config tests/browser/vite.config.ts && node tests/browser/server.mjs', port: 4173, reuseExistingServer: false },
});
