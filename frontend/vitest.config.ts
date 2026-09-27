import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';
// Browser specs run via the separate Chromium/WebKit command; the unit runner
// must not load Playwright's test lifecycle as a Vitest suite.
export default mergeConfig(viteConfig, defineConfig({ test: { include: ['src/**/*.test.{ts,tsx}'] } }));
