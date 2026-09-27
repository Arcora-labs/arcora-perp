# Frontend dependency delta

The only new direct dependency is test-only `@playwright/test@1.58.2` (exact pin), with matching Playwright/core and optional macOS fsevents. Browser engines installed: Chromium 145.0.7632.6 / WebKit 26.0 (Playwright build 2248). Package installation used pnpm 11.5.1 / Node 24.12.0; the repository CI recommends Node 22 / pnpm 10, so CI-version parity is a separate gate.

Compatible transitive security updates used `pnpm update --depth Infinity postcss nanoid browserslist baseline-browser-mapping`. They remain within upstream ranges: postcss 8.5.15 → 8.5.28, nanoid 3.3.15 → 3.3.19, browserslist 4.28.4 → 4.29.1, baseline-browser-mapping 2.10.38 → 2.11.26 and their browser-data packages. No production dependency version changed.

The live npm registry audit responses are retained separately:

| Selection | Before | After |
|---|---|---|
| Production | 0 findings | 0 findings |
| All dependencies | 1 critical / 6 high / 7 moderate | 1 critical / 1 high / 5 moderate |

Unresolved advisories involve Vite 5.x, Vitest 2.x, @vitest/mocker and Vite's esbuild 0.21.5. Their suggested safe branches require a major build/test-tool upgrade. This patch does not silently override those dependency contracts or claim audit is clean. Do not expose dev/Vitest UI servers to untrusted networks. A separate Vite/Vitest migration with CI parity and plugin review is the next dependency task. The browser verification server is loopback-only and serves compiled assets; it is not the vulnerable development server.
