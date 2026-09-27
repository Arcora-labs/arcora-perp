import { test, expect, type BrowserContext, type Page, type Route } from '@playwright/test';

// All credentials and addresses below are public, synthetic test fixtures.
const OWNER = '0x' + '22'.repeat(32), OLD = '0x' + '11'.repeat(32), NEW = '0x' + '77'.repeat(32);
const AUTH = '0x' + '44'.repeat(20), VAULT = '0x' + '3b'.repeat(20);
const SCOPE = { base: 'http://127.0.0.1:4173', chainId: 4242, vault: VAULT };
const KEY = `darkperp.v2Account:${JSON.stringify([SCOPE.base, SCOPE.chainId, VAULT])}`;
const record = (apiKey = OLD, recoveryNonce = 0) => ({ ...SCOPE, schema: 2, owner: OWNER, apiKey, recoveryNonce });
const market = { id: 0, symbol: 'BTC/USDC', maxLeverage: 20, maintenanceMarginRatio: .05, initialMarginRatio: .1, referencePrice: '6450000000000', live: false, takerFeeBps: 8, makerRebateBps: 2 };
const state = { markets: [market, { ...market, id: 1, symbol: 'ETH/USDC' }], selectedMarketId: 0, market, mode: 'Normal', oracle: { marketId: 0, price: '6450000000000', confidence: '1', publishTimeMs: 0 }, book: { marketId: 0, bids: [], asks: [] }, marks: { 0: '6450000000000', 1: '350000000000' }, account: { settledBalance: '0', positions: [] }, orders: [], batches: [], insuranceFund: '0', treasury: '0', userAdlClawed: '0', lp: { tvl: '0', navPerShare: '1.000000', totalShares: '0', myShares: '0', myValue: '0' }, mmHedge: [], l1: null, attestation: null };
const deferred = () => { let release!: () => void; const promise = new Promise<void>(r => release = r); return { promise, release }; };

async function fixture(context: BrowserContext, mode: 'normal' | 'legacy' | 'mismatch' | 'corrupt' = 'normal') {
  const calls: { path: string; method: string; key?: string; body: any }[] = [];
  const consoleMessages: string[] = [], urls: string[] = [];
  let generation = 0;
  let hook: ((route: Route, call: typeof calls[number]) => Promise<boolean>) | undefined;
  const sockets: any[] = [];
  await context.addInitScript(({ KEY, OWNER, OLD, AUTH, record, mode }) => {
    if (!sessionStorage.getItem('seeded')) {
      sessionStorage.setItem('seeded', 'yes');
      if (mode === 'legacy') localStorage.setItem('darkperp.v1Account', JSON.stringify({ owner: OWNER, apiKey: OLD }));
      else if (mode === 'mismatch') localStorage.setItem(KEY, JSON.stringify({ ...record, chainId: 999 }));
      else if (mode === 'corrupt') localStorage.setItem(KEY, '{broken');
      else if (!localStorage.getItem(KEY)) localStorage.setItem(KEY, JSON.stringify(record));
    }
    const control = { signs: 0, reject: false, hold: false, release: null as (() => void) | null };
    Object.assign(window, { testWallet: control, ethereum: {
      on() {}, removeListener() {},
      async request({ method }: { method: string }) {
        if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [AUTH];
        if (method === 'eth_chainId') return '0x1092';
        if (method === 'personal_sign') {
          control.signs++;
          if (control.reject) throw new Error('User rejected');
          if (control.hold) await new Promise<void>(r => control.release = r);
          return '0x' + 'ab'.repeat(65);
        }
        throw new Error('Unexpected wallet method');
      }
    }});
  }, { KEY, OWNER, OLD, AUTH, record: record(), mode });
  context.on('page', page => {
    page.on('console', msg => consoleMessages.push(msg.text()));
    page.on('request', request => urls.push(request.url()));
  });
  await context.routeWebSocket(/\/ws$/, ws => {
    sockets.push(ws);
    ws.onMessage(message => { if (JSON.parse(String(message)).type === 'auth') ws.send(JSON.stringify({ type: 'authOk', owner: OWNER })); });
  });
  await context.route(/\/(api|v1)\//, async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    const call = { path, method: req.method(), key: req.headers()['x-api-key'], body: req.postDataJSON() };
    calls.push(call);
    if (await hook?.(route, call)) return;
    let body: any = {}, status = 200;
    if (path === '/api/state') body = state;
    else if (path === '/v1/system/status') body = SCOPE;
    else if (path === '/v1/enclave/epoch') { body = { error: 'No enclave fixture: order encryption verified separately by unit suite' }; status = 503; }
    else if (path === '/v1/accounts/me') {
      if (generation > 0 && call.key === OLD) { status = 401; body = { error: 'revoked' }; }
      else body = { ...SCOPE, owner: OWNER, recoveryNonce: call.key === NEW ? generation : 0, settledBalance: '123000000', depositAddress: AUTH, callerSigned: false, nextWithdrawNonce: 1 };
    } else if (path === '/v1/positions') body = { positions: [] };
    else if (path === '/v1/orders' && call.method === 'GET') body = { orders: [] };
    else if (path.startsWith('/v1/accounts/recovery/')) body = { ...SCOPE, owner: OWNER, authorizer: AUTH, recoveryNonce: generation };
    else if (path === '/v1/accounts/recovery') { generation++; body = { owner: OWNER, apiKey: NEW, recoveryNonce: generation, durability: 'confirmed' }; }
    else if (path === '/v1/accounts/withdrawals') body = { withdrawals: [], vault: VAULT };
    else if (path.includes('book')) body = { marketId: 1, bids: [], asks: [] };
    else if (path.includes('oracle')) body = { marketId: 1, price: '350000000000', confidence: '1', publishTimeMs: Date.now() };
    else if (path === '/v1/accounts/deposit/authorize') body = { ownerCommit: OWNER, sig: '0x' + 'ab'.repeat(65) };
    await route.fulfill({ status, json: body });
  });
  return { calls, consoleMessages, urls, sockets, setHook(value: typeof hook) { hook = value; }, posts: () => calls.filter(c => c.path === '/v1/accounts/recovery' && c.method === 'POST') };
}
async function open(context: BrowserContext) {
  const page = await context.newPage(); await page.goto('/');
  await page.waitForFunction(() => !!(window as any).testClient);
  await page.getByRole('button', { name: 'Recover', exact: true }).click();
  return page;
}
async function recover(page: Page) {
  await page.getByLabel('Account owner id').fill(OWNER);
  await page.getByRole('button', { name: /^(Sign|Connect wallet).*recover$/i }).click();
}
const api = (page: Page, code: string) => page.evaluate(code);

test('BR-01 real same-origin tabs serialize recovery and adopt storage generation', async ({ context }) => {
  const f = await fixture(context); const a = await open(context), b = await open(context);
  const gate = deferred(); let parked = false;
  f.setHook(async (_r, c) => { if (c.path === '/v1/accounts/recovery') { parked = true; await gate.promise; } return false; });
  await recover(a); await expect.poll(() => parked).toBe(true);
  await b.bringToFront(); await recover(b);
  await expect(b.getByRole('alert')).toContainText('another tab');
  expect(f.posts()).toHaveLength(1);
  expect(await api(b, 'window.testWallet.signs')).toBe(0);
  gate.release(); await expect(a.getByRole('status')).toContainText('generation is now #1');
  await expect.poll(() => api(b, 'window.testClient.depositAccount().then(a => a.apiKey === "' + NEW + '")')).toBe(true);
  await b.reload(); await b.waitForFunction(() => !!(window as any).testClient);
  expect(await api(b, 'window.testClient.depositAccount().then(a => a.apiKey === "' + NEW + '")')).toBe(true);
  expect(f.urls.some(u => u.includes(OLD) || u.includes(NEW))).toBe(false);
  expect(f.consoleMessages.some(s => s.includes(OLD) || s.includes(NEW))).toBe(false);
});

test('BR-01 closing tab holding native Web Lock releases recovery for sibling', async ({ context }) => {
  const f = await fixture(context); const a = await open(context), b = await open(context);
  await api(a, 'window.testWallet.hold = true'); await recover(a);
  await expect.poll(() => api(a, 'window.testWallet.signs')).toBe(1);
  await a.close(); await recover(b);
  await expect(b.getByRole('status')).toContainText('generation is now #1'); expect(f.posts()).toHaveLength(1);
});

test('BR-04 wallet rejection and absent Web Locks both fail before POST', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  await api(page, 'window.testWallet.reject = true'); await recover(page);
  await expect(page.getByRole('alert')).toContainText('Wallet refused'); expect(f.posts()).toHaveLength(0);
  await api(page, 'window.testWallet.reject = false; Object.defineProperty(navigator, "locks", { value: undefined })');
  await recover(page); await expect(page.getByRole('alert')).toContainText('cross-tab locking'); expect(f.posts()).toHaveLength(0);
});

test('BR-05 storage quota failure retains new key in memory and warns after confirmed rotation', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  await page.evaluate(key => { const original = Storage.prototype.setItem; Storage.prototype.setItem = function(k, v) { if (k === key) throw new DOMException('quota', 'QuotaExceededError'); original.call(this, k, v); }; }, KEY);
  await recover(page); await expect(page.getByRole('status')).toContainText('this tab only');
  expect(await api(page, 'window.testClient.depositAccount().then(a => a.apiKey === "' + NEW + '")')).toBe(true);
  expect(await page.evaluate(key => JSON.parse(localStorage.getItem(key)!).apiKey === '0x' + '11'.repeat(32), KEY)).toBe(true);
  await page.reload(); await page.waitForFunction(() => !!(window as any).testClient);
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  await expect(page.getByText(/placeholders \(0\), not your/)).toBeVisible();
  expect(f.calls.filter(c => c.path === '/v1/accounts' && c.method === 'POST')).toHaveLength(0);
});

for (const mode of ['legacy', 'mismatch', 'corrupt'] as const) test(`BR-06 ${mode} record never transmits old key or registers replacement`, async ({ context }) => {
  const f = await fixture(context, mode), page = await open(context);
  expect(f.calls.some(c => c.key === OLD)).toBe(false);
  expect(f.calls.filter(c => c.path === '/v1/accounts' && c.method === 'POST')).toHaveLength(0);
  if (mode === 'legacy') {
    await expect(page.getByText(/saved legacy account/i)).toBeVisible();
    await expect(page.getByLabel('Account owner id')).toHaveValue(OWNER);
    expect(await page.evaluate(() => localStorage.getItem('darkperp.v1Account') !== null)).toBe(true);
  }
});

test('BR-08 withdrawal retains signed market when selection changes during wallet prompt', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  await api(page, 'window.testWallet.hold = true; window.pending = window.testClient.requestWithdrawal(1000000n).then(() => "ok", e => e.message); undefined');
  await expect.poll(() => api(page, 'window.testWallet.signs')).toBe(1);
  await api(page, 'window.testClient.selectMarket(1); window.testWallet.release()');
  expect(await api(page, 'window.pending')).toBe('ok');
  expect(f.calls.find(c => c.path === '/v1/accounts/withdraw')?.body.marketId).toBe(0);
});

test('BR-07 cancel response after recovery cannot emit success into new credential context', async ({ context }) => {
  const f = await fixture(context), page = await open(context); const gate = deferred(); let parked = false;
  f.setHook(async (_r, c) => { if (c.method === 'DELETE') { parked = true; await gate.promise; } return false; });
  await api(page, 'window.events = []; window.testClient.onOrderEvent(e => window.events.push(e)); window.pending = window.testClient.cancelOrder("o42").then(() => "ok", e => e.message); undefined');
  await expect.poll(() => parked).toBe(true); await recover(page); await expect(page.getByRole('status')).toContainText('generation is now #1');
  gate.release(); expect(await api(page, 'window.pending')).toMatch(/account.*changed|credential.*changed/i);
  expect(await api(page, 'window.events.length')).toBe(0);
});

test('S2-04 CSP blocks inline script and external connect; errors render only text', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  const response = await page.request.get('/');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self'");
  const checks = await page.evaluate(async () => {
    const script = document.createElement('script'); script.textContent = 'window.xssExecuted = true'; document.body.append(script);
    let blocked = false; try { await fetch('https://invalid.example.test/forbidden'); } catch { blocked = true; }
    return { executed: !!(window as any).xssExecuted, blocked };
  });
  expect(checks).toEqual({ executed: false, blocked: true });
  f.setHook(async (route, c) => { if (c.path === '/v1/accounts/withdraw') { await route.fulfill({ status: 400, json: { error: '<img src=x onerror="window.xssExecuted=true">' } }); return true; } return false; });
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  await page.getByRole('button', { name: 'Withdraw', exact: true }).click();
  await expect(page.locator('.notice--error')).toContainText('<img');
  expect(await api(page, '!!window.xssExecuted')).toBe(false);
  expect(await page.locator('.notice--error img').count()).toBe(0);
});

test('BR-03 real HTTP body stall is bounded and preserves saved credential', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  f.setHook(async (route, c) => { if (c.path.includes('/recovery/')) { await route.continue({ url: SCOPE.base + '/__stall-body' }); return true; } return false; });
  await recover(page);
  await expect(page.getByRole('alert')).toContainText('3 attempts', { timeout: 55000 });
  expect(f.posts()).toHaveLength(0);
  expect(await page.evaluate(key => JSON.parse(localStorage.getItem(key)!).apiKey === '0x' + '11'.repeat(32), KEY)).toBe(true);
});

test('BR-08 cross-tab rotation while withdrawal signature waits aborts old mutation', async ({ context }) => {
  const f = await fixture(context), a = await open(context), b = await open(context);
  await api(a, 'window.testWallet.hold = true; window.pending = window.testClient.requestWithdrawal(1000000n).then(() => "ok", e => e.message); undefined');
  await expect.poll(() => api(a, 'window.testWallet.signs')).toBe(1);
  await recover(b); await expect(b.getByRole('status')).toContainText('generation is now #1');
  await expect.poll(() => api(a, 'window.testClient.depositAccount().then(a => a.apiKey === "' + NEW + '")')).toBe(true);
  await api(a, 'window.testWallet.release()');
  expect(await api(a, 'window.pending')).toMatch(/account.*changed|credential.*changed/i);
  expect(f.calls.filter(c => c.path === '/v1/accounts/withdraw')).toHaveLength(0);
});

test('BR-07 stale withdrawal proof response is discarded after rotation', async ({ context }) => {
  const f = await fixture(context), page = await open(context), gate = deferred(); let parked = false;
  f.setHook(async (r, c) => { if (c.path === '/v1/accounts/withdrawals') { parked = true; await gate.promise; await r.fulfill({ json: { withdrawals: [], vault: VAULT } }); return true; } return false; });
  await api(page, 'window.pending = window.testClient.listWithdrawals(); undefined');
  await expect.poll(() => parked).toBe(true); await recover(page); await expect(page.getByRole('status')).toContainText('generation is now #1');
  gate.release(); expect(await api(page, 'window.pending')).toBe(null);
});

test('BR-01 metadata and storage-write barriers retain one recovery lock across tabs', async ({ context }) => {
  const f = await fixture(context), a = await open(context), b = await open(context);
  const metadata = deferred(); let parked = false;
  f.setHook(async (_r, c) => { if (c.path.includes('/recovery/')) { parked = true; await metadata.promise; } return false; });
  await recover(a); await expect.poll(() => parked).toBe(true);
  await recover(b); await expect(b.getByRole('alert')).toContainText('another tab');
  expect(await api(a, 'window.testWallet.signs')).toBe(0); expect(f.posts()).toHaveLength(0);
  await b.evaluate(key => { void navigator.locks.request(key + ':write', () => new Promise<void>(resolve => { Object.assign(window, { releaseWrite: resolve }); })); }, KEY);
  await b.waitForFunction(() => !!(window as any).releaseWrite);
  metadata.release(); await expect.poll(() => f.posts().length).toBe(1);
  await recover(b); await expect(b.getByRole('alert')).toContainText('another tab');
  expect(await api(b, 'window.testWallet.signs')).toBe(0);
  await api(b, 'window.releaseWrite()'); await expect(a.getByRole('status')).toContainText('generation is now #1');
});

test('BR-02 obsolete socket callbacks cannot close current native browser socket', async ({ context }) => {
  await fixture(context); const page = await open(context);
  await page.waitForFunction(() => (window as any).testClient.wsV1?.readyState === WebSocket.OPEN);
  await api(page, 'window.oldSocket = window.testClient.wsV1; window.oldCallbacks = [window.oldSocket.onmessage, window.oldSocket.onerror, window.oldSocket.onclose]');
  await recover(page); await expect(page.getByRole('status')).toContainText('generation is now #1');
  await page.waitForFunction(() => (window as any).testClient.wsV1?.readyState === WebSocket.OPEN);
  await page.evaluate(owner => {
    const w = window as any;
    w.oldCallbacks[0].call(w.oldSocket, new MessageEvent('message', { data: JSON.stringify({ type: 'authOk', owner }) }));
    w.oldCallbacks[0].call(w.oldSocket, new MessageEvent('message', { data: JSON.stringify({ type: 'error', message: 'obsolete fixture' }) }));
    w.oldCallbacks[1].call(w.oldSocket, new Event('error'));
    w.oldCallbacks[2].call(w.oldSocket, new CloseEvent('close'));
  }, OWNER);
  expect(await api(page, 'window.testClient.wsV1.readyState')).toBe(1);
  expect(await api(page, 'window.testClient.depositAccount().then(a => a.apiKey === "' + NEW + '")')).toBe(true);
});

test('BR-07 old refresh held across rotation cannot install stale balance', async ({ context }) => {
  const f = await fixture(context), page = await open(context), gate = deferred(); let parked = false;
  f.setHook(async (r, c) => {
    if (c.path === '/v1/accounts/me' && c.key === OLD) {
      parked = true; await gate.promise;
      await r.fulfill({ json: { ...SCOPE, owner: OWNER, recoveryNonce: 0, settledBalance: '999999999999' } }); return true;
    }
    return false;
  });
  await api(page, 'window.pendingRefresh = window.testClient.refreshOwnState(); undefined');
  await expect.poll(() => parked).toBe(true); await recover(page);
  await expect.poll(() => f.posts().length).toBe(1);
  gate.release(); await expect(page.getByRole('status')).toContainText('generation is now #1');
  await api(page, 'window.testClient.ownStateSettled()');
  expect(await api(page, 'window.testClient.getState().account.settledBalance.toString()')).toBe('123000000');
});

test('BR-05 session-only warning survives leaving and returning to recovery panel', async ({ context }) => {
  await fixture(context); const page = await open(context);
  await page.evaluate(key => { const original = Storage.prototype.setItem; Storage.prototype.setItem = function(k, v) { if (k === key) throw new DOMException('quota', 'QuotaExceededError'); original.call(this, k, v); }; }, KEY);
  await recover(page); await expect(page.getByRole('status')).toContainText('this tab only');
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  await page.getByRole('button', { name: 'Recover', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('this tab only');
});

test('S2-02 disabled storage does not crash application shell', async ({ context }) => {
  await fixture(context);
  await context.addInitScript(() => { Storage.prototype.getItem = () => { throw new DOMException('storage denied', 'SecurityError'); }; });
  const page = await context.newPage(); await page.goto('/');
  await expect(page.getByRole('button', { name: 'Recover', exact: true })).toBeVisible();
});

test('BR-05 session-only warning remains during and after rejected second recovery', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  await page.evaluate(key => { const original = Storage.prototype.setItem; Storage.prototype.setItem = function(k, v) { if (k === key) throw new DOMException('quota', 'QuotaExceededError'); original.call(this, k, v); }; }, KEY);
  await recover(page); await expect(page.getByRole('status')).toContainText('this tab only');
  const metadata = deferred(); let parked = false;
  f.setHook(async (_r, c) => { if (c.path.includes('/recovery/')) { parked = true; await metadata.promise; } return false; });
  await api(page, 'window.testWallet.reject = true');
  await recover(page); await expect.poll(() => parked).toBe(true);
  const during = (await page.getByRole('status').allTextContents()).join(' ') || null;
  metadata.release(); await expect(page.getByRole('alert')).toContainText('Wallet refused');
  const after = (await page.getByRole('status').allTextContents()).join(' ') || null;
  expect({ during, after }).toEqual({ during: expect.stringContaining('this tab only'), after: expect.stringContaining('this tab only') });
  expect(f.posts()).toHaveLength(1);
  expect(await api(page, 'window.testClient.credentialStorage')).toBe('session');
});
