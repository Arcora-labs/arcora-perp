import { test, expect, type BrowserContext, type Page, type Route } from '@playwright/test';

// Synthetic HTTP and EIP-1193 fixtures. Browser uses real client code and native
// origin locks/storage; no RPC, extension wallet, or actual chain write occurs.
const OWNER = '0x' + '22'.repeat(32), OLD = '0x' + '11'.repeat(32), NEW = '0x' + '77'.repeat(32);
const ADDRESS = '0x' + '44'.repeat(20), VAULT = '0x57e951f6a378e00e4f1b26510380e089d7c07b8b';
const SCOPE = { base: 'http://127.0.0.1:4173', chainId: 84532, vault: VAULT };
const KEY = `darkperp.v2Account:${JSON.stringify([SCOPE.base, SCOPE.chainId, VAULT])}`;
const market = { id: 0, symbol: 'BTC/USDC', maxLeverage: 20, maintenanceMarginRatio: .05, initialMarginRatio: .1, referencePrice: '6450000000000', live: false, takerFeeBps: 8, makerRebateBps: 2 };
const state = { markets: [market, { ...market, id: 1, symbol: 'ETH/USDC' }], selectedMarketId: 0, market, mode: 'Normal', oracle: { marketId: 0, price: '6450000000000', confidence: '1', publishTimeMs: 0 }, book: { marketId: 0, bids: [], asks: [] }, marks: { 0: '6450000000000', 1: '350000000000' }, account: { settledBalance: '0', positions: [] }, orders: [], batches: [], insuranceFund: '0', treasury: '0', userAdlClawed: '0', lp: { tvl: '0', navPerShare: '1.000000', totalShares: '0', myShares: '0', myValue: '0' }, mmHedge: [], l1: null, attestation: null };
const barrier = () => { let release!: () => void; const promise = new Promise<void>(r => { release = r; }); return { promise, release }; };
const api = (page: Page, code: string) => page.evaluate(code);
async function fixture(context: BrowserContext) {
  const calls: { path: string; method: string; key?: string; body: any }[] = [];
  let generation = 0;
  let hook: ((route: Route, call: typeof calls[number]) => Promise<boolean>) | undefined;
  await context.addInitScript(({ KEY, OWNER, OLD, ADDRESS, SCOPE }) => {
    if (!localStorage.getItem(KEY)) localStorage.setItem(KEY, JSON.stringify({ ...SCOPE, schema: 2, owner: OWNER, apiKey: OLD, recoveryNonce: 0 }));
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    const control = { sends: [] as any[], signs: 0, hold: '', fail: '', parked: '', release: null as (() => void) | null, receiptStatus: '0x1' as string | null,
      emit(event: string) { for (const fn of listeners.get(event) ?? []) fn(); } };
    const pause = async (stage: string) => {
      if (control.hold === stage) { control.parked = stage; await new Promise<void>(r => { control.release = r; }); control.hold = ''; }
      if (control.fail === stage) throw new Error('RPC response lost after submission');
    };
    Object.assign(window, { depositWallet: control, ethereum: {
      on(event: string, fn: (...args: unknown[]) => void) { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event)!.add(fn); },
      removeListener(event: string, fn: (...args: unknown[]) => void) { listeners.get(event)?.delete(fn); },
      async request({ method, params }: { method: string; params?: unknown[] }) {
        if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [ADDRESS];
        if (method === 'eth_chainId') return '0x14a34';
        if (method === 'wallet_switchEthereumChain') return null;
        if (method === 'personal_sign') { control.signs++; await pause('signature'); return '0x' + 'ab'.repeat(65); }
        if (method === 'eth_sendTransaction') {
          const tx = params![0] as any; control.sends.push(tx);
          await pause(tx.data.startsWith('0x40c10f19') ? 'mint' : tx.data.startsWith('0x095ea7b3') ? 'approve' : 'deposit');
          return '0x' + control.sends.length.toString(16).padStart(64, '0');
        }
        if (method === 'eth_getTransactionReceipt') return control.receiptStatus === null ? null : { status: control.receiptStatus, transactionHash: params![0] };
        throw new Error('Unexpected wallet method: ' + method);
      },
    } });
  }, { KEY, OWNER, OLD, ADDRESS, SCOPE });
  await context.routeWebSocket(/\/ws$/, ws => {
    ws.onMessage(message => { if (JSON.parse(String(message)).type === 'auth') ws.send(JSON.stringify({ type: 'authOk', owner: OWNER })); });
  });
  await context.route(/\/(api|v1)\//, async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    const call = { path, method: request.method(), key: request.headers()['x-api-key'], body: request.postDataJSON() };
    calls.push(call); if (await hook?.(route, call)) return;
    let json: any = {}, status = 200;
    if (path === '/api/state') json = state;
    else if (path === '/v1/system/status') json = SCOPE;
    else if (path === '/v1/enclave/epoch') { json = { error: 'no enclave fixture' }; status = 503; }
    else if (path === '/v1/accounts/me') json = { ...SCOPE, owner: OWNER, recoveryNonce: call.key === NEW ? generation : 0, settledBalance: '123000000', depositAddress: ADDRESS, callerSigned: false, nextWithdrawNonce: 1 };
    else if (path === '/v1/orders') json = { orders: [] };
    else if (path === '/v1/positions') json = { positions: [] };
    else if (path.startsWith('/v1/accounts/recovery/')) json = { ...SCOPE, owner: OWNER, authorizer: ADDRESS, recoveryNonce: generation };
    else if (path === '/v1/accounts/recovery') { generation++; json = { owner: OWNER, apiKey: NEW, recoveryNonce: generation, durability: 'confirmed' }; }
    else if (path === '/v1/accounts/withdrawals') json = { withdrawals: [], vault: VAULT };
    else if (path === '/v1/accounts/deposit/authorize') json = { ownerCommit: OWNER, sig: '0x' + 'ab'.repeat(65) };
    else if (path === '/v1/accounts/deposit/onchain') json = { status: 'credited', durability: 'confirmed', purpose: 'collateral', marketId: call.body.marketId, depositIds: [0], credited: '1000000000', account: { ...SCOPE, owner: OWNER, recoveryNonce: call.key === NEW ? generation : 0 } };
    else if (path.includes('book')) json = { marketId: 1, bids: [], asks: [] };
    else if (path.includes('oracle')) json = { marketId: 1, price: '350000000000', confidence: '1', publishTimeMs: Date.now() };
    await route.fulfill({ status, json });
  });
  return { calls, setHook(value: typeof hook) { hook = value; } };
}
async function open(context: BrowserContext) {
  const page = await context.newPage(); await page.goto('/');
  await page.waitForFunction(() => !!(window as any).testClient);
  await page.getByRole('button', { name: 'Account', exact: true }).click();
  await page.locator('.walletflow').getByRole('button', { name: 'Connect wallet', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Deposit', exact: true })).toBeVisible();
  return page;
}
const start = (page: Page) => page.getByRole('button', { name: 'Deposit', exact: true }).click();
const error = (page: Page) => page.locator('.walletflow .notice--error');

test('DP-01 full synthetic wallet pipeline retains exact calldata and scoped HTTP intent', async ({ context }) => {
  const f = await fixture(context), page = await open(context); await start(page);
  await expect(page.locator('.walletflow .notice--ok')).toContainText('$1,000.00');
  const txs = await api(page, 'window.depositWallet.sends');
  expect(txs).toHaveLength(3);
  expect(txs.every((tx: any) => tx.chainId === '0x14a34')).toBe(true);
  expect(txs.map((t: any) => t.data.slice(0, 10))).toEqual(['0x40c10f19', '0x095ea7b3', '0x2b681307']);
  expect(txs[2].to.toLowerCase()).toBe(VAULT);
  const authorize = f.calls.find(c => c.path.endsWith('/deposit/authorize'))!;
  expect(authorize.key).toBe(OLD); expect(authorize.body).toEqual({ from: ADDRESS, amount: '1000000000', marketId: 0, purpose: 'collateral' });
  expect(f.calls.find(c => c.path.endsWith('/deposit/onchain'))!.body).toEqual({ marketId: 0, txHash: '0x' + '3'.padStart(64, '0') });
});

for (const stage of ['mint', 'approve', 'signature', 'deposit']) test(`DP-02 market changes during ${stage} prompt stop all subsequent mutation`, async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  await api(page, `window.depositWallet.hold = '${stage}'`); await start(page);
  await expect.poll(() => api(page, 'window.depositWallet.parked')).toBe(stage);
  const postsBefore = f.calls.filter(c => c.method === 'POST').length;
  await api(page, 'window.testClient.selectMarket(1); window.depositWallet.release()');
  await expect(error(page)).toContainText(/market changed/);
  expect(f.calls.filter(c => c.method === 'POST')).toHaveLength(postsBefore);
  expect(f.calls.some(c => c.path.endsWith('/deposit/onchain'))).toBe(false);
  await expect(page.locator('.walletflow .notice--ok')).toHaveCount(0);
});

test('DP-03 native two-tab lock and credential propagation stop pending bind signature', async ({ context }) => {
  const f = await fixture(context), a = await open(context), b = await open(context);
  await api(a, "window.depositWallet.hold = 'signature'"); await start(a);
  await expect.poll(() => api(a, 'window.depositWallet.parked')).toBe('signature');
  await b.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(error(b)).toContainText('another tab');
  expect(await api(b, 'window.depositWallet.sends.length')).toBe(0);
  await api(b, `window.testClient.recoverAccount('${OWNER}')`);
  await expect.poll(() => api(a, 'window.testClient.depositAccount().then(a => a.apiKey)')).toBe(NEW);
  await api(a, 'window.depositWallet.release()');
  await expect(error(a)).toContainText(/credential|account.*changed/i);
  expect(f.calls.some(c => c.path.endsWith('/deposit/address'))).toBe(false);
});

for (const endpoint of ['authorize', 'onchain']) test(`DP-04 delayed ${endpoint} reply cannot succeed after credential rotation`, async ({ context }) => {
  const f = await fixture(context), a = await open(context), b = await open(context), gate = barrier(); let parked = false;
  f.setHook(async (_route, call) => { if (call.path.endsWith('/deposit/' + endpoint)) { parked = true; await gate.promise; } return false; });
  await start(a); await expect.poll(() => parked).toBe(true);
  await api(b, `window.testClient.recoverAccount('${OWNER}')`);
  await expect.poll(() => api(a, 'window.testClient.depositAccount().then(a => a.apiKey)')).toBe(NEW);
  gate.release(); await expect(error(a)).toContainText(/credential|account.*changed/i);
  await expect(a.locator('.walletflow .notice--ok')).toHaveCount(0);
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(endpoint === 'authorize' ? 2 : 3);
});

test('DP-05 unknown wallet send survives reload and refuses duplicate transfer', async ({ context }) => {
  const f = await fixture(context), a = await open(context);
  await api(a, "window.depositWallet.fail = 'deposit'"); await start(a);
  await expect(error(a)).toContainText('outcome is unknown');
  await a.reload(); await a.waitForFunction(() => !!(window as any).testClient);
  await a.getByRole('button', { name: 'Account', exact: true }).click();
  await a.locator('.walletflow').getByRole('button', { name: 'Connect wallet', exact: true }).click();
  await expect(a.getByRole('region', { name: 'Original deposit recovery' })).toContainText('outcome is unknown');
  await expect(a.getByRole('button', { name: 'Deposit', exact: true })).toHaveCount(0);
  await expect(a.getByRole('button', { name: 'Check original transaction', exact: true })).toHaveCount(0);
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(0);
  expect(f.calls.some(c => c.path.endsWith('/deposit/onchain'))).toBe(false);
});

test('DP-06 unknown credit response resumes recorded transaction after reload', async ({ context }) => {
  const f = await fixture(context), a = await open(context); let once = true;
  f.setHook(async (route, call) => { if (call.path.endsWith('/deposit/onchain') && once) { once = false; await route.abort(); return true; } return false; });
  await start(a); await expect(error(a)).toBeVisible();
  await a.reload(); await a.waitForFunction(() => !!(window as any).testClient);
  await a.getByRole('button', { name: 'Account', exact: true }).click();
  await a.locator('.walletflow').getByRole('button', { name: 'Connect wallet', exact: true }).click();
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('Original deposit of $1,000.000000 is credited');
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(0);
  expect(f.calls.filter(c => c.path.endsWith('/deposit/authorize'))).toHaveLength(1);
  expect(f.calls.filter(c => c.path.endsWith('/deposit/onchain'))).toHaveLength(2);
});

for (const bad of ['missing', 'unknown', 'zero', 'wrongAmount']) test(`DP-07 ${bad} credit receipt retains journal and retries only original transaction`, async ({ context }) => {
  const f = await fixture(context), a = await open(context); let once = true;
  f.setHook(async (route, call) => {
    if (!call.path.endsWith('/deposit/onchain') || !once) return false;
    once = false;
    const good = { status: 'credited', durability: 'confirmed', purpose: 'collateral', marketId: 0, depositIds: [0], credited: '1000000000', account: { ...SCOPE, owner: OWNER, recoveryNonce: 0 } };
    const json = bad === 'missing' ? {} : bad === 'unknown' ? { ...good, status: 'unknown' } : { ...good, credited: bad === 'zero' ? '0' : '999999999' };
    await route.fulfill({ status: 200, json }); return true;
  });
  await start(a); await expect(error(a)).toContainText(/receipt/);
  await expect(a.locator('.walletflow .notice--ok')).toHaveCount(0);
  expect(await api(a, 'Object.keys(localStorage).filter(k => k.startsWith("darkperp.deposit.v1:")).length')).toBe(1);
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('Original deposit of $1,000.000000 is credited');
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(3);
  expect(f.calls.filter(c => c.path.endsWith('/deposit/authorize'))).toHaveLength(1);
  expect(f.calls.filter(c => c.path.endsWith('/deposit/onchain'))).toHaveLength(2);
});


test('DP-08 status-only reconciliation after same-owner credential rotation retains the original hash', async ({ context }) => {
  const f = await fixture(context), a = await open(context), b = await open(context); let once = true;
  f.setHook(async (route, call) => { if (call.path.endsWith('/deposit/onchain') && once) { once = false; await route.abort(); return true; } return false; });
  await start(a); await expect(error(a)).toBeVisible();
  const recovery = a.getByRole('region', { name: 'Original deposit recovery' });
  await expect(recovery).toContainText(ADDRESS); await expect(recovery).toContainText(OWNER);
  await expect(recovery).toContainText('Base Sepolia'); await expect(recovery).toContainText('$1,000.000000 USDC');
  const signs = await api(a, 'window.depositWallet.signs');
  await api(b, `window.testClient.recoverAccount('${OWNER}')`);
  await expect.poll(() => api(a, 'window.testClient.depositAccount().then(a => a.apiKey)')).toBe(NEW);
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('is credited');
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(3);
  expect(await api(a, 'window.depositWallet.signs')).toBe(signs);
  const credits = f.calls.filter(call => call.path.endsWith('/deposit/onchain'));
  expect(credits).toHaveLength(2); expect(credits[1].key).toBe(NEW);
  expect(credits[1].body.txHash).toBe(credits[0].body.txHash);
});

test('DP-09 original market must be restored before checking the recorded deposit', async ({ context }) => {
  const f = await fixture(context), a = await open(context); let once = true;
  f.setHook(async (route, call) => { if (call.path.endsWith('/deposit/onchain') && once) { once = false; await route.abort(); return true; } return false; });
  await start(a); await expect(error(a)).toBeVisible();
  await api(a, 'window.testClient.selectMarket(1)');
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('alert')).toContainText('original account and market #0');
  expect(f.calls.filter(call => call.path.endsWith('/deposit/onchain'))).toHaveLength(1);
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(3);
  await api(a, 'window.testClient.selectMarket(0)');
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('is credited');
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(3);
});

test('DP-10 pending and reverted status checks preserve the original operation without sends', async ({ context }) => {
  const f = await fixture(context), a = await open(context);
  f.setHook(async (route, call) => { if (call.path.endsWith('/deposit/onchain')) { await route.abort(); return true; } return false; });
  await start(a); await expect(error(a)).toBeVisible();
  await api(a, 'window.depositWallet.receiptStatus = null');
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('still pending');
  await api(a, 'window.depositWallet.receiptStatus = "0x0"');
  await a.getByRole('button', { name: 'Check original transaction', exact: true }).click();
  await expect(a.getByRole('status')).toContainText('reverted');
  expect(await api(a, 'window.depositWallet.sends.length')).toBe(3);
  expect(f.calls.filter(call => call.path.endsWith('/deposit/onchain'))).toHaveLength(1);
  await expect(a.getByRole('button', { name: 'Deposit', exact: true })).toHaveCount(0);
  expect(await api(a, 'Object.keys(localStorage).filter(k => k.startsWith("darkperp.deposit.v1:")).length')).toBe(1);
});
