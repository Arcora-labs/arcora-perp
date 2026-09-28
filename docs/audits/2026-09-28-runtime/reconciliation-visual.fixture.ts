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


test('temporary narrow recovery visual check', async ({ context }) => {
  const f = await fixture(context), page = await open(context);
  f.setHook(async (route, call) => { if (call.path.endsWith('/deposit/onchain')) { await route.abort(); return true; } return false; });
  await start(page); await expect(error(page)).toBeVisible();
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const panel = page.getByRole('region', { name: 'Original deposit recovery' });
    await panel.scrollIntoViewIfNeeded();
    await expect(panel).toBeVisible();
    const dimensions = await page.evaluate(() => ({ width: window.innerWidth, scrollWidth: document.documentElement.scrollWidth }));
    await page.screenshot({ path: `../docs/audits/2026-09-28-runtime/reconciliation-narrow-${width}.png`, fullPage: true });
    expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.width);
  }
});
