// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pendingDeposits, reconcileDeposit, runWalletDeposit } from "./depositFlow";
import { BASE_SEPOLIA_CHAIN_ID, COLLATERAL_VAULT, connect, disconnectWallet, type DepositContext, type WalletDepositClient } from "./wallet";
import { installTestLocks } from "../testSupport/locks";

const ADDRESS = "0x" + "ab".repeat(20), OWNER = "0x" + "22".repeat(32), SIG = "0x" + "ab".repeat(65);
const hash = (n: number) => "0x" + n.toString(16).padStart(64, "0");
const barrier = () => { let release!: () => void; const promise = new Promise<void>(r => { release = r; }); return { promise, release }; };

async function setup() {
  const calls: string[] = [], sendData: unknown[] = [], creditHashes: string[] = [];
  let version = 0, sendCount = 0;
  const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  const control = { hook: async (_stage: string) => {}, account: ADDRESS, chain: BASE_SEPOLIA_CHAIN_ID, receiptStatus: "0x1" as string | null };
  window.ethereum = {
    on(event, fn) { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event)!.add(fn); },
    removeListener(event, fn) { listeners.get(event)?.delete(fn); },
    async request({ method, params }) {
      if (method === "eth_requestAccounts" || method === "eth_accounts") return [control.account];
      if (method === "eth_chainId") return control.chain;
      if (method === "wallet_switchEthereumChain") { calls.push("chain"); await control.hook("chain"); return null; }
      if (method === "personal_sign") { calls.push("signature"); await control.hook("signature"); return SIG; }
      if (method === "eth_sendTransaction") {
        const n = ++sendCount;
        const stage = ["mint", "approve", "deposit"][n - 1] ?? "duplicate";
        calls.push(stage); sendData.push(params);
        await control.hook(stage);
        return hash(n);
      }
      if (method === "eth_getTransactionReceipt") {
        const stage = `receipt:${params![0]}`;
        calls.push(stage); await control.hook(stage); return control.receiptStatus === null ? null : { status: control.receiptStatus, transactionHash: params![0] };
      }
      throw new Error(`Unexpected wallet method ${method}`);
    },
  };
  const client: WalletDepositClient = {
    async captureDepositContext() {
      const captured = version;
      const context: DepositContext = Object.freeze({ base: "http://localhost", chainId: 84532, vault: COLLATERAL_VAULT,
        owner: OWNER, marketId: 0, recoveryNonce: captured,
        assertCurrent() { if (version !== captured) throw new Error("Deposit context changed"); } });
      await control.hook("capture");
      return context;
    },
    async depositAccount() { return { apiKey: "synthetic", owner: new Uint8Array(32).fill(0x22) }; },
    async bindDepositAddress(_address, _signature, ctx) { ctx!.assertCurrent(); calls.push("bind"); await control.hook("bind"); },
    async authorizeDeposit(_address, _amount, ctx) { ctx!.assertCurrent(); calls.push("authorize"); await control.hook("authorize"); return { ownerCommit: OWNER, sig: SIG }; },
    async creditOnchainDeposit(_hash, ctx) { ctx!.assertCurrent(); calls.push("credit"); creditHashes.push(_hash); await control.hook("credit"); return 1_000_000n; },
  };
  await connect();
  const run = () => runWalletDeposit({ client, address: ADDRESS, amount: 1_000_000n, assertView() {}, progress() {} });
  return { calls, sendData, creditHashes, control, client, run, rotate() { version++; }, emit(event: string) { for (const fn of listeners.get(event) ?? []) fn(); } };
}
beforeEach(() => { vi.stubGlobal("localStorage", new Storage()); installTestLocks(); });
afterEach(() => { disconnectWallet(); delete window.ethereum; localStorage.clear(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("deposit immutable context barriers", () => {
  for (const stage of ["capture", "chain", "mint", `receipt:${hash(1)}`, "approve", `receipt:${hash(2)}`, "signature", "bind", "authorize", "deposit", `receipt:${hash(3)}`, "credit"]) {
    it(`stops credential-generation change while ${stage} awaits`, async () => {
      const f = await setup(), gate = barrier(); let parked = false;
      f.control.hook = async s => { if (s === stage) { parked = true; await gate.promise; } };
      const result = f.run().then(() => "success", e => e.message);
      await vi.waitFor(() => expect(parked).toBe(true));
      const callsBefore = [...f.calls];
      f.rotate(); gate.release();
      expect(await result).toMatch(/context changed/);
      expect(f.calls).toEqual(callsBefore); // no later wallet prompt, POST, or success
    });
  }
  for (const event of ["accountsChanged", "chainChanged", "disconnect"]) {
    it(`invalidates transient ${event} during bind signature even when current RPC values are unchanged`, async () => {
      const f = await setup(), gate = barrier(); let parked = false;
      f.control.hook = async s => { if (s === "signature") { parked = true; await gate.promise; } };
      const result = f.run().catch(e => e.message);
      await vi.waitFor(() => expect(parked).toBe(true)); f.emit(event); gate.release();
      expect(await result).toMatch(/Wallet context changed/);
      expect(f.calls).not.toContain("bind");
    });
  }
  it("checks account and chain RPC values even without provider events", async () => {
    const f = await setup();
    f.control.hook = async stage => { if (stage === "signature") f.control.account = "0x" + "33".repeat(20); };
    await expect(f.run()).rejects.toThrow(/Wallet account or network changed/);
    expect(f.calls).not.toContain("bind");
  });
  it("rejects deployment mismatch before any wallet transaction", async () => {
    const f = await setup(), original = f.client.captureDepositContext;
    f.client.captureDepositContext = async () => ({ ...await original(), vault: "0x" + "99".repeat(20) });
    await expect(f.run()).rejects.toThrow(/deployment does not match/);
    expect(f.calls).toEqual([]);
  });
});

describe("deposit durable ambiguity and native lock boundary", () => {
  for (const step of ["mint", "approve", "deposit"]) {
    it(`blocks a duplicate ${step} after a send loses its response, including a fresh run`, async () => {
      const f = await setup();
      f.control.hook = async stage => { if (stage === step) throw new Error("RPC disconnected after submission"); };
      await expect(f.run()).rejects.toThrow(/outcome is unknown/);
      const before = [...f.calls]; f.control.hook = async () => {};
      await expect(f.run()).rejects.toThrow(/outcome is unknown/);
      expect(f.calls).toEqual(before);
      const journal = localStorage.getItem(Object.keys(localStorage)[0])!;
      expect(JSON.parse(journal).sending).toBe(step);
      expect(journal).not.toContain(SIG);
      expect(journal).not.toContain("apiKey");
    });
  }
  it("native lock prevents a competing run before it opens another wallet prompt", async () => {
    const f = await setup(), gate = barrier(); let parked = false;
    f.control.hook = async stage => { if (stage === "mint") { parked = true; await gate.promise; } };
    const first = f.run(); await vi.waitFor(() => expect(parked).toBe(true));
    await expect(f.run()).rejects.toThrow(/another tab/);
    expect(f.calls.filter(s => s === "mint")).toHaveLength(1);
    gate.release(); await expect(first).resolves.toBe(1_000_000n);
  });
  it("persists a known deposit hash even when credentials change before the wallet returns", async () => {
    const f = await setup(); f.control.hook = async stage => { if (stage === "deposit") f.rotate(); };
    await expect(f.run()).rejects.toThrow(/context changed/);
    const journal = JSON.parse(localStorage.getItem(Object.keys(localStorage)[0])!);
    expect(journal.txs.deposit).toBe(hash(3)); expect(journal.sending).toBeNull();
    await expect(f.run()).rejects.toThrow(/another account, market or credential generation/);
    expect(f.calls.filter(s => s === "deposit")).toHaveLength(1);
  });
  it("resumes the same deposit after unknown credit outcome without new authorization or transfer", async () => {
    const f = await setup(); let once = true;
    f.control.hook = async stage => { if (stage === "credit" && once) { once = false; throw new Error("credit response lost"); } };
    await expect(f.run()).rejects.toThrow(/response lost/);
    await expect(f.run()).resolves.toBe(1_000_000n);
    expect(f.calls.filter(s => s === "deposit")).toHaveLength(1);
    expect(f.calls.filter(s => s === "authorize")).toHaveLength(1);
    expect(f.calls.filter(s => s === "credit")).toHaveLength(2);
  });
  it("fails closed when progress cannot be durably saved", async () => {
    const f = await setup(); vi.spyOn(localStorage, "setItem").mockImplementation(() => { throw new Error("storage full"); });
    await expect(f.run()).rejects.toThrow(/storage full/);
    expect(f.sendData).toHaveLength(0);
  });
  it("fails closed without origin-wide locking", async () => {
    const f = await setup(); Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
    await expect(f.run()).rejects.toThrow(/Web Locks/); expect(f.calls).toEqual([]);
  });
});


describe("deposit journal intent identity", () => {
  it("normalizes Ethereum address casing for the origin lock", async () => {
    const f = await setup(), gate = barrier(); let parked = false;
    f.control.hook = async stage => { if (stage === "mint") { parked = true; await gate.promise; } };
    const first = f.run(); await vi.waitFor(() => expect(parked).toBe(true));
    const upper = ADDRESS.slice(0, 2) + ADDRESS.slice(2).toUpperCase();
    await expect(runWalletDeposit({ client: f.client, address: upper, amount: 1_000_000n, assertView() {}, progress() {} })).rejects.toThrow(/another tab/);
    gate.release(); await first;
    expect(f.sendData).toHaveLength(3);
  });
  it("allows a new credential context after explicit mint rejection with no hash", async () => {
    const f = await setup(); let reject = true;
    f.control.hook = async stage => { if (stage === "mint" && reject) { reject = false; throw { code: 4001 }; } };
    await expect(f.run()).rejects.toThrow(/rejected/);
    f.rotate();
    await expect(f.run()).resolves.toBe(1_000_000n);
    expect(f.calls.filter(s => s === "credit")).toHaveLength(1);
  });
});


describe("deposit receipt amount gate", () => {
  for (const badAmount of [0n, -1n, 999_999n, 1_000_001n]) {
    it(`retains the original transaction for invalid credited amount ${badAmount}`, async () => {
      const f = await setup(), credit = f.client.creditOnchainDeposit;
      f.client.creditOnchainDeposit = async () => badAmount;
      await expect(f.run()).rejects.toThrow(/does not match the original amount/);
      const journal = JSON.parse(localStorage.getItem(Object.keys(localStorage)[0])!);
      expect(journal.txs.deposit).toBe(hash(3));
      expect(journal.done).not.toContain("credit");
      f.client.creditOnchainDeposit = credit;
      await expect(f.run()).resolves.toBe(1_000_000n);
      expect(f.sendData).toHaveLength(3);
      expect(f.calls.filter(call => call === "authorize")).toHaveLength(1);
    });
  }
});


async function pendingFixture() {
  const f = await setup(), credit = f.client.creditOnchainDeposit;
  f.client.creditOnchainDeposit = async () => { throw new Error("credit pending"); };
  await expect(f.run()).rejects.toThrow(/credit pending/);
  f.client.creditOnchainDeposit = credit;
  return { ...f, pending: pendingDeposits()[0] };
}

describe("known-hash status-only reconciliation", () => {
  it("reloads exact original identity and checks credit without another send, signature or network switch", async () => {
    const f = await pendingFixture();
    expect(f.pending).toMatchObject({ wallet: ADDRESS, chainId: 84532, owner: OWNER, marketId: 0, amount: 1_000_000n, step: "deposit", hash: hash(3), unknownSend: false });
    const before = f.calls.filter(call => ["chain", "signature", "mint", "approve", "deposit", "authorize"].includes(call));
    await expect(reconcileDeposit(f.client, f.pending, () => {})).resolves.toMatchObject({ status: "credited", hash: hash(3) });
    expect(f.calls.filter(call => ["chain", "signature", "mint", "approve", "deposit", "authorize"].includes(call))).toEqual(before);
    expect(f.creditHashes).toEqual([hash(3)]); expect(pendingDeposits()).toEqual([]);
  });
  it("uses a freshly captured credential after same-owner rotation but only queries the original hash", async () => {
    const f = await pendingFixture(); f.rotate();
    await expect(reconcileDeposit(f.client, f.pending, () => {})).resolves.toMatchObject({ status: "credited" });
    expect(f.sendData).toHaveLength(3); expect(f.creditHashes).toEqual([hash(3)]);
  });
  for (const mismatch of [{ owner: "0x" + "99".repeat(32) }, { marketId: 1 }, { base: "http://other.test" }, { chainId: 999 }, { vault: "0x" + "99".repeat(20) }]) {
    it(`refuses changed original context ${JSON.stringify(mismatch)} before any RPC/credit request`, async () => {
      const f = await pendingFixture(), capture = f.client.captureDepositContext;
      f.client.captureDepositContext = async () => ({ ...await capture(), ...mismatch });
      const before = [...f.calls];
      await expect(reconcileDeposit(f.client, f.pending, () => {})).rejects.toThrow(/original account and market/);
      expect(f.calls).toEqual(before); expect(pendingDeposits()).toHaveLength(1);
    });
  }
  for (const status of [null, "0x0"]) {
    it(`preserves pending/reverted receipt ${status} without requesting credit`, async () => {
      const f = await pendingFixture(); f.control.receiptStatus = status;
      await expect(reconcileDeposit(f.client, f.pending, () => {})).resolves.toMatchObject({ status: status === null ? "pending" : "reverted" });
      expect(f.creditHashes).toEqual([]); expect(pendingDeposits()).toHaveLength(1); expect(f.sendData).toHaveLength(3);
    });
  }
  for (const stage of [`receipt:${hash(3)}`, "credit"]) {
    it(`cannot apply a stale reconciliation result after rotation during ${stage}`, async () => {
      const f = await pendingFixture(), gate = barrier(); let parked = false;
      f.control.hook = async current => { if (current === stage) { parked = true; await gate.promise; } };
      const result = reconcileDeposit(f.client, f.pending, () => {}).catch(e => e.message);
      await vi.waitFor(() => expect(parked).toBe(true)); f.rotate(); gate.release();
      expect(await result).toMatch(/context changed/); expect(pendingDeposits()).toHaveLength(1); expect(f.sendData).toHaveLength(3);
      if (stage.startsWith("receipt")) expect(f.creditHashes).toEqual([]);
    });
  }
  it("uses only the stored hash even if a caller alters the displayed copy", async () => {
    const f = await pendingFixture();
    await expect(reconcileDeposit(f.client, { ...f.pending, hash: hash(99), amount: 1n }, () => {})).resolves.toMatchObject({ hash: hash(3), status: "credited" });
    expect(f.creditHashes).toEqual([hash(3)]);
  });
  it("rejects a receipt for another hash and retains the original operation", async () => {
    const f = await pendingFixture(), request = window.ethereum!.request;
    window.ethereum!.request = async args => args.method === "eth_getTransactionReceipt" ? { status: "0x1", transactionHash: hash(99) } : request(args);
    await expect(reconcileDeposit(f.client, f.pending, () => {})).rejects.toThrow(/another transaction/);
    expect(f.creditHashes).toEqual([]); expect(pendingDeposits()).toHaveLength(1);
  });
  it("refuses an unknown send without a hash before account capture or wallet RPC", async () => {
    const f = await setup(); f.control.hook = async step => { if (step === "deposit") throw new Error("lost response"); };
    await expect(f.run()).rejects.toThrow(/unknown/);
    const before = [...f.calls], capture = vi.spyOn(f.client, "captureDepositContext");
    const pending = pendingDeposits()[0]; expect(pending.unknownSend).toBe(true); expect(pending.hash).toBeNull();
    await expect(reconcileDeposit(f.client, pending, () => {})).rejects.toThrow(/did not return/);
    expect(capture).not.toHaveBeenCalled(); expect(f.calls).toEqual(before);
  });
  it("refuses a stale displayed revision while preserving the newer stored operation", async () => {
    const f = await pendingFixture();
    const journal = JSON.parse(localStorage.getItem(f.pending.id)!); journal.recoveryNonce++;
    localStorage.setItem(f.pending.id, JSON.stringify(journal));
    await expect(reconcileDeposit(f.client, f.pending, () => {})).rejects.toThrow(/progress changed/);
    expect(pendingDeposits()[0].recoveryNonce).toBe(1); expect(f.creditHashes).toEqual([]);
  });
});


describe("explicit resume identity and corrupt journals", () => {
  for (const mismatch of [{ base: "http://other.test" }, { chainId: 999 }, { vault: "0x" + "99".repeat(20) }, { owner: "0x" + "99".repeat(32) }, { marketId: 1 }]) {
    it(`never starts a fresh transfer when resuming from another context ${JSON.stringify(mismatch)}`, async () => {
      const f = await setup(); f.control.hook = async step => { if (step === "signature") throw { code: 4001 }; };
      await expect(f.run()).rejects.toThrow();
      const original = pendingDeposits()[0], capture = f.client.captureDepositContext;
      f.client.captureDepositContext = async () => ({ ...await capture(), ...mismatch });
      const before = [...f.calls];
      await expect(runWalletDeposit({ client: f.client, address: ADDRESS, amount: original.amount, resume: original, assertView() {}, progress() {} })).rejects.toThrow(/deployment|another|changed/);
      expect(f.calls).toEqual(before); expect(pendingDeposits()).toHaveLength(1); expect(f.sendData).toHaveLength(2);
    });
  }
  for (const txs of [{}, [], null]) {
    it(`refuses a completed deposit without a hash in malformed txs ${JSON.stringify(txs)}`, async () => {
      const f = await pendingFixture();
      const journal = JSON.parse(localStorage.getItem(f.pending.id)!);
      localStorage.setItem(f.pending.id, JSON.stringify({ ...journal, txs, done: ["chain", "mint", "approve", "bind", "authorize", "deposit"] }));
      const before = [...f.calls];
      await expect(f.run()).rejects.toThrow(/malformed/);
      expect(() => pendingDeposits()).toThrow(/malformed/); expect(f.calls).toEqual(before);
    });
  }
  it("requires an exact receipt hash, including refusing a missing hash", async () => {
    const f = await pendingFixture(), request = window.ethereum!.request;
    window.ethereum!.request = async args => args.method === "eth_getTransactionReceipt" ? { status: "0x1" } : request(args);
    await expect(reconcileDeposit(f.client, f.pending, () => {})).rejects.toThrow(/another transaction/);
    expect(f.creditHashes).toEqual([]); expect(pendingDeposits()).toHaveLength(1);
  });
});
