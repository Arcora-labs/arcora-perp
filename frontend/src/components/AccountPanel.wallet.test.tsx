// @vitest-environment happy-dom
//
// WalletDepositCard / claim-with-wallet flows against a scripted EIP-1193
// provider and a fake gateway client: happy-path pipeline order + payloads,
// user rejection, recovery (re-run skips completed steps — but always re-runs
// the chain ensure, and resumes recorded tx hashes instead of re-sending),
// bind memoization, and mock-mode hiding.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor } from "@testing-library/react";
import { bytesToHex } from "@noble/hashes/utils";
import { StoreProvider } from "../store";
import {
  AccountPanel,
  WalletDepositCard,
  WithdrawalsSection,
} from "./AccountPanel";
import {
  BASE_SEPOLIA_CHAIN_ID,
  COLLATERAL_VAULT,
  MOCK_USDC,
  bindDepositDigest,
  connect,
  disconnectWallet,
  encodeClaim,
  type Eip1193Provider,
} from "../api/wallet";
import type { DarkPerpClient } from "../api/client";
import type { WithdrawalEntry } from "../domain/types";
import { installTestLocks } from "../testSupport/locks";
beforeEach(installTestLocks);

const ADDR = "0xAbCdEF0123456789AbCdEF0123456789AbCdEF01";
const addr = ADDR.toLowerCase();
const OWNER = new Uint8Array(32).fill(0x11);
const SIG = "0x" + "ab".repeat(65);
const COMMIT = "0x" + "ab".repeat(32); // gateway-issued blinded ownerCommit (fake)
const GWSIG = "0x" + "cd".repeat(65); // gateway 65-byte authorization sig (fake)

interface Call {
  method: string;
  params?: unknown[];
}

/// A scripted EIP-1193 provider: records every call, answers the pipeline's
/// methods, and lets a test override any method (e.g. to inject a rejection).
function makeProvider(
  overrides: Partial<Record<string, (call: Call, calls: Call[]) => unknown>> = {},
) {
  const calls: Call[] = [];
  let txCount = 0;
  const provider: Eip1193Provider = {
    async request({ method, params }) {
      const call: Call = { method, params };
      calls.push(call);
      const o = overrides[method];
      if (o) return o(call, calls);
      switch (method) {
        case "eth_chainId": return BASE_SEPOLIA_CHAIN_ID;
        case "eth_accounts":
        case "eth_requestAccounts":
          return [ADDR];
        case "wallet_switchEthereumChain":
          return null;
        case "eth_sendTransaction":
          txCount += 1;
          return "0x" + txCount.toString(16).padStart(64, "0");
        case "eth_getTransactionReceipt":
          return { status: "0x1", transactionHash: params?.[0] };
        case "personal_sign":
          return SIG;
        default:
          throw new Error(`unexpected provider method ${method}`);
      }
    },
  };
  const sent = () => calls.filter((c) => c.method === "eth_sendTransaction");
  const signs = () => calls.filter((c) => c.method === "personal_sign");
  const switches = () => calls.filter((c) => c.method === "wallet_switchEthereumChain");
  return { provider, calls, sent, signs, switches };
}

function install(provider: Eip1193Provider) {
  (window as unknown as { ethereum?: Eip1193Provider }).ethereum = provider;
}

/// A fake gateway client implementing only the wallet-deposit surface.
function makeClient() {
  const bindCalls: [string, string][] = [];
  const authorizeCalls: [string, bigint][] = [];
  const creditCalls: string[] = [];
  const client = {
    captureDepositContext: async () => ({ owner: "0x" + bytesToHex(OWNER), base: "http://localhost", chainId: 84532, vault: COLLATERAL_VAULT, marketId: 0, recoveryNonce: 0, assertCurrent() {} }),
    depositAccount: async () => ({ apiKey: "0x" + "aa".repeat(32), owner: OWNER }),
    bindDepositAddress: async (a: string, s: string) => {
      bindCalls.push([a, s]);
    },
    authorizeDeposit: async (from: string, amount: bigint) => {
      authorizeCalls.push([from, amount]);
      return { ownerCommit: COMMIT, sig: GWSIG };
    },
    creditOnchainDeposit: async (txHash: string) => {
      creditCalls.push(txHash);
      return authorizeCalls[authorizeCalls.length - 1]?.[1] ?? 1_000_000_000n;
    },
  };
  return { client, bindCalls, authorizeCalls, creditCalls };
}

function txField(call: Call, field: "to" | "data" | "from"): string {
  return (call.params?.[0] as Record<string, string>)[field];
}

afterEach(() => {
  cleanup();
  disconnectWallet();
  delete (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("WalletDepositCard", () => {
  it("shows the no-wallet notice (CLI quickstart link) when nothing is injected", () => {
    const { client } = makeClient();
    render(<WalletDepositCard client={client} />);
    expect(screen.getByText(/No browser wallet detected/i)).toBeTruthy();
    const quickstart = screen.getByRole("link", { name: /quickstart/i });
    expect(quickstart.getAttribute("href")).toContain("docs.arcoralabs.xyz");
    expect(screen.queryByRole("button", { name: /connect wallet/i })).toBeNull();
  });

  it("happy path: connect → deposit runs the 7-step pipeline in order", async () => {
    const p = makeProvider();
    install(p.provider);
    const { client, bindCalls, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    expect(await screen.findByText(/0xabcd…ef01/)).toBeTruthy(); // short address shown

    // default amount 1000 → 1_000_000_000 base units (6 dp)
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/credited to your trading account/i)).toBeTruthy();
    expect(screen.getByText(/\$1,000\.00/)).toBeTruthy();

    // [1] chain ensured
    expect(p.switches().length).toBe(1);

    // [2..3] mint → approve, correct targets + calldata
    const txs = p.sent();
    expect(txs.length).toBe(3);
    expect(txField(txs[0], "to")).toBe(MOCK_USDC);
    expect(txField(txs[0], "data").startsWith("0x40c10f19")).toBe(true);
    expect(txField(txs[0], "data")).toContain(addr.slice(2)); // mint to self
    expect(txField(txs[1], "to")).toBe(MOCK_USDC);
    expect(txField(txs[1], "data").startsWith("0x095ea7b3")).toBe(true);
    expect(txField(txs[1], "data")).toContain(COLLATERAL_VAULT.slice(2).toLowerCase());

    // [4] bind BEFORE the deposit: personal_sign over the exact bind digest, POSTed
    const signs = p.signs();
    expect(signs.length).toBe(1);
    expect(signs[0].params).toEqual(["0x" + bytesToHex(bindDepositDigest(OWNER, addr)), addr]);
    expect(bindCalls).toEqual([[addr, SIG]]);
    expect(Object.keys(localStorage).some(key => key.startsWith("darkperp.deposit.v1:"))).toBe(false);

    // [5] SEC-019 authorization for the exact (from, amount)
    expect(authorizeCalls).toEqual([[addr, 1_000_000_000n]]);

    // [6] deposit tx carries the NEW calldata: selector + the gateway ownerCommit
    expect(txField(txs[2], "to")).toBe(COLLATERAL_VAULT);
    expect(txField(txs[2], "data").startsWith("0x2b681307")).toBe(true);
    expect(txField(txs[2], "data")).toContain(COMMIT.slice(2));
    for (const t of txs) {
      expect(txField(t, "from")).toBe(addr);
      expect((t.params![0] as Record<string, string>).chainId).toBe(BASE_SEPOLIA_CHAIN_ID);
    }

    // [7] credit with the DEPOSIT tx hash (the 3rd fake hash the provider issued)
    expect(creditCalls).toEqual(["0x" + (3).toString(16).padStart(64, "0")]);
  });

  it("does not trust an unscoped legacy binding cache", async () => {
    const p = makeProvider();
    install(p.provider);
    const { client, bindCalls } = makeClient();
    localStorage.setItem(`darkperp.walletBound.${bytesToHex(OWNER)}.${addr}`, "1");
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    await screen.findByText(/credited to your trading account/i);

    expect(p.signs().length).toBe(1);
    expect(bindCalls.length).toBe(1);
  });

  it("surfaces a readable error when the user rejects the connection", async () => {
    const p = makeProvider({
      eth_requestAccounts: () => {
        throw { code: 4001, message: "User rejected the request." };
      },
    });
    install(p.provider);
    const { client } = makeClient();
    render(<WalletDepositCard client={client} />);
    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    expect(await screen.findByText(/rejected in the wallet/i)).toBeTruthy();
  });

  it("rejects an invalid amount without touching the wallet", async () => {
    const p = makeProvider();
    install(p.provider);
    const { client } = makeClient();
    render(<WalletDepositCard client={client} />);
    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);
    fireEvent.change(screen.getByLabelText(/deposit amount/i), { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/valid amount/i)).toBeTruthy();
    expect(p.switches().length).toBe(0);
    expect(p.sent().length).toBe(0);
  });

  it("recovers after a mid-pipeline rejection: re-run skips completed steps", async () => {
    let rejectNextSend = true;
    const p = makeProvider({
      eth_sendTransaction: (_call, calls) => {
        if (rejectNextSend) {
          rejectNextSend = false;
          throw { code: 4001 };
        }
        // default behavior: sequential fake hashes
        const n = calls.filter((c) => c.method === "eth_sendTransaction").length;
        return "0x" + n.toString(16).padStart(64, "0");
      },
    });
    install(p.provider);
    const { client, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt: the MINT tx is rejected → readable error, chain step done.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/Transaction rejected in the wallet/i)).toBeTruthy();
    expect(p.switches().length).toBe(1);

    // Second attempt succeeds — the chain step re-runs (it is NEVER skipped:
    // the user may have manually switched networks between attempts).
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/credited to your trading account/i)).toBeTruthy();
    expect(p.switches().length).toBe(2);
    // sends: rejected-mint attempt + mint + approve + deposit = 4 calls,
    // deposit hash = 4th successful-numbering (call count based)
    expect(creditCalls.length).toBe(1);
  });

  it("re-authorizes on a re-run when the deposit tx was never sent (sig binds the amount)", async () => {
    let rejectDeposit = true;
    const p = makeProvider({
      eth_sendTransaction: (_call, calls) => {
        const n = calls.filter((c) => c.method === "eth_sendTransaction").length;
        if (n === 3 && rejectDeposit) {
          rejectDeposit = false; // reject only the FIRST deposit attempt
          throw { code: 4001 };
        }
        return "0x" + n.toString(16).padStart(64, "0");
      },
    });
    install(p.provider);
    const { client, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt: mint + approve land, bind + authorize succeed, the DEPOSIT
    // send is rejected — no hash recorded.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/Transaction rejected in the wallet/i)).toBeTruthy();
    expect(authorizeCalls.length).toBe(1);

    // Re-run: mint/approve/bind are skipped (done) but authorize runs AGAIN —
    // a fresh gateway sig for the re-sent deposit.
    fireEvent.click(screen.getByRole("button", { name: /resume original deposit/i }));
    expect(await screen.findByText(/credited to your trading account/i)).toBeTruthy();
    expect(authorizeCalls.length).toBe(2);
    expect(p.sent().length).toBe(4); // mint, approve, rejected deposit, re-sent deposit
    expect(creditCalls).toEqual(["0x" + (4).toString(16).padStart(64, "0")]);
  });

  it("retains the original amount when prerequisite transactions were already sent", async () => {
    let rejectDeposit = true;
    const p = makeProvider({
      eth_sendTransaction: (_call, calls) => {
        const n = calls.filter((c) => c.method === "eth_sendTransaction").length;
        if (n === 3 && rejectDeposit) {
          rejectDeposit = false; // reject only the FIRST deposit attempt
          throw { code: 4001 };
        }
        return "0x" + n.toString(16).padStart(64, "0");
      },
    });
    install(p.provider);
    const { client, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt at 1000 USDC: deposit send rejected, NO hash recorded.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    await screen.findByText(/Transaction rejected in the wallet/i);
    expect(authorizeCalls).toEqual([[addr, 1_000_000_000n]]);

    // The displayed amount remains pinned to the original saved intent.
    fireEvent.change(screen.getByLabelText(/deposit amount/i), { target: { value: "500" } });
    fireEvent.click(screen.getByRole("button", { name: /resume original deposit/i }));
    await screen.findByText(/credited to your trading account/i);

    // Resume keeps the original mint/approval and re-authorizes its exact amount.
    expect(authorizeCalls.length).toBe(2);
    expect(authorizeCalls[1]).toEqual([addr, 1_000_000_000n]);
    expect(p.sent().length).toBe(4);
    expect(creditCalls).toEqual(["0x" + (4).toString(16).padStart(64, "0")]);
  });

  it("re-invokes ensureBaseSepolia on a re-run after a chain-step error (never skipped)", async () => {
    let rejectSwitch = true;
    const p = makeProvider({
      wallet_switchEthereumChain: () => {
        if (rejectSwitch) {
          rejectSwitch = false;
          throw { code: 4001 };
        }
        return null;
      },
    });
    install(p.provider);
    const { client, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt: the network switch is rejected → nothing sent on-chain.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/Network switch rejected in the wallet/i)).toBeTruthy();
    expect(p.switches().length).toBe(1);
    expect(p.sent().length).toBe(0);

    // Re-run: ensureBaseSepolia is invoked AGAIN and the pipeline completes.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/credited to your trading account/i)).toBeTruthy();
    expect(p.switches().length).toBe(2);
    expect(creditCalls.length).toBe(1);
  });

  it("resumes a timed-out deposit wait on the SAME tx hash instead of re-sending", async () => {
    // Hashes are sequential: mint=1, approve=2, deposit=3.
    const DEPOSIT_HASH = "0x" + (3).toString(16).padStart(64, "0");
    let failDepositReceipt = true;
    const p = makeProvider({
      eth_getTransactionReceipt: (call) => {
        const [hash] = call.params as [string];
        if (hash === DEPOSIT_HASH && failDepositReceipt) {
          failDepositReceipt = false; // one RPC hiccup while waiting for the deposit
          throw new Error("rpc hiccup");
        }
        return { status: "0x1", transactionHash: call.params?.[0] };
      },
    });
    install(p.provider);
    const { client, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt: the deposit tx is SENT (hash recorded) but the wait fails.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/Could not read the transaction receipt/i)).toBeTruthy();
    expect(p.sent().length).toBe(3); // mint + approve + deposit all sent

    // Re-run: NO second deposit tx — the runner resumes waitForTx on the
    // recorded hash, and the credit is keyed to that same confirmed hash.
    fireEvent.click(screen.getByRole("button", { name: /check original transaction/i }));
    expect(await screen.findByText(/Original deposit.*is credited/i)).toBeTruthy();
    expect(p.sent().length).toBe(3); // still 3 — sendTx was NOT called again
    const depositPolls = p.calls.filter(
      (c) => c.method === "eth_getTransactionReceipt" && c.params?.[0] === DEPOSIT_HASH,
    );
    expect(depositPolls.length).toBe(2); // failed wait + resumed wait, same hash
    expect(creditCalls).toEqual([DEPOSIT_HASH]);
    // The recorded hash also means authorize is NOT re-run — the on-chain sig
    // was already consumed by the sent tx; only the wait + credit resume.
    expect(authorizeCalls.length).toBe(1);
  });
});

describe("deposit form intent", () => {
  it("rejects a programmatic amount change while bind signature is pending", async () => {
    let release!: (signature: string) => void;
    const p = makeProvider({ personal_sign: () => new Promise<string>(resolve => { release = resolve; }) });
    install(p.provider);
    const { client, bindCalls, authorizeCalls } = makeClient();
    render(<WalletDepositCard client={client} />);
    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    await waitFor(() => expect(p.signs()).toHaveLength(1));
    fireEvent.change(screen.getByLabelText(/deposit amount/i), { target: { value: "500" } });
    release(SIG);
    await screen.findByText(/form or wallet context changed/i);
    expect(bindCalls).toHaveLength(0); expect(authorizeCalls).toHaveLength(0);
    expect(p.sent()).toHaveLength(2);
  });
});

describe("WithdrawalsSection claim-with-wallet", () => {
  const entry: WithdrawalEntry = {
    to: "0x" + "11".repeat(20),
    amount: 100_000_000n,
    nonce: 3,
    leaf: "0x" + "aa".repeat(32),
    root: "0x" + "bb".repeat(32),
    claimable: true,
    proof: ["0x" + "cc".repeat(32), "0x" + "dd".repeat(32)],
  };
  const listClient = {
    listWithdrawals: async () => ({ withdrawals: [entry], vault: COLLATERAL_VAULT }),
  } as unknown as DarkPerpClient;

  it("sends the encoded claim from the connected wallet and shows the tx", async () => {
    const p = makeProvider();
    install(p.provider);
    await connect(); // wallet connected before the section renders

    render(<WithdrawalsSection client={listClient} />);
    expect(await screen.findByText(/^Claimable$/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /claim with wallet/i }));
    expect(await screen.findByText(/Claimed ✓/)).toBeTruthy();

    const txs = p.sent();
    expect(txs.length).toBe(1);
    expect(txField(txs[0], "to")).toBe(COLLATERAL_VAULT);
    expect(txField(txs[0], "data")).toBe(encodeClaim(entry)); // byte-exact (pinned in wallet.test.ts)
    expect(txField(txs[0], "data").startsWith("0xe1b656ae")).toBe(true);
    expect(txField(txs[0], "from")).toBe(addr);

    // The cast fallback stays available.
    expect(screen.getByRole("button", { name: /copy claim command/i })).toBeTruthy();
  });

  it("hides the wallet claim button when no wallet is connected", async () => {
    render(<WithdrawalsSection client={listClient} />);
    expect(await screen.findByText(/^Claimable$/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /claim with wallet/i })).toBeNull();
    expect(screen.getByRole("button", { name: /copy claim command/i })).toBeTruthy();
  });
});

describe("mock mode", () => {
  it("hides ALL wallet UI (even with a wallet injected) and keeps the demo deposit", async () => {
    const p = makeProvider();
    install(p.provider); // wallet present — but the mock client can't use it
    render(
      <StoreProvider>
        <AccountPanel />
      </StoreProvider>,
    );
    await screen.findByText(/settled balance/i);
    expect(screen.queryByRole("button", { name: /connect wallet/i })).toBeNull();
    expect(screen.queryByText(/No browser wallet detected/i)).toBeNull();
    // The demo deposit path stays for the in-browser mock.
    expect(screen.getByRole("button", { name: /^deposit$/i })).toBeTruthy();
    await waitFor(() => expect(p.calls.length).toBe(0));
  });
});
