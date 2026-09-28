// @vitest-environment happy-dom
//
// Injected-wallet module tests: the ABI encodings are pinned byte-exact against
// independently computed calldata (keccak selectors recomputed here, never
// trusted from memory), the gateway bind digest against an in-test keccak of
// the documented preimage, and the EIP-1193 flows against a scripted provider.

import { describe, it, expect, afterEach, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, utf8ToBytes, concatBytes } from "@noble/hashes/utils";
import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_PARAMS,
  COLLATERAL_VAULT,
  bindDepositDigest,
  connect,
  connectedAddress,
  disconnectWallet,
  encodeAddress,
  encodeApprove,
  encodeBytes32,
  encodeClaim,
  encodeDeposit,
  encodeMint,
  encodeUint256,
  ensureBaseSepolia,
  hasInjected,
  personalSign,
  selectorHex,
  sendTx,
  supportsWalletDeposit,
  verifyFinalizedRevertedTransaction,
  waitForTx,
  type Eip1193Provider,
} from "./wallet";

const ADDR = "0xAbCdEF0123456789AbCdEF0123456789AbCdEF01";
const TX = "0x" + "12".repeat(32);

function install(provider: Eip1193Provider) {
  (window as unknown as { ethereum?: Eip1193Provider }).ethereum = provider;
}

afterEach(() => {
  disconnectWallet();
  delete (window as unknown as { ethereum?: Eip1193Provider }).ethereum;
});

// ── selectors: computed keccak(signature)[0..4], pinned ───────────────────────

describe("function selectors", () => {
  it("computes the canonical 4-byte selectors", () => {
    expect(selectorHex("mint(address,uint256)")).toBe("0x40c10f19");
    expect(selectorHex("approve(address,uint256)")).toBe("0x095ea7b3");
    expect(selectorHex("deposit(uint256,bytes32,bytes)")).toBe("0x2b681307");
    expect(selectorHex("claim(address,uint256,uint256,bytes32,bytes32[])")).toBe("0xe1b656ae");
  });

  it("selector really is keccak256(signature)[0..4] (recomputed independently)", () => {
    for (const sig of ["mint(address,uint256)", "deposit(uint256,bytes32,bytes)"]) {
      const expected = "0x" + bytesToHex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
      expect(selectorHex(sig)).toBe(expected);
    }
  });
});

// ── ABI word encoders ─────────────────────────────────────────────────────────

describe("abi word encoding", () => {
  it("left-pads an address to a 32-byte word (lowercased)", () => {
    expect(bytesToHex(encodeAddress(ADDR))).toBe(
      "000000000000000000000000abcdef0123456789abcdef0123456789abcdef01",
    );
    expect(() => encodeAddress("0x1234")).toThrow(/20-byte/);
    expect(() => encodeAddress("0x" + "zz".repeat(20))).toThrow(/20-byte/);
  });

  it("encodes uint256 as 32-byte big-endian and range-checks", () => {
    expect(bytesToHex(encodeUint256(1_000_000_000n))).toBe(
      "000000000000000000000000000000000000000000000000000000003b9aca00",
    );
    expect(bytesToHex(encodeUint256(0n))).toBe("00".repeat(32));
    expect(bytesToHex(encodeUint256((1n << 256n) - 1n))).toBe("ff".repeat(32));
    expect(() => encodeUint256(-1n)).toThrow(/out of range/);
    expect(() => encodeUint256(1n << 256n)).toThrow(/out of range/);
  });

  it("passes bytes32 through verbatim and rejects wrong lengths", () => {
    expect(bytesToHex(encodeBytes32("0x" + "ab".repeat(32)))).toBe("ab".repeat(32));
    expect(() => encodeBytes32("0x1234")).toThrow(/32-byte/);
  });
});

// ── full calldata, pinned byte-exact ──────────────────────────────────────────

describe("calldata builders (pinned)", () => {
  it("mint(0xAbCdEF…, 1000000000)", () => {
    expect(encodeMint(ADDR, 1_000_000_000n)).toBe(
      "0x40c10f19" +
        "000000000000000000000000abcdef0123456789abcdef0123456789abcdef01" +
        "000000000000000000000000000000000000000000000000000000003b9aca00",
    );
  });

  it("approve(vault, 1000000000)", () => {
    // Expected value derived from the constant so a vault redeploy doesn't break the
    // pin — what's pinned is the ENCODING (selector + left-padded address word + amount).
    const vaultWord = COLLATERAL_VAULT.slice(2).toLowerCase().padStart(64, "0");
    expect(encodeApprove(COLLATERAL_VAULT, 1_000_000_000n)).toBe(
      "0x095ea7b3" +
        vaultWord +
        "000000000000000000000000000000000000000000000000000000003b9aca00",
    );
  });

  it("deposit(1000000000, commit, sig) — SEC-019, dynamic sig tail at offset 0x60", () => {
    expect(
      encodeDeposit(1_000_000_000n, "0x" + "ab".repeat(32), "0x" + "cd".repeat(65)),
    ).toBe(
      "0x2b681307" +
        "000000000000000000000000000000000000000000000000000000003b9aca00" +
        "ab".repeat(32) +
        "0000000000000000000000000000000000000000000000000000000000000060" +
        "0000000000000000000000000000000000000000000000000000000000000041" +
        "cd".repeat(65) +
        "00".repeat(31),
    );
  });

  it("deposit rejects a malformed ownerCommit or a non-65-byte sig", () => {
    expect(() => encodeDeposit(1n, "0x1234", "0x" + "cd".repeat(65))).toThrow(/32-byte/);
    expect(() => encodeDeposit(1n, "0x" + "ab".repeat(32), "0x" + "cd".repeat(64))).toThrow(/65-byte/);
    expect(() => encodeDeposit(1n, "0x" + "ab".repeat(32), "0xzz")).toThrow(/65-byte/);
  });

  const claimArgs = {
    to: "0x" + "11".repeat(20),
    amount: 100_000_000n,
    nonce: 3,
    root: "0x" + "bb".repeat(32),
  };

  it("claim(...) with a 2-element proof — dynamic tail at offset 0xa0", () => {
    expect(
      encodeClaim({ ...claimArgs, proof: ["0x" + "cc".repeat(32), "0x" + "dd".repeat(32)] }),
    ).toBe(
      "0xe1b656ae" +
        "0000000000000000000000001111111111111111111111111111111111111111" +
        "0000000000000000000000000000000000000000000000000000000005f5e100" +
        "0000000000000000000000000000000000000000000000000000000000000003" +
        "bb".repeat(32) +
        "00000000000000000000000000000000000000000000000000000000000000a0" +
        "0000000000000000000000000000000000000000000000000000000000000002" +
        "cc".repeat(32) +
        "dd".repeat(32),
    );
  });

  it("claim(...) with an empty proof — length word 0, no items", () => {
    expect(encodeClaim({ ...claimArgs, proof: [] })).toBe(
      "0xe1b656ae" +
        "0000000000000000000000001111111111111111111111111111111111111111" +
        "0000000000000000000000000000000000000000000000000000000005f5e100" +
        "0000000000000000000000000000000000000000000000000000000000000003" +
        "bb".repeat(32) +
        "00000000000000000000000000000000000000000000000000000000000000a0" +
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
  });
});

// ── gateway bind digest ───────────────────────────────────────────────────────

describe("bindDepositDigest", () => {
  it("matches keccak256(ascii tag ‖ owner(32) ‖ addr(20)) — fixed vector", () => {
    const owner = new Uint8Array(32).fill(0x11);
    const addr = "0x" + "22".repeat(20);
    // Expected computed HERE from the documented preimage, independently of the
    // implementation's concatenation.
    const preimage = concatBytes(
      utf8ToBytes("dark-perp:bind-deposit:"),
      new Uint8Array(32).fill(0x11),
      new Uint8Array(20).fill(0x22),
    );
    const expected = keccak_256(preimage);
    expect(bytesToHex(bindDepositDigest(owner, addr))).toBe(bytesToHex(expected));
    // Belt-and-braces literal pin (recomputed out-of-band) so a drift in BOTH
    // sides of the comparison above cannot slip through.
    expect(bytesToHex(expected)).toBe(
      "203d0b34d62b88553cb0246a75d36c1a306b3a884669cb7c6ba5a3796a99e4b5",
    );
  });

  it("rejects a non-32-byte owner and a malformed address", () => {
    expect(() => bindDepositDigest(new Uint8Array(31), "0x" + "22".repeat(20))).toThrow(/32 bytes/);
    expect(() => bindDepositDigest(new Uint8Array(32), "0x1234")).toThrow(/20-byte/);
  });
});

// ── EIP-1193 flows against a scripted provider ────────────────────────────────

describe("connect", () => {
  it("throws readably with no injected wallet", async () => {
    expect(hasInjected()).toBe(false);
    await expect(connect()).rejects.toThrow(/No browser wallet/i);
  });

  it("returns the first account lowercased and remembers it", async () => {
    install({ request: async () => [ADDR] });
    expect(await connect()).toBe(ADDR.toLowerCase());
    expect(connectedAddress()).toBe(ADDR.toLowerCase());
    disconnectWallet();
    expect(connectedAddress()).toBeNull();
  });

  it("maps user rejection (4001) to a readable error", async () => {
    install({ request: async () => { throw { code: 4001, message: "User rejected the request." }; } });
    await expect(connect()).rejects.toThrow(/rejected in the wallet/i);
    expect(connectedAddress()).toBeNull();
  });

  it("rejects an empty account list", async () => {
    install({ request: async () => [] });
    await expect(connect()).rejects.toThrow(/no accounts/i);
  });
});

describe("ensureBaseSepolia", () => {
  it("switches and does not add when the wallet knows the chain", async () => {
    const calls: string[] = [];
    install({ request: async ({ method }) => { calls.push(method); return null; } });
    await ensureBaseSepolia();
    expect(calls).toEqual(["wallet_switchEthereumChain"]);
  });

  it("falls back to wallet_addEthereumChain on 4902 with the full chain params", async () => {
    const calls: { method: string; params?: unknown[] }[] = [];
    install({
      request: async ({ method, params }) => {
        calls.push({ method, params });
        if (method === "wallet_switchEthereumChain") throw { code: 4902 };
        return null;
      },
    });
    await ensureBaseSepolia();
    expect(calls.map((c) => c.method)).toEqual([
      "wallet_switchEthereumChain",
      "wallet_addEthereumChain",
    ]);
    expect(calls[0].params).toEqual([{ chainId: BASE_SEPOLIA_CHAIN_ID }]);
    expect(calls[1].params).toEqual([BASE_SEPOLIA_PARAMS]);
  });

  it("maps a user-rejected switch to a readable error (and does not try to add)", async () => {
    const calls: string[] = [];
    install({
      request: async ({ method }) => {
        calls.push(method);
        throw { code: 4001 };
      },
    });
    await expect(ensureBaseSepolia()).rejects.toThrow(/rejected in the wallet/i);
    expect(calls).toEqual(["wallet_switchEthereumChain"]);
  });
});

describe("sendTx", () => {
  it("sends from/to/data and returns the lowercased hash", async () => {
    let sent: unknown;
    install({
      request: async ({ method, params }) => {
        if (method !== "eth_sendTransaction") throw new Error("unexpected");
        sent = params;
        return TX.toUpperCase().replace("0X", "0x");
      },
    });
    const h = await sendTx({ from: ADDR, to: COLLATERAL_VAULT, data: "0xb6b55f25" });
    expect(h).toBe(TX);
    expect(sent).toEqual([{ from: ADDR, to: COLLATERAL_VAULT, data: "0xb6b55f25" }]);
  });

  it("maps user rejection to a readable error", async () => {
    install({ request: async () => { throw { code: 4001 }; } });
    await expect(sendTx({ from: ADDR, to: COLLATERAL_VAULT, data: "0x" })).rejects.toThrow(
      /Transaction rejected in the wallet/i,
    );
  });

  it("rejects a malformed hash from the wallet", async () => {
    install({ request: async () => "not-a-hash" });
    await expect(sendTx({ from: ADDR, to: COLLATERAL_VAULT, data: "0x" })).rejects.toThrow(
      /invalid transaction hash/i,
    );
  });
});

describe("waitForTx", () => {
  it("polls until the receipt lands with status 0x1", async () => {
    let polls = 0;
    install({
      request: async ({ method }) => {
        if (method !== "eth_getTransactionReceipt") throw new Error("unexpected");
        polls++;
        return polls < 3 ? null : { status: "0x1" };
      },
    });
    await waitForTx(TX, { pollMs: 1, timeoutMs: 1000 });
    expect(polls).toBe(3);
  });

  it("throws on a reverted tx (status 0x0) with the explorer link", async () => {
    install({ request: async () => ({ status: "0x0" }) });
    await expect(waitForTx(TX, { pollMs: 1 })).rejects.toThrow(/reverted.*basescan\.org/i);
  });

  it("times out readably when the receipt never lands", async () => {
    install({ request: async () => null });
    await expect(waitForTx(TX, { pollMs: 5, timeoutMs: 20 })).rejects.toThrow(/not confirmed/i);
  });
});

describe("verifyFinalizedRevertedTransaction", () => {
  const BLOCK = "0x" + "ab".repeat(32);
  const FINALIZED = "0x" + "cd".repeat(32);
  const OTHER = "0x" + "ef".repeat(32);
  const reverted = { transactionHash: TX, status: "0x0", blockHash: BLOCK, blockNumber: "0x2a" };
  const finalized = { hash: FINALIZED, number: "0x30" };
  const canonical = { hash: BLOCK, number: "0x2a" };
  type Read = { method: string; params?: unknown[] };

  function scripted(options: {
    receipt?: unknown;
    secondReceipt?: unknown;
    finalized?: unknown;
    canonical?: unknown;
    afterRead?: (request: Read, index: number) => void;
    chain?: string;
    rejectFinalized?: boolean;
  } = {}) {
    const calls: Read[] = [];
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    let receiptReads = 0;
    const source: Eip1193Provider = {
      on: (event, callback) => {
        if (!listeners.has(event)) listeners.set(event, new Set());
        listeners.get(event)!.add(callback);
      },
      removeListener: (event, callback) => { listeners.get(event)?.delete(callback); },
      request: async (request) => {
        calls.push(request);
        let response: unknown;
        if (request.method === "eth_chainId") response = options.chain ?? BASE_SEPOLIA_CHAIN_ID;
        else if (request.method === "eth_getTransactionReceipt") {
          receiptReads++;
          response = receiptReads > 1 && "secondReceipt" in options ? options.secondReceipt : "receipt" in options ? options.receipt : reverted;
        } else if (request.method === "eth_getBlockByNumber" && request.params?.[0] === "finalized") {
          if (options.rejectFinalized) throw new Error("finalized tag unsupported");
          response = "finalized" in options ? options.finalized : finalized;
        } else if (request.method === "eth_getBlockByNumber" && request.params?.[0] === "0x2a") {
          response = "canonical" in options ? options.canonical : canonical;
        } else throw new Error(`Unexpected wallet request: ${request.method}`);
        options.afterRead?.(request, calls.length);
        return response;
      },
    };
    install(source);
    return { calls, source, listeners, emit: (event: string) => listeners.get(event)?.forEach((callback) => callback()) };
  }

  it("returns pinned finalized revert evidence using only read-only RPC calls", async () => {
    const { calls, listeners } = scripted();
    await expect(verifyFinalizedRevertedTransaction(TX)).resolves.toEqual({
      transactionHash: TX, blockHash: BLOCK, blockNumber: "0x2a",
      finalizedBlockHash: FINALIZED, finalizedBlockNumber: "0x30",
    });
    expect(calls.filter(({ method }) => method === "eth_getTransactionReceipt")).toEqual([
      { method: "eth_getTransactionReceipt", params: [TX] },
      { method: "eth_getTransactionReceipt", params: [TX] },
    ]);
    expect(calls.every(({ method }) => ["eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByNumber"].includes(method))).toBe(true);
    expect([...listeners.values()].every((callbacks) => callbacks.size === 0)).toBe(true);
  });

  it("accepts a revert in the finalized block itself", async () => {
    scripted({ finalized: canonical });
    await expect(verifyFinalizedRevertedTransaction(TX)).resolves.toMatchObject({ finalizedBlockHash: BLOCK, finalizedBlockNumber: "0x2a" });
  });

  it("normalizes valid mixed-case RPC hashes and quantities", async () => {
    scripted({
      receipt: { ...reverted, blockHash: BLOCK.toUpperCase().replace("0X", "0x"), blockNumber: "0x2A" },
      finalized: { ...finalized, hash: FINALIZED.toUpperCase().replace("0X", "0x") },
    });
    await expect(verifyFinalizedRevertedTransaction(TX)).resolves.toMatchObject({ blockHash: BLOCK, blockNumber: "0x2a", finalizedBlockHash: FINALIZED });
  });

  it.each([
    ["pending", null, /pending|not mined/i],
    ["successful", { ...reverted, status: "0x1" }, /succeeded|successful/i],
    ["unknown status", { ...reverted, status: "0x2" }, /status|reverted/i],
    ["noncanonical status", { ...reverted, status: "0x00" }, /status|reverted/i],
    ["other transaction", { ...reverted, transactionHash: OTHER }, /transaction/i],
    ["missing transaction", { ...reverted, transactionHash: undefined }, /transaction/i],
    ["missing block hash", { ...reverted, blockHash: null }, /block|receipt/i],
    ["invalid block hash", { ...reverted, blockHash: "0x1234" }, /block|receipt/i],
    ["zero block hash", { ...reverted, blockHash: "0x" + "00".repeat(32) }, /block|receipt/i],
    ["pending block number", { ...reverted, blockNumber: null }, /block|receipt/i],
    ["decimal block number", { ...reverted, blockNumber: "42" }, /block|receipt/i],
    ["numeric block number", { ...reverted, blockNumber: 42 }, /block|receipt/i],
    ["padded block number", { ...reverted, blockNumber: "0x02a" }, /block|receipt/i],
    ["oversized block number", { ...reverted, blockNumber: "0x" + "f".repeat(65) }, /block|receipt/i],
    ["array receipt", [], /receipt/i],
  ])("keeps retry blocked for a %s receipt", async (_name, receipt, error) => {
    const { calls } = scripted({ receipt });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(error as RegExp);
    expect(calls.some(({ method }) => method === "eth_getBlockByNumber")).toBe(false);
  });

  it.each([
    ["not finalized", { ...finalized, number: "0x29" }],
    ["missing finalized block", null],
    ["missing finalized height", { hash: FINALIZED }],
    ["noncanonical finalized height", { ...finalized, number: "0x030" }],
    ["invalid finalized hash", { ...finalized, hash: "0x1234" }],
    ["conflicting finalized block", { ...finalized, number: "0x2a" }],
  ])("keeps retry blocked with %s", async (_name, finality) => {
    scripted({ finalized: finality });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/final|block|canonical/i);
  });

  it("does not fall back to latest when finalized tags are unsupported", async () => {
    const { calls } = scripted({ rejectFinalized: true });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/finalized tag unsupported/);
    expect(calls.some(({ params }) => params?.[0] === "latest")).toBe(false);
  });

  it.each([
    ["missing canonical block", null],
    ["reorganized block", { ...canonical, hash: OTHER }],
    ["wrong canonical height", { ...canonical, number: "0x2b" }],
    ["malformed canonical block", { ...canonical, hash: "0x1" }],
  ])("keeps retry blocked for a %s", async (_name, block) => {
    scripted({ canonical: block });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/canonical|block/i);
  });

  it.each([
    ["disappears", null],
    ["succeeds", { ...reverted, status: "0x1" }],
    ["moves to another block", { ...reverted, blockHash: OTHER }],
    ["moves to another height", { ...reverted, blockNumber: "0x2b" }],
  ])("keeps retry blocked if the final receipt %s", async (_name, secondReceipt) => {
    scripted({ secondReceipt });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/pending|succeed|changed|block/i);
  });

  it("rejects a malformed saved hash before any wallet RPC", async () => {
    const { calls } = scripted();
    await expect(verifyFinalizedRevertedTransaction("0x1234")).rejects.toThrow(/transaction hash/i);
    expect(calls).toEqual([]);
  });

  it.each(["0x1", "84532", "0x014a34"])("rejects wrong or malformed chain %s", async (chain) => {
    const { calls } = scripted({ chain });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/network|chain|Base Sepolia/i);
    expect(calls.some(({ method }) => method !== "eth_chainId")).toBe(false);
  });

  it("rejects a provider replacement during a read", async () => {
    scripted({ afterRead: ({ method }) => {
      if (method === "eth_getTransactionReceipt") install({ request: async () => BASE_SEPOLIA_CHAIN_ID });
    } });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/wallet|provider|context/i);
  });

  it("rejects provider replacement during the final chain confirmation", async () => {
    let receipts = 0;
    scripted({ afterRead: ({ method }) => {
      if (method === "eth_getTransactionReceipt") receipts++;
      if (method === "eth_chainId" && receipts === 2) install({ request: async () => BASE_SEPOLIA_CHAIN_ID });
    } });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/wallet|provider|context/i);
  });

  it.each(["chainChanged", "disconnect"])("rejects a %s event even if chain ID reads remain unchanged", async (event) => {
    const state = scripted({ afterRead: ({ method }) => {
      if (method === "eth_getTransactionReceipt") state.emit(event);
    } });
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/wallet|network|context/i);
    expect([...state.listeners.values()].every((callbacks) => callbacks.size === 0)).toBe(true);
  });

  it("rejects a silent network change after the first receipt", async () => {
    let changed = false;
    const { source } = scripted({ afterRead: ({ method }) => { if (method === "eth_getTransactionReceipt") changed = true; } });
    const originalRequest = source.request;
    source.request = (request) => request.method === "eth_chainId" && changed ? Promise.resolve("0x1") : originalRequest(request);
    await expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/network|chain|Base Sepolia/i);
  });

  it("bounds an unresponsive provider and makes no follow-up requests after timeout", async () => {
    vi.useFakeTimers();
    try {
      let release!: (value: unknown) => void;
      const request = vi.fn(() => new Promise<unknown>((resolve) => { release = resolve; }));
      install({ request });
      const pending = expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/timed out/i);
      await vi.advanceTimersByTimeAsync(15_001);
      await pending;
      release(BASE_SEPOLIA_CHAIN_ID);
      await Promise.resolve();
      expect(request).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("uses one total deadline for successive slow RPC reads", async () => {
    vi.useFakeTimers();
    try {
      const { source, calls } = scripted();
      const originalRequest = source.request;
      source.request = async (request) => {
        await new Promise((resolve) => setTimeout(resolve, 2_000));
        return originalRequest(request);
      };
      const pending = expect(verifyFinalizedRevertedTransaction(TX)).rejects.toThrow(/timed out/i);
      await vi.advanceTimersByTimeAsync(15_001);
      await pending;
      await vi.advanceTimersByTimeAsync(5_000);
      // The delayed read can settle after timeout, but no new RPC may start.
      expect(calls.filter(({ method }) => method === "eth_getTransactionReceipt")).toHaveLength(2);
      expect(calls.at(-1)?.method).toBe("eth_getTransactionReceipt");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("personalSign", () => {
  it("passes [digestHex, address] and returns the 65-byte signature", async () => {
    const sig = "0x" + "ab".repeat(65);
    const seen: unknown[] = [];
    install({
      request: async ({ method, params }) => {
        expect(method).toBe("personal_sign");
        seen.push(params);
        return sig;
      },
    });
    const digest = "0x" + "cd".repeat(32);
    expect(await personalSign(digest, ADDR)).toBe(sig);
    expect(seen[0]).toEqual([digest, ADDR]);
  });

  it("maps user rejection to a readable error", async () => {
    install({ request: async () => { throw { code: 4001 }; } });
    await expect(personalSign("0x" + "cd".repeat(32), ADDR)).rejects.toThrow(
      /Signature request rejected/i,
    );
  });

  it("rejects a malformed signature from the wallet", async () => {
    install({ request: async () => "0x1234" });
    await expect(personalSign("0x" + "cd".repeat(32), ADDR)).rejects.toThrow(/invalid signature/i);
  });
});

describe("supportsWalletDeposit", () => {
  it("true only when the immutable context and wallet-deposit methods exist", () => {
    const full = {
      captureDepositContext: vi.fn(),
      depositAccount: vi.fn(),
      bindDepositAddress: vi.fn(),
      authorizeDeposit: vi.fn(),
      creditOnchainDeposit: vi.fn(),
    };
    expect(supportsWalletDeposit(full)).toBe(true);
    expect(supportsWalletDeposit({})).toBe(false);
    expect(supportsWalletDeposit(null)).toBe(false);
    expect(supportsWalletDeposit({ depositAccount: vi.fn() })).toBe(false);
    // SEC-019: a client without the authorize call must NOT pass the gate —
    // it could only build the pre-SEC-019 deposit the vault now rejects.
    expect(supportsWalletDeposit({ ...full, authorizeDeposit: undefined })).toBe(false);
  });

  it("the REAL gateway client passes the gate; the mock does not", async () => {
    // Prototype-level check — no instance needed (bootstrap would hit the network).
    const { RealDarkPerpClient } = await import("./realClient");
    const { MockDarkPerpClient } = await import("./mockClient");
    expect(supportsWalletDeposit(RealDarkPerpClient.prototype)).toBe(true);
    expect(supportsWalletDeposit(MockDarkPerpClient.prototype)).toBe(false);
  });
});
