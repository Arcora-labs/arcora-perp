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
    expect(selectorHex("deposit(uint256)")).toBe("0xb6b55f25");
    expect(selectorHex("claim(address,uint256,uint256,bytes32,bytes32[])")).toBe("0xe1b656ae");
  });

  it("selector really is keccak256(signature)[0..4] (recomputed independently)", () => {
    for (const sig of ["mint(address,uint256)", "deposit(uint256)"]) {
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

  it("deposit(1000000000)", () => {
    expect(encodeDeposit(1_000_000_000n)).toBe(
      "0xb6b55f25" + "000000000000000000000000000000000000000000000000000000003b9aca00",
    );
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
  it("true only when all four wallet-deposit methods exist", () => {
    const full = {
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
