import { describe, expect, it } from "vitest";
import { parseWithdrawal } from "./withdrawal";

const vault = "0x" + "22".repeat(20);
const valid = {
  to: "0x" + "11".repeat(20), amount: "100000000", nonce: 3,
  leaf: "0x" + "aa".repeat(32), root: "0x" + "bb".repeat(32),
  claimable: true, proof: ["0x" + "cc".repeat(32)],
};

describe("withdrawal wire boundary", () => {
  it("retains exact integers and accepts an empty single-leaf proof", () => {
    const amount = ((1n << 256n) - 1n).toString();
    expect(parseWithdrawal({ ...valid, amount, proof: [] }, vault))
      .toEqual({ ...valid, amount: BigInt(amount), proof: [] });
    expect(parseWithdrawal({ ...valid, claimable: false }, vault)?.claimable).toBe(false);
  });

  it.each(["-1", "0x10", "1e3", "1.5", " 1", "01", "", (1n << 256n).toString(), "9".repeat(10000)])(
    "rejects noncanonical or out-of-range amounts: %.25s", amount => {
      expect(parseWithdrawal({ ...valid, amount }, vault)).toBeNull();
    },
  );

  it("drops malformed ABI fields instead of creating executable shell text", () => {
    const changes = [
      { to: "$(echo unsafe)" }, { root: "`echo unsafe`" }, { leaf: "0x12" },
      { proof: ['$(echo unsafe)'] }, { proof: "[]" },
      { proof: Array(257).fill(valid.leaf) }, { nonce: -1 }, { nonce: 1.5 },
      { nonce: Number.MAX_SAFE_INTEGER + 1 }, { amount: 100 }, { claimable: "true" },
    ];
    for (const change of changes) {
      expect(parseWithdrawal({ ...valid, ...change }, vault)).toBeNull();
    }
    expect(parseWithdrawal(valid, `${vault}; echo unsafe`)).toBeNull();
    expect(parseWithdrawal(null, vault)).toBeNull();
  });
});
