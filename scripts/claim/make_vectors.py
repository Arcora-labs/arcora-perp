#!/usr/bin/env python3
"""Regenerate fixtures/withdrawal-vectors.json from claim_withdrawal.py.

The gateway test `withdrawals::tests::claim_tool_vectors_match_rust_tree`
checks every leaf, root and proof in that file against perp-core, so the file
only passes CI when the Python and Rust trees agree. Sizes cover a single
leaf, a pair, odd-node promotion (3, 5) and a full power of two (8); one
entry uses the largest u128 amount and u64 nonce the gateway can produce.
"""
import json
from pathlib import Path

import claim_withdrawal as cw

OUT = Path(__file__).resolve().parent / "fixtures" / "withdrawal-vectors.json"


def withdrawals(size, seed):
    rows = []
    for i in range(size):
        rows.append({
            "to": "0x" + f"{seed:02x}{i + 1:038x}",
            "amount": str((i + 1) * 1_000_000 + seed),
            "nonce": seed * 100 + i,
        })
    return rows


def tree(rows):
    leaves = [cw.withdrawal_leaf(r["to"], int(r["amount"]), r["nonce"]) for r in rows]
    return {
        "withdrawals": rows,
        "leaves": ["0x" + leaf.hex() for leaf in leaves],
        "root": "0x" + cw.merkle_root(leaves).hex(),
        "proofs": [["0x" + p.hex() for p in cw.merkle_proof(leaves, i)] for i in range(len(leaves))],
    }


def main():
    trees = [tree(withdrawals(size, seed)) for seed, size in enumerate([1, 2, 3, 5, 8], start=1)]
    extreme = withdrawals(3, 9)
    extreme[1].update(amount=str((1 << 128) - 1), nonce=(1 << 64) - 1)
    trees.append(tree(extreme))
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"schema": "arcora.withdrawal-vectors.v1", "trees": trees}, indent=1) + "\n")
    print(f"wrote {OUT} ({len(trees)} trees)")


if __name__ == "__main__":
    main()
