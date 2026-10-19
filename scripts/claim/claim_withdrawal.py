#!/usr/bin/env python3
"""Check a saved Arcora claim bundle without the operator, then print the claim call.

A claim bundle is the JSON file the web client saves for every withdrawal once
it is claimable (schema `arcora.claim-bundle.v1`; "Export all" writes a JSON
array of them). It holds everything `CollateralVault.claim` needs:
recipient, amount, nonce, the published withdrawals root and the Merkle
proof. This tool needs no gateway:

* recomputes the leaf `keccak256(abi.encodePacked(to, amount, nonce))`;
* folds the proof with the vault's sorted-pair rule (`MerkleLib.verify`);
* with `--rpc`, reads (never writes) the chain: chain id, whether the vault
  has published the root (`rootPublished`), and whether the leaf was already
  claimed (`claimed`), using Foundry `cast`;
* prints the exact `cast send` call. Anyone may send it (the vault pays `to`);
  sign it with your own wallet flags in place of `<YOUR_SIGNER>`. The call reads
  the RPC URL from `$RPC_URL` in your shell: this tool never prints the URL it
  was given (it can carry a provider key), so export it before sending.

    python3 scripts/claim/claim_withdrawal.py my-claim.json --rpc https://sepolia.base.org

Exit status 0 when every bundle verifies (and, with --rpc, its root is
published on the bundle's chain), 1 otherwise.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse

SCHEMA = "arcora.claim-bundle.v1"
CLAIM_SIGNATURE = "claim(address,uint256,uint256,bytes32,bytes32[])"
MAX_PROOF = 256
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_DIGEST = re.compile(r"0x[0-9a-fA-F]{64}")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")

# --- Keccak-256 (original padding, as used by Solidity) -----------------------

_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Rotation offsets r[x][y].
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_RATE = 136


def _rol(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(a):
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a = [
            b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        a[0] ^= rc
    return a


def keccak256(data):
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * (-len(padded) % _RATE)
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), _RATE):
        block = padded[offset:offset + _RATE]
        for lane in range(_RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8:lane * 8 + 8], "little")
        state = _permute(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


# --- Withdrawal tree (perp-core merkle.rs / MerkleLib.sol) ---------------------

def withdrawal_leaf(to, amount, nonce):
    if not _ADDRESS.fullmatch(to):
        raise ValueError("recipient must be a 20-byte 0x address")
    if not 0 <= amount < 1 << 256 or not 0 <= nonce < 1 << 256:
        raise ValueError("amount and nonce must fit uint256")
    return keccak256(bytes.fromhex(to[2:]) + amount.to_bytes(32, "big") + nonce.to_bytes(32, "big"))


def _hash_pair(a, b):
    return keccak256(a + b if a <= b else b + a)


def _next_level(level):
    return [_hash_pair(level[i], level[i + 1]) if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]


def merkle_root(leaves):
    if not leaves:
        return bytes(32)
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_proof(leaves, index):
    proof, level = [], list(leaves)
    while len(level) > 1:
        sibling = index + 1 if index % 2 == 0 else index - 1
        if sibling < len(level):
            proof.append(level[sibling])
        index //= 2
        level = _next_level(level)
    return proof


def verify(root, leaf, proof):
    computed = leaf
    for node in proof:
        computed = _hash_pair(computed, node)
    return computed == root


# --- Bundles -------------------------------------------------------------------

class BundleError(ValueError):
    pass


def parse_bundle(raw):
    """Validate shape and types; return a normalized dict or raise BundleError."""
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise BundleError(f"not a {SCHEMA} object")
    chain = raw.get("chainId")
    if type(chain) is not int or chain <= 0:
        raise BundleError("chainId must be a positive integer")
    for key in ("vault", "to"):
        if not isinstance(raw.get(key), str) or not _ADDRESS.fullmatch(raw[key]):
            raise BundleError(f"{key} must be a 20-byte 0x address")
    amount = raw.get("amount")
    if not isinstance(amount, str) or not _DECIMAL.fullmatch(amount) or int(amount) >= 1 << 256:
        raise BundleError("amount must be a decimal string of USDC base units")
    nonce = raw.get("nonce")
    if type(nonce) is not int or not 0 <= nonce < 1 << 256:
        raise BundleError("nonce must be a non-negative integer")
    for key in ("leaf", "root"):
        if not isinstance(raw.get(key), str) or not _DIGEST.fullmatch(raw[key]):
            raise BundleError(f"{key} must be a 32-byte 0x hex value")
    if int(raw["root"], 16) == 0:
        raise BundleError("root is zero: the withdrawal is not claimable yet")
    proof = raw.get("proof")
    if (not isinstance(proof, list) or len(proof) > MAX_PROOF
            or not all(isinstance(p, str) and _DIGEST.fullmatch(p) for p in proof)):
        raise BundleError("proof must be a list of 32-byte 0x hex values")
    return {
        "chainId": chain, "vault": raw["vault"], "to": raw["to"], "amount": amount,
        "nonce": nonce, "leaf": raw["leaf"].lower(), "root": raw["root"].lower(),
        "proof": [p.lower() for p in proof],
    }


def check_bundle(raw):
    """Return a list of problems (empty when the proof checks out offline)."""
    b = parse_bundle(raw)
    problems = []
    leaf = withdrawal_leaf(b["to"], int(b["amount"]), b["nonce"])
    if "0x" + leaf.hex() != b["leaf"]:
        problems.append("leaf does not match keccak256(to, amount, nonce)")
    proof = [bytes.fromhex(p[2:]) for p in b["proof"]]
    if not verify(bytes.fromhex(b["root"][2:]), leaf, proof):
        problems.append("Merkle proof does not lead to the bundle root")
    return problems


def cast_command(b):
    """The `cast send` line for the claim; its RPC URL is `"$RPC_URL"`, read from the shell."""
    # Imported here: chain_read takes keccak256 from this module, so it cannot load first, and this
    # file is also loaded by path alone (scripts/local-verification/test_pin_coherence.py).
    import chain_read
    proof = f'"[{",".join(b["proof"])}]"'
    return chain_read.cast_send(b["vault"], CLAIM_SIGNATURE, [b["to"], b["amount"], b["nonce"], b["root"], proof])


# --- Read-only chain checks ----------------------------------------------------

def _cast(args, rpc):
    env = {**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    try:
        result = subprocess.run(["cast", *args, "--rpc-url", rpc], capture_output=True, text=True, env=env,
                                timeout=60)
    except subprocess.TimeoutExpired:
        # Its own message quotes the whole command, RPC URL included.
        raise RuntimeError(f"cast {args[0]} timed out after 60 s") from None
    if result.returncode != 0:
        raise RuntimeError(f"cast {args[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def _bool(text):
    if text not in ("true", "false"):
        raise RuntimeError("unexpected cast output")
    return text == "true"


def chain_problems(b, rpc):
    """Return (problems, already_claimed) from read-only calls."""
    chain = _cast(["chain-id"], rpc)
    if chain != str(b["chainId"]):
        return [f"RPC is chain {chain}, bundle is for chain {b['chainId']}"], False
    if not _bool(_cast(["call", b["vault"], "rootPublished(bytes32)(bool)", b["root"]], rpc)):
        return ["root is not published by this vault"], False
    return [], _bool(_cast(["call", b["vault"], "claimed(bytes32)(bool)", b["leaf"]], rpc))


def _plain_rpc(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ValueError("--rpc must be an http(s) URL without user info or fragment")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", help="claim bundle JSON (one object, or the export-all array)")
    parser.add_argument("--rpc", help="read-only chain checks through this RPC URL (needs Foundry cast)")
    args = parser.parse_args(argv)
    if args.rpc:
        try:
            _plain_rpc(args.rpc)
        except ValueError as error:
            parser.error(str(error))
    import chain_read  # see cast_command
    out = chain_read.noting_rpc_url(print)
    with open(args.bundle) as stream:
        raw = json.load(stream)
    entries = raw if isinstance(raw, list) else [raw]
    ok = True
    for index, entry in enumerate(entries):
        label = f"[{index}]" if isinstance(raw, list) else "bundle"
        try:
            problems = check_bundle(entry)
            b = parse_bundle(entry)
            claimed = False
            if not problems and args.rpc:
                problems, claimed = chain_problems(b, args.rpc)
        except (BundleError, RuntimeError) as error:
            problems = [str(error)]
        if problems:
            ok = False
            print(f"{label} FAILED: " + "; ".join(problems))
            continue
        status = "already claimed" if claimed else "OK"
        print(f"{label} {status}: {b['amount']} base units to {b['to']} (nonce {b['nonce']})")
        if not claimed:
            out("  " + cast_command(b))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
