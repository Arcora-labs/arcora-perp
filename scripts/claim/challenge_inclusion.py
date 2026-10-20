#!/usr/bin/env python3
"""Check a saved order receipt's L1 challenge kit and print the next challenge call.

The gateway's order receipt carries `l1Challenge {chainId, settlement,
beneficiary, signature}`: the enclave's authorization to open an L1 inclusion
challenge for that order on one settlement, paying any fine to `beneficiary`
(the account's bound deposit address). The browser's challenge kit
(`arcora.challenge-kit.v1`) has the same shape. This tool needs no gateway:

* requires every field the challenge call or the signature check reads: the
  receipt's `orderHash`, `seqNo`, `recvTimeMs`, `batchIdHint` and
  `enclaveSigner`, and `l1Challenge` with all four of its fields; a kit missing
  one, or with one malformed, is refused and no call is printed;
* recomputes `challengeAuthDigest` = keccak256(abi.encode(tag, chainId,
  settlement, orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary)), checks
  the signature is canonical (65 bytes `r||s||v`, low `s`, `v` 27/28) and
  recovers the signer, which must be the kit's `enclaveSigner`; offline that is
  all it can check, and `--rpc` also checks the settlement's `enclaveSigner()`;
* with `--rpc`, reads (never writes) the settlement: chain, `ABI_VERSION`,
  `enclaveSigner`, the on-chain digest, close-only, the challenge state, the
  stake (`challengeBond`) and the ripeness time
  (`recvTimeMs / 1000 + inclusionDeadlineSecs`), and simulates the next call;
* prints the exact `cast send` for the stage the challenge is in:
  `challengeInclusion` (open it; anyone may send it with the stake),
  `slashUnanswered` (once `progressBatches` batches settled after it opened and
  `challengeGraceBlocks` passed without an answer), `releaseStaleChallenge`
  (close-only began before that progress), and the `claimUsdc` / `claimEth`
  withdrawals of credited fines and stakes. The commands read the RPC URL
  from the shell (`--rpc-url "$RPC_URL"`); the tool never prints the URL,
  which may carry a provider key.

When the bond is below `slashPayoutCap`, the fine is reduced and only the
beneficiary may trigger the slash (the submitter may, one liveness window
later). Opening a challenge publishes the beneficiary address next to the
order hash on L1.

    python3 scripts/claim/challenge_inclusion.py my-order.json --rpc https://sepolia.base.org

Exit status 0 when every kit verifies (and, with --rpc, matches the chain); 1 otherwise,
including for a file that holds no kit.
"""
import argparse
import json
import re
import sys

import chain_read as chain
from claim_withdrawal import keccak256

CHALLENGE_AUTH_TAG = keccak256(b"arcora:l1-inclusion-challenge:v1")
ABI_VERSION = 3
CHALLENGE_SIGNATURE = "challengeInclusion(bytes32,uint64,uint64,uint64,address,bytes)"
SETTLEMENT_ERRORS = chain.error_names(
    "InCloseOnly()", "AlreadyResolved()", "ChallengeExists()", "WrongChallengeBond()", "BadBeneficiary()",
    "NonCanonicalSignature()", "BadReceiptSignature()", "NotRipe()", "NoSuchChallenge()", "NoProgress()",
    "ChallengeNotExpired()", "ShortBondSlashRestricted()", "NotStale()")
_U64 = 1 << 64
_SIG = re.compile(r"0x[0-9a-fA-F]{130}")

# --- secp256k1 public-key recovery (Ethereum `ecrecover`) ----------------------

_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, _P) % _P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, _P) % _P
    x = (slope * slope - a[0] - b[0]) % _P
    return x, (slope * (a[0] - x) - a[1]) % _P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def point_address(point):
    return "0x" + keccak256(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def is_canonical(signature):
    """The settlement's rule: 65 bytes, 1 <= r, s < n, s <= n/2, v in {27, 28}."""
    if len(signature) != 65:
        return False
    r, s, v = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"), signature[64]
    return 0 < r < _N and 0 < s <= _N // 2 and v in (27, 28)


def recover(digest, signature):
    """The address that signed `digest` (32 bytes), or None when it does not recover."""
    if not is_canonical(signature):
        return None
    r, s, v = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"), signature[64]
    y_squared = (pow(r, 3, _P) + 7) % _P
    y = pow(y_squared, (_P + 1) // 4, _P)
    if y * y % _P != y_squared:
        return None
    if y % 2 != v - 27:
        y = _P - y
    e = int.from_bytes(digest, "big") % _N
    r_inverse = pow(r, -1, _N)
    point = _add(_mul(s * r_inverse % _N, (r, y)), _mul((-e * r_inverse) % _N, _G))
    return None if point is None else point_address(point)


# --- Kits ------------------------------------------------------------------------

class KitError(ValueError):
    pass


def auth_digest(chain_id, settlement, order_hash, seq_no, recv_time_ms, batch_id_hint, beneficiary):
    """`DarkPerpSettlement.challengeAuthDigest` for the given chain and settlement."""
    return keccak256(CHALLENGE_AUTH_TAG + bytes.fromhex("".join(chain.word(v) for v in (
        chain_id, settlement, order_hash, seq_no, recv_time_ms, batch_id_hint, beneficiary))))


def _field(obj, key, name, valid, shape):
    """`obj[key]` when present and `valid`, else a KitError naming the field."""
    if key not in obj:
        raise KitError(f"{name} is missing")
    if not valid(obj[key]):
        raise KitError(f"{name} must be {shape}")
    return obj[key]


def _u64(value):
    return type(value) is int and 0 <= value < _U64


def _address(value):
    return isinstance(value, str) and chain.ADDRESS.fullmatch(value) is not None


def parse_kit(raw):
    """Normalize a receipt (or a tracked order holding one) with its `l1Challenge`.

    Every field the challenge call or the signature check reads is required:
    the receipt's `orderHash`, `seqNo`, `recvTimeMs`, `batchIdHint` and
    `enclaveSigner`, and `l1Challenge` with `chainId`, `settlement`,
    `beneficiary` and `signature`. A missing or malformed one is a KitError.
    """
    if isinstance(raw, dict) and isinstance(raw.get("receipt"), dict):
        raw = raw["receipt"]
    if not isinstance(raw, dict):
        raise KitError("not an order receipt object")
    order_hash = _field(raw, "orderHash", "orderHash",
                        lambda v: isinstance(v, str) and chain.DIGEST.fullmatch(v), "a 32-byte 0x hex value")
    for key in ("seqNo", "recvTimeMs", "batchIdHint"):
        _field(raw, key, key, _u64, "an unsigned 64-bit integer")
    enclave = _field(raw, "enclaveSigner", "enclaveSigner", _address, "a 20-byte 0x address")
    if "l1Challenge" not in raw:
        raise KitError("l1Challenge is missing (a receipt issued before L1 challenge kits has none)")
    kit = raw["l1Challenge"]
    if kit is None:
        raise KitError("no L1 challenge authorization: the account had no bound deposit address")
    if not isinstance(kit, dict):
        raise KitError("l1Challenge must be an object")
    _field(kit, "chainId", "l1Challenge.chainId", lambda v: _u64(v) and v > 0, "a positive integer")
    for key in ("settlement", "beneficiary"):
        _field(kit, key, f"l1Challenge.{key}", _address, "a 20-byte 0x address")
    if int(kit["beneficiary"], 16) == 0:
        raise KitError("l1Challenge.beneficiary is zero")
    _field(kit, "signature", "l1Challenge.signature",
           lambda v: isinstance(v, str) and _SIG.fullmatch(v), "a 65-byte 0x hex value")
    return {
        "orderHash": order_hash.lower(), "seqNo": raw["seqNo"], "recvTimeMs": raw["recvTimeMs"],
        "batchIdHint": raw["batchIdHint"], "chainId": kit["chainId"], "settlement": kit["settlement"].lower(),
        "beneficiary": kit["beneficiary"].lower(), "signature": kit["signature"].lower(),
        "enclaveSigner": enclave.lower(),
    }


def check_kit(k):
    """(problems, digest, signer) from offline checks: the signature must recover to `enclaveSigner`."""
    digest = auth_digest(k["chainId"], k["settlement"], k["orderHash"], k["seqNo"], k["recvTimeMs"],
                         k["batchIdHint"], k["beneficiary"])
    signature = bytes.fromhex(k["signature"][2:])
    problems = []
    if not is_canonical(signature):
        problems.append("the signature is not canonical (low s, v 27/28); the settlement refuses it")
        return problems, digest, None
    signer = recover(digest, signature)
    if signer is None:
        problems.append("the signature does not recover to an address")
    elif signer != k["enclaveSigner"]:
        problems.append("the authorization is not signed by the receipt's enclave signer")
    return problems, digest, signer


def challenge_args(k):
    return [k["orderHash"], k["seqNo"], k["recvTimeMs"], k["batchIdHint"], k["beneficiary"], k["signature"]]


def encode_challenge(k):
    """ABI arguments of challengeInclusion; `bytes sig` is the dynamic tail at 0xc0."""
    head = "".join(chain.word(v) for v in challenge_args(k)[:5]) + chain.word(0xC0)
    sig = k["signature"][2:]
    return head + chain.word(65) + sig + "0" * (-len(sig) % 64)


def chain_report(k, signer, digest, rpc, staker=None, out=print):
    """Read the settlement, print the next call; return a list of problems."""
    chain_id = chain.quantity(rpc("eth_chainId", []))
    if chain_id != k["chainId"]:
        return [f"the RPC serves chain {chain_id}, the kit is for chain {k['chainId']}"]
    head, timestamp = chain.pin_latest(rpc)
    read = chain.Reader(rpc, hex(head))
    s = k["settlement"]
    try:
        version = read.uint(s, "ABI_VERSION()")
    except chain.ChainError:
        return ["the address does not answer ABI_VERSION(); not a settlement this kit supports"]
    if version != ABI_VERSION:
        return [f"settlement ABI_VERSION is {version}, this tool supports {ABI_VERSION}"]
    if read.address(s, "enclaveSigner()") != signer:
        return ["the settlement's enclaveSigner did not sign this authorization"]
    on_chain = read.bytes32(s, "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)", k["orderHash"],
                            k["seqNo"], k["recvTimeMs"], k["batchIdHint"], k["beneficiary"])
    if on_chain != "0x" + digest.hex():
        return ["the settlement computes a different authorization digest"]
    h = k["orderHash"]
    close_only = read.boolean(s, "closeOnly()")
    resolved = read.boolean(s, "challengeResolved(bytes32)", h)
    fields = chain.words(read.call(s, "challenges(bytes32)", h, size=192))
    challenge = {"openedBlock": int.from_bytes(fields[2], "big"),
                 "openBatchCount": int.from_bytes(fields[3], "big"), "open": chain.as_bool(fields[5])}
    out(f"settlement {s} on chain {chain_id}, block {head}")
    problems = []
    if challenge["open"]:
        problems += open_challenge_report(k, read, challenge, close_only, head, staker, out)
    elif resolved:
        out(f"the challenge for {h} is resolved (answered, slashed or released)")
    elif close_only:
        out("the settlement is in close-only: no new challenge can be opened; uncredited deposits are "
            "refundable (scripts/claim/refund_deposit.py)")
    else:
        bond = read.uint(s, "challengeBond()")
        ripe_at = k["recvTimeMs"] // 1000 + read.uint(s, "inclusionDeadlineSecs()")
        if timestamp < ripe_at:
            out(f"not ripe yet: it can be opened from unix time {ripe_at} ({ripe_at - timestamp} s from now)")
            out("  " + chain.cast_send(s, CHALLENGE_SIGNATURE, challenge_args(k), value=bond))
        else:
            tx = {"to": s, "data": chain.selector(CHALLENGE_SIGNATURE) + encode_challenge(k), "value": hex(bond)}
            if staker:
                tx["from"] = staker
            reverted = simulate_raw(rpc, tx, hex(head))
            if reverted is not None:
                problems.append("opening it would revert now: " + SETTLEMENT_ERRORS.get(reverted, reverted or "no reason"))
            else:
                out(f"open the challenge (anyone may send it with the {bond} wei stake):")
                out("  " + chain.cast_send(s, CHALLENGE_SIGNATURE, challenge_args(k), value=bond))
    claims_report(k, read, staker, out)
    return problems


def simulate_raw(rpc, tx, block):
    try:
        rpc("eth_call", [tx, block])
    except chain.Reverted as reverted:
        return reverted.selector or ""
    return None


def open_challenge_report(k, read, challenge, close_only, head, staker, out):
    s, h = k["settlement"], k["orderHash"]
    progress = read.uint(s, "progressBatches()")
    target = challenge["openBatchCount"] + progress
    settled = read.uint(s, "closeOnlyBatchCount()" if close_only else "batchCount()")
    out(f"challenge open since block {challenge['openedBlock']} (batch count then {challenge['openBatchCount']})")
    if close_only and target > settled:
        out("close-only began before enough batches settled after it; release it to refund the stake:")
        out("  " + chain.cast_send(s, "releaseStaleChallenge(bytes32)", [h]))
        return []
    if settled < target:
        out(f"waiting for {target - settled} more settled batch(es) before a slash is possible; "
            "an answer in any of them closes it")
        return []
    grace = read.uint(s, "challengeGraceBlocks()")
    settled_at = int.from_bytes(read.call(s, "batches(uint256)", target - 1, size=128)[96:], "big")
    expiry = settled_at + grace
    if head <= expiry:
        out(f"unanswered so far; slashable after block {expiry} ({expiry - head} blocks)")
        return []
    bond, cap = read.uint(s, "sequencerBond()"), read.uint(s, "slashPayoutCap()")
    payout = min(bond, cap)
    sender = k["beneficiary"]
    if payout < cap:
        out(f"the bond is below the payout cap: the fine is reduced to {payout}; only the beneficiary "
            f"{k['beneficiary']} may trigger it (the submitter after block "
            f"{expiry + read.uint(s, 'livenessTimeoutBlocks()')})")
    reverted = read.simulate(s, "slashUnanswered(bytes32)", h, sender=sender)
    if reverted is not None:
        return ["the slash would revert now: " + SETTLEMENT_ERRORS.get(reverted, reverted or "no reason")]
    who = "send it from the beneficiary" if payout < cap else "anyone may send it"
    out(f"unanswered past the grace: slash it ({who}; fine {payout} USDC base units to the beneficiary):")
    out("  " + chain.cast_send(s, "slashUnanswered(bytes32)", [h]))
    return []


def claims_report(k, read, staker, out):
    s = k["settlement"]
    usdc = read.uint(s, "pendingUsdc(address)", k["beneficiary"])
    if usdc:
        out(f"{usdc} USDC base units are credited to the beneficiary; withdraw them from that address "
            "(claimUsdcTo(address) pays another address):")
        out("  " + chain.cast_send(s, "claimUsdc()", []))
    for account in dict.fromkeys(a for a in (staker, k["beneficiary"]) if a):
        eth = read.uint(s, "pendingEth(address)", account)
        if eth:
            out(f"{eth} wei of stake is credited to {account}; withdraw it from that address:")
            out("  " + chain.cast_send(s, "claimEth()", []))


def main(argv=None, rpc_factory=chain.HttpRPC):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kit", help="order receipt JSON with l1Challenge (one object, a tracked order, or an array)")
    parser.add_argument("--rpc", help="read-only chain checks through this RPC URL")
    parser.add_argument("--staker", help="address that submits (or submitted) the challenge, for simulation")
    args = parser.parse_args(argv)
    try:
        if args.rpc:
            chain.plain_rpc(args.rpc)
        if args.staker and not chain.ADDRESS.fullmatch(args.staker):
            raise ValueError("--staker must be a 20-byte 0x address")
    except ValueError as error:
        parser.error(str(error))
    with open(args.kit) as stream:
        raw = json.load(stream)
    entries = raw if isinstance(raw, list) else [raw]
    if not entries:
        print("FAILED: the file holds no kits")
        return 1
    rpc = rpc_factory(args.rpc) if args.rpc else None
    out = chain.noting_rpc_url(print)
    ok = True
    for index, entry in enumerate(entries):
        label = f"[{index}]" if isinstance(raw, list) else "kit"
        try:
            k = parse_kit(entry)
            problems, digest, signer = check_kit(k)
            if not problems:
                out(f"{label} OK: order {k['orderHash']} authorized by {signer} for beneficiary {k['beneficiary']}")
                if rpc is None:
                    out(f"  offline check: signed by the kit's enclaveSigner {signer}; --rpc also checks that it "
                        "is the settlement's enclaveSigner()")
                    out("  " + chain.cast_send(k["settlement"], CHALLENGE_SIGNATURE, challenge_args(k),
                                               value="<challengeBond()>"))
                else:
                    problems = chain_report(k, signer, digest, rpc, args.staker.lower() if args.staker else None,
                                            out=out)
        except (KitError, chain.ChainError) as error:
            problems = [str(error)]
        if problems:
            ok = False
            print(f"{label} FAILED: " + "; ".join(problems))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
