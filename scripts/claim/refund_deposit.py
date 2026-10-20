#!/usr/bin/env python3
"""Find an uncredited Arcora deposit on L1 and print its refund, without the operator.

A deposit the settled state never consumed (id >= the settlement's
`consumedDepositCount`) can be refunded from the vault at its exact principal
once the settlement is in close-only. This tool needs no gateway. Through a
read-only RPC it:

* locates the `Deposit` log: by transaction hash (`--tx`), by deposit id
  (`--id`, via the block `depositMeta(id)` records), or every unconsumed deposit
  of one payer (`--from`);
* checks the log against the vault's deposit chain:
  `keccak256(depositTipAt[id] || keccak256(from, ownerCommit, amount, uint256(id)))`
  must equal `depositTipAt[id + 1]`;
* reads whether the deposit was credited, refunded, or is refundable, and
  whether the settlement is in close-only;
* when it is not, reports whether anyone may call `triggerCloseOnly()` now
  (the settlement made no progress for `livenessTimeoutBlocks`, or the oldest
  unconsumed deposit is older than that) and from which block it can;
* prints the exact `cast send` calls. Anyone may send `triggerCloseOnly()` and
  `refundDeposit(...)`; the refund always pays the deposit's payer `from`,
  unless `from` itself sends it with another recipient (`--to`).

    python3 scripts/claim/refund_deposit.py --rpc https://sepolia.base.org \\
        --vault 0x... --from 0xYOUR_DEPOSIT_ADDRESS

Exit status 0 when at least one checked deposit is refundable (now, or once
the settlement is in close-only) and nothing failed; 1 otherwise.
"""
import argparse
import sys

import chain_read as chain
from claim_withdrawal import keccak256

DEPOSIT_EVENT = "Deposit(address,bytes32,uint256,uint64,bytes32)"
DEPOSIT_TOPIC = chain.topic(DEPOSIT_EVENT)
REFUND_SIGNATURE = "refundDeposit(uint64,address,bytes32,uint256,address)"
MAX_SCAN = 256
VAULT_ERRORS = chain.error_names(
    "NotPaired()", "NotCloseOnly()", "NotRefundable()", "AlreadyRefunded()", "BadRefundRecipient()",
    "BadDepositPreimage()", "TransferFailed()")
SETTLEMENT_ERRORS = chain.error_names("LivenessNotExpired()")


def deposit_leaf(payer, owner_commit, amount, deposit_id):
    """`keccak256(abi.encodePacked(from, ownerCommit, amount, uint256(id)))`."""
    return keccak256(bytes.fromhex(payer[2:]) + bytes.fromhex(owner_commit[2:])
                     + amount.to_bytes(32, "big") + deposit_id.to_bytes(32, "big"))


def fold(tip, leaf):
    return keccak256(tip + leaf)


def parse_deposit_log(log, vault):
    """A Deposit log of `vault` as a dict, or None if it is some other log."""
    if not isinstance(log, dict) or str(log.get("address", "")).lower() != vault:
        return None
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 3 or str(topics[0]).lower() != DEPOSIT_TOPIC:
        return None
    if log.get("removed") is True:
        raise chain.ChainError("deposit log was removed by a reorganization")
    data = chain.data_bytes(log.get("data"), 96)
    amount, deposit_id, new_tip = chain.words(data)
    deposit_id = int.from_bytes(deposit_id, "big")
    if deposit_id >= 1 << 64:
        raise chain.ChainError("deposit id does not fit uint64")
    return {
        "id": deposit_id,
        "from": chain.as_address(chain.data_bytes(topics[1], 32)),
        "ownerCommit": "0x" + chain.data_bytes(topics[2], 32).hex(),
        "amount": int.from_bytes(amount, "big"),
        "newTip": "0x" + new_tip.hex(),
        "block": chain.quantity(log.get("blockNumber")) if log.get("blockNumber") is not None else None,
        "tx": log.get("transactionHash"),
    }


class Vault:
    def __init__(self, reader, vault):
        self.read, self.address = reader, vault

    def deposit_block(self, deposit_id):
        raw = self.read.call(self.address, "depositMeta(uint64)", deposit_id, size=64)
        return int.from_bytes(raw[:32], "big")

    def tip_at(self, n):
        return self.read.call(self.address, "depositTipAt(uint64)", n)

    def refunded(self, deposit_id):
        return self.read.boolean(self.address, "depositRefunded(uint64)", deposit_id)


def logs_at(rpc, vault, block, payer=None):
    topics = [DEPOSIT_TOPIC]
    if payer is not None:
        topics.append("0x" + payer[2:].rjust(64, "0"))
    logs = rpc("eth_getLogs", [{"fromBlock": hex(block), "toBlock": hex(block), "address": vault, "topics": topics}])
    if not isinstance(logs, list):
        raise chain.ChainError("eth_getLogs returned no list")
    return [d for d in (parse_deposit_log(log, vault) for log in logs) if d is not None]


def find_deposits(rpc, vault, state, *, tx=None, ids=(), payer=None, max_scan=MAX_SCAN):
    """Return (deposits, notes). Each deposit is a parsed Deposit log."""
    found, notes = {}, []
    if tx is not None:
        receipt = rpc("eth_getTransactionReceipt", [tx])
        if not isinstance(receipt, dict):
            raise chain.ChainError("transaction receipt not found")
        if receipt.get("status") != "0x1":
            raise chain.ChainError("the transaction did not succeed")
        for log in receipt.get("logs") or []:
            deposit = parse_deposit_log(log, vault)
            if deposit is not None:
                found[deposit["id"]] = deposit
        if not found:
            raise chain.ChainError("the transaction has no Deposit log from this vault")
    for deposit_id in ids:
        if deposit_id >= state["depositCount"]:
            raise chain.ChainError(f"deposit {deposit_id} does not exist (depositCount {state['depositCount']})")
        block = state["vault"].deposit_block(deposit_id)
        matches = [d for d in logs_at(rpc, vault, block) if d["id"] == deposit_id]
        if len(matches) != 1:
            raise chain.ChainError(f"deposit {deposit_id}: no unique Deposit log in its block {block}")
        found[deposit_id] = matches[0]
    if payer is not None:
        first, end = state["consumed"], state["depositCount"]
        if end - first > max_scan:
            notes.append(f"{end - first} unconsumed deposits; checked the first {max_scan} "
                         f"(use --max-scan or --id for the rest)")
            end = first + max_scan
        blocks = sorted({state["vault"].deposit_block(i) for i in range(first, end)})
        for block in blocks:
            for deposit in logs_at(rpc, vault, block, payer):
                if first <= deposit["id"] < end:
                    found[deposit["id"]] = deposit
        if not found:
            notes.append(f"no unconsumed deposit from {payer} (ids {first}..{max(first, end) - 1})")
    return [found[i] for i in sorted(found)], notes


def read_state(reader, vault):
    settlement = reader.address(vault, "settlement()")
    state = {"vault": Vault(reader, vault), "settlement": settlement}
    state["paired"] = reader.address(settlement, "vault()") == vault
    state["closeOnly"] = reader.boolean(settlement, "closeOnly()")
    state["consumed"] = reader.uint(settlement, "consumedDepositCount()")
    state["depositCount"] = reader.uint(vault, "depositCount()")
    return state


def close_only_outlook(reader, state, head):
    """When `triggerCloseOnly()` becomes available, from the same rules the contract uses."""
    s = state["settlement"]
    liveness = reader.uint(s, "livenessTimeoutBlocks()")
    last = reader.uint(s, "lastProgressBlock()")
    holds = (reader.uint(s, "batchCount()") != 0 or state["depositCount"] != 0
             or reader.uint(s, "openChallengeCount()") != 0)
    candidates = []
    if holds:
        candidates.append((last + liveness + 1, "no settlement progress for livenessTimeoutBlocks"))
    if state["depositCount"] > state["consumed"]:
        oldest = state["vault"].deposit_block(state["consumed"])
        candidates.append((oldest + liveness + 1, "the oldest unconsumed deposit waited livenessTimeoutBlocks"))
    simulated = reader.simulate(s, "triggerCloseOnly()")
    return {"available_now": simulated is None, "earliest": min(candidates) if candidates else None,
            "head": head, "revert": SETTLEMENT_ERRORS.get(simulated, simulated)}


def check(rpc, vault, *, tx=None, ids=(), payer=None, to=None, max_scan=MAX_SCAN, out=print):
    """Run the checks and print the report; return the exit status."""
    head, _ = chain.pin_latest(rpc)
    reader = chain.Reader(rpc, hex(head))
    state = read_state(reader, vault)
    out(f"vault {vault}, settlement {state['settlement']}, block {head}")
    out(f"  deposits {state['depositCount']}, consumed by the settled state {state['consumed']}, "
        f"close-only {'yes' if state['closeOnly'] else 'no'}")
    if not state["paired"]:
        out("FAILED: the settlement is not paired with this vault; refunds would revert")
        return 1
    deposits, notes = find_deposits(rpc, vault, state, tx=tx, ids=ids, payer=payer, max_scan=max_scan)
    for note in notes:
        out("  note: " + note)
    refundable, failed = [], False
    for d in deposits:
        label = f"deposit {d['id']}: {d['amount']} base units from {d['from']}"
        tip, next_tip = state["vault"].tip_at(d["id"]), state["vault"].tip_at(d["id"] + 1)
        leaf = deposit_leaf(d["from"], d["ownerCommit"], d["amount"], d["id"])
        if fold(tip, leaf) != next_tip or bytes.fromhex(d["newTip"][2:]) != next_tip:
            out(f"{label} FAILED: the log does not match the vault's deposit chain")
            failed = True
        elif d["id"] < state["consumed"]:
            out(f"{label} is credited by the settled state; withdraw it through the normal claim path")
        elif state["vault"].refunded(d["id"]):
            out(f"{label} was already refunded")
        else:
            refundable.append(d)
            out(f"{label} is refundable" + ("" if state["closeOnly"] else " once the settlement is in close-only"))
    if refundable and not state["closeOnly"]:
        outlook = close_only_outlook(reader, state, head)
        if outlook["available_now"]:
            out("close-only can be triggered now by anyone:")
            out("  " + chain.cast_send(state["settlement"], "triggerCloseOnly()", []))
        elif outlook["earliest"] is not None:
            block, reason = outlook["earliest"]
            when = f"from block {block}" if block > head + 1 else "from the next block"
            out(f"close-only cannot be triggered yet; {when} ({reason})")
        else:
            out("close-only cannot be triggered yet")
    for d in refundable:
        recipient = (to or d["from"]).lower()
        args = [d["id"], d["from"], d["ownerCommit"], d["amount"], recipient]
        if state["closeOnly"]:
            sender = d["from"] if recipient != d["from"] else None
            result = reader.simulate(vault, REFUND_SIGNATURE, *args, sender=sender)
            if result is not None:
                out(f"deposit {d['id']} refund would revert now: {VAULT_ERRORS.get(result, result or 'no reason')}")
                failed = True
                continue
        when = "" if state["closeOnly"] else ", after close-only"
        who = f"only {d['from']} may send this one" if recipient != d["from"] else "anyone may send it"
        out(f"refund deposit {d['id']} to {recipient} ({who}{when}):")
        out("  " + chain.cast_send(vault, REFUND_SIGNATURE, args))
    return 0 if refundable and not failed else 1


def main(argv=None, rpc_factory=chain.HttpRPC):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rpc", required=True, help="read-only RPC URL of the vault's chain")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--vault", help="CollateralVault address")
    target.add_argument("--settlement", help="DarkPerpSettlement address (its paired vault is used)")
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--tx", help="hash of the deposit transaction")
    which.add_argument("--id", type=int, action="append", dest="ids", help="deposit id (repeatable)")
    which.add_argument("--from", dest="payer", help="payer address: check all its unconsumed deposits")
    parser.add_argument("--to", help="refund recipient other than the payer (the payer must then send it)")
    parser.add_argument("--chain-id", type=int, help="refuse unless the RPC serves this chain")
    parser.add_argument("--max-scan", type=int, default=MAX_SCAN, help="unconsumed ids to scan with --from")
    args = parser.parse_args(argv)
    try:
        chain.plain_rpc(args.rpc)
        for name in ("vault", "settlement", "payer", "to"):
            value = getattr(args, name)
            if value is not None and not chain.ADDRESS.fullmatch(value):
                raise ValueError(f"--{'from' if name == 'payer' else name} must be a 20-byte 0x address")
        if args.tx is not None and not chain.DIGEST.fullmatch(args.tx):
            raise ValueError("--tx must be a 32-byte 0x transaction hash")
        if any(i < 0 or i >= 1 << 64 for i in args.ids or ()):
            raise ValueError("--id must fit uint64")
        if args.max_scan <= 0:
            raise ValueError("--max-scan must be positive")
    except ValueError as error:
        parser.error(str(error))
    rpc = rpc_factory(args.rpc)
    try:
        chain_id = chain.quantity(rpc("eth_chainId", []))
        if args.chain_id is not None and chain_id != args.chain_id:
            print(f"FAILED: the RPC serves chain {chain_id}, not {args.chain_id}")
            return 1
        vault = args.vault.lower() if args.vault else None
        if vault is None:
            vault = chain.Reader(rpc).address(args.settlement.lower(), "vault()")
            if int(vault, 16) == 0:
                print("FAILED: the settlement has no vault")
                return 1
        return check(rpc, vault, tx=args.tx, ids=args.ids or (), payer=args.payer.lower() if args.payer else None,
                     to=args.to, max_scan=args.max_scan, out=chain.noting_rpc_url(print))
    except chain.ChainError as error:
        print(f"FAILED: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
