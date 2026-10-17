"""refund_deposit: find and check uncredited deposits against a simulated vault.

The fake chain below models the vault and settlement rules the tool relies on
(deposit chain, consumed count, close-only triggers, refund checks); it is not
the contract. The deposit leaf/fold vector is the one CrossLayer.t.sol pins.
"""
import contextlib
import http.server
import io
import json
import threading
import unittest

import chain_read as chain
import refund_deposit as rd
from claim_withdrawal import keccak256

VAULT = "0x" + "a1" * 20
SETTLEMENT = "0x" + "a2" * 20
ALICE = "0x" + "a3" * 20
BOB = "0x" + "a4" * 20
CAROL = "0x" + "a5" * 20


def word(value):
    return chain.word(value)


class FakeChain:
    """A caller-owned model of one vault/settlement pair, answering JSON-RPC reads."""

    def __init__(self):
        self.chain_id = 84532
        self.head = 10_000
        self.deposits = []  # (from, commit, amount, block)
        self.consumed = 0
        self.close_only = False
        self.refunded = set()
        self.liveness = 100
        self.last_progress = 9_990
        self.batch_count = 1
        self.open_challenges = 0
        self.paired = True
        self.calls = []
        self.tampered_log = None

    def deposit(self, payer, amount, block, commit=None):
        commit = commit or "0x" + keccak256(f"{payer}{len(self.deposits)}".encode()).hex()
        self.deposits.append((payer, commit, amount, block))
        return len(self.deposits) - 1

    def tips(self):
        tips = [bytes(32)]
        for i, (payer, commit, amount, _) in enumerate(self.deposits):
            tips.append(rd.fold(tips[-1], rd.deposit_leaf(payer, commit, amount, i)))
        return tips

    def log(self, i):
        payer, commit, amount, block = self.deposits[i]
        if self.tampered_log == i:
            amount += 1
        return {"address": VAULT, "topics": [rd.DEPOSIT_TOPIC, "0x" + payer[2:].rjust(64, "0"), commit],
                "data": "0x" + word(amount) + word(i) + self.tips()[i + 1].hex(),
                "blockNumber": hex(block), "transactionHash": "0x" + format(i + 1, "064x"), "removed": False}

    def can_trigger(self):
        holds = self.batch_count or self.deposits or self.open_challenges
        stalled = bool(holds) and self.head - self.last_progress > self.liveness
        starved = (not stalled and len(self.deposits) > self.consumed
                   and self.head - self.deposits[self.consumed][3] > self.liveness)
        return stalled or starved

    def revert(self, name):
        raise chain.Reverted(chain.selector(name + "()"))

    def eth_call(self, tx, block):
        self.calls.append(tx)
        data, to = tx["data"], tx["to"]
        sel, args = data[:10], [data[10 + 64 * i:74 + 64 * i] for i in range((len(data) - 10) // 64)]
        ints = [int(a, 16) for a in args]
        n = len(self.deposits)
        if to == VAULT:
            table = {
                "settlement()": lambda: word(SETTLEMENT),
                "depositCount()": lambda: word(n),
                "depositMeta(uint64)": lambda: word(self.deposits[ints[0]][3] if ints[0] < n else 0) + word(0),
                "depositTipAt(uint64)": lambda: (self.tips()[ints[0]] if ints[0] <= n else bytes(32)).hex(),
                "depositRefunded(uint64)": lambda: word(ints[0] in self.refunded),
                rd.REFUND_SIGNATURE: lambda: self.refund(ints, args, tx),
            }
        elif to == SETTLEMENT:
            table = {
                "vault()": lambda: word(VAULT if self.paired else "0x" + "ee" * 20),
                "closeOnly()": lambda: word(self.close_only),
                "consumedDepositCount()": lambda: word(self.consumed),
                "livenessTimeoutBlocks()": lambda: word(self.liveness),
                "lastProgressBlock()": lambda: word(self.last_progress),
                "batchCount()": lambda: word(self.batch_count),
                "openChallengeCount()": lambda: word(self.open_challenges),
                "triggerCloseOnly()": lambda: "" if self.close_only or self.can_trigger() else self.revert("LivenessNotExpired"),
            }
        else:
            raise chain.Reverted(None)
        for signature, answer in table.items():
            if chain.selector(signature) == sel:
                return "0x" + answer()
        raise AssertionError(f"unexpected call {sel} to {to}")

    def refund(self, ints, args, tx):
        deposit_id, amount = ints[0], ints[3]
        payer, commit, to = "0x" + args[1][24:], "0x" + args[2], "0x" + args[4][24:]
        if not self.paired:
            self.revert("NotPaired")
        if not self.close_only:
            self.revert("NotCloseOnly")
        if deposit_id < self.consumed or deposit_id >= len(self.deposits):
            self.revert("NotRefundable")
        if deposit_id in self.refunded:
            self.revert("AlreadyRefunded")
        if to != payer and tx.get("from") != payer:
            self.revert("BadRefundRecipient")
        if self.deposits[deposit_id][:3] != (payer, commit, amount):
            self.revert("BadDepositPreimage")
        return ""

    def __call__(self, method, params):
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            return {"number": hex(self.head), "timestamp": hex(1_800_000_000)}
        if method == "eth_call":
            return self.eth_call(*params)
        if method == "eth_getLogs":
            (query,) = params
            block = int(query["fromBlock"], 16)
            assert query["toBlock"] == query["fromBlock"] and query["address"] == VAULT
            logs = [self.log(i) for i, d in enumerate(self.deposits) if d[3] == block]
            if len(query["topics"]) > 1:
                logs = [log for log in logs if log["topics"][1] == query["topics"][1]]
            return logs
        if method == "eth_getTransactionReceipt":
            index = int(params[0], 16) - 1
            if not 0 <= index < len(self.deposits):
                return {"status": "0x1", "logs": [{"address": "0x" + "99" * 20, "topics": [], "data": "0x"}]}
            return {"status": "0x1", "logs": [self.log(index)]}
        raise AssertionError("unexpected method " + method)


class Vectors(unittest.TestCase):
    def test_deposit_leaf_and_fold_match_the_cross_layer_vector(self):
        leaf = rd.deposit_leaf("0x" + "22" * 20, "0x" + "33" * 32, 1000, 0)
        self.assertEqual(rd.fold(bytes(32), leaf).hex(),
                         "fc3a11b391f25a5fd841529b4f9cf4d9b799696ca83139dc3662589dc84a011b")

    def test_event_topic_and_refund_selector(self):
        self.assertEqual(rd.DEPOSIT_TOPIC, "0xdf3f00354434921901d8a49f26c4b0e4a907d497e57f2e9478e9ba4ea43eb0f9")
        self.assertEqual(chain.selector(rd.REFUND_SIGNATURE), "0xb07e8ad3")
        self.assertEqual(chain.selector("triggerCloseOnly()"), "0xa6f5545a")
        self.assertEqual(chain.selector("depositMeta(uint64)"), "0xa496b413")


class Tool(unittest.TestCase):
    def setUp(self):
        self.chain = FakeChain()
        self.chain.deposit(ALICE, 5_000_000, 9_000)   # id 0, consumed below
        self.chain.deposit(BOB, 7_000_000, 9_100)     # id 1
        self.chain.deposit(ALICE, 10_000_000, 9_100)  # id 2, same block as id 1
        self.chain.deposit(ALICE, 3_000_000, 9_950)   # id 3
        self.chain.consumed = 1

    def run_tool(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rd.main(["--rpc", "https://rpc.example", *args], rpc_factory=lambda _url: self.chain)
        return code, out.getvalue()

    def test_close_only_refunds_every_unconsumed_deposit_of_the_payer(self):
        self.chain.close_only = True
        code, out = self.run_tool("--vault", VAULT, "--from", ALICE)
        self.assertEqual(code, 0, out)
        self.assertIn("deposit 2: 10000000 base units from " + ALICE + " is refundable\n", out)
        self.assertIn("deposit 3: 3000000 base units", out)
        self.assertNotIn("deposit 0", out)  # consumed ids are not scanned
        self.assertNotIn("deposit 1", out)  # another payer
        commit = self.chain.deposits[2][1]
        self.assertIn(f'cast send {VAULT} "{rd.REFUND_SIGNATURE}" 2 {ALICE} {commit} 10000000 {ALICE} '
                      "--rpc-url https://rpc.example <YOUR_SIGNER>", out)
        self.assertIn("(anyone may send it)", out)
        self.assertNotIn("triggerCloseOnly", out)
        # Every eth_call is pinned to the same block.
        refunds = [c for c in self.chain.calls if c["data"].startswith(chain.selector(rd.REFUND_SIGNATURE))]
        self.assertEqual(len(refunds), 2)

    def test_live_settlement_reports_when_close_only_can_be_triggered(self):
        # Progress 10 blocks ago; the oldest unconsumed deposit (id 1, block 9100) is starved.
        code, out = self.run_tool("--vault", VAULT, "--id", "1")
        self.assertEqual(code, 0, out)
        self.assertIn("is refundable once the settlement is in close-only", out)
        self.assertIn("close-only can be triggered now by anyone:", out)
        self.assertIn(f'cast send {SETTLEMENT} "triggerCloseOnly()" --rpc-url https://rpc.example', out)
        self.assertIn("after close-only", out)
        # Nothing waits long enough yet: the earliest block is reported instead.
        self.chain.consumed, self.chain.head = 3, 9_960
        code, out = self.run_tool("--vault", VAULT, "--id", "3")
        self.assertEqual(code, 0, out)
        self.assertIn("close-only cannot be triggered yet; from block 10051", out)
        self.assertIn("oldest unconsumed deposit", out)
        self.chain.last_progress = 9_900
        code, out = self.run_tool("--vault", VAULT, "--id", "3")
        self.assertIn("from block 10001 (no settlement progress", out)

    def test_credited_and_refunded_deposits_are_explained_not_refunded(self):
        self.chain.close_only = True
        code, out = self.run_tool("--vault", VAULT, "--id", "0")
        self.assertEqual(code, 1)
        self.assertIn("deposit 0: 5000000 base units from " + ALICE + " is credited by the settled state", out)
        self.assertNotIn("cast send", out)
        self.chain.refunded.add(2)
        code, out = self.run_tool("--vault", VAULT, "--id", "2")
        self.assertEqual(code, 1)
        self.assertIn("was already refunded", out)

    def test_transaction_hash_locates_the_log(self):
        self.chain.close_only = True
        code, out = self.run_tool("--vault", VAULT, "--tx", "0x" + format(2, "064x"))
        self.assertEqual(code, 0, out)
        self.assertIn("deposit 1: 7000000 base units from " + BOB, out)
        code, out = self.run_tool("--vault", VAULT, "--tx", "0x" + format(99, "064x"))
        self.assertEqual(code, 1)
        self.assertIn("FAILED: the transaction has no Deposit log from this vault", out)

    def test_a_log_that_does_not_match_the_deposit_chain_fails(self):
        self.chain.close_only = True
        self.chain.tampered_log = 2
        code, out = self.run_tool("--vault", VAULT, "--id", "2")
        self.assertEqual(code, 1)
        self.assertIn("FAILED: the log does not match the vault's deposit chain", out)
        self.assertNotIn("cast send", out)

    def test_other_recipient_must_be_sent_by_the_payer(self):
        self.chain.close_only = True
        code, out = self.run_tool("--vault", VAULT, "--id", "2", "--to", CAROL)
        self.assertEqual(code, 0, out)
        self.assertIn(f"refund deposit 2 to {CAROL} (only {ALICE} may send this one)", out)
        refund = [c for c in self.chain.calls if c["data"].startswith(chain.selector(rd.REFUND_SIGNATURE))][-1]
        self.assertEqual(refund["from"], ALICE)

    def test_unpaired_vault_and_wrong_chain_fail_before_any_refund(self):
        self.chain.paired = False
        code, out = self.run_tool("--vault", VAULT, "--from", ALICE)
        self.assertEqual(code, 1)
        self.assertIn("not paired", out)
        self.chain.paired = True
        code, out = self.run_tool("--vault", VAULT, "--from", ALICE, "--chain-id", "8453")
        self.assertEqual(code, 1)
        self.assertIn("serves chain 84532, not 8453", out)

    def test_settlement_address_resolves_its_vault(self):
        self.chain.close_only = True
        code, out = self.run_tool("--settlement", SETTLEMENT, "--id", "3")
        self.assertEqual(code, 0, out)
        self.assertIn(f"vault {VAULT}, settlement {SETTLEMENT}", out)

    def test_missing_id_and_scan_bound(self):
        code, out = self.run_tool("--vault", VAULT, "--id", "9")
        self.assertEqual(code, 1)
        self.assertIn("deposit 9 does not exist", out)
        self.chain.close_only = True
        code, out = self.run_tool("--vault", VAULT, "--from", ALICE, "--max-scan", "2")
        self.assertIn("3 unconsumed deposits; checked the first 2", out)
        self.assertIn("deposit 2:", out)
        self.assertNotIn("deposit 3:", out)

    def test_refund_that_would_revert_is_reported_not_printed(self):
        self.chain.close_only = True
        self.chain.paired = True
        original = self.chain.refund
        self.chain.refund = lambda *a: self.chain.revert("TransferFailed")
        code, out = self.run_tool("--vault", VAULT, "--id", "2")
        self.chain.refund = original
        self.assertEqual(code, 1)
        self.assertIn("refund would revert now: TransferFailed", out)
        self.assertNotIn("cast send", out)

    def test_bad_arguments_are_refused(self):
        for args in (["--vault", "0x12", "--id", "1"], ["--vault", VAULT, "--tx", "0x12"],
                     ["--vault", VAULT, "--id", "-1"], ["--vault", VAULT], ["--id", "1"],
                     ["--vault", VAULT, "--settlement", SETTLEMENT, "--id", "1"],
                     ["--vault", VAULT, "--id", "1", "--from", ALICE]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.run_tool(*args)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            rd.main(["--rpc", "https://user:secret@rpc.example", "--vault", VAULT, "--id", "1"],
                    rpc_factory=lambda _url: self.chain)


class Handler(http.server.BaseHTTPRequestHandler):
    reply = None

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).last = request
        body = json.dumps(type(self).reply(request)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Transport(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/private-path-token"

    def test_read_call_and_revert_selector_over_real_http(self):
        Handler.reply = staticmethod(lambda r: {"jsonrpc": "2.0", "id": r["id"], "result": "0x" + word(7)})
        rpc = chain.HttpRPC(self.url)
        self.assertEqual(chain.Reader(rpc).uint(VAULT, "depositCount()"), 7)
        self.assertEqual(Handler.last["method"], "eth_call")
        self.assertEqual(Handler.last["params"][1], "latest")
        selector = chain.selector("NotCloseOnly()")
        Handler.reply = staticmethod(lambda r: {"jsonrpc": "2.0", "id": r["id"], "error": {
            "code": 3, "message": "execution reverted " + self.url, "data": selector}})
        self.assertEqual(chain.Reader(rpc).simulate(VAULT, "triggerCloseOnly()"), selector)

    def test_write_methods_bad_envelopes_and_provider_errors_fail_without_echo(self):
        rpc = chain.HttpRPC(self.url)
        with self.assertRaisesRegex(chain.ChainError, "read-only allowlist"):
            rpc("eth_sendRawTransaction", ["0x00"])
        for reply in ({"jsonrpc": "2.0", "id": 999, "result": "0x1"},
                      {"jsonrpc": "2.0", "id": None, "error": {"code": -32005, "message": self.url}}):
            Handler.reply = staticmethod(lambda r, reply=reply: {**reply, "id": reply["id"] or r["id"]})
            with self.subTest(reply=reply), self.assertRaises(chain.ChainError) as raised:
                rpc("eth_chainId", [])
            self.assertNotIn("private-path-token", str(raised.exception))
        # A rate limit on eth_call is a transport error, not a revert.
        Handler.reply = staticmethod(lambda r: {"jsonrpc": "2.0", "id": r["id"],
                                                "error": {"code": -32005, "message": "limit"}})
        with self.assertRaises(chain.ChainError) as raised:
            rpc("eth_call", [{"to": VAULT, "data": "0x"}, "latest"])
        self.assertNotIsInstance(raised.exception, chain.Reverted)

    def test_unreachable_endpoint_does_not_echo_the_url(self):
        self.server.server_close()
        rpc = chain.HttpRPC("http://127.0.0.1:9/private-path-token")
        with self.assertRaises(chain.ChainError) as raised:
            rpc("eth_chainId", [])
        self.assertNotIn("private-path-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
