"""challenge_inclusion: offline kit checks and each challenge stage against a simulated settlement.

Authorization A is the cross-layer vector CrossLayer.t.sol pins (fixture enclave
key, settlement 0x22..22, beneficiary 0x33..33, chain 84532). The fake settlement
answers that vector's digest as a constant, so the tool's own digest code is
checked against it rather than against itself.
"""
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest

import chain_read as chain
import challenge_inclusion as ci

SETTLEMENT = "0x" + "22" * 20
BENEFICIARY = "0x" + "33" * 20
STAKER = "0x" + "44" * 20
ENCLAVE = "0x4a62316623ad457f02cdc5d997ded67a383ec569"
ORDER = "0x0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5"
AUTH_A_DIGEST = "0xc97f5f187d95859ac2b5787fc5a2b4aaab47da927688f0b2038e0a03ff6f337d"
AUTH_A_SIG = ("0x490ce9b286399686afb9dfb81f58c2fa2622d492fb468f27682b22fc15ed8164"
              "4c1c3b569abd8431ff2e339bb14d1022a5ef5d58dad371b6cfe314ad28e41482" "1b")
AUTH_B_DIGEST = "0x72e7483a96cc46922628812fa90ac8351fb95784c7883861a34836b14f882225"
CAP = 1_000_000_000


def receipt():
    return {"orderHash": ORDER, "seqNo": 0, "recvTimeMs": 1000, "batchIdHint": 0, "windowId": 0,
            "signature": "0x" + "00" * 65, "enclaveSigner": ENCLAVE,
            "l1Challenge": {"chainId": 84532, "settlement": SETTLEMENT, "beneficiary": BENEFICIARY,
                            "signature": AUTH_A_SIG}}


def word(value):
    return chain.word(value)


class FakeSettlement:
    def __init__(self):
        self.head, self.timestamp = 500, 1_800_000_000
        self.abi_version = 3
        self.close_only = False
        self.resolved = False
        self.challenge = None  # dict(openedBlock, openBatchCount, beneficiary, bond)
        self.batch_count = 4
        self.close_only_batch_count = 0
        self.progress = 2
        self.grace = 50
        self.settled_at = {}
        self.bond = 50_000 * 10**6
        self.liveness = 100
        self.pending_usdc = {}
        self.pending_eth = {}
        self.calls = []

    def revert(self, name):
        raise chain.Reverted(chain.selector(name + "()"))

    def slash(self, sender):
        c = self.challenge
        if c is None:
            self.revert("NoSuchChallenge")
        target = c["openBatchCount"] + self.progress
        settled = self.close_only_batch_count if self.close_only else self.batch_count
        if settled < target:
            self.revert("NoProgress")
        expiry = self.settled_at.get(target - 1, 0) + self.grace
        if self.head <= expiry:
            self.revert("ChallengeNotExpired")
        if min(self.bond, CAP) < CAP and sender != BENEFICIARY:
            self.revert("ShortBondSlashRestricted")
        return ""

    def open(self, tx):
        if self.close_only:
            self.revert("InCloseOnly")
        if int(tx["value"], 16) != 10**16:
            self.revert("WrongChallengeBond")
        if self.timestamp < 1 + 3600:
            self.revert("NotRipe")
        return ""

    def __call__(self, method, params):
        if method == "eth_chainId":
            return hex(84532)
        if method == "eth_getBlockByNumber":
            return {"number": hex(self.head), "timestamp": hex(self.timestamp)}
        assert method == "eth_call", method
        tx, block = params
        assert block == hex(self.head)
        self.calls.append(tx)
        assert tx["to"] == SETTLEMENT
        data = tx["data"]
        sel, args = data[:10], [data[10 + 64 * i:74 + 64 * i] for i in range(min(6, (len(data) - 10) // 64))]
        c = self.challenge or {}
        table = {
            "ABI_VERSION()": lambda: word(self.abi_version),
            "enclaveSigner()": lambda: word(ENCLAVE),
            "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)": self.digest,
            "closeOnly()": lambda: word(self.close_only),
            "challengeResolved(bytes32)": lambda: word(self.resolved),
            "challenges(bytes32)": lambda: "".join(word(v) for v in (
                c.get("beneficiary", "0x00"), 0, c.get("openedBlock", 0), c.get("openBatchCount", 0),
                c.get("bond", 0), bool(c))),
            "challengeBond()": lambda: word(10**16),
            "inclusionDeadlineSecs()": lambda: word(3600),
            "progressBatches()": lambda: word(self.progress),
            "batchCount()": lambda: word(self.batch_count),
            "closeOnlyBatchCount()": lambda: word(self.close_only_batch_count),
            "challengeGraceBlocks()": lambda: word(self.grace),
            "batches(uint256)": lambda: word(1) * 3 + word(self.settled_at.get(int(args[0], 16), 0)),
            "sequencerBond()": lambda: word(self.bond),
            "slashPayoutCap()": lambda: word(CAP),
            "livenessTimeoutBlocks()": lambda: word(self.liveness),
            "pendingUsdc(address)": lambda: word(self.pending_usdc.get("0x" + args[0][24:], 0)),
            "pendingEth(address)": lambda: word(self.pending_eth.get("0x" + args[0][24:], 0)),
            "slashUnanswered(bytes32)": lambda: self.slash(tx.get("from")),
            ci.CHALLENGE_SIGNATURE: lambda: self.open(tx),
        }
        for signature, answer in table.items():
            if chain.selector(signature) == sel:
                return "0x" + answer()
        raise AssertionError("unexpected call " + sel)

    def digest(self):
        # Independent of the tool: the pinned vectors for the two known inputs.
        args = self.calls[-1]["data"][10:]
        if args[:64] == ORDER[2:] and args[-64:] == word(BENEFICIARY):
            return AUTH_A_DIGEST[2:]
        return "ab" * 32


class Offline(unittest.TestCase):
    def test_cross_layer_vectors(self):
        self.assertEqual(ci.CHALLENGE_AUTH_TAG.hex(), "69f32c88aac1254085ee4ba164b69f2f12fb02828e83d559eff228842bdcc42a")
        digest = ci.auth_digest(84532, SETTLEMENT, ORDER, 0, 1000, 0, BENEFICIARY)
        self.assertEqual("0x" + digest.hex(), AUTH_A_DIGEST)
        self.assertEqual("0x" + ci.auth_digest(84532, SETTLEMENT, "0x" + "12" * 32, 7, 123_456_789, 3,
                                               BENEFICIARY).hex(), AUTH_B_DIGEST)
        self.assertEqual(ci.recover(digest, bytes.fromhex(AUTH_A_SIG[2:])), ENCLAVE)
        self.assertEqual(chain.selector(ci.CHALLENGE_SIGNATURE), "0x7422b0ea")

    def test_recovery_matches_known_keys(self):
        # Private key 1 is the generator itself.
        self.assertEqual(ci.point_address(ci._G), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")

    def test_kit_parsing_accepts_receipts_and_tracked_orders(self):
        k = ci.parse_kit(receipt())
        self.assertEqual(ci.parse_kit({"id": "o1", "receipt": receipt()}), k)
        problems, digest, signer = ci.check_kit(k)
        self.assertEqual((problems, signer), ([], ENCLAVE))

    def test_changed_fields_do_not_verify_against_the_receipt_signer(self):
        for field, value in (("orderHash", "0x" + "12" * 32), ("seqNo", 1), ("recvTimeMs", 1001),
                             ("batchIdHint", 1)):
            raw = receipt()
            raw[field] = value
            with self.subTest(field=field):
                problems, _, signer = ci.check_kit(ci.parse_kit(raw))
                self.assertNotEqual(signer, ENCLAVE)
                self.assertTrue(problems)
        for field, value in (("chainId", 84533), ("settlement", "0x" + "23" * 20), ("beneficiary", STAKER)):
            raw = receipt()
            raw["l1Challenge"][field] = value
            with self.subTest(field=field):
                problems, _, signer = ci.check_kit(ci.parse_kit(raw))
                self.assertNotEqual(signer, ENCLAVE)
                self.assertTrue(problems)

    def test_non_canonical_signatures_are_refused(self):
        sig = bytes.fromhex(AUTH_A_SIG[2:])
        r, s = sig[:32], int.from_bytes(sig[32:64], "big")
        high_s = r + (ci._N - s).to_bytes(32, "big") + bytes([28])
        for bad in (high_s, sig[:64] + bytes([0]), sig[:64] + bytes([1]), bytes(32) + sig[32:]):
            raw = receipt()
            raw["l1Challenge"]["signature"] = "0x" + bad.hex()
            with self.subTest(sig=bad.hex()[-4:]):
                problems, _, signer = ci.check_kit(ci.parse_kit(raw))
                self.assertIsNone(signer)
                self.assertIn("not canonical", problems[0])

    def test_missing_or_malformed_kits(self):
        cases = [(lambda r: r.update(l1Challenge=None), "no bound deposit address"),
                 (lambda r: r.pop("l1Challenge"), "no l1Challenge field"),
                 (lambda r: r["l1Challenge"].update(beneficiary="0x" + "00" * 20), "beneficiary is zero"),
                 (lambda r: r["l1Challenge"].update(signature="0x12"), "65-byte"),
                 (lambda r: r.update(seqNo=-1), "seqNo"),
                 (lambda r: r.update(recvTimeMs=True), "recvTimeMs"),
                 (lambda r: r.update(orderHash="0x12"), "orderHash"),
                 (lambda r: r["l1Challenge"].update(chainId=0), "chainId")]
        for mutate, text in cases:
            raw = receipt()
            mutate(raw)
            with self.subTest(text=text), self.assertRaisesRegex(ci.KitError, text):
                ci.parse_kit(raw)

    def test_challenge_calldata_tail_is_the_signature(self):
        k = ci.parse_kit(receipt())
        encoded = ci.encode_challenge(k)
        self.assertEqual(len(encoded), 64 * 10)  # 6 head words, length, 3 padded signature words
        self.assertEqual(encoded[64 * 5:64 * 6], word(0xC0))
        self.assertEqual(int(encoded[64 * 6:64 * 7], 16), 65)
        self.assertEqual(encoded[64 * 7:64 * 7 + 130], AUTH_A_SIG[2:])


class Cli(unittest.TestCase):
    def setUp(self):
        self.chain = FakeSettlement()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def run_tool(self, kit, *args, rpc=True):
        path = os.path.join(self.temp.name, "kit.json")
        with open(path, "w") as stream:
            json.dump(kit, stream)
        out = io.StringIO()
        extra = ["--rpc", "https://rpc.example"] if rpc else []
        with contextlib.redirect_stdout(out):
            code = ci.main([path, *extra, *args], rpc_factory=lambda _url: self.chain)
        return code, out.getvalue()

    def test_offline_prints_the_challenge_call(self):
        code, out = self.run_tool(receipt(), rpc=False)
        self.assertEqual(code, 0, out)
        self.assertIn(f"kit OK: order {ORDER} authorized by {ENCLAVE} for beneficiary {BENEFICIARY}", out)
        self.assertIn(f'cast send {SETTLEMENT} "{ci.CHALLENGE_SIGNATURE}" {ORDER} 0 1000 0 {BENEFICIARY} '
                      f"{AUTH_A_SIG} --value <challengeBond()>", out)
        self.assertEqual(self.chain.calls, [])

    def test_ripe_challenge_is_simulated_with_the_stake_and_printed(self):
        code, out = self.run_tool(receipt(), "--staker", STAKER)
        self.assertEqual(code, 0, out)
        self.assertIn("open the challenge (anyone may send it with the 10000000000000000 wei stake):", out)
        self.assertIn("--value 10000000000000000 --rpc-url https://rpc.example <YOUR_SIGNER>", out)
        sent = [c for c in self.chain.calls if c["data"].startswith(chain.selector(ci.CHALLENGE_SIGNATURE))]
        self.assertEqual(sent[0]["from"], STAKER)
        self.assertEqual(sent[0]["value"], hex(10**16))

    def test_not_ripe_reports_the_time(self):
        self.chain.timestamp = 3000
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn("not ripe yet: it can be opened from unix time 3601 (601 s from now)", out)

    def test_chain_mismatches_fail(self):
        for attribute, value, text in (("abi_version", 2, "ABI_VERSION is 2"),):
            setattr(self.chain, attribute, value)
            code, out = self.run_tool(receipt())
            self.assertEqual(code, 1)
            self.assertIn(text, out)
        self.chain.abi_version = 3
        raw = receipt()
        raw["l1Challenge"]["chainId"] = 8453
        raw.pop("enclaveSigner")
        code, out = self.run_tool(raw)
        self.assertEqual(code, 1)
        self.assertIn("the RPC serves chain 84532, the kit is for chain 8453", out)
        raw = receipt()
        raw["l1Challenge"]["beneficiary"] = STAKER
        raw.pop("enclaveSigner")
        code, out = self.run_tool(raw)
        self.assertEqual(code, 1)
        self.assertIn("enclaveSigner did not sign", out)

    def test_close_only_and_resolved_states(self):
        self.chain.close_only = True
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn("no new challenge can be opened", out)
        self.assertIn("refund_deposit.py", out)
        self.chain.close_only, self.chain.resolved = False, True
        self.chain.pending_usdc[BENEFICIARY] = CAP
        self.chain.pending_eth[STAKER] = 10**16
        code, out = self.run_tool(receipt(), "--staker", STAKER)
        self.assertEqual(code, 0, out)
        self.assertIn("is resolved", out)
        self.assertIn("1000000000 USDC base units are credited to the beneficiary", out)
        self.assertIn(f'cast send {SETTLEMENT} "claimUsdc()"', out)
        self.assertIn(f"10000000000000000 wei of stake is credited to {STAKER}", out)

    def test_open_challenge_stages(self):
        self.chain.challenge = {"openedBlock": 300, "openBatchCount": 3, "beneficiary": BENEFICIARY, "bond": 10**16}
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn("waiting for 1 more settled batch(es)", out)
        self.chain.batch_count, self.chain.settled_at = 5, {4: 470}
        code, out = self.run_tool(receipt())
        self.assertIn("slashable after block 520 (20 blocks)", out)
        self.chain.head = 521
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn("anyone may send it; fine 1000000000 USDC base units", out)
        self.assertIn(f'cast send {SETTLEMENT} "slashUnanswered(bytes32)" {ORDER}', out)

    def test_short_bond_slash_is_left_to_the_beneficiary(self):
        self.chain.challenge = {"openedBlock": 300, "openBatchCount": 3, "beneficiary": BENEFICIARY, "bond": 10**16}
        self.chain.batch_count, self.chain.settled_at, self.chain.head = 5, {4: 470}, 521
        self.chain.bond = 400 * 10**6
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn("the fine is reduced to 400000000; only the beneficiary", out)
        self.assertIn("the submitter after block 620", out)
        self.assertIn("send it from the beneficiary", out)
        slash = [c for c in self.chain.calls if c["data"].startswith(chain.selector("slashUnanswered(bytes32)"))]
        self.assertEqual(slash[-1]["from"], BENEFICIARY)

    def test_stale_challenge_in_close_only_is_released(self):
        self.chain.challenge = {"openedBlock": 300, "openBatchCount": 3, "beneficiary": BENEFICIARY, "bond": 10**16}
        self.chain.close_only, self.chain.close_only_batch_count = True, 4
        code, out = self.run_tool(receipt())
        self.assertEqual(code, 0, out)
        self.assertIn(f'cast send {SETTLEMENT} "releaseStaleChallenge(bytes32)" {ORDER}', out)
        # Enough progress before close-only: the slash path still applies.
        self.chain.close_only_batch_count, self.chain.settled_at, self.chain.head = 5, {4: 470}, 521
        code, out = self.run_tool(receipt())
        self.assertIn("slashUnanswered", out)
        self.assertNotIn("releaseStaleChallenge", out)

    def test_array_input_reports_each_entry(self):
        bad = copy.deepcopy(receipt())
        bad["l1Challenge"] = None
        code, out = self.run_tool([receipt(), bad], rpc=False)
        self.assertEqual(code, 1)
        self.assertIn("[0] OK", out)
        self.assertIn("[1] FAILED: no L1 challenge authorization", out)


if __name__ == "__main__":
    unittest.main()
