"""The browser's challenge-kit file is what scripts/claim/challenge_inclusion.py checks.

frontend/src/domain/challengeKit.ts builds the `kit` in
fixtures/challenge-kit-vectors.json from its `acceptReceipt` (pinned by
challengeKit.test.ts). Here that same file goes through the gateway-free tool:
offline it verifies against authorization A (the vector pinned in
crates/gateway/src/challenge_auth.rs and contracts/test/CrossLayer.t.sol), every
tampered field fails, and through a read-only RPC the tool prints the
`challengeInclusion` call with the stake and a signer placeholder, or reports
that the order is already resolved. The fake settlement answers the pinned
digest, so the tool's digest code is checked against the vector, not itself.
"""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "claim"))

import chain_read as chain  # noqa: E402
import challenge_inclusion as ci  # noqa: E402

with open(os.path.join(HERE, "fixtures", "challenge-kit-vectors.json")) as _stream:
    VECTORS = json.load(_stream)
KIT = VECTORS["kit"]
ENCLAVE = VECTORS["enclaveSigner"]
A, B = VECTORS["digestVectors"]
AUTH = KIT["l1Challenge"]
BOND = 10**16
RPC_LABEL = "https://rpc.example"


class FakeSettlement:
    """Read-only JSON-RPC for the settlement at authorization A's address."""

    def __init__(self):
        self.chain_id = A["chainId"]
        self.resolved = False
        self.methods = []

    def __call__(self, method, params):
        self.methods.append(method)
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            return {"number": hex(100), "timestamp": hex(1_800_000_000)}
        assert method == "eth_call", method
        tx = params[0]
        assert tx["to"] == A["settlement"]
        answers = {
            "ABI_VERSION()": chain.word(3),
            "enclaveSigner()": chain.word(ENCLAVE),
            "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)": A["digest"][2:],
            "closeOnly()": chain.word(False),
            "challengeResolved(bytes32)": chain.word(self.resolved),
            "challenges(bytes32)": chain.word(0) * 6,
            "challengeBond()": chain.word(BOND),
            "inclusionDeadlineSecs()": chain.word(3600),
            "pendingUsdc(address)": chain.word(0),
            "pendingEth(address)": chain.word(0),
        }
        if tx["data"].startswith(chain.selector(ci.CHALLENGE_SIGNATURE)):
            assert tx["value"] == hex(BOND), "the simulated challenge must carry the exact stake"
            return "0x"
        for signature, answer in answers.items():
            if tx["data"].startswith(chain.selector(signature)):
                return "0x" + answer
        raise AssertionError("unexpected call " + tx["data"][:10])


class Vectors(unittest.TestCase):
    def test_digests_and_signer_match_the_cross_layer_vectors(self):
        self.assertEqual("0x" + ci.CHALLENGE_AUTH_TAG.hex(), VECTORS["authTag"])
        for v in (A, B):
            digest = ci.auth_digest(v["chainId"], v["settlement"], v["orderHash"], v["seqNo"],
                                    v["recvTimeMs"], v["batchIdHint"], v["beneficiary"])
            self.assertEqual("0x" + digest.hex(), v["digest"], v["name"])
        digest = bytes.fromhex(A["digest"][2:])
        self.assertEqual(ci.recover(digest, bytes.fromhex(AUTH["signature"][2:])), ENCLAVE)

    def test_the_kit_is_the_accept_receipt_plus_schema(self):
        receipt = VECTORS["acceptReceipt"]
        fields = ("orderHash", "seqNo", "recvTimeMs", "batchIdHint", "enclaveSigner", "l1Challenge")
        for key in fields:
            self.assertEqual(KIT[key], receipt[key], key)
        self.assertEqual(KIT["schema"], "arcora.challenge-kit.v1")
        self.assertEqual(set(KIT), {"schema", *fields})


class BrowserKitThroughTheTool(unittest.TestCase):
    def setUp(self):
        self.chain = FakeSettlement()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def run_tool(self, kit, *args):
        path = os.path.join(self.temp.name, "arcora-challenge-84532-0-0c164689.json")
        with open(path, "w") as stream:
            json.dump(kit, stream, indent=2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = ci.main([path, *args], rpc_factory=lambda _url: self.chain)
        return code, out.getvalue()

    def test_offline_the_kit_verifies_and_the_call_is_printed(self):
        code, out = self.run_tool(KIT)
        self.assertEqual(code, 0, out)
        self.assertIn(f"kit OK: order {KIT['orderHash']} authorized by {ENCLAVE} "
                      f"for beneficiary {AUTH['beneficiary']}", out)
        self.assertIn(f'cast send {AUTH["settlement"]} "{ci.CHALLENGE_SIGNATURE}" {KIT["orderHash"]} 0 1000 0 '
                      f'{AUTH["beneficiary"]} {AUTH["signature"]} --value <challengeBond()> '
                      "--rpc-url <RPC_URL> <YOUR_SIGNER>", out)
        self.assertEqual(self.chain.methods, [])

    def test_export_all_is_an_array_checked_entry_by_entry(self):
        code, out = self.run_tool([KIT, KIT])
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count(" OK: order "), 2)
        broken = copy.deepcopy(KIT)
        broken["seqNo"] = 1
        code, out = self.run_tool([KIT, broken])
        self.assertEqual(code, 1)
        self.assertIn("[0] OK", out)
        self.assertIn("[1] FAILED", out)

    def test_every_tampered_field_fails(self):
        def set_field(path, value):
            def mutate(kit):
                target = kit
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return mutate

        sig = AUTH["signature"]
        flipped = sig[:20] + ("0" if sig[20] != "0" else "1") + sig[21:]
        cases = {
            "orderHash": set_field(["orderHash"], "0x" + "12" * 32),
            "seqNo": set_field(["seqNo"], 1),
            "recvTimeMs": set_field(["recvTimeMs"], 1001),
            "batchIdHint": set_field(["batchIdHint"], 1),
            "enclaveSigner": set_field(["enclaveSigner"], "0x" + "44" * 20),
            "chainId": set_field(["l1Challenge", "chainId"], 84533),
            "settlement": set_field(["l1Challenge", "settlement"], "0x" + "23" * 20),
            "beneficiary": set_field(["l1Challenge", "beneficiary"], "0x" + "34" * 20),
            "signature": set_field(["l1Challenge", "signature"], flipped),
            "no authorization": set_field(["l1Challenge"], None),
        }
        for name, mutate in cases.items():
            kit = copy.deepcopy(KIT)
            mutate(kit)
            with self.subTest(field=name):
                code, out = self.run_tool(kit)
                self.assertEqual(code, 1, out)
                self.assertIn("kit FAILED", out)
                self.assertNotIn("cast send", out)

    def test_rpc_prints_the_open_call_with_the_stake(self):
        code, out = self.run_tool(KIT, "--rpc", RPC_LABEL)
        self.assertEqual(code, 0, out)
        self.assertIn(f"settlement {AUTH['settlement']} on chain 84532", out)
        self.assertIn(f"open the challenge (anyone may send it with the {BOND} wei stake):", out)
        self.assertIn(f"--value {BOND} --rpc-url {RPC_LABEL} <YOUR_SIGNER>", out)
        self.assertTrue(set(self.chain.methods) <= chain.READ_METHODS)

    def test_rpc_reports_an_order_already_answered(self):
        self.chain.resolved = True
        code, out = self.run_tool(KIT, "--rpc", RPC_LABEL)
        self.assertEqual(code, 0, out)
        self.assertIn(f"the challenge for {KIT['orderHash']} is resolved", out)
        self.assertNotIn(ci.CHALLENGE_SIGNATURE, out)

    def test_rpc_on_another_chain_fails(self):
        self.chain.chain_id = 8453
        code, out = self.run_tool(KIT, "--rpc", RPC_LABEL)
        self.assertEqual(code, 1)
        self.assertIn("the RPC serves chain 8453, the kit is for chain 84532", out)


if __name__ == "__main__":
    unittest.main()
