"""claim_withdrawal: operator-free verification of a saved claim bundle.

Keccak vectors come from Foundry `cast keccak`; withdrawal leaves from
`cast keccak $(cast abi-encode --packed ...)` (same values the gateway's Rust
tests pin). Tree vectors are shared with the gateway test
`withdrawals::tests::claim_tool_vectors_match_rust_tree`.
"""
import io
import json
import os
import stat
import tempfile
import textwrap
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

import claim_withdrawal as cw

HERE = Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "fixtures" / "withdrawal-vectors.json").read_text())
VAULT = "0x57e951F6a378E00e4F1b26510380E089D7c07b8B"


class Keccak(unittest.TestCase):
    def test_matches_cast_across_the_rate_boundary(self):
        for data, digest in [
            (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
            (b"a" * 135, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"),
            (b"a" * 136, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
            (b"a" * 137, "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"),
            (b"a" * 200, "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"),
        ]:
            self.assertEqual(cw.keccak256(data).hex(), digest, len(data))


class Leaf(unittest.TestCase):
    def test_leaf_matches_solidity_abi_encode_packed(self):
        self.assertEqual(
            cw.withdrawal_leaf("0x000000000000000000000000000000000000A11c", 2_000_000_000, 7).hex(),
            "23364960683ed6fd90133ecd0211d3fdf2945779e400729471f69c45cb699932",
        )
        self.assertEqual(
            cw.withdrawal_leaf("0x" + "00" * 20, 1, 1).hex(),
            "4e641f195fa577e5e909e012d9b75354bf06ec15a5d1aa2dca05d496c62ab460",
        )


class Tree(unittest.TestCase):
    def test_shared_vectors_root_and_every_proof(self):
        self.assertGreaterEqual(len(VECTORS["trees"]), 4)
        for tree in VECTORS["trees"]:
            leaves = [cw.withdrawal_leaf(w["to"], int(w["amount"]), w["nonce"]) for w in tree["withdrawals"]]
            self.assertEqual(["0x" + l.hex() for l in leaves], tree["leaves"])
            self.assertEqual("0x" + cw.merkle_root(leaves).hex(), tree["root"])
            for i, leaf in enumerate(leaves):
                proof = cw.merkle_proof(leaves, i)
                self.assertEqual(["0x" + p.hex() for p in proof], tree["proofs"][i])
                self.assertTrue(cw.verify(cw.merkle_root(leaves), leaf, proof))

    def test_tampering_breaks_verification(self):
        tree = VECTORS["trees"][-1]
        root = bytes.fromhex(tree["root"][2:])
        leaf = bytes.fromhex(tree["leaves"][1][2:])
        proof = [bytes.fromhex(p[2:]) for p in tree["proofs"][1]]
        self.assertTrue(cw.verify(root, leaf, proof))
        flipped = bytearray(proof[0]); flipped[0] ^= 1
        self.assertFalse(cw.verify(root, leaf, [bytes(flipped)] + proof[1:]))
        self.assertFalse(cw.verify(root, leaf, proof + [proof[0]]))
        self.assertFalse(cw.verify(root, bytes(32), proof))


def bundle_from_tree(tree_index=-1, i=1, **overrides):
    tree = VECTORS["trees"][tree_index]
    w = tree["withdrawals"][i]
    bundle = {
        "schema": "arcora.claim-bundle.v1",
        "chainId": 84532,
        "vault": VAULT,
        "to": w["to"],
        "amount": w["amount"],
        "nonce": w["nonce"],
        "leaf": tree["leaves"][i],
        "root": tree["root"],
        "proof": tree["proofs"][i],
        "createdAt": "2026-10-16T12:00:00Z",
    }
    bundle.update(overrides)
    return bundle


class Bundle(unittest.TestCase):
    def test_valid_bundle_checks_offline(self):
        self.assertEqual(cw.check_bundle(bundle_from_tree()), [])

    def test_each_corruption_is_reported(self):
        for name, overrides in [
            ("leaf", {"leaf": "0x" + "11" * 32}),
            ("amount", {"amount": "1"}),
            ("root", {"root": "0x" + "22" * 32}),
            ("proof", {"proof": []}),
        ]:
            with self.subTest(name):
                self.assertNotEqual(cw.check_bundle(bundle_from_tree(**overrides)), [])

    def test_malformed_fields_are_refused_before_hashing(self):
        for overrides in [
            {"schema": "other"}, {"to": "0x1234"}, {"vault": "not-an-address"},
            {"amount": "-1"}, {"amount": 5}, {"nonce": -1}, {"nonce": "3"},
            {"proof": ["0xzz"]}, {"chainId": "84532"}, {"root": "0x" + "00" * 32},
        ]:
            with self.subTest(overrides):
                with self.assertRaises(cw.BundleError):
                    cw.parse_bundle(bundle_from_tree(**overrides))

    def test_cast_command_has_no_key_and_exact_arguments(self):
        b = cw.parse_bundle(bundle_from_tree())
        cmd = cw.cast_command(b, "https://sepolia.base.org")
        self.assertTrue(cmd.startswith(f'cast send {VAULT} "claim(address,uint256,uint256,bytes32,bytes32[])" '))
        self.assertIn(f'"[{",".join(b["proof"])}]"', cmd)
        self.assertIn("--rpc-url https://sepolia.base.org", cmd)
        self.assertIn("<YOUR_SIGNER>", cmd)


# The wind-down reserve leaf as the gateway publishes it (the POST /v1/admin/wind-down
# `reserveSink` and the status read-out, which adds `claimable`): the only leaf of
# its batch, so its root is the leaf itself and its proof is empty. The vector is
# the one the gateway test `the_reserve_claim_data_is_a_claim_bundle` pins.
RESERVE_LEAF = "0x9b70005e6c1a4d420bac265b81fa429cd6fa2dae864e709fff695e4f5330ea3e"


def reserve_bundle(**overrides):
    bundle = {"schema": "arcora.claim-bundle.v1", "chainId": 84532, "vault": "0x" + "ab" * 20,
              "to": "0x" + "c0" * 20, "amount": "1234567", "nonce": 3, "leaf": RESERVE_LEAF,
              "root": RESERVE_LEAF, "proof": []}
    bundle.update(overrides)
    return bundle


class SingleLeafBundle(unittest.TestCase):
    def test_the_reserve_leaf_checks_with_an_empty_proof(self):
        self.assertEqual(cw.withdrawal_leaf("0x" + "c0" * 20, 1234567, 3).hex(), RESERVE_LEAF[2:])
        self.assertEqual(cw.check_bundle(reserve_bundle()), [])
        # The status read-out's extra `claimable` field is not part of the claim.
        self.assertEqual(cw.check_bundle(reserve_bundle(claimable=True)), [])
        self.assertEqual(cw.merkle_root([bytes.fromhex(RESERVE_LEAF[2:])]).hex(), RESERVE_LEAF[2:])

    def test_a_single_leaf_bundle_must_still_match_its_root_and_leaf(self):
        for name, overrides in (("root", {"root": "0x" + "22" * 32}), ("amount", {"amount": "1234566"}),
                                ("nonce", {"nonce": 4}), ("to", {"to": "0x" + "c1" * 20})):
            with self.subTest(name):
                self.assertNotEqual(cw.check_bundle(reserve_bundle(**overrides)), [])

    def test_the_cli_prints_the_claim_call_with_an_empty_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reserve.json"
            path.write_text(json.dumps(reserve_bundle(claimable=False)))
            out = io.StringIO()
            with redirect_stdout(out):
                code = cw.main([str(path)])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("1234567 base units to 0x" + "c0" * 20 + " (nonce 3)", out.getvalue())
        self.assertIn(f'cast send 0x{"ab" * 20} "claim(address,uint256,uint256,bytes32,bytes32[])" '
                      f'0x{"c0" * 20} 1234567 3 {RESERVE_LEAF} "[]"', out.getvalue())


FAKE_CAST = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    with open(os.environ["FAKE_CAST_LOG"], "a") as log:
        log.write(json.dumps(sys.argv[1:]) + "\\n")
    args = sys.argv[1:]
    if args[0] == "chain-id":
        print(os.environ.get("FAKE_CHAIN", "84532"))
    elif args[0] == "call" and args[2].startswith("rootPublished"):
        print(os.environ.get("FAKE_PUBLISHED", "true"))
    elif args[0] == "call" and args[2].startswith("claimed"):
        print(os.environ.get("FAKE_CLAIMED", "false"))
    else:
        sys.exit(2)
""")


class OnChain(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        fake = self.tmp / "cast"
        fake.write_text(FAKE_CAST)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.log = self.tmp / "cast.log"
        self.env = {"PATH": f"{self.tmp}{os.pathsep}{os.environ['PATH']}", "FAKE_CAST_LOG": str(self.log)}
        self.file = self.tmp / "bundle.json"
        self.file.write_text(json.dumps(bundle_from_tree()))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def run_cli(self, extra_env=None, rpc="https://rpc.example"):
        env = {**self.env, **(extra_env or {})}
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env), redirect_stdout(out):
            code = cw.main([str(self.file), "--rpc", rpc])
        return code, out.getvalue()

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_published_unclaimed_bundle_passes_with_read_only_calls(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0, out)
        self.assertIn("cast send", out)
        verbs = [c[0] for c in self.calls()]
        self.assertEqual(verbs, ["chain-id", "call", "call"])
        self.assertNotIn("send", verbs)

    def test_unpublished_root_fails(self):
        code, out = self.run_cli({"FAKE_PUBLISHED": "false"})
        self.assertEqual(code, 1)
        self.assertIn("not published", out)

    def test_wrong_chain_fails_before_vault_reads(self):
        code, out = self.run_cli({"FAKE_CHAIN": "8453"})
        self.assertEqual(code, 1)
        self.assertEqual([c[0] for c in self.calls()], ["chain-id"])

    def test_already_claimed_is_reported_not_failed(self):
        code, out = self.run_cli({"FAKE_CLAIMED": "true"})
        self.assertEqual(code, 0)
        self.assertIn("already claimed", out)

    def test_rpc_url_must_be_plain_http(self):
        with self.assertRaises(SystemExit):
            self.run_cli(rpc="https://user:pw@rpc.example")


class Files(unittest.TestCase):
    def test_export_all_array_is_checked_entry_by_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "all.json"
            path.write_text(json.dumps([bundle_from_tree(i=0), bundle_from_tree(i=1, amount="1")]))
            out = io.StringIO()
            with redirect_stdout(out):
                code = cw.main([str(path)])
        self.assertEqual(code, 1)
        self.assertIn("[1]", out.getvalue())


if __name__ == "__main__":
    unittest.main()
