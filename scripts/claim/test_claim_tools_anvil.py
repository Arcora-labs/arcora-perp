"""Opt-in owned-Anvil run of refund_deposit and challenge_inclusion on the real contracts.

Deploys the compiled DarkPerpSettlement, CollateralVault and MockUSDC (with the
MockClockVerifier test shim as the verifier) to a child Anvil on a loopback
port, then walks the gateway-free paths: open a challenge from a kit, let it go
unanswered and slash it, trigger close-only, and refund an uncredited deposit.
The enclave and gateway keys are generated per run and never written anywhere.

    ARCORA_RUN_CLAIM_ANVIL=1 python3 -m unittest discover -s scripts/claim -p test_claim_tools_anvil.py

ARCORA_CLAIM_ANVIL_EVIDENCE=PATH writes the tools' outputs to a fresh file.

Needs `anvil` and the contract artifacts from `forge build --root contracts`.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import select
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request

import chain_read as chain
import challenge_inclusion as ci
import refund_deposit as rd

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "contracts" / "out"


def keypair():
    key = secrets.randbelow(ci._N - 1) + 1
    return key, ci.point_address(ci._mul(key, ci._G))


def sign(key, digest):
    """Low-s secp256k1 signature `r||s||v` over a raw 32-byte digest (test helper)."""
    e = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(ci._N - 1) + 1
        point = ci._mul(k, ci._G)
        r = point[0] % ci._N
        s = pow(k, -1, ci._N) * (e + r * key) % ci._N
        if r and s:
            break
    parity = point[1] & 1
    if s > ci._N // 2:
        s, parity = ci._N - s, parity ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + parity])


@unittest.skipUnless(os.environ.get("ARCORA_RUN_CLAIM_ANVIL") == "1", "opt-in owned Anvil claim-tool run")
class ClaimToolsOnAnvil(unittest.TestCase):
    def start_anvil(self):
        process = subprocess.Popen(["anvil", "--host", "127.0.0.1", "--port", "0", "--chain-id", "31337"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threads = []

        def cleanup():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=5)
            process.stdout.close()
        self.addCleanup(cleanup)
        output, port, deadline = b"", None, time.monotonic() + 30
        while port is None and time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "owned Anvil exited before binding")
            if select.select([process.stdout], [], [], 0.1)[0]:
                output += os.read(process.stdout.fileno(), 8192)
                found = re.search(rb"Listening on 127\.0\.0\.1:(\d+)", output)
                port = int(found.group(1)) if found else None
        self.assertIsNotNone(port, "owned Anvil did not report its port")
        # Startup output lists development keys; it is drained and discarded.
        thread = threading.Thread(target=lambda: [None for _ in iter(lambda: process.stdout.read(8192), b"")],
                                  daemon=True)
        thread.start()
        threads.append(thread)
        return f"http://127.0.0.1:{port}"

    def raw_rpc(self, method, params):
        self.sequence += 1
        request = urllib.request.Request(self.url, data=json.dumps({"jsonrpc": "2.0", "id": self.sequence,
                                         "method": method, "params": params}).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
        self.assertNotIn("error", value, (method, value))
        return value["result"]

    def send(self, sender, to, data, value=0):
        tx = {"from": sender, "data": data, "gas": hex(10_000_000)}
        if to:
            tx["to"] = to
        if value:
            tx["value"] = hex(value)
        transaction = self.raw_rpc("eth_sendTransaction", [tx])
        for _ in range(200):
            receipt = self.raw_rpc("eth_getTransactionReceipt", [transaction])
            if receipt is not None:
                break
            time.sleep(0.05)
        self.assertIsNotNone(receipt, "owned local transaction was not mined")
        self.assertEqual(receipt["status"], "0x1", "owned local transaction reverted")
        return receipt

    def create(self, artifact, *args):
        code = json.loads((OUT / artifact).read_text())["bytecode"]["object"]
        code = code if code.startswith("0x") else "0x" + code
        return self.send(self.owner, None, code + "".join(chain.word(a) for a in args))["contractAddress"].lower()

    def call(self, to, signature, *args):
        return self.raw_rpc("eth_call", [{"to": to, "data": chain.calldata(signature, *args)}, "latest"])

    def run_tool(self, module, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = module.main(argv)
        self.transcript.append({"tool": module.__name__, "exit": code,
                                "output": out.getvalue().replace(self.url, "<RPC_URL>")})
        return code, out.getvalue()

    def settle(self, deposits):
        """One mock-verified batch consuming the first `deposits` deposits."""
        s = self.settlement
        prev = self.call(s, "currentStateRoot()")
        roots = [prev, "0x" + secrets.token_hex(32), "0x" + secrets.token_hex(32), "0x" + secrets.token_hex(32),
                 "0x" + "00" * 32, "0x" + "00" * 32, self.call(self.vault, "depositTipAt(uint64)", deposits)]
        commitment = self.call(s, "publicCommitment(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)", *roots)
        # settleBatch(9 params): seven roots, the count, then `bytes proof` (32 bytes) at 0x120.
        data = (chain.selector("settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)")
                + "".join(chain.word(v) for v in (*roots, deposits, 0x120, 32)) + commitment[2:])
        self.send(self.owner, s, data)

    def deposit(self, payer, amount):
        commit = "0x" + secrets.token_hex(32)
        valid_until = int(time.time()) + 3600
        digest = self.call(self.vault, "permitDigest(address,bytes32,uint256,uint64)", payer, commit, amount, valid_until)
        sig = sign(self.gateway_key, bytes.fromhex(digest[2:])).hex()
        data = (chain.selector("deposit(uint256,bytes32,uint64,bytes)")
                + "".join(chain.word(v) for v in (amount, commit, valid_until, 0x80, 65)) + sig + "0" * 62)
        self.send(payer, self.vault, data)
        return commit

    def test_challenge_slash_close_only_and_refund_without_the_gateway(self):
        self.sequence, self.transcript = 0, []
        evidence = os.environ.get("ARCORA_CLAIM_ANVIL_EVIDENCE")
        if evidence:
            self.assertFalse(Path(evidence).exists(), "evidence output must be fresh")
            self.addCleanup(lambda: Path(evidence).write_text(json.dumps(
                {"scope": "Owned local Anvil; real settlement, vault and MockUSDC with the MockClockVerifier "
                          "shim; per-run keys; no gateway, prover or public chain.",
                 "transcript": self.transcript}, indent=2) + "\n"))
        self.url = self.start_anvil()
        accounts = self.raw_rpc("eth_accounts", [])
        self.owner, alice, staker = accounts[0], accounts[3].lower(), accounts[4].lower()
        enclave_key, enclave = keypair()
        self.gateway_key, gateway = keypair()
        liveness, grace, bond_wei, cap = 40, 3, 10**16, 1_000 * 10**6
        mock = self.create("MockClockVerifier.sol/MockClockVerifier.json")
        self.settlement = self.create("DarkPerpSettlement.sol/DarkPerpSettlement.json",
                                      self.owner, enclave, mock, "0x" + "11" * 32, liveness, grace, bond_wei, 1,
                                      self.owner, 10, 2, cap)
        usdc = self.create("MockUSDC.sol/MockUSDC.json")
        self.vault = self.create("CollateralVault.sol/CollateralVault.json", self.settlement, usdc, gateway)
        s, v = self.settlement, self.vault
        self.send(self.owner, s, chain.calldata("setVault(address)", v))
        bond = 2_000 * 10**6
        self.send(self.owner, usdc, chain.calldata("mint(address,uint256)", self.owner, bond))
        self.send(self.owner, usdc, chain.calldata("approve(address,uint256)", s, bond))
        self.send(self.owner, s, chain.calldata("postBond(uint256)", bond))
        self.send(self.owner, usdc, chain.calldata("mint(address,uint256)", alice, 50 * 10**6))
        self.send(alice, usdc, chain.calldata("approve(address,uint256)", v, 50 * 10**6))
        self.deposit(alice, 10 * 10**6)
        uncredited = self.deposit(alice, 20 * 10**6)
        self.settle(1)
        rpc = ["--rpc", self.url]

        # Before close-only: deposit 1 is refundable once close-only starts, which it cannot yet.
        code, out = self.run_tool(rd, [*rpc, "--vault", v, "--from", alice])
        self.assertEqual(code, 0, out)
        self.assertIn("deposit 1: 20000000 base units from " + alice + " is refundable once", out)
        self.assertIn("close-only cannot be triggered yet", out)

        # A kit as the gateway would issue it, signed by this run's enclave key.
        order = "0x" + secrets.token_hex(32)
        digest = ci.auth_digest(31337, s, order, 0, 1000, 0, alice)
        on_chain = self.call(s, "challengeAuthDigest(bytes32,uint64,uint64,uint64,address)", order, 0, 1000, 0, alice)
        self.assertEqual(on_chain, "0x" + digest.hex())
        kit = {"orderHash": order, "seqNo": 0, "recvTimeMs": 1000, "batchIdHint": 0, "windowId": 0,
               "enclaveSigner": enclave, "l1Challenge": {"chainId": 31337, "settlement": s, "beneficiary": alice,
                                                         "signature": "0x" + sign(enclave_key, digest).hex()}}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "kit.json")
            Path(path).write_text(json.dumps(kit))
            code, out = self.run_tool(ci, [path, *rpc, "--staker", staker])
            self.assertEqual(code, 0, out)
            self.assertIn("open the challenge", out)
            self.send(staker, s, chain.selector(ci.CHALLENGE_SIGNATURE) + ci.encode_challenge(ci.parse_kit(kit)),
                      value=bond_wei)
            code, out = self.run_tool(ci, [path, *rpc])
            self.assertIn("waiting for 2 more settled batch(es)", out)
            self.settle(1)
            self.settle(1)
            code, out = self.run_tool(ci, [path, *rpc])
            self.assertIn("unanswered so far; slashable after block", out)
            self.raw_rpc("anvil_mine", [hex(grace + 1)])
            code, out = self.run_tool(ci, [path, *rpc])
            self.assertEqual(code, 0, out)
            self.assertIn("anyone may send it; fine 1000000000 USDC base units", out)
            self.send(self.owner, s, chain.calldata("slashUnanswered(bytes32)", order))
            code, out = self.run_tool(ci, [path, *rpc, "--staker", staker])
            self.assertEqual(code, 0, out)
            self.assertIn("is resolved", out)
            self.assertIn("1000000000 USDC base units are credited to the beneficiary", out)
            self.assertIn(f"10000000000000000 wei of stake is credited to {staker}", out)

        # No progress for the liveness window: anyone may trigger close-only, then refund.
        self.raw_rpc("anvil_mine", [hex(liveness + 2)])
        code, out = self.run_tool(rd, [*rpc, "--settlement", s, "--from", alice])
        self.assertEqual(code, 0, out)
        self.assertIn("close-only can be triggered now by anyone", out)
        self.send(staker, s, chain.calldata("triggerCloseOnly()"))
        code, out = self.run_tool(rd, [*rpc, "--vault", v, "--from", alice])
        self.assertEqual(code, 0, out)
        self.assertIn("deposit 1: 20000000 base units from " + alice + " is refundable\n", out)
        self.assertIn(uncredited, out)
        before = int(self.call(usdc, "balanceOf(address)", alice), 16)
        self.send(staker, v, chain.calldata(rd.REFUND_SIGNATURE, 1, alice, uncredited, 20 * 10**6, alice))
        self.assertEqual(int(self.call(usdc, "balanceOf(address)", alice), 16) - before, 20 * 10**6)
        code, out = self.run_tool(rd, [*rpc, "--vault", v, "--id", "1"])
        self.assertEqual(code, 1)
        self.assertIn("was already refunded", out)
        code, out = self.run_tool(rd, [*rpc, "--vault", v, "--id", "0"])
        self.assertIn("is credited by the settled state", out)


if __name__ == "__main__":
    unittest.main()
