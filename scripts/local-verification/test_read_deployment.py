"""Exercise deployment observations without a network connection or chain writes."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/local-verification/read_deployment.py"


class DeploymentObservationTests(unittest.TestCase):
    def observe(self, fail_getter=None, reorg=False):
        calls = []
        config = json.loads((ROOT / "contracts/deployments/base-sepolia.json").read_text())
        address = {name: item["address"] for name, item in config["contracts"].items()}
        bindings = {
            (address["DarkPerpSettlement"], "vault()"): address["CollateralVault"],
            (address["DarkPerpSettlement"], "verifier()"): address["SP1ZkVerifier"],
            (address["DarkPerpSettlement"], "sequencer()"): config["params"]["sequencer"],
            (address["DarkPerpSettlement"], "enclaveSigner()"): config["params"]["enclaveSigner"],
            (address["CollateralVault"], "settlement()"): address["DarkPerpSettlement"],
            (address["CollateralVault"], "token()"): address["MockUSDC"],
            (address["SP1ZkVerifier"], "gateway()"): config["contracts"]["SP1ZkVerifier"]["sp1VerifierGateway"],
        }
        def rpc(req, timeout):
            body = json.loads(req.data)
            method, params = body["method"], body["params"]
            calls.append((method, params))
            error = None
            if method == "eth_chainId": result = hex(config["chainId"])
            elif method == "eth_getBlockByNumber":
                result = {"number": "0x40", "hash": "0x" + ("bb" if reorg and params[0] != "finalized" else "aa") * 32}
            elif method == "eth_getCode": result = "0x6000"
            elif method == "eth_call":
                signature = params[0]["data"]
                if signature == fail_getter:
                    error = {"code": -32000, "message": "fixture unavailable"}
                raw = bindings.get((params[0]["to"], signature), "0x" + "0" * 64)
                result = "0x" + raw[2:].lower().rjust(64, "0")
            else: raise AssertionError(f"Unexpected RPC {method}")
            response = {"jsonrpc": "2.0", "id": body["id"]}
            response["error" if error else "result"] = error or result
            return io.BytesIO(json.dumps(response).encode())
        def cast(argv, **_):
            self.assertEqual(argv[0], "cast")
            return argv[2] if argv[1] == "sig" else "0x" + "cc" * 32
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "observation.json"
            with patch("sys.argv", [str(SCRIPT), "--output", str(out)]), \
                 patch("urllib.request.urlopen", rpc), \
                 patch("subprocess.check_output", cast), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as exit_context:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
            return json.loads(out.read_text()), calls, exit_context.exception.code

    def test_hash_pins_every_contract_read_and_checks_token_binding(self):
        result, calls, code = self.observe()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "OBSERVED")
        self.assertTrue(result["configured_bindings_match"])
        # An observed deployment is not automatically a matching release vkey.
        self.assertFalse(result["vkey_matches_local"])
        for method, params in calls:
            if method in ("eth_call", "eth_getCode"):
                self.assertEqual(params[-1], {"blockHash": "0x" + "aa" * 32, "requireCanonical": True})
        getters = [p[0]["data"] for m, p in calls if m == "eth_call"]
        self.assertIn("token()", getters)
        self.assertNotIn("asset()", getters)

    def test_failed_required_call_is_partial_and_never_success(self):
        result, _, code = self.observe(fail_getter="token()")
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["configured_bindings_match"])
        self.assertEqual(result["call_errors"][0]["getter"], "token()")

    def test_changed_finalized_hash_is_blocked(self):
        result, _, code = self.observe(reorg=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("finalized block changed", result["blocker"])


if __name__ == "__main__":
    unittest.main()
