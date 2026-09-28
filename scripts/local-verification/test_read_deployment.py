"""Exercise deployment observations without a network connection or chain writes."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/local-verification/read_deployment.py"
HASH = "0x" + "aa" * 32
OTHER_HASH = "0x" + "bb" * 32
WITNESS = "https://independent.example"


class DeploymentObservationTests(unittest.TestCase):
    def observe(self, fail_getter=None, reorg=False, witness=None, change=None):
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
            endpoint = "primary" if req.full_url == config["rpc"] else "witness"
            method, params = body["method"], body["params"]
            calls.append((endpoint, method, params))
            error = None
            if method == "eth_chainId": result = hex(config["chainId"])
            elif method == "eth_getBlockByNumber":
                result = {"number": "0x40", "hash": OTHER_HASH if reorg and params[0] != "finalized" else HASH}
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
            if change:
                response = change(endpoint, method, params, response, calls)
            return io.BytesIO(json.dumps(response).encode())
        def cast(argv, **_):
            self.assertEqual(argv[0], "cast")
            return argv[2] if argv[1] == "sig" else "0x" + "cc" * 32
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "observation.json"
            argv = [str(SCRIPT), "--output", str(out)]
            if witness is not None:
                argv.extend(["--witness-rpc", witness])
            captured_stdout = io.StringIO()
            with patch("sys.argv", argv), patch("urllib.request.urlopen", rpc), \
                 patch("subprocess.check_output", cast), contextlib.redirect_stdout(captured_stdout):
                with self.assertRaises(SystemExit) as exit_context:
                    runpy.run_path(str(SCRIPT), run_name="__main__")
            self.last_stdout = captured_stdout.getvalue()
            return json.loads(out.read_text()), calls, exit_context.exception.code

    def assert_blocked(self, result, code, text):
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["rpc_agreement"]["status"], "BLOCKED")
        self.assertIn(text, result["blocker"])

    def test_hash_pins_every_contract_read_and_checks_token_binding(self):
        result, calls, code = self.observe()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["rpc_agreement"]["status"], "NOT_REQUESTED")
        self.assertTrue(result["configured_bindings_match"])
        # Observation and endpoint agreement do not imply a matching release vkey.
        self.assertFalse(result["vkey_matches_local"])
        for _, method, params in calls:
            if method in ("eth_call", "eth_getCode"):
                self.assertEqual(params[-1], {"blockHash": HASH, "requireCanonical": True})
        getters = [p[0]["data"] for _, m, p in calls if m == "eth_call"]
        self.assertIn("token()", getters)
        self.assertNotIn("asset()", getters)

    def test_single_endpoint_same_hash_wrong_height_is_blocked(self):
        def change(_, method, params, response, __):
            if method == "eth_getBlockByNumber" and params[0] != "finalized":
                response["result"]["number"] = "0x41"
            return response
        result, _, code = self.observe(change=change)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("wrong block height", result["blocker"])

    def test_single_endpoint_short_abi_word_is_partial(self):
        def change(_, method, params, response, __):
            if method == "eth_call" and params[0]["data"] == "batchCount()":
                response["result"] = "0x00"
            return response
        result, _, code = self.observe(change=change)
        self.assertNotEqual(code, 0)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["call_errors"][0]["getter"], "batchCount()")

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

    def test_two_endpoints_agree_on_every_pinned_read_and_recheck_headers(self):
        result, calls, code = self.observe(witness=WITNESS)
        self.assertEqual(code, 0)
        self.assertEqual(result["rpc_agreement"]["status"], "AGREED")
        self.assertTrue(result["configured_bindings_match"])
        self.assertFalse(result["vkey_matches_local"])
        self.assertIn("NOT_PROVEN", result["deployment_matches_local_source"])
        for endpoint in ("primary", "witness"):
            reads = [(method, params) for ep, method, params in calls
                     if ep == endpoint and method in ("eth_call", "eth_getCode")]
            self.assertEqual(len(reads), 19)
            for _, params in reads:
                self.assertEqual(params[-1], {"blockHash": HASH, "requireCanonical": True})
        self.assertEqual(calls[-2:], [("primary", "eth_getBlockByNumber", ["0x40", False]),
                                     ("witness", "eth_getBlockByNumber", ["0x40", False])])
        self.assertTrue(all(method in {"eth_chainId", "eth_getBlockByNumber", "eth_call", "eth_getCode"}
                            for _, method, _ in calls))

    def test_ahead_witness_uses_primary_anchor_not_a_mixed_newer_state(self):
        def change(ep, method, params, response, _):
            if ep == "witness" and method == "eth_getBlockByNumber" and params[0] == "finalized":
                response["result"] = {"number": "0x41", "hash": OTHER_HASH}
            return response
        result, calls, code = self.observe(witness=WITNESS, change=change)
        self.assertEqual(code, 0)
        self.assertEqual(result["rpc_agreement"]["witness_finalized_number"], 65)
        self.assertEqual(result["block_number"], 64)
        self.assertEqual(result["block_hash"], HASH)
        self.assertTrue(all(p[-1]["blockHash"] == HASH for _, m, p in calls if m in ("eth_call", "eth_getCode")))

    def test_wrong_witness_chain_blocks_before_contract_reads(self):
        def change(ep, method, _, response, __):
            if ep == "witness" and method == "eth_chainId": response["result"] = "0x1"
            return response
        result, calls, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "wrong chain")
        self.assertFalse(any(m == "eth_getCode" for _, m, _ in calls))

    def test_witness_finality_lag_does_not_fall_back_to_unfinalized_height(self):
        def change(ep, method, params, response, _):
            if ep == "witness" and method == "eth_getBlockByNumber" and params[0] == "finalized":
                response["result"]["number"] = "0x3f"
            return response
        result, calls, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "not yet finalized")
        self.assertFalse(any(m == "eth_getCode" for _, m, _ in calls))

    def test_witness_historical_header_disagreement_blocks(self):
        def change(ep, method, params, response, _):
            if ep == "witness" and method == "eth_getBlockByNumber" and params[0] != "finalized":
                response["result"]["hash"] = OTHER_HASH
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "anchor disagreement")

    def test_witness_conflicting_finalized_and_historical_header_blocks(self):
        def change(ep, method, params, response, _):
            if ep == "witness" and method == "eth_getBlockByNumber" and params[0] == "finalized":
                response["result"]["hash"] = OTHER_HASH
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "inconsistent finalized header")

    def test_historical_header_same_hash_wrong_number_is_not_accepted(self):
        for endpoint in ("primary", "witness"):
            with self.subTest(endpoint=endpoint):
                def change(ep, method, params, response, _):
                    if ep == endpoint and method == "eth_getBlockByNumber" and params[0] != "finalized":
                        response["result"]["number"] = "0x41"
                    return response
                result, _, code = self.observe(witness=WITNESS, change=change)
                self.assert_blocked(result, code, "wrong block height")

    def test_code_disagreement_at_same_anchor_blocks(self):
        def change(ep, method, _, response, __):
            if ep == "witness" and method == "eth_getCode": response["result"] = "0x6001"
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "code disagreement")

    def test_getter_disagreement_at_same_anchor_blocks(self):
        def change(ep, method, params, response, _):
            if ep == "witness" and method == "eth_call" and params[0]["data"] == "batchCount()":
                response["result"] = "0x" + "00" * 31 + "01"
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "getter disagreement")

    def test_witness_rpc_error_is_not_silently_a_single_endpoint_success(self):
        def change(ep, method, _, response, __):
            if ep == "witness" and method == "eth_call":
                response.pop("result")
                response["error"] = {"code": -32000, "message": "canonical hash unavailable"}
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "RPC error")

    def test_transport_failure_blocks_without_retry_or_fallback(self):
        def change(ep, method, _, response, __):
            if ep == "witness" and method == "eth_chainId": raise TimeoutError("fixture timeout")
            return response
        result, calls, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "TimeoutError")
        self.assertEqual(len([1 for ep, _, _ in calls if ep == "witness"]), 1)

    def test_canonical_change_after_reads_blocks_either_endpoint(self):
        for endpoint in ("primary", "witness"):
            with self.subTest(endpoint=endpoint):
                def change(ep, method, params, response, calls):
                    if ep == endpoint and method == "eth_getBlockByNumber" and params[0] != "finalized" \
                            and any(m == "eth_call" for _, m, _ in calls):
                        response["result"]["hash"] = OTHER_HASH
                    return response
                result, _, code = self.observe(witness=WITNESS, change=change)
                self.assert_blocked(result, code, f"{endpoint}: finalized block changed")

    def test_malformed_header_and_abi_data_fail_closed(self):
        cases = [("eth_getBlockByNumber", None),
                 ("eth_getBlockByNumber", {"number": "0x40", "hash": "0x12"}),
                 ("eth_getBlockByNumber", {"number": "0x040", "hash": HASH}),
                 ("eth_call", "0x"), ("eth_call", "0x" + "00" * 31),
                 ("eth_getCode", "0x00 00")]
        for rpc_method, value in cases:
            with self.subTest(method=rpc_method, value=value):
                def change(ep, method, _, response, __):
                    if ep == "witness" and method == rpc_method: response["result"] = value
                    return response
                result, _, code = self.observe(witness=WITNESS, change=change)
                self.assert_blocked(result, code, "ObservationError")

    def test_unbound_json_rpc_response_is_rejected(self):
        for alteration in ({"id": 99999}, {"id": True}, {"jsonrpc": "1.0"}):
            with self.subTest(alteration=alteration):
                def change(ep, _, __, response, ___):
                    if ep == "witness": response.update(alteration)
                    return response
                result, _, code = self.observe(witness=WITNESS, change=change)
                self.assert_blocked(result, code, "response envelope")

    def test_same_host_alias_is_not_an_independent_witness(self):
        for endpoint in ("https://SEPOLIA.BASE.ORG/other-path", "https://sepolia.base.org./"):
            with self.subTest(endpoint=endpoint):
                result, calls, code = self.observe(witness=endpoint)
                self.assert_blocked(result, code, "distinct endpoint host")
                self.assertEqual(calls, [])

    def test_explicit_empty_or_invalid_witness_cannot_disable_agreement(self):
        for endpoint in ("", " ", "file:///tmp/data", "https://independent.example:bad"):
            with self.subTest(endpoint=endpoint):
                result, calls, code = self.observe(witness=endpoint)
                self.assert_blocked(result, code, "ObservationError")
                self.assertEqual(calls, [])

    def test_oversized_rpc_response_is_blocked_before_hashing_or_logging_it(self):
        def change(ep, method, _, response, __):
            if ep == "witness" and method == "eth_getCode":
                response["result"] = "0x" + "aa" * (1024 * 1024)
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assert_blocked(result, code, "response exceeds size limit")
        self.assertLess(len(json.dumps(result)), 16 * 1024)

    def test_all_rpc_error_codes_fail_closed_even_with_a_result(self):
        for error_code in (-32700, -32601, -32602, -32000, -32001):
            with self.subTest(error_code=error_code):
                def change(ep, _, __, response, ___):
                    if ep == "witness":
                        response["error"] = {"code": error_code, "message": "fixture error"}
                    return response
                result, _, code = self.observe(witness=WITNESS, change=change)
                self.assert_blocked(result, code, "RPC error")

    def test_credential_bearing_witness_url_is_rejected_and_not_printed(self):
        for endpoint in ("https://secret:password@independent.example", "https://independent.example/?key=secret"):
            with self.subTest(endpoint=endpoint):
                result, calls, code = self.observe(witness=endpoint)
                self.assert_blocked(result, code, "anonymous public RPC")
                self.assertEqual(calls, [])
                self.assertNotIn("secret", json.dumps(result))

    def assert_no_path_token(self, result, token):
        self.assertNotIn(token, json.dumps(result))
        self.assertNotIn(token, self.last_stdout)

    def test_redaction_rpc_error_payload_and_error_code_never_echo_url_path(self):
        token = "private-fixture-token"
        url = WITNESS + "/" + token
        for error_code in (-32000, token):
            with self.subTest(error_code=error_code):
                def change(ep, method, _, response, __):
                    if ep == "witness" and method == "eth_call":
                        response["error"] = {"code": error_code, "message": url, "data": {"request": url}}
                    return response
                result, _, code = self.observe(witness=url, change=change)
                self.assert_blocked(result, code, "RPC error")
                self.assert_no_path_token(result, token)
                record = result["rpc_records"][-1]
                self.assertEqual(record["endpoint"], "witness")
                self.assertEqual(record["method"], "eth_call")
                self.assertEqual(record["error"]["code"], error_code if type(error_code) is int else None)

    def test_redaction_transport_exceptions_never_echo_url_path(self):
        token = "private-fixture-token"
        url = WITNESS + "/" + token
        failures = [TimeoutError(url), urllib.error.URLError(url),
                    urllib.error.HTTPError(url, 403, url, {}, None)]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                def change(ep, method, _, response, __):
                    if ep == "witness" and method == "eth_call": raise failure
                    return response
                result, _, code = self.observe(witness=url, change=change)
                self.assert_blocked(result, code, type(failure).__name__)
                self.assert_no_path_token(result, token)

    def test_redaction_invalid_url_port_never_echoes_supplied_value(self):
        token = "private-fixture-token"
        result, calls, code = self.observe(witness=WITNESS + ":" + token)
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, [])
        self.assert_no_path_token(result, token)

    def test_redaction_ignores_extra_fields_and_rejects_unvalidated_echoes(self):
        token = "private-fixture-token"
        for attack in ("extras", "invalid_result", "invalid_id"):
            with self.subTest(attack=attack):
                def change(ep, method, _, response, __):
                    if ep == "witness":
                        response["provider_debug"] = token
                        if attack == "extras" and method == "eth_getBlockByNumber":
                            response["result"]["provider_debug"] = token
                        elif attack == "invalid_result" and method == "eth_call":
                            response["result"] = token
                        elif attack == "invalid_id":
                            response["id"] = token
                    return response
                result, _, code = self.observe(witness=WITNESS + "/" + token, change=change)
                self.assertEqual(code, 0 if attack == "extras" else 1)
                self.assert_no_path_token(result, token)

    def test_nonzero_address_padding_does_not_match_a_configured_binding(self):
        def change(_, method, params, response, __):
            if method == "eth_call" and params[0]["data"] == "token()":
                response["result"] = "0x01" + response["result"][4:]
            return response
        result, _, code = self.observe(witness=WITNESS, change=change)
        self.assertEqual(code, 0)  # It is an agreed observation, explicitly not a binding match.
        self.assertEqual(result["rpc_agreement"]["status"], "AGREED")
        self.assertFalse(result["configured_bindings_match"])


if __name__ == "__main__":
    unittest.main()
