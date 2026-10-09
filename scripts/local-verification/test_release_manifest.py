#!/usr/bin/env python3
"""Release preflight regressions; all deployments/configuration here are synthetic."""
import copy
import json
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import patch

import release_manifest as release


def config():
    addresses = {role: "0x" + format(i, "040x")
                 for i, role in enumerate(sorted(release.ADDRESS_ROLES), 1)}
    gateway = {env: addresses[role] for env, role in release.ENV_ADDRESSES.items()}
    gateway.update(L1_CHAIN_ID="31337", L1_ALLOW_MOCK_PROOF="0")
    return {"chain_id": 31337, "addresses": addresses, "program_vkey": release.clock.EXPECTED_VKEY,
            "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000}, "gateway": gateway,
            "prover": {"program_vkey": release.clock.EXPECTED_VKEY,
                       "guest_elf_sha256": release.clock.EXPECTED_ELF}}


class ConfigTests(unittest.TestCase):
    def test_matching_explicit_public_settings(self):
        self.assertEqual(release.public_config(config()), config())

    def test_old_deployment_key_is_rejected(self):
        path = release.ROOT / "contracts/deployments/base-sepolia.json"
        with self.assertRaisesRegex(ValueError, "does not match reviewed clock guest"):
            release.check_deployment_config(release.read_json(path))

    def test_legacy_stack_with_new_key_is_still_rejected(self):
        old = release.read_json(release.ROOT / "contracts/deployments/base-sepolia.json")
        old["contracts"]["SP1ZkVerifier"]["programVKey"] = release.clock.EXPECTED_VKEY
        with self.assertRaisesRegex(ValueError, "no clock verifier"):
            release.check_deployment_config(old)

    def test_old_prover_key_or_guest_cannot_be_mixed(self):
        for field in ("program_vkey", "guest_elf_sha256"):
            value = config()
            value["prover"][field] = ("0x" if field == "program_vkey" else "") + "ab" * 32
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "prover .* mismatch"):
                release.public_config(value)

    def test_wrong_gateway_chain_vault_or_clock_is_rejected(self):
        for field in ("L1_CHAIN_ID", "L1_VAULT", "CLOCK_BOUND_VERIFIER"):
            value = config()
            value["gateway"][field] = "1" if field == "L1_CHAIN_ID" else "0x" + "ab" * 20
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.public_config(value)

    def test_mock_mode_and_missing_explicit_mode_are_rejected(self):
        for mode in (None, "1", 0):
            value = config()
            if mode is None:
                value["gateway"].pop("L1_ALLOW_MOCK_PROOF")
            else:
                value["gateway"]["L1_ALLOW_MOCK_PROOF"] = mode
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                release.public_config(value)

    def test_zero_duplicate_and_malformed_addresses_are_rejected(self):
        for address in ("0x" + "0" * 40, config()["addresses"]["vault"], "0x1"):
            value = config()
            value["addresses"]["settlement"] = address
            with self.subTest(address=address), self.assertRaises(ValueError):
                release.public_config(value)

    def test_bad_types_and_unschedulable_clock_policy_are_rejected(self):
        for field, bad in (("chain_id", True), ("chain_id", 2**64), ("clock_skew_ms", 399),
                           ("max_window_ms", "30000"), ("max_window_ms", 2**64)):
            value = config()
            (value if field == "chain_id" else value["clock"])[field] = bad
            with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                release.public_config(value)

    def test_unknown_or_secret_config_keys_are_rejected_without_echo(self):
        value = config()
        value["gateway"]["L1_SEQUENCER_KEY"] = "sensitive-test-value"
        with self.assertRaises(ValueError) as raised:
            release.public_config(value)
        self.assertNotIn("sensitive-test-value", str(raised.exception))

    def test_process_environment_must_match_and_does_not_echo_secrets(self):
        value = release.public_config(config())
        env = dict(value["gateway"], L1_SEQUENCER_KEY="sensitive-test-value")
        release.check_environment(value, env)
        env["L1_CHAIN_ID"] = "sensitive-test-value"
        with self.assertRaisesRegex(ValueError, "process environment mismatch: L1_CHAIN_ID") as raised:
            release.check_environment(value, env)
        self.assertNotIn("sensitive-test-value", str(raised.exception))


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_path_traversal_absolute_and_parent_symlinks_are_rejected(self):
        for name in ("../outside", "/etc/passwd"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unsafe"):
                release.regular(self.root, name)
        (self.root / "source").mkdir()
        (self.root / "source/a.rs").write_text("hello")
        (self.root / "linked").symlink_to(self.root / "source", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            release.regular(self.root, "linked/a.rs")

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"program_vkey":"new","program_vkey":"old"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            release.read_json(path)

    def test_new_guest_source_and_build_inputs_require_new_provenance(self):
        source = self.root / "crates/sp1-guest/src/new.rs"
        source.parent.mkdir(parents=True)
        source.write_text("unreviewed guest code")
        with patch.object(release.clock, "EXPECTED_GUEST_SOURCES", {}):
            with self.assertRaisesRegex(ValueError, "source layout changed"):
                release.verify_reviewed_guest(self.root)
            source.unlink()
            (self.root / "crates/sp1-guest/build.rs").write_text("fn main() {}")
            with self.assertRaisesRegex(ValueError, "unreviewed guest build input"):
                release.verify_reviewed_guest(self.root)

    def make_artifact(self):
        source = self.root / "contracts/src/DarkPerpSettlement.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract DarkPerpSettlement {}")
        relative, name, compiler = release.CONTRACTS["settlement"]
        self.artifact_path = self.root / "contracts" / relative
        self.artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact = {"metadata": {"compiler": {"version": compiler},
                    "settings": {"optimizer": {"enabled": True, "runs": 200},
                                 "compilationTarget": {"src/DarkPerpSettlement.sol": name}},
                    "sources": {"src/DarkPerpSettlement.sol": {"keccak256": "0x" + "aa" * 32}}},
                    "bytecode": {"object": "0x123456"}, "deployedBytecode": {"object": "0x789abc"}}
        self.write_artifact(artifact)
        return artifact

    def write_artifact(self, artifact):
        self.artifact_path.write_text(json.dumps(artifact))

    @patch.object(release, "command", return_value="0x" + "aa" * 32)
    def test_compiled_artifact_binds_both_bytecodes(self, _command):
        self.make_artifact()
        result = release.compiled_contract(self.root, "settlement")
        self.assertEqual(result["creation_bytecode_sha256"], release.digest(bytes.fromhex("123456")))
        self.assertEqual(result["runtime_template_sha256"], release.digest(bytes.fromhex("789abc")))
        self.assertIn("not the deployed runtime", result["runtime_note"])

    @patch.object(release, "command", return_value="0x" + "bb" * 32)
    def test_stale_compiler_source_is_rejected(self, _command):
        self.make_artifact()
        with self.assertRaisesRegex(ValueError, "stale compiled source"):
            release.compiled_contract(self.root, "settlement")

    @patch.object(release, "command", return_value="0x" + "aa" * 32)
    def test_wrong_compiler_target_and_unlinked_bytecode_are_rejected(self, _command):
        original = self.make_artifact()
        for mutation in ("compiler", "target", "optimizer", "optimizer-type", "unlinked", "empty", "library"):
            artifact = copy.deepcopy(original)
            if mutation == "compiler":
                artifact["metadata"]["compiler"]["version"] = "0.8.20+commit.a1b79de6"
            elif mutation == "target":
                artifact["metadata"]["settings"]["compilationTarget"] = {"mock.sol": "MockZkVerifier"}
            elif mutation == "optimizer":
                artifact["metadata"]["settings"]["optimizer"]["runs"] = 1
            elif mutation == "optimizer-type":
                artifact["metadata"]["settings"]["optimizer"]["enabled"] = 1
            elif mutation == "library":
                artifact["bytecode"]["linkReferences"] = {"external.sol": {}}
            else:
                artifact["bytecode"]["object"] = "__$unlinked$__" if mutation == "unlinked" else "0x"
            self.write_artifact(artifact)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                release.compiled_contract(self.root, "settlement")

    def test_untracked_new_source_invalidates_inventory(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for name in ("Cargo.toml", "Cargo.lock", "contracts/foundry.toml", "crates/gateway/src/main.rs"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("source")
        before = release.source_inventory(self.root)
        (self.root / "crates/gateway/src/new.rs").write_text("new source")
        after = release.source_inventory(self.root)
        self.assertNotEqual(before, after)
        self.assertIn("crates/gateway/src/new.rs", after)

    def test_even_tracked_dotenv_and_credential_files_are_excluded(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        safe = ("Cargo.toml", "Cargo.lock", "contracts/foundry.toml", "crates/gateway/src/main.rs")
        private = ("crates/gateway/.env.json", "crates/gateway/private-keys.json",
                   "crates/gateway/credentials.toml", "crates/gateway/secrets.json")
        for name in safe + private:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("sensitive-test-value" if name in private else "source")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        inventory = release.source_inventory(self.root)
        self.assertEqual(set(inventory), set(safe))
        self.assertNotIn("sensitive-test-value", json.dumps(inventory))

    @patch.object(release, "build_manifest")
    def test_missing_fields_and_forged_readiness_do_not_pass(self, build):
        expected = {"schema": release.SCHEMA, "source": {"files_sha256": {"a": "123"}},
                    "compiled_contracts": {"settlement": "456"}, "scope": dict(release.SCOPE)}
        build.return_value = expected
        release.validate_manifest(self.root, expected, config())
        for field in ("source", "compiled_contracts", "scope"):
            bad = copy.deepcopy(expected)
            bad.pop(field)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "manifest mismatch"):
                release.validate_manifest(self.root, bad, config())
        bad = copy.deepcopy(expected)
        bad["scope"]["release_gate"] = "PASS"
        with self.assertRaisesRegex(ValueError, "manifest mismatch"):
            release.validate_manifest(self.root, bad, config())
        bad = copy.deepcopy(expected)
        bad["scope"]["target_chain_observed"] = 0
        self.assertEqual(bad, expected)  # Python equality alone would accept it.
        with self.assertRaisesRegex(ValueError, "manifest mismatch"):
            release.validate_manifest(self.root, bad, config())


class RuntimeTests(unittest.TestCase):
    def artifact(self):
        return {"deployedBytecode": {"object": "0x60" + "00" * 32 + "61" + "00" * 32 + "62",
                                    "immutableReferences": {"7": [{"start": 1, "length": 32},
                                                                  {"start": 34, "length": 32}]}}}

    def deployed(self):
        return b"\x60" + bytes.fromhex("ab" * 32) + b"\x61" + bytes.fromhex("ab" * 32) + b"\x62"

    def test_exact_runtime_including_consistent_immutable_substitution(self):
        result = release.runtime_identity(self.artifact(), self.deployed(), "test")
        self.assertEqual(result["runtime_sha256"], release.digest(self.deployed()))
        self.assertEqual(result["immutable_words_by_compiler_id"], {"7": "0x" + "ab" * 32})

    def test_changed_opcode_metadata_length_or_repeated_immutable_is_rejected(self):
        for offset in (0, 33, 34, 66):
            changed = bytearray(self.deployed())
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                release.runtime_identity(self.artifact(), changed, "test")
        with self.assertRaisesRegex(ValueError, "runtime size mismatch"):
            release.runtime_identity(self.artifact(), self.deployed() + b"\x00", "test")

    def test_malformed_overlapping_and_nonzero_placeholder_ranges_are_rejected(self):
        for locations in ([{"start": -1, "length": 32}], [{"start": 1, "length": True}],
                          [{"start": 1, "length": 64}], [{"start": 40, "length": 32}],
                          [{"start": 1, "length": 32}, {"start": 2, "length": 32}], []):
            artifact = self.artifact()
            artifact["deployedBytecode"]["immutableReferences"]["7"] = locations
            with self.subTest(locations=locations), self.assertRaises(ValueError):
                release.runtime_identity(artifact, self.deployed(), "test")
        artifact = self.artifact()
        artifact["deployedBytecode"]["object"] = "0x60" + "ab" * 32 + "61" + "00" * 32 + "62"
        with self.assertRaisesRegex(ValueError, "nonzero immutable placeholder"):
            release.runtime_identity(artifact, self.deployed(), "test")


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.public = config()
        self.addresses = self.public["addresses"]
        self.by_address = {value: role for role, value in self.addresses.items()}
        self.manifest = {"schema": release.SCHEMA, "public_config": self.public, "compiled_contracts": {}}
        for role, (relative, _, _) in release.CONTRACTS.items():
            path = self.root / "contracts" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"deployedBytecode": {"object": "0x606162"}}))
            self.manifest["compiled_contracts"][role] = {"sha256": release.digest(path.read_bytes())}
        self.head = {"number": "0x42", "hash": "0x" + "ab" * 32}
        self.calls = []
        self.overrides = {}
        self.values = {
            ("settlement", "verifier()"): self.addresses["clock_verifier"],
            ("settlement", "vault()"): self.addresses["vault"],
            ("vault", "settlement()"): self.addresses["settlement"],
            ("vault", "token()"): self.addresses["token"],
            ("clock_verifier", "settlement()"): self.addresses["settlement"],
            ("clock_verifier", "innerVerifier()"): self.addresses["sp1_adapter"],
            ("sp1_adapter", "gateway()"): self.addresses["sp1_gateway"],
            ("sp1_adapter", "programVKey()"): release.clock.EXPECTED_VKEY,
            ("clock_verifier", "maxWindowMs()"): 30000,
            ("clock_verifier", "clockSkewMs()"): 10000,
            ("clock_verifier", "proofVersion()"): 2,
            ("sp1_verifier", "VERIFIER_HASH()"): "0x" + release.clock.target.VERIFIER_HASH,
        }
        validator = patch.object(release, "validate_manifest", return_value=self.manifest)
        self.validate = validator.start()
        self.addCleanup(validator.stop)
        selector = patch.object(release.deployment_reader, "selector", side_effect=lambda name: name)
        selector.start()
        self.addCleanup(selector.stop)

    @staticmethod
    def word(value):
        return "0x" + (format(value, "064x") if type(value) is int else value[2:].rjust(64, "0"))

    def rpc(self, method, params):
        self.calls.append((method, params))
        if method in self.overrides:
            value = self.overrides[method]
            return value(params) if callable(value) else value
        if method == "eth_chainId":
            return "0x7a69"
        if method == "eth_getBlockByNumber":
            return dict(self.head)
        if method == "eth_getCode":
            return "0x606162"
        if method == "eth_call":
            role = self.by_address[params[0]["to"]]
            signature = params[0]["data"]
            if signature.startswith("routes(bytes4)"):
                self.assertEqual(signature, "routes(bytes4)" + release.clock.target.VERIFIER_HASH[:8] + "0" * 56)
                return self.word(self.addresses["sp1_verifier"]) + "0" * 64
            return self.word(self.values.get((role, signature), 1))
        self.fail("unexpected RPC method")

    def observe(self):
        return release.observe_target(self.root, self.manifest, self.public, self.rpc)

    def test_all_six_runtimes_bindings_route_and_one_finalized_hash_are_checked(self):
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertEqual(set(result["contracts"]), set(release.CONTRACTS))
        self.assertEqual(len(result["bindings"]), 12)
        self.assertEqual(result["scope"]["release_gate"], "HOLD")
        self.assertFalse(result["scope"]["operator_and_settlement_policy_approved"])
        self.assertFalse(result["scope"]["token_runtime_verified"])
        self.assertEqual(self.validate.call_count, 2)
        reads = [(method, params) for method, params in self.calls if method in {"eth_getCode", "eth_call"}]
        self.assertTrue(reads)
        self.assertTrue(all(params[-1] == {"blockHash": self.head["hash"], "requireCanonical": True}
                            for _, params in reads))
        self.assertEqual({method for method, _ in self.calls}, release.deployment_reader.READ_METHODS)

    def test_each_configured_address_key_clock_and_proof_version_mismatch_blocks(self):
        for key in list(self.values):
            original = self.values[key]
            self.values[key] = original + 1 if type(original) is int else "0x" + "ff" * ((len(original) - 2) // 2)
            with self.subTest(binding=key):
                result = self.observe()
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("target binding mismatch", result["blocker"])
                self.assertFalse(result["scope"]["runtime_bytecode_verified"])
            self.values[key] = original

    def test_missing_code_or_wrong_runtime_blocks(self):
        for code in ("0x", "0x606163", "0x60616200"):
            self.overrides["eth_getCode"] = code
            with self.subTest(code=code):
                self.assertEqual(self.observe()["status"], "BLOCKED")

    def test_wrong_chain_missing_finality_and_reorganization_have_no_latest_fallback(self):
        self.overrides["eth_chainId"] = "0x1"
        self.assertIn("chain_id mismatch", self.observe()["blocker"])
        self.overrides.clear()
        self.overrides["eth_getBlockByNumber"] = None
        self.assertEqual(self.observe()["status"], "BLOCKED")
        self.overrides["eth_getBlockByNumber"] = lambda params: (self.head if params[0] == "finalized"
                                                               else {**self.head, "hash": "0x" + "ff" * 32})
        self.assertIn("finalized block changed", self.observe()["blocker"])
        self.assertFalse(any(params[0] == "latest" for method, params in self.calls if method == "eth_getBlockByNumber"))

    def test_route_wrong_frozen_or_noncanonical_cannot_pass(self):
        original_rpc = self.rpc
        for route in (self.word(0) + "0" * 64,
                      self.word(self.addresses["sp1_verifier"]) + format(1, "064x"),
                      self.word(self.addresses["sp1_verifier"]) + format(2, "064x"),
                      "0x" + "ff" * 12 + self.addresses["sp1_verifier"][2:] + "0" * 64):
            def changed(method, params):
                if method == "eth_call" and params[0]["data"].startswith("routes(bytes4)"):
                    return route
                return original_rpc(method, params)
            with self.subTest(route=route):
                result = release.observe_target(self.root, self.manifest, self.public, changed)
                self.assertEqual(result["status"], "BLOCKED")

    def test_noncanonical_address_and_truncated_getter_are_rejected(self):
        for raw in ("0x" + "ff" * 32, "0x" + "00" * 31):
            self.overrides["eth_call"] = raw
            with self.subTest(raw=raw):
                self.assertEqual(self.observe()["status"], "BLOCKED")

    def test_changed_artifact_or_source_during_observation_blocks(self):
        self.manifest["compiled_contracts"]["settlement"]["sha256"] = "00" * 32
        self.assertIn("compiled artifact changed", self.observe()["blocker"])
        path = self.root / "contracts" / release.CONTRACTS["settlement"][0]
        self.manifest["compiled_contracts"]["settlement"]["sha256"] = release.digest(path.read_bytes())
        self.validate.side_effect = [self.manifest, ValueError("release manifest mismatch")]
        self.assertEqual(self.observe()["status"], "BLOCKED")

    def test_invalid_manifest_never_claims_local_identity_or_queries_rpc(self):
        self.validate.side_effect = ValueError("release manifest mismatch")
        result = self.observe()
        self.assertFalse(result["scope"]["local_identity_checked"])
        self.assertEqual(self.calls, [])

    def test_empty_token_code_blocks_but_token_runtime_is_never_approved(self):
        self.overrides["eth_getCode"] = lambda params: ("0x" if params[0] == self.addresses["token"] else "0x606162")
        result = self.observe()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("no token code", result["blocker"])

    def test_unconfigured_operator_policy_is_observed_without_approval(self):
        self.values[("settlement", "governance()")] = 0
        self.values[("settlement", "challengeBond()")] = 12345
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK")
        self.assertEqual(result["contracts"]["settlement"]["getters"]["governance()"], "0x" + "00" * 20)
        self.assertEqual(result["contracts"]["settlement"]["getters"]["challengeBond()"], 12345)
        self.assertFalse(result["scope"]["operator_and_settlement_policy_approved"])
        self.assertEqual(result["scope"]["release_gate"], "HOLD")

    def test_transport_failure_omits_private_response_text(self):
        def failed(method, params):
            raise OSError("private-provider-credential")
        result = release.observe_target(self.root, self.manifest, self.public, failed)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertNotIn("private-provider-credential", json.dumps(result))


class TransportTests(unittest.TestCase):
    def test_read_allowlist_precedes_transport_and_rejects_credential_urls(self):
        rpc = release.TargetRPC("https://example.invalid")
        with self.assertRaisesRegex(ValueError, "read-only allowlist"):
            rpc("eth_sendTransaction", [])
        for url in ("https://user:password@example.invalid", "https://example.invalid?key=private"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                release.TargetRPC(url)

    def test_bad_envelope_rpc_error_oversize_and_redirect_fail_closed(self):
        class Response:
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return self.body[:limit]
        cases = [b'{"jsonrpc":"2.0","id":true,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":2,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":1,"error":{"message":"private-provider-credential"}}',
                 b"private-provider-credential", b"x" * (release.deployment_reader.MAX_RPC_RESPONSE_BYTES + 1)]
        for body in cases:
            rpc = release.TargetRPC("https://example.invalid/private-provider-credential")
            with self.subTest(body=body[:80]), patch.object(rpc.opener, "open", return_value=Response(body)):
                with self.assertRaises(ValueError) as raised:
                    rpc("eth_chainId", [])
                self.assertNotIn("private-provider-credential", str(raised.exception))
        with self.assertRaisesRegex(ValueError, "redirects"):
            release.NoRedirect().redirect_request(None, None, 302, "", {}, "https://private.invalid")


@unittest.skipUnless(os.environ.get("ARCORA_RUN_MANIFEST_ANVIL") == "1", "opt-in owned Anvil integration")
class AnvilTargetTests(unittest.TestCase):
    def test_actual_deployed_stack_matches_then_frozen_route_fails(self):
        """Deploy only to a new child Anvil; no external URL or key is accepted."""
        # The child requests a kernel-assigned port and reports it after binding.
        # Reserving/closing a socket first could race an existing local service.
        process = subprocess.Popen(["anvil", "--host", "127.0.0.1", "--port", "0",
                                    "--chain-id", "31337"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        drain_thread = None
        def cleanup():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if drain_thread is not None:
                drain_thread.join(timeout=5)
            process.stdout.close()
        self.addCleanup(cleanup)
        output = b""
        port = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "owned Anvil failed before binding")
            if select.select([process.stdout], [], [], 0.1)[0]:
                output += os.read(process.stdout.fileno(), 8192)
                self.assertLess(len(output), 128 * 1024, "unexpected owned Anvil startup output")
                matched = re.search(rb"Listening on 127\.0\.0\.1:(\d+)", output)
                if matched:
                    port = int(matched.group(1))
                    break
        self.assertIsNotNone(port, "owned Anvil did not report its bound port")
        # Consume later mining logs without retaining or emitting startup keys.
        def drain_output():
            while process.stdout.read(8192):
                pass
        drain_thread = threading.Thread(target=drain_output, daemon=True)
        drain_thread.start()
        url = f"http://127.0.0.1:{port}"
        sequence = 0
        def local_rpc(method, params):
            nonlocal sequence
            sequence += 1
            request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": sequence,
                                             "method": method, "params": params}).encode(),
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:
                value = json.load(response)
            self.assertNotIn("error", value, value)
            return value["result"]
        for _ in range(100):
            self.assertIsNone(process.poll(), "owned Anvil failed before binding")
            try:
                accounts = local_rpc("eth_accounts", [])
                break
            except OSError:
                time.sleep(0.05)
        else:
            self.fail("owned Anvil did not start")
        owner = accounts[0]
        def word(value):
            return format(value, "064x") if type(value) is int else value.removeprefix("0x").rjust(64, "0")
        def transact(data, to=None):
            tx = {"from": owner, "data": data, "gas": "0x1c9c380"}
            if to:
                tx["to"] = to
            transaction = local_rpc("eth_sendTransaction", [tx])
            for _ in range(100):
                receipt = local_rpc("eth_getTransactionReceipt", [transaction])
                if receipt is not None:
                    break
                time.sleep(0.05)
            self.assertIsNotNone(receipt, "owned local transaction was not mined")
            self.assertEqual(receipt["status"], "0x1", receipt)
            return receipt
        def deploy(role, *args):
            relative = release.CONTRACTS[role][0] if role in release.CONTRACTS else "out/MockUSDC.sol/MockUSDC.json"
            artifact = release.read_json(release.ROOT / "contracts" / relative)
            return transact(artifact["bytecode"]["object"] + "".join(word(arg) for arg in args))["contractAddress"]
        addresses = {}
        addresses["sp1_verifier"] = deploy("sp1_verifier")
        addresses["sp1_gateway"] = deploy("sp1_gateway", owner)
        transact(release.deployment_reader.selector("addRoute(address)") + word(addresses["sp1_verifier"]), addresses["sp1_gateway"])
        addresses["sp1_adapter"] = deploy("sp1_adapter", addresses["sp1_gateway"], release.clock.EXPECTED_VKEY)
        addresses["clock_verifier"] = deploy("clock_verifier", addresses["sp1_adapter"], 30000, 10000)
        addresses["settlement"] = deploy("settlement", owner, accounts[1], addresses["clock_verifier"], 0, 100, 50, 1000, 600, owner, 10)
        addresses["token"] = deploy("token")
        addresses["vault"] = deploy("vault", addresses["settlement"], addresses["token"], accounts[2])
        transact(release.deployment_reader.selector("setVault(address)") + word(addresses["vault"]), addresses["settlement"])
        transact(release.deployment_reader.selector("bindSettlement(address)") + word(addresses["settlement"]), addresses["clock_verifier"])
        local_rpc("anvil_mine", ["0x80"])
        public = config()
        public["addresses"] = addresses
        public["gateway"].update({env: addresses[role] for env, role in release.ENV_ADDRESSES.items()})
        manifest = release.build_manifest(release.ROOT, public)
        observed = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url))
        self.assertEqual(observed["status"], "VERIFIED_AT_FINALIZED_BLOCK", observed)
        self.assertEqual(len(observed["contracts"]), 6)
        transact(release.deployment_reader.selector("freezeRoute(bytes4)") + release.clock.target.VERIFIER_HASH[:8] + "0" * 56,
                 addresses["sp1_gateway"])
        local_rpc("anvil_mine", ["0x80"])
        frozen = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url))
        self.assertEqual(frozen["status"], "BLOCKED", frozen)
        self.assertIn("wrong or frozen", frozen["blocker"])
        evidence = os.environ.get("ARCORA_MANIFEST_ANVIL_EVIDENCE")
        if evidence:
            Path(evidence).write_text(json.dumps({"scope": "Owned local Anvil; real compiled constructors and RPC, mock token, no proof submission or target deployment.",
                                                "pass": observed, "frozen_route_rejected": frozen}, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
