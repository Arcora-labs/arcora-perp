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

# Synthetic genesis values: none is a contract, operator or public dev address.
GENESIS_ROOT = "0x" + "4d" * 32
RECIPIENT = "0x" + "5a" * 20
ORACLE_SIGNER = "0x" + "6b" * 20


def config():
    addresses = {role: "0x" + format(i, "040x")
                 for i, role in enumerate(sorted(release.ADDRESS_ROLES), 1)}
    gateway = {env: addresses[role] for env, role in release.ENV_ADDRESSES.items()}
    gateway.update(L1_CHAIN_ID="31337", L1_ALLOW_MOCK_PROOF="0", DEPOSIT_PERMIT_TTL_SECS="1800",
                   WIND_DOWN_RECIPIENT=RECIPIENT, PROVER_EXPECTED_ELF_SHA256=release.clock.REVIEWED_GUEST["elf"])
    return {"chain_id": 31337, "addresses": addresses, "program_vkey": release.clock.REVIEWED_GUEST["vkey"],
            "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000, "anchor_timeout_ms": 3_600_000},
            "gateway": gateway,
            "prover": {"program_vkey": release.clock.REVIEWED_GUEST["vkey"],
                       "guest_elf_sha256": release.clock.REVIEWED_GUEST["elf"]},
            "genesis": {"root": GENESIS_ROOT, "wind_down_recipient": RECIPIENT, "oracle_signer": ORACLE_SIGNER}}


def operator_policy(address="0x" + "00" * 19 + "0a"):
    """A complete operator policy whose every address is `address`."""
    value = {role: {name: address for name in fields} for role, fields in release.OPERATOR_ADDRESSES.items()}
    value["settlement"].update({name: 1 for name in release.SETTLEMENT_POLICY})
    return value


class ConfigTests(unittest.TestCase):
    def test_matching_explicit_public_settings(self):
        self.assertEqual(release.public_config(config()), config())

    def test_old_deployment_key_is_rejected(self):
        path = release.ROOT / "contracts/deployments/base-sepolia.json"
        with self.assertRaisesRegex(ValueError, "does not match reviewed clock guest"):
            release.check_deployment_config(release.read_json(path))

    def test_legacy_stack_with_new_key_is_still_rejected(self):
        old = release.read_json(release.ROOT / "contracts/deployments/base-sepolia.json")
        old["contracts"]["SP1ZkVerifier"]["programVKey"] = release.clock.REVIEWED_GUEST["vkey"]
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
                           ("max_window_ms", "30000"), ("max_window_ms", 2**64),
                           ("anchor_timeout_ms", 999), ("anchor_timeout_ms", True),
                           ("anchor_timeout_ms", 2**64)):
            value = config()
            (value if field == "chain_id" else value["clock"])[field] = bad
            with self.subTest(field=field, value=bad), self.assertRaises(ValueError):
                release.public_config(value)
        value = config()
        value["clock"]["anchor_timeout_ms"] = release.MIN_ANCHOR_TIMEOUT_MS
        self.assertEqual(release.public_config(value)["clock"]["anchor_timeout_ms"], 1000)

    def test_clock_policy_requires_the_anchor_timeout(self):
        value = config()
        del value["clock"]["anchor_timeout_ms"]
        with self.assertRaisesRegex(ValueError, "clock policy"):
            release.public_config(value)
        value = config()
        value["clock"]["anchor_timeout"] = 3_600_000
        with self.assertRaisesRegex(ValueError, "clock policy"):
            release.public_config(value)

    def test_permit_ttl_is_part_of_the_public_gateway_config(self):
        value = config()
        del value["gateway"]["DEPOSIT_PERMIT_TTL_SECS"]
        with self.assertRaisesRegex(ValueError, "public gateway config"):
            release.public_config(value)
        for bad in ("0", "-1", "01", "1800 ", "", 1800, None, "18446744073709551616", "1e3"):
            value = config()
            value["gateway"]["DEPOSIT_PERMIT_TTL_SECS"] = bad
            with self.subTest(value=bad), self.assertRaises(ValueError):
                release.public_config(value)
        result = release.public_config(config())
        env = dict(result["gateway"])
        release.check_environment(result, env)
        env["DEPOSIT_PERMIT_TTL_SECS"] = "3600"
        with self.assertRaisesRegex(ValueError, "process environment mismatch: DEPOSIT_PERMIT_TTL_SECS"):
            release.check_environment(result, env)

    def test_settlement_policy_follows_the_twelve_word_constructor(self):
        self.assertEqual(list(release.SETTLEMENT_POLICY), [
            "liveness_timeout_blocks", "challenge_grace_blocks", "challenge_bond_wei",
            "inclusion_deadline_seconds", "final_settle_grace_blocks", "progress_batches",
            "slash_payout_cap_usdc"])
        self.assertNotIn("challengeWindowBlocks()", release.SETTLEMENT_POLICY.values())
        self.assertEqual(release.SETTLEMENT_ABI_VERSION, 3)

    def test_prover_expected_elf_is_the_reviewed_guest_elf(self):
        self.assertEqual(release.public_config(config())["gateway"]["PROVER_EXPECTED_ELF_SHA256"],
                         release.clock.REVIEWED_GUEST["elf"])
        value = config()
        del value["gateway"]["PROVER_EXPECTED_ELF_SHA256"]
        with self.assertRaisesRegex(ValueError, "public gateway config"):
            release.public_config(value)
        elf = release.clock.REVIEWED_GUEST["elf"]
        for bad in ("ab" * 32, "0x" + elf, elf.upper(), elf[:-1], "", None, 1):
            value = config()
            value["gateway"]["PROVER_EXPECTED_ELF_SHA256"] = bad
            with self.subTest(value=bad), self.assertRaisesRegex(ValueError, "PROVER_EXPECTED_ELF_SHA256"):
                release.public_config(value)

    def test_genesis_is_required_and_normalized(self):
        value = config()
        del value["genesis"]
        with self.assertRaisesRegex(ValueError, "public config"):
            release.public_config(value)
        for field in release.GENESIS_KEYS:
            value = config()
            del value["genesis"][field]
            with self.subTest(missing=field), self.assertRaisesRegex(ValueError, "genesis"):
                release.public_config(value)
        value = config()
        value["genesis"]["extra"] = "0x" + "01" * 20
        with self.assertRaisesRegex(ValueError, "genesis"):
            release.public_config(value)
        value = config()
        value["genesis"] = {"root": GENESIS_ROOT.upper().replace("0X", "0x"),
                            "wind_down_recipient": RECIPIENT.upper().replace("0X", "0x"),
                            "oracle_signer": ORACLE_SIGNER.upper().replace("0X", "0x")}
        self.assertEqual(release.public_config(value)["genesis"], config()["genesis"])

    def test_zero_or_malformed_genesis_values_are_rejected(self):
        for field, bad in (("root", "0x" + "00" * 32), ("root", "0x" + "4d" * 31), ("root", None),
                           ("wind_down_recipient", "0x" + "00" * 20), ("wind_down_recipient", "0x" + "5a" * 19),
                           ("oracle_signer", "0x" + "00" * 20), ("oracle_signer", 7)):
            value = config()
            value["genesis"][field] = bad
            if field == "wind_down_recipient" and isinstance(bad, str) and len(bad) == 42:
                value["gateway"]["WIND_DOWN_RECIPIENT"] = bad
            with self.subTest(field=field, value=bad), self.assertRaisesRegex(ValueError, "genesis"):
                release.public_config(value)

    def test_recipient_and_oracle_signer_are_independent_addresses(self):
        value = config()
        value["genesis"]["oracle_signer"] = RECIPIENT
        with self.assertRaisesRegex(ValueError, "must be distinct"):
            release.public_config(value)
        for field in ("wind_down_recipient", "oracle_signer"):
            for role in ("settlement", "vault", "token"):
                value = config()
                value["genesis"][field] = value["addresses"][role]
                if field == "wind_down_recipient":
                    value["gateway"]["WIND_DOWN_RECIPIENT"] = value["addresses"][role]
                with self.subTest(field=field, contract=role), \
                        self.assertRaisesRegex(ValueError, "must not be a contract address"):
                    release.public_config(value)

    def test_genesis_addresses_differ_from_every_operator_address(self):
        value = config()
        value["operator_policy"] = operator_policy()
        release.public_config(value)
        for field in ("wind_down_recipient", "oracle_signer"):
            for role, fields in release.OPERATOR_ADDRESSES.items():
                for name in fields:
                    value = config()
                    value["operator_policy"] = operator_policy()
                    value["operator_policy"][role][name] = value["genesis"][field].upper().replace("0X", "0x")
                    with self.subTest(field=field, operator=role + "." + name), \
                            self.assertRaisesRegex(ValueError, "must differ from every operator address"):
                        release.public_config(value)

    def test_gateway_recipient_must_be_the_genesis_recipient(self):
        value = config()
        value["gateway"]["WIND_DOWN_RECIPIENT"] = RECIPIENT.upper().replace("0X", "0x")
        self.assertEqual(release.public_config(value)["gateway"]["WIND_DOWN_RECIPIENT"], RECIPIENT)
        for bad in (ORACLE_SIGNER, "0x" + "00" * 20, "0x5a", None):
            value = config()
            value["gateway"]["WIND_DOWN_RECIPIENT"] = bad
            with self.subTest(value=bad), self.assertRaisesRegex(ValueError, "WIND_DOWN_RECIPIENT"):
                release.public_config(value)
        value = config()
        del value["gateway"]["WIND_DOWN_RECIPIENT"]
        with self.assertRaisesRegex(ValueError, "public gateway config"):
            release.public_config(value)

    def test_process_environment_accepts_equivalent_spellings_of_the_new_keys(self):
        value = release.public_config(config())
        env = dict(value["gateway"])
        env["WIND_DOWN_RECIPIENT"] = RECIPIENT.upper().replace("0X", "0x")
        env["PROVER_EXPECTED_ELF_SHA256"] = "0x" + release.clock.REVIEWED_GUEST["elf"].upper()
        release.check_environment(value, env)
        for key, bad in (("WIND_DOWN_RECIPIENT", ORACLE_SIGNER), ("PROVER_EXPECTED_ELF_SHA256", "ab" * 32),
                         ("PROVER_EXPECTED_ELF_SHA256", None), ("WIND_DOWN_RECIPIENT", None)):
            changed = dict(env)
            if bad is None:
                del changed[key]
            else:
                changed[key] = bad
            with self.subTest(key=key, value=bad), self.assertRaisesRegex(ValueError, "mismatch: " + key):
                release.check_environment(value, changed)

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
        with patch.dict(release.clock.REVIEWED_GUEST, {"sources": {}}):
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
                    "compiled_contracts": {"settlement": "456"}, "scope": dict(release.SCOPE),
                    "public_config": release.public_config(config()),
                    "real_proof": {"status": release.clock.PROVEN}}
        build.return_value = expected
        release.validate_manifest(self.root, expected, config())
        for field in ("source", "compiled_contracts", "scope", "real_proof"):
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
        # A manifest cannot claim PROVEN when the files on disk say otherwise.
        pending = copy.deepcopy(expected)
        pending["real_proof"]["status"] = release.clock.PENDING_REPROOF
        build.return_value = pending
        with self.assertRaisesRegex(ValueError, "manifest mismatch"):
            release.validate_manifest(self.root, expected, config(), owned_test_chain=True)


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
        self.manifest = {"schema": release.SCHEMA, "public_config": self.public, "compiled_contracts": {},
                         "real_proof": {"status": release.clock.PROVEN}}
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
            ("sp1_adapter", "programVKey()"): release.clock.REVIEWED_GUEST["vkey"],
            ("clock_verifier", "maxWindowMs()"): 30000,
            ("clock_verifier", "clockSkewMs()"): 10000,
            ("clock_verifier", "anchorTimeoutMs()"): 3_600_000,
            ("clock_verifier", "proofVersion()"): 2,
            ("settlement", "ABI_VERSION()"): 3,
            ("sp1_verifier", "VERIFIER_HASH()"): "0x" + release.clock.target.VERIFIER_HASH,
            ("settlement", "currentStateRoot()"): GENESIS_ROOT,
        }
        # Chain state read without an expected value (no settled batch yet).
        self.state = {("settlement", "batchCount()"): 0}
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
            if (role, signature) in self.state:
                return self.word(self.state[(role, signature)])
            return self.word(self.values.get((role, signature), 1))
        self.fail("unexpected RPC method")

    def observe(self):
        return release.observe_target(self.root, self.manifest, self.public, self.rpc)

    def test_all_six_runtimes_bindings_route_and_one_finalized_hash_are_checked(self):
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertEqual(set(result["contracts"]), set(release.CONTRACTS))
        self.assertEqual(len(result["bindings"]), 15)
        bound = {(item["contract"], item["getter"]) for item in result["bindings"]}
        self.assertIn(("settlement", "ABI_VERSION()"), bound)
        self.assertIn(("clock_verifier", "anchorTimeoutMs()"), bound)
        self.assertIn(("settlement", "currentStateRoot()"), bound)
        self.assertTrue(result["scope"]["genesis_root_verified"])
        self.assertEqual(result["genesis"], {**config()["genesis"], "batch_count": 0, "root_observed": True})
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

    def test_genesis_root_is_compared_only_before_the_first_batch(self):
        self.values[("settlement", "currentStateRoot()")] = "0x" + "ee" * 32
        result = self.observe()
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("target binding mismatch: settlement.currentStateRoot()", result["blocker"])
        self.assertFalse(result["scope"]["genesis_root_verified"])
        # After a settled batch the root has moved on: recorded, never claimed.
        self.state[("settlement", "batchCount()")] = 3
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertFalse(result["scope"]["genesis_root_verified"])
        self.assertEqual(result["genesis"]["batch_count"], 3)
        self.assertIs(result["genesis"]["root_observed"], False)
        self.assertNotIn("currentStateRoot()", result["contracts"]["settlement"]["getters"])

    def test_genesis_address_equal_to_an_observed_operator_blocks_without_a_policy(self):
        for field in ("wind_down_recipient", "oracle_signer"):
            for key in (("settlement", "governance()"), ("settlement", "sequencer()"),
                        ("vault", "gatewaySigner()"), ("clock_verifier", "configurator()")):
                self.values[key] = config()["genesis"][field]
                with self.subTest(field=field, getter=key):
                    result = self.observe()
                    self.assertEqual(result["status"], "BLOCKED")
                    self.assertIn("genesis " + field + " equals an observed operator address", result["blocker"])
                del self.values[key]

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


PENDING_GUEST = {"elf": "cd" * 32, "vkey": "0x" + "ab" * 32}


class ProofStatusGateTests(unittest.TestCase):
    """The real proof status, read from disk, gates release creation and non-owned targets."""

    def expected(self, status, chain_id=31337):
        value = config()
        value["chain_id"] = chain_id
        value["gateway"]["L1_CHAIN_ID"] = str(chain_id)
        return {"schema": release.SCHEMA, "public_config": release.public_config(value),
                "real_proof": {"status": status}, "scope": dict(release.SCOPE)}

    def test_manifest_records_the_status_and_both_identities(self):
        record = release.real_proof(release.ROOT)
        # The status is the on-disk reading, whichever it is today.
        self.assertIn(record["status"], {release.clock.PROVEN, release.clock.PENDING_REPROOF})
        self.assertEqual(record["status"], release.clock.proof_status(release.ROOT))
        self.assertEqual(record["proof"]["proof_sha256"], release.clock.PROOF_FIXTURE["proof_sha256"])
        self.assertEqual(record["proof"]["program_vkey"], release.clock.PROOF_FIXTURE["vkey"])
        self.assertEqual(record["reviewed"], {"guest_elf_sha256": release.clock.REVIEWED_GUEST["elf"],
                                              "program_vkey": release.clock.REVIEWED_GUEST["vkey"]})
        with patch.dict(release.clock.REVIEWED_GUEST, PENDING_GUEST):
            record = release.real_proof(release.ROOT)
        self.assertEqual(record["status"], release.clock.PENDING_REPROOF)
        self.assertEqual(record["reviewed"]["program_vkey"], PENDING_GUEST["vkey"])
        self.assertEqual(record["proof"]["program_vkey"], release.clock.PROOF_FIXTURE["vkey"])

    def test_create_requires_proven(self):
        with patch.object(release, "build_manifest", return_value=self.expected(release.clock.PROVEN)):
            self.assertEqual(release.create_manifest(release.ROOT, config())["real_proof"]["status"],
                             release.clock.PROVEN)
        with patch.object(release, "build_manifest", return_value=self.expected(release.clock.PENDING_REPROOF)):
            with self.assertRaisesRegex(ValueError, "create requires a committed proof"):
                release.create_manifest(release.ROOT, config())

    def test_validate_refuses_a_non_owned_target_while_pending(self):
        for chain_id in (31337, 1337, 900, 84532, 8453):
            pending = self.expected(release.clock.PENDING_REPROOF, chain_id)
            value = copy.deepcopy(pending)
            with self.subTest(chain_id=chain_id), patch.object(release, "build_manifest", return_value=pending):
                with self.assertRaisesRegex(ValueError, "validate refused: real proof status is PENDING_REPROOF"):
                    release.validate_manifest(release.ROOT, value, config())
                if chain_id not in release.LOCAL_TEST_CHAINS:
                    # Offline, only a local chain id can be declared owned while pending.
                    with self.assertRaisesRegex(ValueError, "validate refused.*local chain id 1337 or 31337"):
                        release.validate_manifest(release.ROOT, value, config(), owned_test_chain=True)
                else:
                    self.assertEqual(release.validate_manifest(release.ROOT, value, config(),
                                                               owned_test_chain=True), pending)
            proven = self.expected(release.clock.PROVEN, chain_id)
            with self.subTest(chain_id=chain_id, status="PROVEN"), \
                    patch.object(release, "build_manifest", return_value=proven):
                self.assertEqual(release.validate_manifest(release.ROOT, copy.deepcopy(proven), config()), proven)
        with self.assertRaisesRegex(ValueError, "owned test chain declaration"):
            release.validate_manifest(release.ROOT, self.expected(release.clock.PROVEN), config(), owned_test_chain=1)

    def test_ownership_follows_the_deploy_rule(self):
        self.assertEqual(release.LOCAL_TEST_CHAINS, {31337, 1337})
        self.assertTrue(release.target_owned(84532, True, False))
        self.assertTrue(release.target_owned(31337, False, True))
        self.assertTrue(release.target_owned(1337, False, True))
        self.assertFalse(release.target_owned(31337, False, False))
        self.assertFalse(release.target_owned(84532, False, True))
        self.assertFalse(release.target_owned(8453, False, True))
        self.assertFalse(release.target_owned(900, "anvil", 1))
        # While pending, a declared chain must be a local one.
        self.assertFalse(release.target_owned(900, False, True))
        self.assertFalse(release.target_owned(900, False, True, proven=False))
        # Once proven, a declaration covers any chain that is not a public Base chain.
        self.assertTrue(release.target_owned(900, False, True, proven=True))
        self.assertFalse(release.target_owned(84532, False, True, proven=True))
        self.assertFalse(release.target_owned(8453, False, True, proven=True))
        self.assertFalse(release.target_owned(900, False, True, proven=1))


class PendingTargetTests(unittest.TestCase):
    """observe-target while PENDING_REPROOF: only an owned test chain is observed."""
    setUp = TargetTests.setUp
    rpc = TargetTests.rpc
    word = staticmethod(TargetTests.word)

    def pending(self, chain_id=31337):
        self.manifest["real_proof"] = {"status": release.clock.PENDING_REPROOF}
        self.public["chain_id"] = chain_id
        self.overrides["eth_chainId"] = hex(chain_id)

    def observe(self, client, **kwargs):
        self.overrides["web3_clientVersion"] = client
        return release.observe_target(self.root, self.manifest, self.public, self.rpc, **kwargs)

    def test_non_owned_target_is_refused_before_any_contract_read(self):
        self.pending()
        result = self.observe("Geth/v1.14")
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("observe-target refused: real proof status is PENDING_REPROOF", result["blocker"])
        self.assertEqual(result["real_proof_status"], release.clock.PENDING_REPROOF)
        self.assertIs(result["target_owned"], False)
        self.assertEqual([method for method, _ in self.calls], ["eth_chainId", "web3_clientVersion"])

    def test_owned_anvil_including_the_base_sepolia_id_is_observed(self):
        for chain_id in (31337, 84532):
            self.calls.clear()
            self.pending(chain_id)
            with self.subTest(chain_id=chain_id):
                result = self.observe("anvil/v1.2.3")
                self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
                self.assertIs(result["target_owned"], True)
                self.assertIn("web3_clientVersion", {method for method, _ in self.calls})

    def test_declared_owned_test_chain_must_be_a_local_chain_id(self):
        for chain_id in (31337, 1337):
            self.pending(chain_id)
            with self.subTest(chain_id=chain_id):
                result = self.observe("Geth/v1.14", owned_test_chain=True)
                self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
                self.assertIs(result["target_owned"], True)
        for chain_id in (900, 84532, 8453):
            self.calls.clear()
            self.pending(chain_id)
            with self.subTest(chain_id=chain_id):
                result = self.observe("Geth/v1.14", owned_test_chain=True)
                self.assertEqual(result["status"], "BLOCKED")
                self.assertIn("observe-target refused", result["blocker"])
                self.assertIs(result["target_owned"], False)
                self.assertEqual([method for method, _ in self.calls], ["eth_chainId", "web3_clientVersion"])

    def test_proven_status_does_not_query_the_client(self):
        result = release.observe_target(self.root, self.manifest, self.public, self.rpc)
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertEqual(result["real_proof_status"], release.clock.PROVEN)
        self.assertNotIn("web3_clientVersion", {method for method, _ in self.calls})
        self.assertNotIn("target_owned", result)


class TransportTests(unittest.TestCase):
    def test_read_allowlist_precedes_transport_and_rejects_credential_urls(self):
        rpc = release.TargetRPC("https://example.invalid")
        with self.assertRaisesRegex(ValueError, "read-only allowlist"):
            rpc("eth_sendTransaction", [])
        self.assertEqual(release.READ_METHODS - release.deployment_reader.READ_METHODS, {"web3_clientVersion"})
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
        addresses["sp1_adapter"] = deploy("sp1_adapter", addresses["sp1_gateway"], release.clock.REVIEWED_GUEST["vkey"])
        addresses["clock_verifier"] = deploy("clock_verifier", addresses["sp1_adapter"], 30000, 10000, 3_600_000)
        # DarkPerpSettlement.Config: 12 words, a static struct encoded inline.
        addresses["settlement"] = deploy("settlement", owner, accounts[1], addresses["clock_verifier"], GENESIS_ROOT,
                                         100, 50, 1000, 600, owner, 10, 2, 1_000_000_000)
        addresses["token"] = deploy("token")
        addresses["vault"] = deploy("vault", addresses["settlement"], addresses["token"], accounts[2])
        transact(release.deployment_reader.selector("setVault(address)") + word(addresses["vault"]), addresses["settlement"])
        transact(release.deployment_reader.selector("bindSettlement(address)") + word(addresses["settlement"]), addresses["clock_verifier"])
        local_rpc("anvil_mine", ["0x80"])
        public = config()
        public["addresses"] = addresses
        public["gateway"].update({env: addresses[role] for env, role in release.ENV_ADDRESSES.items()})
        public["operator_policy"] = {
            "settlement": {"sequencer": owner, "enclave_signer": accounts[1], "governance": owner,
                           "liveness_timeout_blocks": 100, "challenge_grace_blocks": 50,
                           "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                           "final_settle_grace_blocks": 10, "progress_batches": 2,
                           "slash_payout_cap_usdc": 1_000_000_000},
            "vault": {"gateway_signer": accounts[2]},
            "clock_verifier": {"configurator": owner},
            "sp1_gateway": {"owner": owner},
        }
        manifest = release.build_manifest(release.ROOT, public)
        if manifest["real_proof"]["status"] != release.clock.PROVEN:
            # The owned drill still observes while pending; a release still refuses.
            with self.assertRaisesRegex(ValueError, "create requires a committed proof"):
                release.create_manifest(release.ROOT, public)
        observed = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url),
                                          require_operator_policy=True)
        self.assertEqual(observed["status"], "VERIFIED_AT_FINALIZED_BLOCK", observed)
        self.assertEqual(len(observed["contracts"]), 6)
        self.assertTrue(observed["scope"]["operator_and_settlement_policy_matches"])
        self.assertFalse(observed["scope"]["operator_and_settlement_policy_approved"])
        self.assertTrue(observed["scope"]["genesis_root_verified"])
        self.assertEqual(observed["contracts"]["settlement"]["getters"]["currentStateRoot()"], GENESIS_ROOT)
        # A config naming another genesis root needs its own manifest; the
        # deployed settlement's constructor root still refuses it.
        wrong_genesis = copy.deepcopy(public)
        wrong_genesis["genesis"]["root"] = "0x" + "4e" * 32
        wrong_manifest = copy.deepcopy(manifest)
        wrong_manifest["public_config"] = release.public_config(wrong_genesis)
        wrong_manifest["public_config_sha256"] = release.digest(release.canonical(wrong_manifest["public_config"]))
        genesis_rejected = release.observe_target(release.ROOT, wrong_manifest, wrong_genesis, release.TargetRPC(url),
                                                  require_operator_policy=True)
        self.assertEqual(genesis_rejected["status"], "BLOCKED", genesis_rejected)
        self.assertIn("target binding mismatch: settlement.currentStateRoot()", genesis_rejected["blocker"])
        policy_rejections = {}
        for field, wrong in (("governance", accounts[3]), ("challenge_bond_wei", 1001),
                             ("progress_batches", 3), ("slash_payout_cap_usdc", 999_999_999)):
            bad_public = copy.deepcopy(public)
            bad_public["operator_policy"]["settlement"][field] = wrong
            # A new declared policy requires its own manifest identity. The
            # observer must still reject it against actual same-block getters.
            bad_manifest = copy.deepcopy(manifest)
            bad_manifest["public_config"] = release.public_config(bad_public)
            bad_manifest["public_config_sha256"] = release.digest(release.canonical(bad_manifest["public_config"]))
            rejected = release.observe_target(release.ROOT, bad_manifest, bad_public, release.TargetRPC(url),
                                               require_operator_policy=True)
            self.assertEqual(rejected["status"], "BLOCKED", rejected)
            self.assertIn("target binding mismatch", rejected["blocker"])
            self.assertFalse(rejected["scope"]["operator_and_settlement_policy_matches"])
            policy_rejections[field] = rejected
        transact(release.deployment_reader.selector("freezeRoute(bytes4)") + release.clock.target.VERIFIER_HASH[:8] + "0" * 56,
                 addresses["sp1_gateway"])
        local_rpc("anvil_mine", ["0x80"])
        frozen = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url))
        self.assertEqual(frozen["status"], "BLOCKED", frozen)
        self.assertIn("wrong or frozen", frozen["blocker"])
        evidence = os.environ.get("ARCORA_MANIFEST_ANVIL_EVIDENCE")
        if evidence:
            Path(evidence).write_text(json.dumps({"scope": "Owned local Anvil; real compiled constructors and RPC, mock token, no proof submission or target deployment.",
                                                "pass": observed, "policy_mismatches_rejected": policy_rejections,
                                                "genesis_root_mismatch_rejected": genesis_rejected,
                                                "frozen_route_rejected": frozen}, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
