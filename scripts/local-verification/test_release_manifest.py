#!/usr/bin/env python3
"""Release preflight regressions; all deployments/configuration here are synthetic."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
