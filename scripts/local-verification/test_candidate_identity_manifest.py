"""Owned synthetic compiler/config fixtures; no chain, Forge, setup or proof.

Committed ELF/metadata and 21/9 source pins are copied unchanged. Compiler
templates, Keccak interface and release/ancestry responses are explicitly mocked
for CI portability; these tests are not compiled-runtime/provenance acceptance.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import candidate_identity_manifest as identity


def config():
    roles = sorted(identity.ADDRESS_ROLES)
    return {"chain_id": 84532, "network": 0,
            "addresses": {role: "0x" + format(i, "040x") for i, role in enumerate(roles, 1)},
            "expected_runtime_code_hashes": {role: "0x" + "bb" * 32 for role in roles},
            "program_vkey": identity.candidate.VKEY,
            "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000},
            "oracle_policy_hash": "0x" + "aa" * 32, "sequencer_grace_seconds": 60}


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="arcora-candidate-identity-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        names = (set(identity.candidate.CANDIDATE_SOURCES)
                 | set(identity.legacy.clock.EXPECTED_GUEST_SOURCES)
                 | set(identity.AUXILIARY_TEST_SOURCES))
        names |= {identity.BUILDER, "Cargo.toml", "Cargo.lock", "contracts/foundry.toml", identity.FIXTURE + "/guest.elf",
                  identity.FIXTURE + "/metadata.json"}
        for name in names:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(identity.ROOT / name, target)
        self.artifacts = {}
        for role, (relative, name, compiler) in identity.CONTRACTS.items():
            base = self.root / ("contracts/vendor/sp1-contracts" if role in {"sp1_gateway", "sp1_verifier"} else "contracts")
            source = "src/" + name + ".sol"
            path = base / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// Explicitly synthetic compiler fixture\ncontract " + name + " {}\n")
            artifact = {"metadata": {"compiler": {"version": compiler}, "settings": {
                "compilationTarget": {source: name}, "optimizer": {"enabled": True, "runs": 200}},
                "sources": {source: {"keccak256": self.fake_keccak(None, path.read_bytes()),
                                     "license": "MIT", "urls": ["ipfs://synthetic-owned-fixture"]}}},
                "bytecode": {"object": "6001600055", "linkReferences": {}},
                "deployedBytecode": {"object": "6002600055", "linkReferences": {}}}
            target = self.root / "contracts" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(artifact))
            self.artifacts[role] = (target, artifact)
        self.addCleanup(patch.stopall)
        patch.object(identity, "source_keccak", side_effect=self.fake_keccak).start()
        patch.object(identity.legacy.check_sp1_release, "check", return_value={"passed": True}).start()
        self.head = "1" * 40
        patch.object(identity, "code_commit", side_effect=lambda _root, value=None: value or self.head).start()

    @staticmethod
    def fake_keccak(_root, data):
        # Deliberately mocked interface, NOT an Ethereum Keccak implementation.
        return "0x" + hashlib.sha256(data).hexdigest()

    def manifest(self):
        return identity.build_manifest(self.root, config())

    def write_artifact(self, role):
        path, value = self.artifacts[role]
        path.write_text(json.dumps(value))

    def test_local_identity_has_fixed_hold_and_separate_historical_key(self):
        manifest = self.manifest()
        self.assertEqual(identity.validate_manifest(self.root, manifest, config()), manifest)
        self.assertEqual(manifest["scope"], identity.SCOPE)
        self.assertEqual(manifest["program"]["witness_wire"], "DPCLK3")
        self.assertEqual(manifest["program"]["inner_clock_proof_version"], 2)
        self.assertNotEqual(manifest["program"]["program_vkey"], identity.legacy.clock.EXPECTED_VKEY)
        self.assertNotIn("setup_key", manifest["program"])
        self.assertEqual(len(manifest["pins"]["reviewed_v2_sources_sha256"]), 21)
        self.assertEqual(len(manifest["pins"]["candidate_sources_sha256"]), 9)
        self.assertEqual(manifest["pins"]["candidate_auxiliary_test_sources_sha256"], identity.AUXILIARY_TEST_SOURCES)
        actual = {p.relative_to(self.root).as_posix() for p in (self.root / "crates/chainlink-oracle/src").rglob("*")
                  if p.is_file()}
        expected = {p for p in set(identity.candidate.CANDIDATE_SOURCES) | set(identity.AUXILIARY_TEST_SOURCES)
                    if p.startswith("crates/chainlink-oracle/src/")}
        self.assertEqual(actual, expected)

    def test_metadata_only_head_advance_keeps_explicit_code_commit(self):
        manifest = self.manifest()
        self.head = "2" * 40
        self.assertEqual(identity.validate_manifest(self.root, manifest, config()), manifest)
        self.assertEqual(manifest["source"]["code_commit"], "1" * 40)

    def test_legacy_schema_and_keys_cannot_cross_validate(self):
        for key in (identity.legacy.clock.EXPECTED_VKEY, "0x" + "ab" * 32):
            value = config()
            value["program_vkey"] = key
            with self.subTest(key=key), self.assertRaises(ValueError):
                identity.public_config(value)
        manifest = self.manifest()
        manifest["schema"] = identity.legacy.SCHEMA
        with self.assertRaises(ValueError):
            identity.validate_manifest(self.root, manifest, config())
        addresses = {role: "0x" + format(i, "040x") for i, role in enumerate(sorted(identity.legacy.ADDRESS_ROLES), 1)}
        gateway = {env: addresses[role] for env, role in identity.legacy.ENV_ADDRESSES.items()}
        gateway.update(L1_CHAIN_ID="31337", L1_ALLOW_MOCK_PROOF="0")
        old = {"chain_id": 31337, "addresses": addresses, "program_vkey": identity.candidate.VKEY,
               "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000}, "gateway": gateway,
               "prover": {"program_vkey": identity.candidate.VKEY, "guest_elf_sha256": identity.candidate.ELF_SHA}}
        with self.assertRaises(ValueError):
            identity.legacy.public_config(old)

    def test_wrong_elf_including_reviewed_v2_is_rejected(self):
        path = self.root / identity.FIXTURE / "guest.elf"
        for data in (b"\x7fELFwrong-candidate", (identity.ROOT / identity.legacy.FIXTURE / "guest.elf").read_bytes()):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                self.manifest()

    def test_changed_pinned_inputs_new_module_and_build_override_refuse(self):
        path = self.root / "crates/sp1-chainlink-guest/src/main.rs"
        old = path.read_bytes()
        path.write_bytes(old + b"\n")
        with self.assertRaises(ValueError): self.manifest()
        path.write_bytes(old)
        for name in identity.AUXILIARY_TEST_SOURCES:
            auxiliary = self.root / name
            original = auxiliary.read_bytes(); auxiliary.write_bytes(original + b"\n")
            with self.subTest(auxiliary=name), self.assertRaises(ValueError): self.manifest()
            auxiliary.write_bytes(original)
        extra = path.with_name("unreviewed.rs")
        extra.write_text("// unreviewed")
        with self.assertRaises(ValueError): self.manifest()
        extra.unlink()
        override = self.root / "crates/sp1-chainlink-guest/build.rs"
        override.write_text("fn main() {}")
        with self.assertRaises(ValueError): self.manifest()

    def test_changed_reviewed_core_and_failed_dependency_guard_refuse(self):
        path = self.root / "crates/perp-core/src/lib.rs"
        old = path.read_bytes()
        path.write_bytes(old + b"\n")
        with self.assertRaises(ValueError): self.manifest()
        path.write_bytes(old)
        with patch.object(identity.legacy.check_sp1_release, "check", return_value={"passed": False}):
            with self.assertRaises(ValueError): self.manifest()

    def test_candidate_metadata_sdk_key_and_scope_cannot_be_promoted(self):
        path = self.root / identity.FIXTURE / "metadata.json"
        original = identity.read_json(path)
        for field, value in (("sdk_version", "6.2.0"), ("measured_program_vkey", identity.legacy.clock.EXPECTED_VKEY),
                             ("elf_bytes", True), ("proof_generated", True), ("production_approved", True),
                             ("independent_build", True)):
            modified = copy.deepcopy(original); modified[field] = value
            path.write_text(json.dumps(modified))
            with self.subTest(field=field), self.assertRaises(ValueError): self.manifest()

    def test_missing_extra_and_forged_manifest_identity_are_rejected(self):
        manifest = self.manifest()
        for mutate in (lambda m: m.pop("pins"), lambda m: m.update(unknown=True),
                       lambda m: m["source"].pop("builder"),
                       lambda m: m["source"].update(inventory_sha256="00" * 32),
                       lambda m: m["program"].update(witness_wire="DPCLK2"),
                       lambda m: m["program"].update(inner_clock_proof_version=True)):
            changed = copy.deepcopy(manifest); mutate(changed)
            with self.assertRaises(ValueError): identity.validate_manifest(self.root, changed, config())

    def test_scope_flags_and_release_gate_never_promote(self):
        manifest = self.manifest()
        for field in identity.SCOPE:
            changed = copy.deepcopy(manifest)
            changed["scope"][field] = "PASS" if field == "release_gate" else not identity.SCOPE[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                identity.validate_manifest(self.root, changed, config())
        changed = copy.deepcopy(manifest); changed["scope"]["target_chain_observed"] = 0
        with self.assertRaises(ValueError): identity.validate_manifest(self.root, changed, config())

    def test_stale_covered_source_builder_and_contract_artifact_refuse(self):
        manifest = self.manifest()
        path = self.root / identity.BUILDER
        old = path.read_bytes(); path.write_bytes(old + b"\n# changed builder\n")
        with self.assertRaises(ValueError): identity.validate_manifest(self.root, manifest, config())
        path.write_bytes(old)
        extra = self.root / "crates/host-added.rs"; extra.write_text("// changed relevant source")
        with self.assertRaises(ValueError): identity.validate_manifest(self.root, manifest, config())
        extra.unlink()
        self.artifacts["oracle_wrapper"][1]["deployedBytecode"]["object"] = "6003600055"
        self.write_artifact("oracle_wrapper")
        with self.assertRaises(ValueError): identity.validate_manifest(self.root, manifest, config())

    def test_compiler_optimizer_links_and_source_bindings_are_checked(self):
        path, original = self.artifacts["oracle_wrapper"]
        for mutate in (lambda a: a["metadata"]["compiler"].update(version="0.8.25"),
                       lambda a: a["metadata"]["settings"]["optimizer"].update(runs=True),
                       lambda a: a["bytecode"].update(object="__unlinked__"),
                       lambda a: a["deployedBytecode"].update(linkReferences={"x": [1]}),
                       lambda a: next(iter(a["metadata"]["sources"].values())).update(keccak256="0x" + "ab" * 32)):
            artifact = copy.deepcopy(original); mutate(artifact); path.write_text(json.dumps(artifact))
            with self.assertRaises(ValueError): self.manifest()

    def test_config_integer_bounds_roles_and_program_are_strict(self):
        for field, bad in (("chain_id", True), ("network", True), ("network", 1),
                           ("sequencer_grace_seconds", 0), ("sequencer_grace_seconds", 2**64)):
            value = config(); value[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError): identity.public_config(value)
        for bad in (True, 0, 2**64, "30000"):
            value = config(); value["clock"]["max_window_ms"] = bad
            with self.assertRaises(ValueError): identity.public_config(value)
        value = config(); value["clock"]["clock_skew_ms"] = 0
        self.assertEqual(identity.public_config(value)["clock"]["clock_skew_ms"], 0)
        for bad in (True, -1, 2**64):
            value = config(); value["clock"]["clock_skew_ms"] = bad
            with self.assertRaises(ValueError): identity.public_config(value)
        for bad in ("0x" + "00" * 20, config()["addresses"]["settlement"], "0x1"):
            value = config(); value["addresses"]["oracle_wrapper"] = bad
            with self.assertRaises(ValueError): identity.public_config(value)
        value = config(); value["expected_runtime_code_hashes"].pop("uptime_feed")
        with self.assertRaises(ValueError): identity.public_config(value)

    def test_duplicate_nonfinite_and_oversized_json_are_rejected(self):
        for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '[' * 2000 + '0' + ']' * 2000):
            with self.assertRaises(ValueError): identity.decode_json(data)
        path = self.root / "oversize.json"; path.write_bytes(b" " * (identity.MAX_JSON + 1))
        with self.assertRaises(ValueError): identity.read_json(path)

    def test_unsafe_artifact_and_source_paths_refuse(self):
        for name in ("../outside", "/etc/passwd"):
            with self.assertRaises(ValueError): identity.legacy.regular(self.root, name)
        source = self.root / "contracts/src/ChainlinkOracleVerifier.sol"
        old = source.read_bytes(); source.unlink(); source.symlink_to(self.root / "Cargo.toml")
        with self.assertRaises(ValueError): self.manifest()
        source.unlink(); source.write_bytes(old)
        artifact, _ = self.artifacts["oracle_wrapper"]
        artifact.unlink(); artifact.symlink_to(self.root / "Cargo.toml")
        with self.assertRaises(ValueError): self.manifest()
        artifact.unlink(); self.write_artifact("oracle_wrapper")
        secret_source = self.root / "contracts/src/private-keys/key.sol"
        secret_source.parent.mkdir(parents=True, exist_ok=True)
        secret_source.write_text("owned synthetic prohibited source marker")
        value = self.artifacts["oracle_wrapper"][1]
        value["metadata"]["sources"] = {"src/private-keys/key.sol": {"keccak256": "0x" + "ff" * 32}}
        self.write_artifact("oracle_wrapper")
        with patch.object(identity, "source_keccak", side_effect=self.fake_keccak) as keccak:
            with self.assertRaises(ValueError): identity.compiled_contract(self.root, "oracle_wrapper")
            keccak.assert_not_called()

    def test_secret_fields_rejected_without_echo_and_never_invented(self):
        value = config(); value["RPC_URL"] = "sensitive-owned-test-value"
        with self.assertRaises(ValueError) as raised: identity.public_config(value)
        self.assertNotIn("sensitive-owned-test-value", str(raised.exception))
        path = self.root / "bad-config.json"; path.write_text(json.dumps(value))
        result = subprocess.run([sys.executable, str(identity.ROOT / identity.BUILDER), "create",
                                 "--config", str(path), "--output", str(self.root / "never-created.json")],
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("sensitive-owned-test-value", result.stdout + result.stderr)
        self.assertFalse((self.root / "never-created.json").exists())
        for name in ("vendor/credentials.rs", "vendor/private-keys/key.py", "crates/secret.sh"):
            prohibited = self.root / name; prohibited.parent.mkdir(parents=True, exist_ok=True)
            prohibited.write_text("owned synthetic secret marker")
        with patch.object(identity.legacy, "identity", wraps=identity.legacy.identity) as read:
            inventory = identity.source_inventory(self.root)
            self.assertFalse(any("credentials" in name or "private-keys" in name or "secret.sh" in name for name in inventory))
            self.assertFalse(any("credentials" in call.args[1] or "private-keys" in call.args[1] or "secret.sh" in call.args[1]
                                 for call in read.call_args_list))

    def test_public_output_creation_never_clobbers_previous_bytes(self):
        path = self.root / "manifest.json"
        identity.create_output(path, self.manifest())
        old = path.read_bytes()
        with self.assertRaises(FileExistsError): identity.create_output(path, {"replacement": True})
        self.assertEqual(path.read_bytes(), old)

    def test_manifest_source_change_during_creation_is_refused(self):
        original = identity.source_inventory
        calls = 0
        def moving(root):
            nonlocal calls
            calls += 1
            values = original(root)
            if calls == 2: values["changed.rs"] = "00" * 32
            return values
        with patch.object(identity, "source_inventory", side_effect=moving):
            with self.assertRaises(ValueError): self.manifest()

    def public_input_samples(self, label, value):
        """Owned public JSON only, even below synthetic prohibited names."""
        public = self.root / "path-samples"
        public.mkdir(exist_ok=True)
        hidden = self.root / ".env-fixture" / label
        private = self.root / "private-keys" / label
        named = public / ("credentials-" + label)
        for path in (hidden, private, named):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        leaf = public / ("leaf-" + label)
        leaf.symlink_to(hidden)
        ancestor = public / ("ancestor-" + label)
        ancestor.symlink_to(hidden.parent, target_is_directory=True)
        return [("prohibited-parent", hidden), ("private-key-parent", private),
                ("prohibited-leaf", named), ("leaf-symlink", leaf),
                ("ancestor-symlink", ancestor / label)], {
                    path: path.read_bytes() for path in (hidden, private, named)}

    def public_output_samples(self, label):
        public = self.root / "output-samples"
        public.mkdir(exist_ok=True)
        hidden = self.root / ".env-output-fixture"
        private = self.root / "private-keys-output-fixture"
        hidden.mkdir(exist_ok=True)
        private.mkdir(exist_ok=True)
        target = hidden / ("existing-" + label)
        target.write_bytes(b"owned synthetic prior public JSON bytes\n")
        leaf = public / ("leaf-" + label)
        leaf.symlink_to(target)
        ancestor = public / ("ancestor-" + label)
        ancestor.symlink_to(hidden, target_is_directory=True)
        paths = [("prohibited-parent", hidden / label),
                 ("private-key-parent", private / label),
                 ("prohibited-leaf", public / ("credentials-" + label)),
                 ("leaf-symlink", leaf), ("ancestor-symlink", ancestor / label)]
        absent = [hidden / label, private / label, public / ("credentials-" + label)]
        return paths, {target: target.read_bytes()}, absent

    def identity_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", [identity.BUILDER, *args]), \
                patch.object(identity, "ROOT", self.root), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = identity.main()
        return code, stdout.getvalue() + stderr.getvalue()

    def test_public_regular_json_and_identity_cli_positive_preserve_hold(self):
        # Exercise actual file I/O and both CLI branches using the existing
        # synthetic compiler/ancestry interfaces, rather than a mocked builder.
        path = self.root / "regular-public.json"
        value = {"owned_public_fixture": True}
        identity.create_output(path, value)
        self.assertEqual(identity.read_json(path), value)
        config_path = self.root / "regular-config.json"
        config_path.write_text(json.dumps(config()))
        output = self.root / "regular-manifest.json"
        code, text = self.identity_cli(["create", "--config", str(config_path),
                                        "--output", str(output)])
        self.assertEqual(code, 0, text)
        expected = self.manifest()
        self.assertEqual(identity.read_json(output), expected)
        self.assertEqual(expected["scope"], identity.SCOPE)
        prior = output.read_bytes()
        code, text = self.identity_cli(["validate", "--config", str(config_path),
                                        "--manifest", str(output)])
        self.assertEqual(code, 0, text)
        self.assertEqual(output.read_bytes(), prior)

    def test_public_json_forbidden_paths_refuse_before_any_open(self):
        self.assertEqual(identity.validate_manifest(self.root, self.manifest(), config())["scope"],
                         identity.SCOPE)
        samples, preserved = self.public_input_samples("input.json", config())
        for label, path in samples:
            with self.subTest(path_kind=label), \
                    patch.object(Path, "open", side_effect=AssertionError("forbidden input opened")) as opened:
                with self.assertRaises(ValueError):
                    identity.read_json(path)
                opened.assert_not_called()
        for path, before in preserved.items():
            self.assertEqual(path.read_bytes(), before)

    def test_public_output_forbidden_paths_refuse_before_open_and_preserve_bytes(self):
        samples, preserved, absent = self.public_output_samples("output.json")
        for label, path in samples:
            with self.subTest(path_kind=label), \
                    patch.object(Path, "open", side_effect=AssertionError("forbidden output opened")) as opened:
                with self.assertRaises(ValueError):
                    identity.create_output(path, {"owned_public_fixture": True})
                opened.assert_not_called()
        for path, before in preserved.items():
            self.assertEqual(path.read_bytes(), before)
        self.assertTrue(all(not path.exists() for path in absent))

    def test_identity_cli_forbidden_input_paths_do_not_read_or_build(self):
        manifest = self.manifest()
        regular_config = self.root / "cli-public-config.json"
        regular_config.write_text(json.dumps(config()))
        for role, value in (("config", config()), ("manifest", manifest)):
            samples, preserved = self.public_input_samples("cli-" + role + ".json", value)
            for label, bad in samples:
                output = self.root / ("unused-" + role + "-" + label + ".json")
                args = (["create", "--config", str(bad), "--output", str(output)]
                        if role == "config" else ["validate", "--config", str(regular_config),
                                                  "--manifest", str(bad)])
                opened = []
                original = Path.open
                def record_open(path, *args, **kwargs):
                    if path == bad:
                        opened.append(path)
                    return original(path, *args, **kwargs)
                with self.subTest(role=role, path_kind=label), \
                        patch.object(Path, "open", record_open), \
                        patch.object(identity, "build_manifest") as build, \
                        patch.object(identity, "validate_manifest") as validate:
                    code, text = self.identity_cli(args)
                    self.assertEqual(code, 1, text)
                    self.assertEqual(opened, [])
                    build.assert_not_called()
                    validate.assert_not_called()
                    self.assertNotIn(str(bad), text)
                    self.assertFalse(output.exists())
            for path, before in preserved.items():
                self.assertEqual(path.read_bytes(), before)

    def test_identity_cli_forbidden_outputs_preflight_before_reads_or_build(self):
        self.assertEqual(self.manifest()["scope"], identity.SCOPE)
        regular_config = self.root / "early-public-config.json"
        regular_config.write_text(json.dumps(config()))
        samples, preserved, absent = self.public_output_samples("early.json")
        existing = self.root / "existing-public-output.json"
        existing.write_bytes(b"owned prior manifest bytes\n")
        preserved[existing] = existing.read_bytes()
        for label, output in [*samples, ("existing-regular", existing)]:
            with self.subTest(path_kind=label), \
                    patch.object(identity, "read_json", side_effect=AssertionError("late input read")) as read, \
                    patch.object(identity, "build_manifest") as build, \
                    patch.object(identity, "create_output") as create:
                code, text = self.identity_cli(["create", "--config", str(regular_config),
                                                "--output", str(output)])
                self.assertEqual(code, 1, text)
                read.assert_not_called()
                build.assert_not_called()
                create.assert_not_called()
                self.assertNotIn(str(output), text)
        for path, before in preserved.items():
            self.assertEqual(path.read_bytes(), before)
        self.assertTrue(all(not path.exists() for path in absent))

    def test_relative_public_paths_bind_current_directory_before_private_name_checks(self):
        public = self.root / "ordinary-relative-public"
        public.mkdir()
        value = {"owned_public_fixture": True}
        with contextlib.chdir(public):
            identity.create_output("regular.json", value)
            self.assertEqual(identity.read_json("regular.json"), value)
        private = self.root / ".env-relative-fixture"
        private.mkdir()
        input_path = private / "input.json"
        input_path.write_text(json.dumps(value))
        before = input_path.read_bytes()
        with contextlib.chdir(private):
            for name, action in (("read", lambda: identity.read_json("input.json")),
                                 ("write", lambda: identity.create_output("output.json", value))):
                with self.subTest(operation=name), \
                        patch.object(Path, "open", side_effect=AssertionError("forbidden relative path opened")) as opened:
                    with self.assertRaises(ValueError):
                        action()
                    opened.assert_not_called()
        self.assertEqual(input_path.read_bytes(), before)
        self.assertFalse((private / "output.json").exists())


class CommitAndInterfaceTests(unittest.TestCase):
    def test_code_commit_must_be_an_ancestor_not_current_head_equal(self):
        with patch.object(identity.subprocess, "run", return_value=type("Result", (), {"returncode": 0})()) as command:
            self.assertEqual(identity.code_commit(Path("."), "1" * 40), "1" * 40)
            self.assertIn("--is-ancestor", command.call_args.args[0])
        with patch.object(identity.subprocess, "run", return_value=type("Result", (), {"returncode": 1})()):
            with self.assertRaises(ValueError): identity.code_commit(Path("."), "2" * 40)
        with self.assertRaises(ValueError): identity.code_commit(Path("."), "bad-commit")

    def test_cli_has_no_rpc_observer_or_process_environment_mode(self):
        for args in (["observe-target"], ["validate", "--rpc", "synthetic-not-a-real-endpoint"]):
            result = subprocess.run([sys.executable, str(identity.ROOT / identity.BUILDER), *args],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("synthetic-not-a-real-endpoint", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
