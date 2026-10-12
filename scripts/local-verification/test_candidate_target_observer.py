"""Synthetic unit acceptance for the NEW read-only candidate target observer.

Reuse the owned identity fixture by composition, without inheriting/rerunning
its 19 tests. ELF and 21/9 runtime pins stay real and unchanged. Compiler
templates, selectors, runtime Keccak and ancestry/provider responses below are
explicit mocks. Owned Anvil acceptance is a separate test module.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

import candidate_identity_manifest as identity
import candidate_target_observer as observer
import test_candidate_identity_manifest as fixtures

REAL_CODE_COMMIT = identity.code_commit


def address(number):
    return "0x" + format(number, "040x")


def block_hash(number):
    return "0x" + format(number, "064x")


def mocked_runtime_keccak(_root, data):
    # Deliberately NOT Keccak. Its domain differs from the compiler fixture's
    # SHA256 mock so a SHA256-as-EVM-codehash substitution is actually rejected.
    return "0x" + hashlib.sha256(b"mocked-evm-keccak" + data).hexdigest()


def mocked_selector(_root, signature):
    return "0x" + hashlib.sha256(signature.encode()).hexdigest()[:8]


def word(value):
    return "0x" + (format(value, "064x") if type(value) is int
                   else value.removeprefix("0x").rjust(64, "0"))


def policy():
    return {"schema": observer.POLICY_SCHEMA, "runtime_hash_algorithm": "keccak256-evm",
            "oracle_configurator": address(107),
            "operator_policy": {
                "settlement": {"sequencer": address(101), "enclave_signer": address(102),
                               "governance": address(103), "liveness_timeout_blocks": 100,
                               "challenge_window_blocks": 50, "challenge_bond_wei": 1000,
                               "inclusion_deadline_seconds": 600, "final_settle_grace_blocks": 10},
                "vault": {"gateway_signer": address(104)},
                "clock_verifier": {"configurator": address(105)},
                "sp1_gateway": {"owner": address(106)}}}


class FakeRPC:
    """Caller-owned consistent RPC responses; not a chain or consensus oracle."""
    def __init__(self, case):
        self.case = case
        self.calls = []
        self.counts = {}
        self.hook = None
        self.overrides = {}
        self.finalized_count = 0
        self.tip = 100
        self.headers = {i: {"number": hex(i), "hash": block_hash(i),
                            "parentHash": block_hash(i - 1)} for i in range(1, 167)}
        self.header_changes = {}
        self.initial_header = copy.deepcopy(self.headers[100])
        self.by_address = {value: role for role, value in case.public["addresses"].items()}
        self.values = {}
        # Declare the intended graph independently of the implementation LINKS.
        links = (
            ("settlement", "verifier()", "clock_verifier"),
            ("settlement", "vault()", "vault"),
            ("vault", "settlement()", "settlement"),
            ("vault", "token()", "token"),
            ("clock_verifier", "settlement()", "settlement"),
            ("clock_verifier", "innerVerifier()", "oracle_wrapper"),
            ("oracle_wrapper", "innerVerifier()", "sp1_adapter"),
            ("oracle_wrapper", "streamsVerifier()", "verifier_proxy"),
            ("oracle_wrapper", "clockVerifier()", "clock_verifier"),
            ("oracle_wrapper", "sequencerUptimeFeed()", "uptime_feed"),
            ("sp1_adapter", "gateway()", "sp1_gateway"),
        )
        self.values.update({(role, signature): case.public["addresses"][target]
                            for role, signature, target in links})
        self.values.update({
            ("sp1_adapter", "programVKey()"): case.public["program_vkey"],
            ("clock_verifier", "maxWindowMs()"): case.public["clock"]["max_window_ms"],
            ("clock_verifier", "clockSkewMs()"): case.public["clock"]["clock_skew_ms"],
            ("clock_verifier", "proofVersion()"): 2,
            ("oracle_wrapper", "policyHash()"): case.public["oracle_policy_hash"],
            ("oracle_wrapper", "deploymentChainId()"): case.public["chain_id"],
            ("oracle_wrapper", "sequencerGraceSeconds()"): case.public["sequencer_grace_seconds"],
            ("oracle_wrapper", "configurator()"): case.policy["oracle_configurator"],
            ("sp1_verifier", "VERIFIER_HASH()"): "0x" + identity.legacy.clock.target.VERIFIER_HASH,
        })
        for role, fields in identity.legacy.OPERATOR_ADDRESSES.items():
            for name, signature in fields.items():
                self.values[(role, signature)] = case.policy["operator_policy"][role][name]
        for name, signature in identity.legacy.SETTLEMENT_POLICY.items():
            self.values[("settlement", signature)] = case.policy["operator_policy"]["settlement"][name]
        self.by_selector = {mocked_selector(None, signature): signature
                            for _, signature in self.values}
        self.route_selector = mocked_selector(None, "routes(bytes4)")
        self.route = word(case.public["addresses"]["sp1_verifier"]) + "0" * 64

    def __call__(self, method, params):
        self.case.assertIn(method, observer.READ_METHODS)
        self.calls.append((method, copy.deepcopy(params)))
        key = (method, json.dumps(params, sort_keys=True))
        count = self.counts.get(key, 0) + 1
        self.counts[key] = count
        if method == "eth_chainId":
            result = hex(self.case.public["chain_id"])
        elif method == "eth_getBlockByNumber":
            if params[0] == "finalized":
                self.finalized_count += 1
                result = (self.initial_header if self.finalized_count == 1 else self.headers[self.tip])
            else:
                height = int(params[0], 16)
                result = self.header_changes.get(height, self.headers.get(height))
            result = copy.deepcopy(result)
        elif method == "eth_getCode":
            role = self.by_address[params[0]]
            result = "0x" + self.case.codes[role].hex()
        else:
            role = self.by_address[params[0]["to"]]
            data = params[0]["data"]
            if data.startswith(self.route_selector):
                self.case.assertEqual(data, self.route_selector
                                      + identity.legacy.clock.target.VERIFIER_HASH[:8] + "0" * 56)
                result = self.route
            else:
                self.case.assertEqual(len(data), 10)
                result = word(self.values[(role, self.by_selector[data])])
        if method in self.overrides:
            override = self.overrides[method]
            result = override(params, result, count) if callable(override) else override
        if self.hook:
            result = self.hook(method, params, result, count)
        return result


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.owned = fixtures.ManifestTests(methodName="runTest")
        self.owned.setUp()
        self.addCleanup(self.owned.doCleanups)
        self.root = self.owned.root
        target = self.root / observer.BUILDER
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(identity.ROOT / observer.BUILDER, target)
        self.public = fixtures.config()
        template = bytes.fromhex("6002600055")
        self.codes = {role: template for role in identity.CONTRACTS}
        self.codes.update({"token": bytes.fromhex("6010600055"),
                           "verifier_proxy": bytes.fromhex("6011600055"),
                           "uptime_feed": bytes.fromhex("6012600055")})
        self.policy = policy()
        self.addCleanup(patch.stopall)
        patch.object(observer, "source_keccak", side_effect=mocked_runtime_keccak).start()
        patch.object(observer, "selector", side_effect=mocked_selector).start()
        self.rebuild()
        # All negative mutations start from an independently passing baseline,
        # including the optional unprefixed compiler objects accepted by the
        # existing identity schema. Its separate RPC cannot pollute counters.
        self.assertTrue(all(not artifact["deployedBytecode"]["object"].startswith("0x")
                            for _, artifact in self.owned.artifacts.values()))
        baseline = observer.observe_target(self.root, self.manifest, self.public,
                                           self.policy, FakeRPC(self))
        self.assertEqual(baseline["status"], "VERIFIED_AT_FINALIZED_BLOCK", baseline)
        self.assertEqual(self.rpc.calls, [])

    def rebuild(self):
        self.public["expected_runtime_code_hashes"] = {
            role: mocked_runtime_keccak(self.root, data) for role, data in self.codes.items()}
        self.manifest = identity.build_manifest(self.root, self.public)
        self.rpc = FakeRPC(self)

    def observe(self):
        return observer.observe_target(self.root, self.manifest, self.public, self.policy, self.rpc)

    def blocked(self, *, before_rpc=False):
        result = self.observe()
        self.assertEqual(result["status"], "BLOCKED", result)
        self.assertFalse(result["scope"]["target_chain_observed"])
        self.assertFalse(result["scope"]["runtime_bytecode_verified"])
        self.assertFalse(result["scope"]["operator_and_settlement_policy_matches"])
        self.assertFalse(result["scope"]["rpc_ancestry_consistent"])
        self.assertEqual(result["scope"]["release_gate"], "HOLD")
        self.assertFalse(result["scope"]["candidate_submission_enabled"])
        if before_rpc:
            self.assertEqual(self.rpc.calls, [])
        return result

    def test_all_ten_roles_seven_templates_candidate_graph_and_repeat_reads_hold(self):
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertEqual(set(result["contracts"]), identity.ADDRESS_ROLES)
        for role, item in result["contracts"].items():
            expected = ("compiler_template_and_declared_code_hash" if role in identity.CONTRACTS
                        else "declared_code_hash_only")
            self.assertEqual(item["identity_kind"], expected)
            self.assertEqual(item["runtime_sha256"], hashlib.sha256(self.codes[role]).hexdigest())
            self.assertNotEqual(item["evm_code_hash"], "0x" + item["runtime_sha256"])
        self.assertEqual(result["contracts"]["clock_verifier"]["getters"]["innerVerifier()"],
                         self.public["addresses"]["oracle_wrapper"])
        for key in ("local_identity_checked", "target_chain_observed", "runtime_bytecode_verified",
                    "operator_and_settlement_policy_matches", "rpc_ancestry_consistent"):
            self.assertTrue(result["scope"][key])
        for key in identity.SCOPE:
            if key not in {"local_identity_checked", "target_chain_observed", "runtime_bytecode_verified"}:
                self.assertEqual(result["scope"][key], identity.SCOPE[key])
        self.assertFalse(result["scope"]["uptime_health_observed"])
        self.assertFalse(result["scope"]["token_proxy_feed_implementations_audited"])
        pin = {"blockHash": block_hash(100), "requireCanonical": True}
        reads = [(method, params) for method, params in self.rpc.calls
                 if method in {"eth_getCode", "eth_call"}]
        self.assertTrue(all(params[-1] == pin for _, params in reads))
        codes = [params[0] for method, params in reads if method == "eth_getCode"]
        for value in self.public["addresses"].values():
            self.assertEqual(codes.count(value), 2)
        self.assertTrue(all(self.rpc.counts[key] == 2 for key in self.rpc.counts
                            if key[0] == "eth_call"))
        self.assertFalse(any(method == "eth_getBlockByNumber" and params[0] == "latest"
                             for method, params in self.rpc.calls))

    def test_explicit_policy_is_strict_normalized_and_never_inferred(self):
        value = policy()
        value["oracle_configurator"] = "0x" + "Ab" * 20
        self.assertEqual(observer.expected_policy(value)["oracle_configurator"], "0x" + "ab" * 20)
        for mutate in (lambda p: p.update(schema="foreign"),
                       lambda p: p.update(runtime_hash_algorithm="sha256"),
                       lambda p: p.pop("operator_policy"),
                       lambda p: p["operator_policy"]["sp1_gateway"].pop("owner"),
                       lambda p: p.update(private_key="owned-test-secret-marker"),
                       lambda p: p.update(oracle_configurator="0x1"),
                       lambda p: p["operator_policy"]["settlement"].update(challenge_bond_wei=True)):
            self.policy = policy()
            mutate(self.policy)
            with self.subTest(policy=self.policy.keys()):
                self.blocked(before_rpc=True)

    def test_wrong_schema_missing_roles_and_forged_manifest_hash_refuse_before_rpc(self):
        original = copy.deepcopy(self.manifest)
        for mutate in (lambda m: m.update(schema=identity.legacy.SCHEMA),
                       lambda m: m["compiled_contracts"].pop("oracle_wrapper"),
                       lambda m: m["source"].update(inventory_sha256="00" * 32),
                       lambda m: m["source"]["files_sha256"].update({observer.BUILDER: "00" * 32}),
                       lambda m: m["program"].update(program_vkey=identity.legacy.clock.EXPECTED_VKEY)):
            self.manifest = copy.deepcopy(original)
            mutate(self.manifest)
            with self.subTest(mutation=mutate):
                self.blocked(before_rpc=True)

    def test_wrong_code_commit_format_and_unrelated_ancestry_refuse_before_rpc(self):
        for value in ("not-a-commit", "A" * 40, "f" * 40):
            self.manifest["source"]["code_commit"] = value
            with self.subTest(commit=value), patch.object(identity, "code_commit", side_effect=REAL_CODE_COMMIT), \
                    patch.object(identity.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                self.blocked(before_rpc=True)

    def test_metadata_only_descendant_accepts_original_informational_code_commit(self):
        self.owned.head = "2" * 40
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        self.assertEqual(self.manifest["source"]["code_commit"], "1" * 40)

    def test_stale_elf_reviewed_source_and_observer_builder_refuse_before_rpc(self):
        for name in (identity.FIXTURE + "/guest.elf", "crates/perp-core/src/lib.rs", observer.BUILDER):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"\nowned-synthetic-stale-marker")
            with self.subTest(source=name):
                self.blocked(before_rpc=True)
            path.write_bytes(original)

    def test_missing_declared_address_and_hash_roles_refuse_before_rpc(self):
        original = copy.deepcopy(self.public)
        for field in ("addresses", "expected_runtime_code_hashes"):
            for role in sorted(identity.ADDRESS_ROLES):
                self.public = copy.deepcopy(original)
                self.public[field].pop(role)
                with self.subTest(field=field, role=role):
                    self.blocked(before_rpc=True)

    def test_stale_compiler_profile_source_binding_and_artifact_refuse_before_rpc(self):
        path, original = self.owned.artifacts["oracle_wrapper"]
        for mutate in (lambda a: a["metadata"]["compiler"].update(version="0.8.25"),
                       lambda a: a["metadata"]["settings"]["optimizer"].update(runs=201),
                       lambda a: a["deployedBytecode"].update(object="600260005500"),
                       lambda a: next(iter(a["metadata"]["sources"].values())).update(keccak256="0x" + "11" * 32)):
            value = copy.deepcopy(original)
            mutate(value)
            path.write_text(json.dumps(value))
            with self.subTest(artifact=mutate):
                self.blocked(before_rpc=True)
        path.write_text(json.dumps(original))

    def test_each_runtime_hash_and_sha256_substitution_fails_against_valid_manifest(self):
        for role in sorted(identity.ADDRESS_ROLES):
            for bad in ("0x" + "ee" * 32, "0x" + hashlib.sha256(self.codes[role]).hexdigest()):
                self.rebuild()
                self.public["expected_runtime_code_hashes"][role] = bad
                self.manifest = identity.build_manifest(self.root, self.public)
                with self.subTest(role=role, hash=bad):
                    self.blocked()
                    self.assertTrue(any(method == "eth_getCode" for method, _ in self.rpc.calls))

    def test_empty_nonhex_and_oversized_runtime_for_every_role_is_refused(self):
        for role in sorted(identity.ADDRESS_ROLES):
            for bad in ("0x", "0x0", "0xgg", "0x" + "00" * (observer.MAX_RUNTIME_BYTES + 1)):
                self.rpc = FakeRPC(self)
                self.rpc.overrides["eth_getCode"] = lambda params, good, _count, target=role, wrong=bad: \
                    wrong if self.rpc.by_address[params[0]] == target else good
                with self.subTest(role=role, runtime=bad[:10]):
                    self.blocked()

    def test_immutable_reference_ranges_placeholders_and_repeated_words_are_strict(self):
        role = "sp1_adapter"
        path, base = self.owned.artifacts[role]
        template = bytes.fromhex("60aa") + bytes(32) + bytes.fromhex("60bb") + bytes(32) + bytes.fromhex("60cc")
        reference = {"1": [{"start": 2, "length": 32}, {"start": 36, "length": 32}]}
        original = copy.deepcopy(base)
        for mutation in range(6):
            artifact = copy.deepcopy(original)
            artifact["deployedBytecode"].update(object=template.hex(), immutableReferences=copy.deepcopy(reference))
            code = bytearray(template)
            value = bytes.fromhex(word(self.public["addresses"]["sp1_gateway"])[2:])
            code[2:34] = value
            code[36:68] = value
            if mutation == 0:
                artifact["deployedBytecode"]["immutableReferences"]["1"][0]["length"] = 31
            elif mutation == 1:
                artifact["deployedBytecode"]["immutableReferences"]["1"][0]["start"] = -1
            elif mutation == 2:
                artifact["deployedBytecode"]["immutableReferences"]["1"][1]["start"] = 2
            elif mutation == 3:
                artifact["deployedBytecode"]["immutableReferences"]["1"][1]["start"] = 1000
            elif mutation == 4:
                changed = bytearray(template)
                changed[2] = 1
                artifact["deployedBytecode"]["object"] = changed.hex()
            else:
                code[67] ^= 1
            path.write_text(json.dumps(artifact))
            self.codes[role] = bytes(code)
            self.rebuild()
            with self.subTest(immutable_case=mutation):
                self.blocked()
        # A genuine repeat substitution is accepted, still explicitly synthetic.
        artifact["deployedBytecode"].update(object=template.hex(), immutableReferences=reference)
        path.write_text(json.dumps(artifact))
        code[2:34] = value
        code[36:68] = value
        self.codes[role] = bytes(code)
        self.rebuild()
        self.assertEqual(self.observe()["status"], "VERIFIED_AT_FINALIZED_BLOCK")

    def test_all_candidate_graph_key_clock_policy_chain_and_grace_getters_are_bound(self):
        keys = [key for key in self.rpc.values if key[1] not in {
            "sequencer()", "enclaveSigner()", "governance()", "gatewaySigner()", "configurator()", "owner()"}
                and key[1] not in set(identity.legacy.SETTLEMENT_POLICY.values())]
        for key in keys:
            self.rpc = FakeRPC(self)
            value = self.rpc.values[key]
            self.rpc.values[key] = value + 1 if type(value) is int else "0x" + "ff" * ((len(value) - 2) // 2)
            with self.subTest(getter=key):
                self.blocked()
        self.rpc = FakeRPC(self)
        # The old direct clock->SP1 graph must not satisfy the candidate graph.
        self.rpc.values[("clock_verifier", "innerVerifier()")] = self.public["addresses"]["sp1_adapter"]
        self.blocked()

    def test_every_signer_owner_configurator_and_economic_policy_is_independently_pinned(self):
        keys = [key for key in self.rpc.values if key[1] in {
            "sequencer()", "enclaveSigner()", "governance()", "gatewaySigner()", "configurator()", "owner()"}
                or key[1] in set(identity.legacy.SETTLEMENT_POLICY.values())]
        for key in keys:
            self.rpc = FakeRPC(self)
            value = self.rpc.values[key]
            self.rpc.values[key] = value + 1 if type(value) is int else address(999)
            with self.subTest(getter=key):
                self.blocked()

    def test_return_abi_address_width_narrow_uint_and_selector_are_canonical(self):
        address_key = ("clock_verifier", "innerVerifier()")
        for bad in ("0x" + "ff" * 12 + self.public["addresses"]["oracle_wrapper"][2:],
                    "0x" + "00" * 31, word(self.public["addresses"]["oracle_wrapper"]) + "00"):
            self.rpc = FakeRPC(self)
            self.rpc.overrides["eth_call"] = lambda params, good, _count, wrong=bad: \
                wrong if params[0]["to"] == self.public["addresses"][address_key[0]] \
                and params[0]["data"] == mocked_selector(None, address_key[1]) else good
            with self.subTest(raw=bad[:20]):
                self.blocked()
        for key, bad in ((("clock_verifier", "maxWindowMs()"), 2**64),
                         (("oracle_wrapper", "sequencerGraceSeconds()"), 2**64),
                         (("clock_verifier", "proofVersion()"), 256)):
            self.rpc = FakeRPC(self)
            self.rpc.values[key] = bad
            with self.subTest(narrow=key):
                self.blocked()
        self.rpc = FakeRPC(self)
        with patch.object(observer, "selector", return_value="not-a-selector"):
            self.blocked()

    def test_verifier_full_hash_route_target_freeze_bool_and_width_are_checked(self):
        correct = self.rpc.route
        for bad in (word(0) + "0" * 64,
                    word(self.public["addresses"]["sp1_verifier"]) + format(1, "064x"),
                    word(self.public["addresses"]["sp1_verifier"]) + format(2, "064x"),
                    "0x" + "ff" * 12 + self.public["addresses"]["sp1_verifier"][2:] + "0" * 64,
                    correct[:-2], correct + "00"):
            self.rpc = FakeRPC(self)
            self.rpc.route = bad
            with self.subTest(route=bad[:24]):
                self.blocked()
        self.rpc = FakeRPC(self)
        full = self.rpc.values[("sp1_verifier", "VERIFIER_HASH()")]
        self.rpc.values[("sp1_verifier", "VERIFIER_HASH()")] = full[:10] + "ff" * 28
        self.blocked()

    def test_provider_runtime_equivocation_at_same_block_is_rejected_for_each_role(self):
        for role in sorted(identity.ADDRESS_ROLES):
            self.rpc = FakeRPC(self)
            self.rpc.overrides["eth_getCode"] = lambda params, good, count, target=role: \
                good + "00" if count == 2 and self.rpc.by_address[params[0]] == target else good
            with self.subTest(role=role):
                self.blocked()

    def test_provider_getter_equivocation_at_same_block_is_rejected(self):
        keys = list(self.rpc.values)
        for role, signature in keys:
            self.rpc = FakeRPC(self)
            target = self.public["addresses"][role]
            selector = mocked_selector(None, signature)
            self.rpc.overrides["eth_call"] = lambda params, good, count, target=target, selector=selector: \
                "0x" + "ff" * 32 if count == 2 and params[0] == {"to": target, "data": selector} else good
            with self.subTest(getter=(role, signature)):
                self.blocked()
        self.rpc = FakeRPC(self)
        self.rpc.overrides["eth_call"] = lambda params, good, count: \
            good[:-1] + "1" if count == 2 and params[0]["data"].startswith(self.rpc.route_selector) else good
        self.blocked()

    def test_caller_input_snapshot_and_local_source_artifact_changes_are_never_accepted(self):
        original_manifest, original_public, original_policy = map(copy.deepcopy,
            (self.manifest, self.public, self.policy))
        mutations = [lambda: self.manifest.update(unknown=True),
                     lambda: self.public["clock"].update(clock_skew_ms=10001),
                     lambda: self.policy.update(oracle_configurator=address(999))]
        source = self.root / observer.BUILDER
        artifact = self.owned.artifacts["oracle_wrapper"][0]
        original_source, original_artifact = source.read_bytes(), artifact.read_bytes()
        mutations += [lambda: source.write_bytes(original_source + b"\n# changed mid observation\n"),
                      lambda: artifact.write_bytes(original_artifact + b"\n")]
        for mutate in mutations:
            self.manifest, self.public, self.policy = map(copy.deepcopy,
                (original_manifest, original_public, original_policy))
            source.write_bytes(original_source)
            artifact.write_bytes(original_artifact)
            self.rpc = FakeRPC(self)
            def hook(method, _params, good, _count):
                if method == "eth_call" and not getattr(self.rpc, "changed", False):
                    self.rpc.changed = True
                    mutate()
                return good
            self.rpc.hook = hook
            with self.subTest(input_or_file=mutate):
                self.blocked()

    def test_wrong_chain_and_mid_observation_chain_switch_refuse(self):
        for override in ("0x1", lambda _params, _good, count: "0x1" if count > 1 else "0x14a34"):
            self.rpc = FakeRPC(self)
            self.rpc.overrides["eth_chainId"] = override
            with self.subTest(chain=override):
                self.blocked()

    def test_missing_noncanonical_and_zero_headers_are_rejected_without_latest_fallback(self):
        for bad in (None, {}, {"number": "0x64", "hash": block_hash(100)},
                    {"number": "0x064", "hash": block_hash(100), "parentHash": block_hash(99)},
                    {"number": "0x64", "hash": block_hash(0), "parentHash": block_hash(99)},
                    {"number": "0x64", "hash": "0x1", "parentHash": block_hash(99)},
                    {"number": "0x64", "hash": block_hash(100), "parentHash": "0x1"},
                    {"number": hex(2**64), "hash": block_hash(100), "parentHash": block_hash(99)}):
            self.rpc = FakeRPC(self)
            self.rpc.initial_header = bad
            with self.subTest(header=bad):
                self.blocked()
                self.assertFalse(any(method == "eth_getBlockByNumber" and params[0] == "latest"
                                     for method, params in self.rpc.calls))

    def test_finalized_regression_same_height_fork_and_changed_anchor_refuse(self):
        for mutation in range(4):
            self.rpc = FakeRPC(self)
            if mutation == 0:
                self.rpc.tip = 99
            elif mutation == 1:
                self.rpc.headers[100]["hash"] = block_hash(999)
            elif mutation == 2:
                self.rpc.header_changes[100] = {**self.rpc.headers[100], "hash": block_hash(999)}
            else:
                self.rpc.headers[100]["parentHash"] = block_hash(999)
            with self.subTest(finality_case=mutation):
                self.blocked()

    def test_valid_finalized_advancement_and_exact_ancestry_bound_are_allowed(self):
        for count in (0, 3, observer.MAX_ANCESTRY):
            self.rpc = FakeRPC(self)
            self.rpc.tip = 100 + count
            with self.subTest(advance=count):
                result = self.observe()
                self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
                self.assertTrue(result["scope"]["rpc_ancestry_consistent"])
                self.assertEqual(result["anchor"]["hash"], block_hash(100))
                self.assertEqual(result["finalized_tip_at_completion"]["number"], 100 + count)

    def test_ancestry_hole_fork_wrong_height_and_over_bound_are_hold(self):
        for mutation in range(4):
            self.rpc = FakeRPC(self)
            self.rpc.tip = 103
            if mutation == 0:
                self.rpc.header_changes[102] = None
            elif mutation == 1:
                self.rpc.headers[103]["parentHash"] = block_hash(999)
            elif mutation == 2:
                self.rpc.header_changes[102] = {**self.rpc.headers[102], "number": "0x65"}
            else:
                self.rpc.tip = 100 + observer.MAX_ANCESTRY + 1
            with self.subTest(ancestry_case=mutation):
                self.blocked()
                height_reads = [params for method, params in self.rpc.calls
                                if method == "eth_getBlockByNumber" and params[0] != "finalized"]
                self.assertLessEqual(len(height_reads), observer.MAX_ANCESTRY + 1)

    def test_injected_provider_cannot_mutate_saved_pin_or_replay_call_arguments(self):
        def mutate_arguments(method, params, result, _count):
            if method in {"eth_getCode", "eth_call"}:
                params[-1]["blockHash"] = block_hash(999)
                if method == "eth_call":
                    params[0]["data"] = "0xdeadbeef"
            return result
        self.rpc.hook = mutate_arguments
        result = self.observe()
        self.assertEqual(result["status"], "VERIFIED_AT_FINALIZED_BLOCK", result)
        pin = {"blockHash": block_hash(100), "requireCanonical": True}
        self.assertTrue(all(params[-1] == pin for method, params in self.rpc.calls
                            if method in {"eth_getCode", "eth_call"}))

    def test_unexpected_provider_exceptions_and_local_tool_errors_never_echo_payloads(self):
        marker = "owned-provider-private-error-marker"
        for error in (ValueError(marker), OSError(marker), KeyError(marker), RuntimeError(marker)):
            self.rpc = FakeRPC(self)
            def failed(_method, _params, _result, _count):
                raise error
            self.rpc.hook = failed
            with self.subTest(error_type=type(error).__name__):
                self.assertNotIn(marker, json.dumps(self.blocked()))
        self.rpc = FakeRPC(self)
        with patch.object(observer, "source_keccak", side_effect=ValueError(marker)):
            self.assertNotIn(marker, json.dumps(self.blocked()))


class Response:
    def __init__(self, body):
        self.body = body
        self.offset = 0
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def read(self, limit):
        result = self.body[self.offset:self.offset + limit]
        self.offset += len(result)
        return result
    def read1(self, limit):
        if limit > 4096:
            raise AssertionError("response chunk must be bounded")
        return self.read(limit)


class TransportTests(unittest.TestCase):
    def test_only_anonymous_root_endpoints_and_four_read_methods_are_accepted(self):
        with patch.object(observer.urllib.request, "getproxies", side_effect=AssertionError("ambient proxy lookup")) as proxies:
            direct = observer.CandidateRPC("http://127.0.0.1:12345/")
            proxies.assert_not_called()
        self.assertFalse(any(name.lower() in {"authorization", "proxy-authorization"}
                             for name, _ in direct.opener.addheaders))
        for url in ("https://user:secret@example.invalid", "https://example.invalid/path-key",
                    "https://example.invalid?key=secret", "https://example.invalid#secret",
                    "ws://example.invalid", "https://example.invalid:bad", "https://example.invalid/\n"):
            with self.subTest(endpoint=url), self.assertRaises(observer.ObserverError) as raised:
                observer.CandidateRPC(url)
            self.assertNotIn(url, str(raised.exception))
        rpc = observer.CandidateRPC("http://127.0.0.1:12345/")
        for method in ("eth_sendTransaction", "eth_accounts", "eth_getStorageAt", "anvil_mine"):
            with self.subTest(method=method), patch.object(rpc.opener, "open") as opened:
                with self.assertRaises(observer.ObserverError):
                    rpc(method, [])
                opened.assert_not_called()

    def test_bad_envelope_duplicate_deep_nonfinite_size_and_redirect_fail_without_echo(self):
        marker = "owned-private-provider-marker"
        cases = [b'{"jsonrpc":"2.0","id":true,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":2,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":1,"result":"0x1","extra":"private"}',
                 ('{"jsonrpc":"2.0","id":1,"error":{"message":"' + marker + '"}}').encode(),
                 b'{"jsonrpc":"2.0","id":1,"result":NaN}',
                 ('{"jsonrpc":"2.0","id":1,"result":' + '[' * 70 + '0' + ']' * 70 + '}').encode(),
                 b'\xff', marker.encode(),
                 b'x' * (identity.legacy.deployment_reader.MAX_RPC_RESPONSE_BYTES + 1)]
        for body in cases:
            rpc = observer.CandidateRPC("https://example.invalid")
            with self.subTest(response=body[:30]), patch.object(rpc.opener, "open", return_value=Response(body)):
                with self.assertRaises(observer.ObserverError) as raised:
                    rpc("eth_chainId", [])
                self.assertNotIn(marker, str(raised.exception))
        with self.assertRaises(observer.ObserverError):
            observer.NoRedirect().redirect_request(None, None, 302, "", {}, "https://private.invalid")

    def test_successful_envelopes_have_monotonic_ids_and_total_time_budget_is_enforced(self):
        rpc = observer.CandidateRPC("https://example.invalid")
        responses = [Response(json.dumps({"jsonrpc": "2.0", "id": i, "result": "0x1"}).encode())
                     for i in (1, 2)]
        with patch.object(rpc.opener, "open", side_effect=responses) as opened:
            self.assertEqual(rpc("eth_chainId", []), "0x1")
            self.assertEqual(rpc("eth_chainId", []), "0x1")
            requests = [json.loads(call.args[0].data) for call in opened.call_args_list]
            self.assertEqual([request["id"] for request in requests], [1, 2])
            self.assertTrue(all(call.kwargs["timeout"] <= 15 for call in opened.call_args_list))
        rpc.deadline = 0
        with patch.object(rpc.opener, "open") as opened:
            with self.assertRaises(observer.ObserverError):
                rpc("eth_chainId", [])
            opened.assert_not_called()
        # EOF does not excuse elapsed socket/call budget. Fake time changes only
        # when this response's EOF is observed; no real waiting is required.
        elapsed = [0.0]
        class SlowEOF(Response):
            def read1(self, limit):
                result = super().read1(limit)
                if not result:
                    elapsed[0] = 16.0
                return result
        rpc = observer.CandidateRPC("https://example.invalid")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()
        with patch.object(observer.time, "monotonic", side_effect=lambda: elapsed[0]), \
                patch.object(rpc.opener, "open", return_value=SlowEOF(body)):
            with self.assertRaises(observer.ObserverError):
                rpc("eth_chainId", [])


if __name__ == "__main__":
    unittest.main()
