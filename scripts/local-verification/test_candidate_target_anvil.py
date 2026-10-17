#!/usr/bin/env python3
"""Opt-in owned Anvil observation: real candidate contracts, explicit mocks.

No caller URL/key/node is accepted. This test generates no proof, authenticates
no DON, starts no gateway/prover, and cannot promote the release beyond HOLD.
"""
import copy
import json
import os
from pathlib import Path
import re
import select
import subprocess
import threading
import time
import unittest

import candidate_identity_manifest as identity
import candidate_target_observer as observer
import release_manifest as legacy


@unittest.skipUnless(os.environ.get("ARCORA_RUN_CANDIDATE_TARGET_ANVIL") == "1",
                     "opt-in owned candidate Anvil integration")
class CandidateTargetAnvilTests(unittest.TestCase):
    def test_seven_real_contracts_and_safe_candidate_refusals(self):
        evidence = os.environ.get("ARCORA_CANDIDATE_TARGET_ANVIL_EVIDENCE")
        evidence_path = Path(evidence) if evidence else None
        if evidence_path is not None:
            self.assertFalse(evidence_path.exists() or evidence_path.is_symlink(),
                             "evidence output must be fresh; never clobber")
            self.assertTrue(evidence_path.parent.is_dir(), "owned output parent must exist")

        # The child itself asks the kernel for a port. No reserve/close race,
        # fixed port, supplied external URL, credentials or existing node.
        process = subprocess.Popen(
            ["anvil", "--host", "127.0.0.1", "--port", "0", "--chain-id", "84532"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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
        # Startup output can contain synthetic keys. Consume both streams and
        # discard all of it; neither assertions nor evidence emit those bytes.
        output = b""

        def drain_output():
            while process.stdout.read(8192):
                pass

        drain_thread = threading.Thread(target=drain_output, daemon=True)
        drain_thread.start()
        url = f"http://127.0.0.1:{port}"
        sequence = 0

        def local_rpc(method, params):
            import urllib.request
            nonlocal sequence
            sequence += 1
            request = urllib.request.Request(
                url, data=json.dumps({"jsonrpc": "2.0", "id": sequence,
                                      "method": method, "params": params}).encode(),
                headers={"Content-Type": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), observer.NoRedirect)
            with opener.open(request, timeout=10) as response:
                value = json.load(response)
            self.assertNotIn("error", value, "owned local RPC rejected test operation")
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
            return (format(value, "064x") if type(value) is int
                    else value.removeprefix("0x").rjust(64, "0"))

        def transact(data, to=None):
            tx = {"from": owner, "data": data, "gas": "0x1c9c380"}
            if to is not None:
                tx["to"] = to
            transaction = local_rpc("eth_sendTransaction", [tx])
            for _ in range(100):
                receipt = local_rpc("eth_getTransactionReceipt", [transaction])
                if receipt is not None:
                    break
                time.sleep(0.05)
            self.assertIsNotNone(receipt, "owned local transaction was not mined")
            self.assertEqual(receipt["status"], "0x1", "owned local test transaction reverted")
            return receipt

        mock_artifacts = {
            "token": "out/MockUSDC.sol/MockUSDC.json",
            "verifier_proxy": "out/ChainlinkOracleVerifier.t.sol/MockStreamsForCandidate.json",
            "uptime_feed": "out/MockSequencerUptime.sol/MockSequencerUptime.json",
        }

        def deploy(role, *args):
            relative = (identity.CONTRACTS[role][0] if role in identity.CONTRACTS
                        else mock_artifacts[role])
            artifact = identity.read_json(identity.ROOT / "contracts" / relative,
                                          64 * 1024 * 1024)
            creation = artifact["bytecode"]["object"]
            if not creation.startswith("0x"):
                creation = "0x" + creation
            address = transact(creation + "".join(word(arg) for arg in args))["contractAddress"]
            self.assertRegex(address, r"^0x[0-9a-fA-F]{40}$")
            return address.lower()

        def call_transaction(signature, target, *args):
            return transact(legacy.deployment_reader.selector(signature)
                            + "".join(word(arg) for arg in args), target)

        def mine_finalized():
            local_rpc("anvil_mine", ["0x80"])

        def runtime_hash(address):
            code = local_rpc("eth_getCode", [address, "latest"])
            self.assertNotEqual(code, "0x", "owned deployed contract has empty runtime")
            return identity.source_keccak(identity.ROOT, bytes.fromhex(code[2:]))

        # Seven REAL compiler artifacts: verifier, gateway, adapter, wrapper,
        # clock, settlement and collateral vault. The three additional mocks
        # are token/proxy/uptime only; #50's mock prefix vault/gateway are unused.
        self.assertEqual(len(identity.CONTRACTS), 7)
        key = identity.candidate.VKEY
        policy_hash = "0x" + "31" * 32
        grace = 10
        max_window_ms, clock_skew_ms, anchor_timeout_ms = 2000, 0, 3_600_000
        # DarkPerpSettlement.Config after the verifier: genesis root, liveness, challenge
        # grace, challenge bond, inclusion deadline, governance, final-settle grace,
        # progress batches, slash payout cap (12 words with sequencer/enclave/verifier).
        settlement_tail = (0, 100, 50, 1000, 600, owner, 10, 2, 1_000_000_000)
        addresses = {}
        addresses["sp1_verifier"] = deploy("sp1_verifier")
        addresses["sp1_gateway"] = deploy("sp1_gateway", owner)
        call_transaction("addRoute(address)", addresses["sp1_gateway"], addresses["sp1_verifier"])
        addresses["sp1_adapter"] = deploy("sp1_adapter", addresses["sp1_gateway"], key)
        addresses["verifier_proxy"] = deploy("verifier_proxy")
        addresses["uptime_feed"] = deploy("uptime_feed")
        addresses["oracle_wrapper"] = deploy("oracle_wrapper", addresses["sp1_adapter"],
                                               addresses["verifier_proxy"], policy_hash,
                                               addresses["uptime_feed"], grace)
        addresses["clock_verifier"] = deploy("clock_verifier", addresses["oracle_wrapper"],
                                               max_window_ms, clock_skew_ms, anchor_timeout_ms)
        addresses["settlement"] = deploy("settlement", owner, accounts[1],
                                           addresses["clock_verifier"], *settlement_tail)
        addresses["token"] = deploy("token")
        addresses["vault"] = deploy("vault", addresses["settlement"],
                                      addresses["token"], accounts[2])
        call_transaction("setVault(address)", addresses["settlement"], addresses["vault"])
        call_transaction("bindSettlement(address)", addresses["clock_verifier"], addresses["settlement"])
        call_transaction("bindClock(address)", addresses["oracle_wrapper"], addresses["clock_verifier"])
        mine_finalized()
        self.assertEqual(set(addresses), identity.ADDRESS_ROLES)
        self.assertEqual(len(set(addresses.values())), 10)
        public = {
            "chain_id": 84532, "network": 0, "addresses": addresses,
            "expected_runtime_code_hashes": {role: runtime_hash(address) for role, address in addresses.items()},
            "program_vkey": key,
            "clock": {"max_window_ms": max_window_ms, "clock_skew_ms": clock_skew_ms,
                      "anchor_timeout_ms": anchor_timeout_ms},
            "oracle_policy_hash": policy_hash, "sequencer_grace_seconds": grace,
        }
        policy = {
            "schema": "arcora-chainlink-target-policy/v1",
            "runtime_hash_algorithm": "keccak256-evm",
            "operator_policy": {
                "settlement": {"sequencer": owner, "enclave_signer": accounts[1], "governance": owner,
                               "liveness_timeout_blocks": 100, "challenge_grace_blocks": 50,
                               "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                               "final_settle_grace_blocks": 10, "progress_batches": 2,
                               "slash_payout_cap_usdc": 1_000_000_000},
                "vault": {"gateway_signer": accounts[2]},
                "clock_verifier": {"configurator": owner},
                "sp1_gateway": {"owner": owner},
            },
            "oracle_configurator": owner,
        }
        observer.expected_policy(policy)
        manifest = identity.build_manifest(identity.ROOT, public)
        read_transport = observer.CandidateRPC(url)

        def observe(config=public, expected=policy, declaration=None):
            calls = []

            def traced(method, params):
                calls.append((method, copy.deepcopy(params)))
                return read_transport(method, params)

            result = observer.observe_target(identity.ROOT, declaration or manifest,
                                             config, expected, traced)
            return result, calls

        observed, calls = observe()
        self.assertEqual(observed["status"], "VERIFIED_AT_FINALIZED_BLOCK", observed)
        self.assertTrue(observed["scope"]["target_chain_observed"])
        self.assertTrue(observed["scope"]["runtime_bytecode_verified"])
        self.assertEqual(observed["scope"]["release_gate"], "HOLD")
        for field in ("running_services_attested", "proof_generated", "real_don_verified",
                      "custody_accepted", "operator_policy_approved", "candidate_submission_enabled"):
            self.assertFalse(observed["scope"][field], field)
        self.assertTrue(calls)
        self.assertTrue(all(method in legacy.deployment_reader.READ_METHODS for method, _ in calls))
        bound = [params[-1] for method, params in calls if method in ("eth_call", "eth_getCode")]
        self.assertTrue(bound)
        self.assertTrue(all(value == bound[0] for value in bound))
        self.assertEqual(set(bound[0]), {"blockHash", "requireCanonical"})
        self.assertIs(bound[0]["requireCanonical"], True)
        self.assertEqual(len(bytes.fromhex(bound[0]["blockHash"][2:])), 32)
        code_addresses = {params[0].lower() for method, params in calls if method == "eth_getCode"}
        self.assertEqual(code_addresses, set(addresses.values()))
        rejections = {}

        def rejected(name, config=public, expected=policy):
            # Each altered public config has its own genuine current-source
            # manifest. A declaration mismatch cannot be blamed on stale bytes.
            declaration = (manifest if config is public
                           else identity.build_manifest(identity.ROOT, config))
            result, attempted = observe(config, expected, declaration)
            self.assertEqual(result["status"], "BLOCKED", (name, result))
            self.assertEqual(result["scope"]["release_gate"], "HOLD")
            self.assertFalse(result["scope"]["runtime_bytecode_verified"], name)
            self.assertFalse(result["scope"]["target_chain_observed"], name)
            rejections[name] = result
            return attempted

        for name, field in (("wrong_policy_hash", "oracle_policy_hash"),
                            ("wrong_grace", "sequencer_grace_seconds"),
                            ("wrong_runtime_hash", "expected_runtime_code_hashes"),
                            ("wrong_clock_policy", "clock"),
                            ("wrong_anchor_timeout", "anchor_timeout_ms")):
            bad = copy.deepcopy(public)
            if field == "oracle_policy_hash":
                bad[field] = "0x" + "ab" * 32
            elif field == "sequencer_grace_seconds":
                bad[field] += 1
            elif field == "expected_runtime_code_hashes":
                bad[field]["oracle_wrapper"] = "0x" + "ab" * 32
            elif field == "anchor_timeout_ms":
                bad["clock"]["anchor_timeout_ms"] += 1
            else:
                bad[field]["max_window_ms"] += 1
            with self.subTest(name=name):
                rejected(name, bad)
        for name in ("wrong_governance", "wrong_challenge_bond", "wrong_progress_batches",
                     "wrong_slash_payout_cap", "wrong_oracle_configurator"):
            bad_policy = copy.deepcopy(policy)
            if name == "wrong_governance":
                bad_policy["operator_policy"]["settlement"]["governance"] = accounts[3]
            elif name == "wrong_challenge_bond":
                bad_policy["operator_policy"]["settlement"]["challenge_bond_wei"] += 1
            elif name == "wrong_progress_batches":
                bad_policy["operator_policy"]["settlement"]["progress_batches"] += 1
            elif name == "wrong_slash_payout_cap":
                bad_policy["operator_policy"]["settlement"]["slash_payout_cap_usdc"] -= 1
            else:
                bad_policy["oracle_configurator"] = accounts[3]
            with self.subTest(name=name):
                observer.expected_policy(bad_policy)
                rejected(name, expected=bad_policy)

        bad_key = copy.deepcopy(public)
        bad_key["program_vkey"] = legacy.clock.EXPECTED_VKEY
        blocked_key, attempted = observe(bad_key)
        self.assertEqual(blocked_key["status"], "BLOCKED")
        self.assertEqual(attempted, [], "wrong reviewed-v2 key must be rejected before RPC")
        self.assertEqual(blocked_key["scope"]["release_gate"], "HOLD")
        rejections["wrong_reviewed_v2_key_pre_rpc"] = blocked_key

        for role in ("verifier_proxy", "uptime_feed"):
            replacement = deploy(role)
            mine_finalized()
            bad = copy.deepcopy(public)
            bad["addresses"][role] = replacement
            bad["expected_runtime_code_hashes"][role] = runtime_hash(replacement)
            with self.subTest(role=role):
                rejected("unbound_" + role, bad)
        wrong_clock = deploy("clock_verifier", addresses["sp1_adapter"], max_window_ms, clock_skew_ms,
                             anchor_timeout_ms)
        # Keep every link before clock.innerVerifier valid. These additional
        # REAL settlement/vault instances use the original explicit operator
        # values, token and policy; only the direct SP1 inner route is wrong.
        wrong_settlement = deploy("settlement", owner, accounts[1], wrong_clock, *settlement_tail)
        wrong_vault = deploy("vault", wrong_settlement, addresses["token"], accounts[2])
        call_transaction("setVault(address)", wrong_settlement, wrong_vault)
        call_transaction("bindSettlement(address)", wrong_clock, wrong_settlement)
        mine_finalized()
        bad_clock = copy.deepcopy(public)
        for role, address in (("clock_verifier", wrong_clock),
                              ("settlement", wrong_settlement), ("vault", wrong_vault)):
            bad_clock["addresses"][role] = address
            bad_clock["expected_runtime_code_hashes"][role] = runtime_hash(address)
        self.assertEqual(len(set(bad_clock["addresses"].values())), 10)
        rejected("direct_sp1_clock_instead_of_wrapper", bad_clock)
        self.assertEqual(
            rejections["direct_sp1_clock_instead_of_wrapper"]["blocker"],
            "target binding mismatch: clock_verifier.innerVerifier()")

        # Actual mutation of OUR gateway, then a newly finalized observation.
        # The test never registers reports, submits proofs or invokes settlement.
        freeze = (legacy.deployment_reader.selector("freezeRoute(bytes4)")
                  + legacy.clock.target.VERIFIER_HASH[:8] + "0" * 56)
        transact(freeze, addresses["sp1_gateway"])
        mine_finalized()
        rejected("actual_frozen_sp1_route")
        if evidence_path is not None:
            payload = {
                "scope": "Owned disposable Anvil chain84532, seven real compiled contracts and mock token/streams/uptime; no public target, DON, service, proof or release acceptance.",
                "public_config": public,
                "expected_policy": policy,
                "manifest_sha256": identity.digest(identity.canonical(manifest)),
                "pass": observed,
                "refusals": rejections,
                "read_methods": sorted({method for method, _ in calls}),
                "proof_generated": False, "real_don_verified": False,
                "running_services_attested": False, "release_gate": "HOLD",
            }
            with evidence_path.open("x", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True)
                stream.write("\n")


if __name__ == "__main__":
    unittest.main()
