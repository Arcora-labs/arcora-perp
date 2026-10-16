"""deploy_clock_stack: ordered clock-stack deploy through cast, guarded by chain kind."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
import unittest.mock
from pathlib import Path

import deploy_clock_stack as deploy
import release_manifest as release

GENESIS = "0x" + "4d" * 32
OWNER = "0x" + "f1" * 20


def policy():
    return {
        "settlement": {"sequencer": OWNER, "enclave_signer": "0x" + "e2" * 20, "governance": OWNER,
                       "liveness_timeout_blocks": 100, "challenge_window_blocks": 50,
                       "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                       "final_settle_grace_blocks": 10},
        "vault": {"gateway_signer": "0x" + "a3" * 20},
        "clock_verifier": {"configurator": OWNER},
        "sp1_gateway": {"owner": OWNER},
    }


def plan_config(**overrides):
    value = {"chain_id": 31337, "genesis_root": GENESIS, "sp1_gateway": None,
             "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000},
             "operator_policy": policy()}
    value.update(overrides)
    return value


# Records every argv; answers like cast. Contract addresses are 0x..01, 0x..02, ...
FAKE_CAST = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    log = os.environ["FAKE_CAST_LOG"]
    args = sys.argv[1:]
    with open(log, "a") as stream:
        stream.write(json.dumps(args) + "\\n")
    if args[0] == "chain-id":
        print(os.environ.get("FAKE_CHAIN", "31337"))
    elif args[:2] == ["rpc", "web3_clientVersion"]:
        print(json.dumps(os.environ.get("FAKE_CLIENT", "anvil/v1.0.0")))
    elif args[0] == "send":
        count = sum(1 for line in open(log) if json.loads(line)[0] == "send")
        fail_at = int(os.environ.get("FAKE_FAIL_AT", "0"))
        receipt = {"status": "0x0" if count == fail_at else "0x1",
                   "transactionHash": "0x" + format(count, "064x"),
                   "blockNumber": hex(100 + count)}
        if "--create" in args:
            receipt["contractAddress"] = "0x" + format(count, "040x")
        print(json.dumps(receipt))
    else:
        sys.exit(3)
""")


class CastFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        fake = self.tmp / "cast"
        fake.write_text(FAKE_CAST)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.log = self.tmp / "cast.log"
        self.log.touch()
        self.env = {"PATH": f"{self.tmp}{os.pathsep}{os.environ['PATH']}", "FAKE_CAST_LOG": str(self.log)}
        self.config = self.tmp / "deploy.json"
        self.output = self.tmp / "public-config.json"
        self.artifacts = {role: "0x60" + format(i, "02x") for i, role in enumerate(deploy.ROLES_IN_ORDER, 1)}

    def write_config(self, **overrides):
        self.config.write_text(json.dumps(plan_config(**overrides)))

    def run_cli(self, extra=(), env=None, signer=("--unlocked", "--from", OWNER)):
        with unittest.mock.patch.dict(os.environ, {**self.env, **(env or {})}), \
                unittest.mock.patch.object(deploy, "bytecode", lambda role: self.artifacts[role]):
            return deploy.main(["--config", str(self.config), "--rpc", "http://127.0.0.1:8545",
                                "--output", str(self.output), *extra, "--", *signer])

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def sends(self):
        return [c for c in self.calls() if c[0] == "send"]


class Guards(CastFixture):
    def test_public_chain_is_refused_without_explicit_flag(self):
        self.write_config(chain_id=84532)
        code = self.run_cli(env={"FAKE_CHAIN": "84532", "FAKE_CLIENT": "Geth/v1.14"})
        self.assertEqual(code, 2)
        self.assertEqual(self.sends(), [])
        self.assertFalse(self.output.exists())

    def test_public_dev_gateway_signer_is_refused_off_anvil(self):
        anvil0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        config = policy()
        config["vault"]["gateway_signer"] = anvil0
        self.write_config(chain_id=84532, operator_policy=config)
        code = self.run_cli(extra=["--allow-public-chain"], env={"FAKE_CHAIN": "84532", "FAKE_CLIENT": "Geth/v1.14"})
        self.assertEqual(code, 2)
        self.assertEqual(self.sends(), [])
        self.assertFalse(self.output.exists())
        # The same signer is fine on an owned Anvil (local and fork dry runs).
        self.write_config(operator_policy=config)
        self.assertEqual(self.run_cli(), 0)

    def test_config_chain_must_match_rpc(self):
        self.write_config(chain_id=84532)
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])

    def test_zero_genesis_root_is_refused(self):
        self.write_config(genesis_root="0x" + "00" * 32)
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])

    def test_program_key_is_not_configurable(self):
        self.write_config(program_vkey="0x" + "ab" * 32)
        self.assertEqual(self.run_cli(), 2)

    def test_signer_flags_are_required(self):
        self.write_config()
        self.assertEqual(self.run_cli(signer=()), 2)
        self.assertEqual(self.sends(), [])


class Order(CastFixture):
    def test_fresh_stack_deploys_in_dependency_order(self):
        self.write_config()
        self.assertEqual(self.run_cli(), 0)
        sends = self.sends()
        kinds = [("create", s[s.index("--create") + 1][:6]) if "--create" in s else ("call", s[-2]) for s in sends]
        a = self.artifacts
        self.assertEqual(kinds, [
            ("create", a["sp1_verifier"]), ("create", a["sp1_gateway"]),
            ("call", "addRoute(address)"),
            ("create", a["sp1_adapter"]), ("create", a["clock_verifier"]),
            ("create", a["settlement"]), ("create", a["token"]), ("create", a["vault"]),
            ("call", "setVault(address)"), ("call", "bindSettlement(address)"),
        ])
        for s in sends:
            # cast reads everything after `--create <CODE>` as constructor
            # arguments, so every option must precede the payload.
            payload = s.index("--create") if "--create" in s else len(s) - 3
            self.assertEqual(s[1:payload], ["--rpc-url", "http://127.0.0.1:8545", "--json", "--unlocked", "--from", OWNER])

    def test_settlement_constructor_words_follow_the_policy(self):
        self.write_config()
        self.run_cli()
        settlement = self.sends()[5]
        initcode = settlement[settlement.index("--create") + 1]
        words = [initcode[len(self.artifacts["settlement"]) + 64 * i:][:64] for i in range(10)]
        p = policy()["settlement"]
        self.assertEqual(words, [
            p["sequencer"][2:].rjust(64, "0"), p["enclave_signer"][2:].rjust(64, "0"),
            "0" * 24 + format(5, "040x"),  # clock verifier = 5th contract created
            GENESIS[2:],
            format(100, "064x"), format(50, "064x"), format(1000, "064x"), format(600, "064x"),
            p["governance"][2:].rjust(64, "0"), format(10, "064x"),
        ])

    def test_output_is_a_valid_release_public_config(self):
        self.write_config()
        self.run_cli()
        public = json.loads(self.output.read_text())
        self.assertEqual(release.public_config(public)["program_vkey"], release.clock.EXPECTED_VKEY)
        self.assertEqual(public["gateway"]["L1_SETTLEMENT"], public["addresses"]["settlement"])
        self.assertEqual(public["gateway"]["L1_ALLOW_MOCK_PROOF"], "0")
        record = json.loads(self.output.with_suffix(".deployment.json").read_text())
        self.assertEqual(len(record["transactions"]), 10)

    def test_existing_sp1_gateway_is_reused(self):
        gateway = "0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"
        self.write_config(sp1_gateway=gateway, sp1_verifier="0x" + "0b" * 20)
        self.assertEqual(self.run_cli(), 0)
        sends = self.sends()
        self.assertEqual(len(sends), 7)
        adapter = sends[0][sends[0].index("--create") + 1]
        self.assertEqual(adapter[len(self.artifacts["sp1_adapter"]):][:64], gateway[2:].lower().rjust(64, "0"))
        public = json.loads(self.output.read_text())
        self.assertEqual(public["addresses"]["sp1_gateway"], gateway.lower())

    def test_failed_transaction_stops_and_keeps_a_partial_record(self):
        self.write_config()
        code = self.run_cli(env={"FAKE_FAIL_AT": "6"})
        self.assertEqual(code, 1)
        self.assertEqual(len(self.sends()), 6)
        self.assertFalse(self.output.exists())
        partial = json.loads(self.output.with_suffix(".partial.json").read_text())
        self.assertEqual(sorted(partial["addresses"]), ["clock_verifier", "sp1_adapter", "sp1_gateway", "sp1_verifier"])
        self.assertEqual(partial["failed"], "settlement")


if __name__ == "__main__":
    unittest.main()


def start_owned_anvil(test, extra=()):
    """Child Anvil on a kernel-assigned loopback port; returns its URL."""
    import re, select, threading, time
    process = subprocess.Popen(["anvil", "--host", "127.0.0.1", "--port", "0", *extra],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    drain = []

    def cleanup():
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        for thread in drain:
            thread.join(timeout=5)
        process.stdout.close()
    test.addCleanup(cleanup)
    output, port, deadline = b"", None, time.monotonic() + 30
    while time.monotonic() < deadline and port is None:
        test.assertIsNone(process.poll(), "owned Anvil failed before binding")
        if select.select([process.stdout], [], [], 0.1)[0]:
            output += os.read(process.stdout.fileno(), 8192)
            matched = re.search(rb"Listening on 127\.0\.0\.1:(\d+)", output)
            port = int(matched.group(1)) if matched else None
    test.assertIsNotNone(port, "owned Anvil did not report its bound port")
    thread = threading.Thread(target=lambda: [None for _ in iter(lambda: process.stdout.read(8192), b"")], daemon=True)
    thread.start()
    drain.append(thread)
    return f"http://127.0.0.1:{port}"


def rpc(url, method, params):
    import urllib.request
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                                     "params": params}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    assert "error" not in value, value
    return value["result"]


@unittest.skipUnless(os.environ.get("ARCORA_RUN_DEPLOY_ANVIL") == "1", "opt-in owned Anvil deploy (needs forge build)")
class OwnedAnvil(unittest.TestCase):
    def test_real_artifacts_deploy_and_observe_as_verified(self):
        url = start_owned_anvil(self, ["--chain-id", "31337"])
        accounts = rpc(url, "eth_accounts", [])
        owner = accounts[0]
        operator_policy = {
            "settlement": {"sequencer": owner, "enclave_signer": accounts[1], "governance": owner,
                           "liveness_timeout_blocks": 100, "challenge_window_blocks": 50,
                           "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                           "final_settle_grace_blocks": 10},
            "vault": {"gateway_signer": accounts[2]},
            "clock_verifier": {"configurator": owner},
            "sp1_gateway": {"owner": owner},
        }
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        config = tmp / "deploy.json"
        config.write_text(json.dumps({"chain_id": 31337, "genesis_root": GENESIS, "sp1_gateway": None,
                                      "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000},
                                      "operator_policy": operator_policy}))
        output = tmp / "public-config.json"
        code = deploy.main(["--config", str(config), "--rpc", url, "--output", str(output),
                            "--", "--unlocked", "--from", owner])
        self.assertEqual(code, 0)
        rpc(url, "anvil_mine", ["0x80"])
        public = json.loads(output.read_text())
        manifest = release.build_manifest(release.ROOT, public)
        observed = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url),
                                          require_operator_policy=True)
        evidence = os.environ.get("ARCORA_DEPLOY_ANVIL_EVIDENCE")
        if evidence:
            Path(evidence).write_text(json.dumps({"public_config": public, "observed": observed,
                                                  "deployment": json.loads(output.with_suffix(".deployment.json").read_text())},
                                                 indent=2, sort_keys=True) + "\n")
        self.assertEqual(observed["status"], "VERIFIED_AT_FINALIZED_BLOCK", observed)
        self.assertEqual(len(observed["contracts"]), 6)
        self.assertTrue(observed["scope"]["operator_and_settlement_policy_matches"])
