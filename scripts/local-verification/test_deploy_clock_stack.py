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
# Synthetic genesis addresses, distinct from every policy and public dev account.
RECIPIENT = "0x" + "5a" * 20
ORACLE_SIGNER = "0x" + "6b" * 20
ANVIL0 = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"


def policy():
    """Small local-test values: below the Base floors, valid for the constructors."""
    return {
        "settlement": {"sequencer": OWNER, "enclave_signer": "0x" + "e2" * 20, "governance": OWNER,
                       "liveness_timeout_blocks": 100, "challenge_grace_blocks": 50,
                       "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                       "final_settle_grace_blocks": 10, "progress_batches": 2,
                       "slash_payout_cap_usdc": 1_000_000_000},
        "vault": {"gateway_signer": "0x" + "a3" * 20},
        "clock_verifier": {"configurator": OWNER},
        "sp1_gateway": {"owner": OWNER},
    }


def launch_policy():
    """The Base Sepolia launch defaults."""
    value = policy()
    value["settlement"].update(liveness_timeout_blocks=43_200, challenge_grace_blocks=3_600,
                               challenge_bond_wei=10**16, inclusion_deadline_seconds=3_600,
                               final_settle_grace_blocks=300, progress_batches=2,
                               slash_payout_cap_usdc=1_000_000_000)
    return value


LAUNCH_CLOCK = {"max_window_ms": 30000, "clock_skew_ms": 30000, "anchor_timeout_ms": 3_600_000}


def plan_config(**overrides):
    value = {"chain_id": 31337, "genesis_root": GENESIS, "wind_down_recipient": RECIPIENT,
             "oracle_signer_address": ORACLE_SIGNER, "sp1_gateway": None,
             "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000, "anchor_timeout_ms": 60000},
             "operator_policy": policy(), "deposit_permit_ttl_secs": 1800}
    value.update(overrides)
    return value


def launch_config(**overrides):
    value = plan_config(chain_id=84532, clock=dict(LAUNCH_CLOCK), operator_policy=launch_policy())
    value.update(overrides)
    return value


PUBLIC = {"FAKE_CHAIN": "84532", "FAKE_CLIENT": "Geth/v1.14"}


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
    def proof_status(self, status):
        """Fix the shared on-disk real proof status for this test."""
        patcher = unittest.mock.patch.object(release.clock, "proof_status", return_value=status)
        patcher.start()
        self.addCleanup(patcher.stop)

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
        self.proof_status(release.clock.PROVEN)
        anvil0 = ANVIL0
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

    def test_genesis_addresses_are_required_nonzero_and_independent(self):
        for key in ("wind_down_recipient", "oracle_signer_address"):
            config = plan_config()
            del config[key]
            with self.subTest(missing=key):
                self.config.write_text(json.dumps(config))
                self.assertEqual(self.run_cli(), 2)
            for bad in ("0x" + "00" * 20, "0x" + "5a" * 19, None, 5):
                with self.subTest(key=key, value=bad):
                    self.write_config(**{key: bad})
                    self.assertEqual(self.run_cli(), 2)
        self.write_config(oracle_signer_address=RECIPIENT.upper().replace("0X", "0x"))
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])

    def test_genesis_addresses_differ_from_every_operator_address(self):
        operators = [(role, name) for role, fields in release.OPERATOR_ADDRESSES.items() for name in fields]
        self.assertEqual(len(operators), 6)
        for key in ("wind_down_recipient", "oracle_signer_address"):
            for role, name in operators:
                config = policy()
                config[role][name] = plan_config()[key]
                with self.subTest(key=key, operator=role + "." + name):
                    self.write_config(operator_policy=config)
                    self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])

    def test_public_dev_genesis_addresses_are_refused_off_anvil(self):
        self.proof_status(release.clock.PROVEN)
        for key in ("wind_down_recipient", "oracle_signer_address"):
            with self.subTest(key=key):
                self.write_config(**launch_config(**{key: ANVIL0}))
                self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 2)
                self.assertEqual(self.sends(), [])
                self.assertFalse(self.output.exists())
                # A local or forked Anvil may use the published accounts.
                self.write_config(**{key: ANVIL0})
                self.assertEqual(self.run_cli(), 0)
                self.output.unlink()
                self.log.write_text("")

    def test_program_key_is_not_configurable(self):
        self.write_config(program_vkey="0x" + "ab" * 32)
        self.assertEqual(self.run_cli(), 2)

    def test_signer_flags_are_required(self):
        self.write_config()
        self.assertEqual(self.run_cli(signer=()), 2)
        self.assertEqual(self.sends(), [])

    def test_old_policy_keys_and_old_clock_shape_are_refused(self):
        old = policy()
        old["settlement"]["challenge_window_blocks"] = old["settlement"].pop("challenge_grace_blocks")
        for overrides in ({"operator_policy": old},
                          {"clock": {"max_window_ms": 30000, "clock_skew_ms": 10000}}):
            with self.subTest(overrides=list(overrides)):
                self.write_config(**overrides)
                self.assertEqual(self.run_cli(), 2)
        config = plan_config()
        del config["deposit_permit_ttl_secs"]
        self.config.write_text(json.dumps(config))
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])

    def test_values_the_constructors_would_revert_on_are_refused_before_any_send(self):
        cases = [("progress_batches", 0), ("progress_batches", 17), ("slash_payout_cap_usdc", 0),
                 ("slash_payout_cap_usdc", 2**128), ("liveness_timeout_blocks", 0),
                 ("challenge_grace_blocks", 0), ("governance", "0x" + "00" * 20),
                 ("sequencer", "0x" + "00" * 20), ("enclave_signer", "0x" + "00" * 20)]
        for field, bad in cases:
            config = policy()
            config["settlement"][field] = bad
            with self.subTest(field=field, value=bad):
                self.write_config(operator_policy=config)
                self.assertEqual(self.run_cli(), 2)
        for clock in ({"max_window_ms": 30000, "clock_skew_ms": 10000, "anchor_timeout_ms": 999},
                      {"max_window_ms": 30000, "clock_skew_ms": 399, "anchor_timeout_ms": 60000},
                      {"max_window_ms": 30000, "clock_skew_ms": 10000, "anchor_timeout_ms": 2**64}):
            with self.subTest(clock=clock):
                self.write_config(clock=clock)
                self.assertEqual(self.run_cli(), 2)
        for ttl in (0, -1, "1800", True, 2**64):
            with self.subTest(ttl=ttl):
                self.write_config(deposit_permit_ttl_secs=ttl)
                self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.sends(), [])
        # The upper edges are accepted.
        config = policy()
        config["settlement"].update(progress_batches=16, slash_payout_cap_usdc=2**128 - 1)
        self.write_config(operator_policy=config)
        self.assertEqual(self.run_cli(), 0)


class BaseFloors(CastFixture):
    """The floors, on a target that is deployable only once the real proof is PROVEN."""

    def setUp(self):
        super().setUp()
        self.proof_status(release.clock.PROVEN)

    def test_launch_defaults_pass_the_floors_on_a_public_chain(self):
        self.write_config(**launch_config())
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 0)
        self.assertEqual(len(self.sends()), 10)
        public = json.loads(self.output.read_text())
        self.assertEqual(public["clock"], LAUNCH_CLOCK)
        self.assertEqual(public["gateway"]["DEPOSIT_PERMIT_TTL_SECS"], "1800")
        record = json.loads(self.output.with_suffix(".deployment.json").read_text())
        self.assertFalse(record["owned_test_chain"])

    def test_each_floor_is_refused_on_a_public_chain(self):
        for section, key, minimum in deploy.BASE_FLOORS:
            config = launch_config()
            target = config["clock"] if section == "clock" else config["operator_policy"]["settlement"]
            target[key] = minimum - 1
            if (section, key) == ("clock", "max_window_ms"):
                continue  # below 400 is already a config error everywhere
            with self.subTest(floor=key):
                self.config.write_text(json.dumps(config))
                self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 2)
                # The same value at the floor passes.
                target[key] = minimum
                self.config.write_text(json.dumps(config))
                self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 0)

    def test_permit_ttl_is_bounded_by_an_eighth_of_liveness(self):
        liveness_secs = launch_policy()["settlement"]["liveness_timeout_blocks"] * 2
        self.write_config(**launch_config(deposit_permit_ttl_secs=liveness_secs // 8 + 1))
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 2)
        self.assertEqual(self.sends(), [])
        self.write_config(**launch_config(deposit_permit_ttl_secs=liveness_secs // 8))
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 0)

    def test_owned_anvil_at_base_sepolia_chain_id_skips_the_floors(self):
        # The candidate harness and the fork dry run use Anvil with chain id 84532.
        self.write_config(chain_id=84532)
        self.assertEqual(self.run_cli(env={"FAKE_CHAIN": "84532"}), 0)
        record = json.loads(self.output.with_suffix(".deployment.json").read_text())
        self.assertTrue(record["owned_test_chain"])

    def test_small_values_are_refused_on_a_public_chain(self):
        self.write_config(chain_id=84532)
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 2)
        self.assertEqual(self.sends(), [])

    def test_explicit_owned_test_chain_flag(self):
        # Once PROVEN, a non-Anvil chain the operator owns may waive the floors explicitly.
        self.write_config(chain_id=900)
        own = {"FAKE_CHAIN": "900", "FAKE_CLIENT": "Geth/v1.14"}
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=own), 2)
        self.assertEqual(self.run_cli(extra=["--allow-public-chain", "--owned-test-chain"], env=own), 0)
        # A public Base chain id is never an owned test chain unless the client is Anvil.
        self.write_config(chain_id=84532)
        before = len(self.sends())
        self.assertEqual(self.run_cli(extra=["--allow-public-chain", "--owned-test-chain"], env=PUBLIC), 2)
        self.write_config(chain_id=8453)
        self.assertEqual(self.run_cli(extra=["--allow-public-chain", "--owned-test-chain"],
                                      env={"FAKE_CHAIN": "8453", "FAKE_CLIENT": "Geth/v1.14"}), 2)
        self.assertEqual(len(self.sends()), before)


class ProofStatusGate(CastFixture):
    """A target that is not an owned test chain needs the real proof status PROVEN."""

    def pending(self):
        # A reviewed guest the committed proof files do not belong to: read from
        # disk, the status is PENDING_REPROOF.
        patcher = unittest.mock.patch.dict(release.clock.REVIEWED_GUEST,
                                           {"elf": "cd" * 32, "vkey": "0x" + "ab" * 32})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertEqual(release.clock.proof_status(), release.clock.PENDING_REPROOF)

    def test_status_is_the_shared_on_disk_reading(self):
        # No dict edit or flag changes it; the deploy tool asks the one shared function.
        self.assertIn(release.clock.proof_status(), {release.clock.PROVEN, release.clock.PENDING_REPROOF})
        self.write_config(**launch_config())
        for status, code in ((release.clock.PENDING_REPROOF, 2), (release.clock.PROVEN, 0)):
            with self.subTest(status=status), \
                    unittest.mock.patch.object(release.clock, "proof_status", return_value=status) as reading:
                self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), code)
                reading.assert_called_once_with()

    def test_non_owned_target_is_refused_until_proven(self):
        self.pending()
        self.write_config(**launch_config())
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"], env=PUBLIC), 2)
        self.write_config(chain_id=900)
        self.assertEqual(self.run_cli(extra=["--allow-public-chain"],
                                      env={"FAKE_CHAIN": "900", "FAKE_CLIENT": "Geth/v1.14"}), 2)
        self.assertEqual(self.sends(), [])
        self.assertFalse(self.output.exists())

    def test_declared_owned_chain_must_be_local_while_pending(self):
        self.pending()
        for chain_id in (900, 84532, 8453):
            with self.subTest(chain_id=chain_id):
                self.write_config(chain_id=chain_id)
                self.assertEqual(self.run_cli(extra=["--allow-public-chain", "--owned-test-chain"],
                                              env={"FAKE_CHAIN": str(chain_id), "FAKE_CLIENT": "Geth/v1.14"}), 2)
        self.assertEqual(self.sends(), [])
        self.assertFalse(self.output.exists())

    def test_owned_targets_deploy_while_pending(self):
        self.pending()
        geth = "Geth/v1.14"
        declared = ["--allow-public-chain", "--owned-test-chain"]
        cases = [({}, [], 31337),
                 # The candidate harness and the fork dry run use Anvil with chain id 84532.
                 ({"FAKE_CHAIN": "84532"}, [], 84532),
                 # A declared non-Anvil owned chain must use a local chain id.
                 ({"FAKE_CHAIN": "31337", "FAKE_CLIENT": geth}, declared, 31337),
                 ({"FAKE_CHAIN": "1337", "FAKE_CLIENT": geth}, declared, 1337)]
        for env, extra, chain_id in cases:
            with self.subTest(chain_id=chain_id):
                self.write_config(chain_id=chain_id)
                self.assertEqual(self.run_cli(extra=list(extra), env=env), 0)
                public = json.loads(self.output.read_text())
                self.assertEqual(public["program_vkey"], "0x" + "ab" * 32)
                self.assertTrue(json.loads(self.output.with_suffix(".deployment.json").read_text())["owned_test_chain"])
                self.output.unlink()


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

    @staticmethod
    def constructor_words(send, code):
        initcode = send[send.index("--create") + 1]
        args = initcode[len(code):]
        return [args[64 * i:64 * (i + 1)] for i in range(len(args) // 64)], len(args)

    def test_settlement_constructor_is_the_twelve_word_config_in_order(self):
        self.write_config()
        self.run_cli()
        words, size = self.constructor_words(self.sends()[5], self.artifacts["settlement"])
        self.assertEqual(size, 12 * 64)
        p = policy()["settlement"]
        self.assertEqual(words, [
            p["sequencer"][2:].rjust(64, "0"), p["enclave_signer"][2:].rjust(64, "0"),
            "0" * 24 + format(5, "040x"),  # clock verifier = 5th contract created
            GENESIS[2:],
            format(100, "064x"),  # livenessTimeoutBlocks
            format(50, "064x"),  # challengeGraceBlocks
            format(1000, "064x"),  # challengeBond
            format(600, "064x"),  # inclusionDeadlineSecs
            p["governance"][2:].rjust(64, "0"),
            format(10, "064x"),  # finalSettleGraceBlocks
            format(2, "064x"),  # progressBatches
            format(1_000_000_000, "064x"),  # slashPayoutCap
        ])

    def test_clock_constructor_is_four_words_with_the_anchor_timeout(self):
        self.write_config()
        self.run_cli()
        words, size = self.constructor_words(self.sends()[4], self.artifacts["clock_verifier"])
        self.assertEqual(size, 4 * 64)
        self.assertEqual(words, ["0" * 24 + format(4, "040x"),  # adapter = 4th contract created
                                 format(30000, "064x"), format(10000, "064x"), format(60000, "064x")])

    def test_output_is_a_valid_release_public_config(self):
        self.write_config()
        self.run_cli()
        public = json.loads(self.output.read_text())
        self.assertEqual(release.public_config(public)["program_vkey"], release.clock.REVIEWED_GUEST["vkey"])
        self.assertEqual(public["gateway"]["L1_SETTLEMENT"], public["addresses"]["settlement"])
        self.assertEqual(public["gateway"]["L1_ALLOW_MOCK_PROOF"], "0")
        self.assertEqual(public["gateway"]["DEPOSIT_PERMIT_TTL_SECS"], "1800")
        self.assertEqual(public["gateway"]["WIND_DOWN_RECIPIENT"], RECIPIENT)
        self.assertEqual(public["gateway"]["PROVER_EXPECTED_ELF_SHA256"], release.clock.REVIEWED_GUEST["elf"])
        self.assertEqual(set(public["gateway"]), release.GATEWAY_KEYS)
        self.assertEqual(public["genesis"], {"root": GENESIS, "wind_down_recipient": RECIPIENT,
                                             "oracle_signer": ORACLE_SIGNER})
        self.assertEqual(public["clock"]["anchor_timeout_ms"], 60000)
        self.assertEqual(set(public["operator_policy"]["settlement"]),
                         {"sequencer", "enclave_signer", "governance"} | set(release.SETTLEMENT_POLICY))
        record = json.loads(self.output.with_suffix(".deployment.json").read_text())
        self.assertEqual((record["genesis_root"], record["wind_down_recipient"], record["oracle_signer_address"]),
                         (GENESIS, RECIPIENT, ORACLE_SIGNER))
        self.assertEqual(len(record["transactions"]), 10)
        # Fake cast mines send n at block 100 + n; the settlement is the 6th send.
        self.assertEqual(record["deploy_block"], 101)
        self.assertEqual(record["settlement_block"], 106)
        self.assertTrue(record["owned_test_chain"])

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
        self.assertEqual(partial["deploy_block"], 101)


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
                           "liveness_timeout_blocks": 100, "challenge_grace_blocks": 50,
                           "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                           "final_settle_grace_blocks": 10, "progress_batches": 2,
                           "slash_payout_cap_usdc": 1_000_000_000},
            "vault": {"gateway_signer": accounts[2]},
            "clock_verifier": {"configurator": owner},
            "sp1_gateway": {"owner": owner},
        }
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        config = tmp / "deploy.json"
        config.write_text(json.dumps({"chain_id": 31337, "genesis_root": GENESIS, "wind_down_recipient": RECIPIENT,
                                      "oracle_signer_address": ORACLE_SIGNER, "sp1_gateway": None,
                                      "clock": {"max_window_ms": 30000, "clock_skew_ms": 10000,
                                                "anchor_timeout_ms": 3_600_000},
                                      "operator_policy": operator_policy, "deposit_permit_ttl_secs": 1800}))
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
        # The settlement holds the configured genesis root before its first batch.
        self.assertTrue(observed["scope"]["genesis_root_verified"])
        self.assertEqual(public["genesis"], {"root": GENESIS, "wind_down_recipient": RECIPIENT,
                                             "oracle_signer": ORACLE_SIGNER})
        getters = observed["contracts"]["settlement"]["getters"]
        self.assertEqual((getters["batchCount()"], getters["currentStateRoot()"]), (0, GENESIS))
        self.assertEqual(getters["ABI_VERSION()"], release.SETTLEMENT_ABI_VERSION)
        self.assertEqual(getters["progressBatches()"], 2)
        self.assertEqual(getters["slashPayoutCap()"], 1_000_000_000)
        self.assertEqual(observed["contracts"]["clock_verifier"]["getters"]["anchorTimeoutMs()"], 3_600_000)
        record = json.loads(output.with_suffix(".deployment.json").read_text())
        # The settlement's liveness clock starts at its creation block.
        progress = int(rpc(url, "eth_call", [{"to": public["addresses"]["settlement"],
                                              "data": release.deployment_reader.selector("lastProgressBlock()")},
                                             "latest"]), 16)
        self.assertEqual(progress, record["settlement_block"])
        self.assertLessEqual(record["deploy_block"], record["settlement_block"])
