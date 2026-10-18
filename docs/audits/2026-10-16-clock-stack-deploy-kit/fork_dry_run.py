"""One-off: deploy the clock stack on a local Anvil fork of Base Sepolia, with our
own SP1 verifier and gateway, then observe it with release_manifest.

    python3 fork_dry_run.py <repo>/scripts/local-verification <output.json>

Note (18 October 2026): the deploy config gains `wind_down_recipient` and
`oracle_signer_address`; the release public config gains a `genesis` block
{root, wind_down_recipient, oracle_signer} and the gateway keys
WIND_DOWN_RECIPIENT and PROVER_EXPECTED_ELF_SHA256; observe-target also compares
the settlement's currentStateRoot() with the configured genesis root while
batchCount() is 0. The genesis root, recipient and oracle signer below are
synthetic and were not printed together by `--print-genesis-root`, so this run
checks only that the deployed root is the configured one. The fork is an Anvil
client, so it stays an owned test chain while the real proof status is not
PROVEN. The JSON records in this directory were produced with earlier versions
of the contracts and of this script; they are historical and were not re-run.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path


def fork_config(accounts, genesis, recipient, oracle_signer):
    """The dry-run deploy config: Anvil's public accounts and synthetic genesis values."""
    owner = accounts[0]
    return {"chain_id": 84532, "genesis_root": genesis,
            "wind_down_recipient": recipient, "oracle_signer_address": oracle_signer,
            "sp1_gateway": None, "deposit_permit_ttl_secs": 1800,
            "clock": {"max_window_ms": 30000, "clock_skew_ms": 30000, "anchor_timeout_ms": 3600000},
            "operator_policy": {
                "settlement": {"sequencer": owner, "enclave_signer": accounts[1], "governance": owner,
                               "liveness_timeout_blocks": 100, "challenge_grace_blocks": 50,
                               "challenge_bond_wei": 1000, "inclusion_deadline_seconds": 600,
                               "final_settle_grace_blocks": 10, "progress_batches": 2,
                               "slash_payout_cap_usdc": 1000000000},
                "vault": {"gateway_signer": accounts[2]},
                "clock_verifier": {"configurator": owner},
                "sp1_gateway": {"owner": owner}}}


class Fork(unittest.TestCase):
    def runTest(self):
        url = start_owned_anvil(self, ["--fork-url", "https://sepolia.base.org"])
        accounts = rpc(url, "eth_accounts", [])
        owner = accounts[0]
        config = fork_config(accounts, GENESIS, RECIPIENT, ORACLE_SIGNER)
        tmp = Path(tempfile.mkdtemp())
        (tmp / "deploy.json").write_text(json.dumps(config))
        out = tmp / "public-config.json"
        code = deploy.main(["--config", str(tmp / "deploy.json"), "--rpc", url, "--output", str(out),
                            "--", "--unlocked", "--from", owner])
        result = {"deploy_exit": code}
        if code == 0:
            rpc(url, "anvil_mine", ["0x80"])
            public = json.loads(out.read_text())
            manifest = release.build_manifest(release.ROOT, public)
            observed = release.observe_target(release.ROOT, manifest, public, release.TargetRPC(url),
                                              require_operator_policy=True)
            result.update(public_config=public, observed=observed,
                          deployment=json.loads(out.with_suffix(".deployment.json").read_text()))
        else:
            result["partial"] = json.loads(out.with_suffix(".partial.json").read_text())
        OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print("deploy_exit", code, "status", result.get("observed", {}).get("status"),
              "genesis_root_verified", result.get("observed", {}).get("scope", {}).get("genesis_root_verified"),
              "blocker", result.get("observed", {}).get("blocker"))


if __name__ == "__main__":
    sys.path.insert(0, sys.argv[1])
    import deploy_clock_stack as deploy
    import release_manifest as release
    from test_deploy_clock_stack import start_owned_anvil, rpc, GENESIS, RECIPIENT, ORACLE_SIGNER

    OUT = Path(sys.argv[2])
    unittest.TextTestRunner(verbosity=0).run(Fork())
