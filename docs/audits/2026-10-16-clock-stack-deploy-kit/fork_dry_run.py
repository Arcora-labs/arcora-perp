"""One-off: deploy the clock stack on a local Anvil fork of Base Sepolia, reusing
the real SP1 verifier gateway, then observe it with release_manifest."""
import json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import deploy_clock_stack as deploy
import release_manifest as release
from test_deploy_clock_stack import start_owned_anvil, rpc, GENESIS

OUT = Path(sys.argv[2])

class Fork(unittest.TestCase):
    def runTest(self):
        url = start_owned_anvil(self, ["--fork-url", "https://sepolia.base.org"])
        accounts = rpc(url, "eth_accounts", [])
        owner = accounts[0]
        config = {"chain_id": 84532, "genesis_root": GENESIS,
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
              "blocker", result.get("observed", {}).get("blocker"))

unittest.TextTestRunner(verbosity=0).run(Fork())
