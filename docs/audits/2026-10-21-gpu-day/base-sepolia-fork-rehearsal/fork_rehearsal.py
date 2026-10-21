"""GPU-day deploy rehearsal on a local Anvil fork of Base Sepolia (read-only public RPC).

Launch policy values, our own SP1 verifier and gateway, a genesis root printed by the
built gateway for synthetic non-default recipient and oracle addresses, then
release_manifest create (requires PROVEN) and observe-target. Anvil's public dev
accounts sign; no real key or transaction leaves this machine.

    python3 fork_rehearsal.py <repo> <gateway-bin> <output-dir>
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO, GATEWAY, OUT = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
sys.path.insert(0, str(REPO / "scripts/local-verification"))
import deploy_clock_stack as deploy  # noqa: E402
import release_manifest as release  # noqa: E402
from test_deploy_clock_stack import start_owned_anvil, rpc  # noqa: E402

RECIPIENT = "0x" + "c0" * 20   # synthetic cold recipient (not a public dev account)
ORACLE = "0x" + "0a" * 20      # synthetic per-deployment oracle signer address


def genesis():
    out = subprocess.run([str(GATEWAY), "--print-genesis-root", "--oracle-address", ORACLE],
                         env={"WIND_DOWN_RECIPIENT": RECIPIENT, "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, check=True).stdout
    values = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return values["GENESIS_ROOT"], values["WIND_DOWN_RECIPIENT"], values["ORACLE_SIGNER_ADDRESS"]


class Rehearsal(unittest.TestCase):
    def runTest(self):
        root, recipient, oracle = genesis()
        url = start_owned_anvil(self, ["--fork-url", "https://sepolia.base.org"])
        accounts = rpc(url, "eth_accounts", [])
        owner = accounts[0]
        config = {"chain_id": 84532, "genesis_root": root, "wind_down_recipient": recipient,
                  "oracle_signer_address": oracle, "sp1_gateway": None, "deposit_permit_ttl_secs": 1800,
                  "clock": {"max_window_ms": 30000, "clock_skew_ms": 30000, "anchor_timeout_ms": 3600000},
                  "operator_policy": {
                      "settlement": {"sequencer": owner, "enclave_signer": accounts[1], "governance": accounts[3],
                                     "liveness_timeout_blocks": 43200, "challenge_grace_blocks": 3600,
                                     "challenge_bond_wei": 10**16, "inclusion_deadline_seconds": 3600,
                                     "final_settle_grace_blocks": 300, "progress_batches": 2,
                                     "slash_payout_cap_usdc": 1_000_000_000},
                      "vault": {"gateway_signer": accounts[2]},
                      "clock_verifier": {"configurator": owner},
                      "sp1_gateway": {"owner": owner}}}
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "deploy.json").write_text(json.dumps(config, indent=2))
        public_path = OUT / "public-config.json"
        code = deploy.main(["--config", str(OUT / "deploy.json"), "--rpc", url, "--output", str(public_path),
                            "--gateway-bin", str(GATEWAY), "--", "--unlocked", "--from", owner])
        self.assertEqual(code, 0)
        rpc(url, "anvil_mine", ["0x80"])
        result = {"proof_status": release.clock.proof_status(release.ROOT), "deploy_exit": code,
                  "genesis": {"root": root, "wind_down_recipient": recipient, "oracle_signer": oracle},
                  "deployment": json.loads(public_path.with_suffix(".deployment.json").read_text())}
        manifest_path = OUT / "manifest.json"
        created = subprocess.run([sys.executable, str(REPO / "scripts/local-verification/release_manifest.py"),
                                  "create", "--config", str(public_path), "--output", str(manifest_path),
                                  "--gateway-bin", str(GATEWAY)], capture_output=True, text=True)
        result["create_exit"] = created.returncode
        result["create_stderr_tail"] = created.stderr[-400:]
        observed_path = OUT / "observed.json"
        observe = subprocess.run([sys.executable, str(REPO / "scripts/local-verification/release_manifest.py"),
                                  "observe-target", "--manifest", str(manifest_path), "--config", str(public_path),
                                  "--rpc", url, "--output", str(observed_path), "--require-operator-policy",
                                  "--gateway-bin", str(GATEWAY)], capture_output=True, text=True)
        result["observe_exit"] = observe.returncode
        if observed_path.exists():
            observed = json.loads(observed_path.read_text())
            result["observed_status"] = observed.get("status")
            result["observed_blocker"] = observed.get("blocker")
        (OUT / "rehearsal.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps({k: result[k] for k in ("proof_status", "deploy_exit", "create_exit", "observe_exit",
                                                 "observed_status", "observed_blocker") if k in result}))


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=0).run(Rehearsal())
