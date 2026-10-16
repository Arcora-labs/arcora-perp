#!/usr/bin/env python3
"""Deploy the clock-bound settlement stack from the release artifacts, in order.

Deploys exactly the compiled artifacts `release_manifest.py` verifies (so the
on-chain code can be observed as VERIFIED), in the order the owned-Anvil
manifest test proves:

  [sp1_verifier, sp1_gateway, addRoute] → sp1_adapter(gateway, reviewed vkey)
  → clock_verifier(adapter, max_window_ms, clock_skew_ms) → settlement(policy,
  genesis_root) → token (MockUSDC) → vault(settlement, token, gateway_signer)
  → settlement.setVault(vault) → clock_verifier.bindSettlement(settlement)

The first three steps are skipped when `sp1_gateway` names an existing SP1
verifier gateway (Base Sepolia: Succinct's 0x397A5f7f…), whose route verifier
must then be given as `sp1_verifier`. The program key is never configurable:
it is the reviewed clock guest key the release manifest pins.

Every transaction goes through `cast send --json` with the signer flags given
after `--` (`--unlocked --from ADDR` on Anvil; `--account NAME` or `--ledger`
elsewhere). The tool never reads or stores keys. Any chain whose client is not
Anvil (including a public chain) needs --allow-public-chain.

    deploy_clock_stack.py --config deploy.json --rpc http://127.0.0.1:8545 \
        --output public-config.json -- --unlocked --from 0x…

Writes the release public config to --output (input for `release_manifest.py
create` / `observe-target`) and the transaction record next to it as
`<output>.deployment.json`. If a transaction fails, nothing is written to
--output; `<output>.partial.json` records what was deployed before it.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import release_manifest as release

ROLES_IN_ORDER = ["sp1_verifier", "sp1_gateway", "sp1_adapter", "clock_verifier", "settlement", "token", "vault"]
TOKEN_ARTIFACT = "out/MockUSDC.sol/MockUSDC.json"
CONFIG_KEYS = {"chain_id", "genesis_root", "sp1_gateway", "clock", "operator_policy"}


class DeployError(Exception):
    pass


def bytecode(role):
    relative = TOKEN_ARTIFACT if role == "token" else release.CONTRACTS[role][0]
    code = release.read_json(release.ROOT / "contracts" / relative)["bytecode"]["object"]
    return code if code.startswith("0x") else "0x" + code


def word(value):
    if type(value) is int:
        return format(value, "064x")
    return value.lower().removeprefix("0x").rjust(64, "0")


def load_config(raw):
    keys = set(raw) if isinstance(raw, dict) else set()
    expected = CONFIG_KEYS | ({"sp1_verifier"} if isinstance(raw, dict) and raw.get("sp1_gateway") else set())
    if keys != expected:
        raise DeployError(f"config keys must be exactly {sorted(expected)}")
    if type(raw["chain_id"]) is not int or raw["chain_id"] <= 0:
        raise DeployError("chain_id must be a positive integer")
    genesis = release.normalized_hex(raw["genesis_root"], 32, "genesis_root")
    if int(genesis, 16) == 0:
        raise DeployError("genesis_root must be the gateway's production root (gateway --print-genesis-root)")
    policy = release.operator_policy(raw["operator_policy"])
    clock = raw["clock"]
    if set(clock) != {"max_window_ms", "clock_skew_ms"} or not all(type(v) is int and v >= 400 for v in clock.values()):
        raise DeployError("clock needs integer max_window_ms and clock_skew_ms (>= 400)")
    reuse = None
    if raw["sp1_gateway"]:
        reuse = {"sp1_gateway": release.normalized_hex(raw["sp1_gateway"], 20, "sp1_gateway"),
                 "sp1_verifier": release.normalized_hex(raw["sp1_verifier"], 20, "sp1_verifier")}
    return {"chain_id": raw["chain_id"], "genesis_root": genesis, "clock": dict(clock),
            "operator_policy": policy, "reuse": reuse}


def _run_cast(argv, timeout=300):
    env = {**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    result = subprocess.run(["cast", *argv], capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode != 0:
        raise DeployError(f"cast {argv[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def cast(args, rpc):
    return _run_cast([*args, "--rpc-url", rpc])


def check_chain(config, rpc, allow_public):
    chain = cast(["chain-id"], rpc)
    if chain != str(config["chain_id"]):
        raise DeployError(f"RPC chain {chain} does not match config chain_id {config['chain_id']}")
    client = json.loads(cast(["rpc", "web3_clientVersion"], rpc))
    if not str(client).lower().startswith("anvil") and not allow_public:
        raise DeployError(f"RPC client {client!r} is not Anvil; refusing without --allow-public-chain")
    return client


class Deployer:
    def __init__(self, rpc, signer):
        self.rpc, self.signer = rpc, list(signer)
        self.addresses, self.transactions = {}, []

    def _send(self, step, args):
        # Options first: after `--create <CODE>` cast reads every remaining word
        # as a constructor argument.
        receipt = json.loads(_run_cast(["send", "--rpc-url", self.rpc, "--json", *self.signer, *args], timeout=600))
        if receipt.get("status") != "0x1":
            raise DeployError(f"{step} transaction reverted")
        self.transactions.append({"step": step, "hash": receipt["transactionHash"], "block": receipt["blockNumber"]})
        return receipt

    def create(self, role, *args):
        receipt = self._send(role, ["--create", bytecode(role) + "".join(word(a) for a in args)])
        self.addresses[role] = receipt["contractAddress"].lower()

    def call(self, step, to, signature, *args):
        self._send(step, [to, signature, *args])


def deploy_stack(config, deployer):
    p, a = config["operator_policy"], deployer.addresses
    s = p["settlement"]
    if config["reuse"]:
        a.update(config["reuse"])
    else:
        deployer.create("sp1_verifier")
        deployer.create("sp1_gateway", p["sp1_gateway"]["owner"])
        deployer.call("sp1_gateway.addRoute", a["sp1_gateway"], "addRoute(address)", a["sp1_verifier"])
    deployer.create("sp1_adapter", a["sp1_gateway"], release.clock.EXPECTED_VKEY)
    deployer.create("clock_verifier", a["sp1_adapter"], config["clock"]["max_window_ms"], config["clock"]["clock_skew_ms"])
    deployer.create("settlement", s["sequencer"], s["enclave_signer"], a["clock_verifier"], config["genesis_root"],
                    s["liveness_timeout_blocks"], s["challenge_window_blocks"], s["challenge_bond_wei"],
                    s["inclusion_deadline_seconds"], s["governance"], s["final_settle_grace_blocks"])
    deployer.create("token")
    deployer.create("vault", a["settlement"], a["token"], p["vault"]["gateway_signer"])
    deployer.call("settlement.setVault", a["settlement"], "setVault(address)", a["vault"])
    deployer.call("clock_verifier.bindSettlement", a["clock_verifier"], "bindSettlement(address)", a["settlement"])


def public_config(config, addresses):
    gateway = {env: addresses[role] for env, role in release.ENV_ADDRESSES.items()}
    gateway.update(L1_CHAIN_ID=str(config["chain_id"]), L1_ALLOW_MOCK_PROOF="0")
    return release.public_config({
        "chain_id": config["chain_id"], "addresses": addresses, "program_vkey": release.clock.EXPECTED_VKEY,
        "clock": config["clock"], "gateway": gateway,
        "prover": {"program_vkey": release.clock.EXPECTED_VKEY, "guest_elf_sha256": release.clock.EXPECTED_ELF},
        "operator_policy": config["operator_policy"],
    })


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    signer = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    parser = argparse.ArgumentParser(description="Deploy the clock-bound settlement stack (see module docstring).")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-public-chain", action="store_true")
    args = parser.parse_args(own)
    try:
        if not signer:
            raise DeployError("signer flags are required after `--` (e.g. --unlocked --from ADDR, --account NAME)")
        config = load_config(release.read_json(args.config))
        client = check_chain(config, args.rpc, args.allow_public_chain)
    except (DeployError, ValueError, OSError) as error:
        print(f"[deploy] REFUSED: {error}", file=sys.stderr)
        return 2
    deployer = Deployer(args.rpc, signer)
    try:
        deploy_stack(config, deployer)
        public = public_config(config, deployer.addresses)
    except (DeployError, ValueError, KeyError, json.JSONDecodeError) as error:
        failed = next((r for r in ROLES_IN_ORDER if r not in deployer.addresses), None)
        args.output.with_suffix(".partial.json").write_text(json.dumps({
            "chain_id": config["chain_id"], "rpc_client": client, "addresses": deployer.addresses,
            "transactions": deployer.transactions, "failed": failed, "error": str(error),
        }, indent=2) + "\n")
        print(f"[deploy] FAILED: {error}; partial record written", file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(public, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".deployment.json").write_text(json.dumps({
        "chain_id": config["chain_id"], "rpc_client": client, "genesis_root": config["genesis_root"],
        "transactions": deployer.transactions,
    }, indent=2) + "\n")
    print(json.dumps({"status": "DEPLOYED", "addresses": public["addresses"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
