#!/usr/bin/env python3
"""Deploy the clock-bound settlement stack from the release artifacts, in order.

Deploys exactly the compiled artifacts `release_manifest.py` verifies (so the
on-chain code can be observed as VERIFIED), in the order the owned-Anvil
manifest test proves:

  [sp1_verifier, sp1_gateway, addRoute] → sp1_adapter(gateway, reviewed vkey)
  → clock_verifier(adapter, max_window_ms, clock_skew_ms, anchor_timeout_ms)
  → settlement(Config: 12 words from the policy and genesis_root) → token
  (MockUSDC) → vault(settlement, token, gateway_signer) → settlement.setVault(vault)
  → clock_verifier.bindSettlement(settlement)

The first three steps are skipped when `sp1_gateway` names an existing SP1
verifier gateway (Base Sepolia: Succinct's 0x397A5f7f…), whose route verifier
must then be given as `sp1_verifier`. The program key is never configurable:
it is the reviewed clock guest key the release manifest pins.

Every transaction goes through `cast send --json` with the signer flags given
after `--` (`--unlocked --from ADDR` on Anvil; `--account NAME` or `--ledger`
elsewhere). The tool never reads or stores keys. Any chain whose client is not
Anvil (including a public chain) needs --allow-public-chain.

Before any transaction the config is checked against the constructor rules
(a settlement or clock that would revert is refused up front) and, unless the
target is an owned test chain, against the Base launch floors in BASE_FLOORS.
An owned test chain is an Anvil client (a local chain or a local fork) or a
chain the operator marks with --owned-test-chain; a public Base chain id is
never accepted as one unless its client is Anvil. A target that is not an owned
test chain is also refused unless the real proof status
(`verify_clock_proof.proof_status()`, read from the committed proof files and
shared with `release_manifest.py`) is PROVEN.

    deploy_clock_stack.py --config deploy.json --rpc http://127.0.0.1:8545 \
        --output public-config.json -- --unlocked --from 0x…

The config holds exactly: `chain_id`, `genesis_root`, `sp1_gateway` (null, or
an existing gateway plus `sp1_verifier`), `clock` {max_window_ms,
clock_skew_ms, anchor_timeout_ms}, `deposit_permit_ttl_secs` (bound into the
public gateway config as DEPOSIT_PERMIT_TTL_SECS) and `operator_policy`
(`release_manifest.operator_policy`: settlement addresses plus
SETTLEMENT_POLICY, the vault gateway signer, the clock configurator and the
SP1 gateway owner). The Base Sepolia launch values are liveness 43,200 blocks,
challenge grace 3,600 blocks, a 0.01 ETH challenge bond, a 3,600 s inclusion
deadline, final-settle grace 300 blocks, 2 progress batches, a 1,000 USDC
(1,000,000,000 base units) payout cap, clock 30,000 / 30,000 / 3,600,000 ms and
a 1,800 s permit lifetime.

Writes the release public config to --output (input for `release_manifest.py
create` / `observe-target`) and the transaction record next to it as
`<output>.deployment.json`, including `deploy_block` (the block of the first
transaction) and `settlement_block` (the block the settlement was created in,
where its liveness clock starts). If a transaction fails, nothing is written to
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

# The ten default Anvil/Hardhat accounts (the published `test ... junk` mnemonic).
PUBLIC_DEV_ADDRESSES = frozenset({
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
    "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
    "0x976ea74026e726554db657fa54763abd0c3a0aa9", "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
    "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
})
TOKEN_ARTIFACT = "out/MockUSDC.sol/MockUSDC.json"
CONFIG_KEYS = {"chain_id", "genesis_root", "sp1_gateway", "clock", "operator_policy", "deposit_permit_ttl_secs"}
# Public Base networks: never treated as an owned test chain unless the client is Anvil.
PUBLIC_BASE_CHAINS = release.PUBLIC_BASE_CHAINS
# Base launch floors (2 s blocks). Each entry: (policy section, key, minimum).
BASE_FLOORS = (
    ("settlement", "liveness_timeout_blocks", 7_200),
    ("settlement", "final_settle_grace_blocks", 150),
    ("settlement", "challenge_grace_blocks", 1_200),
    ("settlement", "progress_batches", 2),
    ("settlement", "inclusion_deadline_seconds", 3_600),
    ("settlement", "challenge_bond_wei", 1),
    ("settlement", "slash_payout_cap_usdc", 1),
    ("clock", "anchor_timeout_ms", 3_600_000),
    ("clock", "clock_skew_ms", 20_000),
    ("clock", "max_window_ms", 400),
)
BASE_BLOCK_SECONDS = 2
MAX_PROGRESS_BATCHES = 16
MAX_SLASH_PAYOUT_CAP = 2**128 - 1


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
    if (not isinstance(clock, dict) or set(clock) != set(release.CLOCK_POLICY)
            or not all(type(v) is int and 400 <= v < 2**64 for v in clock.values())):
        raise DeployError("clock needs integer max_window_ms, clock_skew_ms and anchor_timeout_ms (>= 400)")
    ttl = raw["deposit_permit_ttl_secs"]
    if type(ttl) is not int or not 0 < ttl < 2**64:
        raise DeployError("deposit_permit_ttl_secs must be a positive integer number of seconds")
    reuse = None
    if raw["sp1_gateway"]:
        reuse = {"sp1_gateway": release.normalized_hex(raw["sp1_gateway"], 20, "sp1_gateway"),
                 "sp1_verifier": release.normalized_hex(raw["sp1_verifier"], 20, "sp1_verifier")}
    config = {"chain_id": raw["chain_id"], "genesis_root": genesis, "clock": dict(clock),
              "operator_policy": policy, "deposit_permit_ttl_secs": ttl, "reuse": reuse}
    check_constructor_rules(config)
    return config


def check_constructor_rules(config):
    """Refuse values the settlement or clock constructor would revert on.

    Checked before the first transaction, so a bad policy cannot leave a
    half-deployed stack behind.
    """
    s = config["operator_policy"]["settlement"]
    for name in ("sequencer", "enclave_signer", "governance"):
        if int(s[name], 16) == 0:
            raise DeployError(f"settlement {name} must be a nonzero address")
    if s["liveness_timeout_blocks"] == 0 or s["challenge_grace_blocks"] == 0:
        raise DeployError("liveness_timeout_blocks and challenge_grace_blocks must be nonzero")
    if not 1 <= s["progress_batches"] <= MAX_PROGRESS_BATCHES:
        raise DeployError(f"progress_batches must be in 1..{MAX_PROGRESS_BATCHES}")
    if not 0 < s["slash_payout_cap_usdc"] <= MAX_SLASH_PAYOUT_CAP:
        raise DeployError("slash_payout_cap_usdc must be nonzero and fit uint128")
    if config["clock"]["anchor_timeout_ms"] < release.MIN_ANCHOR_TIMEOUT_MS:
        raise DeployError(f"anchor_timeout_ms must be at least {release.MIN_ANCHOR_TIMEOUT_MS}")


def check_base_floors(config):
    """Refuse launch parameters below the Base floors (not for owned test chains)."""
    sections = {"settlement": config["operator_policy"]["settlement"], "clock": config["clock"]}
    low = [f"{section}.{key} < {minimum}" for section, key, minimum in BASE_FLOORS
           if sections[section][key] < minimum]
    liveness_secs = sections["settlement"]["liveness_timeout_blocks"] * BASE_BLOCK_SECONDS
    if config["deposit_permit_ttl_secs"] * 8 > liveness_secs:
        low.append("deposit_permit_ttl_secs > liveness seconds / 8")
    if low:
        raise DeployError("below the Base launch floors: " + ", ".join(low)
                          + " (an owned test chain may use --owned-test-chain)")


def _run_cast(argv, timeout=300):
    env = {**os.environ, "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}
    result = subprocess.run(["cast", *argv], capture_output=True, text=True, timeout=timeout, env=env)
    if result.returncode != 0:
        raise DeployError(f"cast {argv[0]} failed (exit {result.returncode})")
    return result.stdout.strip()


def cast(args, rpc):
    return _run_cast([*args, "--rpc-url", rpc])


def check_chain(config, rpc, allow_public, owned_test_chain=False):
    """Return (client, owned): the RPC client string and whether floors are waived."""
    chain = cast(["chain-id"], rpc)
    if chain != str(config["chain_id"]):
        raise DeployError(f"RPC chain {chain} does not match config chain_id {config['chain_id']}")
    client = json.loads(cast(["rpc", "web3_clientVersion"], rpc))
    anvil = str(client).lower().startswith("anvil")
    if not anvil and not allow_public:
        raise DeployError(f"RPC client {client!r} is not Anvil; refusing without --allow-public-chain")
    if owned_test_chain and not anvil and config["chain_id"] in PUBLIC_BASE_CHAINS:
        raise DeployError("a public Base chain is not an owned test chain unless its client is Anvil")
    # A vault pins its deposit-authorization signer for life; off Anvil it must be a
    # secret key, never one of the published default accounts.
    if not anvil and config["operator_policy"]["vault"]["gateway_signer"].lower() in PUBLIC_DEV_ADDRESSES:
        raise DeployError("vault gateway_signer is a public default Anvil account; refusing off Anvil")
    owned = release.target_owned(config["chain_id"], anvil, owned_test_chain is True)
    if not owned:
        status = release.clock.proof_status()
        if status != release.clock.PROVEN:
            raise DeployError(f"real proof status is {status}: until the reviewed guest has a committed real proof, "
                              "only an owned test chain (Anvil, or --owned-test-chain) may be deployed to")
        check_base_floors(config)
    return client, owned


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

    def block_of(self, step):
        """The block number (int) a recorded step was mined in, or None."""
        for transaction in self.transactions:
            if transaction["step"] == step:
                return int(str(transaction["block"]), 0)
        return None

    def create(self, role, *args):
        receipt = self._send(role, ["--create", bytecode(role) + "".join(word(a) for a in args)])
        self.addresses[role] = receipt["contractAddress"].lower()

    def call(self, step, to, signature, *args):
        self._send(step, [to, signature, *args])


def deploy_stack(config, deployer):
    p, a = config["operator_policy"], deployer.addresses
    if config["reuse"]:
        a.update(config["reuse"])
    else:
        deployer.create("sp1_verifier")
        deployer.create("sp1_gateway", p["sp1_gateway"]["owner"])
        deployer.call("sp1_gateway.addRoute", a["sp1_gateway"], "addRoute(address)", a["sp1_verifier"])
    deployer.create("sp1_adapter", a["sp1_gateway"], release.clock.REVIEWED_GUEST["vkey"])
    c = config["clock"]
    deployer.create("clock_verifier", a["sp1_adapter"], c["max_window_ms"], c["clock_skew_ms"], c["anchor_timeout_ms"])
    deployer.create("settlement", *settlement_words(config, a["clock_verifier"]))
    deployer.create("token")
    deployer.create("vault", a["settlement"], a["token"], p["vault"]["gateway_signer"])
    deployer.call("settlement.setVault", a["settlement"], "setVault(address)", a["vault"])
    deployer.call("clock_verifier.bindSettlement", a["clock_verifier"], "bindSettlement(address)", a["settlement"])


def settlement_words(config, clock_verifier):
    """`DarkPerpSettlement.Config` as its 12 ABI words (a static struct encodes inline)."""
    s = config["operator_policy"]["settlement"]
    return (s["sequencer"], s["enclave_signer"], clock_verifier, config["genesis_root"],
            s["liveness_timeout_blocks"], s["challenge_grace_blocks"], s["challenge_bond_wei"],
            s["inclusion_deadline_seconds"], s["governance"], s["final_settle_grace_blocks"],
            s["progress_batches"], s["slash_payout_cap_usdc"])


def public_config(config, addresses):
    gateway = {env: addresses[role] for env, role in release.ENV_ADDRESSES.items()}
    gateway.update(L1_CHAIN_ID=str(config["chain_id"]), L1_ALLOW_MOCK_PROOF="0",
                   DEPOSIT_PERMIT_TTL_SECS=str(config["deposit_permit_ttl_secs"]))
    reviewed = release.clock.REVIEWED_GUEST
    return release.public_config({
        "chain_id": config["chain_id"], "addresses": addresses, "program_vkey": reviewed["vkey"],
        "clock": config["clock"], "gateway": gateway,
        "prover": {"program_vkey": reviewed["vkey"], "guest_elf_sha256": reviewed["elf"]},
        "operator_policy": config["operator_policy"],
    })


def first_block(deployer):
    """Block of the first transaction this run sent (the stack's deploy block), or None."""
    return int(str(deployer.transactions[0]["block"]), 0) if deployer.transactions else None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    signer = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    parser = argparse.ArgumentParser(description="Deploy the clock-bound settlement stack (see module docstring).")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-public-chain", action="store_true")
    parser.add_argument("--owned-test-chain", action="store_true",
                        help="the target is a disposable chain you own; skips the Base launch floors")
    args = parser.parse_args(own)
    try:
        if not signer:
            raise DeployError("signer flags are required after `--` (e.g. --unlocked --from ADDR, --account NAME)")
        config = load_config(release.read_json(args.config))
        # The release config must accept this policy before anything is sent.
        public_config(config, {role: "0x" + format(i, "040x")
                               for i, role in enumerate(sorted(release.ADDRESS_ROLES), 1)})
        client, owned = check_chain(config, args.rpc, args.allow_public_chain, args.owned_test_chain)
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
            "chain_id": config["chain_id"], "rpc_client": client, "owned_test_chain": owned,
            "addresses": deployer.addresses, "transactions": deployer.transactions,
            "deploy_block": first_block(deployer), "failed": failed, "error": str(error),
        }, indent=2) + "\n")
        print(f"[deploy] FAILED: {error}; partial record written", file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(public, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".deployment.json").write_text(json.dumps({
        "chain_id": config["chain_id"], "rpc_client": client, "owned_test_chain": owned,
        "genesis_root": config["genesis_root"], "deploy_block": first_block(deployer),
        "settlement_block": deployer.block_of("settlement"), "transactions": deployer.transactions,
    }, indent=2) + "\n")
    print(json.dumps({"status": "DEPLOYED", "addresses": public["addresses"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
