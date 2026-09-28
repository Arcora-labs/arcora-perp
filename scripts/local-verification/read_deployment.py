#!/usr/bin/env python3
"""Read public deployment bindings at one finalized block; never submit transactions."""
import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "contracts/deployments/base-sepolia.json"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=pathlib.Path,
                    default=ROOT / "docs/audits/2026-09-28-continuation/deployment-observation.json")
args = parser.parse_args()
OUT = args.output
config = json.loads(CONFIG.read_text())
records = []


def rpc(method, params):
    assert method in {"eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"}
    req = urllib.request.Request(config["rpc"], data=json.dumps({
        "jsonrpc": "2.0", "id": len(records) + 1, "method": method, "params": params,
    }).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        value = json.load(response)
    records.append({"method": method, "params": params, "response": value})
    if "error" in value:
        raise RuntimeError(str(value["error"]))
    return value["result"]


def selector(signature):
    return subprocess.check_output(["cast", "sig", signature], text=True, timeout=10).strip()


result = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "scope": "Public read-only RPC. No private key, live mutation, account query or load test.",
    "config_sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
    "rpc_url": config["rpc"], "status": "BLOCKED", "contracts": {}, "rpc_records": records,
}
try:
    chain = rpc("eth_chainId", [])
    assert int(chain, 16) == config["chainId"], "wrong chain"
    block = rpc("eth_getBlockByNumber", ["finalized", False])
    assert block and block["hash"] and block["number"]
    result.update(chain_id=int(chain, 16), block_number=int(block["number"], 16), block_hash=block["hash"])
    pin = {"blockHash": block["hash"], "requireCanonical": True}
    queries = {
        "DarkPerpSettlement": ["sequencer()", "enclaveSigner()", "verifier()", "vault()", "governance()", "currentStateRoot()", "batchCount()", "closeOnly()", "windDownSettled()"],
        "CollateralVault": ["settlement()", "gatewaySigner()", "token()", "depositCount()"],
        "SP1ZkVerifier": ["programVKey()", "gateway()"],
        "MockUSDC": [],
    }
    for name, signatures in queries.items():
        address = config["contracts"][name]["address"]
        item = result["contracts"][name] = {"address": address, "calls": {}}
        code = rpc("eth_getCode", [address, pin])
        raw = bytes.fromhex(code[2:])
        item.update(runtime_bytes=len(raw), runtime_sha256=hashlib.sha256(raw).hexdigest())
        item["runtime_keccak256"] = subprocess.check_output(["cast", "keccak", code], text=True, timeout=10).strip()
        assert raw, f"no code at {name}"
        for signature in signatures:
            try:
                item["calls"][signature] = {"result": rpc("eth_call", [{"to": address, "data": selector(signature)}, pin])}
            except Exception as exc:
                item["calls"][signature] = {"error": str(exc)}
    after = rpc("eth_getBlockByNumber", [block["number"], False])
    assert after["hash"] == block["hash"], "finalized block changed during observation"
    key = result["contracts"]["SP1ZkVerifier"]["calls"]["programVKey()"].get("result")
    local_log = ROOT / "docs/audits/2026-09-27-local/checks/sp1-vkey.log"
    local_key = next(line.strip() for line in local_log.read_text().splitlines() if line.startswith("0x"))
    def address_result(name, signature):
        value = result["contracts"][name]["calls"][signature].get("result")
        if not isinstance(value, str) or len(value) != 66:
            return None
        return "0x" + value[-40:].lower()

    expected = [
        ("DarkPerpSettlement", "vault()", config["contracts"]["CollateralVault"]["address"]),
        ("DarkPerpSettlement", "verifier()", config["contracts"]["SP1ZkVerifier"]["address"]),
        ("DarkPerpSettlement", "sequencer()", config["params"]["sequencer"]),
        ("DarkPerpSettlement", "enclaveSigner()", config["params"]["enclaveSigner"]),
        ("CollateralVault", "settlement()", config["contracts"]["DarkPerpSettlement"]["address"]),
        ("CollateralVault", "token()", config["contracts"]["MockUSDC"]["address"]),
        ("SP1ZkVerifier", "gateway()", config["contracts"]["SP1ZkVerifier"]["sp1VerifierGateway"]),
    ]
    bindings = [{"contract": name, "getter": signature, "expected": value.lower(),
                 "observed": address_result(name, signature),
                 "matches": address_result(name, signature) == value.lower()}
                for name, signature, value in expected]
    call_errors = [{"contract": name, "getter": signature, "error": call["error"]}
                   for name, item in result["contracts"].items()
                   for signature, call in item["calls"].items() if "error" in call]
    result.update(status="PARTIAL" if call_errors else "OBSERVED",
                  local_guest_vkey=local_key, deployed_vkey=key,
                  vkey_matches_local=key == local_key,
                  bindings=bindings, configured_bindings_match=all(v["matches"] for v in bindings),
                  call_errors=call_errors,
                  deployment_matches_local_source="NOT_PROVEN: runtime hashes recorded, source bytecode equivalence not established")
except Exception as exc:
    result["blocker"] = f"{type(exc).__name__}: {exc}"
finally:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in {"contracts", "rpc_records"}}, indent=2))
sys.exit(0 if result["status"] == "OBSERVED" else 1)
