#!/usr/bin/env python3
"""Read public deployment bindings at one finalized block; never submit transactions."""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from verify_clock_proof import EXPECTED_VKEY

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "contracts/deployments/base-sepolia.json"
READ_METHODS = {"eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"}
MAX_RPC_RESPONSE_BYTES = 1024 * 1024


class ObservationError(ValueError):
    """A diagnostic constructed locally without untrusted error/URL text."""


def require(condition, message):
    if not condition:
        raise ObservationError(message)


def safe_error(exc):
    if isinstance(exc, ObservationError):
        return f"ObservationError: {exc}"
    # Transport and subprocess errors may echo credential-bearing URLs or commands.
    if isinstance(exc, urllib.error.HTTPError) and type(exc.code) is int:
        return f"HTTPError: HTTP status {exc.code}"
    return type(exc).__name__


def quantity(value):
    require(isinstance(value, str) and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value),
            "invalid RPC quantity")
    return int(value, 16)


def hex_data(value, size=None):
    require(isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value),
            "invalid RPC hex data")
    raw = bytes.fromhex(value[2:])
    require(size is None or len(raw) == size, "invalid RPC data length")
    return raw


def header(value, expected_number=None):
    require(isinstance(value, dict), "missing finalized block")
    number = quantity(value.get("number"))
    block_hash = "0x" + hex_data(value.get("hash"), 32).hex()
    require(expected_number is None or number == expected_number, "RPC returned wrong block height")
    return number, block_hash


def public_endpoint(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ObservationError("invalid RPC endpoint URL") from None
    require(parsed.scheme in {"http", "https"} and parsed.hostname,
            "RPC endpoint must be an HTTP(S) URL")
    require(not (parsed.username or parsed.password or parsed.query or parsed.fragment),
            "only anonymous public RPC endpoints are accepted")
    # Do not record paths, which can contain provider credentials.
    return f"{parsed.scheme}://{parsed.hostname}" + (f":{port}" if port else "")


def selector(signature):
    return subprocess.check_output(["cast", "sig", signature], text=True, timeout=10).strip()


def observe(config, witness_url=None):
    records = []
    endpoints = {"primary": config["rpc"]}
    has_witness = witness_url is not None
    if has_witness:
        endpoints["witness"] = witness_url
    result = {
        "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Public read-only RPC. No private key, live mutation, account query or load test.",
        "config_sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
        "status": "BLOCKED", "contracts": {}, "rpc_records": records,
        "rpc_agreement": {
            "status": "PENDING" if has_witness else "NOT_REQUESTED",
            "policy": "Both endpoints must agree on chain, finalized anchor, code and all getters; any failure blocks. No majority or latest fallback.",
            "limitation": "Distinct endpoint hosts do not prove independent operators; agreement does not establish source-bytecode equivalence or release readiness.",
        },
    }

    def rpc(endpoint, method, params):
        require(method in READ_METHODS, "RPC method outside read-only allowlist")
        request_id = len(records) + 1
        record = {"endpoint": endpoint, "method": method, "params": params}
        records.append(record)
        try:
            req = urllib.request.Request(endpoints[endpoint], data=json.dumps({
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
            }).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read(MAX_RPC_RESPONSE_BYTES + 1)
            require(len(body) <= MAX_RPC_RESPONSE_BYTES, f"{endpoint}: RPC response exceeds size limit")
            value = json.loads(body)
            require(isinstance(value, dict) and value.get("jsonrpc") == "2.0"
                    and type(value.get("id")) is int and value["id"] == request_id,
                    f"{endpoint}: invalid JSON-RPC response envelope")
            if "error" in value:
                error = value["error"]
                code = error.get("code") if isinstance(error, dict) else None
                code = code if type(code) is int else None
                record["error"] = {"kind": "rpc", "code": code}
                raise ObservationError(f"{endpoint}: RPC error for {method} (code={code})")
            require("result" in value, f"{endpoint}: missing RPC result")
            observed = value["result"]
            # Keep only method-bound values after validation, never provider debug
            # fields, malformed echoes, raw error messages/data or untrusted IDs.
            if method == "eth_chainId":
                observed = hex(quantity(observed))
            elif method == "eth_getBlockByNumber":
                height, block_hash = header(observed)
                observed = {"number": hex(height), "hash": block_hash}
            else:
                observed = "0x" + hex_data(observed, 32 if method == "eth_call" else None).hex()
            record["response"] = {"jsonrpc": "2.0", "id": request_id, "result": observed}
            return observed
        except Exception as exc:
            diagnostic = safe_error(exc)
            record.setdefault("error", {"kind": "observation", "diagnostic": diagnostic})
            raise ObservationError(f"{endpoint}: {method}: {diagnostic}") from None

    try:
        result["rpc_url"] = public_endpoint(endpoints["primary"])
        if has_witness:
            result["witness_rpc_url"] = public_endpoint(witness_url)
            require(urllib.parse.urlsplit(witness_url).hostname.lower().rstrip(".")
                    != urllib.parse.urlsplit(endpoints["primary"]).hostname.lower().rstrip("."),
                    "witness must use a distinct endpoint host")
        chain = quantity(rpc("primary", "eth_chainId", []))
        require(chain == config["chainId"], "primary: wrong chain")
        anchor = header(rpc("primary", "eth_getBlockByNumber", ["finalized", False]))
        number, block_hash = anchor
        result.update(chain_id=chain, block_number=number, block_hash=block_hash)
        pin = {"blockHash": block_hash, "requireCanonical": True}
        if has_witness:
            require(quantity(rpc("witness", "eth_chainId", [])) == chain, "witness: wrong chain")
            witness_head = header(rpc("witness", "eth_getBlockByNumber", ["finalized", False]))
            result["rpc_agreement"]["witness_finalized_number"] = witness_head[0]
            result["rpc_agreement"]["witness_finalized_hash"] = witness_head[1]
            require(witness_head[0] >= number, "witness: anchor is not yet finalized")
            witness_anchor = header(rpc("witness", "eth_getBlockByNumber", [hex(number), False]), number)
            require(witness_anchor == anchor, "witness: finalized anchor disagreement")
            if witness_head[0] == number:
                require(witness_head == anchor, "witness: inconsistent finalized header")

        queries = {
            "DarkPerpSettlement": ["sequencer()", "enclaveSigner()", "verifier()", "vault()", "governance()", "currentStateRoot()", "batchCount()", "closeOnly()", "windDownSettled()"],
            "CollateralVault": ["settlement()", "gatewaySigner()", "token()", "depositCount()"],
            "SP1ZkVerifier": ["programVKey()", "gateway()"],
            "MockUSDC": [],
        }
        for name, signatures in queries.items():
            address = config["contracts"][name]["address"]
            item = result["contracts"][name] = {"address": address, "calls": {}}
            code = rpc("primary", "eth_getCode", [address, pin])
            raw = hex_data(code)
            require(raw, f"no code at {name}")
            item.update(runtime_bytes=len(raw), runtime_sha256=hashlib.sha256(raw).hexdigest())
            item["runtime_keccak256"] = subprocess.check_output(["cast", "keccak", code], text=True, timeout=10).strip()
            if has_witness:
                require(hex_data(rpc("witness", "eth_getCode", [address, pin])) == raw,
                        f"witness: code disagreement at {name}")
            for signature in signatures:
                params = [{"to": address, "data": selector(signature)}, pin]
                try:
                    value = rpc("primary", "eth_call", params)
                    word = hex_data(value, 32)
                    item["calls"][signature] = {"result": "0x" + word.hex()}
                    if has_witness:
                        require(hex_data(rpc("witness", "eth_call", params), 32) == word,
                                f"witness: getter disagreement at {name}.{signature}")
                except Exception as exc:
                    item["calls"][signature] = {"error": safe_error(exc)}
                    if has_witness:
                        raise
        for endpoint in endpoints:
            after = header(rpc(endpoint, "eth_getBlockByNumber", [hex(number), False]), number)
            require(after == anchor, f"{endpoint}: finalized block changed during observation")
        if has_witness:
            result["rpc_agreement"]["status"] = "AGREED"
        key = result["contracts"]["SP1ZkVerifier"]["calls"]["programVKey()"].get("result")
        # Compare to the independently reviewed clock guest, not a historical
        # pre-clock build log. This observation still does not prove a deployment.
        local_key = EXPECTED_VKEY

        def address_result(name, signature):
            value = result["contracts"][name]["calls"][signature].get("result")
            if value is None or value[2:26] != "0" * 24:
                return None
            return "0x" + value[-40:]

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
                      local_guest_reference="reviewed clock-v2 guest (verify_clock_proof.EXPECTED_VKEY)",
                      local_guest_vkey=local_key, deployed_vkey=key,
                      vkey_matches_local=key == local_key,
                      bindings=bindings, configured_bindings_match=all(v["matches"] for v in bindings),
                      call_errors=call_errors,
                      deployment_matches_local_source="NOT_PROVEN: runtime hashes recorded, source bytecode equivalence not established")
    except Exception as exc:
        result["blocker"] = safe_error(exc)
        if has_witness:
            result["rpc_agreement"]["status"] = "BLOCKED"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=pathlib.Path,
                        default=ROOT / "docs/audits/2026-09-28-continuation/deployment-observation.json")
    parser.add_argument("--witness-rpc", help="Optional second anonymous public RPC URL; disagreement or unavailable data blocks the observation.")
    args = parser.parse_args()
    result = observe(json.loads(CONFIG.read_text()), args.witness_rpc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in {"contracts", "rpc_records"}}, indent=2))
    return 0 if result["status"] == "OBSERVED" else 1


if __name__ == "__main__":
    sys.exit(main())
