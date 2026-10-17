#!/usr/bin/env python3
"""Read a candidate's declared public bindings at one finalized block. HOLD only."""
import argparse
import datetime
import json
import re
import sys
import time
import urllib.parse
import urllib.request

import candidate_identity_manifest as identity
import release_manifest as legacy

ROOT = identity.ROOT
BUILDER = "scripts/local-verification/candidate_target_observer.py"
SCHEMA = "arcora-chainlink-target-observation/v1"
POLICY_SCHEMA = "arcora-chainlink-target-policy/v1"
MAX_ANCESTRY = 64
MAX_RUNTIME_BYTES = 64 * 1024
READ_METHODS = frozenset({"eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"})
LINKS = (
    ("settlement", "verifier()", "clock_verifier"),
    ("settlement", "vault()", "vault"),
    ("vault", "settlement()", "settlement"),
    ("vault", "token()", "token"),
    ("clock_verifier", "settlement()", "settlement"),
    ("clock_verifier", "innerVerifier()", "oracle_wrapper"),
    ("oracle_wrapper", "innerVerifier()", "sp1_adapter"),
    ("oracle_wrapper", "streamsVerifier()", "verifier_proxy"),
    ("oracle_wrapper", "clockVerifier()", "clock_verifier"),
    ("oracle_wrapper", "sequencerUptimeFeed()", "uptime_feed"),
    ("sp1_adapter", "gateway()", "sp1_gateway"),
)


class ObserverError(ValueError):
    """Only fixed local diagnostics may reach an observation report."""


def require(ok, label):
    if not ok:
        raise ObserverError(label)


def source_keccak(root, data):
    return identity.source_keccak(root, data)


def selector(root, signature):
    return legacy.deployment_reader.selector(signature)


def expected_policy(value):
    try:
        identity.exact(value, {"schema", "runtime_hash_algorithm", "operator_policy",
                               "oracle_configurator"}, "candidate target policy")
        require(value["schema"] == POLICY_SCHEMA, "wrong candidate target policy schema")
        require(value["runtime_hash_algorithm"] == "keccak256-evm", "wrong runtime hash algorithm")
        return {"schema": POLICY_SCHEMA, "runtime_hash_algorithm": "keccak256-evm",
                "operator_policy": legacy.operator_policy(value["operator_policy"]),
                "oracle_configurator": identity.hex_value(value["oracle_configurator"], 20,
                                                          "oracle configurator")}
    except Exception:
        raise ObserverError("invalid explicit target policy") from None


def quantity(value):
    require(isinstance(value, str) and len(value) <= 66
            and re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value), "invalid RPC quantity")
    return int(value, 16)


def hex_data(value, size=None, limit=MAX_RUNTIME_BYTES):
    require(isinstance(value, str) and len(value) <= 2 + 2 * limit
            and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value), "invalid RPC hex data")
    data = bytes.fromhex(value[2:])
    require(size is None or len(data) == size, "invalid RPC data length")
    return data


def header(value, expected=None):
    require(isinstance(value, dict), "missing finalized header")
    number = quantity(value.get("number"))
    require(number < 2**64 and (expected is None or number == expected), "wrong block height")
    block_hash = "0x" + hex_data(value.get("hash"), 32).hex()
    parent = "0x" + hex_data(value.get("parentHash"), 32).hex()
    require(int(block_hash, 16) != 0, "zero block hash")
    return {"number": number, "hash": block_hash, "parentHash": parent}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ObserverError("RPC redirect refused")


class CandidateRPC:
    """Anonymous root endpoint, bounded reads; never exposes URL/body/error text."""
    def __init__(self, url):
        try:
            parsed = urllib.parse.urlsplit(url)
            port = parsed.port
            require(parsed.scheme in {"http", "https"} and parsed.hostname,
                    "invalid RPC endpoint")
            require(not (parsed.username or parsed.password or parsed.query or parsed.fragment)
                    and parsed.path in {"", "/"}, "anonymous root RPC endpoint required")
            require(not any(ord(c) < 33 or ord(c) == 127 for c in url), "invalid RPC endpoint")
            host = parsed.hostname
            if ":" in host:
                host = "[" + host + "]"
            self.origin = parsed.scheme + "://" + host + (":" + str(port) if port else "")
        except Exception:
            raise ObserverError("invalid anonymous root RPC endpoint") from None
        self.url = url
        self.sequence = 0
        self.deadline = None
        # Never consult ambient proxy configuration or send proxy credentials.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)

    def __call__(self, method, params):
        require(method in READ_METHODS, "RPC method outside read-only allowlist")
        if self.deadline is None:
            self.deadline = time.monotonic() + 120
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "RPC observation time budget exhausted")
        call_deadline = min(self.deadline, time.monotonic() + 15)
        self.sequence += 1
        request = urllib.request.Request(self.url, data=identity.canonical({
            "jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params}),
            headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=min(15, remaining)) as response:
                # read1 returns after one buffered/network read, so a drip-fed
                # body cannot postpone every deadline check until a full buffer.
                body = bytearray()
                while len(body) <= legacy.deployment_reader.MAX_RPC_RESPONSE_BYTES:
                    require(time.monotonic() <= call_deadline, "RPC checked time budget exhausted")
                    chunk = response.read1(min(4096,
                        legacy.deployment_reader.MAX_RPC_RESPONSE_BYTES + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                body = bytes(body)
            require(len(body) <= legacy.deployment_reader.MAX_RPC_RESPONSE_BYTES, "RPC response exceeds bound")
            value = identity.decode_json(body)
            require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
                    and value["jsonrpc"] == "2.0" and type(value["id"]) is int
                    and value["id"] == self.sequence, "invalid RPC response envelope")
            require(time.monotonic() <= call_deadline, "RPC checked time budget exhausted")
            return value["result"]
        except Exception:
            raise ObserverError("RPC response or transport refused") from None


def observe_target(root, manifest, config, policy, rpc):
    scope = {**identity.SCOPE, "local_identity_checked": False,
             "operator_and_settlement_policy_matches": False,
             "rpc_ancestry_consistent": False, "uptime_health_observed": False,
             "token_proxy_feed_implementations_audited": False}
    result = {"schema": SCHEMA, "status": "BLOCKED",
              "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "contracts": {}, "bindings": [], "scope": scope,
              "limitations": [
                  "RPC code, storage and parent hashes are trusted responses; no light client or independent consensus.",
                  "Seven compiler runtimes are matched; token, DON proxy and uptime feed have declaration-only code hashes.",
                  "Operator/policy values are matched, not approved; no uptime health or real DON verification.",
                  "No service attestation, fresh build/setup/proof, transaction, custody or production acceptance."]}
    try:
        try:
            snapshots = tuple(identity.canonical(v) for v in (manifest, config, policy))
            validated = identity.validate_manifest(root, manifest, config)
            declared = expected_policy(policy)
            observer = legacy.identity(root, BUILDER)
            require(validated["source"]["files_sha256"].get(BUILDER) == observer["sha256"],
                    "observer source is not manifest-bound")
        except Exception:
            raise ObserverError("local candidate identity or explicit policy refused") from None
        scope["local_identity_checked"] = True
        public = validated["public_config"]
        addresses = public["addresses"]
        result.update(manifest_sha256=identity.digest(snapshots[0]),
                      public_config_sha256=identity.digest(snapshots[1]),
                      target_policy_sha256=identity.digest(identity.canonical(declared)),
                      observer=observer, runtime_hash_algorithm="keccak256-evm")
        if isinstance(rpc, CandidateRPC):
            result["rpc_origin"] = rpc.origin

        def read(method, params):
            require(method in READ_METHODS, "RPC method outside read-only allowlist")
            try:
                # An injected transport must not mutate our saved anchor/calls.
                return rpc(method, json.loads(identity.canonical(params)))
            except Exception:
                raise ObserverError("RPC request refused") from None

        chain = quantity(read("eth_chainId", []))
        require(chain == public["chain_id"], "target chain mismatch")
        anchor = header(read("eth_getBlockByNumber", ["finalized", False]))
        result.update(chain_id=chain, anchor=anchor)
        pin = {"blockHash": anchor["hash"], "requireCanonical": True}
        original_codes = {}
        for role in sorted(identity.ADDRESS_ROLES):
            code = hex_data(read("eth_getCode", [addresses[role], pin]))
            require(bool(code), "configured runtime missing: " + role)
            try:
                code_hash = identity.hex_value(source_keccak(root, code), 32, "runtime hash")
            except Exception:
                raise ObserverError("runtime hash computation refused") from None
            require(code_hash == public["expected_runtime_code_hashes"][role],
                    "declared runtime code hash mismatch: " + role)
            value = {"address": addresses[role], "evm_code_hash": code_hash,
                     "runtime_sha256": identity.digest(code), "runtime_bytes": len(code), "getters": {},
                     "identity_kind": "declared_code_hash_only"}
            if role in identity.CONTRACTS:
                path = "contracts/" + identity.CONTRACTS[role][0]
                try:
                    raw = legacy.regular(root, path).read_bytes()
                    require(identity.digest(raw) == validated["compiled_contracts"][role]["sha256"],
                            "compiler artifact changed")
                    artifact = identity.decode_json(raw)
                    # Candidate artifacts allow compiler object hex with or
                    # without 0x; the legacy runtime helper requires the prefix.
                    template = artifact["deployedBytecode"]["object"]
                    artifact["deployedBytecode"]["object"] = "0x" + template.removeprefix("0x")
                    value.update(legacy.runtime_identity(artifact, code, role))
                except Exception:
                    raise ObserverError("compiler runtime template refused: " + role) from None
                value["identity_kind"] = "compiler_template_and_declared_code_hash"
            result["contracts"][role] = value
            original_codes[role] = code

        original_calls = []

        def call(role, signature, argument="", size=32):
            try:
                data = selector(root, signature)
                require(isinstance(data, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", data), "invalid selector")
            except Exception:
                raise ObserverError("local ABI selector refused") from None
            params = [{"to": addresses[role], "data": data + argument}, pin]
            raw = hex_data(read("eth_call", params), size)
            original_calls.append((params, raw))
            return raw

        def getter(role, signature, expected, kind="address", bits=256):
            raw = call(role, signature)
            if kind == "address":
                require(raw[:12] == bytes(12), "noncanonical ABI address")
                value = "0x" + raw[12:].hex()
            elif kind == "uint":
                value = int.from_bytes(raw, "big")
                require(value < 2**bits, "noncanonical narrow ABI integer")
            else:
                value = "0x" + raw.hex()
            require(value == expected, "target binding mismatch: " + role + "." + signature)
            result["contracts"][role]["getters"][signature] = value
            result["bindings"].append({"role": role, "getter": signature, "expected": expected, "matches": True})

        for role, signature, target in LINKS:
            getter(role, signature, addresses[target])
        getter("sp1_adapter", "programVKey()", public["program_vkey"], "bytes32")
        getter("clock_verifier", "maxWindowMs()", public["clock"]["max_window_ms"], "uint", 64)
        getter("clock_verifier", "clockSkewMs()", public["clock"]["clock_skew_ms"], "uint", 64)
        getter("clock_verifier", "anchorTimeoutMs()", public["clock"]["anchor_timeout_ms"], "uint", 64)
        getter("clock_verifier", "proofVersion()", 2, "uint", 8)
        getter("settlement", "ABI_VERSION()", legacy.SETTLEMENT_ABI_VERSION, "uint")
        getter("oracle_wrapper", "policyHash()", public["oracle_policy_hash"], "bytes32")
        getter("oracle_wrapper", "deploymentChainId()", chain, "uint")
        getter("oracle_wrapper", "sequencerGraceSeconds()", public["sequencer_grace_seconds"], "uint", 64)
        getter("oracle_wrapper", "configurator()", declared["oracle_configurator"])
        verifier_hash = "0x" + legacy.clock.target.VERIFIER_HASH
        getter("sp1_verifier", "VERIFIER_HASH()", verifier_hash, "bytes32")
        route = call("sp1_gateway", "routes(bytes4)", verifier_hash[2:10] + "0" * 56, 64)
        require(route[:12] == bytes(12) and route[32:] in (bytes(32), bytes(31) + b"\x01"),
                "noncanonical SP1 route ABI")
        require("0x" + route[12:32].hex() == addresses["sp1_verifier"] and route[32:] == bytes(32),
                "SP1 route is wrong or frozen")
        result["sp1_route"] = {"selector": verifier_hash[:10], "verifier": addresses["sp1_verifier"], "frozen": False}
        operators = declared["operator_policy"]
        for role, fields in legacy.OPERATOR_ADDRESSES.items():
            for name, signature in fields.items():
                getter(role, signature, operators[role][name])
        for name, signature in legacy.SETTLEMENT_POLICY.items():
            getter("settlement", signature, operators["settlement"][name], "uint")

        # Detect repeated-read equivocation at the same anchor; no consensus claim.
        for role, expected in original_codes.items():
            require(hex_data(read("eth_getCode", [addresses[role], pin])) == expected,
                    "runtime changed at fixed block")
        for params, expected in original_calls:
            require(hex_data(read("eth_call", params), len(expected)) == expected,
                    "getter changed at fixed block")
        require(header(read("eth_getBlockByNumber", [hex(anchor["number"]), False]), anchor["number"]) == anchor,
                "original finalized anchor changed")
        tip = header(read("eth_getBlockByNumber", ["finalized", False]))
        require(anchor["number"] <= tip["number"] <= anchor["number"] + MAX_ANCESTRY,
                "finalized head regressed or ancestry bound exceeded")
        final_tip = dict(tip)
        while tip["number"] > anchor["number"]:
            parent = header(read("eth_getBlockByNumber", [hex(tip["number"] - 1), False]), tip["number"] - 1)
            require(parent["hash"] == tip["parentHash"], "finalized ancestry gap or fork")
            tip = parent
        require(tip == anchor, "finalized ancestry did not reach original anchor")
        require(quantity(read("eth_chainId", [])) == chain, "chain changed during observation")
        try:
            require(tuple(identity.canonical(v) for v in (manifest, config, policy)) == snapshots,
                    "input snapshot changed during observation")
            identity.validate_manifest(root, manifest, config)
            require(expected_policy(policy) == declared, "declared policy changed during observation")
        except Exception:
            raise ObserverError("local identity or input snapshot changed during observation") from None
        result["finalized_tip_at_completion"] = final_tip
        scope.update(target_chain_observed=True, runtime_bytecode_verified=True,
                     operator_and_settlement_policy_matches=True, rpc_ancestry_consistent=True)
        result["status"] = "VERIFIED_AT_FINALIZED_BLOCK"
    except Exception as error:
        # Provider exceptions were wrapped above; never echo an arbitrary message.
        result["blocker"] = str(error) if type(error) is ObserverError else "candidate observation refused"
    return result


def main():
    class PublicParser(argparse.ArgumentParser):
        def error(self, _message):
            self.exit(2, "Invalid candidate target observer arguments.\n")
    parser = PublicParser(description=__doc__)
    for name in ("manifest", "config", "policy", "rpc", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        output = identity.public_path(args.output)
        require(not output.exists() and not output.is_symlink(), "observation output already exists")
        paths = [identity.public_path(name) for name in (args.manifest, args.config, args.policy)]
        inputs = [identity.read_json(path) for path in paths]
        result = observe_target(ROOT, *inputs, CandidateRPC(args.rpc))
        identity.create_output(output, result)
        print(json.dumps({"status": result["status"], "release_gate": "HOLD", "schema": SCHEMA}))
        return 0 if result["status"] == "VERIFIED_AT_FINALIZED_BLOCK" else 1
    except Exception:
        print("Candidate target observation refused.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
