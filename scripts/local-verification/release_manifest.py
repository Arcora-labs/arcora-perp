#!/usr/bin/env python3
"""Bind reviewed clock identities; optionally observe a target with read-only RPC.

Manifest create/validate are offline. observe-target checks finalized runtime
and contract links, without submitting transactions. Neither operation builds an
ELF, verifies a new proof, or attests a running prover. Manifest integrity is
relative to a trusted script and release manifest, not a release signature.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

if sys.version_info < (3, 11):
    sys.exit("Release preflight requires Python 3.11+ (tomllib).")

import check_sp1_release
import verify_clock_proof as clock
import read_deployment as deployment_reader

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "arcora-clock-release/v1"
FIXTURE = "contracts/integration/fixtures/clock-v2-verified"
CONTRACTS = {
    "settlement": ("out/DarkPerpSettlement.sol/DarkPerpSettlement.json", "DarkPerpSettlement", "0.8.24+commit.e11b9ed9"),
    "vault": ("out/CollateralVault.sol/CollateralVault.json", "CollateralVault", "0.8.24+commit.e11b9ed9"),
    "sp1_adapter": ("out/SP1ZkVerifier.sol/SP1ZkVerifier.json", "SP1ZkVerifier", "0.8.24+commit.e11b9ed9"),
    "clock_verifier": ("out/ClockBoundVerifier.sol/ClockBoundVerifier.json", "ClockBoundVerifier", "0.8.24+commit.e11b9ed9"),
    "sp1_gateway": ("out/sp1-upstream/SP1VerifierGateway.sol/SP1VerifierGateway.json", "SP1VerifierGateway", "0.8.20+commit.a1b79de6"),
    "sp1_verifier": ("out/sp1-upstream/SP1VerifierGroth16.sol/SP1Verifier.json", "SP1Verifier", "0.8.20+commit.a1b79de6"),
}
ENV_ADDRESSES = {
    "L1_SETTLEMENT": "settlement", "L1_VAULT": "vault", "L1_USDC": "token",
    "CLOCK_BOUND_VERIFIER": "clock_verifier",
}
ADDRESS_ROLES = set(CONTRACTS) | {"token"}
GATEWAY_KEYS = set(ENV_ADDRESSES) | {"L1_CHAIN_ID", "L1_ALLOW_MOCK_PROOF"}
# Public, independently reviewed expected values. Reading a getter must never
# silently approve the identity or economic policy it happens to return.
OPERATOR_ADDRESSES = {
    "settlement": {"sequencer": "sequencer()", "enclave_signer": "enclaveSigner()",
                   "governance": "governance()"},
    "vault": {"gateway_signer": "gatewaySigner()"},
    "clock_verifier": {"configurator": "configurator()"},
    "sp1_gateway": {"owner": "owner()"},
}
SETTLEMENT_POLICY = {
    "liveness_timeout_blocks": "livenessTimeoutBlocks()",
    "challenge_window_blocks": "challengeWindowBlocks()",
    "challenge_bond_wei": "challengeBond()",
    "inclusion_deadline_seconds": "inclusionDeadlineSecs()",
    "final_settle_grace_blocks": "finalSettleGraceBlocks()",
}
SCOPE = {
    "local_identity_checked": True,
    "target_chain_observed": False,
    "runtime_bytecode_verified": False,
    "running_services_attested": False,
    "fresh_guest_build_performed": False,
    "state_migration_rehearsed": False,
    "release_gate": "HOLD",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(_value):
        raise ValueError("non-finite JSON number")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def read_json(path):
    return decode_json(Path(path).read_text())


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + ": unexpected or missing fields")


def regular(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
            and ".." not in Path(relative).parts, "unsafe artifact/source path")
    path = root
    for part in Path(relative).parts:
        path /= part
        require(not path.is_symlink(), "symlinked artifact/source path")
    require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024,
            "missing, nonregular or oversized artifact/source: " + relative)
    return path


def identity(root, relative):
    data = regular(root, relative).read_bytes()
    return {"path": relative, "sha256": digest(data), "size_bytes": len(data)}


def normalized_hex(value, size, label):
    require(isinstance(value, str) and re.fullmatch("0x[0-9a-fA-F]{%d}" % (size * 2), value),
            "invalid " + label)
    return value.lower()


def operator_policy(value):
    """Validate public identity/ABI policy pins, not their economic suitability.

    Explicit zero addresses/values are retained, never filled in or inferred:
    renounced governance and zero bonds are review decisions, not parser defaults.
    Unknown fields (including credentials) fail without echoing their values.
    """
    exact_keys(value, OPERATOR_ADDRESSES, "operator policy")
    result = {}
    for role, fields in OPERATOR_ADDRESSES.items():
        keys = set(fields) | (set(SETTLEMENT_POLICY) if role == "settlement" else set())
        exact_keys(value[role], keys, "operator policy " + role)
        result[role] = {name: normalized_hex(value[role][name], 20, role + "." + name)
                        for name in fields}
        if role == "settlement":
            for name in SETTLEMENT_POLICY:
                number = value[role][name]
                require(type(number) is int and 0 <= number < 2**256,
                        "invalid settlement policy " + name)
                result[role][name] = number
    return result


def public_config(value):
    keys = {"chain_id", "addresses", "program_vkey", "clock", "gateway", "prover"}
    if isinstance(value, dict) and "operator_policy" in value:
        keys.add("operator_policy")
    exact_keys(value, keys, "public config")
    require(type(value["chain_id"]) is int and 0 < value["chain_id"] < 2**64, "invalid chain_id")
    exact_keys(value["addresses"], ADDRESS_ROLES, "addresses")
    addresses = {key: normalized_hex(address, 20, key) for key, address in value["addresses"].items()}
    require(all(int(address, 16) != 0 for address in addresses.values()), "zero contract address")
    require(len(set(addresses.values())) == len(addresses), "contract roles must use distinct addresses")
    key = normalized_hex(value["program_vkey"], 32, "program_vkey")
    require(key == clock.EXPECTED_VKEY, "program_vkey does not match reviewed clock guest")
    exact_keys(value["clock"], {"max_window_ms", "clock_skew_ms"}, "clock policy")
    for number in value["clock"].values():
        require(type(number) is int and 400 <= number < 2**64, "clock policy cannot satisfy gateway cadence")
    exact_keys(value["gateway"], GATEWAY_KEYS, "public gateway config")
    gateway = dict(value["gateway"])
    require(gateway["L1_CHAIN_ID"] == str(value["chain_id"]), "gateway chain_id mismatch")
    require(gateway["L1_ALLOW_MOCK_PROOF"] == "0", "mock proof mode must be disabled explicitly")
    for env, role in ENV_ADDRESSES.items():
        gateway[env] = normalized_hex(gateway[env], 20, env)
        require(gateway[env] == addresses[role], "gateway address mismatch: " + env)
    exact_keys(value["prover"], {"program_vkey", "guest_elf_sha256"}, "public prover config")
    prover_key = normalized_hex(value["prover"]["program_vkey"], 32, "prover program_vkey")
    require(prover_key == key, "prover program_vkey mismatch")
    require(value["prover"]["guest_elf_sha256"] == clock.EXPECTED_ELF, "prover guest ELF mismatch")
    result = {"chain_id": value["chain_id"], "addresses": addresses, "program_vkey": key,
              "clock": dict(value["clock"]), "gateway": gateway,
              "prover": {"program_vkey": prover_key, "guest_elf_sha256": clock.EXPECTED_ELF}}
    if "operator_policy" in value:
        result["operator_policy"] = operator_policy(value["operator_policy"])
    return result


def check_environment(config, env):
    # Never read, record, or diagnose key values from the service environment.
    for key, expected in config["gateway"].items():
        actual = env.get(key)
        if key in ENV_ADDRESSES and isinstance(actual, str):
            actual = actual.lower()
        require(actual == expected, "process environment mismatch: " + key)


def verify_reviewed_guest(root):
    expected = set(clock.EXPECTED_GUEST_SOURCES)
    # Existing pins cover file contents, but a new build.rs, module or Cargo
    # config can change the program without modifying any previously pinned file.
    for directory in ("crates/perp-core/src", "crates/sp1-guest/src"):
        actual = {p.relative_to(root).as_posix() for p in (root / directory).rglob("*")
                  if p.is_file() or p.is_symlink()}
        require(actual == {name for name in expected if name.startswith(directory + "/")},
                "guest source layout changed; rebuild and reprove: " + directory)
    for directory in ("", "crates", "crates/perp-core", "crates/sp1-guest"):
        for name in ("build.rs", ".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
            path = root / directory / name
            require(not path.exists() and not path.is_symlink(),
                    "unreviewed guest build input; rebuild and reprove: " + str(path.relative_to(root)))
    for name, expected_hash in clock.EXPECTED_GUEST_SOURCES.items():
        require(identity(root, name)["sha256"] == expected_hash, "guest source changed; rebuild and reprove: " + name)


def source_inventory(root):
    # Include untracked new source files: a commit SHA alone cannot identify a
    # dirty worktree. Git's excludes avoid target/, out/, secrets and caches.
    raw = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root)
    files = set(raw.decode().rstrip("\0").split("\0"))
    prefixes = ("crates/", "vendor/", "contracts/src/", "contracts/vendor/", "scripts/local-verification/")
    fixed = {"Cargo.toml", "Cargo.lock", "contracts/foundry.toml"}
    def is_source(name):
        path = Path(name)
        # Git exclusions do not hide tracked secrets. Never fingerprint dotenv
        # files or credential/config stores accidentally checked into the tree.
        if any(part.lower().startswith(".env") for part in path.parts):
            return False
        if path.suffix in {".json", ".toml"} and re.search(
            r"(?:^|[._-])(?:secrets?|credentials?|private[-_]keys?)(?:[._-]|$)", path.name.lower()
        ):
            return False
        return name in fixed or (name.startswith(prefixes)
                                 and path.suffix in {".rs", ".toml", ".lock", ".sol", ".py", ".json", ".sh"})
    selected = sorted(name for name in files if is_source(name))
    require(fixed <= set(selected), "incomplete source tree")
    return {name: identity(root, name)["sha256"] for name in selected}


def command(args, root):
    # A subprocess failure can contain local paths/URLs; do not echo stderr.
    result = subprocess.run(args, cwd=root, text=True, capture_output=True, timeout=60)
    require(result.returncode == 0, "required local tool failed: " + args[0])
    return result.stdout.strip()


def compiled_contract(root, role):
    relative, name, compiler = CONTRACTS[role]
    path = "contracts/" + relative
    artifact = read_json(regular(root, path))
    metadata = artifact["metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    require(metadata["compiler"]["version"] == compiler, "wrong Solidity compiler: " + role)
    settings = metadata["settings"]
    require(list(settings["compilationTarget"].values()) == [name], "wrong compilation target: " + role)
    optimizer = settings["optimizer"]
    require(isinstance(optimizer, dict) and set(optimizer) == {"enabled", "runs"}
            and optimizer["enabled"] is True and type(optimizer["runs"]) is int
            and optimizer["runs"] == 200, "wrong optimizer profile: " + role)
    compiler_root = root / ("contracts/vendor/sp1-contracts" if role.startswith("sp1_")
                            and role in {"sp1_gateway", "sp1_verifier"} else "contracts")
    sources = metadata["sources"]
    require(isinstance(sources, dict) and sources, "missing compiler source bindings: " + role)
    for source, expected in sources.items():
        source_path = regular(compiler_root, source)
        actual = command(["cast", "keccak", "0x" + source_path.read_bytes().hex()], root)
        require(actual.lower() == expected["keccak256"].lower(), "stale compiled source: " + source)
    result = {**identity(root, path), "compiler": compiler}
    for field, label in (("bytecode", "creation_bytecode_sha256"),
                         ("deployedBytecode", "runtime_template_sha256")):
        bytecode = artifact[field]["object"]
        require(isinstance(bytecode, str) and re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})+", bytecode),
                "empty or unlinked contract bytecode: " + role)
        require(not artifact[field].get("linkReferences"), "external library links require separate binding")
        result[label] = digest(bytes.fromhex(bytecode.removeprefix("0x")))
    result["runtime_note"] = "Compiler template, including immutable placeholders; not the deployed runtime hash."
    return result


def build_manifest(root, config):
    config = public_config(config)
    # The reviewed ELF and key are pinned independently of caller-supplied JSON.
    release = check_sp1_release.check(root)
    require(release["passed"], "SP1 dependency/provenance release guard failed")
    verify_reviewed_guest(root)
    sources = source_inventory(root)
    artifacts = {name: identity(root, FIXTURE + "/" + name) for name in ("guest.elf", "program-vkey.bin")}
    require(regular(root, FIXTURE + "/guest.elf").read_bytes().startswith(b"\x7fELF"), "actual guest ELF required")
    require(artifacts["guest.elf"]["sha256"] == clock.EXPECTED_ELF, "wrong reviewed guest ELF")
    require("0x" + regular(root, FIXTURE + "/program-vkey.bin").read_bytes().hex() == clock.EXPECTED_VKEY,
            "wrong reviewed setup key")
    contracts = {role: compiled_contract(root, role) for role in CONTRACTS}
    require(source_inventory(root) == sources, "source changed while generating manifest")
    commit = command(["git", "rev-parse", "HEAD"], root)
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit), "invalid source commit")
    return {"schema": SCHEMA, "source": {"commit": commit, "files_sha256": sources,
            "inventory_sha256": digest(canonical(sources))},
            "guest": {"elf": artifacts["guest.elf"], "setup_key": artifacts["program-vkey.bin"],
                      "program_vkey": clock.EXPECTED_VKEY, "sp1_version": check_sp1_release.RELEASE,
                      "provenance": "PR31 reviewed clock guest identity; this command does not rebuild or reprove it."},
            "compiled_contracts": contracts, "public_config": config,
            "public_config_sha256": digest(canonical(config)), "scope": dict(SCOPE)}


def validate_manifest(root, manifest, config, env=None):
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA, "unsupported release manifest")
    expected = build_manifest(root, config)
    # Rebuild the full expected object: deleting source/contract/config fields or
    # inventing a PASS claim must not weaken validation.
    # JSON types matter: Python's dictionary equality accepts True == 1 and
    # False == 0. Canonical serialized comparison preserves that distinction.
    require(canonical(manifest) == canonical(expected),
            "release manifest mismatch (source, artifact, configuration or scope changed)")
    if env is not None:
        check_environment(expected["public_config"], env)
    return expected


def check_deployment_config(deployment):
    """Reject legacy deployment records before operators use them for clock v2.

    This checks only recorded addresses/key, never current chain state.
    """
    contracts = deployment["contracts"]
    key = normalized_hex(contracts["SP1ZkVerifier"]["programVKey"], 32, "deployment programVKey")
    require(key == clock.EXPECTED_VKEY, "deployment programVKey does not match reviewed clock guest")
    require("ClockBoundVerifier" in contracts, "deployment has no clock verifier")
    require(type(deployment["chainId"]) is int and 0 < deployment["chainId"] < 2**64, "invalid deployment chainId")
    for name in ("DarkPerpSettlement", "CollateralVault", "SP1ZkVerifier", "ClockBoundVerifier"):
        address = normalized_hex(contracts[name]["address"], 20, "deployment address")
        require(int(address, 16) != 0, "zero deployment address")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("RPC redirects are not accepted")


class TargetRPC:
    """Strict read-only transport. Diagnostics never include a URL or RPC payload."""
    def __init__(self, url):
        self.origin = deployment_reader.public_endpoint(url)
        self.url = url
        self.sequence = 0
        self.opener = urllib.request.build_opener(NoRedirect)

    def __call__(self, method, params):
        require(method in deployment_reader.READ_METHODS, "RPC method outside read-only allowlist")
        self.sequence += 1
        request = urllib.request.Request(self.url, data=canonical({
            "jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params,
        }), headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=15) as response:
                body = response.read(deployment_reader.MAX_RPC_RESPONSE_BYTES + 1)
        except Exception as error:
            raise ValueError("target RPC transport failed: " + deployment_reader.safe_error(error)) from None
        require(len(body) <= deployment_reader.MAX_RPC_RESPONSE_BYTES, "RPC response exceeds size limit")
        try:
            value = decode_json(body)
        except (ValueError, UnicodeError):
            raise ValueError("invalid RPC JSON response") from None
        require(isinstance(value, dict) and value.get("jsonrpc") == "2.0"
                and type(value.get("id")) is int and value["id"] == self.sequence,
                "invalid JSON-RPC response envelope")
        require("error" not in value and "result" in value, "RPC did not return a successful result")
        return value["result"]


def runtime_identity(artifact, deployed, role):
    """Match every byte; substitute only compiler-declared immutable words.

    Each occurrence of the same immutable must agree. Values are OBSERVED,
    not approved constructor parameters. Configured links/key/clock policy are
    checked separately via the same-block getters of the matched runtime.
    """
    template = deployment_reader.hex_data(artifact["deployedBytecode"]["object"])
    require(template and len(template) == len(deployed), "runtime size mismatch: " + role)
    references = artifact["deployedBytecode"].get("immutableReferences", {})
    require(isinstance(references, dict), "invalid compiler immutable references: " + role)
    rebuilt = bytearray(template)
    occupied = set()
    values = {}
    for name, locations in references.items():
        require(isinstance(name, str) and name.isdecimal() and isinstance(locations, list) and locations,
                "invalid compiler immutable reference: " + role)
        word = None
        for location in locations:
            exact_keys(location, {"start", "length"}, "immutable reference")
            start, length = location["start"], location["length"]
            require(type(start) is int and type(length) is int and length == 32
                    and 0 <= start <= len(template) - length, "invalid immutable range: " + role)
            offsets = set(range(start, start + length))
            require(not occupied.intersection(offsets), "overlapping immutable references: " + role)
            occupied.update(offsets)
            require(template[start:start + length] == bytes(32), "nonzero immutable placeholder: " + role)
            actual = deployed[start:start + length]
            require(word is None or word == actual, "inconsistent immutable occurrences: " + role)
            word = actual
            rebuilt[start:start + length] = word
        values[name] = "0x" + word.hex()
    require(bytes(rebuilt) == deployed, "runtime bytecode mismatch outside immutables: " + role)
    return {"runtime_sha256": digest(deployed), "runtime_bytes": len(deployed),
            "immutable_words_by_compiler_id": values,
            "runtime_matches_compiler_template": True}


def observe_target(root, manifest, config, rpc, *, require_operator_policy=False):
    """Observe the complete clock stack at a single finalized, hash-pinned block.

    `rpc` is injectable for deterministic failure tests. The CLI always uses the
    read-only TargetRPC; this function never deploys or repairs contract state.
    """
    result = {"status": "BLOCKED", "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "manifest_sha256": digest(canonical(manifest)), "contracts": {}, "bindings": [],
              "scope": {**SCOPE, "local_identity_checked": False, "operator_and_settlement_policy_approved": False,
                        "operator_and_settlement_policy_matches": False,
                        "token_runtime_verified": False},
              "limitations": ["RPC responses are trusted; no light-client or independent endpoint consensus.",
                              "Declared operator/settlement policy can be matched; its security and economic suitability are not approved.",
                              "Token code presence is checked; its implementation, proxy and issuance policy are not audited.",
                              "No proof is generated or submitted; no service identity, state migration or release readiness is established."]}
    try:
        validated = validate_manifest(root, manifest, config)
        result["scope"]["local_identity_checked"] = True
        public = validated["public_config"]
        addresses = public["addresses"]
        require(type(require_operator_policy) is bool, "invalid operator policy requirement")
        policy = public.get("operator_policy")
        require(not require_operator_policy or policy is not None, "explicit operator policy required")
        if policy is not None:
            policy = operator_policy(policy)
            result["operator_policy_sha256"] = digest(canonical(policy))
        if isinstance(rpc, TargetRPC):
            result["rpc_origin"] = rpc.origin
        chain = deployment_reader.quantity(rpc("eth_chainId", []))
        require(chain == public["chain_id"], "target chain_id mismatch")
        height, block_hash = deployment_reader.header(rpc("eth_getBlockByNumber", ["finalized", False]))
        result.update(chain_id=chain, block_number=height, block_hash=block_hash)
        pin = {"blockHash": block_hash, "requireCanonical": True}
        for role, (relative, _, _) in CONTRACTS.items():
            artifact_bytes = regular(root, "contracts/" + relative).read_bytes()
            require(digest(artifact_bytes) == validated["compiled_contracts"][role]["sha256"],
                    "compiled artifact changed during observation: " + role)
            artifact = json.loads(artifact_bytes)
            code = deployment_reader.hex_data(rpc("eth_getCode", [addresses[role], pin]))
            result["contracts"][role] = {"address": addresses[role], **runtime_identity(artifact, code, role), "getters": {}}
        token = deployment_reader.hex_data(rpc("eth_getCode", [addresses["token"], pin]))
        require(token, "no token code at configured address")
        result["token"] = {"address": addresses["token"], "runtime_sha256": digest(token), "runtime_bytes": len(token)}

        def getter(role, signature, kind="address", expected=None, argument=""):
            data = deployment_reader.selector(signature) + argument
            raw = deployment_reader.hex_data(rpc("eth_call", [{"to": addresses[role], "data": data}, pin]), 32)
            if kind == "address":
                require(raw[:12] == bytes(12), "noncanonical ABI address: " + role + "." + signature)
                value = "0x" + raw[12:].hex()
            elif kind == "uint":
                value = int.from_bytes(raw, "big")
            else:
                value = "0x" + raw.hex()
            result["contracts"][role]["getters"][signature] = value
            if expected is not None:
                require(value == expected, "target binding mismatch: " + role + "." + signature)
                result["bindings"].append({"contract": role, "getter": signature, "expected": expected, "matches": True})
            return value

        for role, signature, target in (
            ("settlement", "verifier()", "clock_verifier"), ("settlement", "vault()", "vault"),
            ("vault", "settlement()", "settlement"), ("vault", "token()", "token"),
            ("clock_verifier", "settlement()", "settlement"), ("clock_verifier", "innerVerifier()", "sp1_adapter"),
            ("sp1_adapter", "gateway()", "sp1_gateway"),
        ):
            getter(role, signature, expected=addresses[target])
        getter("sp1_adapter", "programVKey()", "bytes32", public["program_vkey"])
        getter("clock_verifier", "maxWindowMs()", "uint", public["clock"]["max_window_ms"])
        getter("clock_verifier", "clockSkewMs()", "uint", public["clock"]["clock_skew_ms"])
        getter("clock_verifier", "proofVersion()", "uint", 2)
        verifier_hash = "0x" + clock.target.VERIFIER_HASH
        getter("sp1_verifier", "VERIFIER_HASH()", "bytes32", verifier_hash)
        # bytes4 is left-aligned in a 32-byte ABI word. The gateway returns
        # (address,bool); both canonical encodings and the unfrozen route matter.
        route_data = deployment_reader.selector("routes(bytes4)") + verifier_hash[2:10] + "0" * 56
        route = deployment_reader.hex_data(rpc("eth_call", [{"to": addresses["sp1_gateway"], "data": route_data}, pin]), 64)
        require(route[:12] == bytes(12) and route[32:] in (bytes(32), bytes(31) + b"\x01"),
                "noncanonical SP1 gateway route ABI")
        require("0x" + route[12:32].hex() == addresses["sp1_verifier"] and route[32:] == bytes(32),
                "SP1 gateway route is wrong or frozen")
        result["sp1_route"] = {"selector": verifier_hash[:10], "verifier": addresses["sp1_verifier"], "frozen": False}
        # Compare only with explicitly supplied, manifest-bound policy. Omitting
        # a policy keeps legacy observation mode; it cannot produce a match claim.
        for role, fields in OPERATOR_ADDRESSES.items():
            for name, signature in fields.items():
                getter(role, signature, expected=policy[role][name] if policy is not None else None)
        for name, signature in SETTLEMENT_POLICY.items():
            getter("settlement", signature, "uint",
                   policy["settlement"][name] if policy is not None else None)
        require(deployment_reader.header(rpc("eth_getBlockByNumber", [hex(height), False]), height) == (height, block_hash),
                "finalized block changed during observation")
        require(deployment_reader.quantity(rpc("eth_chainId", [])) == chain, "chain changed during observation")
        # Source/artifacts/config must still be the validated release at completion.
        validate_manifest(root, manifest, config)
        result["status"] = "VERIFIED_AT_FINALIZED_BLOCK"
        result["scope"].update(target_chain_observed=True, runtime_bytecode_verified=True,
                               operator_and_settlement_policy_matches=policy is not None)
    except Exception as error:
        # Never expose provider error data, response body, credential URL or paths.
        result["blocker"] = str(error) if type(error) is ValueError else deployment_reader.safe_error(error)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="record local release identities; target chain remains HOLD")
    create.add_argument("--config", type=Path, required=True, help="public config only; never an .env or keys file")
    create.add_argument("--output", type=Path, required=True)
    validate = commands.add_parser("validate", help="fail closed on source/artifact/config changes")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--check-process-env", action="store_true", help="compare allowlisted gateway variables before startup")
    deployment = commands.add_parser("check-deployment", help="check recorded deployment key only, without RPC")
    deployment.add_argument("--deployment", type=Path, required=True)
    target = commands.add_parser("observe-target", help="read-only finalized clock-stack runtime and binding verification; release remains HOLD")
    target.add_argument("--manifest", type=Path, required=True)
    target.add_argument("--config", type=Path, required=True)
    target.add_argument("--rpc", required=True, help="anonymous public HTTP(S) RPC; no keys or credentials")
    target.add_argument("--output", type=Path, required=True)
    target.add_argument("--require-operator-policy", action="store_true",
                        help="refuse before RPC unless a complete expected operator/settlement policy is bound")
    args = parser.parse_args()
    if args.command == "check-deployment":
        check_deployment_config(read_json(args.deployment))
        print(json.dumps({"status": "PASS", "scope": "recorded key and address shape only; no RPC or runtime verification"}))
    elif args.command == "observe-target":
        result = observe_target(ROOT, read_json(args.manifest), read_json(args.config), TargetRPC(args.rpc),
                                require_operator_policy=args.require_operator_policy)
        with args.output.open("x") as output:
            output.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ("status", "scope", "blocker") if key in result}))
        if result["status"] != "VERIFIED_AT_FINALIZED_BLOCK":
            sys.exit(1)
    elif args.command == "create":
        result = build_manifest(ROOT, read_json(args.config))
        with args.output.open("x") as output:
            output.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"status": "PASS", "scope": SCOPE}))
    else:
        validate_manifest(ROOT, read_json(args.manifest), read_json(args.config),
                          os.environ if args.check_process_env else None)
        print(json.dumps({"status": "PASS", "scope": SCOPE}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        # Unexpected exceptions may include credential-bearing paths. Validation
        # errors are constructed locally and omit submitted values.
        message = str(error) if type(error) is ValueError else type(error).__name__
        print("Release preflight refused: " + message, file=sys.stderr)
        sys.exit(1)
