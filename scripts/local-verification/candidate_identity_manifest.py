#!/usr/bin/env python3
"""Offline identity binding for the unapproved Chainlink candidate only.

No RPC, environment inspection, discovery, setup, proof, deployment or route
activation. Integrity relies on a trusted builder and inputs, not a signature.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import release_manifest as legacy
import run_chainlink_replay as candidate

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "arcora-chainlink-candidate-offline/v1"
FIXTURE = "contracts/integration/fixtures/chainlink-candidate-v1"
BUILDER = "scripts/local-verification/candidate_identity_manifest.py"
# Existing test-only files at merged base f9a0f2f59ffae651163fc10a43a995054a07ebcc.
# They are separate from the unchanged nine candidate runtime source pins.
AUXILIARY_TEST_SOURCES = {
    "crates/chainlink-oracle/src/tests.rs": "42396d0053fc92062acb33f67ecd253c590a09a18bb23cda72566e5092b9702f",
    "crates/chainlink-oracle/src/replay_vectors.rs": "512a4966a886231ceb94fd034f94135b98b4ee4dfc3e894e45912da93ca1b54c",
}
MAX_JSON = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_SOURCE_FILES = 8192
CONTRACTS = {**legacy.CONTRACTS,
    "oracle_wrapper": ("out/ChainlinkOracleVerifier.sol/ChainlinkOracleVerifier.json",
                       "ChainlinkOracleVerifier", "0.8.24+commit.e11b9ed9")}
ADDRESS_ROLES = set(CONTRACTS) | {"token", "verifier_proxy", "uptime_feed"}
SCOPE = {
    "local_identity_checked": True,
    "target_chain_observed": False,
    "runtime_bytecode_verified": False,
    "running_services_attested": False,
    "fresh_guest_build_performed": False,
    "fresh_setup_key_derived": False,
    "proof_generated": False,
    "real_don_verified": False,
    "custody_accepted": False,
    "operator_policy_approved": False,
    "candidate_submission_enabled": False,
    "release_gate": "HOLD",
}


def require(ok, label):
    if not ok:
        raise ValueError(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode_json(data):
    try:
        source = data.decode("utf-8") if isinstance(data, bytes) else data
    except UnicodeDecodeError as error:
        raise ValueError("invalid JSON encoding") from error
    require(isinstance(source, str), "JSON text required")
    depth, quoted, escaped = 0, False, False
    for character in source:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds bound")
        elif character in "]}":
            depth -= 1
            require(depth >= 0, "invalid JSON nesting")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    def nonfinite(_value):
        raise ValueError("non-finite JSON number")
    try:
        return json.loads(source, object_pairs_hook=unique, parse_constant=nonfinite)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError("invalid or excessively nested JSON") from error


def read_json(path, limit=MAX_JSON):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "regular JSON input required")
    require(path.stat().st_size <= limit, "JSON input exceeds bound")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "JSON input exceeds bound")
    return decode_json(data)


def exact(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields),
            label + ": unexpected or missing fields")


def hex_value(value, size, label):
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (size * 2), value),
            "invalid " + label)
    return value.lower()


def integer(value, low, high, label):
    require(type(value) is int and low <= value < high, "invalid " + label)
    return value


def public_config(value):
    exact(value, {"chain_id", "network", "addresses", "expected_runtime_code_hashes",
                  "program_vkey", "clock", "oracle_policy_hash", "sequencer_grace_seconds"},
          "candidate public config")
    chain = integer(value["chain_id"], 1, 2**64, "chain_id")
    network = integer(value["network"], 0, 2, "network")
    require((chain, network) in {(84532, 0), (8453, 1)}, "unsupported chain/network declaration")
    exact(value["addresses"], ADDRESS_ROLES, "addresses")
    addresses = {role: hex_value(value["addresses"][role], 20, role) for role in sorted(ADDRESS_ROLES)}
    require(all(int(v, 16) != 0 for v in addresses.values()), "zero address declaration")
    require(len(set(addresses.values())) == len(addresses), "contract roles must be distinct")
    exact(value["expected_runtime_code_hashes"], ADDRESS_ROLES, "runtime declarations")
    runtime = {role: hex_value(value["expected_runtime_code_hashes"][role], 32,
                              "runtime code hash") for role in sorted(ADDRESS_ROLES)}
    require(all(int(v, 16) != 0 for v in runtime.values()), "zero runtime hash declaration")
    key = hex_value(value["program_vkey"], 32, "candidate program_vkey")
    require(key == candidate.VKEY, "program_vkey does not match historical candidate identity")
    exact(value["clock"], {"max_window_ms", "clock_skew_ms"}, "clock declaration")
    clock = {"max_window_ms": integer(value["clock"]["max_window_ms"], 1, 2**64, "max_window_ms"),
             "clock_skew_ms": integer(value["clock"]["clock_skew_ms"], 0, 2**64, "clock_skew_ms")}
    policy = hex_value(value["oracle_policy_hash"], 32, "oracle policy hash")
    require(int(policy, 16) != 0, "zero policy hash declaration")
    grace = integer(value["sequencer_grace_seconds"], 1, 2**64, "uptime grace")
    return {"chain_id": chain, "network": network, "addresses": addresses,
            "expected_runtime_code_hashes": runtime, "program_vkey": key,
            "clock": clock, "oracle_policy_hash": policy, "sequencer_grace_seconds": grace}


def verify_pins(root):
    require(legacy.check_sp1_release.check(root)["passed"], "SP1 release/provenance guard failed")
    legacy.verify_reviewed_guest(root)
    for path, expected in candidate.CANDIDATE_SOURCES.items():
        require(legacy.identity(root, path)["sha256"] == expected,
                "candidate runtime source changed: " + path)
    for path, expected in AUXILIARY_TEST_SOURCES.items():
        require(legacy.identity(root, path)["sha256"] == expected,
                "candidate auxiliary test source changed: " + path)
    library = legacy.regular(root, "crates/chainlink-oracle/src/lib.rs").read_text()
    tests = legacy.regular(root, "crates/chainlink-oracle/src/tests.rs").read_text()
    require(re.search(r"#\[cfg\(test\)\]\s*mod tests;", library)
            and re.search(r'#\[path = "replay_vectors.rs"\]\s*mod replay_vectors;', tests),
            "candidate auxiliary modules must remain test-only")
    # Existing pins alone do not cover an added module or a build override.
    for directory in ("crates/chainlink-oracle/src", "crates/sp1-chainlink-guest/src"):
        actual = {p.relative_to(root).as_posix() for p in (root / directory).rglob("*")
                  if p.is_file() or p.is_symlink()}
        expected = {p for p in set(candidate.CANDIDATE_SOURCES) | set(AUXILIARY_TEST_SOURCES)
                    if p.startswith(directory + "/")}
        require(actual == expected, "candidate source layout changed")
    for directory in ("", "crates", "crates/chainlink-oracle", "crates/sp1-chainlink-guest"):
        for name in ("build.rs", ".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
            path = root / directory / name
            require(not path.exists() and not path.is_symlink(), "unreviewed candidate build input")
    return {"reviewed_v2_sources_sha256": dict(legacy.clock.EXPECTED_GUEST_SOURCES),
            "candidate_sources_sha256": dict(candidate.CANDIDATE_SOURCES),
            "candidate_auxiliary_test_sources_sha256": dict(AUXILIARY_TEST_SOURCES)}


def prohibited_public_path(name):
    return any(part.lower().startswith(".env") or re.search(
        r"(?:^|[._-])(?:secrets?|credentials?|private[-_]keys?)(?:[._-]|$)", part.lower())
        for part in Path(name).parts)


def source_inventory(root):
    prefixes = ("crates", "vendor", "contracts/src", "contracts/vendor", "scripts/local-verification")
    selected = {"Cargo.toml", "Cargo.lock", "contracts/foundry.toml"}
    for prefix in prefixes:
        for path in (root / prefix).rglob("*"):
            name = path.relative_to(root).as_posix()
            if prohibited_public_path(name):
                continue
            if any(part in {"target", "out", "node_modules", "__pycache__", ".git"} for part in path.parts):
                continue
            if path.is_symlink() or path.is_file() and path.suffix in {".rs", ".toml", ".lock", ".sol", ".py", ".json", ".sh"}:
                selected.add(name)
                require(len(selected) <= MAX_SOURCE_FILES, "source inventory exceeds bound")
    return {name: legacy.identity(root, name)["sha256"] for name in sorted(selected)}


def code_commit(root, value=None):
    if value is None:
        value = legacy.command(["git", "rev-parse", "HEAD"], root)
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40,64}", value), "invalid code_commit")
    result = subprocess.run(["git", "merge-base", "--is-ancestor", value, "HEAD"],
                            cwd=root, capture_output=True, timeout=60)
    require(result.returncode == 0, "code_commit is not an ancestor of current HEAD")
    return value


def source_keccak(root, data):
    return legacy.command(["cast", "keccak", "0x" + data.hex()], root).lower()


def compiled_contract(root, role):
    relative, name, compiler = CONTRACTS[role]
    path = "contracts/" + relative
    artifact_identity = legacy.identity(root, path)
    artifact = read_json(legacy.regular(root, path), 64 * 1024 * 1024)
    metadata = artifact["metadata"]
    if isinstance(metadata, str):
        metadata = decode_json(metadata)
    require(metadata["compiler"]["version"] == compiler, "wrong Solidity compiler: " + role)
    settings = metadata["settings"]
    require(list(settings["compilationTarget"].values()) == [name], "wrong compilation target: " + role)
    require(canonical(settings["optimizer"]) == canonical({"enabled": True, "runs": 200}),
            "wrong optimizer profile: " + role)
    compiler_root = root / ("contracts/vendor/sp1-contracts" if role in {"sp1_gateway", "sp1_verifier"} else "contracts")
    sources = metadata["sources"]
    require(isinstance(sources, dict) and sources, "missing compiler source bindings")
    for source, expected in sources.items():
        require(isinstance(source, str) and not prohibited_public_path(source),
                "nonpublic compiler source path")
        require(isinstance(expected, dict) and "keccak256" in expected
                and set(expected) <= {"keccak256", "license", "urls"}, "invalid compiler source binding")
        data = legacy.regular(compiler_root, source).read_bytes()
        require(source_keccak(root, data) == hex_value(expected["keccak256"], 32, "compiler source hash"),
                "stale compiled source: " + role)
    require(legacy.identity(root, path) == artifact_identity, "compiler artifact changed while reading")
    result = {**artifact_identity, "compiler": compiler}
    for field, label in (("bytecode", "creation_bytecode_sha256"), ("deployedBytecode", "runtime_template_sha256")):
        bytecode = artifact[field]["object"]
        require(isinstance(bytecode, str) and re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})+", bytecode),
                "empty or unlinked compiler bytecode")
        require(not artifact[field].get("linkReferences"), "external library links require separate binding")
        result[label] = digest(bytes.fromhex(bytecode.removeprefix("0x")))
    result["runtime_note"] = "Compiler template, not observed deployed runtime."
    return result


def build_manifest(root, config, commit=None):
    root = Path(root)
    config = public_config(config)
    commit = code_commit(root, commit)
    pins = verify_pins(root)
    sources = source_inventory(root)
    elf = legacy.identity(root, FIXTURE + "/guest.elf")
    require(legacy.regular(root, elf["path"]).read_bytes().startswith(b"\x7fELF"), "actual candidate ELF required")
    require(elf["sha256"] == candidate.ELF_SHA, "wrong candidate ELF")
    metadata_path = FIXTURE + "/metadata.json"
    metadata_identity = legacy.identity(root, metadata_path)
    metadata = read_json(legacy.regular(root, metadata_path))
    exact(metadata, {"kind", "sdk_version", "elf_sha256", "elf_bytes", "measured_program_vkey",
                     "candidate_runtime_sources_sha256", "same_machine_rebuild_byte_equal",
                     "independent_build", "proof_generated", "real_don_verified",
                     "production_approved", "evidence"}, "candidate metadata")
    require(metadata["kind"] == "unapproved-chainlink-candidate-elf"
            and metadata["sdk_version"] == "6.1.0"
            and metadata["elf_sha256"] == candidate.ELF_SHA
            and type(metadata["elf_bytes"]) is int and metadata["elf_bytes"] == elf["size_bytes"]
            and metadata["measured_program_vkey"] == candidate.VKEY
            and canonical(metadata["candidate_runtime_sources_sha256"]) == canonical(candidate.CANDIDATE_SOURCES),
            "candidate metadata identity mismatch")
    for field in ("independent_build", "proof_generated", "real_don_verified", "production_approved"):
        require(metadata[field] is False, "unsupported candidate metadata claim")
    require(metadata["same_machine_rebuild_byte_equal"] is True
            and metadata["evidence"] == "docs/audits/2026-10-10-chainlink-guest-replay/",
            "historical candidate provenance mismatch")
    artifacts = {role: compiled_contract(root, role) for role in sorted(CONTRACTS)}
    require(source_inventory(root) == sources, "source changed while creating candidate identity")
    for identity in [elf, metadata_identity, *artifacts.values()]:
        require(legacy.identity(root, identity["path"]) ==
                {key: identity[key] for key in ("path", "sha256", "size_bytes")},
                "artifact changed while creating candidate identity")
    manifest = {"schema": SCHEMA, "source": {"code_commit": commit,
            "commit_note": "Informational ancestor; current covered fingerprints determine local identity.",
            "files_sha256": sources, "inventory_sha256": digest(canonical(sources)),
            "builder": legacy.identity(root, BUILDER)}, "pins": pins,
            "program": {"elf": elf, "metadata": metadata_identity,
                "program_vkey": candidate.VKEY, "sp1_version": "6.1.0", "witness_wire": "DPCLK3",
                "inner_clock_proof_version": 2,
                "key_provenance": "Historical measured candidate key; no fresh setup performed."},
            "compiled_contracts": artifacts, "public_config": config,
            "public_config_sha256": digest(canonical(config)),
            "configuration_note": "Addresses, runtime hashes, policy and uptime grace are declarations, not observations or approvals.",
            "scope": dict(SCOPE)}
    require(len(canonical(manifest)) <= MAX_JSON, "candidate manifest exceeds bound")
    return manifest


def validate_manifest(root, manifest, config):
    require(isinstance(manifest, dict) and manifest.get("schema") == SCHEMA, "unsupported candidate identity schema")
    require(isinstance(manifest.get("source"), dict), "missing source identity")
    expected = build_manifest(root, config, manifest["source"].get("code_commit"))
    require(canonical(manifest) == canonical(expected), "candidate identity manifest mismatch")
    return expected


def create_output(path, value):
    # Public-only output. Exclusive creation never replaces an old manifest.
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def main():
    class PublicParser(argparse.ArgumentParser):
        def error(self, _message):
            # Do not echo forbidden arguments or a caller-supplied endpoint.
            self.exit(2, "Invalid candidate identity arguments.\n")
    parser = PublicParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--config", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--code-commit")
    validate = sub.add_parser("validate")
    validate.add_argument("--config", required=True)
    validate.add_argument("--manifest", required=True)
    args = parser.parse_args()
    try:
        config = read_json(args.config)
        if args.command == "create":
            create_output(args.output, build_manifest(ROOT, config, args.code_commit))
        else:
            validate_manifest(ROOT, read_json(args.manifest), config)
        print(json.dumps({"status": "LOCAL_IDENTITY_MATCH", "release_gate": "HOLD",
                          "schema": SCHEMA, "target_observed": False}))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        # Inputs may contain prohibited secret fields. Never echo their values,
        # caller paths, tool stderr, credentials or endpoint strings.
        print("Candidate offline identity validation failed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
