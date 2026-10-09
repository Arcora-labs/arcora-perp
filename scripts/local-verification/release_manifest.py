#!/usr/bin/env python3
"""Bind the reviewed clock guest, local contract artifacts and public service config.

This offline preflight does not deploy, query a chain, build an ELF, verify a new
proof, or attest a running prover. Manifest integrity is relative to a trusted
copy of this script and release manifest; it is not a signature/authenticity check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

if sys.version_info < (3, 11):
    sys.exit("Release preflight requires Python 3.11+ (tomllib).")

import check_sp1_release
import verify_clock_proof as clock

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


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


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


def public_config(value):
    exact_keys(value, {"chain_id", "addresses", "program_vkey", "clock", "gateway", "prover"}, "public config")
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
    return {"chain_id": value["chain_id"], "addresses": addresses, "program_vkey": key,
            "clock": dict(value["clock"]), "gateway": gateway,
            "prover": {"program_vkey": prover_key, "guest_elf_sha256": clock.EXPECTED_ELF}}


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
    args = parser.parse_args()
    if args.command == "check-deployment":
        check_deployment_config(read_json(args.deployment))
        print(json.dumps({"status": "PASS", "scope": "recorded key and address shape only; no RPC or runtime verification"}))
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
