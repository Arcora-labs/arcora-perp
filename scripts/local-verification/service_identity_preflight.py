#!/usr/bin/env python3
"""Offline comparison of public service snapshots. Self-report match; HOLD only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

import candidate_identity_manifest as identity
import gateway_formats

SCHEMA = "arcora-public-service-preflight/v1"
EXPECTATIONS_SCHEMA = "arcora-public-service-expectations/v1"
SERVICE_SCHEMA = "arcora-public-service-identity/v1"
MAX_INPUT_BYTES = 64 * 1024
BUILD_FIELDS = {"schema", "algorithm", "source_files", "source_sha256"}
PROGRAM_FIELDS = {"elf_sha256", "elf_bytes", "program_vkey", "supported_witness_domains", "sdk_version"}
CAPABILITIES = {"candidate_submission_supported": False, "candidate_submission_enabled": False}
ENDPOINT_SCOPE = {"running_services_attested": False, "operator_policy_approved": False,
                  "proof_generated_by_identity_request": False, "release_gate": "HOLD"}
CLOCK_SOURCE = "crates/perp-core/src/clock.rs"


def witness_domains(root=None):
    """The one witness domain a prover may report: the reviewed clock framing magic.

    Parsed from perp-core's `WIRE_MAGIC` (NUL padding removed), so the expectation
    follows the guest's framing instead of a hand-copied list; any other domain,
    including the unframed tuple ("legacy") and earlier framings, is refused.
    """
    magic = gateway_formats.rust_magic(CLOCK_SOURCE, "WIRE_MAGIC", root)
    domain = magic.rstrip(b"\0")
    require(re.fullmatch(rb"[A-Z0-9]{4,8}", domain) is not None and b"\0" not in domain)
    return [domain.decode()]


def require(ok):
    if not ok:
        raise ValueError("public service declarations refused")


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def integer(value, low, high):
    require(type(value) is int and low <= value < high)


def boolean(value):
    require(type(value) is bool)


def checksum(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def hex_value(value, size, nonzero=False):
    require(type(value) is str and re.fullmatch(r"0x[0-9a-f]{%d}" % (2 * size), value) is not None)
    require(not nonzero or int(value, 16) != 0)


def same(left, right):
    require(identity.canonical(left) == identity.canonical(right))


def validate_build(value):
    exact(value, BUILD_FIELDS)
    require(value["schema"] == "arcora-service-build-identity/v1")
    require(value["algorithm"] == "sha256-canonical-source-map-v1")
    integer(value["source_files"], 1, 8193)
    checksum(value["source_sha256"])


def validate_program(value, service):
    if service == "gateway":
        require(value is None)
        return
    exact(value, PROGRAM_FIELDS)
    checksum(value["elf_sha256"])
    integer(value["elf_bytes"], 1, 64 * 1024 * 1024 + 1)
    hex_value(value["program_vkey"], 32, True)
    require(value["sdk_version"] == "6.1.0")
    same(value["supported_witness_domains"], witness_domains())


def validate_public_config(value, service):
    if service == "prover":
        exact(value, {"measurement", "dev_insecure", "admission"})
        hex_value(value["measurement"], 32)
        boolean(value["dev_insecure"])
        limits = value["admission"]
        exact(limits, {"max_concurrent", "body_bytes", "body_timeout_ms"})
        integer(limits["max_concurrent"], 1, 9)
        integer(limits["body_bytes"], 1, 512 * 1024 * 1024 + 1)
        integer(limits["body_timeout_ms"], 1000, 300001)
        require(limits["body_timeout_ms"] % 1000 == 0)
        return
    exact(value, {"chain_id", "vault", "gateway_signer", "l1", "prover_configured",
                  "clocked_prover_configured", "candidate_archive_required", "candidate_archive"})
    integer(value["chain_id"], 1, 2**64)
    hex_value(value["vault"], 20)
    hex_value(value["gateway_signer"], 20, True)
    for name in ("prover_configured", "clocked_prover_configured", "candidate_archive_required"):
        boolean(value[name])
    l1 = value["l1"]
    if l1 is not None:
        exact(l1, {"settlement", "vault", "token", "clock"})
        hex_value(l1["settlement"], 20, True)
        for name in ("vault", "token"):
            if l1[name] is not None:
                hex_value(l1[name], 20, True)
        if l1["clock"] is not None:
            exact(l1["clock"], {"chain_id", "verifier"})
            integer(l1["clock"]["chain_id"], 1, 2**64)
            hex_value(l1["clock"]["verifier"], 20, True)
    archive = value["candidate_archive"]
    if archive is not None:
        exact(archive, {"policy_binding", "oracle_policy_hash"})
        hex_value(archive["policy_binding"], 32)
        hex_value(archive["oracle_policy_hash"], 32)
    require(not value["candidate_archive_required"] or archive is not None)
    require(not value["clocked_prover_configured"] or
            value["prover_configured"] and l1 is not None and l1["clock"] is not None)


def validate_snapshot(value, service):
    exact(value, {"schema", "service", "evidence_kind", "build", "program", "public_config",
                  "public_config_sha256", "capabilities", "scope"})
    require(value["schema"] == SERVICE_SCHEMA and value["service"] == service)
    require(value["evidence_kind"] == "self_reported_unattested")
    validate_build(value["build"])
    validate_program(value["program"], service)
    validate_public_config(value["public_config"], service)
    checksum(value["public_config_sha256"])
    same(value["public_config_sha256"], hashlib.sha256(identity.canonical(value["public_config"])).hexdigest())
    same(value["capabilities"], CAPABILITIES)
    same(value["scope"], ENDPOINT_SCOPE)


def validate_expectations(value):
    exact(value, {"schema", "gateway", "prover"})
    require(value["schema"] == EXPECTATIONS_SCHEMA)
    for service in ("gateway", "prover"):
        expected = value[service]
        exact(expected, {"build", "public_config_sha256", "program"})
        validate_build(expected["build"])
        checksum(expected["public_config_sha256"])
        validate_program(expected["program"], service)


def result(status):
    return {"schema": SCHEMA, "status": status, "evidence_kind": "self_reported_unattested",
            "candidate_compatibility": {"status": "REFUSED", "compatible": False,
                "reason": "current services do not support candidate DPCLK3 submission"},
            "capabilities": dict(CAPABILITIES),
            "scope": {"running_services_attested": False, "operator_policy_approved": False,
                      "proof_generated_by_preflight": False, "release_gate": "HOLD"}}


def compare_snapshots(expectations, gateway, prover):
    """Compare supplied declarations; never bootstrap expectations from responses."""
    try:
        originals = (expectations, gateway, prover)
        encoded = tuple(identity.canonical(value) for value in originals)
        require(all(len(value) <= MAX_INPUT_BYTES for value in encoded))
        expected, *snapshots = [identity.decode_json(value) for value in encoded]
        validate_expectations(expected)
        for service, snapshot in zip(("gateway", "prover"), snapshots):
            validate_snapshot(snapshot, service)
            for field in ("build", "public_config_sha256", "program"):
                same(snapshot[field], expected[service][field])
        require(tuple(identity.canonical(value) for value in originals) == encoded)
        matched = result("DECLARATIONS_MATCH")
        matched["input_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in
                                   zip(("expectations", "gateway", "prover"), encoded)}
        return matched
    except Exception:
        return result("BLOCKED")


def public_path(path):
    path = Path(path)
    require(not identity.prohibited_public_path(str(path)))
    require(not any(item.is_symlink() for item in (path, *path.parents)))
    return path


def file_cut(path):
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_INPUT_BYTES)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load_input(path):
    path = public_path(path)
    before = file_cut(path)
    value = identity.read_json(path, MAX_INPUT_BYTES)
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    require(len(raw) <= MAX_INPUT_BYTES and file_cut(path) == before)
    same(value, identity.decode_json(raw))
    return value, (path, before, raw)


def run_files(expectations, gateway, prover, output):
    output = public_path(output)
    require(not output.exists())
    loaded = [load_input(path) for path in (expectations, gateway, prover)]
    compared = compare_snapshots(*(value for value, _cut in loaded))
    for _value, (path, cut, raw) in loaded:
        try:
            _fresh_value, (_path, fresh_cut, fresh_raw) = load_input(path)
            require(fresh_cut == cut and fresh_raw == raw)
        except Exception:
            compared = result("BLOCKED")
    identity.create_output(output, compared)
    return compared


def main():
    class PublicParser(argparse.ArgumentParser):
        def error(self, _message):
            self.exit(2, "Invalid public service preflight arguments.\n")
    parser = PublicParser(description=__doc__)
    for field in ("expectations", "gateway", "prover", "output"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    try:
        compared = run_files(args.expectations, args.gateway, args.prover, args.output)
    except Exception:
        compared = result("BLOCKED")
    print(json.dumps(compared, sort_keys=True))
    return 0 if compared["status"] == "DECLARATIONS_MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
