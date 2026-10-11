#!/usr/bin/env python3
"""No-FFI synthetic bridge fixture pipeline (requires Python pycryptodome).

source SOURCE_JSON FIXTURE_DIR
context FORGE_JSON OUTPUT_JSON
vector BRIDGE_JSON FIXTURE_DIR

Foundry captures each case in its own fresh test. This decoder accepts exactly
two successful capture tests and their static32-word log_named_bytes values.
The source and vector encoders independently check native/Solidity hash domains.
This is local fixture tooling, not RPC identity or DON/SP1 proof authentication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from Crypto.Hash import keccak

NAMES = ("normal-lifecycle", "liquidation")
ROOTS = ("prev_state_root", "manifest_hash", "new_state_root", "ordered_root",
         "withdrawals_root", "rejected_root", "deposits_root")
# Solidity Context ABI order, width and exact Rust JSON field names.
CONTEXT = (
    ("chain_id", 64), ("network", 8), ("clock_verifier", 160), ("settlement", 160),
    ("oracle_wrapper", 160), ("verifier_proxy", 160), ("sp1_adapter", 160),
    ("sp1_gateway", 160), ("uptime_feed", 160), ("prefix_vault", 160),
    ("clock_verifier_code_hash", 256), ("settlement_code_hash", 256),
    ("oracle_wrapper_code_hash", 256), ("verifier_proxy_code_hash", 256),
    ("sp1_adapter_code_hash", 256), ("sp1_gateway_code_hash", 256),
    ("uptime_feed_code_hash", 256), ("prefix_vault_code_hash", 256),
    ("anchored_at_ms", 64), ("max_window_ms", 64), ("clock_skew_ms", 64),
    ("uptime_round_id", 80), ("uptime_started_at", 64), ("grace_seconds", 64),
    ("registered_receipt", 256), ("clock_commitment", 256),
    ("source_witness_sha256", 256), ("base_commitment", 256), ("policy_hash", 256),
    ("post_consumed_deposit_count", 64), ("post_consumed_deposit_tip", 256),
    ("program_vkey", 256),
)


def check(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(path, maximum=8 * 1024 * 1024):
    path = Path(path)
    check(path.is_file() and not path.is_symlink(), "regular input file required")
    before = path.stat()
    check(0 < before.st_size <= maximum, "bounded JSON input")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        check((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "input changed before open")
        raw = stream.read(maximum + 1)
    check(len(raw) == before.st_size and len(raw) <= maximum, "bounded stable JSON read")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            check(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique), raw


def hexbytes(value, size=None):
    check(isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-f]{2})*", value), "canonical hex")
    data = bytes.fromhex(value[2:])
    check(size is None or len(data) == size, "hex width")
    return data


def integer(value, width=64):
    check(type(value) is int and 0 <= value < 2 ** width, "unsigned integer width")
    return value


def word(value):
    return integer(value, 256).to_bytes(32, "big")


def h(data):
    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def report_body(full):
    check(224 <= len(full) <= 4096 and len(full) % 32 == 0, "bounded full report")
    at = int.from_bytes(full[96:128], "big")
    check(at % 32 == 0 and at + 32 <= len(full), "body offset")
    size = int.from_bytes(full[at:at + 32], "big")
    check(size == 288 and at + 32 + size <= len(full), "v3 body width")
    return full[at + 32:at + 32 + size]


def dynamic(data):
    return word(len(data)) + data + bytes((-len(data)) % 32)


def encoded_entries(entries):
    check(type(entries) is list and 0 < len(entries) <= 128, "bounded priced entries")
    tuples = []
    for entry in entries:
        base = hexbytes(entry["base_full_report"])
        quote = hexbytes(entry["quote_full_report"])
        report_body(base)
        report_body(quote)
        b = dynamic(base)
        q = dynamic(quote)
        tuples.append(word(integer(entry["market_id"])) + word(integer(entry["now_ms"]))
                      + word(128) + word(128 + len(b)) + b + q)
    offset = len(tuples) * 32
    heads = []
    for item in tuples:
        heads.append(word(offset))
        offset += len(item)
    return word(32) + word(len(tuples)) + b"".join(heads) + b"".join(tuples)


def body_evidence(policy, entries):
    value = h(h(b"arcora:chainlink-evidence:v1") + policy + word(len(entries)))
    for e in entries:
        value = h(value + word(integer(e["market_id"])) + word(integer(e["now_ms"]))
                  + h(report_body(hexbytes(e["base_full_report"])))
                  + h(report_body(hexbytes(e["quote_full_report"]))))
    return value


def cases(document):
    check(type(document["cases"]) is list and len(document["cases"]) == 2, "exact two cases")
    check(sorted(c["name"] for c in document["cases"]) == sorted(NAMES), "exact case names")
    check(document["synthetic"] is True and document["real_don_verified"] is False
          and document["proof_generated"] is False and document["candidate_submission"] == "HOLD",
          "synthetic HOLD scope")
    return [next(c for c in document["cases"] if c["name"] == name) for name in NAMES]


def verify_case(case):
    roots = [hexbytes(case["roots"][name], 32) for name in ROOTS]
    check(case["batch_id"] == 0 and case["phase"] == 0, "normal settlement context")
    check(case["post_consumed_deposit_count"] == 9 and roots[6] != bytes(32)
          and roots[6] == hexbytes(case["post_consumed_deposit_tip"], 32), "native synthetic prefix")
    check(h(b"\x07" + b"".join(roots)) == hexbytes(case["base_commitment"], 32), "seven roots base")
    entries = encoded_entries(case["entries"])
    clock = case.get("clock", case)
    check(len(case["entries"]) == clock["timed_ops"]
          and case["entries"][0]["now_ms"] == clock["first_ms"]
          and case["entries"][-1]["now_ms"] == clock["last_ms"], "entry clock endpoints/count")
    check(all(a["now_ms"] <= b["now_ms"] for a, b in zip(case["entries"], case["entries"][1:])), "ordered times")
    check(entries == hexbytes(case["entries_abi"]), "independent Entry[] ABI bytes")
    check(h(entries) == hexbytes(case["input_hash"], 32), "full container input hash")
    check(body_evidence(hexbytes(case["policy_hash"], 32), case["entries"])
          == hexbytes(case["evidence_hash"], 32), "ordered body evidence hash")
    return roots


def write(path, data):
    path = Path(path)
    check(path.parent.is_dir(), "existing output directory required")
    if path.exists():
        check(path.is_file() and not path.is_symlink(), "regular owned output required")
        if path.read_bytes() != data:
            check(args.replace_owned, "refuse different existing output without --replace-owned")
            path.write_bytes(data)
    else:
        with path.open("xb") as output:
            output.write(data)


def source(input_path, output_dir):
    document, raw = load(input_path)
    check(document["schema"] == "arcora-native-contract-bridge-source-v1", "source schema")
    text = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.24;", "",
            'import {ChainlinkNativeContractBridgeTypes as T} from "./ChainlinkNativeContractBridgeTypes.sol";',
            "", "/// Generated from preserved PUBLIC synthetic source; original full containers.",
            "/// This seed is not an old archive admission/receipt reconstruction.",
            "library ChainlinkNativeContractBridgeSource {",
            f"    // Exact source.json SHA256: {hashlib.sha256(raw).hexdigest()}"]
    mapping = {"sourceWitnessSha256": "source_witness_sha256", "depositCount": "post_consumed_deposit_count",
               "batchId": "batch_id", "phase": "phase", "baseCommitment": "base_commitment",
               "policyHash": "policy_hash", "evidenceHash": "evidence_hash", "inputHash": "input_hash",
               "firstMs": "first_ms", "lastMs": "last_ms", "timedOps": "timed_ops",
               "maxWindowMs": "max_window_ms", "clockSkewMs": "clock_skew_ms"}
    for case in cases(document):
        verify_case(case)
        func = "normal" if case["name"] == "normal-lifecycle" else "liquidation"
        text.append(f"    function {func}() internal pure returns (T.SourceData memory d) {{")
        for field, key in mapping.items():
            value = case[key]
            if isinstance(value, str):
                hexbytes(value, 32)
            else:
                integer(value, 8 if key == "phase" else 64)
            text.append(f"        d.{field} = {value};")
        for i, name in enumerate(ROOTS):
            text.append(f"        d.roots[{i}] = {case['roots'][name]};")
        text.append(f"        d.entriesAbi = hex\"{case['entries_abi'][2:]}\";")
        text.append("    }")
    text.append("}")
    write(Path(output_dir) / "ChainlinkNativeContractBridgeSource.sol", ("\n".join(text) + "\n").encode())
    write(Path(output_dir) / "chainlink-native-contract-bridge-source.json", raw)
    print(json.dumps({"source_sha256": hashlib.sha256(raw).hexdigest(), "independent_abi_hashes": "PASS", "cases": 2}))


def context(input_path, output_path):
    document, _ = load(input_path, 4 * 1024 * 1024)
    check(type(document) is dict, "Forge JSON object")
    suites = [v for k, v in document.items() if k.endswith(":ChainlinkNativeContractBridgeTest")]
    check(len(suites) == 1, "exact bridge test suite")
    results = suites[0]["test_results"]
    check(set(results) == {"test_capture_normal_context()", "test_capture_liquidation_context()"}, "only two capture tests")
    out = []
    for name, test in zip(NAMES, ("test_capture_normal_context()", "test_capture_liquidation_context()")):
        result = results[test]
        check(result["status"] == "Success", "successful actual capture")
        logs = result["decoded_logs"]
        matches = [line[len(name) + 2:] for line in logs if isinstance(line, str) and line.startswith(name + ": ")]
        check(len(matches) == 1, "one actual context log per case")
        encoded = hexbytes(matches[0], 32 * 32)
        values = [encoded[i:i + 32] for i in range(0, len(encoded), 32)]
        fields = {"name": name}
        for (key, width), data in zip(CONTEXT, values):
            value = int.from_bytes(data, "big")
            integer(value, width)
            fields[key] = "0x" + data[-width // 8:].hex() if width in (80, 160, 256) else value
        out.append(fields)
    raw = (json.dumps({"schema": "arcora-native-contract-bridge-context-v1", "cases": out}, indent=2) + "\n").encode()
    check(len(raw) <= 64 * 1024, "bounded context output")
    write(output_path, raw)
    print(json.dumps({"context_sha256": hashlib.sha256(raw).hexdigest(), "actual_contexts": 2, "abi_words_each": 32}))


def camel(name):
    head, *tail = name.split("_")
    return head + "".join(t.capitalize() for t in tail)


def vector(input_path, output_dir):
    document, raw = load(input_path)
    check(document["schema"] == "arcora-native-contract-bridge-v1", "derived schema")
    text = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.24;", "",
            'import {ChainlinkNativeContractBridgeTypes as T} from "./ChainlinkNativeContractBridgeTypes.sol";',
            "", "/// NEW target-bound PUBLIC synthetic native witness. Mock proof is opaque,",
            "/// not SP1 proof evidence. Runtime identity is checked by the EVM harness.",
            "library ChainlinkNativeContractBridgeVector {",
            f"    // Exact bridge.json SHA256: {hashlib.sha256(raw).hexdigest()}"]
    for case in cases(document):
        verify_case(case)
        c = case["target_context"]
        check(set(c) == {"name"} | {key for key, _ in CONTEXT} and c["name"] == case["name"], "exact target context")
        check(c["source_witness_sha256"] == case["source_witness_sha256"], "source witness identity")
        addr = lambda key: bytes(12) + hexbytes(c[key], 20)
        receipt = h(h(b"arcora:clock-bound-proof:v2") + word(c["chain_id"]) + addr("clock_verifier")
                    + addr("settlement") + word(case["batch_id"]) + hexbytes(case["roots"]["prev_state_root"], 32)
                    + hexbytes(case["base_commitment"], 32) + word(case["phase"])
                    + word(case["clock"]["first_ms"]) + word(case["clock"]["last_ms"])
                    + word(case["clock"]["timed_ops"]) + word(c["anchored_at_ms"])
                    + word(c["max_window_ms"]) + word(c["clock_skew_ms"]))
        cb = h(h(b"arcora:clock-bound-proof:v2") + hexbytes(case["base_commitment"], 32) + receipt)
        native = h(h(b"arcora:chainlink-bound-proof:v1") + cb + addr("oracle_wrapper") + addr("verifier_proxy")
                   + hexbytes(case["policy_hash"], 32) + hexbytes(case["evidence_hash"], 32))
        check(receipt == hexbytes(c["registered_receipt"], 32) == hexbytes(case["clock_receipt"], 32), "actual clock receipt")
        check(cb == hexbytes(c["clock_commitment"], 32) == hexbytes(case["clock_commitment"], 32), "clock domain")
        check(native == hexbytes(case["candidate_commitment"], 32), "native outer domain")
        func = "normal" if case["name"] == "normal-lifecycle" else "liquidation"
        text.append(f"    function {func}() internal pure returns (T.VectorData memory d) {{")
        text.append(f"        d.witnessSha256 = {case['witness_sha256']};")
        text.append(f"        d.nativeCommitment = {case['candidate_commitment']};")
        for key, width in CONTEXT:
            value = c[key]
            if width in (80, 160, 256):
                parsed = hexbytes(value, width // 8)
                # Solidity address literals use checksums when lexically 40hex;
                # address(bytes20(hex"..")) avoids accidental case normalization.
                value = f'address(bytes20(hex"{parsed.hex()}"))' if width == 160 else value
            else:
                integer(value, width)
            text.append(f"        d.context.{camel(key)} = {value};")
        text.append("    }")
    text.append("}")
    write(Path(output_dir) / "ChainlinkNativeContractBridgeVector.sol", ("\n".join(text) + "\n").encode())
    write(Path(output_dir) / "chainlink-native-contract-bridge.json", raw)
    print(json.dumps({"bridge_sha256": hashlib.sha256(raw).hexdigest(), "independent_native_domains": "PASS", "cases": 2}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("source", "context", "vector"))
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--replace-owned", action="store_true",
                        help="explicitly refresh these new generated fixture files after final builder freeze")
    args = parser.parse_args()
    globals()[args.mode](args.input, args.output)
