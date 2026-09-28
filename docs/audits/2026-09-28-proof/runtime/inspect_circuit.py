#!/usr/bin/env python3
"""Read only 72 bytes from the SP1 6.1.0 R1CS artifact for a live-array floor."""
import argparse
import json
import struct
from pathlib import Path


def inspect(path):
    file_bytes = path.stat().st_size
    with path.open("rb") as stream:
        outer = stream.read(32)
        sections = stream.read(32)
        if len(outer) != 32 or len(sections) != 32:
            raise ValueError("truncated R1CS headers")
        total, major, minor, patch = struct.unpack("<4Q", outer)
        levels, instructions, calldata, body = struct.unpack("<4Q", sections)
        if total + 32 != file_bytes:
            raise ValueError("outer serialized length differs from file length")
        calldata_offset = 64 + levels + instructions
        if calldata < 8 or calldata_offset + calldata + body > file_bytes:
            raise ValueError("invalid section lengths")
        stream.seek(calldata_offset)
        calldata_elements = struct.unpack("<Q", stream.read(8))[0]
    from inspect_pk import inspect as inspect_pk
    pk = inspect_pk(path.with_name("groth16_pk.bin"))
    calldata_bytes = calldata_elements * 4
    combined = pk["pk_array_payload_lower_bound_bytes"] + calldata_bytes
    return {
        "artifact": str(path),
        "file_bytes": file_bytes,
        "header_bytes_read": 72,
        "gnark_serialization_version": [major, minor, patch],
        "serialized_sections_bytes": {"levels": levels, "instructions": instructions,
                                      "calldata": calldata, "body": body},
        "calldata_u32_elements": calldata_elements,
        "calldata_retained_array_bytes": calldata_bytes,
        "pk_array_payload_lower_bound_bytes": pk["pk_array_payload_lower_bound_bytes"],
        "pk_plus_one_r1cs_array_lower_bound_bytes": combined,
        "pk_plus_one_r1cs_array_lower_bound_gib": combined / 2**30,
        "excluded_allocations": ["other R1CS fields including instructions, levels, debug metadata and coefficients",
                                 "Go/runtime/allocation overhead", "witness", "solver arrays",
                                 "MSM/FFT proving buffers", "retained Rust memory"],
        "sources": {
            "outer_header": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/constraint/bn254/marshal.go#L51-L85",
            "section_header": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/constraint/marshal.go#L139-L161",
            "calldata_allocation": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/constraint/marshal.go#L300-L312",
            "solver_extra_arrays": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/constraint/bn254/solver.go#L91-L118",
            "prover_extra_arrays": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/backend/groth16/bn254/prove.go#L119-L153"
        },
        "native_feasibility": {
            "released_feature_exists": True,
            "cargo_feature": "sp1-sdk/native-gnark",
            "build_mechanism": "The published SP1 6.1.0 feature selects native FFI instead of Docker and builds Go code as a c-archive with CGO_ENABLED=1. The build script explicitly links macOS CoreFoundation/Security; Go 1.24 supports darwin/arm64 c-archive.",
            "prerequisites": ["Go compatible with go.mod (go 1.24.0 minimum directive)", "C compiler and libclang for bindgen"],
            "built_or_run_in_this_diagnosis": False,
            "memory_result": "Native compilation is a source-supported pathway, but PK plus only CallData already exceeds the current 8 GiB supervisor ceiling. No verified safe peak-memory estimate or successful 16 GiB native run is claimed. The current 5 GiB Docker configuration demonstrably OOM-killed the ordinary proof. No retry was made.",
            "gomemlimit": "Soft Go runtime limit only; it excludes Rust/C allocations and cannot make live arrays fit a lower bound.",
            "sources": {
                "sdk_feature": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/sdk/Cargo.toml",
                "ffi_selection": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/src/ffi/mod.rs",
                "native_build_macos": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/build.rs#L54-L106",
                "go_version": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/go/go.mod",
                "darwin_arm64_c_archive": "https://github.com/golang/go/blob/go1.24.0/src/cmd/go/internal/work/init.go#L184-L203",
                "go_supported_build_mode": "https://github.com/golang/go/blob/go1.24.0/src/internal/platform/supported.go#L123-L158",
                "go_soft_memory_limit": "https://pkg.go.dev/runtime#hdr-Environment_Variables",
                "official_general_ram_guidance": "https://github.com/succinctlabs/sp1-project-template#generate-an-evm-compatible-proof"
            }
        },
        "finding_scope": "Insufficient capacity under the presently allocated environment. This is not a proof that all 16 GiB Mac configurations are impossible."
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path,
                        default=Path("/tmp/arcora-proof-runtime-20260928/circuits/groth16/v6.1.0/groth16_circuit.bin"))
    print(json.dumps(inspect(parser.parse_args().path), indent=2))
