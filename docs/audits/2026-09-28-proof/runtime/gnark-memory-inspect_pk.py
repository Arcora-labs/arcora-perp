#!/usr/bin/env python3
"""Inspect SP1 6.1.0's published BN254 raw PK headers without loading it.

Read-only: seeks over payloads, reads 85 bytes for the current zero-commitment
artifact, and validates that the pinned ReadDump layout ends exactly at EOF.
This is a payload allocation lower bound, not a process peak-RSS estimate.
"""
import argparse
import json
import struct
from pathlib import Path


def inspect(path):
    file_bytes = path.stat().st_size
    header_bytes_read = 0
    with path.open("rb") as stream:
        def read(length):
            nonlocal header_bytes_read
            data = stream.read(length)
            if len(data) != length:
                raise ValueError("truncated header")
            header_bytes_read += length
            return data

        def skip(length):
            if length < 0 or stream.tell() + length > file_bytes:
                raise ValueError("payload length exceeds file bounds")
            stream.seek(length, 1)

        marker = read(8)
        if marker != bytes.fromhex("efbeadde00000000"):
            raise ValueError("expected 64-bit little-endian dump marker")
        cardinality = struct.unpack(">Q", read(8))[0]
        if not cardinality or cardinality & (cardinality - 1):
            raise ValueError("FFT cardinality must be a power of two")
        skip(5 * 32)  # five BN254 scalar-field elements in Domain.WriteTo
        precompute_byte = read(1)[0]
        if precompute_byte not in (0, 1):
            raise ValueError("invalid domain precompute flag")
        skip(3 * 64 + 2 * 128)  # three G1 and two G2 fixed uncompressed points
        wires, infinity_a, infinity_b = struct.unpack(">QQQ", read(24))
        skip(wires * 2)  # InfinityA and InfinityB bool arrays
        commitments = struct.unpack(">I", read(4))[0]
        vector_specs = [("G1.A", 64), ("G1.B", 64), ("G1.Z", 64),
                        ("G1.K", 64), ("G2.B", 128)]
        vector_specs += [(f"Commitment{i}.{name}", 64)
                         for i in range(commitments)
                         for name in ("Basis", "BasisExpSigma")]
        vectors = []
        for name, item_bytes in vector_specs:
            count = struct.unpack("<Q", read(8))[0]
            payload_bytes = count * item_bytes
            vectors.append({"name": name, "elements": count,
                            "element_bytes": item_bytes, "bytes": payload_bytes})
            skip(payload_bytes)
        if stream.tell() != file_bytes:
            raise ValueError("pinned ReadDump layout does not end at EOF")

    stages = cardinality.bit_length() - 1
    # Domain.preComputeTwiddles retains 2 N-element coset tables and two
    # independent arrays of stage vectors, each sum(N/2^i+1) = N-1+stages.
    fft_bytes = (2 * cardinality + 2 * (cardinality - 1 + stages)) * 32 \
        if precompute_byte else 0
    raw_bytes = sum(vector["bytes"] for vector in vectors)
    bool_bytes = wires * 2
    lower_bound = raw_bytes + bool_bytes + fft_bytes
    return {
        "artifact": str(path),
        "file_bytes": file_bytes,
        "header_bytes_read": header_bytes_read,
        "layout_ends_at_eof": True,
        "marker": marker.hex(),
        "domain_cardinality": cardinality,
        "domain_with_precompute": bool(precompute_byte),
        "wires": wires,
        "infinity_a": infinity_a,
        "infinity_b": infinity_b,
        "commitments": commitments,
        "vectors": vectors,
        "raw_vectors_bytes": raw_bytes,
        "bool_arrays_bytes": bool_bytes,
        "fft_field_arrays_bytes": fft_bytes,
        "pk_array_payload_lower_bound_bytes": lower_bound,
        "pk_array_payload_lower_bound_gib": lower_bound / 2 ** 30,
        "docker_cap_bytes": 5 * 2 ** 30,
        "raw_vectors_alone_exceed_docker_cap": raw_bytes > 5 * 2 ** 30,
        "excluded_allocations": ["R1CS live object", "Go/runtime/allocation overhead",
                                 "witness", "proof working buffers", "Rust native prover"],
        "finding": "The current 5 GiB gnark container limit is insufficient. "
                   "This does not establish that every 16 GiB Mac configuration is infeasible.",
        "sources": {
            "sp1_release_dependency_pins": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/go/go.mod",
            "sp1_retains_r1cs_and_pk": "https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/go/sp1/prove_groth16.go#L19-L96",
            "gnark_pk_read_dump": "https://github.com/p4u/gnark/blob/cd7874155e266e08ca8dc247dbc66efb1030bd3b/backend/groth16/bn254/marshal.go#L422-L504",
            "gnark_crypto_whole_slice_allocation": "https://github.com/Consensys/gnark-crypto/blob/022ec58e8c19be75662dd2f4f24b2488ec00fbbc/utils/unsafe/dump_slice.go#L32-L70",
            "gnark_crypto_domain_precompute": "https://github.com/Consensys/gnark-crypto/blob/022ec58e8c19be75662dd2f4f24b2488ec00fbbc/ecc/bn254/fr/fft/domain.go#L224-L273",
            "gnark_crypto_domain_read_from": "https://github.com/Consensys/gnark-crypto/blob/022ec58e8c19be75662dd2f4f24b2488ec00fbbc/ecc/bn254/fr/fft/domain.go#L355-L391"
        }
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path,
                        default=Path("/tmp/arcora-proof-runtime-20260928/circuits/groth16/v6.1.0/groth16_pk.bin"))
    print(json.dumps(inspect(parser.parse_args().path), indent=2))
