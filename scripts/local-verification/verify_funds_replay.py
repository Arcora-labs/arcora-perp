#!/usr/bin/env python3
"""Check replay-funds native input guards using only the synthetic test export.

Does not create a proof, execute a guest, submit transactions or contact a prover.
A successful positive control is mandatory before any rejection counts as passing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--witness-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = args.witness_dir.resolve(strict=True)
    output = args.output_dir
    output.mkdir()  # Exclusive new evidence directory; preserve prior evidence.
    manifest = json.loads((source / "lifecycle.json").read_text())
    if manifest.get("syntheticWitnesses") is not True:
        raise ValueError("only synthetic gateway test exports are accepted")

    def run(directory, name):
        command = [str(binary), str(directory), str(output / name), "--native-only"]
        if args.elf:
            command.extend(["--elf", str(args.elf.resolve(strict=True))])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=120, check=False,
        )
        (output / f"{name}.stdout.log").write_text(result.stdout)
        (output / f"{name}.stderr.log").write_text(result.stderr)
        return result

    positive = run(source, "native-positive")
    if positive.returncode != 0:
        raise RuntimeError("native positive control failed; no negative result is valid")
    positive_report = json.loads((output / "native-positive/manifest.json").read_text())
    assert positive_report["status"] == "PASS"
    assert positive_report["guest_executed"] is False
    assert positive_report["proof_generated"] is False
    assert len(positive_report["batches"]) == 4

    cases = [
        ("missing-window", "complete four-window lifecycle required"),
        ("reordered-window", "assertion `left == right` failed"),
        ("substituted-commitment", "assertion `left == right` failed"),
        ("changed-witness", "assertion `left == right` failed"),
        ("trailing-witness", "no trailing witness bytes"),
        ("legacy-witness", "clock-v2 input required"),
        ("symlink-witness", "regular input file required"),
    ]
    results = []
    for name, expected in cases:
        directory = output / f"input-{name}"
        directory.mkdir()
        for entry in source.iterdir():
            if entry.is_symlink() or not entry.is_file():
                raise ValueError("synthetic export may contain only regular files")
            shutil.copyfile(entry, directory / entry.name)
        data = json.loads((directory / "lifecycle.json").read_text())
        witness = directory / "batch-1.witness.bin"
        if name == "missing-window":
            data["batches"].pop()
        elif name == "reordered-window":
            data["batches"][1], data["batches"][2] = data["batches"][2], data["batches"][1]
        elif name == "substituted-commitment":
            data["batches"][1]["clock"]["commitment"] = "0x" + "00" * 32
        elif name == "changed-witness":
            changed = bytearray(witness.read_bytes())
            changed[-1] ^= 1
            witness.write_bytes(changed)
        elif name in ("trailing-witness", "legacy-witness"):
            raw = witness.read_bytes()
            witness.write_bytes(raw + b"\x00" if name == "trailing-witness" else raw[8:])
            # Keep metadata coherent so the actual wire decoder is reached.
            data["batches"][1]["clock"]["witnessSha256"] = "0x" + digest(witness)
            data["batches"][1]["clock"]["witnessBytes"] = witness.stat().st_size
        elif name == "symlink-witness":
            witness.unlink()
            witness.symlink_to(source / witness.name)
        (directory / "lifecycle.json").write_text(json.dumps(data))
        result = run(directory, name)
        assert result.returncode != 0, f"{name}: malformed export accepted"
        assert expected in result.stderr, f"{name}: infrastructure error is not rejection"
        assert not (output / name / "manifest.json").exists(), f"{name}: false success manifest"
        results.append({"case": name, "status": "PASS", "exit_code": result.returncode})
    report = {
        "status": "PASS", "kind": "synthetic-funds-replay-input-guards",
        "binary_sha256": digest(binary),
        "lifecycle_manifest_sha256": digest(source / "lifecycle.json"),
        "native_positive_control": True, "guest_executed": False,
        "proof_generated": False, "negative_controls": results,
    }
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
