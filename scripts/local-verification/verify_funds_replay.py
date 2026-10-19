#!/usr/bin/env python3
"""Check replay-funds native input guards using only the synthetic test export.

Does not create a proof, execute a guest, submit transactions or contact a prover.
A successful positive control is mandatory before any rejection counts as passing.

Each negative control rewrites one copy of the export and must be refused with
the message replay-funds prints for that refusal (CASES). A witness the strict
clock decoder refuses panics with `WITNESS_REFUSAL: <ProverError variant>`:
`UnboundWitness` for input without the `WIRE_MAGIC` framing, `WitnessDecode` for
a framed body that does not decode exactly. test_verify_funds_replay.py reads
those texts from the Rust sources, so a message changed in the binary fails that
test before this harness runs.

The committed export (LIFECYCLE_DIR) is pinned file by file. A --witness-dir
that names it is refused before any replay unless it holds exactly the pinned
files with the pinned SHA-256 digests. Other directories, such as a fresh export,
are not pinned.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
# The committed funds-lifecycle export: the four wallet windows replay-funds
# replays, the keepalive's empty window and their manifest. The gateway's funds
# lifecycle test wrote them on its injected clock; the directory's README.md
# records how. A re-export is a deliberate re-pin of these digests and of the
# README's SHA-256 list (test_verify_funds_replay.py compares the two).
LIFECYCLE_DIR = "contracts/integration/fixtures/clock-pkg3-reviewed/lifecycle"
LIFECYCLE_MANIFEST_SHA256 = "fa4c04ae1b08b17d7beb56696fc2876b558f5042644f2fb224382a6bf9b1b1f3"
LIFECYCLE_WITNESSES = {
    "batch-0.witness.bin": "8d0f6c540bfe0624ab08204e1c3aebe9e24dff2306d34a7e3d47010ddfff1cb7",
    "batch-1.witness.bin": "d5b0f13ae8925fe5975b2c67b324ab3869cbb0e94eb82c254d1dcf11226a2c98",
    "batch-2.witness.bin": "79161f155882a14e9db392f8e07c6b8e7e3f74cef000d9ca851b1695eb43767b",
    "batch-3.witness.bin": "97b3965c29aeeac57c8d28acadf968cc8dce871f35daa3b91a11bc5826115a57",
    "keepalive-batch-4.witness.bin": "5c78b6e48ecd8d57e2006afb8e75100ac6840d4880e70a7df7dd51594333379a",
}
# The only unpinned file the committed directory may hold.
LIFECYCLE_README = "README.md"

# `perp_core::clock::WIRE_MAGIC`, the framing of the one witness encoding.
WIRE_MAGIC = b"DPCLK4\0\0"
# The `.expect` text of replay-funds' strict witness decode.
WITNESS_REFUSAL = "exact clock-bound witness required"
# The panic text of a failed `assert_eq!` (Rust's standard library).
ASSERT_EQ_REFUSAL = "assertion `left == right` failed"
# (case, the stderr text that identifies its refusal). Witness cases rewrite
# batch-1.witness.bin through `witness_mutation`.
CASES = (
    ("missing-window", "complete four-window lifecycle required"),
    ("reordered-window", ASSERT_EQ_REFUSAL),
    ("substituted-commitment", ASSERT_EQ_REFUSAL),
    ("changed-witness", ASSERT_EQ_REFUSAL),
    ("trailing-witness", WITNESS_REFUSAL + ": WitnessDecode"),
    ("magic-only-witness", WITNESS_REFUSAL + ": WitnessDecode"),
    ("legacy-witness", WITNESS_REFUSAL + ": UnboundWitness"),
    ("dpclk2-witness", WITNESS_REFUSAL + ": UnboundWitness"),
    ("symlink-witness", "regular input file required"),
)
# Cases whose rewritten witness must reach the strict decoder: the export's
# metadata is updated to the rewritten bytes, so only the decoder can refuse it.
DECODER_CASES = ("trailing-witness", "magic-only-witness", "legacy-witness", "dpclk2-witness")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_committed_export(directory):
    """Refuse `directory` unless it holds exactly the pinned committed export."""
    pinned = dict(LIFECYCLE_WITNESSES, **{"lifecycle.json": LIFECYCLE_MANIFEST_SHA256})
    names = {entry.name for entry in directory.iterdir()}
    if names != set(pinned) | {LIFECYCLE_README}:
        raise ValueError("committed lifecycle export changed: files differ from the pins")
    for name, expected in sorted(pinned.items()):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("committed lifecycle export changed: not a regular file: " + name)
        if digest(path) != expected:
            raise ValueError("committed lifecycle export changed: " + name)
    readme = directory / LIFECYCLE_README
    if readme.is_symlink() or not readme.is_file():
        raise ValueError("committed lifecycle export changed: not a regular file: " + LIFECYCLE_README)


def witness_mutation(name, raw):
    """The rewritten bytes of a framed witness `raw` for decoder case `name`."""
    if not raw.startswith(WIRE_MAGIC):
        raise ValueError("the export's witness is not WIRE_MAGIC-framed")
    body = raw[len(WIRE_MAGIC):]
    if name == "trailing-witness":
        return raw + b"\x00"  # one byte after an exact body
    if name == "magic-only-witness":
        return WIRE_MAGIC  # framing with no body
    if name == "legacy-witness":
        return body  # the unframed body
    if name == "dpclk2-witness":
        return b"DPCLK2\0\0" + body  # an earlier framing
    raise ValueError("not a decoder case: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--witness-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = args.witness_dir.resolve(strict=True)
    if source == (ROOT / LIFECYCLE_DIR).resolve():
        check_committed_export(source)
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

    results = []
    for name, expected in CASES:
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
        elif name in DECODER_CASES:
            witness.write_bytes(witness_mutation(name, witness.read_bytes()))
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
