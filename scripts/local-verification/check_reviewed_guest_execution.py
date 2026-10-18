#!/usr/bin/env python3
"""Execute the reviewed guest on CPU and compare every output with its pins.

The program is REVIEWED_GUEST's committed ELF (`identity_dir/guest.elf`), never a
build-script output. In order:

1. the checkout's guest inputs are REVIEWED_GUEST's (source pins, source layout,
   no build overrides; `release_manifest.verify_reviewed_guest`);
2. `identity_dir` holds that ELF, its setup key and the normal fixture witness;
3. `vkey --elf ELF` derives REVIEWED_GUEST["vkey"] from the ELF on CPU;
4. `clock-proof --elf ELF --no-prove DIR` executes the normal fixture, every case
   witness and every negative on the execute-only client. Its record,
   DIR/execution.json, must equal REVIEWED_FIXTURE:
   - `witness_sha256` and `commitment` of the normal fixture, with
     `native_guest_equal` true, positive `cycles`, and no proof or setup;
   - `cases`: one entry per REVIEWED_FIXTURE["cases"] name, each
     {name, witness_sha256, commitment, guest_exit 0, native_guest_equal true,
     cycles > 0}; the list may be absent only while no case is pinned;
   - `negatives`: one entry per REVIEWED_FIXTURE["negatives"] name, each
     {name, witness_sha256, guest_exit 1, public_bytes 0}.

No proof is generated. Evidence is written to --output-dir/verification.json.
A mismatch refuses with the first differing field; it never updates a pin.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import release_manifest as release
import verify_clock_proof as clock

ROOT = release.ROOT
MAX_ELF_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}")
WORD = re.compile(r"0x[0-9a-f]{64}")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_regular(path, limit):
    require(path.is_file() and not path.is_symlink(), "missing or nonregular file: " + path.name)
    require(path.stat().st_size <= limit, "oversized file: " + path.name)
    return path.read_bytes()


def reviewed_identity(root):
    """The reviewed ELF bytes, after checking the tree, the ELF, its key and the fixture witness."""
    release.verify_reviewed_guest(root)
    guest = clock.REVIEWED_GUEST
    directory = release.regular(root, guest["identity_dir"] + "/guest.elf").parent
    elf = read_regular(directory / "guest.elf", MAX_ELF_BYTES)
    require(elf.startswith(b"\x7fELF"), "reviewed guest.elf is not an ELF file")
    require(clock.target.sha256(elf) == guest["elf"], "committed guest.elf differs from REVIEWED_GUEST elf")
    key = read_regular(directory / "program-vkey.bin", 32)
    require("0x" + key.hex() == guest["vkey"], "committed program-vkey.bin differs from REVIEWED_GUEST vkey")
    witness = read_regular(directory / "clock.witness.bin", MAX_RECORD_BYTES)
    require(clock.target.sha256(witness) == clock.REVIEWED_FIXTURE["witness_sha256"],
            "committed clock.witness.bin differs from REVIEWED_FIXTURE witness")
    return directory / "guest.elf", elf, witness


def run(command, log, timeout):
    with log.open("w") as stream:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=stream, text=True, timeout=timeout)
    log.with_suffix(".stdout").write_text(result.stdout)
    require(result.returncode == 0, f"{Path(command[0]).name} exited {result.returncode}; see {log.name}")
    return result.stdout


def single(pattern, text, label):
    found = re.findall(pattern, text, flags=re.MULTILINE)
    require(len(found) == 1, f"expected exactly one {label} line, found {len(found)}")
    return found[0]


def check_vkey_output(stdout):
    """`vkey --elf` prints ELF_SHA256= and VKEY= for the ELF it was given."""
    elf = single(r"^ELF_SHA256=([0-9a-f]{64})$", stdout, "ELF_SHA256")
    key = single(r"^VKEY=(0x[0-9a-f]{64})$", stdout, "VKEY")
    require(elf == clock.REVIEWED_GUEST["elf"], "vkey ran on an ELF other than the reviewed one")
    require(key == clock.REVIEWED_GUEST["vkey"], "derived setup key differs from REVIEWED_GUEST vkey")
    return {"elf_sha256": elf, "program_vkey": key}


def named(entries, label):
    require(isinstance(entries, list) and all(isinstance(e, dict) and isinstance(e.get("name"), str)
                                              for e in entries), label + " must be a list of named records")
    names = [e["name"] for e in entries]
    require(len(set(names)) == len(names), "duplicate " + label + " name")
    return {e["name"]: e for e in entries}


def positive(value):
    return type(value) is int and value > 0


def check_execution_record(record, witness, elf):
    """Compare a `clock-proof --no-prove` record with REVIEWED_GUEST and REVIEWED_FIXTURE."""
    fixture = clock.REVIEWED_FIXTURE
    require(isinstance(record, dict), "execution record must be an object")
    require(record.get("sdk_version") == clock.SDK_VERSION, "execution record SDK version")
    require(record.get("elf_sha256") == clock.REVIEWED_GUEST["elf"] == clock.target.sha256(elf),
            "execution ELF differs from REVIEWED_GUEST elf")
    require(record.get("proof_generated") is False and record.get("setup_performed") is False,
            "execution-only run must not prove or run setup")
    require(record.get("native_guest_equal") is True and positive(record.get("cycles")),
            "normal fixture: native and guest results must be equal")
    require(record.get("witness_sha256") == clock.target.sha256(witness) == fixture["witness_sha256"],
            "normal fixture witness differs from REVIEWED_FIXTURE")
    require(record.get("commitment") == fixture["commitment"], "normal fixture commitment differs from REVIEWED_FIXTURE")
    pinned = fixture["cases"]
    require("cases" in record or not pinned, "execution record has no cases but REVIEWED_FIXTURE pins some")
    cases = named(record.get("cases", []), "case")
    require(set(cases) == set(pinned), "case set differs from REVIEWED_FIXTURE: "
            + ", ".join(sorted(set(cases) ^ set(pinned))))
    for name, case in cases.items():
        expected = pinned[name]
        require(case.get("guest_exit") == 0 and case.get("native_guest_equal") is True
                and positive(case.get("cycles")), "case " + name + ": guest must succeed with native == guest")
        require(case.get("witness_sha256") == expected["witness_sha256"], "case " + name + ": witness differs")
        require(case.get("commitment") == expected["commitment"], "case " + name + ": commitment differs")
    negatives = named(record.get("negatives"), "negative")
    require(set(negatives) == set(fixture["negatives"]), "negative set differs from REVIEWED_FIXTURE: "
            + ", ".join(sorted(set(negatives) ^ set(fixture["negatives"]))))
    for name, negative in negatives.items():
        require(negative.get("guest_exit") == 1 and negative.get("public_bytes") == 0,
                "negative " + name + ": the guest must reject it with no public values")
        require(negative.get("witness_sha256") == fixture["negatives"][name], "negative " + name + ": witness differs")
    return {"cycles": record["cycles"], "cases": {name: case["cycles"] for name, case in sorted(cases.items())},
            "negatives": sorted(negatives)}


def check_fixture_shape():
    """REVIEWED_FIXTURE's own shape, so a malformed pin cannot pass by matching itself."""
    fixture = clock.REVIEWED_FIXTURE
    require(isinstance(fixture["witness_sha256"], str) and HEX64.fullmatch(fixture["witness_sha256"])
            and isinstance(fixture["commitment"], str) and WORD.fullmatch(fixture["commitment"]),
            "malformed REVIEWED_FIXTURE witness or commitment")
    require(isinstance(fixture["negatives"], dict) and fixture["negatives"]
            and all(isinstance(v, str) and HEX64.fullmatch(v) for v in fixture["negatives"].values()),
            "malformed REVIEWED_FIXTURE negatives")
    require(isinstance(fixture["cases"], dict)
            and all(isinstance(v, dict) and set(v) == {"witness_sha256", "commitment"}
                    and isinstance(v["witness_sha256"], str) and HEX64.fullmatch(v["witness_sha256"])
                    and isinstance(v["commitment"], str) and WORD.fullmatch(v["commitment"])
                    for v in fixture["cases"].values()), "malformed REVIEWED_FIXTURE cases")


def verify(vkey_bin, clock_proof_bin, output, root=ROOT, timeout=2400):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), "fresh output directory required")
    check_fixture_shape()
    elf_path, elf, witness = reviewed_identity(root)
    binaries = {}
    for label, binary in (("vkey", vkey_bin), ("clock-proof", clock_proof_bin)):
        binary = Path(binary).resolve(strict=True)
        binaries[label] = {"path": str(binary), "sha256": clock.target.sha256(read_regular(binary, 1 << 30))}
    output.mkdir(parents=True)
    derived = check_vkey_output(run([binaries["vkey"]["path"], "--elf", str(elf_path)],
                                    output / "vkey.log", timeout))
    execution = output / "execution"
    run([binaries["clock-proof"]["path"], "--elf", str(elf_path), str(execution), "--no-prove"],
        output / "clock-proof.log", timeout)
    raw = read_regular(execution / "execution.json", MAX_RECORD_BYTES)
    produced = read_regular(execution / "clock.witness.bin", MAX_RECORD_BYTES)
    require(produced == witness, "produced fixture witness differs from the committed clock.witness.bin")
    require(read_regular(execution / "guest.elf", MAX_ELF_BYTES) == elf, "clock-proof executed a different ELF")
    summary = check_execution_record(release.decode_json(raw), produced, elf)
    # Nothing the comparison relied on may have changed while the binaries ran.
    _, after_elf, after_witness = reviewed_identity(root)
    require((after_elf, after_witness) == (elf, witness), "reviewed identity changed during execution")
    for label, entry in binaries.items():
        require(clock.target.sha256(Path(entry["path"]).read_bytes()) == entry["sha256"], label + " binary changed")
    evidence = {
        "status": "PASS", "kind": "reviewed-guest-cpu-execution",
        "proof_generated": False, "execution_setup_performed": False,
        "scope": ("CPU execution of the committed reviewed guest ELF on its normal fixture, case and negative "
                  "witnesses, plus a CPU setup-key derivation; no proof, no deployment, no live service."),
        "reviewed_guest": {"identity_dir": clock.REVIEWED_GUEST["identity_dir"],
                           "guest_elf_sha256": clock.REVIEWED_GUEST["elf"],
                           "program_vkey": clock.REVIEWED_GUEST["vkey"]},
        "reviewed_fixture": {"witness_sha256": clock.REVIEWED_FIXTURE["witness_sha256"],
                             "commitment": clock.REVIEWED_FIXTURE["commitment"],
                             "cases": sorted(clock.REVIEWED_FIXTURE["cases"]),
                             "negatives": sorted(clock.REVIEWED_FIXTURE["negatives"])},
        "derived_setup_key": derived, "execution": summary,
        "execution_record_sha256": clock.target.sha256(raw), "binaries": binaries,
        "runner_sha256": clock.target.sha256(Path(__file__).read_bytes()),
    }
    (output / "verification.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vkey-bin", required=True, type=Path)
    parser.add_argument("--clock-proof-bin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=2400)
    args = parser.parse_args()
    require(0 < args.timeout_seconds <= 7200, "bounded positive timeout required")
    evidence = verify(args.vkey_bin, args.clock_proof_bin, args.output_dir, timeout=args.timeout_seconds)
    print(json.dumps({key: evidence[key] for key in ("status", "reviewed_guest", "execution")}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"Reviewed guest execution refused: {error}", file=sys.stderr)
        sys.exit(1)
