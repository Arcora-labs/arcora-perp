#!/usr/bin/env python3
"""Build the separate candidate guest using a pinned local SP1 compiler.

Existing Cargo cache is reused. This is NOT an independent/cold build or proof.
Output directory must not exist. No reviewed ELF, vkey or source pin is replaced.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import time
import check_chainlink_candidate
import rebuild_reviewed_guest as recipe
from verify_clock_proof import verify_guest_source

ROOT = Path(__file__).resolve().parents[2]
RUSTC_SHA = "985c33069083f55ed42b68ef51a8528d0cb1632e43428ffdb5c489306154f964"

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def inputs():
    paths = list((ROOT / "crates/chainlink-oracle/src").glob("*.rs"))
    paths += [ROOT / p for p in ["crates/chainlink-oracle/Cargo.toml", "crates/chainlink-oracle/Cargo.lock",
              "crates/sp1-chainlink-guest/src/main.rs", "crates/sp1-chainlink-guest/Cargo.toml",
              "crates/sp1-chainlink-guest/Cargo.lock"]]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.cargo = args.cargo.resolve(strict=True)
    args.rustc = args.rustc.resolve(strict=True)
    args.cargo_home = args.cargo_home.resolve(strict=True)
    out = args.output.resolve()
    if out.exists() or args.output.is_symlink():
        raise SystemExit("fresh output directory required")
    assert sha(args.rustc) == RUSTC_SHA, "unexpected SP1 compiler"
    assert subprocess.check_output([str(args.cargo), "--version"], text=True).strip() == recipe.CARGO_VERSION
    check_chainlink_candidate.check()
    before = inputs()
    pins = verify_guest_source()
    out.mkdir(parents=True)
    for sub in ("home", "tmp"):
        (out / sub).mkdir()
    env = {"HOME": str(out / "home"), "CARGO_HOME": str(args.cargo_home),
           "CARGO_TARGET_DIR": str(out / "target"), "TMPDIR": str(out / "tmp"),
           "PATH": ":".join((str(args.cargo.parent), str(args.rustc.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
           "LANG": "C", "LC_ALL": "C", "RUSTC": str(args.rustc), "RUSTC_BOOTSTRAP": "1",
           "CARGO_BUILD_JOBS": "2", "CARGO_TERM_COLOR": "never",
           "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(recipe.FLAGS)}
    cmd = [str(args.cargo), "build", "--manifest-path", "crates/sp1-chainlink-guest/Cargo.toml",
           "--locked", "--offline", "--release", "--target", recipe.TARGET]
    start = time.monotonic()
    with (out / "build.log").open("w") as log:
        run = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    assert before == inputs() and pins == verify_guest_source(), "build inputs changed"
    result = {"command": cmd, "exit_code": run.returncode, "elapsed_seconds": round(time.monotonic()-start, 3),
              "source_sha256": before, "rustc_sha256": sha(args.rustc), "cargo_sha256": sha(args.cargo),
              "reviewed_v2_pins_unchanged": len(pins), "cache": "existing local; NOT cold or independent",
              "proof_generated": False, "guest_executed": False,
              "log_sha256": sha(out / "build.log"), "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if run.returncode == 0:
        elf = out / "target" / recipe.TARGET / "release/arcora-chainlink-candidate-guest"
        result.update(candidate_elf_path=str(elf), candidate_elf_sha256=sha(elf), candidate_elf_bytes=elf.stat().st_size)
    (out / "result.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result, indent=2))
    if run.returncode:
        print("\n".join((out / "build.log").read_text().splitlines()[-20:]))
    raise SystemExit(run.returncode)

if __name__ == "__main__":
    main()
