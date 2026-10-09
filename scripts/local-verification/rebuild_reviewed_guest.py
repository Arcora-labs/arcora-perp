#!/usr/bin/env python3
"""Rebuild the reviewed clock ELF in a new target on the pinned ARM64 Mac tools.

Normalizes two Cargo crate identities and embedded paths after verifying all 21
reviewed guest source pins. Never changes source, ELF/vkey pins, or existing targets.
Same-machine cached dependencies only; this does not generate or verify a proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

import verify_clock_proof as clock
import release_manifest

ROOT = Path(__file__).resolve().parents[2]
TARGET = "riscv64im-succinct-zkvm-elf"
REFERENCE_ROOT = "/Users/huseyinarslan/kimi-bridge/worktrees/Arcora-labs__arcora-perp/clock-anchor-20261009"
# Captured from original Cargo rustc invocations in a separate copy-on-write
# target. These affect symbol/crate identity, not protocol inputs or source code.
METADATA = {"perp_core": "85153213d10819ef", "perp_core_guest": "2c8a895641ad00f3"}
RUSTC_VERSION = """rustc 1.93.0-dev
binary: rustc
commit-hash: unknown
commit-date: unknown
host: aarch64-apple-darwin
release: 1.93.0-dev
LLVM version: 21.1.8"""
CARGO_VERSION = "cargo 1.99.0 (5f94df478 2026-08-27)"
FLAGS = ["-C", "passes=lower-atomic", "-C", "link-arg=--image-base=2013265920",
         "-C", "panic=abort", "--cfg", 'getrandom_backend="custom"',
         "-C", "llvm-args=-misched-prera-direction=bottomup",
         "-C", "llvm-args=-misched-postra-direction=bottomup"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reviewed_sources():
    release_manifest.verify_reviewed_guest(ROOT)
    return {name: sha(ROOT / name) for name in clock.EXPECTED_GUEST_SOURCES}


def normalized_args(args, root=ROOT, cwd=None):
    """Only rewrite reviewed workspace RISC-V invocations; preserve other args."""
    after = list(args)
    if "--crate-name" not in args or "--target" not in args:
        return after
    name = args[args.index("--crate-name") + 1]
    if name not in METADATA or args[args.index("--target") + 1] != TARGET:
        return after
    expected = root / ("crates/perp-core/src/lib.rs" if name == "perp_core"
                       else "crates/sp1-guest/src/main.rs")
    sources = [Path(arg) for arg in args if arg.endswith(".rs")]
    directory = Path.cwd() if cwd is None else cwd
    require(len(sources) == 1 and (directory / sources[0]).resolve() == expected.resolve(),
            "crate identity normalization requires the exact reviewed source path")
    positions = [i for i, arg in enumerate(args)
                 if arg.startswith("metadata=") and i > 0 and args[i - 1] == "-C"]
    require(len(positions) == 1, "exactly one existing -C metadata required")
    require(not any(arg.startswith("--remap-path-prefix") for arg in args),
            "unexpected existing source-path remap")
    after[positions[0]] = "metadata=" + METADATA[name]
    after.append(f"--remap-path-prefix={root}={REFERENCE_ROOT}")
    return after


def compiler_wrapper(argv):
    # This guard runs BEFORE any compiler identity normalization, including when
    # the generated wrapper is invoked directly rather than via the build runner.
    reviewed_sources()
    expected_compiler, log, compiler, *args = argv
    require(Path(compiler).resolve() == Path(expected_compiler).resolve(),
            "unexpected compiler executable")
    after = normalized_args(args)
    if after != args:
        with Path(log).open("a") as stream:
            stream.write(json.dumps({"crate": args[args.index("--crate-name") + 1],
                                     "original_args": args, "normalized_args": after}) + "\n")
    os.execv(compiler, [compiler, *after])


def prepare_output(path):
    output = path.resolve()
    require(not output.is_relative_to(ROOT), "build evidence must be outside the source checkout")
    output.mkdir()  # Exclusive: never delete or overwrite an existing target.
    (output / "target").mkdir()
    return output


def build(args):
    sources = reviewed_sources()  # Before tools, filesystem writes or normalization.
    # rustup dispatches by argv[0]; resolving the cargo symlink would invoke
    # rustup directly and make '+1.99.0 build' invalid.
    cargo = args.cargo.absolute()
    require(cargo.is_file(), "Cargo executable does not exist")
    rustc = args.rustc.resolve(strict=True)
    cargo_version = subprocess.check_output([str(cargo), "+1.99.0", "--version"], text=True, timeout=15).strip()
    rustc_version = subprocess.check_output([str(rustc), "-vV"], text=True, timeout=15).strip()
    require(cargo_version == CARGO_VERSION, "different Cargo build; this recipe pins 1.99.0")
    require(rustc_version == RUSTC_VERSION, "different SP1 compiler; reviewed recipe is ARM64 macOS only")
    output = prepare_output(args.output_dir)
    wrapper = output / "rustc-wrapper.sh"
    wrapper_args = [sys.executable, str(Path(__file__).resolve()), "--compiler-wrapper",
                    str(rustc), str(output / "compiler-invocations.jsonl")]
    wrapper.write_text("#!/bin/sh\nexec " + " ".join(map(shlex.quote, wrapper_args)) + ' "$@"\n')
    wrapper.chmod(0o700)
    env = os.environ.copy()
    for key in ("RUSTFLAGS", "RUSTC_WORKSPACE_WRAPPER", "SP1_SKIP_PROGRAM_BUILD"):
        env.pop(key, None)
    env.update(CARGO_TARGET_DIR=str(output / "target"), CARGO_BUILD_JOBS="2",
               CARGO_ENCODED_RUSTFLAGS="\x1f".join(FLAGS), RUSTC=str(rustc),
               RUSTC_WRAPPER=str(wrapper), RUSTC_BOOTSTRAP="1", CARGO_NET_OFFLINE="true")
    command = [str(cargo), "+1.99.0", "build", "--manifest-path", "crates/sp1-guest/Cargo.toml",
               "--locked", "--offline", "--release", "--target", TARGET]
    started = time.monotonic()
    with (output / "build.log").open("wb") as log:
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise RuntimeError("owned build process group timed out; no success manifest") from None
    require(code == 0, f"guest build failed ({code}); inspect build.log")
    require(reviewed_sources() == sources, "source changed during build")
    elf = output / "target" / TARGET / "release/perp-core-guest"
    require(elf.is_file() and not elf.is_symlink(), "regular compiled ELF required")
    require(sha(elf) == clock.EXPECTED_ELF, "compiled ELF differs from independently reviewed pin")
    invocations = [json.loads(line) for line in (output / "compiler-invocations.jsonl").read_text().splitlines()]
    require({row["crate"] for row in invocations} == set(METADATA),
            "missing reviewed workspace compiler invocation")
    report = {
        "status": "PASS_BYTE_EXACT_REVIEWED_ELF_REBUILD", "elf_sha256": sha(elf),
        "elf_bytes": elf.stat().st_size, "elf_path": str(elf),
        "source_pins_before_and_after": sources, "fresh_target": True,
        "dependency_registry_cache_reused": True, "independent_machine": False,
        "compiler_metadata_normalization": METADATA,
        "path_remap": {"from": str(ROOT), "to": REFERENCE_ROOT}, "compiler_flags": FLAGS,
        "cargo": cargo_version, "rustc": rustc_version,
        "rustc_binary_sha256": sha(rustc), "recipe_sha256": sha(__file__),
        "compiler_invocations_sha256": sha(output / "compiler-invocations.jsonl"),
        "build_log_sha256": sha(output / "build.log"), "build_seconds": time.monotonic() - started,
        "command": command, "proof_generated": False, "guest_executed": False,
        "program_vkey_rederived": False,
        "scope": "Local clean-target rebuild with cached dependencies and the pinned ARM64 Mac compiler; no independent cold environment, fresh proof or deployment claim.",
    }
    with (output / "verification.json").open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    return report


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--compiler-wrapper":
        compiler_wrapper(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path, default=Path.home() / ".cargo/bin/cargo")
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    require(1 <= args.timeout_seconds <= 900, "timeout must be between 1 and 900 seconds")
    print(json.dumps(build(args), indent=2))


if __name__ == "__main__":
    main()
