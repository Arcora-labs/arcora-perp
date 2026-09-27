#!/usr/bin/env python3
"""Exercise the actual release-test environment declared by the A11 workflow.

An independent miniature crate asserts debug assertions and checked arithmetic.
This is deliberately separate from the protocol tests, whose successful inputs
would otherwise miss incorrectly applied Cargo profile settings.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
workflow = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".github/workflows/a11-release-evidence.yml"
section = workflow.read_text().split("- name: release workspace tests", 1)[1].split("run:", 1)[0]
settings = dict(re.findall(r"(CARGO_PROFILE_\w+):\s*['\"]?([\w]+)", section))
environment = {
    k: v for k, v in os.environ.items()
    if not k.startswith(("CARGO_PROFILE_RELEASE_", "CARGO_PROFILE_TEST_"))
    and k not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR")
}
environment.update(settings)
source = '''#[test]
fn release_debug_assertions_are_active() {
    assert!(cfg!(debug_assertions), "release safety flag not applied");
}
#[test]
fn release_overflow_checks_are_active() {
    let n = std::hint::black_box(u64::MAX);
    assert!(std::panic::catch_unwind(|| n + 1).is_err(), "release overflow silently wrapped");
}
'''
with tempfile.TemporaryDirectory(prefix="arcora-release-profile-") as name:
    root = Path(name)
    (root / "src").mkdir()
    (root / "Cargo.toml").write_text('[package]\nname="arcora-profile-control"\nversion="0.0.0"\nedition="2021"\n[workspace]\n')
    (root / "src/lib.rs").write_text(source)
    print("Workflow:", workflow, "Settings:", settings, flush=True)
    result = subprocess.run(["cargo", "test", "--manifest-path", str(root / "Cargo.toml"), "--release", "--lib"], env=environment)
    raise SystemExit(result.returncode)
