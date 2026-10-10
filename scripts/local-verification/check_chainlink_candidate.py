#!/usr/bin/env python3
"""Check candidate dependency coherence without replacing reviewed v2 pins."""
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[2]

def check():
    core = tomllib.loads((ROOT / "crates/chainlink-oracle/Cargo.lock").read_text())
    guest = tomllib.loads((ROOT / "crates/sp1-chainlink-guest/Cargo.lock").read_text())
    manifest = tomllib.loads((ROOT / "crates/sp1-chainlink-guest/Cargo.toml").read_text())
    assert manifest["dependencies"]["sp1-zkvm"] == "=6.1.0", "candidate SP1 release changed"
    family = [p for p in guest["package"] if p["name"].startswith(("sp1-", "slop-"))]
    assert family and all(p["version"] == "6.1.0" for p in family), "mixed candidate SP1 family"
    def registry(packages):
        result = {}
        for package in packages:
            if "source" in package:
                key = (package["name"], package["version"])
                assert key not in result, "duplicate candidate package identity"
                result[key] = (package["source"], package.get("checksum"))
        return result
    a, b = registry(core["package"]), registry(guest["package"])
    shared = sorted(a.keys() & b.keys())
    assert all(a[n] == b[n] for n in shared), "native/guest shared dependency checksum mismatch"
    # Different versions of utility crates may legitimately coexist in SP1.
    # Every core package must nevertheless have its exact guest counterpart.
    assert a.keys() <= b.keys(), "native core dependency absent from guest lock"
    return {"passed": True, "sp1_release": "6.1.0", "family_packages": len(family),
            "shared_locked_dependencies": len(shared), "scope": "lock identity; not proof or live DON verification"}

if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
