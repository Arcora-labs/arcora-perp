#!/usr/bin/env python3
"""Bound the RustSec advisories that only the pinned SP1 release still carries.

RUSTSEC-2026-0387 (crypto-bigint < 0.7.6: operations meant to be constant-time
could branch on secret data) is fixed in this repository's own code: every crate
here uses k256 0.14, whose arithmetic is on crypto-bigint 0.7.x. SP1 6.1.0 itself
still depends on elliptic-curve 0.13 (sp1-lib in the guest, sp1-curves on the
host), so the guest, sp1-host and prover-service locks keep crypto-bigint 0.5.5
until SP1 ships a release without it. The dependency-advisory job may skip that
one advisory for those locks only, and only while this check passes:

* the vulnerable package is present (otherwise the exception is stale: remove it);
* every SP1 crate that leads to it is the reviewed release (check_sp1_release.RELEASE);
* no crate of this repository (a lock entry without a registry or git source)
  reaches it except through an SP1 crate.

The application lock and the TEE capture lock get no exception, so the advisory
fails the job again if this repository's own code ever depends on an affected
crypto-bigint. This check reads lock files only; it does not judge SP1's use of
the crate, which runs on public proving data and holds no key of this service.
"""
import argparse
import sys
import tomllib
from pathlib import Path

import check_sp1_release

SP1_OWNED = {
    "RUSTSEC-2026-0387": {"package": "crypto-bigint", "patched": (0, 7, 6)},
}
SP1_PREFIX = "sp1-"


def version(text):
    return tuple(int(part) for part in text.split("-")[0].split("."))


def lock_graph(path):
    """Lock entries keyed by (name, version, source) and their dependency edges."""
    packages = tomllib.loads(Path(path).read_text())["package"]
    by_name = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
    key = lambda p: (p["name"], p["version"], p.get("source"))
    edges = {}
    for package in packages:
        targets = []
        for dependency in package.get("dependencies", []):
            name, *rest = dependency.split(" ")
            candidates = by_name.get(name, [])
            if rest:
                candidates = [c for c in candidates if c["version"] == rest[0]]
            if len(candidates) != 1:
                raise ValueError(f"unresolvable lock dependency: {package['name']} -> {dependency}")
            targets.append(key(candidates[0]))
        edges[key(package)] = targets
    return edges


def check_lock(path, advisory):
    rule = SP1_OWNED[advisory]
    edges = lock_graph(path)
    vulnerable = {node for node in edges if node[0] == rule["package"] and version(node[1]) < rule["patched"]}
    if not vulnerable:
        raise ValueError(f"{path}: {advisory} no longer present; remove its SP1 exception")
    # Reverse reachability to the vulnerable package, never walking through an SP1 crate.
    reverse = {}
    for node, targets in edges.items():
        for target in targets:
            reverse.setdefault(target, set()).add(node)
    owners, reached, stack = set(), set(vulnerable), list(vulnerable)
    while stack:
        for parent in reverse.get(stack.pop(), ()):
            if parent[0].startswith(SP1_PREFIX):
                owners.add(parent)
                continue
            if parent not in reached:
                reached.add(parent)
                stack.append(parent)
    local = sorted(name for name, _, source in reached if source is None)
    if local:
        raise ValueError(f"{path}: repository crates reach {advisory} outside SP1: {', '.join(local)}")
    if not owners:
        raise ValueError(f"{path}: {advisory} is not reached through an SP1 crate")
    stray = sorted(f"{name} {ver}" for name, ver, _ in owners if ver != check_sp1_release.RELEASE)
    if stray:
        raise ValueError(f"{path}: {advisory} reached through an unreviewed SP1 crate: {', '.join(stray)}")
    return {"advisory": advisory, "vulnerable": sorted(f"{n} {v}" for n, v, _ in vulnerable),
            "sp1_owners": sorted(f"{n} {v}" for n, v, _ in owners)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory", required=True, choices=sorted(SP1_OWNED))
    parser.add_argument("locks", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        for lock in args.locks:
            result = check_lock(lock, args.advisory)
            print(f"{lock}: {result['advisory']} only via SP1 {check_sp1_release.RELEASE} "
                  f"({', '.join(result['sp1_owners'])})")
    except (ValueError, OSError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"SP1-owned advisory check refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
