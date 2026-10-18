#!/usr/bin/env python3
"""External health monitor for one gateway, run by a systemd timer.

Reads only the public, unauthenticated surfaces: `GET /api/state`
(settlementHealth, depositIngestion.state, l1.batchCount, opsAlerts; the
snake_case spellings are accepted too) and `GET /v1/system/status`
(openWindowId). It raises episodic, redacted alerts through ops_notify. Each
condition is reported once when it starts and once when it clears:

* gateway_unreachable: either read failed (connection, HTTP status, size, JSON).
* settlement_held: settlementHealth == "HELD".
* deposit_halted: depositIngestion.state == "halted".
* settle_stall: a sealed window is waiting (openWindowId > l1.batchCount) and
  the same lag has persisted for --stall-seconds. No L1 means no check.
* the gateway's own alerts in ops_notify.GATEWAY_ALERTS (bond_shortfall,
  unanswerable_challenge, challenge_discovery_failed, stale_anchor,
  liveness_low, permit_gc_stalled), while `opsAlerts` lists them. Other names
  are ignored.

With DARKPERP_L1_RPC and DARKPERP_SETTLEMENT set (both or neither), it also
reads the settlement contract directly with read-only Foundry `cast` calls,
all pinned to one block, so these fire while the gateway is down:

* liveness_low: blocks since lastProgressBlock() reach --liveness-low-percent
  of livenessTimeoutBlocks() (50: the gateway's own LivenessLow threshold,
  rounded down the same way). Not while close-only. Shares its episode with
  the gateway's relayed liveness_low.
* l1_close_only: closeOnly() is true. Close-only is irreversible, so this stays
  active.
* challenge_unanswered: an inclusion challenge in openChallenges() has been
  open for --challenge-age-blocks blocks (challenges(h).openedBlock). Each
  challenge is read once and remembered while it stays open.
* l1_unreachable: --l1-failures runs in a row could not read L1. Until reads
  succeed again the other L1 conditions keep their last reading.

The RPC URL may carry a provider key: it reaches cast only through the
ETH_RPC_URL variable of a minimal child environment, never argv, and cast's
output on failure (which echoes the URL) is discarded.

This complements the gateway's own alerts: it also fires when the process is
down or wedged, which in-process alerts cannot report. An alert whose
delivery fails is not recorded, so the next run sends it again.
"""
import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import ops_notify

MAX_BODY = 16 * 1024 * 1024
TIMEOUT_SECONDS = 5.0

# Direct L1 reads.
RPC_ENV = "DARKPERP_L1_RPC"
SETTLEMENT_ENV = "DARKPERP_SETTLEMENT"
L1_ENV = (RPC_ENV, SETTLEMENT_ENV)
L1_EVENTS = ("liveness_low", "l1_close_only", "challenge_unanswered", "l1_unreachable")
CAST_VERBS = frozenset({"block-number", "call"})
CAST_TIMEOUT_SECONDS = 15
CAST_RPC_TIMEOUT_SECONDS = 10
# All L1 reads of one run, so a slow provider cannot outlast the unit's TimeoutStartSec.
L1_BUDGET_SECONDS = 60
# The contract's own page cap (MAX_OPEN_PAGE).
CHALLENGE_PAGE = 512
# New challenges whose opening block is read per run; the rest follow next run.
MAX_CHALLENGE_READS = 16
CHALLENGE_GETTER = "challenges(bytes32)(address,uint64,uint256,uint256,uint256,bool)"
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH = re.compile(r"0x[0-9a-f]{64}")
_UINT = re.compile(r"(0|[1-9][0-9]*)")

L1Policy = collections.namedtuple("L1Policy", "liveness_low_percent challenge_age_blocks failures")


def _field(doc, camel, snake):
    """The gateway serializes /api/state in camelCase; accept snake_case too."""
    return doc[camel] if camel in doc else doc.get(snake)


def evaluate(state_doc, status_doc, track, now, stall_seconds):
    """Return (active condition names, new stall-tracking dict)."""
    if state_doc is None:
        return {"gateway_unreachable"}, dict(track)
    active = set()
    if _field(state_doc, "settlementHealth", "settlement_health") == "HELD":
        active.add("settlement_held")
    deposits = _field(state_doc, "depositIngestion", "deposit_ingestion")
    if isinstance(deposits, dict) and deposits.get("state") == "halted":
        active.add("deposit_halted")
    alerts = _field(state_doc, "opsAlerts", "ops_alerts")
    if isinstance(alerts, list):
        active.update(a for a in alerts if isinstance(a, str) and a in ops_notify.GATEWAY_ALERTS)

    l1 = state_doc.get("l1")
    if not isinstance(l1, dict) or not isinstance(l1.get("batchCount"), int):
        return active, {}
    if status_doc is None or not isinstance(status_doc.get("openWindowId"), int):
        # Cannot judge the lag this run; keep the clock as it was.
        return active, dict(track)
    batch, open_window = l1["batchCount"], status_doc["openWindowId"]
    lagging = open_window > batch
    since = track.get("lag_since") if track.get("batch") == batch else None
    if lagging and since is None:
        since = now
    if not lagging:
        since = None
    if since is not None and now - since >= stall_seconds:
        active.add("settle_stall")
    return active, {"batch": batch, "lag_since": since}


def evaluate_l1(observation, track, policy):
    """Return (active L1 condition names, new L1 track).

    `observation` is a read_l1() result, or None when L1 could not be read.
    """
    known = _known_opened(track.get("opened"))
    if observation is None:
        failures = _count(track.get("failures")) + 1
        previous = track.get("active") if isinstance(track.get("active"), list) else []
        held = {name for name in previous if name in L1_EVENTS and name != "l1_unreachable"}
        active = set(held)
        if failures >= policy.failures:
            active.add("l1_unreachable")
        return active, {"failures": failures, "active": sorted(held), "opened": known}

    head = observation["head"]
    active = set()
    if observation["close_only"]:
        active.add("l1_close_only")
    else:
        idle = max(0, head - observation["last_progress_block"])
        # Same rounding as the gateway: idle >= timeout / 2 in integers at 50 %.
        if idle >= observation["liveness_timeout_blocks"] * policy.liveness_low_percent // 100:
            active.add("liveness_low")
    opened = dict(observation["opened"])
    if any(head - block >= policy.challenge_age_blocks for block in opened.values()):
        active.add("challenge_unanswered")
    return active, {"failures": 0, "active": sorted(active), "opened": opened}


def _count(value):
    return value if type(value) is int and value >= 0 else 0


def _known_opened(value):
    """Opening blocks remembered from earlier runs, keeping only well-formed entries."""
    if not isinstance(value, dict):
        return {}
    return {
        h: b for h, b in value.items()
        if isinstance(h, str) and _HASH.fullmatch(h) and type(b) is int and b >= 0
    }


class L1ReadError(Exception):
    """An L1 read failed or returned something unexpected. Carries no detail."""


def _uint(text):
    # cast annotates large values: "43200 [4.32e4]".
    parts = text.split()
    if not parts or not _UINT.fullmatch(parts[0]) or len(parts) > 2:
        raise L1ReadError
    if len(parts) == 2 and not (parts[1].startswith("[") and parts[1].endswith("]")):
        raise L1ReadError
    return int(parts[0])


def _bool(text):
    if text not in ("true", "false"):
        raise L1ReadError
    return text == "true"


def _hashes(text):
    if not (text.startswith("[") and text.endswith("]")):
        raise L1ReadError
    inner = text[1:-1].strip()
    items = [item.strip().lower() for item in inner.split(",")] if inner else []
    if not all(_HASH.fullmatch(item) for item in items) or len(set(items)) != len(items):
        raise L1ReadError
    return items


def _challenge(text):
    """(openedBlock, open) from a `challenges(bytes32)` tuple, one field per line."""
    lines = text.splitlines()
    if len(lines) != 6:
        raise L1ReadError
    return _uint(lines[2]), _bool(lines[5].strip())


def read_l1(run, settlement, known, clock=time.monotonic):
    """One consistent reading of the settlement at the current head, or None.

    `run(args, timeout)` runs one read-only cast command and returns its stdout,
    or None on any failure. `known` maps open challenge hashes to the opening
    blocks earlier runs read; only new ones are read (at most MAX_CHALLENGE_READS).
    """
    deadline = clock() + L1_BUDGET_SECONDS

    def cast(args):
        remaining = deadline - clock()
        if remaining <= 0:
            raise L1ReadError
        out = run(args, min(CAST_TIMEOUT_SECONDS, remaining))
        if out is None:
            raise L1ReadError
        return out

    try:
        head = _uint(cast(["block-number"]))
        pin = ["--block", str(head)]

        def view(signature, *args):
            return cast(["call", settlement, signature, *(str(a) for a in args), *pin])

        close_only = _bool(view("closeOnly()(bool)"))
        last_progress = _uint(view("lastProgressBlock()(uint256)"))
        timeout = _uint(view("livenessTimeoutBlocks()(uint256)"))
        count = _uint(view("openChallengeCount()(uint256)"))
        hashes = _hashes(view("openChallenges(uint256,uint256)(bytes32[])", 0, CHALLENGE_PAGE)) if count else []
        if len(hashes) != min(count, CHALLENGE_PAGE):
            raise L1ReadError
    except L1ReadError:
        return None

    opened = {h: known[h] for h in hashes if h in known}
    reads = 0
    for h in hashes:
        if h in opened:
            continue
        if reads >= MAX_CHALLENGE_READS:
            break
        reads += 1
        try:
            block, still_open = _challenge(view(CHALLENGE_GETTER, h))
        except L1ReadError:
            break  # Judge the rest next run; the core reading stands.
        if still_open and block <= head:
            opened[h] = block
    return {
        "head": head,
        "last_progress_block": last_progress,
        "liveness_timeout_blocks": timeout,
        "close_only": close_only,
        "open_challenges": count,
        "opened": opened,
    }


def cast_runner(rpc_url, environ):
    """A `run(args, timeout)` for read_l1 that calls Foundry cast.

    Of this process's environment the child gets only PATH, plus the RPC URL as
    ETH_RPC_URL. Its output on failure (which may echo the URL) is dropped.
    """
    env = {
        "PATH": environ.get("PATH") or os.defpath,
        "ETH_RPC_URL": rpc_url,
        "ETH_RPC_TIMEOUT": str(CAST_RPC_TIMEOUT_SECONDS),
        "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1",
    }

    def run(args, timeout):
        if not args or args[0] not in CAST_VERBS:
            raise ValueError("cast command outside the read-only allowlist")
        try:
            result = subprocess.run(
                ["cast", *args], env=env, cwd="/", stdin=subprocess.DEVNULL,
                capture_output=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        try:
            return result.stdout.decode("ascii").strip()
        except UnicodeDecodeError:
            return None

    return run


def plain_rpc(value):
    """The L1 RPC URL, checked. Errors never include the value: it may carry a key."""
    try:
        parts = urllib.parse.urlsplit(value)
        hostname = parts.hostname
    except ValueError:
        raise ValueError("DARKPERP_L1_RPC must be an http(s) URL") from None
    if parts.scheme not in ("http", "https") or not hostname or any(c.isspace() for c in value):
        raise ValueError("DARKPERP_L1_RPC must be an http(s) URL")
    if parts.username or parts.password or parts.fragment or "#" in value:
        raise ValueError("DARKPERP_L1_RPC must not carry user info or a fragment")
    return value


def l1_settings(settlement, environ):
    """(settlement, rpc URL) when L1 reads are configured, None when not at all."""
    rpc = environ.get(RPC_ENV) or None
    settlement = settlement or environ.get(SETTLEMENT_ENV) or None
    if rpc is None and settlement is None:
        return None
    if rpc is None or settlement is None:
        raise ValueError("set DARKPERP_L1_RPC and DARKPERP_SETTLEMENT together")
    if not _ADDRESS.fullmatch(settlement):
        raise ValueError("DARKPERP_SETTLEMENT must be a 0x-prefixed 20-byte address")
    # Lowercase: cast never rejects it as a bad checksum, and the cache key is stable.
    return settlement.lower(), plain_rpc(rpc)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_json(base, path):
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        with opener.open(base + path, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return None
            raw = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        error.close()
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if len(raw) > MAX_BODY:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def plain_base(value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("base URL must be http(s)://host[:port]")
    if parts.username or parts.password or parts.query or parts.fragment or "#" in value:
        raise ValueError("base URL must not carry credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ValueError("base URL must not carry a path")
    return f"{parts.scheme}://{parts.netloc}"


def build_parser():
    parser = argparse.ArgumentParser(description="Poll one gateway's public health and alert on changes.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--state-file", required=True, type=Path)
    parser.add_argument("--stall-seconds", type=int, default=900)
    # Direct L1 reads; the RPC URL comes only from DARKPERP_L1_RPC.
    parser.add_argument("--settlement", help="settlement address (default: $DARKPERP_SETTLEMENT)")
    parser.add_argument("--liveness-low-percent", type=int, default=50)
    parser.add_argument("--challenge-age-blocks", type=int, default=900)
    parser.add_argument("--l1-failures", type=int, default=3)
    ops_notify.add_target_arguments(parser)
    return parser


def main(argv=None, sleep=time.sleep, now=time.time, environ=None):
    environ = os.environ if environ is None else environ
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        base = plain_base(args.base_url)
        target = ops_notify.parse_target(args.local_url, args.ntfy_topic)
        l1 = l1_settings(args.settlement, environ)
    except ValueError as error:
        parser.error(str(error))
    if not 1 <= args.liveness_low_percent <= 100:
        parser.error("--liveness-low-percent must be 1..100")
    if args.challenge_age_blocks < 0:
        parser.error("--challenge-age-blocks must not be negative")
    if args.l1_failures < 1:
        parser.error("--l1-failures must be at least 1")

    saved = ops_notify.load_state(args.state_file)
    previous = saved.get("episodes", {})
    state_doc = fetch_json(base, "/api/state")
    status_doc = fetch_json(base, "/v1/system/status") if state_doc is not None else None
    active, track = evaluate(state_doc, status_doc, saved.get("track", {}), now(), args.stall_seconds)
    new_state = {"track": track}
    if l1 is not None:
        settlement, rpc = l1
        l1_track = saved.get("l1")
        if not isinstance(l1_track, dict) or l1_track.get("settlement") != settlement:
            l1_track = {}  # A different contract: nothing earlier applies.
        observation = read_l1(cast_runner(rpc, environ), settlement, _known_opened(l1_track.get("opened")))
        if observation is None:
            print("[ops-monitor] L1 read failed", file=sys.stderr)
        policy = L1Policy(args.liveness_low_percent, args.challenge_age_blocks, args.l1_failures)
        l1_active, l1_track = evaluate_l1(observation, l1_track, policy)
        active |= l1_active
        new_state["l1"] = dict(l1_track, settlement=settlement)
    events, episodes = ops_notify.transitions(previous, active)
    failed = ops_notify.send(target, events, sleep=sleep)
    for event in failed:
        # Not recorded as sent: the next run sees the same edge and retries it.
        if event in previous:
            episodes[event] = list(previous[event])
        else:
            episodes.pop(event, None)
    new_state["episodes"] = episodes
    ops_notify.save_state(args.state_file, new_state)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
