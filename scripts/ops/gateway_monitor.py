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
  liveness_low), while `opsAlerts` lists them. Other names are ignored.

This complements the gateway's own alerts: it also fires when the process is
down or wedged, which in-process alerts cannot report. An alert whose
delivery fails is not recorded, so the next run sends it again.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import ops_notify

MAX_BODY = 16 * 1024 * 1024
TIMEOUT_SECONDS = 5.0


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
    ops_notify.add_target_arguments(parser)
    return parser


def main(argv=None, sleep=time.sleep, now=time.time):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        base = plain_base(args.base_url)
        target = ops_notify.parse_target(args.local_url, args.ntfy_topic)
    except ValueError as error:
        parser.error(str(error))

    saved = ops_notify.load_state(args.state_file)
    previous = saved.get("episodes", {})
    state_doc = fetch_json(base, "/api/state")
    status_doc = fetch_json(base, "/v1/system/status") if state_doc is not None else None
    active, track = evaluate(state_doc, status_doc, saved.get("track", {}), now(), args.stall_seconds)
    events, episodes = ops_notify.transitions(previous, active)
    failed = ops_notify.send(target, events, sleep=sleep)
    for event in failed:
        # Not recorded as sent: the next run sees the same edge and retries it.
        if event in previous:
            episodes[event] = list(previous[event])
        else:
            episodes.pop(event, None)
    ops_notify.save_state(args.state_file, {"episodes": episodes, "track": track})
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
