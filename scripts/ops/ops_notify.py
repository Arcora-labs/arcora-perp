#!/usr/bin/env python3
"""Redacted operational notifications for host-side Arcora tooling.

Mirrors the gateway's ops_alerts rules: one transport at most, either a
literal loopback collector (`http://127.0.0.1:<port>/alerts`) or an ntfy.sh
topic; a fixed enum-only JSON body; no redirects; bounded retry. Nothing from
an error, URL or response is ever copied into a notification.

As a CLI it sends one-shot events (systemd OnFailure= hooks):

    ops_notify.py --event gateway_service_failed --state-file /var/lib/darkperp-ops/notify.json \
        --ntfy-topic "$FIN_ALERT_NTFY_TOPIC"
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

SCHEMA = "arcora.ops-monitor.v1"
# Alerts the gateway raises itself and lists in its `opsAlerts` health field,
# relayed by the monitor (same snake_case names as the gateway's AlertKind).
GATEWAY_ALERTS = (
    "bond_shortfall",
    "unanswerable_challenge",
    "challenge_discovery_failed",
    "stale_anchor",
    "liveness_low",
    "permit_gc_stalled",
    "engine_close_only",
    "admission_cap_reached",
    "withdraw_nonce_repaired",
)
# Monitor conditions (episodic) and one-shot unit failures.
EVENTS = (
    "gateway_unreachable",
    "settlement_held",
    "deposit_halted",
    "settle_stall",
    "gateway_service_failed",
    "backup_failed",
    "monitor_failed",
) + GATEWAY_ALERTS
ONE_SHOT_EVENTS = ("gateway_service_failed", "backup_failed", "monitor_failed")
TRANSITIONS = ("active", "recovered")
ATTEMPTS = 3
BACKOFF_SECONDS = 1.0
TIMEOUT_SECONDS = 2.0

_LOOPBACK = re.compile(r"http://(?:127\.0\.0\.1|\[::1\]):([0-9]+)/alerts")
_TOPIC = re.compile(r"[A-Za-z0-9_-]{1,128}")


class Target:
    def __init__(self, url, loopback):
        self.url = url
        self.loopback = loopback


def parse_target(local_url, topic):
    """Return a Target, None when nothing is configured, or raise ValueError."""
    local_url = local_url or None
    topic = topic or None
    if local_url and topic:
        raise ValueError("configure only one operational alert transport")
    if local_url:
        # fullmatch: `$` would also accept a trailing newline.
        match = _LOOPBACK.fullmatch(local_url)
        if not match or not 0 < int(match.group(1)) < 65536:
            raise ValueError("local alert URL must be a literal loopback HTTP endpoint ending /alerts")
        return Target(local_url, loopback=True)
    if topic:
        if not _TOPIC.fullmatch(topic):
            raise ValueError("ntfy topic must contain only letters, digits, dash or underscore (max 128)")
        return Target(f"https://ntfy.sh/{topic}", loopback=False)
    return None


def event_body(event, transition, episode):
    if event not in EVENTS:
        raise ValueError("unknown operational event")
    if transition not in TRANSITIONS:
        raise ValueError("unknown transition")
    if not isinstance(episode, int) or episode < 1:
        raise ValueError("episode must be a positive integer")
    return json.dumps(
        {"schema": SCHEMA, "event": event, "transition": transition, "episode": episode},
        separators=(",", ":"),
    ).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _deliver_once(target, body):
    handlers = [_NoRedirect()]
    if target.loopback:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        target.url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        error.close()
        return False
    except (urllib.error.URLError, OSError, ValueError):
        return False


def deliver_with_retry(target, body, attempts=ATTEMPTS, backoff=BACKOFF_SECONDS, sleep=time.sleep):
    for attempt in range(attempts):
        if _deliver_once(target, body):
            return True
        if attempt + 1 < attempts:
            sleep(backoff * 2**attempt)
    return False


def transitions(state, active_now):
    """Episode bookkeeping like the gateway: one event per edge, re-arm on recovery.

    `state` maps event -> [episode, active]; returns (events, new_state) where
    events are (event, transition, episode) tuples in a stable order.
    """
    new_state = {key: list(value) for key, value in state.items()}
    events = []
    for event in sorted(set(new_state) | set(active_now)):
        episode, was_active = new_state.get(event, [0, False])
        is_active = event in active_now
        if is_active == was_active:
            continue
        if is_active:
            episode += 1
        new_state[event] = [episode, is_active]
        events.append((event, "active" if is_active else "recovered", episode))
    return events, new_state


def load_state(path):
    try:
        with open(path, "rb") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        raise ValueError("state file must hold a JSON object")
    return value


def save_state(path, value):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def send(target, events, sleep=time.sleep):
    """Log every event locally; deliver when a target is configured.

    Returns the names of events whose delivery failed (empty when all were
    delivered or no target is configured).
    """
    failed = set()
    for event, transition, episode in events:
        body = event_body(event, transition, episode)
        print(f"[ops-monitor] {body.decode()}", file=sys.stderr)
        if target is not None and not deliver_with_retry(target, body, sleep=sleep):
            print("[ops-monitor] delivery failed; structured event remains in local log", file=sys.stderr)
            failed.add(event)
    return failed


def add_target_arguments(parser):
    parser.add_argument("--ntfy-topic", default=os.environ.get("FIN_ALERT_NTFY_TOPIC"))
    parser.add_argument("--local-url", default=os.environ.get("FIN_ALERT_LOCAL_URL"))


def build_parser():
    parser = argparse.ArgumentParser(description="Send one redacted one-shot operational event.")
    parser.add_argument("--event", required=True, choices=ONE_SHOT_EVENTS)
    parser.add_argument("--state-file", required=True, type=Path)
    add_target_arguments(parser)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = parse_target(args.local_url, args.ntfy_topic)
    except ValueError as error:
        parser.error(str(error))
    state = load_state(args.state_file)
    counters = state.setdefault("one_shot", {})
    episode = int(counters.get(args.event, 0)) + 1
    counters[args.event] = episode
    save_state(args.state_file, state)
    send(target, [(args.event, "active", episode)])
    # A failed notification must not mask the unit failure that triggered it,
    # and the local log line above is the record of last resort.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
