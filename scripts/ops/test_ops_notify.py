"""ops_notify: same target rules as the gateway, fixed schema, bounded retry."""
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

import ops_notify


ROOT = Path(__file__).resolve().parents[2]
# Gateway alerts the external monitor does not relay from `opsAlerts`: it reads
# the first two from their own health fields, and the gateway delivers the last
# two itself while it runs.
NOT_RELAYED = {"settlement_held", "deposit_halted", "persistence_failed", "archive_pressure"}


def gateway_alert_kinds():
    """The snake_case names of the gateway's `ops_alerts::AlertKind` variants."""
    text = (ROOT / "crates/gateway/src/ops_alerts.rs").read_text()
    body = text.split("pub enum AlertKind {", 1)[1].split("\n}", 1)[0]
    lines = [line.strip() for line in body.splitlines()]
    # Comments and attributes (`#[...]`) are not variants.
    names = [line.rstrip(",") for line in lines if line and not line.startswith(("//", "#["))]
    snake = lambda name: "".join("_" + c.lower() if c.isupper() else c for c in name).lstrip("_")
    return {snake(name) for name in names}


class GatewayAlertNames(unittest.TestCase):
    def test_every_gateway_alert_is_relayed_or_deliberately_not(self):
        kinds = gateway_alert_kinds()
        self.assertIn("deposit_blocked_at_cap", kinds)
        self.assertIn("window_voided", kinds)
        self.assertIn("clock_recovery_blocked", kinds)
        self.assertEqual(set(ops_notify.GATEWAY_ALERTS), kinds - NOT_RELAYED)
        self.assertLessEqual(NOT_RELAYED, kinds)
        self.assertEqual(len(ops_notify.GATEWAY_ALERTS), len(set(ops_notify.GATEWAY_ALERTS)))
        for name in ops_notify.GATEWAY_ALERTS:
            ops_notify.event_body(name, "active", 1)


class Collector:
    """Real loopback HTTP collector; answers 503 for the first `reject` posts."""

    def __init__(self, reject=0, status=204, redirect_to=None):
        self.bodies = []
        self.reject = reject
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                outer.bodies.append(json.loads(self.rfile.read(length)))
                if redirect_to:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                elif outer.reject > 0:
                    outer.reject -= 1
                    self.send_response(503)
                else:
                    self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/alerts"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def no_sleep(_seconds):
    pass


class TargetRules(unittest.TestCase):
    def test_accepts_only_literal_loopback_alerts_endpoint(self):
        for url in ["http://127.0.0.1:1/alerts", "http://[::1]:65535/alerts"]:
            self.assertEqual(ops_notify.parse_target(url, None).url, url)
        for url in [
            "http://localhost:80/alerts",
            "http://127.0.0.2:80/alerts",
            "https://127.0.0.1:80/alerts",
            "http://127.0.0.1:0/alerts",
            "http://127.0.0.1:65536/alerts",
            "http://127.0.0.1:80/alerts?token=fake",
            "http://user:pass@127.0.0.1:80/alerts",
            "http://127.0.0.1:80/alerts#fragment",
            "http://example.com:80/alerts",
            "http://127.0.0.1:80/other",
            "http://127.0.0.1:80/../alerts",
            "http://127.0.0.1:80/alerts\n",
        ]:
            with self.assertRaises(ValueError, msg=url):
                ops_notify.parse_target(url, None)

    def test_ntfy_topic_grammar_matches_gateway(self):
        self.assertEqual(
            ops_notify.parse_target(None, "arcora-valid_1").url,
            "https://ntfy.sh/arcora-valid_1",
        )
        for topic in ["../evil", "topic?query", "topic#fragment", "other/topic", "topic\nheader", "topic token", "topic\n", "x" * 129]:
            with self.assertRaises(ValueError, msg=topic):
                ops_notify.parse_target(None, topic)

    def test_one_transport_at_most(self):
        with self.assertRaises(ValueError):
            ops_notify.parse_target("http://127.0.0.1:80/alerts", "topic")
        self.assertIsNone(ops_notify.parse_target(None, None))
        self.assertIsNone(ops_notify.parse_target("", ""))


class Body(unittest.TestCase):
    def test_fixed_keys_and_known_events_only(self):
        body = json.loads(ops_notify.event_body("settle_stall", "active", 2))
        self.assertEqual(body, {
            "schema": "arcora.ops-monitor.v1",
            "event": "settle_stall",
            "transition": "active",
            "episode": 2,
        })
        with self.assertRaises(ValueError):
            ops_notify.event_body("https://user:secret@rpc.example", "active", 1)
        with self.assertRaises(ValueError):
            ops_notify.event_body("settle_stall", "maybe", 1)


class Delivery(unittest.TestCase):
    def test_transient_rejection_is_retried_once(self):
        collector = Collector(reject=1)
        self.addCleanup(collector.close)
        target = ops_notify.parse_target(collector.url, None)
        body = ops_notify.event_body("deposit_halted", "active", 1)
        self.assertTrue(ops_notify.deliver_with_retry(target, body, sleep=no_sleep))
        self.assertEqual(len(collector.bodies), 2)

    def test_persistent_rejection_stops_at_the_bound(self):
        collector = Collector(status=503)
        self.addCleanup(collector.close)
        target = ops_notify.parse_target(collector.url, None)
        body = ops_notify.event_body("settlement_held", "active", 1)
        self.assertFalse(ops_notify.deliver_with_retry(target, body, sleep=no_sleep))
        self.assertEqual(len(collector.bodies), ops_notify.ATTEMPTS)

    def test_redirects_are_not_followed(self):
        destination = Collector()
        self.addCleanup(destination.close)
        redirect = Collector(redirect_to=destination.url)
        self.addCleanup(redirect.close)
        target = ops_notify.parse_target(redirect.url, None)
        body = ops_notify.event_body("settlement_held", "active", 1)
        self.assertFalse(ops_notify.deliver_with_retry(target, body, sleep=no_sleep))
        self.assertEqual(destination.bodies, [])


class Episodes(unittest.TestCase):
    def test_transition_once_recover_once_and_rearm_with_new_episode(self):
        state = {}
        events, state = ops_notify.transitions(state, {"settlement_held"})
        self.assertEqual(events, [("settlement_held", "active", 1)])
        events, state = ops_notify.transitions(state, {"settlement_held"})
        self.assertEqual(events, [])
        events, state = ops_notify.transitions(state, set())
        self.assertEqual(events, [("settlement_held", "recovered", 1)])
        events, state = ops_notify.transitions(state, {"settlement_held"})
        self.assertEqual(events, [("settlement_held", "active", 2)])

    def test_state_file_roundtrip_is_atomic_and_tolerates_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            self.assertEqual(ops_notify.load_state(path), {})
            ops_notify.save_state(path, {"episodes": {"settle_stall": [1, True]}})
            self.assertEqual(ops_notify.load_state(path), {"episodes": {"settle_stall": [1, True]}})
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["state.json"])


class OneShotCli(unittest.TestCase):
    def test_unit_failure_event_reaches_collector_with_increasing_episode(self):
        collector = Collector()
        self.addCleanup(collector.close)
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "notify.json"
            argv = ["--event", "gateway_service_failed", "--state-file", str(state), "--local-url", collector.url]
            self.assertEqual(ops_notify.main(argv), 0)
            self.assertEqual(ops_notify.main(argv), 0)
        self.assertEqual([b["episode"] for b in collector.bodies], [1, 2])
        self.assertEqual({b["event"] for b in collector.bodies}, {"gateway_service_failed"})

    def test_unknown_event_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                ops_notify.main(["--event", "anything", "--state-file", str(Path(tmp) / "s.json")])


if __name__ == "__main__":
    unittest.main()
