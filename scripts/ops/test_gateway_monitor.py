"""gateway_monitor: public health reads → episodic, redacted ops alerts."""
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

import gateway_monitor
from test_ops_notify import Collector


def doc(health="HEALTHY", deposits="ready", batch=7):
    return {
        "settlement_health": health,
        "deposit_ingestion": {"state": deposits},
        "l1": None if batch is None else {"batchCount": batch},
    }


def status(open_window):
    return {"openWindowId": open_window}


class Evaluate(unittest.TestCase):
    def run_eval(self, state_doc, status_doc, track=None, now=1000.0, stall=900):
        return gateway_monitor.evaluate(state_doc, status_doc, track or {}, now, stall)

    def test_healthy_gateway_raises_nothing(self):
        active, _ = self.run_eval(doc(), status(7))
        self.assertEqual(active, set())

    def test_unreachable_is_the_only_condition_reported(self):
        active, _ = self.run_eval(None, None)
        self.assertEqual(active, {"gateway_unreachable"})

    def test_held_settlement_and_halted_deposits(self):
        active, _ = self.run_eval(doc(health="HELD", deposits="halted"), status(7))
        self.assertEqual(active, {"settlement_held", "deposit_halted"})

    def test_degraded_and_paused_are_not_alerts(self):
        active, _ = self.run_eval(doc(health="DEGRADED", deposits="paused"), status(7))
        self.assertEqual(active, set())

    def test_stall_needs_the_lag_to_persist_for_the_threshold(self):
        active, track = self.run_eval(doc(batch=7), status(8), now=1000.0)
        self.assertEqual(active, set())
        active, track = self.run_eval(doc(batch=7), status(8), track, now=1899.0)
        self.assertEqual(active, set())
        active, track = self.run_eval(doc(batch=7), status(8), track, now=1900.0)
        self.assertEqual(active, {"settle_stall"})
        active, track = self.run_eval(doc(batch=8), status(9), track, now=1910.0)
        self.assertEqual(active, set(), "a settled batch restarts the clock")

    def test_a_new_window_after_long_idle_is_not_an_immediate_stall(self):
        _, track = self.run_eval(doc(batch=7), status(7), now=0.0)
        _, track = self.run_eval(doc(batch=7), status(7), track, now=50_000.0)
        active, _ = self.run_eval(doc(batch=7), status(8), track, now=50_001.0)
        self.assertEqual(active, set())

    def test_no_l1_means_no_stall_check(self):
        active, _ = self.run_eval(doc(batch=None), status(50), now=10**9)
        self.assertEqual(active, set())

    def test_unreadable_status_keeps_the_stall_clock(self):
        _, track = self.run_eval(doc(batch=7), status(8), now=1000.0)
        _, track = self.run_eval(doc(batch=7), None, track, now=1500.0)
        active, _ = self.run_eval(doc(batch=7), status(8), track, now=1900.0)
        self.assertEqual(active, {"settle_stall"})


class FakeGateway:
    def __init__(self):
        self.state = doc()
        self.status = status(7)
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = {"/api/state": outer.state, "/v1/system/status": outer.status}.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp))
        self.gateway = FakeGateway()
        self.addCleanup(self.gateway.close)
        self.collector = Collector()
        self.addCleanup(self.collector.close)

    def run_monitor(self, base=None):
        return gateway_monitor.main([
            "--base-url", base or self.gateway.url,
            "--state-file", str(self.tmp / "monitor.json"),
            "--local-url", self.collector.url,
        ], sleep=lambda _s: None)

    def events(self):
        return [(b["event"], b["transition"], b["episode"]) for b in self.collector.bodies]

    def test_held_alerts_once_then_recovers_once(self):
        self.gateway.state = doc(health="HELD")
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.run_monitor(), 0)
        self.gateway.state = doc()
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events(), [
            ("settlement_held", "active", 1),
            ("settlement_held", "recovered", 1),
        ])

    def test_unreachable_gateway_alerts(self):
        self.assertEqual(self.run_monitor(base="http://127.0.0.1:9"), 0)
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1)])

    def test_failed_delivery_is_resent_on_the_next_run(self):
        self.gateway.state = doc(health="HELD")
        self.collector.reject = 10**6
        self.assertEqual(self.run_monitor(), 1)
        self.collector.reject = 0
        self.collector.bodies.clear()
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events(), [("settlement_held", "active", 1)])

    def test_base_url_must_be_plain(self):
        for base in ["http://user:pw@127.0.0.1:8080", "http://127.0.0.1:8080/?x=1", "ftp://127.0.0.1", "http://127.0.0.1:8080#f"]:
            with self.assertRaises(SystemExit, msg=base):
                self.run_monitor(base=base)


if __name__ == "__main__":
    unittest.main()
