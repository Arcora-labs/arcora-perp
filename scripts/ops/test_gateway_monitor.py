"""gateway_monitor: public health and direct L1 reads → episodic, redacted ops alerts."""
import contextlib
import http.server
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from unittest import mock

import gateway_monitor
import ops_notify
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

    def test_gateway_alerts_are_relayed_and_unknown_names_ignored(self):
        state = doc()
        state["opsAlerts"] = ["stale_anchor", "liveness_low", "persistence_failed", 7, "x"]
        active, _ = self.run_eval(state, status(7))
        self.assertEqual(active, {"stale_anchor", "liveness_low"})
        state["opsAlerts"] = "stale_anchor"
        active, _ = self.run_eval(state, status(7))
        self.assertEqual(active, set())

    def test_camel_case_health_fields_are_read(self):
        state = {"settlementHealth": "HELD", "depositIngestion": {"state": "halted"},
                 "l1": {"batchCount": 7}, "opsAlerts": ["bond_shortfall"]}
        active, _ = self.run_eval(state, status(7))
        self.assertEqual(active, {"settlement_held", "deposit_halted", "bond_shortfall"})

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


# A `cast` that records every call and fails; proof that no L1 read was attempted.
CAST_TRIPWIRE = '#!/bin/sh\necho "$@" >> "$(dirname "$0")/cast.log"\nexit 1\n'


def gateway_only_environ():
    """An explicit environment for main() in tests that configure no L1 reads.

    main() falls back to os.environ, so DARKPERP_L1_RPC and DARKPERP_SETTLEMENT
    exported in the shell (ops.env sourced) would switch L1 reads on and run the
    real `cast` against that provider. Only PATH is passed on.
    """
    return {"PATH": os.environ.get("PATH", os.defpath)}


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
        ], sleep=lambda _s: None, environ=gateway_only_environ())

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

    def test_gateway_alert_is_relayed_once_per_episode(self):
        self.gateway.state = dict(doc(), opsAlerts=["unanswerable_challenge"])
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.run_monitor(), 0)
        self.gateway.state = dict(doc(), opsAlerts=[])
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events(), [
            ("unanswerable_challenge", "active", 1),
            ("unanswerable_challenge", "recovered", 1),
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

    def test_l1_settings_exported_in_the_shell_are_never_used(self):
        # An operator who sourced ops.env must not make this suite call the
        # configured provider: these tests configure no L1 reads at all.
        trap = self.tmp / "trap"
        trap.mkdir()
        cast = trap / "cast"
        cast.write_text(CAST_TRIPWIRE)
        cast.chmod(cast.stat().st_mode | stat.S_IEXEC)
        exported = {"PATH": f"{trap}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
                    gateway_monitor.RPC_ENV: RPC, gateway_monitor.SETTLEMENT_ENV: SETTLEMENT}
        self.gateway.state = doc(health="HELD")
        with mock.patch.dict(os.environ, exported):
            self.assertEqual(self.run_monitor(), 0)
        self.assertFalse((trap / "cast.log").exists(), "cast ran although no L1 reads were configured")
        self.assertEqual(self.events(), [("settlement_held", "active", 1)])


# --- direct L1 reads ---------------------------------------------------------

SETTLEMENT = "0x" + "5e" * 20
# A fake provider URL whose path carries a "key", like a real metered RPC.
RPC = "https://rpc.example/v2/fake-provider-key-0123456789"
H1, H2, H3 = ("0x" + c * 64 for c in "abc")

# The fake Foundry `cast`. Output formats were taken from cast 1.x against the
# real DarkPerpSettlement on a local Anvil: large uints carry an annotation
# ("43200 [4.32e4]"), bytes32[] prints as "[0x.., 0x..]", a tuple prints one
# field per line. On failure cast echoes the RPC URL on stderr; so does the fake.
FAKE_CAST = textwrap.dedent(r"""
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path

    CHALLENGE = "challenges(bytes32)(address,uint64,uint256,uint256,uint256,bool)"


    def big(n):
        if n < 10_000:
            return str(n)
        mantissa, exponent = f"{n:e}".split("e")
        return f"{n} [{mantissa.rstrip('0').rstrip('.')}e{int(exponent)}]"


    def respond(scenario, args):
        # (exit code, stdout, stderr) of one cast argv against a scenario dict.
        if scenario.get("down"):
            return 1, "", "Error: error sending request for url (" + os.environ.get("ETH_RPC_URL", "") + ")\n"
        if args[:1] == ["block-number"]:
            return 0, f"{scenario['head']}\n", ""
        if len(args) < 3 or args[0] != "call":
            return 2, "", "unsupported\n"
        sig = args[2]
        if sig in scenario.get("fail", []):
            return 1, "", "Error: server returned an error response (" + os.environ.get("ETH_RPC_URL", "") + ")\n"
        challenges = scenario.get("challenges", {})
        if sig == "closeOnly()(bool)":
            out = "true" if scenario.get("close_only") else "false"
        elif sig == "lastProgressBlock()(uint256)":
            out = big(scenario["last"])
        elif sig == "livenessTimeoutBlocks()(uint256)":
            out = big(scenario["timeout"])
        elif sig == "openChallengeCount()(uint256)":
            out = str(scenario.get("count", len(challenges)))
        elif sig == "openChallenges(uint256,uint256)(bytes32[])":
            start, size = int(args[3]), int(args[4])
            out = "[" + ", ".join(list(challenges)[start:start + size]) + "]"
        elif sig == CHALLENGE:
            opened = challenges.get(args[3])
            # "closed": listed by openChallenges() but reported closed, which a
            # provider consistent with the pinned block never does.
            still_open = opened is not None and args[3] not in scenario.get("closed", [])
            fields = ["0x90F79bf6EB2c4f870365E785982E1f101E93b906", "0", big(opened or 0), "3",
                      "10000000000000000 [1e16]", "true" if still_open else "false"]
            out = "\n".join(fields)
        else:
            return 2, "", "unknown signature\n"
        return 0, out + "\n", ""


    if __name__ == "__main__":
        here = Path(__file__).resolve().parent
        scenario = json.loads((here / "scenario.json").read_text())
        with open(here / "cast.log", "a") as log:
            log.write(json.dumps({"argv": sys.argv[1:], "rpc": os.environ.get("ETH_RPC_URL"),
                                  "env": sorted(os.environ)}) + "\n")
        code, out, err = respond(scenario, sys.argv[1:])
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(code)
""").lstrip("\n")
_FAKE = {}
exec(compile(FAKE_CAST, "fake_cast", "exec"), _FAKE)


@contextlib.contextmanager
def inherited_output(path):
    """Point this process's file descriptors 1 and 2 at `path` for the block.

    contextlib.redirect_stderr swaps only Python's sys.stderr. A child such as
    cast inherits the real descriptors, which systemd sends to the journal, so
    a leak check has to look at those.
    """
    streams = [s for s in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__) if s is not None]
    for stream in streams:
        stream.flush()
    saved = os.dup(1), os.dup(2)
    try:
        with open(path, "ab") as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
        yield
    finally:
        for stream in streams:
            stream.flush()
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        os.close(saved[0])
        os.close(saved[1])


def chain(head=1000, last=None, timeout=100, close_only=False, challenges=None, **extra):
    return dict(head=head, last=head if last is None else last, timeout=timeout, close_only=close_only,
                challenges=dict(challenges or {}), **extra)


class FakeRunner:
    """In-process cast runner over the same responder as the fake binary."""

    def __init__(self, scenario):
        self.scenario = scenario
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        code, out, _err = _FAKE["respond"](self.scenario, list(args))
        return out.strip() if code == 0 else None

    def sigs(self):
        return [c[2] for c in self.calls if c[0] == "call"]


def observation(head=1000, last=None, timeout=100, close_only=False, opened=None, count=None):
    opened = dict(opened or {})
    return {"head": head, "last_progress_block": head if last is None else last,
            "liveness_timeout_blocks": timeout, "close_only": close_only,
            "open_challenges": len(opened) if count is None else count, "opened": opened}


def policy(**overrides):
    terms = {"liveness_low_percent": 50, "challenge_age_blocks": 900, "failures": 3}
    return gateway_monitor.L1Policy(**{**terms, **overrides})


class EvaluateL1(unittest.TestCase):
    def run_eval(self, obs, track=None, terms=None):
        return gateway_monitor.evaluate_l1(obs, track or {}, terms or policy())

    def test_recent_progress_raises_nothing(self):
        active, track = self.run_eval(observation())
        self.assertEqual(active, set())
        self.assertEqual(track["failures"], 0)

    def test_liveness_low_at_half_the_window(self):
        self.assertEqual(self.run_eval(observation(head=1049, last=1000, timeout=100))[0], set())
        self.assertEqual(self.run_eval(observation(head=1050, last=1000, timeout=100))[0], {"liveness_low"})

    def test_liveness_threshold_rounds_down_like_the_gateway(self):
        # l1.rs LivenessObservation::liveness_low: idle >= timeout / 2 in integers.
        self.assertEqual(self.run_eval(observation(head=1049, last=1000, timeout=101))[0], set())
        self.assertEqual(self.run_eval(observation(head=1050, last=1000, timeout=101))[0], {"liveness_low"})

    def test_liveness_percent_is_configurable(self):
        terms = policy(liveness_low_percent=75)
        self.assertEqual(self.run_eval(observation(head=1074, last=1000), terms=terms)[0], set())
        self.assertEqual(self.run_eval(observation(head=1075, last=1000), terms=terms)[0], {"liveness_low"})

    def test_a_head_behind_the_last_progress_is_not_idle(self):
        self.assertEqual(self.run_eval(observation(head=900, last=1000))[0], set())

    def test_close_only_is_reported_instead_of_liveness_low(self):
        active, _ = self.run_eval(observation(head=5000, last=1000, close_only=True))
        self.assertEqual(active, {"l1_close_only"})

    def test_challenge_unanswered_at_the_age_threshold(self):
        self.assertEqual(self.run_eval(observation(head=1899, opened={H1: 1000}))[0], set())
        self.assertEqual(self.run_eval(observation(head=1900, opened={H1: 1000}))[0], {"challenge_unanswered"})
        self.assertEqual(self.run_eval(observation(head=1900, opened={H1: 1500, H2: 1000}))[0],
                         {"challenge_unanswered"}, "the oldest open challenge decides")

    def test_zero_age_alerts_on_any_open_challenge(self):
        terms = policy(challenge_age_blocks=0)
        self.assertEqual(self.run_eval(observation(opened={H1: 1000}), terms=terms)[0], {"challenge_unanswered"})
        self.assertEqual(self.run_eval(observation(opened={}), terms=terms)[0], set())

    def test_a_challenge_opened_after_the_head_is_not_aged(self):
        terms = policy(challenge_age_blocks=0)
        self.assertEqual(self.run_eval(observation(head=1000, opened={H1: 1001}), terms=terms)[0], set())

    def test_unreachable_after_consecutive_failures_while_holding_the_last_reading(self):
        active, track = self.run_eval(observation(head=1050, last=1000))
        self.assertEqual(active, {"liveness_low"})
        for _ in range(2):
            active, track = self.run_eval(None, track)
            self.assertEqual(active, {"liveness_low"}, "a failed read neither clears nor raises")
        active, track = self.run_eval(None, track)
        self.assertEqual(active, {"liveness_low", "l1_unreachable"})
        active, track = self.run_eval(observation(), track)
        self.assertEqual(active, set())
        self.assertEqual(track["failures"], 0)

    def test_failure_threshold_is_configurable(self):
        active, _ = self.run_eval(None, {}, policy(failures=1))
        self.assertEqual(active, {"l1_unreachable"})

    def test_known_open_challenges_are_kept_for_the_next_read(self):
        _, track = self.run_eval(observation(opened={H1: 900}))
        self.assertEqual(track["opened"], {H1: 900})
        _, track = self.run_eval(None, track)
        self.assertEqual(track["opened"], {H1: 900})

    def test_an_open_challenge_of_unknown_age_is_aged_from_the_first_reading_that_listed_it(self):
        # One open challenge whose opening block could not be read: it was open at
        # head 1000, so at head 1900 it has been open for at least 900 blocks.
        active, track = self.run_eval(observation(head=1000, count=1))
        self.assertEqual(active, set())
        self.assertEqual(track["unknown_since"], 1000)
        active, track = self.run_eval(observation(head=1899, count=1), track)
        self.assertEqual(active, set())
        active, track = self.run_eval(observation(head=1900, count=1), track)
        self.assertEqual(active, {"challenge_unanswered"})
        self.assertEqual(track["unknown_since"], 1000)

    def test_a_read_age_replaces_the_unknown_age_clock(self):
        _, track = self.run_eval(observation(head=1000, count=1))
        active, track = self.run_eval(observation(head=1890, opened={H1: 1880}), track)
        self.assertEqual(active, set(), "the read age (10 blocks) decides, not the clock")
        self.assertIsNone(track["unknown_since"])
        active, track = self.run_eval(observation(head=1950, opened={H1: 1880}, count=2), track)
        self.assertEqual(active, set())
        self.assertEqual(track["unknown_since"], 1950, "a new unknown age starts a new clock")

    def test_a_failed_reading_keeps_the_unknown_age_clock(self):
        _, track = self.run_eval(observation(head=1000, count=1))
        active, track = self.run_eval(None, track)
        self.assertEqual(active, set())
        self.assertEqual(track["unknown_since"], 1000)
        active, _ = self.run_eval(observation(head=1900, count=1), track)
        self.assertEqual(active, {"challenge_unanswered"})

    def test_challenges_past_the_first_page_have_an_unknown_age(self):
        def page(first, opened_block):
            return {"0x" + format(first + i, "064x"): opened_block for i in range(gateway_monitor.CHALLENGE_PAGE)}
        over = gateway_monitor.CHALLENGE_PAGE + 1
        _, track = self.run_eval(observation(head=1000, opened=page(0, 1000), count=over))
        # Every listed challenge is young (10 blocks); one past the page is not listed.
        active, _ = self.run_eval(observation(head=1900, opened=page(10_000, 1890), count=over), track)
        self.assertEqual(active, {"challenge_unanswered"})

    def test_zero_age_alerts_on_an_open_challenge_of_unknown_age(self):
        active, _ = self.run_eval(observation(count=1), terms=policy(challenge_age_blocks=0))
        self.assertEqual(active, {"challenge_unanswered"})

    def test_a_malformed_unknown_age_clock_starts_again(self):
        for bad in ["1000", -1, 1.5, True, None]:
            with self.subTest(bad):
                _, track = self.run_eval(observation(head=5000, count=1), {"unknown_since": bad})
                self.assertEqual(track["unknown_since"], 5000)

    def test_every_l1_condition_is_a_known_redacted_event(self):
        for name in gateway_monitor.L1_EVENTS:
            ops_notify.event_body(name, "active", 1)
        self.assertIn("liveness_low", ops_notify.GATEWAY_ALERTS, "same name as the gateway's LivenessLow")


class ReadL1(unittest.TestCase):
    def read(self, runner, known=None, clock=None):
        kwargs = {} if clock is None else {"clock": clock}
        return gateway_monitor.read_l1(runner, SETTLEMENT, known or {}, **kwargs)

    def test_reads_cast_formats_at_one_pinned_block(self):
        runner = FakeRunner(chain(head=50_000, last=40_000, timeout=43_200, challenges={H1: 45_000, H2: 49_999}))
        obs = self.read(runner)
        self.assertEqual(obs, {"head": 50_000, "last_progress_block": 40_000, "liveness_timeout_blocks": 43_200,
                               "close_only": False, "open_challenges": 2, "opened": {H1: 45_000, H2: 49_999},
                               "challenge_read_failed": False})
        self.assertEqual(runner.calls[0], ["block-number"])
        for call in runner.calls[1:]:
            self.assertEqual(call[:2], ["call", SETTLEMENT])
            self.assertEqual(call[-2:], ["--block", "50000"])

    def test_no_open_challenges_needs_no_page_read(self):
        runner = FakeRunner(chain())
        self.assertEqual(self.read(runner)["opened"], {})
        self.assertNotIn("openChallenges(uint256,uint256)(bytes32[])", runner.sigs())

    def test_known_challenges_are_not_read_again_and_closed_ones_are_dropped(self):
        runner = FakeRunner(chain(head=2000, challenges={H1: 1000, H2: 1500}))
        obs = self.read(runner, known={H1: 1000, H3: 700})
        self.assertEqual(obs["opened"], {H1: 1000, H2: 1500})
        details = [c[3] for c in runner.calls if c[0] == "call" and c[2].startswith("challenges(")]
        self.assertEqual(details, [H2])

    def test_detail_reads_are_capped_per_run(self):
        many = {"0x" + format(i, "064x"): 100 + i for i in range(gateway_monitor.MAX_CHALLENGE_READS + 5)}
        runner = FakeRunner(chain(head=5000, challenges=many))
        obs = self.read(runner)
        self.assertEqual(len(obs["opened"]), gateway_monitor.MAX_CHALLENGE_READS)
        self.assertEqual(obs["open_challenges"], len(many))
        obs = self.read(FakeRunner(chain(head=5000, challenges=many)), known=obs["opened"])
        self.assertEqual(len(obs["opened"]), len(many))

    def test_a_failed_detail_read_keeps_the_rest_of_the_reading(self):
        runner = FakeRunner(chain(head=2000, challenges={H1: 1000},
                                  fail=["challenges(bytes32)(address,uint64,uint256,uint256,uint256,bool)"]))
        obs = self.read(runner)
        self.assertEqual((obs["open_challenges"], obs["opened"]), (1, {}))
        self.assertTrue(obs["challenge_read_failed"])

    def test_a_listed_challenge_reported_closed_is_a_failed_detail_read(self):
        # openChallenges() and challenges() are read at the same pinned block, where
        # every listed hash is open; a provider saying otherwise is not believed.
        runner = FakeRunner(chain(head=2000, challenges={H1: 1000}, closed=[H1]))
        obs = self.read(runner)
        self.assertEqual(obs["opened"], {})
        self.assertTrue(obs["challenge_read_failed"])

    def test_a_listed_challenge_opened_after_the_pinned_head_is_a_failed_detail_read(self):
        runner = FakeRunner(chain(head=2000, challenges={H1: 2001}))
        obs = self.read(runner)
        self.assertEqual(obs["opened"], {})
        self.assertTrue(obs["challenge_read_failed"])

    def test_a_failed_detail_read_defers_the_remaining_ones_to_the_next_run(self):
        runner = FakeRunner(chain(head=2000, challenges={H1: 1000, H2: 1500}, closed=[H1]))
        obs = self.read(runner)
        details = [c[3] for c in runner.calls if c[0] == "call" and c[2].startswith("challenges(")]
        self.assertEqual((details, obs["opened"]), ([H1], {}))

    def test_deferred_detail_reads_are_not_failures(self):
        many = {"0x" + format(i, "064x"): 100 + i for i in range(gateway_monitor.MAX_CHALLENGE_READS + 5)}
        obs = self.read(FakeRunner(chain(head=5000, challenges=many)))
        self.assertFalse(obs["challenge_read_failed"])

    def test_any_failed_or_malformed_core_read_fails_the_whole_reading(self):
        for sig in ["closeOnly()(bool)", "lastProgressBlock()(uint256)", "livenessTimeoutBlocks()(uint256)",
                    "openChallengeCount()(uint256)", "openChallenges(uint256,uint256)(bytes32[])"]:
            with self.subTest(sig):
                self.assertIsNone(self.read(FakeRunner(chain(challenges={H1: 1}, fail=[sig]))))
        self.assertIsNone(self.read(FakeRunner(chain(down=True))))
        for bad in ["", "0x", "-1", "12abc", "true", "1e5"]:
            with self.subTest(bad):
                self.assertIsNone(self.read(lambda args, timeout: bad if args[0] == "block-number" else "1"))

    def test_an_inconsistent_challenge_page_fails_the_reading(self):
        self.assertIsNone(self.read(FakeRunner(chain(challenges={H1: 1}, count=2))))
        runner = FakeRunner(chain(challenges={H1: 1}))

        def bad_page(args, timeout):
            if args[0] == "call" and args[2].startswith("openChallenges("):
                return "[0x1234]"
            return runner(args, timeout)
        self.assertIsNone(self.read(bad_page))

    def test_the_time_budget_stops_reads(self):
        ticks = iter(range(0, 10_000, 7))
        many = {"0x" + format(i, "064x"): 100 + i for i in range(10)}
        runner = FakeRunner(chain(head=5000, challenges=many))
        obs = self.read(runner, clock=lambda: next(ticks))
        self.assertIsNotNone(obs, "the core reads fit the budget")
        self.assertLess(len(obs["opened"]), len(many), "detail reads stop when the budget is spent")
        slow = iter(range(0, 10_000, gateway_monitor.L1_BUDGET_SECONDS))
        self.assertIsNone(self.read(FakeRunner(chain()), clock=lambda: next(slow)))

    def test_only_read_only_cast_verbs_can_run(self):
        run = gateway_monitor.cast_runner(RPC, {"PATH": os.defpath})
        for args in (["send", SETTLEMENT, "triggerCloseOnly()"], ["rpc", "eth_sendRawTransaction", "0x"],
                     ["wallet", "new"]):
            with self.assertRaises(ValueError, msg=args):
                run(args, 1)


class L1EndToEnd(unittest.TestCase):
    """main() with a fake `cast` first on PATH and a real loopback collector."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        fake = self.bin / "cast"
        fake.write_text(FAKE_CAST)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.set_chain(chain())
        self.collector = Collector()
        self.addCleanup(self.collector.close)
        self.stderr = io.StringIO()
        # What the monitor's descriptors 1 and 2 (journald in production) received.
        self.fd_output = self.tmp / "fd-output.log"
        self.fd_output.touch()

    def set_chain(self, scenario):
        (self.bin / "scenario.json").write_text(json.dumps(scenario))

    def environ(self, **overrides):
        env = {"PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
               "DARKPERP_L1_RPC": RPC, "DARKPERP_SETTLEMENT": SETTLEMENT,
               "FIN_ALERT_NTFY_TOPIC": "unrelated-secret-topic", "UNRELATED_SECRET": "x"}
        env.update(overrides)
        return {k: v for k, v in env.items() if v is not None}

    def run_monitor(self, *extra, base="http://127.0.0.1:9", **env):
        argv = ["--base-url", base, "--state-file", str(self.tmp / "monitor.json"),
                "--local-url", self.collector.url, *extra]
        with inherited_output(self.fd_output), contextlib.redirect_stderr(self.stderr):
            return gateway_monitor.main(argv, sleep=lambda _s: None, environ=self.environ(**env))

    def events(self):
        return [(b["event"], b["transition"], b["episode"]) for b in self.collector.bodies]

    def cast_log(self):
        path = self.bin / "cast.log"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def state_text(self):
        return (self.tmp / "monitor.json").read_text()

    def assert_no_leak(self):
        for where, text in [("sys.stderr", self.stderr.getvalue()),
                            ("fds 1 and 2", self.fd_output.read_text(errors="replace")),
                            ("state", self.state_text()), ("alerts", json.dumps(self.collector.bodies))]:
            self.assertNotIn("fake-provider-key", text, where)
            self.assertNotIn("rpc.example", text, where)

    def test_the_fake_cast_echoes_the_url_on_stderr_like_real_cast(self):
        # Without this the leak checks below could pass against a quiet fake.
        self.set_chain(chain(down=True))
        result = subprocess.run([str(self.bin / "cast"), "block-number"], env=self.environ(ETH_RPC_URL=RPC),
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"fake-provider-key", result.stderr)

    def test_cast_runner_keeps_a_failing_casts_output_off_the_inherited_descriptors(self):
        self.set_chain(chain(down=True))
        run = gateway_monitor.cast_runner(RPC, self.environ())
        with inherited_output(self.fd_output):
            self.assertIsNone(run(["block-number"], 60))
            self.assertIsNone(run(["call", SETTLEMENT, "closeOnly()(bool)", "--block", "1"], 60))
        self.assertEqual(len(self.cast_log()), 2, "the fake ran and wrote the URL to its stderr")
        self.assertEqual(self.fd_output.read_bytes(), b"")

    def test_the_monitor_process_never_writes_the_url_to_its_real_stdout_or_stderr(self):
        # Run as systemd does: a separate interpreter whose fds 1 and 2 are the journal.
        self.set_chain(chain(down=True))
        script = Path(gateway_monitor.__file__).resolve()
        argv = [sys.executable, "-B", "-W", "error::ResourceWarning", str(script),
                "--base-url", "http://127.0.0.1:9", "--state-file", str(self.tmp / "monitor.json"),
                "--local-url", self.collector.url, "--l1-failures", "1"]
        result = subprocess.run(argv, env=self.environ(FIN_ALERT_NTFY_TOPIC=None), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=120, check=False)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output.decode(errors="replace"))
        self.assertTrue(self.cast_log(), "the fake cast ran and wrote the URL to its stderr")
        self.assertIn(b"L1 read failed", result.stderr)
        self.assertNotIn(b"fake-provider-key", output)
        self.assertNotIn(b"rpc.example", output)
        self.assertIn(("l1_unreachable", "active", 1), self.events())
        self.assertNotIn("fake-provider-key", self.state_text())

    def test_without_l1_settings_no_cast_runs_and_the_state_keeps_its_shape(self):
        self.assertEqual(self.run_monitor(DARKPERP_L1_RPC=None, DARKPERP_SETTLEMENT=None), 0)
        self.assertEqual(self.cast_log(), [])
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1)])
        self.assertEqual(set(json.loads(self.state_text())), {"episodes", "track"})

    def test_liveness_low_is_reported_from_l1_while_the_gateway_is_down(self):
        self.set_chain(chain(head=1050, last=1000, timeout=100))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.run_monitor(), 0)
        self.set_chain(chain(head=1060, last=1055, timeout=100))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events(), [
            ("gateway_unreachable", "active", 1),
            ("liveness_low", "active", 1),
            ("liveness_low", "recovered", 1),
        ])
        self.assert_no_leak()

    def test_only_read_only_calls_pinned_to_one_block_with_the_url_kept_out_of_argv(self):
        self.set_chain(chain(head=60_000, last=59_000, timeout=43_200, challenges={H1: 50_000, H2: 59_990}))
        self.assertEqual(self.run_monitor(), 0)
        log = self.cast_log()
        self.assertEqual(log[0]["argv"], ["block-number"])
        allowed = {"closeOnly()(bool)", "lastProgressBlock()(uint256)", "livenessTimeoutBlocks()(uint256)",
                   "openChallengeCount()(uint256)", "openChallenges(uint256,uint256)(bytes32[])",
                   "challenges(bytes32)(address,uint64,uint256,uint256,uint256,bool)"}
        for entry in log[1:]:
            argv = entry["argv"]
            self.assertEqual(argv[:2], ["call", SETTLEMENT], argv)
            self.assertIn(argv[2], allowed, argv)
            self.assertEqual(argv[-2:], ["--block", "60000"], argv)
        self.assertEqual({e["argv"][0] for e in log}, {"block-number", "call"})
        for entry in log:
            self.assertNotIn("fake-provider-key", json.dumps(entry["argv"]))
            self.assertEqual(entry["rpc"], RPC, "the URL reaches cast through ETH_RPC_URL only")
            self.assertNotIn("FIN_ALERT_NTFY_TOPIC", entry["env"])
            self.assertNotIn("UNRELATED_SECRET", entry["env"])
        self.assertEqual(self.events(), [("challenge_unanswered", "active", 1), ("gateway_unreachable", "active", 1)])
        self.assert_no_leak()

    def test_open_challenge_details_are_read_once(self):
        self.set_chain(chain(head=2000, challenges={H1: 1000}))
        self.run_monitor()
        self.run_monitor()
        details = [e for e in self.cast_log() if e["argv"][0] == "call" and e["argv"][2].startswith("challenges(")]
        self.assertEqual(len(details), 1)
        self.set_chain(chain(head=2001))
        self.run_monitor()
        self.assertEqual([e for e in self.events() if e[0] == "challenge_unanswered"], [
            ("challenge_unanswered", "active", 1),
            ("challenge_unanswered", "recovered", 1),
        ])

    def test_a_new_settlement_address_starts_a_fresh_cache(self):
        self.set_chain(chain(head=2000, challenges={H1: 1000}))
        self.run_monitor()
        self.run_monitor(DARKPERP_SETTLEMENT="0x" + "7a" * 20)
        details = [e for e in self.cast_log() if e["argv"][0] == "call" and e["argv"][2].startswith("challenges(")]
        self.assertEqual([e["argv"][1] for e in details], [SETTLEMENT, "0x" + "7a" * 20])

    def detail_failures_logged(self):
        return self.stderr.getvalue().count("[ops-monitor] L1 challenge detail read failed\n")

    def test_a_transient_challenge_detail_failure_is_logged_and_raises_nothing(self):
        failing = [gateway_monitor.CHALLENGE_GETTER]
        self.set_chain(chain(head=2000, challenges={H1: 1990}, fail=failing))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.detail_failures_logged(), 1)
        self.set_chain(chain(head=2030, challenges={H1: 1990}))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.detail_failures_logged(), 1, "one line per failing run")
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1)])
        self.assertNotIn("L1 read failed", self.stderr.getvalue(), "the core reading stood")
        self.assertEqual(json.loads(self.state_text())["l1"]["opened"], {H1: 1990})
        self.assert_no_leak()

    def test_a_persistent_challenge_detail_failure_raises_challenge_unanswered(self):
        # H1 opened at block 1000; its opening block can never be read. From the
        # first run that lists it (head 1500) it is open for at least head - 1500.
        failing = [gateway_monitor.CHALLENGE_GETTER]
        for head in (1500, 2000, 2399):
            self.set_chain(chain(head=head, challenges={H1: 1000}, fail=failing))
            self.assertEqual(self.run_monitor(), 0)
        self.assertNotIn("challenge_unanswered", [e[0] for e in self.events()])
        self.set_chain(chain(head=2400, challenges={H1: 1000}, fail=failing))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.detail_failures_logged(), 4)
        self.assertIn(("challenge_unanswered", "active", 1), self.events())
        # Readable again: its real age (1430 blocks) keeps the same episode open.
        self.set_chain(chain(head=2430, challenges={H1: 1000}))
        self.assertEqual(self.run_monitor(), 0)
        self.set_chain(chain(head=2460))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual([e for e in self.events() if e[0] == "challenge_unanswered"], [
            ("challenge_unanswered", "active", 1),
            ("challenge_unanswered", "recovered", 1),
        ])
        self.assertEqual(self.detail_failures_logged(), 4)
        self.assert_no_leak()

    def test_removing_the_l1_settings_keeps_every_l1_episode_without_a_recovered(self):
        self.set_chain(chain(head=5000, close_only=True, challenges={H1: 1000}))
        self.assertEqual(self.run_monitor(), 0)
        self.set_chain(chain(down=True))
        self.assertEqual(self.run_monitor("--l1-failures", "1"), 0)
        for _ in range(2):
            self.assertEqual(self.run_monitor(DARKPERP_L1_RPC=None, DARKPERP_SETTLEMENT=None), 0)
        self.assertEqual(self.events(), [
            ("challenge_unanswered", "active", 1),
            ("gateway_unreachable", "active", 1),
            ("l1_close_only", "active", 1),
            ("l1_unreachable", "active", 1),
        ])
        # Back on the same contract: the same episodes continue, and only what
        # really changed (L1 is readable again) is reported.
        self.set_chain(chain(head=5100, close_only=True, challenges={H1: 1000}))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events()[4:], [("l1_unreachable", "recovered", 1)])

    def test_a_different_settlement_closes_the_old_contracts_l1_episodes_without_a_recovered(self):
        other = "0x" + "7a" * 20
        self.set_chain(chain(head=5000, close_only=True, challenges={H1: 1000}))
        self.assertEqual(self.run_monitor(), 0)
        self.set_chain(chain(head=5000))
        self.assertEqual(self.run_monitor(DARKPERP_SETTLEMENT=other), 0)
        self.assertEqual(self.events(), [
            ("challenge_unanswered", "active", 1),
            ("gateway_unreachable", "active", 1),
            ("l1_close_only", "active", 1),
        ])
        # The new contract's own close-only is a new episode.
        self.set_chain(chain(head=5010, close_only=True))
        self.assertEqual(self.run_monitor(DARKPERP_SETTLEMENT=other), 0)
        self.assertEqual(self.events()[3:], [("l1_close_only", "active", 2)])

    def test_l1_settings_removed_then_set_to_a_different_settlement(self):
        self.set_chain(chain(head=5000, close_only=True))
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.run_monitor(DARKPERP_L1_RPC=None, DARKPERP_SETTLEMENT=None), 0)
        self.set_chain(chain(head=5000))
        self.assertEqual(self.run_monitor(DARKPERP_SETTLEMENT="0x" + "7a" * 20), 0)
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1), ("l1_close_only", "active", 1)])

    def test_close_only_alerts_once_and_replaces_liveness_low(self):
        self.set_chain(chain(head=5000, last=1000, timeout=100, close_only=True))
        self.run_monitor()
        self.run_monitor()
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1), ("l1_close_only", "active", 1)])

    def test_l1_unreachable_after_consecutive_failures_then_recovers(self):
        self.set_chain(chain(down=True))
        for _ in range(2):
            self.assertEqual(self.run_monitor("--l1-failures", "3"), 0)
        self.assertNotIn("l1_unreachable", [e[0] for e in self.events()])
        self.assertEqual(self.run_monitor("--l1-failures", "3"), 0)
        self.set_chain(chain())
        self.assertEqual(self.run_monitor("--l1-failures", "3"), 0)
        self.assertEqual([e for e in self.events() if e[0] == "l1_unreachable"], [
            ("l1_unreachable", "active", 1),
            ("l1_unreachable", "recovered", 1),
        ])
        self.assertIn("L1 read failed", self.stderr.getvalue())
        self.assert_no_leak()

    def test_missing_cast_counts_as_a_failed_read(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertEqual(self.run_monitor("--l1-failures", "1", PATH=str(empty)), 0)
        self.assertIn(("l1_unreachable", "active", 1), self.events())

    def test_failed_delivery_of_an_l1_alert_is_resent_on_the_next_run(self):
        self.set_chain(chain(head=5000, close_only=True))
        self.collector.reject = 10**6
        self.assertEqual(self.run_monitor(), 1)
        self.collector.reject = 0
        self.collector.bodies.clear()
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(self.events(), [("gateway_unreachable", "active", 1), ("l1_close_only", "active", 1)])

    def test_gateway_and_l1_share_one_liveness_low_episode(self):
        gateway = FakeGateway()
        self.addCleanup(gateway.close)
        gateway.state = dict(doc(), opsAlerts=["liveness_low"])
        self.set_chain(chain(head=1050, last=1000, timeout=100))
        self.run_monitor(base=gateway.url)
        gateway.state = dict(doc(), opsAlerts=[])
        self.run_monitor(base=gateway.url)
        self.set_chain(chain(head=1050, last=1049, timeout=100))
        self.run_monitor(base=gateway.url)
        self.assertEqual(self.events(), [("liveness_low", "active", 1), ("liveness_low", "recovered", 1)])

    def test_partial_or_malformed_l1_settings_are_refused_without_echoing_the_url(self):
        for env in [dict(DARKPERP_SETTLEMENT=None), dict(DARKPERP_L1_RPC=None),
                    dict(DARKPERP_SETTLEMENT="0x1234"), dict(DARKPERP_SETTLEMENT=SETTLEMENT + "\n"),
                    dict(DARKPERP_L1_RPC="https://user:fake-provider-key@rpc.example"),
                    dict(DARKPERP_L1_RPC="wss://rpc.example/fake-provider-key"),
                    dict(DARKPERP_L1_RPC="https://rpc.example/fake-provider-key#frag")]:
            with self.subTest(env), self.assertRaises(SystemExit):
                self.run_monitor(**env)
        self.assertNotIn("fake-provider-key", self.stderr.getvalue())
        self.assertEqual(self.cast_log(), [])

    def test_threshold_arguments_are_bounded(self):
        for extra in [("--liveness-low-percent", "0"), ("--liveness-low-percent", "101"),
                      ("--challenge-age-blocks", "-1"), ("--l1-failures", "0")]:
            with self.subTest(extra), self.assertRaises(SystemExit):
                self.run_monitor(*extra)

    def test_a_checksummed_address_is_passed_to_cast_in_lowercase(self):
        self.run_monitor(DARKPERP_SETTLEMENT="0x" + "5E" * 20)
        self.assertEqual({e["argv"][1] for e in self.cast_log() if e["argv"][0] == "call"}, {SETTLEMENT})

    def test_settlement_argument_overrides_the_environment(self):
        other = "0x" + "7a" * 20
        self.run_monitor("--settlement", other)
        self.assertEqual({e["argv"][1] for e in self.cast_log() if e["argv"][0] == "call"}, {other})


if __name__ == "__main__":
    unittest.main()
