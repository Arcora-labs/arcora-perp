#!/usr/bin/env python3
"""Real HTTP smoke and one bounded process-kill restore of disposable demo state.

Requires a previously built gateway path. Uses no L1/prover/admin configuration.
Only test-created processes are terminated. Account credentials stay in memory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/audits/2026-09-27-local/runtime"
OUT.mkdir(parents=True, exist_ok=True)
BINARY = Path(sys.argv[1]).resolve()
records = {"binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(), "processes": [],
           "limits": ["Demo balances, no L1 contract/proof/token transfer", "HTTP Vitest uses NullWebSocket",
                      "Waited for a periodic snapshot before SIGKILL; not a snapshot/ACK boundary crash matrix",
                      "Public Crypto.com oracle/candle reads remain enabled; loopback is not outbound isolation"]}


def request(url, path, body=None, key=None):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    req = urllib.request.Request(url + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


with tempfile.TemporaryDirectory(prefix="arcora-http-drill-") as scratch:
    state = Path(scratch) / "fixture.snapshot"
    env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "GATEWAY_BIND_ADDRESS": "127.0.0.1",
           "PORT": "0", "DARKPERP_STATE": str(state)}
    process = None
    def start(label):
        log = OUT / f"gateway-{label}.log"
        handle = log.open("wb")
        proc = subprocess.Popen([str(BINARY)], cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)
        handle.close()
        records["processes"].append({"label": label, "pid": proc.pid})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"test gateway exited {proc.returncode}; inspect {log}")
            match = re.search(r"listening on (http://127\.0\.0\.1:\d+)", log.read_text())
            if match:
                listener = subprocess.check_output(["lsof", "-nP", "-a", "-p", str(proc.pid), "-iTCP", "-sTCP:LISTEN"], text=True)
                assert "127.0.0.1:" in listener and "*:" not in listener, "listener must be loopback only"
                (OUT / f"listener-{label}.txt").write_text(listener)
                return proc, match.group(1)
            time.sleep(0.1)
        proc.terminate()
        proc.wait(timeout=10)
        raise RuntimeError("test gateway failed to listen before deadline")
    try:
        process, url = start("initial")
        smoke_env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "GATEWAY_URL": url}
        with (OUT / "http-smoke.log").open("wb") as log:
            result = subprocess.run(["pnpm", "exec", "vitest", "run", "src/api/realClient.e2e.test.ts"],
                                    cwd=ROOT / "frontend", env=smoke_env, stdout=log, stderr=subprocess.STDOUT, timeout=90)
        records["http_smoke_exit"] = result.returncode
        assert result.returncode == 0, "live HTTP smoke failed"
        account = request(url, "/v1/accounts", {})
        key = account["apiKey"]
        deposited = request(url, "/v1/accounts/deposit", {"marketId": 0, "amount": "1000000"}, key)
        # Record no API key, wallet payload, or full account JSON.
        records["deposit_response_received"] = True
        changed_after = time.time()
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if state.exists() and state.stat().st_mtime > changed_after:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("no post-deposit periodic snapshot observed")
        records["snapshot_before_kill_sha256"] = hashlib.sha256(state.read_bytes()).hexdigest()
        before = request(url, "/v1/accounts/me", key=key)
        process.kill()
        process.wait(timeout=10)
        records["processes"][-1]["exit_code"] = process.returncode
        records["snapshot_after_kill_sha256"] = hashlib.sha256(state.read_bytes()).hexdigest()
        assert records["snapshot_before_kill_sha256"] == records["snapshot_after_kill_sha256"]
        process, url = start("restored")
        after = request(url, "/v1/accounts/me", key=key)
        assert before["owner"] == after["owner"]
        assert before["settledBalance"] == after["settledBalance"]
        assert before["recoveryNonce"] == after["recoveryNonce"]
        assert [(p["marketId"], p["collateral"]) for p in before["positions"]] == [(p["marketId"], p["collateral"]) for p in after["positions"]]
        records["restored_account_balance_collateral_nonce_match"] = True
        process.terminate()
        process.wait(timeout=10)
        records["processes"][-1]["exit_code"] = process.returncode
        assert process.returncode == 0, "graceful test shutdown snapshot failed"
        records["status"] = "PASS"
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        (OUT / "runtime-manifest.json").write_text(json.dumps(records, indent=2) + "\n")
print(json.dumps(records, indent=2))
