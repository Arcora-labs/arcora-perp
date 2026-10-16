"""P5: back up the ops-host gateway, restore it on this Mac, time it, compare state.

The drill ENCLAVE_SEED travels over ssh into this process's memory only; it is
never printed or written to disk here.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HOST = "root@<ops-host>"
SSH = ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", "-i", os.path.expanduser("~/.ssh/id_ed25519"), HOST]
GATEWAY = sys.argv[1]
WORK = Path(sys.argv[2])
REPORT = Path(sys.argv[3])


def ssh(command):
    return subprocess.run([*SSH, command], check=True, capture_output=True, text=True).stdout


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def status(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/system/status", timeout=2) as r:
        return json.load(r)


shutil.rmtree(WORK, ignore_errors=True)
WORK.mkdir(parents=True)
report = {}

# 1. Source host: record state, stop gracefully (final snapshot), take a backup.
pre = json.loads(ssh("curl -sf http://127.0.0.1:8095/v1/system/status"))
ssh("systemctl stop darkperp-gateway && systemctl start darkperp-backup.service")
backup = ssh("ls -d /var/lib/darkperp-backups/2*Z | tail -1").strip()
manifest = json.loads(ssh(f"cat {backup}/manifest.json"))
report.update(source_status=pre, backup=backup.rsplit("/", 1)[1], manifest=manifest)

# 2. Restore on this machine; RTO clock starts at the first transfer byte.
t0 = time.monotonic()
subprocess.run(["scp", "-q", "-o", "BatchMode=yes", "-i", os.path.expanduser("~/.ssh/id_ed25519"),
                f"{HOST}:{backup}/state.snap", str(WORK / "state.snap")], check=True)
t_copied = time.monotonic()
seed = ssh("sed -n 's/^ENCLAVE_SEED=//p' /etc/darkperp/gateway.env").strip()
t_keys = time.monotonic()
port = free_port()
env = {"PATH": os.environ["PATH"], "DARKPERP_STATE": str(WORK / "state.snap"), "ENCLAVE_SEED": seed,
       "GATEWAY_BIND_ADDRESS": "127.0.0.1", "PORT": str(port), **manifest["restore_env"]}
log = open(WORK / "gateway.log", "wb")
proc = subprocess.Popen([GATEWAY], env=env, stdout=log, stderr=subprocess.STDOUT)
del seed, env
restored = None
try:
    for _ in range(600):
        if proc.poll() is not None:
            break
        try:
            restored = status(port)
            break
        except OSError:
            time.sleep(0.05)
    t1 = time.monotonic()
finally:
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()

compare = ["mode", "insuranceFund", "treasury", "nextBatchId", "openWindowId", "accounts", "chainId", "vault"]
boot_log = (WORK / "gateway.log").read_text(errors="replace")
report.update(
    restored_status=restored,
    fields_equal={k: (restored or {}).get(k) == pre.get(k) for k in compare},
    restored_from_snapshot="restored sealed snapshot" in boot_log,
    timings_seconds={"transfer": round(t_copied - t0, 3), "key_delivery": round(t_keys - t_copied, 3),
                     "boot_to_status": round(t1 - t_keys, 3), "rto_measured": round(t1 - t0, 3)},
    excluded_from_rto=["failure detection", "machine provisioning", "binary install", "operator decision time"],
)
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({k: report[k] for k in ("fields_equal", "restored_from_snapshot", "timings_seconds")}, indent=2))
