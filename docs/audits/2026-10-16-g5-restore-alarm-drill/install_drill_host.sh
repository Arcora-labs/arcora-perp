#!/usr/bin/env bash
# P5 drill: install main's gateway (demo posture, loopback only) with deploy/ units.
# Run as root on the ops host from the unpacked bundle directory.
set -euo pipefail
cd "$(dirname "$0")"
PORT=8095

(cd dist && sha256sum -c darkperp-gateway.sha256)

id darkperp >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin darkperp
id darkperp-ops >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin darkperp-ops

install -m 0755 dist/darkperp-gateway /usr/local/bin/darkperp-gateway
install -d -m 0755 /usr/local/lib/darkperp-ops
install -m 0755 ops/ops_notify.py ops/gateway_backup.py ops/gateway_monitor.py /usr/local/lib/darkperp-ops/

# Secrets are created here and never leave the host except the drill seed,
# which the restore step copies to the second machine on purpose.
install -d -m 0700 /etc/darkperp
# The operator's existing ops topic, given by the caller (never committed).
topic=${DRILL_NTFY_TOPIC:?set DRILL_NTFY_TOPIC to the ops ntfy topic}
umask 077
if [ ! -f /etc/darkperp/gateway.env ]; then
  printf 'ENCLAVE_SEED=%s\nFIN_ALERT_NTFY_TOPIC=%s\n' "$(openssl rand -hex 32)" "$topic" > /etc/darkperp/gateway.env
fi
printf 'FIN_ALERT_NTFY_TOPIC=%s\n' "$topic" > /etc/darkperp/ops.env

install -m 0644 systemd/* /etc/systemd/system/
# Port 8080 is taken on this host: move the drill gateway and its monitor.
install -d /etc/systemd/system/darkperp-gateway.service.d /etc/systemd/system/darkperp-monitor.service.d
printf '[Service]\nEnvironment=PORT=%s\n' "$PORT" > /etc/systemd/system/darkperp-gateway.service.d/10-port.conf
printf '[Service]\nExecStart=\nExecStart=/usr/local/lib/darkperp-ops/gateway_monitor.py --base-url http://127.0.0.1:%s --state-file /var/lib/darkperp-ops/monitor.json --stall-seconds 900\n' "$PORT" \
  > /etc/systemd/system/darkperp-monitor.service.d/10-port.conf
systemctl daemon-reload
systemctl start darkperp-gateway.service
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/api/state" >/dev/null && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PORT/identity" > /root/darkperp-drill-identity.json
systemctl is-active darkperp-gateway.service
