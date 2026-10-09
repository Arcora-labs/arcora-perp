#!/usr/bin/env python3
"""Real gateway HTTP ACK / lost-response / SIGKILL / encrypted restart matrix.

Requires a source-bound, normally built gateway binary and frontend's locked
@noble packages. Only disposable loopback processes/state and generated keys are
used. No internal crash hooks, snapshot mocks, L1 writes or proof requests.
Public demo price reads remain enabled: loopback is not outbound isolation.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import re
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]

# Values (including the generated signer secret) travel only through anonymous
# pipes; neither argv, persisted files nor evidence contain credentials.
SIGNER = r"""
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const p = JSON.parse(input), raw = s => Buffer.from(s.replace(/^0x/, ''), 'hex');
const key = raw(p.key), pub = secp256k1.getPublicKey(key, false);
const address = '0x' + Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex');
if (p.kind === 'address') { process.stdout.write(JSON.stringify({address})); }
else {
  const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
  const preimage = p.kind === 'bind'
    ? Buffer.concat([Buffer.from('dark-perp:bind-deposit:'), raw(p.owner), raw(address)])
    : Buffer.concat([Buffer.from('dark-perp:recover-account:'), u64(p.chainId),
        raw(p.vault), raw(p.owner), u64(p.nonce)]);
  const signed = secp256k1.sign(keccak_256(preimage), key);
  const bytes = Buffer.concat([signed.toCompactRawBytes(), Buffer.from([signed.recovery + 27])]);
  process.stdout.write(JSON.stringify({signature:'0x'+bytes.toString('hex')}));
}
"""


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sign(private_key, kind, **fields):
    result = subprocess.run(
        ['node', '--input-type=module', '-e', SIGNER], cwd=ROOT / 'frontend',
        input=json.dumps({'key': private_key, 'kind': kind, **fields}),
        text=True, capture_output=True, timeout=10,
    )
    require(result.returncode == 0, 'test signing helper failed')
    return json.loads(result.stdout)


def wait_until(predicate, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise TimeoutError(label)


def request(port, method, path, body=None, key=None):
    headers = {'Content-Type': 'application/json', 'Connection': 'close'}
    if key:
        headers['X-Api-Key'] = key
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
    try:
        conn.request(method, path, None if body is None else json.dumps(body).encode(), headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        return response.status, data
    finally:
        conn.close()


def ok(port, method, path, body=None, key=None):
    status, data = request(port, method, path, body, key)
    require(status == 200, f'{method} {path.split("/")[-1]} expected HTTP 200, got {status}')
    return data


class ResponseBarrier:
    """One owned TCP proxy: execute the real request, then control only delivery.

    The body is retained privately to distinguish server completion from client
    receipt. In lost mode the client receives ZERO response bytes. Tests may use
    the proxy's private observation to verify server state, but never pretend the
    client received a lost authorization signature or replacement API key.
    """

    def __init__(self, port, method, path, body, key, deliver):
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(1)
        self.server.settimeout(10)
        self.port = self.server.getsockname()[1]
        self.ready = queue.Queue()
        self.release = threading.Event()

        def run():
            try:
                with self.server, self.server.accept()[0] as downstream:
                    downstream.settimeout(10)
                    received = b''
                    while not received.endswith(b'\r\n\r\n'):
                        byte = downstream.recv(1)
                        require(bool(byte), 'proxy client closed before request')
                        received += byte
                    require(received.startswith(b'GET /execute HTTP/1.1\r\n'), 'owned proxy trigger')
                    status, data = request(port, method, path, body, key)
                    payload = json.dumps(data).encode()
                    self.ready.put((status, data))
                    if deliver:
                        downstream.sendall(
                            f'HTTP/1.1 {status} Result\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n'.encode()
                            + payload
                        )
                    require(self.release.wait(15), 'proxy release deadline')
            except Exception as error:
                self.ready.put(error)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def finish(self):
        self.release.set()
        self.thread.join(timeout=15)
        require(not self.thread.is_alive(), 'proxy thread stopped')
        self.server.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    binary = args.gateway_bin.resolve()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    evidence = {
        'status': 'RUNNING', 'binary_sha256': sha256(binary),
        'script_sha256': sha256(Path(__file__)), 'cases': [],
        'scope': 'Production gateway executable in disposable demo mode; real HTTP, SIGKILL and encrypted snapshot restart',
        'limits': [
            'Process crashes, not power-loss/fsync fault injection; no internal snapshot boundary chosen',
            'Demo collateral and unsealed test orders; no live deposits, L1 transaction, proof or settlement',
            'Authorization endpoint creates fresh permits and has no idempotency key; a lost permit is not automatically re-issued',
            'Lost responses are withheld by a controlled proxy after the handler completed; this is not evidence of all possible mid-handler failures',
            'Public demo price/candle reads remain enabled; all listeners and mutation requests are owned loopback',
            'Caller must separately bind the executable build to its source; current git HEAD alone is not build provenance',
        ],
    }
    children = []
    proxies = []
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='arcora-ack-crash-') as directory:
            scratch = Path(directory)

            def start(name, state, seed):
                env = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}
                env.update(GATEWAY_BIND_ADDRESS='127.0.0.1', PORT='0', DARKPERP_STATE=str(state),
                           ENCLAVE_SEED=seed, GATEWAY_HTTP_BODY_TIMEOUT_MS='10000')
                log = out / f'{name}.log'
                with log.open('wb') as stream:
                    child = subprocess.Popen([str(binary)], cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
                children.append(child)

                def listening():
                    require(child.poll() is None, 'gateway stopped before listening')
                    match = re.search(r'listening on http://127\.0\.0\.1:(\d+)', log.read_text())
                    return int(match.group(1)) if match else None

                return child, wait_until(listening, 20, 'gateway listener'), log

            def kill(child):
                require(child.poll() is None, 'owned child alive before SIGKILL')
                child.send_signal(signal.SIGKILL)
                require(child.wait(timeout=10) == -signal.SIGKILL, 'actual SIGKILL exit')

            for operation in ('authorize', 'recovery', 'cancel'):
                for stage in ('before-request-body', 'response-lost', 'ack-received'):
                    name = f'{operation}-{stage}'
                    state = scratch / f'{name}.snapshot'
                    seed, wallet_key = secrets.token_hex(32), secrets.token_hex(32)
                    child, port, log = start(name, state, seed)
                    account = ok(port, 'POST', '/v1/accounts', {})
                    key = account['apiKey']
                    address = sign(wallet_key, 'address')['address']
                    bind = sign(wallet_key, 'bind', owner=account['owner'])['signature']
                    ok(port, 'POST', '/v1/accounts/deposit/address', {'address': address, 'signature': bind}, key)
                    permit = {'from': address, 'amount': '1000000', 'marketId': 0, 'purpose': 'collateral'}
                    if operation == 'cancel':
                        ok(port, 'POST', '/v1/accounts/deposit', {'marketId': 0, 'amount': '20000000000'}, key)
                        ok(port, 'POST', '/v1/orders', {
                            'marketId': 0, 'side': 'Buy', 'size': '10000000',
                            'limitPrice': '1000000', 'tif': 'Gtc', 'reduceOnly': False,
                        }, key)
                        orders = ok(port, 'GET', '/v1/orders', key=key)['orders']
                        require(len(orders) == 1 and orders[0]['cancellable'], 'one unfilled cancellable order')
                        order_id, receipt = orders[0]['orderId'], orders[0]['receipt']
                    # The baseline authorization's genuine durability ACK captures
                    # registration, address binding and (for cancel) the pending order.
                    baseline_permit = ok(port, 'POST', '/v1/accounts/deposit/authorize', permit, key)
                    # New snapshots use v9; v8 is supported only as a legacy reader format.
                    require(state.read_bytes().startswith(b'DPSNAP9\0'), 'encrypted snapshot format')
                    baseline_hash = sha256(state)
                    baseline_account = ok(port, 'GET', '/v1/accounts/me', key=key)
                    if operation == 'authorize':
                        method, path, body = 'POST', '/v1/accounts/deposit/authorize', permit
                    elif operation == 'recovery':
                        metadata = ok(port, 'GET', '/v1/accounts/recovery/' + account['owner'])
                        body = {'owner': account['owner'], 'nonce': metadata['recoveryNonce'], 'signature': sign(
                            wallet_key, 'recovery', owner=account['owner'], chainId=metadata['chainId'],
                            vault=metadata['vault'], nonce=metadata['recoveryNonce'],
                        )['signature']}
                        method, path = 'POST', '/v1/accounts/recovery'
                    else:
                        method, path, body = 'DELETE', '/v1/orders/' + order_id, None
                    case = {'operation': operation, 'stage': stage, 'signal': 9, 'baseline_snapshot_sha256': baseline_hash}
                    server_response = None
                    if stage == 'before-request-body':
                        with socket.create_connection(('127.0.0.1', port), timeout=10) as client:
                            # Even DELETE waits for this body in production service
                            # middleware; the handler cannot mutate before receipt.
                            wire = json.dumps(body if body is not None else {}).encode()
                            client.sendall((f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                                            f'Content-Type: application/json\r\nX-Api-Key: {key}\r\n'
                                            f'Content-Length: {len(wire)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n').encode())
                            interim = b''
                            while not interim.endswith(b'\r\n\r\n'):
                                byte = client.recv(1)
                                require(bool(byte), '100 Continue received')
                                interim += byte
                            require(interim == b'HTTP/1.1 100 Continue\r\n\r\n', 'admitted incomplete body barrier')
                            kill(child)
                            try:
                                require(client.recv(1) == b'', 'no final HTTP response before mutation')
                            except ConnectionResetError:
                                pass
                        case.update(barrier='HTTP 100 Continue; body withheld', client_final_response_bytes=0,
                                    client_outcome='unknown')
                    else:
                        proxy = ResponseBarrier(port, method, path, body, key, stage == 'ack-received')
                        proxies.append(proxy)
                        with socket.create_connection(('127.0.0.1', proxy.port), timeout=10) as client:
                            client.sendall(b'GET /execute HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
                            result = proxy.ready.get(timeout=15)
                            if isinstance(result, Exception):
                                raise result
                            status, server_response = result
                            require(status == 200, 'server operation completed successfully')
                            if stage == 'ack-received':
                                response = http.client.HTTPResponse(client)
                                response.begin()
                                received = response.read()
                                require(response.status == 200 and json.loads(received) == server_response, 'complete client ACK')
                                case.update(client_final_response_bytes=len(received), client_outcome='confirmed')
                            kill(child)
                            proxy.finish()
                            if stage == 'response-lost':
                                require(client.recv(1) == b'', 'client received zero response bytes')
                                case.update(client_final_response_bytes=0, client_outcome='unknown')
                        case['barrier'] = 'real handler complete; response ' + ('delivered' if stage == 'ack-received' else 'withheld at proxy')
                        case['server_status_observed_privately'] = status
                    case['snapshot_after_kill_sha256'] = sha256(state)
                    restored, restored_port, restored_log = start(name + '-restored', state, seed)
                    case['restored_encrypted_snapshot'] = '[state] restored sealed snapshot from ' in restored_log.read_text()
                    require(case['restored_encrypted_snapshot'], 'real startup restored encrypted snapshot')
                    if operation == 'recovery':
                        challenge = ok(restored_port, 'GET', '/v1/accounts/recovery/' + account['owner'])
                        expected_nonce = 0 if stage == 'before-request-body' else 1
                        require(challenge['recoveryNonce'] == expected_nonce, 'restored recovery generation')
                        old_status, _ = request(restored_port, 'GET', '/v1/accounts/me', key=key)
                        require(old_status == (200 if expected_nonce == 0 else 401), 'old credential validity matches durable nonce')
                        case.update(restored_recovery_nonce=expected_nonce, old_key_status=old_status)
                        if stage == 'ack-received':
                            require(server_response['durability'] == 'confirmed', 'recovery confirmed response')
                            recovered = ok(restored_port, 'GET', '/v1/accounts/me', key=server_response['apiKey'])
                            require(recovered['owner'] == account['owner'] and recovered['recoveryNonce'] == 1, 'received replacement key survives')
                            current_key = server_response['apiKey']
                        else:
                            # A lost replacement key is NEVER taken from the proxy.
                            # The client reads fresh public metadata and signs once.
                            fresh = {'owner': account['owner'], 'nonce': challenge['recoveryNonce'], 'signature': sign(
                                wallet_key, 'recovery', owner=account['owner'], chainId=challenge['chainId'],
                                vault=challenge['vault'], nonce=challenge['recoveryNonce'],
                            )['signature']}
                            recovery = ok(restored_port, 'POST', '/v1/accounts/recovery', fresh)
                            require(recovery['recoveryNonce'] == expected_nonce + 1 and recovery['durability'] == 'confirmed', 'fresh challenge resolution')
                            current_key = recovery['apiKey']
                            case['fresh_resolution_nonce'] = recovery['recoveryNonce']
                        replay_status, _ = request(restored_port, 'POST', '/v1/accounts/recovery', body)
                        require(replay_status == 400, 'original recovery cannot apply twice')
                        case['original_nonce_replay_status'] = replay_status
                        case['client_resolution'] = 'received replacement key retained' if stage == 'ack-received' else 'fresh public challenge and new confirmed recovery'
                    else:
                        current_key = key
                    after_account = ok(restored_port, 'GET', '/v1/accounts/me', key=current_key)
                    for field in ('owner', 'settledBalance', 'positions', 'nextNonce', 'nextWithdrawNonce', 'depositAddress', 'rebindCounter'):
                        require(after_account[field] == baseline_account[field], f'{field} retained without duplicate application')
                    case['account_balances_positions_order_and_withdraw_nonces_preserved'] = True
                    if operation == 'authorize':
                        observed = baseline_permit if server_response is None else server_response
                        require(re.fullmatch(r'0x[0-9a-fA-F]{130}', observed['sig']) is not None, 'server emitted signature')
                        # Read/validate an existing permit through the real route
                        # handler. It neither issues a signature nor credits funds.
                        routing = dict(permit, ownerCommit=observed['ownerCommit'])
                        for _ in range(2):
                            route = ok(restored_port, 'POST', '/v1/accounts/deposit/route', routing, current_key)
                            require(route['durability'] == 'confirmed' and route['ownerCommit'] == observed['ownerCommit'], 'same durable permit/routing retained')
                        changed = dict(routing, amount='2000000')
                        changed_status, _ = request(restored_port, 'POST', '/v1/accounts/deposit/route', changed, current_key)
                        require(changed_status == 400, 'existing permit cannot change amount')
                        case.update(same_permit_route_repeated=2, conflicting_route_status=changed_status,
                                    lost_permit_automatically_reissued=False, onchain_send_attempts=0)
                        case['client_resolution'] = {
                            'before-request-body': 'request body never sent; original baseline permit retained',
                            'response-lost': 'unresolved lost signature; no blind retry or on-chain send',
                            'ack-received': 'received authorization retained',
                        }[stage]
                    elif operation == 'cancel':
                        orders = ok(restored_port, 'GET', '/v1/orders', key=current_key)['orders']
                        require(len(orders) == 1 and orders[0]['orderId'] == order_id and orders[0]['receipt'] == receipt, 'single original receipt survives')
                        require(orders[0]['cancellable'] == (stage == 'before-request-body'), 'restored cancellability matches ACK boundary')
                        if stage != 'before-request-body':
                            require(orders[0]['execution']['status'] == 'CANCELLED', 'cancelled execution retained')
                            require(server_response['cancelled'] is True and server_response['cancelledSize'] == '10000000', 'one remainder cancelled before crash')
                        first_retry = ok(restored_port, 'DELETE', '/v1/orders/' + order_id, key=current_key)
                        require(first_retry['cancelledSize'] == '10000000', 'same historical cancellation receipt returned')
                        after_first = ok(restored_port, 'GET', '/v1/orders', key=current_key)['orders']
                        second_retry = ok(restored_port, 'DELETE', '/v1/orders/' + order_id, key=current_key)
                        require(second_retry == first_retry, 'idempotent cancellation repeats historical receipt')
                        final_orders = ok(restored_port, 'GET', '/v1/orders', key=current_key)['orders']
                        require(len(final_orders) == 1 and not final_orders[0]['cancellable'] and final_orders[0]['execution']['status'] == 'CANCELLED', 'retry resolves cancelled state')
                        require(final_orders[0]['execution'] == after_first[0]['execution'], 'retry adds no execution quantity')
                        require(final_orders[0]['execution']['filledSize'] == '0' and final_orders[0]['execution']['remainingSize'] == '0', 'no fill or remaining quantity created')
                        case.update(retry_historical_cancelled_size=first_retry['cancelledSize'], repeated_receipt_identical=True,
                                    retry_execution_unchanged=True, original_receipt_preserved=True,
                                    client_resolution='durable cancellation reconciled and idempotent retry confirmed')
                    final_account = ok(restored_port, 'GET', '/v1/accounts/me', key=current_key)
                    require(final_account == after_account, 'reconciliation/retry did not change account balances or nonces')
                    # A second abrupt restart proves the reconciliation itself was
                    # durable and was not merely observed in restored process RAM.
                    kill(restored)
                    final, final_port, _ = start(name + '-resolved', state, seed)
                    require(ok(final_port, 'GET', '/v1/accounts/me', key=current_key) == final_account, 'resolved credential/account survives second SIGKILL')
                    if operation == 'cancel':
                        rows = ok(final_port, 'GET', '/v1/orders', key=current_key)['orders']
                        require(len(rows) == 1 and rows[0]['execution']['status'] == 'CANCELLED' and not rows[0]['cancellable'], 'resolved cancellation survives second SIGKILL')
                    kill(final)
                    case.update(second_sigkill_resolution_retained=True, status='PASS')
                    evidence['cases'].append(case)
                    print(json.dumps(case), flush=True)
        require(len(evidence['cases']) == 9, 'all nine operation/boundary cases ran')
        require(sha256(binary) == evidence['binary_sha256'], 'same executable throughout matrix')
        require(sha256(Path(__file__)) == evidence['script_sha256'], 'same test script throughout matrix')
        evidence['status'] = 'PASS'
    except Exception as error:
        evidence['status'] = 'FAIL'
        # Only our fixed assertion labels are included, never wire responses.
        evidence['failure_type'] = type(error).__name__
        if isinstance(error, (AssertionError, TimeoutError)):
            evidence['failure_check'] = str(error)
        raise
    finally:
        # A proxy teardown failure must never skip owned-process cleanup or
        # suppress the original assertion. Persist only fixed labels/types.
        previous_failure = evidence['status'] == 'FAIL'
        cleanup_errors = []
        for index, proxy in enumerate(proxies):
            try:
                proxy.finish()
            except Exception as error:
                cleanup_errors.append({'kind': 'proxy', 'index': index, 'error_type': type(error).__name__})
        cleanup = []
        for child in children:
            forced = child.poll() is None
            try:
                if forced:
                    child.kill()
                    child.wait(timeout=10)
            except Exception as error:
                cleanup_errors.append({'kind': 'owned-process', 'pid': child.pid, 'error_type': type(error).__name__})
            cleanup.append({'pid': child.pid, 'exit_code': child.returncode, 'failure_cleanup': forced})
        if cleanup_errors:
            evidence['status'] = 'FAIL'
            evidence['cleanup_errors'] = cleanup_errors
        evidence['owned_processes'] = cleanup
        evidence['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (out / 'result.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if cleanup_errors and not previous_failure:
            raise RuntimeError('owned fixture cleanup failed; inspect redacted result')


if __name__ == '__main__':
    main()
