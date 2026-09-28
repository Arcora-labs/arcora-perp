#!/usr/bin/env python3
"""Owned loopback gateway SIGTERM / accepted-HTTP / durable restart drill.

No L1, prover, wallet or user credentials. API keys stay only in process memory.
Public demo oracle/candle reads remain enabled; this is not network isolation.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def wait_until(predicate, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise TimeoutError(label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', required=True, type=Path)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'docs/audits/2026-09-28-runtime/gateway-process')
    args = parser.parse_args()
    binary = args.gateway_bin.resolve()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    evidence = {'status': 'RUNNING', 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'scope': 'Real owned gateway processes, HTTP sockets, SIGTERM and encrypted snapshot restart; demo only, no L1/proof', 'cases': []}
    children = []
    record_path = out / 'result.json'
    try:
        with tempfile.TemporaryDirectory(prefix='arcora-drain-') as directory:
            scratch = Path(directory)
            base_env = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
            base_env.update(GATEWAY_BIND_ADDRESS='127.0.0.1', PORT='0', GATEWAY_HTTP_BODY_TIMEOUT_MS='1500')

            def start(name, state=None):
                env = dict(base_env)
                if state is not None:
                    env['DARKPERP_STATE'] = str(state)
                log = out / f'{name}.log'
                with log.open('wb') as stream:
                    process = subprocess.Popen([str(binary)], cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
                children.append(process)
                def listening():
                    if process.poll() is not None:
                        raise RuntimeError(f'{name} stopped before listening: {process.returncode}')
                    found = re.search(r'listening on (http://127\.0\.0\.1:\d+)', log.read_text())
                    return found.group(1) if found else None
                url = wait_until(listening, 15, f'{name} listen')
                return process, url, log

            def stop(process, log):
                process.send_signal(signal.SIGTERM)
                wait_until(lambda: '[shutdown] admission closed;' in log.read_text(), 3, 'SIGTERM admission barrier')

            def finish(process, log):
                code = process.wait(timeout=30)
                if code != 0 or '[shutdown] drain complete — exiting 0' not in log.read_text():
                    raise AssertionError(f'unclean drain: {code}')
                return code

            for persist in (True, False):
                name = 'persistent' if persist else 'memory-only'
                state = scratch / f'{name}.snapshot' if persist else None
                process, url, log = start(name, state)
                port = int(url.rsplit(':', 1)[1])
                with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
                    # HTTP 100 Continue proves the real middleware is polling this
                    # accepted body before SIGTERM. No timing-based admission guess.
                    connection.sendall((f'POST /v1/accounts HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                                        'Content-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n').encode())
                    interim = b''
                    while not interim.endswith(b'\r\n\r\n'):
                        byte = connection.recv(1)
                        if not byte:
                            raise AssertionError('no interim response')
                        interim += byte
                    assert interim.startswith(b'HTTP/1.1 100 Continue'), interim
                    stop(process, log)
                    assert process.poll() is None, 'exited before admitted request finished'
                    connection.sendall(b'{}')
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    account = json.loads(response.read())
                    assert response.status == 200 and re.fullmatch('0x[0-9a-fA-F]{64}', account['apiKey'])
                case = {'case': name, 'admission_barrier': 'HTTP 100 Continue', 'accepted_response_status': response.status,
                        'process_alive_after_signal_before_body_complete': True, 'exit_code': finish(process, log)}
                if persist:
                    assert state.is_file()
                    case['snapshot_sha256'] = hashlib.sha256(state.read_bytes()).hexdigest()
                    restored, restored_url, restored_log = start(name + '-restored', state)
                    request = urllib.request.Request(restored_url + '/v1/accounts/me', headers={'X-Api-Key': account['apiKey']})
                    with urllib.request.urlopen(request, timeout=5) as reply:
                        restored_account = json.loads(reply.read())
                        assert restored_account['owner'] == account['owner'] and restored_account['recoveryNonce'] == 0
                        case['restored_original_credential_status'] = reply.status
                    stop(restored, restored_log)
                    case['restored_exit_code'] = finish(restored, restored_log)
                evidence['cases'].append(case)
                print(json.dumps(case), flush=True)

            process, url, log = start('stalled-body', scratch / 'stalled.snapshot')
            port = int(url.rsplit(':', 1)[1])
            with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
                connection.sendall((f'POST /v1/accounts HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                                    'Content-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n').encode())
                interim = b''
                while not interim.endswith(b'\r\n\r\n'):
                    byte = connection.recv(1)
                    if not byte:
                        raise AssertionError('no interim response')
                    interim += byte
                assert interim.startswith(b'HTTP/1.1 100 Continue'), interim
                stop(process, log)
                response = http.client.HTTPResponse(connection)
                response.begin()
                response.read()
                assert response.status == 408
            case = {'case': 'stalled-body', 'body_timeout_status': response.status, 'exit_code': finish(process, log)}
            evidence['cases'].append(case)
            print(json.dumps(case), flush=True)
        evidence['status'] = 'PASS'
    except Exception as error:
        evidence['status'] = 'FAIL'
        # Do not serialize response bodies or request headers containing test keys.
        evidence['failure_type'] = type(error).__name__
        raise
    finally:
        cleanup = []
        for child in children:
            forced = False
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    forced = True
            cleanup.append({'pid': child.pid, 'exit_code': child.returncode, 'forced_cleanup': forced})
        evidence['owned_processes'] = cleanup
        record_path.write_text(json.dumps(evidence, indent=2) + '\n')


if __name__ == '__main__':
    main()
