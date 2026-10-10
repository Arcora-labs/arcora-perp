#!/usr/bin/env python3
"""Relocate an actual encrypted gateway snapshot into fresh local directories.

Only newly owned demo processes, temporary data and generated test credentials.
No external RPC/keys can be supplied. No proof, transaction or live-funds claim.
Public demo price reads are not disabled; this is not outbound network isolation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

from gateway_ack_crash_drill import ok, request, sign

ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_FIELDS = ('owner', 'settledBalance', 'positions', 'nextNonce',
                  'nextWithdrawNonce', 'depositAddress', 'rebindCounter', 'recoveryNonce')


class DrillFailure(AssertionError):
    """Only fixed, non-sensitive assertion labels from this module."""


def require(condition, label):
    if not condition:
        raise DrillFailure(label)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def account_checkpoint(value):
    require(isinstance(value, dict) and all(key in value for key in ACCOUNT_FIELDS),
            'complete account checkpoint required')
    return {key: value[key] for key in ACCOUNT_FIELDS}


def verify_account(expected, actual):
    # JSON comparison keeps booleans distinct from integers and rejects missing
    # fields; a recovery comparison must not silently discard an absent field.
    require(json.dumps(account_checkpoint(expected), sort_keys=True) ==
            json.dumps(account_checkpoint(actual), sort_keys=True), 'account checkpoint retained')


def verify_order(expected, rows):
    require(isinstance(rows, list) and len(rows) == 1, 'exactly one original order retained')
    current = rows[0]
    require(isinstance(current, dict) and all(key in current for key in ('orderId', 'receipt', 'execution', 'cancellable')),
            'complete order checkpoint required')
    require(current['orderId'] == expected['orderId'] and
            json.dumps(current['receipt'], sort_keys=True) == json.dumps(expected['receipt'], sort_keys=True),
            'original acceptance receipt retained')
    require(current['cancellable'] is False and
            json.dumps(current['execution'], sort_keys=True) == json.dumps(expected['execution'], sort_keys=True),
            'cancelled execution retained without duplication')


class OwnedGateways:
    def __init__(self, binary, scratch):
        self.binary, self.scratch, self.children = binary, scratch, []

    def launch(self, name, state, seed, *, required=None, checkpoint=None):
        directory = self.scratch / name
        directory.mkdir()
        log = directory / 'gateway.log'
        env = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
        env.update(GATEWAY_BIND_ADDRESS='127.0.0.1', PORT='0', ENCLAVE_SEED=seed,
                   GATEWAY_HTTP_BODY_TIMEOUT_MS='10000')
        if state is not None:
            env['DARKPERP_STATE'] = str(state)
        if required is not None:
            env['DARKPERP_REQUIRE_RESTORE'] = required
        if checkpoint is not None:
            env['DARKPERP_RESTORE_SHA256'] = checkpoint
        with log.open('wb') as output:
            child = subprocess.Popen([str(self.binary)], cwd=directory, env=env,
                                     stdout=output, stderr=subprocess.STDOUT)
        self.children.append((name, child, log))
        return child, log

    @staticmethod
    def ready(child, log):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(child.poll() is None, 'owned restore exited before readiness')
            found = re.search(r'listening on http://127\.0\.0\.1:(\d+)', log.read_text())
            if found:
                return int(found.group(1))
            time.sleep(.01)
        raise TimeoutError('owned restore readiness deadline')

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.kill()  # A handle returned only by this object's Popen.
        child.wait(timeout=10)

    def refusal(self, name, state, seed, **options):
        existed = state is not None and state.exists()
        before = sha(state.read_bytes()) if state is not None and state.is_file() else None
        child, log = self.launch(name, state, seed, **options)
        deadline = time.monotonic() + 20
        while child.poll() is None and time.monotonic() < deadline:
            require('listening on http://' not in log.read_text(), 'refused restore never serves HTTP')
            time.sleep(.01)
        require(child.poll() == 1, 'invalid restore exits with code 1')
        text = log.read_text()
        require('REFUSING to start' in text and 'listening on http://' not in text,
                'explicit startup refusal before listener')
        if before is not None:
            require(state.is_file() and sha(state.read_bytes()) == before, 'refused input preserved byte-for-byte')
        if state is not None and not existed:
            require(not state.exists(), 'refused missing input was not replaced with a fresh snapshot')
        return {'case': name, 'status': 'PASS', 'exit_code': 1, 'listener_started': False,
                'existing_snapshot_preserved': before is not None}

    def close(self):
        errors, result = [], []
        for name, child, _ in self.children:
            forced = child.poll() is None
            try:
                self.stop(child)
            except Exception as error:
                errors.append({'case': name, 'error_type': type(error).__name__})
            result.append({'case': name, 'exit_code': child.returncode, 'failure_cleanup': forced})
        return result, errors


def run(binary, out):
    require(binary.is_file(), 'existing gateway binary required')
    out.mkdir(parents=True, exist_ok=False)
    result = {'status': 'RUNNING', 'binary_sha256': sha(binary.read_bytes()),
              'script_sha256': sha(Path(__file__).read_bytes()), 'cases': [], 'restore_samples': [],
              'scope': 'Same-machine, fresh-directory restore of real gateway snapshots in disposable demo mode.',
              'release_gate': 'HOLD', 'fresh_proof_generated': False, 'public_chain_transactions': 0,
              'independent_machine': False, 'production_rto_rpo_measured': False,
              'limitations': ['Checkpoint trust is supplied by this test, not an independent signed backup authority.',
                             'Hash matching does not establish latest state: an older valid snapshot with its own trusted pin remains valid.',
                             'Snapshots only; no production rollback journal, L1 cursors, remote backup store or hardware key release.',
                             'RTO samples cover local copy to verified HTTP state, not detection, provisioning or key recovery.',
                             'Zero lost checked observations is not a fleet RPO or unacknowledged-write guarantee.',
                             'Demo collateral, no real funds withdrawal or operator-loss exit; public price reads may occur.']}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='arcora-owned-restore-') as name:
            scratch = Path(name)
            owned = OwnedGateways(binary, scratch)
            try:
                seed, wallet_key = secrets.token_hex(32), secrets.token_hex(32)
                missing = scratch / 'absent.snapshot'
                for label, state, options in (
                    ('missing-state-setting', None, {'required': '1'}),
                    ('missing-snapshot', missing, {'required': '1'}),
                    ('pin-alone-requires-snapshot', missing, {'checkpoint': 'ab' * 32}),
                    ('invalid-mode', missing, {'required': 'typo'}),
                    ('invalid-checkpoint', missing, {'checkpoint': 'not-a-sha256'}),
                ):
                    result['cases'].append(owned.refusal(label, state, seed, **options))
                state = scratch / 'source.snapshot'
                child, log = owned.launch('source-process', state, seed)
                port = owned.ready(child, log)
                account = ok(port, 'POST', '/v1/accounts', {})
                old_key = account['apiKey']
                address = sign(wallet_key, 'address')['address']
                binding = sign(wallet_key, 'bind', owner=account['owner'])['signature']
                ok(port, 'POST', '/v1/accounts/deposit/address', {'address': address, 'signature': binding}, old_key)
                ok(port, 'POST', '/v1/accounts/deposit', {'marketId': 0, 'amount': '20000000000'}, old_key)
                ok(port, 'POST', '/v1/orders', {'marketId': 0, 'side': 'Buy', 'size': '10000000',
                   'limitPrice': '1000000', 'tif': 'Gtc', 'reduceOnly': False}, old_key)
                rows = ok(port, 'GET', '/v1/orders', key=old_key)['orders']
                require(len(rows) == 1 and rows[0]['cancellable'], 'one unfilled order before checkpoint')
                order_id = rows[0]['orderId']
                permit_body = {'from': address, 'amount': '1000000', 'marketId': 0, 'purpose': 'collateral'}
                permit = ok(port, 'POST', '/v1/accounts/deposit/authorize', permit_body, old_key)
                older = state.read_bytes()  # A valid snapshot before durable credential rotation.
                ok(port, 'DELETE', '/v1/orders/' + order_id, key=old_key)
                challenge = ok(port, 'GET', '/v1/accounts/recovery/' + account['owner'])
                recovery_body = {'owner': account['owner'], 'nonce': challenge['recoveryNonce'],
                    'signature': sign(wallet_key, 'recovery', owner=account['owner'],
                                      chainId=challenge['chainId'], vault=challenge['vault'],
                                      nonce=challenge['recoveryNonce'])['signature']}
                recovery = ok(port, 'POST', '/v1/accounts/recovery', recovery_body)
                require(recovery['durability'] == 'confirmed' and recovery['recoveryNonce'] == 1,
                        'credential rotation durably acknowledged')
                current_key = recovery['apiKey']
                expected = ok(port, 'GET', '/v1/accounts/me', key=current_key)
                expected_order = ok(port, 'GET', '/v1/orders', key=current_key)['orders'][0]
                require(expected_order['execution']['status'] == 'CANCELLED', 'cancelled checkpoint baseline')
                owned.stop(child)
                latest = state.read_bytes()
                require(latest.startswith(b'DPSNAP9\0') and older != latest, 'distinct authenticated checkpoint generations')
                latest_hash = sha(latest)
                result['checkpoint_sha256'] = latest_hash
                result['older_checkpoint_sha256'] = sha(older)
                # Remove the original configured pathname. Later processes receive
                # only another directory's snapshot path, never the original path.
                state.rename(scratch / 'archived-original.snapshot')
                require(not state.exists(), 'original configured path absent during restore')
                for label, content, test_seed, options in (
                    ('wrong-seed', latest, secrets.token_hex(32), {'required': '1', 'checkpoint': latest_hash}),
                    ('truncated-snapshot', latest[:31], seed, {'required': '1'}),
                    ('tampered-snapshot', latest[:-1] + bytes([latest[-1] ^ 1]), seed, {'required': '1'}),
                    ('stale-checkpoint', older, seed, {'required': '1', 'checkpoint': latest_hash}),
                    ('wrong-checkpoint', latest, seed, {'checkpoint': '00' * 32}),
                    ('flag-zero-cannot-disable-pin', older, seed, {'required': '0', 'checkpoint': latest_hash}),
                ):
                    bad = scratch / (label + '.snapshot')
                    bad.write_bytes(content)
                    result['cases'].append(owned.refusal(label, bad, test_seed, **options))
                result['cases'].append(owned.refusal('directory-not-snapshot', scratch, seed, required='1'))
                selected = latest
                for number in (1, 2):
                    destination = scratch / ('restore-data-' + str(number))
                    destination.mkdir()
                    restored_state = destination / 'gateway.snapshot'
                    copy_started = time.monotonic()
                    restored_state.write_bytes(selected)
                    checkpoint_hash = sha(selected)
                    restored, restored_log = owned.launch('restored-process-' + str(number), restored_state,
                                                         seed, required='1', checkpoint=checkpoint_hash)
                    restored_port = owned.ready(restored, restored_log)
                    require('[state] restored sealed snapshot from ' in restored_log.read_text(), 'actual snapshot startup path used')
                    verify_account(expected, ok(restored_port, 'GET', '/v1/accounts/me', key=current_key))
                    verify_order(expected_order, ok(restored_port, 'GET', '/v1/orders', key=current_key)['orders'])
                    require(request(restored_port, 'GET', '/v1/accounts/me', key=old_key)[0] == 401,
                            'revoked API key stays revoked')
                    require(request(restored_port, 'POST', '/v1/accounts/recovery', recovery_body)[0] == 400,
                            'used recovery signature cannot replay')
                    routing = dict(permit_body, ownerCommit=permit['ownerCommit'])
                    route = ok(restored_port, 'POST', '/v1/accounts/deposit/route', routing, current_key)
                    require(route['durability'] == 'confirmed' and route['ownerCommit'] == permit['ownerCommit'],
                            'original durable deposit route preserved')
                    retry = ok(restored_port, 'DELETE', '/v1/orders/' + order_id, key=current_key)
                    require(retry['cancelledSize'] == '10000000', 'idempotent cancellation receipt preserved')
                    verify_account(expected, ok(restored_port, 'GET', '/v1/accounts/me', key=current_key))
                    verify_order(expected_order, ok(restored_port, 'GET', '/v1/orders', key=current_key)['orders'])
                    elapsed = time.monotonic() - copy_started
                    result['restore_samples'].append({'attempt': number, 'status': 'PASS',
                        'checkpoint_sha256': checkpoint_hash, 'copy_to_verified_state_seconds': round(elapsed, 6),
                        'account_fields_preserved': len(ACCOUNT_FIELDS), 'original_order_receipt_preserved': True,
                        'revoked_key_status': 401, 'recovery_replay_status': 400,
                        'confirmed_observations_lost': 0, 'original_configured_path_absent': not state.exists()})
                    owned.stop(restored)
                    selected = restored_state.read_bytes()
                    # The periodic writer may reseal identical state with a new
                    # nonce. Pin the selected checkpoint for the next startup.
                require(len(result['cases']) == 12 and len(result['restore_samples']) == 2, 'complete restore matrix')
                require(sha(binary.read_bytes()) == result['binary_sha256'], 'binary unchanged during drill')
                require(sha(Path(__file__).read_bytes()) == result['script_sha256'], 'script unchanged during drill')
                result['status'] = 'PASS'
            finally:
                processes, errors = owned.close()
                result['owned_processes'] = processes
                if errors:
                    result['status'] = 'FAIL'
                    result['cleanup_errors'] = errors
                    raise RuntimeError('owned process cleanup failed')
    except Exception as error:
        result['status'] = 'FAIL'
        result['failure_type'] = type(error).__name__
        if isinstance(error, DrillFailure):
            result['failure_check'] = str(error)
        # Do not serialize exception text: dependencies can include wire data,
        # request content or generated credentials in error messages.
        raise
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway-bin', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.gateway_bin.resolve(), args.output_dir.resolve())
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'failure_type': type(error).__name__}), flush=True)
        raise SystemExit(1) from None
    print(json.dumps({'status': report['status'], 'refusal_cases': len(report['cases']),
                      'restore_samples': report['restore_samples'], 'release_gate': report['release_gate']}), flush=True)


if __name__ == '__main__':
    main()
