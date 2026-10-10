"""CPU-only regression coverage for manifest-bound operator/settlement policy."""
import copy
import json
import unittest
from unittest.mock import patch

import release_manifest as release
import test_release_manifest as existing


def policy():
    value = {role: {name: '0x' + '00' * 19 + '01' for name in fields}
             for role, fields in release.OPERATOR_ADDRESSES.items()}
    value['settlement'].update({name: 1 for name in release.SETTLEMENT_POLICY})
    return value


class PolicyConfigTests(unittest.TestCase):
    def test_complete_policy_is_normalized_and_part_of_public_config_digest(self):
        config = existing.config()
        before = release.digest(release.canonical(release.public_config(config)))
        config['operator_policy'] = policy()
        config['operator_policy']['settlement']['sequencer'] = '0x' + 'AB' * 20
        result = release.public_config(config)
        self.assertEqual(result['operator_policy']['settlement']['sequencer'], '0x' + 'ab' * 20)
        self.assertNotEqual(before, release.digest(release.canonical(result)))
        for role, fields in result['operator_policy'].items():
            for name, old in fields.items():
                changed = copy.deepcopy(result)
                changed['operator_policy'][role][name] = old + 1 if type(old) is int else '0x' + 'fe' * 20
                with self.subTest(role=role, field=name):
                    self.assertNotEqual(release.canonical(result), release.canonical(release.public_config(changed)))

    def test_missing_role_or_any_field_has_no_inferred_default(self):
        for role, fields in policy().items():
            missing = policy()
            del missing[role]
            with self.subTest(role=role), self.assertRaises(ValueError):
                release.operator_policy(missing)
            for name in fields:
                missing = policy()
                del missing[role][name]
                with self.subTest(role=role, field=name), self.assertRaises(ValueError):
                    release.operator_policy(missing)

    def test_wrong_types_extra_fields_and_secret_values_are_not_echoed(self):
        for value in (None, [], '', True, {'secret': 'private-sentinel'}):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError) as raised:
                release.operator_policy(value)
            self.assertNotIn('private-sentinel', str(raised.exception))
        for role in policy():
            value = policy()
            value[role]['private_key'] = 'private-sentinel'
            with self.subTest(role=role), self.assertRaises(ValueError) as raised:
                release.operator_policy(value)
            self.assertNotIn('private-sentinel', str(raised.exception))
        config = existing.config()
        config['operator_policy'] = None
        with self.assertRaises(ValueError):
            release.public_config(config)

    def test_addresses_require_full_abi_shape(self):
        for role, fields in release.OPERATOR_ADDRESSES.items():
            for name in fields:
                for bad in (1, None, '0x01', '0x' + 'gg' * 20, 'private-sentinel'):
                    value = policy()
                    value[role][name] = bad
                    with self.subTest(role=role, field=name), self.assertRaises(ValueError) as raised:
                        release.operator_policy(value)
                    self.assertNotIn('private-sentinel', str(raised.exception))

    def test_uint256_policy_is_exact_and_does_not_accept_bool_float_or_string(self):
        for name in release.SETTLEMENT_POLICY:
            for bad in (True, False, 1.0, '1', -1, 2**256, None):
                value = policy()
                value['settlement'][name] = bad
                with self.subTest(field=name, value=bad), self.assertRaises(ValueError):
                    release.operator_policy(value)
            value = policy()
            value['settlement'][name] = 2**256 - 1
            self.assertEqual(release.operator_policy(value)['settlement'][name], 2**256 - 1)

    def test_explicit_zero_is_preserved_not_approved_as_economically_safe(self):
        value = policy()
        for role, fields in release.OPERATOR_ADDRESSES.items():
            value[role].update({name: '0x' + '00' * 20 for name in fields})
        value['settlement'].update({name: 0 for name in release.SETTLEMENT_POLICY})
        self.assertEqual(release.operator_policy(value), value)


class PolicyTargetTests(unittest.TestCase):
    # Reuse the injected transport/artifact harness, not its test methods. The
    # independent owned-Anvil integration also exercises real ABI/runtime reads.
    setUp = existing.TargetTests.setUp
    rpc = existing.TargetTests.rpc
    word = staticmethod(existing.TargetTests.word)

    def observe(self, required=False):
        return release.observe_target(self.root, self.manifest, self.public, self.rpc,
                                      require_operator_policy=required)

    def test_legacy_observation_cannot_claim_policy_match(self):
        result = self.observe()
        self.assertEqual(result['status'], 'VERIFIED_AT_FINALIZED_BLOCK')
        self.assertFalse(result['scope']['operator_and_settlement_policy_matches'])
        self.assertNotIn('operator_policy_sha256', result)

    def test_required_missing_policy_stops_before_any_rpc(self):
        result = self.observe(required=True)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('explicit operator policy required', result['blocker'])
        self.assertEqual(self.calls, [])

    def test_complete_policy_checks_all_eleven_getters_at_same_block(self):
        self.public['operator_policy'] = policy()
        result = self.observe(required=True)
        self.assertEqual(result['status'], 'VERIFIED_AT_FINALIZED_BLOCK', result)
        self.assertTrue(result['scope']['operator_and_settlement_policy_matches'])
        self.assertFalse(result['scope']['operator_and_settlement_policy_approved'])
        self.assertEqual(result['scope']['release_gate'], 'HOLD')
        self.assertEqual(len(result['bindings']), 23)
        self.assertEqual(result['operator_policy_sha256'], release.digest(release.canonical(policy())))
        self.assertTrue(all(params[-1] == {'blockHash': self.head['hash'], 'requireCanonical': True}
                            for method, params in self.calls if method in ('eth_call', 'eth_getCode')))

    def test_each_address_and_economic_policy_mismatch_blocks(self):
        self.public['operator_policy'] = policy()
        fields = [(role, signature) for role, values in release.OPERATOR_ADDRESSES.items()
                  for signature in values.values()]
        fields += [('settlement', signature) for signature in release.SETTLEMENT_POLICY.values()]
        for field in fields:
            self.values[field] = 2
            with self.subTest(field=field):
                result = self.observe(required=True)
                self.assertEqual(result['status'], 'BLOCKED')
                self.assertIn('target binding mismatch', result['blocker'])
                self.assertFalse(result['scope']['operator_and_settlement_policy_matches'])
                self.assertFalse(result['scope']['runtime_bytecode_verified'])
            del self.values[field]

    def test_explicit_zero_policy_is_actually_compared(self):
        self.public['operator_policy'] = policy()
        self.public['operator_policy']['settlement']['challenge_bond_wei'] = 0
        self.public['operator_policy']['settlement']['governance'] = '0x' + '00' * 20
        self.assertEqual(self.observe()['status'], 'BLOCKED')
        self.values[('settlement', 'challengeBond()')] = 0
        self.values[('settlement', 'governance()')] = 0
        result = self.observe()
        self.assertEqual(result['status'], 'VERIFIED_AT_FINALIZED_BLOCK', result)
        self.assertTrue(result['scope']['operator_and_settlement_policy_matches'])
        self.assertFalse(result['scope']['operator_and_settlement_policy_approved'])

    def test_late_source_or_chain_change_cannot_leave_policy_match_true(self):
        self.public['operator_policy'] = policy()
        self.validate.side_effect = [self.manifest, ValueError('release manifest mismatch')]
        result = self.observe()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['scope']['operator_and_settlement_policy_matches'])
        self.validate.side_effect = None
        self.overrides['eth_getBlockByNumber'] = lambda params: (
            self.head if params[0] == 'finalized' else {**self.head, 'hash': '0x' + 'ff' * 32})
        result = self.observe()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['scope']['operator_and_settlement_policy_matches'])

    def test_malformed_required_flag_fails_before_rpc(self):
        for value in (1, None, 'true'):
            result = self.observe(required=value)
            self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(self.calls, [])


class StrictJsonTransportTests(unittest.TestCase):
    def test_duplicate_keys_and_nonfinite_values_are_rejected_without_echo(self):
        cases = [b'{"jsonrpc":"2.0","id":1,"id":1,"result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":1,"result":"private-sentinel","result":"0x1"}',
                 b'{"jsonrpc":"2.0","id":1,"result":{"a":1,"a":2}}',
                 b'{"jsonrpc":"2.0","id":1,"result":NaN}',
                 b'{"jsonrpc":"2.0","id":1,"result":Infinity}',
                 b'{"jsonrpc":"2.0","id":1,"result":-Infinity}']
        for body in cases:
            rpc = release.TargetRPC('https://example.invalid')
            response = unittest.mock.MagicMock()
            response.__enter__.return_value.read.return_value = body
            with self.subTest(body=body), patch.object(rpc.opener, 'open', return_value=response):
                with self.assertRaises(ValueError) as raised:
                    rpc('eth_chainId', [])
                self.assertNotIn('private-sentinel', str(raised.exception))

    def test_standard_response_still_works(self):
        rpc = release.TargetRPC('https://example.invalid')
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"jsonrpc":"2.0","id":1,"result":"0x1"}'
        with patch.object(rpc.opener, 'open', return_value=response):
            self.assertEqual(rpc('eth_chainId', []), '0x1')


if __name__ == '__main__':
    unittest.main()
