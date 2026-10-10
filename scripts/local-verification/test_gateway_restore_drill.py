"""Pure evidence assertions; process integration is the owned gateway drill."""
import copy
import unittest

import gateway_restore_drill as drill


class RestoreEvidenceTests(unittest.TestCase):
    def account(self):
        return {key: ([] if key == 'positions' else 1) for key in drill.ACCOUNT_FIELDS}

    def order(self):
        return {'orderId': 'order-fixture', 'receipt': {'sequence': 1}, 'cancellable': False,
                'execution': {'status': 'CANCELLED', 'filledSize': '0', 'remainingSize': '0'}}

    def test_complete_same_account_is_accepted(self):
        value = self.account()
        drill.verify_account(value, copy.deepcopy(value))

    def test_every_missing_account_field_is_rejected(self):
        expected = self.account()
        for key in expected:
            actual = dict(expected)
            del actual[key]
            with self.subTest(field=key), self.assertRaises(drill.DrillFailure):
                drill.verify_account(expected, actual)

    def test_every_changed_account_field_is_rejected(self):
        expected = self.account()
        for key in expected:
            actual = copy.deepcopy(expected)
            actual[key] = 'changed'
            with self.subTest(field=key), self.assertRaises(drill.DrillFailure):
                drill.verify_account(expected, actual)

    def test_boolean_cannot_impersonate_integer_nonce(self):
        expected = self.account()
        actual = dict(expected, recoveryNonce=True)
        with self.assertRaises(drill.DrillFailure):
            drill.verify_account(expected, actual)

    def test_same_cancelled_order_is_accepted(self):
        expected = self.order()
        drill.verify_order(expected, [copy.deepcopy(expected)])

    def test_missing_extra_or_changed_order_is_rejected(self):
        expected = self.order()
        cases = [[], [expected, expected], [dict(expected, orderId='other')],
                 [dict(expected, cancellable=True)], [dict(expected, receipt={'sequence': True})],
                 [dict(expected, execution={'status': 'FILLED'})], [{}], [None]]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(drill.DrillFailure):
                drill.verify_order(expected, rows)

    def test_fixed_failure_labels_do_not_echo_checkpoint_contents(self):
        actual = dict(self.account(), owner='private-sentinel')
        with self.assertRaises(drill.DrillFailure) as error:
            drill.verify_account(self.account(), actual)
        self.assertNotIn('private-sentinel', str(error.exception))


if __name__ == '__main__':
    unittest.main()
