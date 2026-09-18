"""Materialize the checksum-locked A04 patch and its reviewed history hardening."""
import base64
import hashlib
import json
import lzma
from pathlib import Path
import re
import subprocess

p = Path('.remediation-a04')
encoded = ''.join((p / f'part{i}.b64').read_text().strip() for i in (1, 2, 3))
patch = lzma.decompress(base64.b64decode(encoded, validate=True))
assert hashlib.sha256(patch).hexdigest() == '3dd64f15433553c2c24f9dcb8bc1507f20ff3cd9157c72b81649356d1c002bdc'
allowed = {'crates/gateway/src/audit_cancellation_tests.rs', 'crates/gateway/src/main.rs',
           'crates/matcher/src/book.rs', 'crates/sequencer/src/cancellation.rs',
           'crates/sequencer/src/cancellation/tests.rs', 'crates/sequencer/src/lib.rs',
           'frontend/src/api/clientContract.test.ts', 'frontend/src/api/mockClient.ts',
           'frontend/src/api/realClient.test.ts', 'frontend/src/api/realClient.ts',
           'frontend/src/components/Tables.tsx', 'frontend/src/components/demoGates.test.tsx',
           'frontend/src/domain/cancellation.ts', 'frontend/src/domain/types.ts'}
seen = set()
for chunk in patch.decode().split('diff --git ')[1:]:
    line = chunk.splitlines()[0]
    match = re.fullmatch(r'a/(\S+) b/(\S+)', line)
    assert match and match[1] == match[2] and match[1] in allowed, line
    path = match[1]
    before = re.search(r'^index ([0-9a-f]{40})\.\.', chunk, re.M)[1]
    if before == '0' * 40:
        assert not Path(path).exists(), path
    else:
        actual = subprocess.check_output(['git', 'hash-object', path], text=True).strip()
        assert before == actual, f'base file changed: {path}'
    seen.add(path)
assert seen == allowed
(p / 'candidate.patch').write_bytes(patch)
subprocess.run(['git', 'apply', '--check', str(p / 'candidate.patch')], check=True)
subprocess.run(['git', 'apply', '--index', str(p / 'candidate.patch')], check=True)
api = Path('docs/API.md')
text = api.read_text()
old = '''**Cancel is effectively pre-seal only.** `DELETE /v1/orders/:orderId` refuses any
order already **sealed** into a batch — even while its finality is still
`ACCEPTED` — and every resting order seals within one sequencer tick (~700 ms).
So in practice only an order cancelled immediately after submission succeeds;
cancelling a resting order returns the refusal until cancel-inside-the-window
lands (SEC-025-E2).'''
new = '''**Cancellation uses the live remainder, not finality.** A pending order or a
resting maker remainder can be cancelled, including after a partial fill is
MATCHED or SETTLED. Prior fills and position balances are not reversed.
GET /v1/orders includes the authenticated owner's `cancellable` capability.
DELETE returns `{ orderId, cancelled: true, cancelledSize }`, with the exact
removed size as a decimal string. The cancelled row leaves the order list;
complete cancellation history and cumulative fill/VWAP accounting remain A05.

The gateway serializes cancellation and the entire matching tick under the
same state mutex. The existing Cancelled reason enters the current window
manifest. Proof-v1 replays accounting and commits that manifest; it does not
independently prove cancellation authorization or CLOB matching fairness.

Production without persistence refuses cancellation before mutation (503).
With persistence, success waits for a durable snapshot ACK. Write failure or
timeout returns 503 with `durability: "unknown"`; the in-memory quote remains
removed, but restart durability is unconfirmed. Do not infer safe replacement
from an empty order list after this error. Obtain confirmed durable state
before replacing the quote. Snapshot acknowledgement is not L1 settlement.'''
assert text.count(old) == 1
text = text.replace(old, new)
old_row = 'cancel a still-`ACCEPTED` order **that has not yet sealed into a batch** (see the cancel note below)'
assert text.count(old_row) == 1
api.write_text(text.replace(old_row, 'cancel a pending order or live maker remainder (see the cancel note below)'))
allowed.add('docs/API.md')
(p / 'allowed.json').write_text(json.dumps(sorted(allowed)))

source = Path('crates/gateway/src/main.rs')
text = source.read_text()
old = '''/// Cap on retained per-account order history. SETTLED orders are terminal display data;
/// without a bound the Vec (and every snapshot) grows forever on a long-lived deployment.'''
new = '''/// Soft cap on retained per-account order history. A SETTLED partial fill can still
/// have a live remainder: only sealed orders absent from the book may be evicted.
/// Live orders take priority over the history cap so their cancellation stays reachable.'''
assert text.count(old) == 1, 'history cap comment changed'
text = text.replace(old, new)
old = '''            // audit Tier-3: bound the retained order history so it (and every snapshot)
            // can't grow without limit. Runs AFTER the seal/finality passes above (which
            // reference orders by index), and only evicts SETTLED (terminal, display-only)
            // orders — live/pending orders and the account's replay nonce are untouched.
            cap_history(&mut acct.orders, MAX_ACCOUNT_ORDER_HISTORY, |o| {
                o.last_finality == "SETTLED"
            });'''
new = '''            // A04: SETTLED is a finality axis, not proof of full execution. Never
            // evict the only API row for a still-live partial maker. Gather its live
            // hashes once (only when pruning is needed), not once per history row.
            if acct.orders.len() > MAX_ACCOUNT_ORDER_HISTORY {
                let live: std::collections::BTreeSet<Digest> = self
                    .mkts
                    .iter()
                    .filter_map(|m| self.seq.book(m.id))
                    .flat_map(|book| book.resting_hashes_for(&acct.wallet.owner))
                    .collect();
                cap_history(&mut acct.orders, MAX_ACCOUNT_ORDER_HISTORY, |o| {
                    o.sealed && o.last_finality == "SETTLED" && !live.contains(&o.order_hash)
                });
            }'''
assert text.count(old) == 1, 'history pruning source changed'
text = text.replace(old, new)
old = 'The in-memory remainder was removed; refresh orders before retrying or replacing it.'
new = 'The in-memory remainder was removed, but an empty order list does not confirm durable cancellation. Do not replace it until durable state is confirmed.'
assert text.count(old) == 1, 'durability error source changed'
source.write_text(text.replace(old, new))

tests = Path('crates/gateway/src/audit_cancellation_tests.rs')
text = tests.read_text()
assert 'settled_partial_maker_survives_history_pruning_and_remains_cancellable' not in text
assert text.rstrip().endswith('}')
extra = r'''
    #[test]
    fn settled_partial_maker_survives_history_pruning_and_remains_cancellable() {
        let mut gw = Gw::boot();
        let (maker_key, maker) = rest(&mut gw);
        let (taker_key, _) = gw.register_account(None);
        gw.account_deposit(&taker_key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order(&taker_key, &OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (maker.size / 4).to_string(),
            limit_price: maker.limit_price.to_string(),
            tif: "Gtc".into(),
            reduce_only: false,
            ..Default::default()
        }).unwrap();
        gw.tick();
        let hash = maker.order_hash::<Keccak256>();
        assert_eq!(gw.seq.state.position(&maker.owner, 0).unwrap().size, -maker.size / 4);
        // Settle the real partial fill, then let the gateway observe that finality.
        // No live chain is involved in this native state-machine regression.
        gw.seq.mark_settled(gw.seq.current_batch_id() - 1);
        gw.tick();
        assert_eq!(gw.seq.finality_of(&hash), Some(Finality::Settled));
        assert_eq!(gw.accounts[&maker_key].orders[0].last_finality, "SETTLED");
        assert_eq!(gw.seq.cancellable_size(&maker.owner, &maker, true), Some(maker.size * 3 / 4));

        // Pad only display history with terminal fixtures, not 500 fabricated
        // accounting fills. The genuine live maker is deliberately first: the
        // legacy finality-only eviction would remove its sole API row first.
        let template = serde_json::to_vec(&gw.accounts[&maker_key].orders[0]).unwrap();
        let account = gw.accounts.get_mut(&maker_key).unwrap();
        for n in 0..MAX_ACCOUNT_ORDER_HISTORY {
            let mut historical: GwOrder = serde_json::from_slice(&template).unwrap();
            historical.id = format!("history-{n}");
            historical.order.nonce = 10_000 + n as u64;
            historical.order_hash = historical.order.order_hash::<Keccak256>();
            assert_ne!(historical.order_hash, hash);
            account.orders.push(historical);
        }
        assert_eq!(account.orders.len(), MAX_ACCOUNT_ORDER_HISTORY + 1);
        gw.tick();
        let account = &gw.accounts[&maker_key];
        assert_eq!(account.orders.len(), MAX_ACCOUNT_ORDER_HISTORY);
        assert!(account.orders.iter().any(|o| o.order_hash == hash), "live maker API row was pruned");
        let view = gw.v1_orders_json(&maker_key).unwrap();
        let maker_view = view["orders"].as_array().unwrap().iter()
            .find(|o| o["orderId"] == "o1").expect("maker visible");
        assert_eq!(maker_view["cancellable"], true);
        assert_eq!(gw.account_cancel(&maker_key, "o1").unwrap(), maker.size * 3 / 4);
        assert_eq!(gw.seq.book(0).unwrap().remaining_for(&maker.owner, &hash), None);
    }
'''
tests.write_text(text.rstrip()[:-1] + extra + '}\n')
