//! Native order lifecycle, separate from proof finality. No ledger/witness changes.
use super::*;
use k256::elliptic_curve::bigint::{Encoding, U256};
use std::collections::BTreeMap;

pub(super) const SNAPSHOT_V7: &[u8] = b"\xffDPA05-SNAPSHOT-v7\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Status {
    Pending,
    Resting,
    PartiallyFilled,
    Filled,
    Cancelled,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub(super) struct Execution {
    pub status: Status,
    last_tick: Option<u64>,
    cancelled_size: i128,
    pub remaining: i128,
    pub filled: i128,
    pub reason: Option<String>,
    /// Full precision sum(size * execution_price), big endian. At most 254 bits:
    /// positive fills sum to <= the positive i128 order size; prices are i128.
    numerator: [u8; 32],
    pending: BTreeMap<u64, i128>,
    /// Old software fabricated quantities. Never bless those as historical fills.
    pub known: bool,
}
impl Execution {
    pub fn new(size: i128) -> Self {
        Self {
            status: Status::Pending,
            last_tick: None,
            cancelled_size: 0,
            remaining: size,
            filled: 0,
            reason: None,
            numerator: [0; 32],
            pending: BTreeMap::new(),
            known: true,
        }
    }
    fn apply(&mut self, size: i128, price: i128, tick: u64, original: i128) -> bool {
        // Applied engine fills satisfy these bounds. A metadata discrepancy must
        // become unavailable, not wrap, panic, or change the financial ledger.
        let Some(total) = self.filled.checked_add(size).filter(|n| *n <= original) else {
            self.known = false;
            self.reason = Some("ExecutionMetadataMismatch".into());
            return false;
        };
        if size <= 0 || price <= 0 {
            self.known = false;
            self.reason = Some("ExecutionMetadataMismatch".into());
            return false;
        }
        let value = U256::from_u128(size as u128).wrapping_mul(&U256::from_u128(price as u128));
        self.numerator = U256::from_be_bytes(self.numerator)
            .wrapping_add(&value)
            .to_be_bytes();
        self.filled = total;
        // total <= original <= i128::MAX also bounds every subset's sum.
        *self.pending.entry(tick).or_default() += size;
        true
    }
    pub fn average(&self) -> i128 {
        if self.filled <= 0 {
            return 0;
        }
        let q = U256::from_be_bytes(self.numerator)
            .wrapping_div(&U256::from_u128(self.filled as u128))
            .to_be_bytes();
        i128::from_be_bytes(q[16..].try_into().expect("16 bytes"))
    }
    pub fn refresh_finality(&mut self, seq: &Sequencer) {
        self.pending.retain(|tick, _| seq.fill_tick_pending(*tick));
    }
    pub fn unsettled(&self) -> i128 {
        self.pending.values().sum()
    }
    pub fn terminal(&self) -> bool {
        matches!(
            self.status,
            Status::Filled | Status::Cancelled | Status::Rejected
        ) && self.known
            && self.remaining == 0
            && self.pending.is_empty()
    }
    pub fn wire(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status, "remainingSize": self.remaining.to_string(),
            "filledSize": self.known.then(|| self.filled.to_string()),
            "avgFillPrice": self.known.then(|| self.average().to_string()),
            "unsettledSize": self.known.then(|| self.unsettled().to_string()),
            "settledSize": self.known.then(|| (self.filled - self.unsettled()).to_string()),
            "reason": self.reason, "available": self.known,
            "proven": false,
        })
    }
    fn validate(&self, size: i128) -> bool {
        if size <= 0
            || self.filled < 0
            || self.filled > size
            || self.remaining < 0
            || self.remaining > size
            || self.cancelled_size < 0
            || self.cancelled_size > size
        {
            return false;
        }
        let max =
            U256::from_u128(self.filled as u128).wrapping_mul(&U256::from_u128(i128::MAX as u128));
        if U256::from_be_bytes(self.numerator) > max {
            return false;
        }
        let pending =
            self.pending
                .values()
                .try_fold(0i128, |s, n| if *n <= 0 { None } else { s.checked_add(*n) });
        let within_tick = self
            .pending
            .keys()
            .all(|tick| self.last_tick.is_some_and(|last| *tick <= last));
        let status_coherent = if !self.known {
            true
        } else {
            match self.status {
                Status::Pending | Status::Resting => self.filled == 0 && self.remaining == size,
                Status::PartiallyFilled => {
                    self.filled > 0 && self.remaining == size - self.filled && self.remaining > 0
                }
                Status::Filled => self.filled == size && self.remaining == 0,
                Status::Cancelled | Status::Rejected => self.remaining == 0,
                Status::Unknown => false,
            }
        };
        pending.is_some_and(|n| n <= self.filled)
            && within_tick
            && status_coherent
            && (!self.known
                || (self.remaining <= size - self.filled
                    && self.cancelled_size <= size - self.filled))
    }
}

fn ensure_record(o: &mut GwOrder, seq: &Sequencer) {
    if o.execution.is_none() {
        let mut e = Execution::new(o.order.size);
        if o.sealed {
            e.known = false;
            e.remaining = seq.remaining_order_size(&o.order_hash).unwrap_or(0);
            e.status = if e.remaining > 0 {
                Status::Resting
            } else {
                Status::Unknown
            };
            e.reason = Some("LegacyExecutionUnavailable".into());
        }
        o.execution = Some(e);
    }
}

/// Call exactly once for each sealed tick; fills are emitted only here, never on
/// a finality transition. A maker can keep filling after earlier fills settle.
pub(super) fn update(
    o: &mut GwOrder,
    seq: &Sequencer,
    batch: &SealedBatch,
    newly_submitted: bool,
) -> Vec<serde_json::Value> {
    ensure_record(o, seq);
    let e = o.execution.as_mut().expect("record initialized");
    // Window rollback does not re-apply financial fills. Replayed notifications
    // must not increment quantities or emit a second fill, including after restart.
    if e.last_tick.is_some_and(|tick| batch.batch_id <= tick) {
        return Vec::new();
    }
    e.last_tick = Some(batch.batch_id);
    let old_status = e.status;
    let old_unsettled = e.unsettled();
    let old_reason = e.reason.clone();
    let mut events = Vec::new();
    for m in &batch.applied_fills {
        if m.taker_order_hash != o.order_hash && m.maker_order_hash != o.order_hash {
            continue;
        }
        let same_leg = (m.taker_order_hash == o.order_hash && m.taker == o.order.owner)
            || (m.maker_order_hash == o.order_hash && m.maker == o.order.owner);
        if !same_leg || m.market_id != o.order.market_id {
            e.known = false;
            e.reason = Some("ExecutionMetadataMismatch".into());
            continue;
        }
        if !e.apply(m.size, m.price, batch.batch_id, o.order.size) {
            continue;
        }
        events.push(serde_json::json!({"type": "fill", "orderId": o.id,
            "marketId": m.market_id, "side": o.input.side,
            "size": m.size.to_string(), "price": m.price.to_string(),
            "tickBatchId": batch.batch_id }));
    }
    e.pending.retain(|tick, _| seq.fill_tick_pending(*tick));
    let rejection = batch
        .manifest
        .rejected
        .iter()
        .find(|(h, _)| *h == o.order_hash)
        .map(|(_, r)| *r);
    let removal = batch.removals.iter().find(|r| r.order_hash == o.order_hash);
    let live = seq.remaining_order_size(&o.order_hash);
    if let Some(r) = removal {
        e.status = Status::Cancelled;
        e.reason = Some(r.reason.into());
        e.remaining = 0;
    } else if let Some(reason) = rejection {
        e.reason = Some(format!("{reason:?}"));
        e.remaining = live.unwrap_or(0);
        e.status = if live.is_some() {
            if e.filled > 0 {
                Status::PartiallyFilled
            } else {
                Status::Resting
            }
        } else if matches!(
            reason,
            perp_core::order::RejectReason::Expired
                | perp_core::order::RejectReason::Cancelled
                | perp_core::order::RejectReason::SelfTradePrevented
        ) {
            Status::Cancelled
        } else {
            Status::Rejected
        };
    } else if let Some(remaining) = live {
        e.remaining = remaining;
        e.status = if e.filled > 0 {
            Status::PartiallyFilled
        } else {
            Status::Resting
        };
    } else if e.known && e.filled == o.order.size {
        e.remaining = 0;
        e.status = Status::Filled;
    } else if newly_submitted {
        e.remaining = 0;
        e.status = Status::Cancelled;
        e.reason = Some("UnfilledRemainder".into());
    } else if !e.known && !events.is_empty() {
        // The last legacy remainder executed; historic totals stay unavailable.
        e.remaining = 0;
        e.status = Status::Unknown;
    }
    // Old fields are retained solely for the v5 positional prefix. New responses
    // use the execution availability flag and never expose old fabricated values.
    if e.known {
        o.filled = e.filled;
        o.avg_fill = e.average();
    }
    if old_status != e.status || old_reason != e.reason || old_unsettled != e.unsettled() {
        events
            .push(serde_json::json!({"type": "execution", "orderId": o.id, "execution": e.wire()}));
    }
    events
}

pub(super) fn cancel(
    seq: &mut Sequencer,
    owner: &[u8; 32],
    o: &mut GwOrder,
) -> Result<i128, String> {
    if o.order.owner != *owner || o.order.order_hash::<Keccak256>() != o.order_hash {
        return Err("ORDER_NOT_OWNED: cancellation record mismatch".into());
    }
    ensure_record(o, seq);
    let e = o.execution.as_mut().expect("record initialized");
    if e.status == Status::Cancelled && e.reason.as_deref() == Some("UserCancelled") {
        return Ok(e.cancelled_size);
    }
    let amount = seq
        .cancel_order(owner, &o.order, o.sealed)
        .ok_or("ORDER_NOT_LIVE: no cancellable remainder")?;
    o.sealed = true;
    e.status = Status::Cancelled;
    e.reason = Some("UserCancelled".into());
    e.cancelled_size = amount;
    e.remaining = 0;
    Ok(amount)
}

// Keep the old (Gw, markets) payload as a prefix. New fields on GwOrder are
// serde-skipped, and a versioned trailer carries them without duplicating ledger
// schemas. DPSNAP7 prevents older software from silently dropping this trailer.
const EXT: &[u8; 8] = b"DPEXEC2\0";
pub(super) fn append_snapshot(gw: &Gw, bytes: &mut Vec<u8>) {
    let records: Vec<_> = gw
        .orders
        .iter()
        .chain(gw.accounts.values().flat_map(|a| &a.orders))
        .map(|o| (o.order_hash, o.execution.clone()))
        .collect();
    bytes.extend_from_slice(EXT);
    bytes.extend_from_slice(&postcard::to_allocvec(&records).expect("execution snapshot encode"));
}
pub(super) fn restore_snapshot(gw: &mut Gw, trailer: &[u8]) -> Result<(), String> {
    if trailer.is_empty() {
        // Explicit v5/v6 migration: preserve every ledger/account/receipt byte, but
        // do not invent execution history that the old program never recorded.
        for o in gw
            .orders
            .iter_mut()
            .chain(gw.accounts.values_mut().flat_map(|a| &mut a.orders))
        {
            ensure_record(o, &gw.seq);
        }
        return Ok(());
    }
    if !trailer.starts_with(EXT) {
        return Err("unknown execution snapshot extension".into());
    }
    let (records, rest): (Vec<(Digest, Option<Execution>)>, _) =
        postcard::take_from_bytes(&trailer[EXT.len()..])
            .map_err(|e| format!("execution snapshot decode: {e}"))?;
    if !rest.is_empty() {
        return Err("trailing execution snapshot bytes".into());
    }
    let count = records.len();
    let mut map: BTreeMap<_, _> = records.into_iter().collect();
    if map.len() != count {
        return Err("duplicate execution record".into());
    }
    for o in gw
        .orders
        .iter_mut()
        .chain(gw.accounts.values_mut().flat_map(|a| &mut a.orders))
    {
        let e = map
            .remove(&o.order_hash)
            .ok_or("missing execution snapshot record")?
            .ok_or("missing execution snapshot payload")?;
        if !e.validate(o.order.size) {
            return Err("invalid execution snapshot record".into());
        }
        // Keep legacy prefix bytes unchanged. Runtime views read the
        // authenticated extension, never the old fabricated quantities.
        o.execution = Some(e);
    }
    if !map.is_empty() {
        return Err("orphan execution snapshot record".into());
    }
    Ok(())
}

pub(super) fn wire(o: &GwOrder, seq: &Sequencer) -> serde_json::Value {
    o.execution
        .as_ref()
        .map(|e| {
            let mut view = e.clone();
            view.refresh_finality(seq);
            view.wire()
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "status": "UNKNOWN", "available": false, "proven": false,
                "remainingSize": null, "filledSize": null, "avgFillPrice": null,
                "unsettledSize": null, "settledSize": null, "reason": "LegacyExecutionUnavailable"
            })
        })
}

#[cfg(test)]
mod arithmetic_tests {
    use super::*;
    #[test]
    fn exact_vwap_keeps_fractional_remainders_across_many_fills() {
        let mut e = Execution::new(7);
        for p in [10, 10, 11, 11, 11, 12, 12] {
            e.apply(1, p, 0, 7);
        }
        assert_eq!(e.average(), 11); // repeated rounded averages would yield 10
        assert_eq!(e.filled, 7);
    }
    #[test]
    fn maximum_positive_i128_size_and_price_do_not_overflow_metadata() {
        let mut e = Execution::new(i128::MAX);
        e.apply(i128::MAX - 1, i128::MAX - 2, 0, i128::MAX);
        e.apply(1, i128::MAX, 1, i128::MAX);
        assert_eq!(e.filled, i128::MAX);
        assert_eq!(e.average(), i128::MAX - 2);
        assert!(e.known);
    }
    #[test]
    fn excess_fill_fails_closed_as_unavailable_metadata() {
        let mut e = Execution::new(10);
        e.apply(11, 100, 0, 10);
        assert!(!e.known);
        assert_eq!(e.filled, 0);
    }
}
