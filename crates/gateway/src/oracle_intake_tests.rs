//! Host ingress regressions, independent of network/proving/TEE fixtures.
use super::*;

fn observation(gw: &Gw, market: u64, published: u64) -> OracleTranscript {
    oracle_of(60_000 * PRICE_SCALE, published, market, &gw.oracle_signer)
}

fn assert_unchanged(gw: &Gw, before: &[u8], previous: Option<OracleTranscript>) {
    assert_eq!(
        gw.snapshot_plain(),
        before,
        "rejected oracle must not mutate persistent state"
    );
    assert_eq!(
        gw.seq.oracle(0).copied(),
        previous,
        "rejected oracle must not replace stored observation"
    );
    let market = gw.mkt(0).unwrap();
    assert!(!market.live);
    assert_eq!(market.feed_ts, 0);
    assert_eq!(market.px_ms, 0);
}

#[test]
fn oracle_intake_preserves_signed_exchange_timestamp() {
    let mut gw = Gw::boot();
    let now = now_ms();
    let incoming = observation(&gw, 0, now - 1_000);
    gw.apply_real_oracle(0, incoming);
    assert_eq!(
        gw.seq.oracle(0).copied(),
        Some(incoming),
        "do not restamp or re-sign a source observation"
    );
    assert_eq!(gw.mkt(0).unwrap().feed_ts, incoming.publish_time_ms);
}

#[test]
fn oracle_intake_refuses_old_advance() {
    let mut gw = Gw::boot();
    let incoming = observation(&gw, 0, now_ms() - 60_000);
    let before = gw.snapshot_plain();
    let previous = gw.seq.oracle(0).copied();
    gw.apply_real_oracle(0, incoming);
    assert_unchanged(&gw, &before, previous);
}

#[test]
fn oracle_intake_refuses_future() {
    let mut gw = Gw::boot();
    let incoming = observation(&gw, 0, now_ms() + 60_000);
    let before = gw.snapshot_plain();
    let previous = gw.seq.oracle(0).copied();
    gw.apply_real_oracle(0, incoming);
    assert_unchanged(&gw, &before, previous);
}

#[test]
fn oracle_intake_refuses_wrong_publisher_before_resigning() {
    let mut gw = Gw::boot();
    let other = k256::ecdsa::SigningKey::from_slice(&[0x77; 32]).unwrap();
    let incoming = oracle_of(60_000 * PRICE_SCALE, now_ms(), 0, &other);
    let before = gw.snapshot_plain();
    let previous = gw.seq.oracle(0).copied();
    gw.apply_real_oracle(0, incoming);
    assert_unchanged(&gw, &before, previous);
}

#[test]
fn oracle_intake_refuses_bad_confidence_before_mutating_mark() {
    let mut gw = Gw::boot();
    let mut incoming = observation(&gw, 0, now_ms());
    incoming.confidence = incoming.price;
    incoming.signature = OracleSig::sign(
        &gw.oracle_signer,
        &oracle_digest(
            0,
            incoming.price,
            incoming.publish_time_ms,
            incoming.confidence,
            incoming.backup_twap,
        ),
    );
    let before = gw.snapshot_plain();
    let previous = gw.seq.oracle(0).copied();
    gw.apply_real_oracle(0, incoming);
    assert_unchanged(&gw, &before, previous);
}

#[test]
fn oracle_intake_rejects_unknown_market() {
    let mut gw = Gw::boot();
    let incoming = observation(&gw, u64::MAX, now_ms());
    assert!(gw.seq.oracle(u64::MAX).is_none());
    gw.apply_real_oracle(u64::MAX, incoming);
    assert!(gw.seq.oracle(u64::MAX).is_none());
}

#[test]
fn production_tick_does_not_simulate_before_live_feed() {
    let mut gw = Gw::boot();
    gw.prod = true;
    let old: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| (m.id, m.px, gw.seq.oracle(m.id).copied()))
        .collect();
    gw.tick();
    for (id, price, transcript) in old {
        assert_eq!(
            gw.mkt(id).unwrap().px,
            price,
            "production never synthesizes missing market prices"
        );
        assert_eq!(gw.seq.oracle(id).copied(), transcript);
    }
}

#[test]
fn oracle_intake_staleness_boundary_and_original_signature_are_preserved() {
    let mut gw = Gw::boot();
    let now = 1_000_000;
    let max_age = gw.seq.state.markets[&0].max_oracle_staleness_ms;
    let at_boundary = observation(&gw, 0, now - max_age);
    assert!(gw.apply_real_oracle_at(0, at_boundary, now));
    assert_eq!(gw.seq.oracle(0), Some(&at_boundary));
    assert_eq!(gw.mkt(0).unwrap().px_ms, now);
    // One millisecond later the signed source observation is stale, not renewed.
    assert!(at_boundary
        .validate(&gw.seq.state.markets[&0], now + 1)
        .is_err());
}

#[test]
fn oracle_intake_advancing_but_delayed_tape_never_becomes_fresh() {
    let mut gw = Gw::boot();
    let now = 1_000_000;
    let before = gw.snapshot_plain();
    let previous = gw.seq.oracle(0).copied();
    for offset in [0, 1, 100, 1_000] {
        let delayed = observation(&gw, 0, now - 60_000 + offset);
        assert!(!gw.apply_real_oracle_at(0, delayed, now + offset));
        assert_unchanged(&gw, &before, previous);
    }
}

#[test]
fn oracle_intake_replay_and_out_of_order_do_not_refresh_receipt_time() {
    let mut gw = Gw::boot();
    let now = 1_000_000;
    let accepted = observation(&gw, 0, now - 100);
    assert!(gw.apply_real_oracle_at(0, accepted, now));
    for published in [now - 100, now - 101] {
        let replay = observation(&gw, 0, published);
        assert!(!gw.apply_real_oracle_at(0, replay, now + 1));
        assert_eq!(gw.mkt(0).unwrap().px_ms, now);
        assert_eq!(gw.seq.oracle(0), Some(&accepted));
    }
}

#[test]
fn production_start_and_restore_wait_for_new_valid_source() {
    let mut original = Gw::boot();
    let live = observation(&original, 0, now_ms());
    assert!(original.apply_real_oracle(0, live));
    let mut gw = Gw::boot_restored(&original.snapshot_plain()).unwrap();
    gw.prod = true;
    gw.require_fresh_production_oracles();
    for m in &gw.mkts {
        let transcript = gw.seq.oracle(m.id).unwrap();
        assert!(transcript
            .validate(&gw.seq.state.markets[&m.id], now_ms())
            .is_err());
        assert!(!m.live);
        assert_eq!(m.px_ms, 0);
    }
    gw.tick();
    assert_eq!(gw.seq.oracle(0).unwrap().publish_time_ms, 0);
    let accepted = observation(&gw, 0, now_ms());
    assert!(gw.apply_real_oracle(0, accepted));
    assert_eq!(gw.seq.oracle(0), Some(&accepted));
    assert!(gw
        .seq
        .oracle(1)
        .unwrap()
        .validate(&gw.seq.state.markets[&1], now_ms())
        .is_err());
}

#[test]
fn demo_mode_keeps_simulation_without_production_admission() {
    let mut gw = Gw::boot();
    let previous = gw.seq.oracle(0).copied();
    gw.require_fresh_production_oracles();
    assert_eq!(gw.seq.oracle(0).copied(), previous);
    gw.tick();
    assert_ne!(gw.seq.oracle(0).copied(), previous);
}
