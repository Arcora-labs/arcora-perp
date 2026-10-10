use super::*;
use oracle_feed::crosscheck_http::{parse_crypto_spot_response, parse_okx_spot_response};
const NOW: u64 = 1_000_000;
fn policy() -> CrosscheckPolicy {
    CrosscheckPolicy::new(1_000).unwrap()
}
fn explicit_test_units(gw: &mut Gw) {
    // Test-only matching denomination; NOT a change to the deployed MARKETS.
    for m in &mut gw.mkts {
        m.symbol = match m.id {
            0 => "BTC/USDT",
            1 => "ETH/USDT",
            2 => "SOL/USDT",
            _ => panic!("unexpected test market"),
        };
    }
}
fn configured() -> Gw {
    let mut gw = Gw::boot();
    explicit_test_units(&mut gw);
    gw.configure_oracle_crosscheck(Some(policy())).unwrap();
    gw
}
fn observations(gw: &Gw, pt: u64, st: u64, secondary_price: &str) -> (SourceTick, SourceTick) {
    let pair = SpotPair::new("BTC", "USDT").unwrap();
    let p = serde_json::to_vec(
        &serde_json::json!({"code":0,"method":"public/get-tickers","result":{"data":[
        {"i":"BTC_USDT","a":"60000","b":"60000","k":"60000","t":pt}]}}),
    )
    .unwrap();
    let s=serde_json::to_vec(&serde_json::json!({"code":"0","msg":"","data":[
        {"instType":"SPOT","instId":"BTC-USDT","last":secondary_price,"bidPx":secondary_price,"askPx":secondary_price,"ts":st.to_string()}]})).unwrap();
    (
        parse_crypto_spot_response(&p, &pair, NOW + 100_000, 0, &gw.oracle_signer).unwrap(),
        parse_okx_spot_response(&s, &pair, NOW + 100_000, 0, &gw.oracle_signer).unwrap(),
    )
}
fn halted(gw: &Gw) {
    assert!(gw
        .seq
        .oracle(0)
        .unwrap()
        .validate(&gw.seq.state.markets[&0], NOW)
        .is_err());
    assert!(!gw.mkt(0).unwrap().live);
}
#[test]
fn current_usdc_labels_and_usdt_sources_refuse_opt_in_without_partial_mutation() {
    let mut gw = Gw::boot();
    let before = gw.snapshot_plain();
    let oracles: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| gw.seq.oracle(m.id).copied())
        .collect();
    assert!(gw
        .configure_oracle_crosscheck(Some(policy()))
        .unwrap_err()
        .contains("quote mismatch"));
    assert!(gw.oracle_crosschecks.is_empty());
    assert_eq!(gw.snapshot_plain(), before);
    assert_eq!(
        gw.mkts
            .iter()
            .map(|m| gw.seq.oracle(m.id).copied())
            .collect::<Vec<_>>(),
        oracles
    );
}
#[test]
fn unset_policy_preserves_legacy_mode_without_claiming_two_sources() {
    let mut gw = Gw::boot();
    let before = gw.snapshot_plain();
    gw.configure_oracle_crosscheck(None).unwrap();
    assert!(gw.oracle_crosschecks.is_empty());
    assert_eq!(gw.snapshot_plain(), before);
    let t = oracle_of(60_000 * PRICE_SCALE, NOW, 0, &gw.oracle_signer);
    assert!(gw.apply_real_oracle_at(0, t, NOW));
}
#[test]
fn configured_start_requires_pair_and_does_not_simulate_even_in_demo() {
    let mut gw = configured();
    halted(&gw);
    let before: Vec<_> = gw
        .mkts
        .iter()
        .map(|m| (m.px, m.px_ms, gw.seq.oracle(m.id).copied()))
        .collect();
    gw.tick();
    assert_eq!(
        before,
        gw.mkts
            .iter()
            .map(|m| (m.px, m.px_ms, gw.seq.oracle(m.id).copied()))
            .collect::<Vec<_>>()
    );
}
#[test]
fn configured_single_source_valid_signature_cannot_bypass_guard() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    let expected = *p.transcript();
    assert!(!gw.apply_real_oracle_at(0, expected, NOW));
    halted(&gw);
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
    assert_eq!(gw.seq.oracle(0), Some(&expected));
    assert_eq!(gw.mkt(0).unwrap().px_ms, NOW);
    assert_eq!(gw.mkt(0).unwrap().feed_ts, NOW - 200);
    let one = oracle_of(60_001 * PRICE_SCALE, NOW, 0, &gw.oracle_signer);
    assert!(!gw.apply_real_oracle_at(0, one, NOW + 1));
    assert_eq!(gw.seq.oracle(0), Some(&expected));
}
#[test]
fn disagreement_halts_immediately_keeps_price_times_and_recovers_with_fresh_pair() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
    let old = (
        gw.mkt(0).unwrap().px,
        gw.mkt(0).unwrap().px_ms,
        gw.mkt(0).unwrap().feed_ts,
    );
    let (p, s) = observations(&gw, NOW - 199, NOW - 99, "62000");
    assert!(!gw.apply_crosschecked_oracle_at(0, p, s, NOW + 1));
    halted(&gw);
    assert_eq!(
        (
            gw.mkt(0).unwrap().px,
            gw.mkt(0).unwrap().px_ms,
            gw.mkt(0).unwrap().feed_ts
        ),
        old
    );
    gw.tick();
    halted(&gw);
    assert_eq!(gw.mkt(0).unwrap().px, old.0);
    let (p, s) = observations(&gw, NOW - 199, NOW - 99, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW + 2));
}
#[test]
fn repeated_secondary_does_not_refresh_price_or_consume_primary_watermark() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
    let (p, s) = observations(&gw, NOW - 199, NOW - 100, "60001");
    assert!(!gw.apply_crosschecked_oracle_at(0, p, s, NOW + 1));
    halted(&gw);
    assert_eq!(gw.mkt(0).unwrap().px_ms, NOW);
    let (p, s) = observations(&gw, NOW - 199, NOW - 99, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW + 2));
}
#[test]
fn missing_source_invalidates_prior_admission_without_signed_price_fabrication() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
    let price = gw.mkt(0).unwrap().px;
    gw.halt_crosschecked_oracle(0);
    halted(&gw);
    assert_eq!(gw.mkt(0).unwrap().px, price);
    assert_eq!(gw.mkt(0).unwrap().px_ms, NOW);
    assert_eq!(gw.seq.oracle(0).unwrap().signature.r, [0; 32]);
}
#[test]
fn queued_first_source_is_rechecked_at_gateway_receipt() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 10_000, NOW, "60001");
    assert!(!gw.apply_crosschecked_oracle_at(0, p, s, NOW + 1));
    halted(&gw);
}
#[test]
fn downstream_rejection_does_not_commit_candidate_watermarks() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    let runtime = gw.mkts.remove(0);
    assert!(!gw.apply_crosschecked_oracle_at(0, p.clone(), s.clone(), NOW));
    gw.mkts.insert(0, runtime);
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
}
#[test]
fn restore_does_not_persist_host_gate_or_bypass_fresh_pair_requirement() {
    let mut gw = configured();
    let (p, s) = observations(&gw, NOW - 200, NOW - 100, "60001");
    assert!(gw.apply_crosschecked_oracle_at(0, p, s, NOW));
    let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert!(restored.oracle_crosschecks.is_empty());
    // Existing configured source units remain incompatible after restart too.
    assert!(restored
        .configure_oracle_crosscheck(Some(policy()))
        .is_err());
    explicit_test_units(&mut restored);
    restored
        .configure_oracle_crosscheck(Some(policy()))
        .unwrap();
    halted(&restored);
    let (p, s) = observations(&restored, NOW, NOW, "60001");
    assert!(restored.apply_crosschecked_oracle_at(0, p, s, NOW));
}
