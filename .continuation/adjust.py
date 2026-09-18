from pathlib import Path
p = Path('crates/gateway/src/execution.rs')
s = p.read_text()
old = '''    } else if newly_submitted {
        e.remaining = 0; e.status = Status::Cancelled; e.reason = Some("UnfilledRemainder".into());
    }
'''
new = '''    } else if newly_submitted {
        e.remaining = 0; e.status = Status::Cancelled; e.reason = Some("UnfilledRemainder".into());
    } else if !e.known && !events.is_empty() {
        // A legacy maker's last live remainder just executed. Its historic
        // quantity stays unavailable, but it must not remain actionable.
        e.remaining = 0; e.status = Status::Unknown;
    }
'''
assert s.count(old) == 1
p.write_text(s.replace(old, new))
p = Path('crates/gateway/src/execution_regression_tests.rs')
s = p.read_text()
marker = '    #[test]\n    fn challenge_prefers_earlier_ordered_evidence_over_later_cancellation() {'
test = '''    #[test]
    fn legacy_maker_finishing_remainder_is_not_actionable_or_fabricated() {
        let (mut gw, maker, taker, _) = paired();
        let markets: Vec<(u64, i128, i128, bool)> = gw.mkts.iter()
            .map(|m| (m.id, m.reference_price, m.px, m.live)).collect();
        let old = postcard::to_allocvec(&(&gw, markets)).unwrap();
        gw = Gw::boot_restored(&old).unwrap();
        gw.window_settle_mode = true;
        submit(&mut gw, &taker, "Buy", SIZE_SCALE / 10, 0, "Ioc");
        tick(&mut gw);
        let order = row(&gw, &maker);
        assert_eq!(order["execution"]["remainingSize"], "0");
        assert_eq!(order["execution"]["available"], false);
        assert!(order["filledSize"].is_null());
        assert!(gw.account_cancel(&maker, "o1").unwrap_err().contains("ORDER_NOT_LIVE"));
    }
'''
assert s.count(marker) == 1
p.write_text(s.replace(marker, test + marker))
