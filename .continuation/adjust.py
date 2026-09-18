from pathlib import Path

def replace(path, old, new, count=1):
    p = Path(path); s = p.read_text()
    assert s.count(old) == count, (path, old[:80], s.count(old))
    p.write_text(s.replace(old, new))

replace('crates/gateway/src/execution.rs', '''    } else if newly_submitted {
        e.remaining = 0; e.status = Status::Cancelled; e.reason = Some("UnfilledRemainder".into());
    }
''', '''    } else if newly_submitted {
        e.remaining = 0; e.status = Status::Cancelled; e.reason = Some("UnfilledRemainder".into());
    } else if !e.known && !events.is_empty() {
        // The last legacy remainder executed; historic totals stay unavailable.
        e.remaining = 0; e.status = Status::Unknown;
    }
''')
replace('crates/gateway/src/execution_regression_tests.rs', '    #[test]\n    fn challenge_prefers_earlier_ordered_evidence_over_later_cancellation() {', '''    #[test]
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
    #[test]
    fn changing_v6_to_a_legacy_header_does_not_bypass_authentication() {
        let seed = [42; 32];
        let mut sealed = snapshot::seal(b"a new-format state", &seed);
        sealed[..8].copy_from_slice(b"DPSNAP5\\0");
        assert!(snapshot::open(&sealed, &seed).is_err());
    }
    #[test]
    fn challenge_prefers_earlier_ordered_evidence_over_later_cancellation() {''')

# Bind the new envelope version into its MAC; retain exactly the v5 MAC on read.
replace('crates/gateway/src/snapshot.rs', 'fn mac(seed: &[u8; 32], nonce: &Digest, ciphertext: &[u8]) -> Digest {\n    let mut words = vec![*seed, *nonce, word_u64(ciphertext.len() as u64)];', '''fn mac(seed: &[u8; 32], nonce: &Digest, ciphertext: &[u8], legacy: bool) -> Digest {
    let mut words = vec![*seed, *nonce, word_u64(ciphertext.len() as u64)];
    if !legacy {
        // The length binds ciphertext independently, so this version word cannot
        // be confused with a prefix of a legacy ciphertext. Header downgrades
        // now fail authentication even before the payload decoder runs.
        let mut version = [0u8; 32];
        version[..8].copy_from_slice(MAGIC);
        words.push(version);
    }''')
replace('crates/gateway/src/snapshot.rs', 'let tag = mac(seed, &nonce, &ciphertext);', 'let tag = mac(seed, &nonce, &ciphertext, false);')
replace('crates/gateway/src/snapshot.rs', 'let expected = mac(seed, &nonce, ciphertext);', 'let expected = mac(seed, &nonce, ciphertext, &sealed[..8] == LEGACY_MAGIC);')
# Authentic old-format fixture: keep v5's exact MAC, not a relabelled v6 envelope.
replace('crates/gateway/src/execution_regression_tests.rs', '        let mut sealed = snapshot::seal(&old, &seed); sealed[..8].copy_from_slice(b"DPSNAP5\\0");', '''        let mut sealed = snapshot::seal(&old, &seed);
        sealed[..8].copy_from_slice(b"DPSNAP5\\0");
        let nonce: [u8; 32] = sealed[8..40].try_into().unwrap();
        let mut words = vec![seed, nonce, perp_core::hash::word_u64((sealed.len() - 72) as u64)];
        for chunk in sealed[72..].chunks(32) {
            let mut word = [0u8; 32]; word[..chunk.len()].copy_from_slice(chunk); words.push(word);
        }
        let tag = <Keccak256 as perp_core::hash::Hasher>::hash_words(Domain::SnapshotSealMac, &words);
        sealed[40..72].copy_from_slice(&tag);''')

# Keep the optional field genuinely absent for old gateway/mock contracts.
replace('frontend/src/api/realClient.ts', '    execution: pExecution(o.execution),', '    ...(o.execution === undefined ? {} : { execution: pExecution(o.execution) }),', 2)
for path in ['frontend/src/api/mockClient.ts', 'frontend/src/api/clientContract.test.ts']:
    replace(path, 'message: "Order cancelled before matching"', 'message: "Unfilled remainder cancelled; existing fills are unchanged"')
replace('crates/gateway/src/main.rs', '// reference orders by index), and only evicts SETTLED (terminal, display-only)\n            // orders — live/pending orders and the account\'s replay nonce are untouched.', '// reference orders by index), and only evicts terminal execution records with\n            // no unconfirmed fills. A SETTLED receipt may still have a live remainder.')
replace('crates/gateway/src/main.rs', '        let ((mut gw, mkt_px), trailer): ((Gw, Vec<(u64, i128, i128, bool)>), _) =', '        type SnapshotPrefix = (Gw, Vec<(u64, i128, i128, bool)>);\n        let ((mut gw, mkt_px), trailer): (SnapshotPrefix, _) =')
