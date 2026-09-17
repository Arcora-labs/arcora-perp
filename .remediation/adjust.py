from pathlib import Path
p = Path('crates/gateway/src/main.rs')
s = p.read_text()
def replace(old, new):
    global s
    assert s.count(old) == 1, (old[:100], s.count(old))
    s = s.replace(old, new)
replace('#[derive(Serialize, serde::Deserialize)]\nstruct Gw {\n    seq: Sequencer,', '''// Public receipt material only. Runtime-only and bounded: repeated polling must
// not perform one ECDSA operation per historical order while holding App.gw.
type ReceiptCache = std::sync::Mutex<std::collections::BTreeMap<(Digest, u64, [u8; 20]), serde_json::Value>>;
const MAX_RECEIPT_CACHE: usize = 4096;

#[derive(Serialize, serde::Deserialize)]
struct Gw {
    seq: Sequencer,
    #[serde(skip)]
    receipt_cache: ReceiptCache,''')
replace('let mut gw = Gw {\n            seq,', 'let mut gw = Gw {\n            seq,\n            receipt_cache: ReceiptCache::default(),')
replace('''        let digest = receipt.signing_digest::<Keccak256>();
        let (r, s, v) = self.seq.enclave().sign_prehash(&digest);''', '''        let digest = receipt.signing_digest::<Keccak256>();
        let signer = self.seq.enclave().eth_address();
        let cache_key = (digest, stored.window_id, signer);
        if let Ok(cache) = self.receipt_cache.lock() {
            if let Some(wire) = cache.get(&cache_key) {
                return wire.clone();
            }
        }
        let (r, s, v) = self.seq.enclave().sign_prehash(&digest);''')
replace('''        wire["enclaveSigner"] = serde_json::json!(hex0x(&self.seq.enclave().eth_address()));
        wire
    }''', '''        wire["enclaveSigner"] = serde_json::json!(hex0x(&signer));
        if let Ok(mut cache) = self.receipt_cache.lock() {
            if cache.len() >= MAX_RECEIPT_CACHE {
                cache.clear();
            }
            cache.insert(cache_key, wire.clone());
        }
        wire
    }''')
p.write_text(s)
p = Path('crates/gateway/src/audit_remediation_tests.rs')
s = p.read_text()
s = s.replace('let ack = rx.recv().await.expect("authorization must request a durability barrier");', 'let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("authorization handler did not reach the durability barrier").expect("authorization must request a durability barrier");')
s = s.replace('rx.recv().await.unwrap().send(false).unwrap();', 'tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("authorization handler did not reach the durability barrier").unwrap().send(false).unwrap();')
assert s.endswith('}\n')
s = s[:-2] + '''
    #[test]
    fn receipt_cache_is_bounded_metadata_bound_and_not_persisted() {
        let gw = Gw::boot();
        let stored = WReceipt { order_hash: hex0x(&[1; 32]), seq_no: 1,
            recv_time_ms: 2000, batch_id_hint: 3, window_id: 4 };
        let before = gw.snapshot_plain();
        let wire = gw.receipt_json(&stored);
        assert_eq!(gw.receipt_json(&stored), wire);
        assert_eq!(gw.receipt_cache.lock().unwrap().len(), 1);
        assert_eq!(gw.snapshot_plain(), before, "read caching cannot change the snapshot schema or state");
        let mut other = stored.clone();
        other.window_id += 1;
        let moved_window = gw.receipt_json(&other);
        assert_eq!(moved_window["windowId"], 5);
        assert_eq!(moved_window["signature"], wire["signature"], "window hint stays unsigned");
        other.recv_time_ms += 1;
        assert_ne!(gw.receipt_json(&other)["signature"], wire["signature"]);
        {
            let mut cache = gw.receipt_cache.lock().unwrap();
            cache.clear();
            for i in 0..MAX_RECEIPT_CACHE as u64 {
                cache.insert(([0; 32], i, [0; 20]), serde_json::Value::Null);
            }
        }
        assert_eq!(gw.receipt_json(&stored), wire);
        assert_eq!(gw.receipt_cache.lock().unwrap().len(), 1, "bounded cache must evict before insertion");
        let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(restored.receipt_cache.lock().unwrap().is_empty());
        assert_eq!(restored.receipt_json(&stored), wire);
    }
}
'''
p.write_text(s)
