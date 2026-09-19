# S1 audit: recovery HTTP dayanıklılığı/yetki ve WS oturum iptali

**Tarih:** 19 Eylül 2026. **Base:** `main@b60e537f9487fd13e3cf453011a11c68f6d5889c` (taze fetch ile doğrulandı). **Head:** bu dalın son commit'i (PR'da kayıtlı). **Kapsam:** yalnız S1. S2–S7'ye dokunulmadı.

## Yeniden üretilen somut buglar (failing-before → passing-after)

### B1 — Rotation sonrası eski WS oturumu iptal edilmiyordu
- Konum (base): `crates/gateway/src/main.rs:6918-6974` (`ws_v1_loop`).
- Oturum yalnızca auth anındaki owner hex string'ini tutuyordu (`auth_owner`); özel event teslimi (base `main.rs:6960-6971`) yalnız owner string eşleşmesine bakıyordu. API-key rotation (`Gw::recover_account`, `account_recovery.rs`) hesabı yeni key'e taşıdığında mevcut oturum bundan habersiz kalıyor ve sahibinin özel event'lerini süresiz almaya devam ediyordu. Yalnız owner filtresi yetmiyordu — oturumun credential generation'ı hiç doğrulanmıyordu.
- Kanıt: `ws_session_revoked_after_key_rotation` ve `ws_unrelated_sessions_unaffected_by_rotation` (gerçek TCP socket + tokio-tungstenite, `/v1/ws`). Düzeltme öncesi mantık bu testlerde eski oturuma event iletilmeye devam ederdi.
- Düzeltme: auth anında `(owner, recovery_nonce)` saklanıyor; her özel event tesliminden önce ve her non-auth frame'de `Gw::ws_auth_valid` ile güncel `recovery_nonce` kısa kilit altında doğrulanıyor; uyuşmazlıkta `{"type":"error","message":"api key rotated"}` gönderilip bağlantı kapatılıyor. Reconnect eski key ile zaten reddediliyordu (korundu). Lock socket send'den önce bırakılıyor.

### B2 — Post-mutation snapshot hatasında kalıcı kilitlenme (durability wedge)
- Konum (base): `crates/gateway/src/main.rs:6200-6228` (`post_v1_recovery`).
- Handler önce bellek içi rotation'ı uyguluyor (eski key ölü, `recovery_nonce` artmış), sonra dayanıklı ACK istiyor. ACK başarısızlığında (writer yok, kapalı/dolu kuyruk, disk hatası, 30 s timeout, istek iptali, kayıp HTTP yanıtı) 503 `durability:"unknown"` dönülüyor ama rotation bellekte işlenmiş durumda; aynı nonce ile blind retry 400 "recovery nonce mismatch" veriyor ve yeni key'i öğrenmenin hiçbir yolu yoktu. Unknown-state'de sessiz rollback, nonce sıfırlama veya geri dönüşsüz kilitlenme arasındaki ayrım tanımsızdı; gerçek davranış geri dönüşsüz kilitlenmeydi.
- Kanıt: `recovery_false_ack_then_retry_returns_same_key`, `recovery_dropped_ack_then_retry_returns_same_key`, `recovery_wedged_writer_times_out_then_retry_returns_same_key` (start_paused 30 s timeout), `recovery_dropped_request_then_retry_returns_same_key`.
- Düzeltme: `Account.recovery_last: Option<(u64,[u8;32])>` (yalnız bellek, `#[serde(skip)]`; pozisyonel postcard ve `DPRECOV1` trailer formatı değişmedi). Aynı yetkili imzalı authorization'ın retry'si (nonce bir geride ve son rotation ile eşleşiyor) byte-identical key'i geri döndürüyor, hiçbir state'i değiştirmiyor; handler yine ACK şartı koşuyor, yani secret yalnızca o generation'ı kapsayan dayanıklı ACK sonrası çıkıyor. Daha eski nonce (superseded) mevcut hata mesajına düşüyor; u64 overflow `checked_add` ile reddediliyor. Process restart `recovery_last`'i unutur — ACK'siz generation'a ait secret restart sonrası asla teslim edilmez.

## Semantik tanımları (netleşen)
- **confirmed:** rotation + ACK; key yanıtta.
- **unknown:** rotation bellekte işlenmiş olabilir; aynı imzalı istek güvenle yeniden denenebilir (idempotent, aynı key, nonce çift artmaz). Restart sonrası unknown state çözülmez — istemci yeni authorization (nonce+1) üretmeli; bu, kayıp secret'ın restart'ta sızmamasının bedelidir ve kayıp yanıt kalıcı kilitlenmeye yol açmaz çünkü yeni rotation her zaman mümkün.
- Sessiz rollback/nonce sıfırlama yok; her başarısızlık yolu açık hata veya unknown döndürüyor.

## Korunan PR #12 invariant'ları
- Deposit permit (`deposits.routes[*].key`) ve credited receipt (`deposits.credits[*].route.key`) taşıması aynı `Gw` kilidi altında, retry yolunda hiç dokunulmadan korundu.
- V7→V8 migration, DPSNAP8 trailer, owner/payer/market/purpose/event/prefix ve native replay testleri değişiklik görmeden geçti.
- Mevcut test güncellemesi: `a07_rotation_preserves_pending_routes_and_other_accounts` içindeki "uygulanmış authorization'ın replay'i hata vermeli" iddiası yeni idempotent-retry semantiğinde bilinçli olarak değişti; superseded authorization reddi korundu.

## Doğrulama (exact head, bu oturumda çalıştırıldı)
- `cargo test -p gateway`: 338 passed / 0 failed / 1 ignored (ignored, önceden var).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`: sonuçlar kanıt JSON'unda ve PR açıklamasında.
- CI: PR push'u üzerine tetiklenen run'lar PR'da kayıtlı; bu belge yazımı anında okunup buraya eklenir.

## Mock/sınır ve kalan riskler
- Snapshot writer testlerde stub (ack-true/false/park/drop); gerçek disk hatası/fsync davranışı ve fiziksel crash drill yapılmadı (S6 konusu).
- WS testleri gerçek socket üzerinden; broadcast kuyruğu dolu/replay edilmiş event senaryosu `ws_auth_valid` kapısında kapsanıyor ama üretim yükü altında ölçülmedi.
- `ws_auth_valid` owner hex üzerinden hesap bulur; aynı owner ile birden fazla hesap varsa davranış belirsizdir (kayıt modelinde owner'ın unique varsayımı, mevcut kodun genel varsayımı).
- Tam codebase audit bitmedi; gerçek SP1 ELF/vkey/proof/deployment doğrulaması yapılmadı.
