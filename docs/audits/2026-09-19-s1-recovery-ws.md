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

---

## Round-3 güncellemesi (2026-09-27, job--10 head) — B2 semantiği değişti

Round-1/2 metnindeki "aynı imzalı authorization idempotent retry" anlatısı **geçersizdir**; bu head'de sözleşme tekleştirildi:

- `Account.recovery_last` kaldırıldı. Kullanılmış/stale authorization artık asla idempotent kabul edilmiyor; replay her zaman "recovery nonce mismatch (stale or replayed authorization)" reddi.
- Belirsizlik (503 `durability:"unknown"`, timeout, kayıp yanıt) sonrası güvenli yol: istemci `GET /v1/accounts/recovery/:owner` ile güncel nonce/challenge alır, CURRENT nonce'u yeniden imzalar ve POST eder. Gateway round-3 testleri bu akışı kanıtlar: `recovery_false_ack_then_fresh_challenge_succeeds`, `recovery_dropped_ack_then_fresh_challenge_succeeds`, `recovery_wedged_writer_times_out_then_fresh_challenge_succeeds`, `recovery_dropped_request_then_fresh_challenge_succeeds`.
- `post_v1_recovery` artık mutation ÖNCESİ snapshot kuyruğunu `try_send` ile preflight eder (kapalı/dolu kuyruk 503, state dokunulmamış kanıtlı: `recovery_closed_queue_is_preflight_503_and_state_unchanged`, `recovery_full_queue_is_preflight_503_and_state_unchanged`). try_send ile mutation arasında yield yok; ACK'in kapladığı generation yanıttaki key/generation ile doğrulanır (gerçek encrypted write/open/boot-restore: `recovery_confirmed_via_real_snapshot_write_and_restore` — restore sonrası eski key yok, eski authorization reddediliyor, taze challenge ile gateway çalışır).
- ACK beklenirken aynı hesaba daha yeni bir rotation girmişse 409 `durability:"confirmed"` ("superseded by a newer rotation") — ölü key asla confirmed dönmez (`recovery_racing_sequential_nonces_and_stale_retry_is_rejected`).
- WS iptali round-3'te TOCTOU-kapalı: private delivery READ guard'ını `ws_auth_valid` kontrolü + 5 s sınırlı send boyunca tutar; rotation WRITE guard'ında lineerize olur (`ws_revocation_race_slow_consumer_and_no_lock_across_send`). İlgisiz hesap isolation'ı korundu (`ws_unrelated_sessions_unaffected_by_rotation`). Timeout'u testte success sayma kuralı korunur.
- A01 deposit permit/credited-receipt taşıması, V7→V8 migration, DPSNAP8 trailer ve mevcut invariant'lar değişmedi (`a07_rotation_preserves_pending_routes_and_other_accounts`, migration/replay testleri değişiklik görmeden geçti).

### Bu head'de (50b3b26 tabanıyla) yeniden çalıştırılan doğrulama
- `cargo test --locked -p gateway s1_recovery_ws_tests -- --test-threads=1`: 16 passed / 0 failed.
- `cargo test --locked -p gateway`: 345 passed / 0 failed / 1 ignored (ignored: mevcut A01 localhost JSON-RPC cast testi; canlı zincir değil).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 0.
- Frontend: `pnpm test` 300 passed / 1 skipped (`realClient.e2e.test.ts`, canlı ortam gerektiren önceden var skip), `pnpm build` başarılı.
- Workspace geneli: `cargo test --workspace --locked` sonucu PR açıklamasında.

### Frontend S1/S2 karşılığı (job--10)
- Credential swap yalnızca tam doğrulanmış `durability:"confirmed"` yanıt sonrası atomik; 400/401/409/503/5xx, network/transport, bozuk yanıt ve wallet reddinde eski credential ve sealing korunur (`frontend/src/api/realClient.recovery.test.ts`, 20 test).
- Retry sözleşmesi sunucuyla aynı: retryable hatada taze metadata + taze imza; stale imza replay'i asla başarı sayılmaz.
- Monoton `credentialEpoch` guard: rotation öncesi başlayan refresh'in geç yanıtı post-rotation state'i ezemez; eski socket'in authOk/error frame'i yeni credential'ı temizleyemez.
- Çok sekme: `storage` event ile aynı-owner + daha yeni generation benimsenir; yabancı owner ve eski nesil reddedilir; legacy kayıtlar generation 0 sayılır.
- API key URL/log/telemetry'ye girmez (yalnızca `X-Api-Key` header ve WS auth frame).

### Hâlâ açık sınırlar
- Fiziksel crash/power-loss drill yapılmadı; restart kanıtı gerçek dosya yazımı + boot-restore testidir. SP1 ELF/vkey/proof/deployment doğrulaması bu işte yapılmadı ve açık olarak yapılmamıştır.
- Frontend↔gateway gerçek yerel E2E (mock'suz) hâlâ roadmap S2'nin açık maddesidir; bu head yalnızca mock'lu birim testleri ekler.
- try_send→mutation arası yield'sızlık tokio `Mutex` uncontended fast-path'ine dayanır; gözlemlenen bir açıklık yok, formal olarak runtime davranışına bağlıdır.
