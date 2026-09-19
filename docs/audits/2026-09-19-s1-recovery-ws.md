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
- `cargo test -p gateway`: 338 passed / 0 failed / 1 ignored (ilk S1 head'i `0cde5ee` için).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`: exit 0 (aynı head).
- CI (head `0cde5ee`, 4/4 success): ci `35446306970`, a01 `35446306976`, a07 `35446306966`, a11 `35446306965`.

## Bağımsız review sonrası ikinci tur (head: bu dalın son commit'i)

Bağımsız current-main incelemesi iki noktayı doğruladı, biri yeni bulgu:

### B3 — Eşzamanlı rotation'da superseded key'in "confirmed" dönmesi (yeni, düzeltildi)
- Konum (önceki head `0cde5ee`): `post_v1_recovery` ACK sonrası yakalanan key'i aktiflik kontrolü olmadan dönüyordu. A (nonce=0) ACK'de takılıyken B (nonce=1) rotation'ını onaylatırsa, A'nın ACK'ı geç tamamlandığında A ölü key'i 200 confirmed ile dönebiliyordu.
- Düzeltme (`main.rs:6242-6266`): ACK sonrası kısa kilit altında `accounts.contains_key(&key)`; key artık aktif değilse 409 `{"error":"recovery superseded by a newer rotation","durability":"confirmed"}` — ölü key asla dönülmez. Client, GET recovery view'daki güncel nonce ile yeni authorization üretir.
- Failing-before kanıt: recheck `true` sabitiyle devre dışı bırakılıp `recovery_interleaved_rotation_returns_superseded_not_dead_key` çalıştırıldığında test 200 + ölü key gördüğü için FAILED; geri yüklemede geçiyor.

### İnceleme kanıtı — WS'te komut yürütme yolu yok
- `ws_non_auth_command_frames_do_not_mutate_state`: authed oturuma placeOrder/cancel/withdraw/subscribe/garbage/binary frame gönderiliyor; Gw kilidi altında hesabın byte-değişmemişliği (emirler boş, nonce aynı, deposit/credit yok) ve bağlantının sağlıklı kalması doğrulanıyor. WS yalnızca `auth` implemente eder; bu test "komut çalıştırma yok" invariant'ını sabitler.

### Kilit sınırı — revocation/send sınırında global kilit yok
- `ws_revocation_race_slow_consumer_and_no_lock_across_send`: 50 özel event okunmadan yayınlanıp socket backpressure altıyken rotation isteği 5 sn içinde tamamlanıyor (kilit socket send'de tutulmuyor); revoke sonrası bounded drain'de sıfır owner event; yeni key ile event akışı doğrulanıyor.

### Restart/pending semantiği — secret sızıntısı yok
- `recovery_restart_drops_pending_retry_and_rejects_old_authorization`: rotation + snapshot roundtrip (restart) sonrası `recovery_last` None; eski nonce-0 authorization reddedilir (nonce mismatch), key1 GERİ VERİLMEZ; GET view `recoveryNonce:1` döner → client taze authorization üretebilir. Kayıp yanıtın restart sonrası kurtarımı yalnızca yeni authenticated generation üzerinden.

### İkinci tur doğrulama (exact head, bu oturumda)
- `cargo test -p gateway`: 342 passed / 0 failed / 1 ignored (+4 yeni test).
- `cargo fmt --all --check` ve `cargo clippy -p gateway --all-targets --locked`: exit 0, sıfır warning.

### Üçüncü tur (bağımsız review #3): sıkılaştırma

1. **Kuyruk pre-flight** (`main.rs:6230-6256`): kapalı/dolu snapshot kuyruğu, geri döndürülemez bellek içi rotation'dan ÖNCE `try_send` ile yakalanıyor; 503 unknown + state kanıtlanmış biçimde dokunulmamış. Failing-before: pre-flight devre dışıyken kapalı-kuyruk testi state'i mutate edip 30 sn timeout'a düşüyor (FAILED).
2. **Strict fresh-challenge retry**: idempotent stale-nonce retry kaldırıldı (`recovery_last` silindi); kullanılmış/eski authorization her zaman reddedilir. Unknown/timeout/kayıp yanıt/restart sonrası istemci GET view'dan güncel nonce'u alıp YENİ imza üretir: rotation bellekte uygulanmışsa ikinci bir rotation (güvenli, monotonic), revert olmuşsa doğrudan başarı. Kilitlenme yok; secret yalnızca ACK sonrası çıkar.
3. **WS TOCTOU kapandı** (`App.ws_delivery` RwLock): event kolu READ guard'ı `ws_auth_valid` kontrolü + sınırlı (5 sn) send boyunca tutar; `post_v1_recovery` pre-flight'tan yanıta kadar WRITE guard tutar. Lineerizasyon: teslimat = kontrol anı, iptal = write-guard edinimi; TCP'ye çıkmış frame'ler geri alınamaz. Rotation, bağlantı başına en fazla bir sınırlı in-flight send kadar gecikir (kuyruktaki okunmamış event'lerle değil).
4. **Gerçek write/restore handler testi** (`recovery_confirmed_via_real_snapshot_write_and_restore`): writer stub production `write_snapshot`'ı aynen çağırır; sealed dosya `snapshot::open` + `Gw::boot_restored` ile açılır; key/nonce kalıcılığı, eski key'in yokluğu, restore sonrası stale replay reddi ve fresh challenge başarısı doğrulanır.
- Not: round-2'nin interleaved-409 testi write guard ile yapısal olarak imkansız olduğundan `recovery_rotations_serialize_against_inflight_ack` ile değiştirildi (recheck derinlik savunması olarak durur).
- Doğrulama (exact head): `cargo test -p gateway` 345 passed / 0 failed / 1 ignored; fmt ve workspace clippy exit 0.

## Mock/sınır ve kalan riskler
- Snapshot writer testlerde stub (ack-true/false/park/drop); gerçek disk hatası/fsync davranışı ve fiziksel crash drill yapılmadı (S6 konusu).
- WS testleri gerçek socket üzerinden; broadcast kuyruğu dolu/replay edilmiş event senaryosu `ws_auth_valid` kapısında kapsanıyor ama üretim yükü altında ölçülmedi.
- `ws_auth_valid` owner hex üzerinden hesap bulur; aynı owner ile birden fazla hesap varsa davranış belirsizdir (kayıt modelinde owner'ın unique varsayımı, mevcut kodun genel varsayımı).
- Tam codebase audit bitmedi; gerçek SP1 ELF/vkey/proof/deployment doğrulaması yapılmadı.
