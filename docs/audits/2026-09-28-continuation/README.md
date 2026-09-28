# Arcora devam çalışması — 28 Eylül 2026

Kalan işlerde deposit yarışları, settlement/journal tutarlılığı ve servis kaynak sınırları için düzeltmeler uygulandı; birleşik yerel doğrulamalar geçti. Frontend dependency audit **7 → 0** bulguya indi. Genel yayın durumu **HOLD**: ekin 15 maddesi hâlâ **10 kısmi / 5 engelli**; gerçek cüzdan, proof/fon döngüsü ve bağımsız yayın kapıları kapanmış sayılmıyor. [15 maddelik güncel tablo](remaining-status.md).

## Değişen davranış

- **Deposit:** hesap, credential nesli, deployment, market ve miktar baştan sabitleniyor; her async sınırda kontrol ediliyor. Sekmeler arası kilit ve kalıcı işlem günlüğü belirsiz gönderimden sonra ikinci transferi engelliyor. Başarı için kalıcı kredi onayı, doğru hesap/deployment/market ve tam miktar eşleşmesi gerekiyor. Hatalı/eksik yanıtta aynı transaction hash'i korunuyor. [Ayrıntı ve sınırlar](deposit-context-review.md).
- **Settlement ve crash recovery:** seal/journal/snapshot aynı state kilidinde; önceki sonuç ve her yeni seal için snapshot ACK var. Broadcast edilmiş olabilecek işlem, sayaç değişmedi diye geri alınmıyor. Belirsizlik journal'ı koruyor, `HELD` durumuna geçiriyor ve admin retry'ı reddediyor. Recovery okuması tek finalized block hash'ine bağlı; eksik/bozuk/fork değişmiş veri ilerlemeyi durduruyor. Kapanış snapshot'ı tamamlanırken mutation kilidi korunuyor. [Journal kanıtı](journal.md).
- **Servis sınırları:** gateway'de açık origin allowlist, HTTP/WS origin denetimi, ortak WS kapasitesi, mesaj/frame/write sınırları ve send deadline var. Prover kimlik/capacity denetimi body okumadan önce çalışıyor; body boyutu/zamanı ve eşzamanlı işler sınırlı. İstek iptali çalışan proof worker'ın slotunu erken bırakmıyor. [Servis kanıtı](service-policy.md).
- **Bağımlılıklar:** Vite 6.4.3 ve Vitest 4.1.11'e geçildi; sürümler ve lockfile sabitlendi. Vitest geçişinde testlerin storage izolasyonu düzeltildi. Güncel frontend audit 0; `rsa 0.9.10 / RUSTSEC-2023-0071` için yama hâlâ yok, bulgu bastırılmadı. [Güncel audit](dependencies.md).
- **Yanlış ortam iddiaları:** yerel gateway'de bile gösterilen “real proof / attested enclave / TLS / 10–20 dakika / canlı zincir” sabit metinleri kaldırıldı. Emir kabulü ile zincir üzerinde kesinleşmenin farkı açıklandı; hatalı yeni API key talimatı kaldırıldı. [Son görünüm](browser-gateway/after-disclosure-fix.png).
- **Deployment okuyucu:** vault `token()` getter'ı ve rol/adres eşlik kontrolleri düzeltildi; kontrat okuma hataları artık başarılı gözlem diye kaydedilmiyor. Gerçek salt-okunur RPC denemesi yine 403 verdi. [Gözlem](deployment-observation.json).

## Doğrulama

| Kontrol | Sonuç | Kanıt |
| --- | --- | --- |
| Gateway native suite | 393 geçti; normal pakette 1 özel transport testi atlandı | [Çalıştırma](checks/gateway-final.json) |
| Gerçek `cast` → scriptli loopback RPC | Atlanan test ayrıca 1/1 geçti; canlı chain değildir | [Çalıştırma](checks/cast-loopback.json) |
| Son servis politikası/gerçek router | 6/6 geçti; gateway suite ile örtüşür | [Çalıştırma](checks/gateway-policy-final.json) |
| Frontend unit/component | 371 geçti, 1 canlı e2e atlandı | [Çalıştırma](checks/frontend-final.json) |
| Chromium ve WebKit senaryoları | 66/66 geçti; kontrollü wallet/HTTP/WS fixture'ları | [Çalıştırma](checks/frontend-browser.json) |
| Gerçek Chromium → Rust HTTP/WS | İki sekme, sealed-order, recovery, eski key 401, storage adoption, reload geçti | [Ayrı entegrasyon](browser-gateway/README.md) |
| Prover admission | Gerçek standalone release/guest build yolu; 5/5 test; proof backend çağrılmadı | [Çalıştırma](service-prover-tests.json) |
| Deployment reader | 3/3 fixture testi | [Çalıştırma](checks/deployment-reader.json) |
| Frontend production build | Geçti | [Çalıştırma](checks/frontend-build.json) |
| Rust format / gateway clippy | Geçti | [Format](checks/format.json), [clippy](checks/gateway-clippy.json) |
| Frontend advisory audit | 0 bulgu, exit 0 | [Çalıştırma](dependencies-final.json) |

Gerçek gateway tarayıcı testinde imza sentetik EIP-1193 sağlayıcısıyla üretildi ve fonlama demo credit idi. Gerçek eklenti cüzdanı, token transferi, L1 settlement, TEE veya SP1 proof doğrulaması değildi. İki sekmenin gerçek private WS ve HTTP trafiği gateway'e gitti; route yanıtları taklit edilmedi. Test gateway/proxy temiz exit 0 ile kapandı, son snapshot hash'i kaydedildi. Tam listener drain veya process-kill/fsync matrisi bununla kanıtlanmış sayılmaz.

Testten sonraki yalnızca metin/yorum farkları `source-validation.json` içinde açıkça listelenir. Son küçük header etiketi kısaltması (`Test environment` → `Test`) nihai production build ve gerçek tarayıcı görsel/taşma kontrolünden geçti; API/wallet/protokol kodu değişmedi. Tam gateway koşusundan sonraki service-policy farkı yalnızca “frames” yerine “messages” açıklamasıdır; aynı nihai dosyada 6 policy/router testi ayrıca geçti. Eski kapsamlı koşudaki 4 yinelenmiş standalone test, modül entegrasyonundan sonra kaldırıldı; 393 sayısına ikinci kez eklenmedi.

## Kaynak ve teslim

Çalışma dizini: `/Users/huseyinarslan/.codex/worktrees/arcora-local-verification/dark-perp`.

Taban: `5c71b2d0a24e1e1e94efeff58df8e26b13190c1b` (`audit/arcora-local-20260927`). Değişiklikler bu ayrı çalışma kopyasında, commit edilmemiş durumda. Masaüstündeki checkout'un kaydedilmiş git durumu ve 19 dosya hash'i değişmedi; denetimin kapsamı [koruma kaydında](original-worktree-preservation.json) belirtilidir. Tam nihai dosya kimliği `source-manifest.json`, doğrulama eşlikleri `source-validation.json` içindedir. Commit, push, PR, deploy veya canlı zincir işlemi yapılmadı.

## Açık kapılar ve sıradaki iş

1. Ayrı test profili ve gerçek cüzdan eklentisiyle recovery/deposit/storage/CSP matrisi; unknown transaction için özgün bağlamı koruyan kullanıcı uzlaştırma akışı.
2. ACK/write/rename/fsync ve prepared-settlement sınırlarında tam process-kill/restore matrisi; gateway HTTP/WS drain ve uzun proof kapanış provası.
3. Çalışan read-only RPC ile deployment/roller/vault/verifier/vkey eşliği; finalized/reorg senaryoları. Bu çalışmadaki Base Sepolia endpoint'i 403 döndürdü.
4. A06 inceleme engeli çözülünce native/guest byte eşliği; ardından kullanılabilir proving altyapısında gerçek proof ve izole tam fon döngüsü. Docker daemon bu çalışmada erişilebilir değildi.
5. RSA bulgusunun çözümü veya açık risk kararı, olay sahipleri/alarmların gerçek teslimi ve dış bağımsız inceleme; sonrasında tek release SHA/toolchain/deployment paketi.

**Otomatik güvenlik incelemesi:** Önceki A06 guest doğrulaması “possible cybersecurity risk” gerekçesiyle engellenmiş. [Kayıt](../2026-09-27-local/protocol/a06-execution-gate.json) ve karantinadaki taslak korundu. Aynı yürütmeyi prompt değiştirerek veya başka ajan/araç üzerinden geçirmek denenmedi; bu oturumda desteklenen bir inceleme/itiraz aracı bulunmadı. Bu kısıt yalnız ilgili dala uygulandı; bağımsız düzeltmeler ve doğrulamalar yukarıda tamamlandı.
