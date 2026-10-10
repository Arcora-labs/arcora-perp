# Chainlink REST istemcisi: dört regresyonun düzeltilmesi

10 Ekim 2026. Dal `feat/chainlink-streams-client-20261010`; PR #43.
Önceki uzak head `8eab00f23a4c02c0fd9eca86decf8759290fd71e`.
Main tabanı `e552bbab6868b070ff9c3b8f4ed3b9dec1230288`.
**Yerel runtime doğrulaması başarılı; PRODUCTION RELEASE HOLD.**
Bu kayıt commit/PR CI öncesi hazırlanır; uzaktaki sonucu ayrıca doğrulayın.

## Uygulanan değişiklik

Kullanıcının tekrar deneme talebinde Mac'e kaynak yazımı başarılı oldu.
Önceki reddin detaylı nedeni mevcut kayıttan doğrulanamaz. Hiçbir araç güvenlik,
OS dosya izni, repository ruleset veya required CI ayarı değiştirilmedi.
Dosyanın eski SHA-256 değeri kontrol edilip yedeklenerek önceden hazırlanmış
aynı yama uygulandı. Önceki yerel test ve belge değişiklikleri korunmuştur.

ReceiptClock her ileri duvar saati adımından sonra geçen monotonic süreyi
izler; retry, duran saat veya alt-ms örnekleme kaynağı tazelemez. Sıfır, geri
zaman ve taşma güvenli ret verir. Auth için gerçek saat kullanılır; kaynak
raporu veya imza yeniden yazılmaz. Normal zaman ilerlemesi iki kez sayılmaz.

HTTP Content-Length yalnız ASCII rakamlarıdır; + işareti reddedilir.
Transfer-Encoding tek chunked alanıyla sınırlıdır. Yinelenen alan, desteklenmeyen
kodlama ve Content-Length ile karışık framing, body decoder öncesi reddedilir.
Valid chunked yanıt ve mevcut 64 KiB limitleri korunur; ureq değiştirilmedi.

## Test ve kanıt kapsamı

Önceki 34 runtime testi değiştirilmedi. Bunlardan dört tanesi eski kaynakta
başarısızdı; tarihsel baseline sonuçları `../2026-10-10-chainlink-client-regressions/`
altındadır. Altı deterministik saat testi eklendi. Debug koşusu **40 PASS,
0 FAIL, 0 IGNORE**. Release koşusu da **40 PASS, 0 FAIL, 0 IGNORE**;
aynı testlerin iki profilde koşulması 80 farklı test anlamına gelmez.

Clippy (-D warnings), format, reviewed release, candidate lock ve kaynak pin
kontrolleri başarılıdır. 21 eski reviewed ve 9 ayrı aday runtime girdisi aynı.
Mevcut standalone istemci CI'ı artık gerçek testleri çalıştırır; compile-only
başarı runtime kanıtı sayılmaz. CI korumaları gevşetilmedi.

13 saf HMAC/parser, 21 gerçek loopback HTTP ve 6 deterministik saat testi
kullanılır. Yalnız açık sentetik kimlikler ve sahte rapor imzaları kullanıldı.
HMAC known-answer vektörü Python stdlib ile hesaplandı. Gerçek kimlik
bilgisi dosyası okunmadı, dış servise credential gönderilmedi. Döndürülen
UnverifiedReport hâlâ DON açısından doğrulanmamıştır; TLS endpoint doğrulaması,
canlı Chainlink hesabı, gerçek proof veya fon güvenliği kabulü değildir.

verification.json gerçek komut/exit/log hash'lerini, kaynak ve yayımlanan kanıt
hash'lerini içerir. Test log'unda yalnız checkout yolu normalize edilmiştir.
Ham kayıtlar ignored target/chainlink-client-fix-20261010T190741085776Z altındadır.
Bu dar pakette geniş workspace/Foundry/frontend/Anvil/restore testleri yeniden
koşulmadı; ilgili çalışma kodları değiştirilmedi.

## Açık kalanlar

Gerçek feed/ölçek/USDC kimlikleri ve hesap erişimi; gateway/prover/L1 bağlantısı,
rapor kalıcılığı, kesinti kurtarması, tam işlem döngüsü ve yeni gerçek proof
kabulü açık. Guest/perp-core/sözleşme/witness/public input, risk eşikleri ve
bağımlılık kilitleri bu düzeltmede değiştirilmedi. State migration, ücretli
altyapı veya production rollout yapılmadı. Güncel sıra docs/ACTIVE_WORK.md.

## Birincil teknik referanslar

- https://docs.chain.link/data-streams/reference/data-streams-api/authentication
- https://www.rfc-editor.org/rfc/rfc9110.html#name-content-length
- https://www.rfc-editor.org/rfc/rfc9112.html#name-transfer-encoding
