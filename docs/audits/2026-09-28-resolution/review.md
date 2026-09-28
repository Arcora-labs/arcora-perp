# Kabul kapsamı ve kod incelemesi

Başlangıçtaki ZIP'in S4-03, S4-05 ve S4-07 kabul maddeleri kod ve ham test kanıtlarıyla ayrı bir read-only incelemede karşılaştırıldı. Sonraki raporlarda eklenmiş production kapasitesi, IP adaleti, kalıcı kopmuş-istemci sonucu ve gerçek proof koşulları bu üç yerel görevin kapanışını değiştirmiyor.

| Görev | Orijinal kabulü karşılayan kanıt | Sınır |
|---|---|---|
| S4-03 | Seal/journal ortak kilidi; snapshot ACK; tek finalized hash; eski pending sonuçta kayıt koruma; 21 SIGKILL vakasında eski/yeni state ve withdrawal root/proof sürekliliği; matching landed gözlem sonrası bir kez commit | Native/MockProverClient; gerçek işlem yayını, proof veya tüm fon akışı değil |
| S4-05 | Yeni 6 birleşik test: kalıcı restart/reseal, gerçek curl/HTTP, 401 sonrası tek session token ve sealing-key yenileme, ikinci 401'de durma, yanlış batch/root/phase reddi, proof dönüşüyle erken SETTLED/claimable olmaması | Prover yeniden başlangıcı/session expiry, native peer ve scripted 401 ile modellenir; gerçek gateway state restore edilir. Gerçek SP1 service reboot/attestation veya kriptografik proof değil |
| S4-07 | Exact origin/CORS; ortak WS kapasitesi ve mesaj/rate/write sınırları; auth-before-body; body timeout ve anında admission/capacity reddi; kabul edilmiş işlerin drain edilmesi; son snapshot ve eski credential restore; bağlı/kopmuş istemciyle gerçek prover SIGTERM | Yerel kapasite ve sentetik worker. Production kapasitesi veya takılmış gerçek proof backend'ini zorla sonlandırma garantisi yok |

Bu tur [gateway 407](checks/gateway.json), [cast 1](checks/cast-loopback.json), [prover 8](checks/prover-service.json) tekrar geçti. Gateway paketindeki dört SIGKILL ebeveyn testi toplam 21 çocuk süreci öldürüp restore ediyor. Normal paketteki ignored testler: ayrıca çalıştırılan cast taşıma testi ve ebeveynlerin çağırdığı çocuk fixture. Prover'daki ignored test de SIGTERM ebeveynlerinin çağırdığı fixture.

Önceki [gerçek gateway süreç kanıtı](../2026-09-28-runtime/gateway-process/result.json) tarihsel kapsamıyla korunur. Bu tur gateway production kodu değişmedi; `main.rs` farkı yalnız `cfg(test)` test modülüdür. Yeni native test dosyası [burada](../../../crates/gateway/src/continuation_settlement_tests.rs). Eski 21 vaka manifesti [burada](../2026-09-28-runtime/crash-matrix/snapshot-sigkill-21.cases.json).

Deposit çözümünün bağımsız dar kod incelemesi iki hata buldu: yeniden deneme cüzdanında iptal sonrası retry durumunun kaybı ve hazırlıktan sonra aynı-owner credential rotation'ın Resume'u kalıcı durdurması. İkisi düzeltildi; üç işlem aşamasında iptal, sonraki rotation, başka owner reddi, bozuk/çelişkili arşiv, storage başarısızlığı, tekrar eden revert ve iki sekme testleri eklendi. Son dar inceleme CLEAR. Bu, bağımsız dış denetim/S7-02 değildir.

Finalized revert doğrulamasının ilk 41 regresyonu uygulama öncesinde başarısız oldu; [önce](wallet-before.log). Son wallet paketi 44 yeni durum dahil 75 geçti; [sonra](wallet-after.log). Bütün frontend için son kanıt [481 geçti / 1 atlandı](checks/frontend-unit.json); bu 1 atlanan test canlı gateway fixture'ıdır. [Chromium/WebKit](checks/frontend-browser.json) 78 geçti; gerçek extension veya Safari cihaz kanıtı sayılmaz.
