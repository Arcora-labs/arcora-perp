# Chainlink aday kabul indeksinin snapshot/restart kurtarması

11 Ekim 2026. Doğrulanan kod: `4977d54d35501234e6307555ce7aed7a70e62c07`. #44'ün kanıt düzeltmesi `5cb1470` üzerine ayrı devam dalı. **PRODUCTION RELEASE HOLD.**

DPCAS2 authenticated snapshot; gateway state/açık işlem penceresi, tam politika bağı ve `(market, transcript) → ilk özgün ArchiveId` indeksini tek payload'da saklar. Intake, seal ve snapshot capture gateway → archive kilit sırasını paylaşır. Atomic snapshot yazımı bütün kesiti birlikte kalıcılaştırır; binding kilidi zehirlenirse legacy snapshot üretilmez. Runtime, shutdown ve boot-recovery yazım yolları aynı bağlamı kullanır.

Startup yalnız snapshot içindeki beklenen özgün kimlikleri geri kurar. Her kayıt politika altında özgün kabul zamanıyla yeniden normalize edilir; tekrar, kapasite, kanonik olmayan kodlama, trailing payload, yanlış politika veya eksik/bozuk kayıt açılışı reddeder. Sonra restored açık op akışı bu kimliklerle doğrulanır; marker kaybı farklı bir politikayı kabul ettirmez. Eşdeğer fiyatlı kardeş kayıt ve dizindeki en yeni dosya fallback değildir. Doğrulanmış v6 journal referansları ilk kabul kimliğiyle çatışmadan ve atomik olarak recovery indeksine eklenir.

## Kapsam ve sürüm sınırı

Geçerli legacy snapshot baytları ve reviewed v2 guest/prover kimliği korunur. Önceki aday DPCAS1 yalnız mod etiketi taşıdığı için otomatik açılmaz; dosya korunarak uzlaştırma gerekir. Yeni DPCAS2 checkpoint'ler özgün indeksle geri kurulabilir. Canlı state migration yapılmadı.

Dayanıklılık başarıyla kalıcı yazılmış snapshot kesitine aittir. Son snapshot'tan sonraki bütün admission'lar için ayrı WAL/sıfır veri kaybı garantisi eklenmedi; mevcut pre-seal `SealNeverPersisted` recovery satırı/RPO sürer. Tüm kabul edilmiş fakat kullanılmamış kimlikler de saklanır/doğrulanır; A2 retention tamamlanmadan kayıt silme/indeks eviction yapılmaz.

## Doğrulama

Son kod için: **535 gateway PASS / 0 FAIL / 16 IGNORE**, bunun içinde **29 binding/restart PASS**; **47 Python guard PASS**. Workspace all-target Clippy `-D warnings` ve format temiz. Test boyunca 7 değişen kaynak girdisinin hash'leri sabit. 29 test toplam 535'in içindedir; ignored testler geçmiş sayılmaz. Bu tur tam workspace/standalone istemci testleri yeniden koşulmadı.

[verification.json](verification.json) gerçek komut, kod SHA'sı, kaynak/log hash'leri ve sonuçları taşır. Ham loglar özel yerel `target/continuation-validation-20261011/` altında kalır; snapshot/witness/credential yayımlanmaz. Önceki e283958 kanıtı [A0 audit](../2026-10-11-chainlink-archive-gateway-binding/README.md) içinde kendi kod sürümüne bağlıdır.

Kabul senaryoları:

- İki farklı kaynak zamanlı sentetik raporla gerçek gateway kabul/fill çağrıları; mühürleme öncesi snapshot/restart sonrası aynı op sırası, özgün kimlikler ve native commitment.
- Gerçek post-seal snapshot + stage-1 journal rollback; başarısız recovery yazımında eski checkpoint ve WAL baytları korunur; başarılı save sonrası WAL silinir ve pencere aynı batch/ops/ID/native commitment ile yeniden seal edilir.
- Marker yokken yanlış politika, aday yapılandırma eksikliği, seçilmiş kayıt eksik/bozukken eşdeğer kardeş kaydın varlığı, reddedilmiş orphan ve yarım state/index kesiti güvenli ret verir.
- Runtime ve final snapshot yazım hataları önceki bütün checkpoint'i korur. Poisoned arşiv kilidi, legacy downgrade, eski/gelecek sürüm, trailing/noncanonical/duplicate/capacity payload ve journal kimlik çatışmaları reddedilir.

Bu testler synthetic DON container'ları, gerçek gateway imzaları/engine çağrıları ve **native MockProverClient** replay kullanır. Kriptografik SP1 proof veya canlı DON doğrulaması değildir. Aday v2 gönderim/exact-resume engelleri, sıfır-oracle ve wind-down dahil, yerinde kalır.

## Açık sonraki paket

A2: 4096 indeks sınırı, aktif referansları koruyan retention ve disk doluluğu politikası. A3: funding/liquidation/close/mark/matching/withdrawal bütün aday yaşam döngüsü. A4: ayrı v3 prover/settlement rotası. Canlı feed/entitlement keşfi kullanıcı kararıyla ertelenmiştir; gerçek fon/exit/proof ve production kabulü açıktır.
