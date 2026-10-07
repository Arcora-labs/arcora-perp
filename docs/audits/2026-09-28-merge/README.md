# Arcora — 28 Eylül 2026 birleştirme kaydı

Bu paket deposit kurtarma ve işlem bağlamı kontrollerini, journal/snapshot kalıcılığını, gateway/prover kapasite ve kapanış düzeltmelerini, frontend bağımlılık güncellemelerini ve bunların yerel kanıtlarını birleştirir. [Kalan iş raporu](remaining-work.md) **15 açık görevi — 10 kısmi, 5 engelli —** ve sonraki kabul adımlarını listeler. Kod birleştirme yetkisi verildi; production yayın kararı **HOLD** olarak sürer.

## Birleştirme kapsamı

- Hash'i bilinen özgün deposit için durum/credit uzlaştırması; farklı wallet, owner, market, deployment veya journal revision ile yanlış/yeni gönderimin engellenmesi. Hash'siz unknown send kayıtları korunur.
- Emir ve demo deposit akışında recovery/credential değişimlerine karşı gönderim öncesi ve yanıt sonrası kontrol; açık WS kimlik reddinden sonra yeni mutation yok. Credential kaydı silinmez ve otomatik replacement account açılmaz.
- Seal + stage-1 journal kilidi, snapshot ACK, hash'e bağlı finalized gözlem ve belirsiz prepared settlement için kayıt koruma.
- Sınırlı HTTP gövdesi/süresi/kapasitesi, origin ve WS sınırları; kabul edilmiş HTTP/arka plan işi bitmeden final snapshot veya prover runtime kapanışı yok.
- Frontend bağımlılık güncellemeleri, test ortamını doğru anlatan metinler ve 320 piksel adres taşması düzeltmesi.

## Kaynak ve kontroller

Başlangıç tabanı `5c71b2d0a24e1e1e94efeff58df8e26b13190c1b`; entegrasyon dalı `fix/arcora-runtime-20260928`. Kontrol kayıtları kendi kaynak hash'leriyle değerlendirilir. Önceki [continuation](../2026-09-28-continuation/README.md) ve [runtime](../2026-09-28-runtime/README.md) paketleri tarihsel kanıt olarak korunmuştur.

- Tüm native Rust workspace: **769 geçti, 0 başarısız, 2 ignored**. Gateway bunların 401'ini içerir. [Komut/sonuç](checks/workspace.json).
- Workspace format ve clippy: **geçti**. [Format](checks/format.json), [clippy](checks/clippy.json).
- Son frontend: **413 geçti / 1 canlı-gateway testi atlandı**; production build geçti. [Son komut ve hash kayıtları](frontend-guard-final-checks.json).
- Son Chromium/WebKit paketi: **72 geçti**. [Son tarayıcı kaydı](checks/frontend-browser-final.json). Önceki `frontend-browser` kaydı ara guard revizyonunu doğrular.
- [Son kaynak manifesti](source-manifest.json) ve [kapsama göre kanıt eşlemesi](source-validation.json) PASS. Herhangi bir kaynak değişiminde ilgili kontroller yeniden değerlendirilmelidir.
- Gerçek `cast` loopback: önceki runtime kaydında ayrıca 1/1; kaynak eşlemesi korunur.
- Prover bağımsız release paketi: önceki runtime kaydında 8/8; bu merge sırasında prover kaynağı değişmedi.
- 21 gerçek SIGKILL vakası ve 3 gateway SIGTERM senaryosu/4 temiz süreç çıkışı önceki runtime paketiyle kaynak bazında eşlenir.

Native workspace içinde bulunan `a06_*` testleri normal host testleri olarak çalışır. Önceki otomatik incelemede engellenen A06 guest yürütmesi, native/guest byte eşitliği veya gerçek proof bu paketin kanıtı değildir.

Merge öncesi ek çapraz inceleme, order/demo deposit yollarında eksik mutation kontrolünü ve storage adoption tamamlanmadan eski yanıtın kabulünü buldu. Toplam 17 regresyon senaryosu eklendi; önce başarısız olan durumlar son kaynakta geçti. [Düzeltme ve inceleme](frontend-guard-final-review.md).

Ham test logları içerik hash'lerini korumak için byte düzeyinde değiştirilmedi. Tam diff whitespace kontrolü bu ham logların sondaki boş satır/boşluklarını bildirir; kaynak kodu ve diğer metinler için `git diff --check origin/main...HEAD -- . ":(exclude)docs/audits/**/*.log"` geçti. Bu ayrım çalıştırılan testleri veya kabul sonuçlarını değiştirmez.

## Önceden var olan yerel çalışma

`<repo>` üzerindeki kirli `main` checkout'u ayrı, önceden var olan A06 wind-down/v9 snapshot çalışmasını içerir. Bu checkout olduğu gibi korunmuştur; bu pakete taşınmamıştır. 62 değiştirilmiş/izlenmeyen dosyanın bytes/hash doğrulamalı yedeği, çalışma/index patch'leri ve porcelain durumu kayıt altına alınmıştır. [Korunum/yedek kaydı](original-preservation.json).

Yerel eski `main` checkout'unu `origin/main` üzerine güncellemek, o ayrı çalışmanın çakışmalarını çözmeyi gerektirir. Bu merge, ilgili yerel dosyaları sıfırlama veya geçmişteki A06 çalışmasını kaybetme işlemi değildir.
