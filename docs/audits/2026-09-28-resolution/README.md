# Arcora — 15 açık işten 11'e

**Özgün kabul kapsamıyla 4 başlık kapandı: S4-03, S4-05, S4-07, S5-01. Kalan: 11 — 6 kısmi, 5 engelli. Production yayın kararı HOLD.** [Güncel kalan işler](remaining-work.md), [madde bazında durum](task-status.json), [kabul/kod incelemesi](review.md).

Kod adayı: `79396952d3422b6cda5c83d05cf60bfa1cded410`, dal `fix/arcora-deposit-resolution-20260928`. Kaynak içerik özeti: `aa9619641fe067ab3c17a0262d9028473277003127366086085dda26bd4ffca0`. Kontroller commit'ten önce bu içerikte çalıştı; commit ile byte eşliği [doğrulandı](source-validation.json). Yeni değişiklikler ayrı dalda inceleme için hazırlanmıştır; bu rapor merge veya yayın kararı değildir.

## Neler kapandı?

| Başlık | Kapanış | Bu tur ile önceki ilerlemenin ayrımı |
|---|---|---|
| S4-03 — Sequencer, finality ve rollback journal | Ortak seal/journal kilidi, snapshot ACK, belirsiz işlemi koruma, hash'e bağlı finality, kesinti sonrası tek commit/root sürekliliği | Önceki düzeltme ve 21 SIGKILL kanıtı tekrar doğrulandı; yeni birleşik restart/taşıma testleri eklendi. Gerçek proof ve fon akışı bu başlığın özgün yerel kabulü değildi. |
| S4-05 — Witness ve prover taşıma sınırı | S4-03 bağımlılığı ve birleşik retry/session/batch/root/phase matrisi | 6 yeni native entegrasyon testi; loopback HTTP/curl, session token ve sealing key yenileme, durable restore, erken SETTLED/claimable reddi. |
| S4-07 — HTTP/WS, kaynak sınırları ve kapanış | Origin/CORS, socket/message/rate/body sınırları, auth-before-body, kabul edilen işi koruyan drain | Önceki uygulama ile gerçek gateway süreç kanıtı korunur; güncel gateway ve prover paketleri tekrar geçti. Daha sonra eklenen kapasite/IP adaleti işleri ayrı tutuldu. |
| S5-01 — Release adayı ve gerçek guest ELF | Sabit aday commit, güncel lock/toolchain kimliği, gerçek ELF/vkey kaynak eşliği | 21 guest/core kaynak ve manifest dosyası geçmiş başarılı build ile eşleşti. Mevcut ELF 515.096 bayt; bütün güncel lockfile'lar ve araçlar adaya bağlandı. [Manifest](release-manifest.json). |

S4-03 ve S4-07 için kapanışın bir bölümü önceki raporun kapsamı yanlış genişletmesini düzeltir. Dört yeni özellik yazılmış gibi sayılmaz. Başlangıçtaki kabul maddeleri gevşetilmedi; production proof/fon sınamaları kendi S5/S6/S7 maddelerinde açık kaldı.

## Deposit için tamamlanan ek çözüm

Kayıtlı mint, approve veya deposit işlemi revert ettiğinde kullanıcı önce durumunu kontrol eder, sonra **Verify failure and allow retry** ile kesinleşmesini doğrular. Kontrol yalnız özgün hash, canonical block ve finalized receipt üzerinde çalışır. Başarılı/pending/unknown, kesinleşmemiş veya çelişkili yanıtlar retry açmaz.

Özgün kayıt ve başarısızlık kanıtı kalıcı arşive yazılmadan aktif işlem değişmez. Bu eylem transfer, imza, ağ değiştirme veya kredi isteği yapmaz. Ayrı **Resume original deposit** eylemi yalnız eksik adımları çalıştırır; tamamlanan mint/approve korunur. Cüzdan iptali, reload, aynı-owner credential recovery, storage hatası, tekrar eden revert ve iki sekme durumları doğrulandı. Hash'siz unknown işlem eşleştirmesi ayrı ek iş olarak açık; otomatik yeni transfer yok.

## Kontroller

| Kontrol | Güncel sonuç |
|---|---|
| Frontend | [481 geçti / 1 canlı-gateway fixture atlandı](checks/frontend-unit.json) |
| Chromium / WebKit | [78 geçti](checks/frontend-browser.json); sentetik EIP-1193 / HTTP yanıtları |
| Production frontend build | [Geçti](checks/frontend-build.json) |
| Gateway | [407 geçti / 2 özel fixture ignored](checks/gateway.json); 6 yeni birleşik test ve 21 SIGKILL vakası dahil |
| Gerçek cast → loopback | Normal pakette ignored olan test ayrıca [1/1 geçti](checks/cast-loopback.json) |
| Prover release paketi | [8 geçti](checks/prover-service.json); bağlı/kopmuş HTTP ile gerçek SIGTERM; sentetik worker |
| Rust format ve gateway clippy | [Format](settlement/format.json), [clippy](settlement/clippy.json) geçti |

Prover komutunun ortamı: `CARGO_TARGET_DIR=/tmp/arcora-prover-service-target`, `PROTOC=/tmp/arcora-tools/protoc-29.3/bin/protoc`, PATH başında `/Users/huseyinarslan/.cargo/bin:/tmp/arcora-tools/sp1-6.0.0`. Gerçek guest ELF derleme altyapısı mevcut; bu testler guest yürütme/gerçek proof üretimi değildir. Paket çıktısındaki worker panic bilinçli test enjeksiyonudur ve testi geçmiştir. Mevcut deprecated uyarılar logda korunmuştur.

Desktop'taki asıl checkout'un **62 dosya hash'i ve git durumu aynı**. Kendi test süreçleri kapandı; canlı cüzdan/zincir mutasyonu, deployment, dış kişiye mesaj veya engelli guest/proof yürütmesi yapılmadı. Önceden kayıtlı RSA bulgusu ve yayın kapıları bu çalışmayla kapanmış sayılmaz.
