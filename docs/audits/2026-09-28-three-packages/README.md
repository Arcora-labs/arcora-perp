# Üç yerel paket — 28 Eylül 2026

Kapsam: S6-03 RPC tutarlılığı, S6-02 gerçek gateway ACK/kesinti/restore matrisi ve S7-01 yerel alarm teslimi. Üçü, özgün yedi işin alt paketleridir. **Özgün toplam: 15; önce kapanan: 8; bu tur kapanan ana iş: 0; kalan: 7.** Kabul metinleri ve bağımlılıklar değiştirilmedi. Yayın kapısı HOLD.

**Doğrulama:** 433 gateway testi, 31 odaklı L1 testi, 6 cursor regresyonu, 7 gerçek cast/HTTP matrisi ve 6 alarm testi başarılı. ACK matrisi 9/9, gerçek SIGKILL sayısı 27. Test kümeleri örtüşür; sayılar toplanmaz. Fmt, tüm workspace Clippy ve production gateway build geçti.

**Teslim:** [PR #25](https://github.com/Kubudak90/dark-perp/pull/25). GitHub Actions hesap ödeme/harcama limiti nedeniyle 13 işi runner atamadan durdurdu; Linux CI çalışmadı (`ci-evidence.json`). PR merge edilmedi. Yerel paket kapısı PASS, yayın kapısı HOLD.

## Tamamlanan uygulama

- **RPC:** ilişkili L1 kelimeleri aynı canonical hash üzerinden okunur. Witness yapılandırılmışsa zincir, hash ve değer uyuşması zorunludur; hata tek sağlayıcıya düşmez. Gate mevcut 12 blok politikasını korur; terminal/challenge kontrolleri güncel blok kullanır. Vault count/tip ve claim budama birlikte doğrulanır. Challenge keşfi 1.024 blok/4.096 olay sınırındadır. Bekleyen en çok 16.384 hash, discovery imlecinden ayrı tutulur; başarısız veya henüz batch’i oluşmamış kayıt diğerlerini engellemez. Süresi dolan açık kayıt terminal sayılır. Önceki tarama hash’i fetch öncesi ve sonrası tekrar kontrol edilir; doğrulanmış reorg pencereye geri sarar. İmzalama/nonce/transaction gönderimi gözlem kapsamının dışındadır.
- **Kesinti:** authorize, recovery ve cancel için gövde gönderilmeden önce, sunucu yanıtı istemciye ulaşmadan ve tam HTTP 200 alındıktan sonra SIGKILL uygulanır. Gerçek şifreli snapshot üzerinden restart ve ikinci restart kontrol edilir. Recovery kayıp credential’ı yeni public challenge ile çözer. Cancel tekrarında yeni execution oluşmaz. Yanıtı kaybolan authorize imzası **çözümlenmemiş unknown** kalır; otomatik yeniden yetkilendirme veya zincir gönderimi yapılmaz.
- **Alarm:** gerçek HELD geçişi, snapshot/final-snapshot yazma arızası ve VaultSource tarafından tespit edilmiş finalized-anchor değişiminden doğan deposit halt, gerçek yerel HTTP collector’a gider. Sabit enum şeması secret/hata metni taşımaz. Dedup, recovery/rearm, 503, timeout ve redirect reddi doğrulanır. Alarm durumu snapshot formatına eklenmez; bildirim hatası kalıcılık başarısı üretemez.

## Kanıt ve inceleme

Nihai komut sonuçları, kaynak manifest’i ve binary kimliği `verification.json`, `source.json`, `checks/`, `l1/`, `alerts/` ve `ack-crash/` altında kaydedilir. `graph-report.json` yalnız bu üç yerel paketin sözleşmesini doğrular; özgün release kapısını açmaz.

Bağımsız inceleme challenge olay keşfi, erken cursor ilerletme, süresi dolmuş açık kaydın kuyruğu durdurması, henüz settle edilmemiş batch kaydının atlanması ve iki polling turu arasında/anchor kontrolüyle fetch arasında reorg bulgularını yakaladı. Bunlar kod ve ilgili regresyonlarla giderildi. Statik inceleme ile çalıştırılmış test kanıtları ayrı tutuldu.

İlk derleme/clippy hataları ve ara kaynak sürümlerindeki sonuçlar `attempts/` altında korunur. Nihai paralel gateway testinde eski HTTP fixture’ının accepted socket’i macOS’ta listener’ın nonblocking modunu miras aldığı için WouldBlock görüldü; ayrı alarm collector çalıştırması aynı sorunu doğruladı. Her iki bloklayan fixture parser’ı accepted socket’i açıkça blocking moda geçirir; süre sınırları ve assertion’lar korunur. Alarm collector cleanup’ı ilk başarısızlığın üstüne ikinci panic üretmez.

## Açık özgün işler

| İş | Kalan kapanış gereği |
|---|---|
| S5-02 | Normal native/guest kanıtı korunur; tutulmuş A06 phase 1/2 parçası bu tur yeniden denenmedi. |
| S5-03 | Yeterli proving belleğinde gerçek tamamlanmış proof ve mevcut target-verifier pozitif/negatif kabulü. Önceki 5 GiB Docker OOM/137 tamamlanmış proof değildir. |
| S6-01 | Gerçek yerel test-token deposit → trade/cancel → proof settlement → withdraw/claim ve acil çıkış muhasebesi. |
| S6-02 | Bu tur gerçek HTTP ACK alt matrisi tamamlandı; tam fon akışındaki kesinti/restore ve S6-01 bağımlılığı sürer. |
| S6-03 | Bu tur normal authoritative okuma politikası tamamlandı; birleşik fon/reorg matrisi, canlı deployment/source eşlemesi ve S6-01 bağımlılığı sürer. |
| S7-01 | Bu tur üç yerel alarm akışı tamamlandı; diğer kritik alarmlar, gerçek olay sahipleri/escalation ve tam restore/CloseOnly tatbikatı sürer. |
| S7-02 | Tüm release kapsamının bağımsız incelemesi, aynı release kimliğine bağlı eksiksiz kanıt ve ayrı yayın kararı. |

Sınırlar: gerçek RPC sağlayıcı kullanılmadı, zincir işlemi gönderilmedi, tam fon akışı/gerçek proof/yayın yapılmadı. Snapshot bildirimleri her journal hatası, eksik writer veya ACK timeout’unu kapsamaz. Alarm teslimi sınırlı kuyruğa bağlı best effort’tur; işlem sonlandırılırken kuyrukta kalan mesajın teslimi garanti edilmez. Süreç SIGKILL testi fiziksel güç kesintisi değildir. Mevcut Desktop checkout’un HEAD’i, 62 dosya hash’i ve 21 status kaydı değişmedi (`desktop-preserved.json`).
