# Chainlink aday arşivi: indeks retention ve kapasite

11 Ekim 2026. **PRODUCTION RELEASE HOLD.**

Bu paket, 4096 kabul girdisinin geçmiş boyunca birikmesini ve reddedilen rapor
tekrarlarının sınırsız disk kullanımını ele alır. Guest kaynakları, reviewed v2
kimliği, aday ELF/vkey ve aday submission engeli korunur.

Checkpoint için önerilen indeks; açık pencerenin fiyatlı op'larını, her marketin
halen kullanılabilen özgün oracle seçimini ve diskteki authenticated v6 WAL'ın
özgün referanslarını tutar. Seçilmiş kayıtlar yeniden doğrulanır. İndeks yalnız
aynı state/indeks kesitinin başarılı atomik snapshot yazımı sonrası değiştirilir.
Eski veya başarısız plan kabul edilmez. Runtime capture, dosya yazımı ve indeks
kurulumu aynı iptal edilemeyen worker içinde gateway mutasyon kilidini tutar.

Yeni authenticated `DPCAS3` zarfı WAL beklentisini de saklar. Beklenen WAL eksik
veya bozuksa startup/checkpoint HOLD eder. DPCAS2 okuma uyumluluğu korunur;
tespit edilebilen tamamlanmamış seal de WAL gerektirir. DPCAS1 uzlaştırma için
korunarak reddedilir. Recovery çözülmüş state'i ve WAL gerekmeyen checkpoint'i
kalıcılaştırdıktan sonra WAL'ı siler. Bu bir anti-rollback veya her admission
için sıfır kayıp garantisi değildir.

Tam rapor kayıtları append-only kalır. Eski checkpoint, backup, dışarı aktarım
ve tarihsel veri erişimi için dosyalar otomatik silinmez. İndeks retention,
dosya retention'ından ayrıdır. 4096 gerçekten canlı kimlik hâlâ kapasite HOLD'u
üretir; yalnız artık ihtiyaç duyulmayan indeks girdileri serbest bırakılır.

Varsayılan mantıksal arşiv bütçesi 256 MiB ve 65.536 girdidir. Candidate moddaki
opsiyonel `DARKPERP_CHAINLINK_ARCHIVE_MAX_BYTES` ve
`DARKPERP_CHAINLINK_ARCHIVE_MAX_RECORDS` bunları ayarlar. Sıfır/geçersiz veya
candidate dışındaki kısmi ayarlar reddedilir. Özgün `.json` kayıtları ve crash
`.pending` dosyaları bütçeye dahildir. Envanter sınırlıdır; symlink, yabancı
dosya, güvensiz izin veya geçersiz boyut HOLD eder. Bu mantıksal bütçe fiziksel
diskte boş blok garantisi değildir; gerçek I/O hatası da admission'dan önce
reddedilir. Tek servis arşiv sahibidir; ayrı süreçler için dağıtık kota kilidi
iddiası yoktur.

Aynı seçilmiş transcript kapasite doluyken de özgün ID ile doğrulanır; yeni
receipt kardeşi yazılmaz. Yeni kimlik kota veya indeks sınırında callback/state
değişiminden önce reddedilir. `archive_pressure` bildirimi sabit, redacted
operasyonel olaydır; bildirim teslimi kabul veya kalıcılık kararını değiştirmez.

Nihai kaynak SHA, komutlar, test keşfi ve kaynak/log hash'leri
`verification.json` içinde kaydedilir. CPU replay, gerçek SP1 proof ve canlı DON
doğrulaması ayrı kabul kapılarıdır.

Doğrulanmış kod: `1b5dcaac31e409fde1f554c5182c65c192da5c59`;
taban main: `c82dd492f74a47ab3806395dd05b46b3dff884e4` (#45).
Nihai tam gateway koşusu **541 PASS / 0 FAIL / 16 IGNORE**; istemci debug ve
release ayrı ayrı **69 PASS / 0 FAIL / 1 yardımcı IGNORE**. 47 Python guard,
workspace/istemci all-target Clippy `-D warnings`, iki format kontrolü ve
21 reviewed + 9 aday kaynak pini başarılıdır. Ignored child helper mevcut
parent kesinti testinden açıkça çalıştırılır.

Yeni altı gateway regresyonu 4.100 gerçek gateway admission + restart,
açık/live/WAL referansları, indeks/kota doluluğu, failed save, beklenen WAL
kaybı ve worker iptalini kapsar. Raporlar sentetiktir. Tam koşuda görülen
iptal testi yarışı, mutex rezervasyonu yerine gerçek worker başlangıcını
bekleyen per-call oneshot ile düzeltildi; kilit, değişmeyen indeks, dosya
yokluğu ve sonraki kalıcı kesit kontrolleri korunur. Odaklı kontrol ve 100
tekrarın kaydı `worker-entry-followup.json` içindedir. Transcript logları
sonradan araç çıktısından aktarılmış olarak açıkça etiketlenir; nihai tam
koşunun logları doğrudan dosyaya yakalanmıştır. İki başarısız önceki koşunun
kaynak/komut/log hash'leri de `verification.json` içinde korunur.

`merge-observations.json`, #44 ve güncellenmiş #45 head'lerinin 19/19 başarılı
kontrol ve normal merge sonucunu kayıt zamanında gösterir. Bu sonuç yeni A2
yayın head'inin CI sonucu değildir; A2 PR CI ayrıca izlenir. Birincil checkout'un
13 özgün dosyasının hash'leri değişmemiştir; job--17 özgün head/staged dosyaları
korunur. Ham loglar yerel `target/retention-validation-20261011/` içindedir.
