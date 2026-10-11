# Chainlink: özgün rapor çifti arşivi ve witness hazırlığı

11 Ekim 2026. **PRODUCTION RELEASE HOLD.**
PreparedPair/ReportArchive host istemci bileşenidir. #44 bunu opt-in aday
gateway intake, authenticated v6 journal ve aday checkpoint ile bağlar.
Legacy varsayılan davranış korunur; aday prover/settlement yolu kapalıdır.
`e283958` için exact-code kanıtı: [önceki doğrulama](audits/2026-10-11-chainlink-archive-gateway-binding/README.md).
A1 devam kodunun ayrı kaydı: [kabul indeksi recovery](audits/2026-10-11-chainlink-admission-recovery/README.md).
A0/#44 ve A1/#45 artık main'dedir; her biri güncel yayın head'inde 19/19
başarılı kontrol sonrası normal merge edildi. Bu dalın A2 kaydı:
[indeks retention ve kapasite](audits/2026-10-11-chainlink-archive-retention/README.md).
`chainlink-oracle` normalizasyon kodu aday guest'in de bağımlılığıdır; bütün
Chainlink katmanı host-only değildir.

## Kullanıcı kararıyla ertelenen adım

Resmi public discovery sorguları önceki oturumda testnet/mainnet için HTTP403
verdi; nedeni belirlenmedi. Kullanıcı bu erişim/feed keşfi adımının şimdilik
atlanmasını ve raporda belirtilmesini istedi. Bu tur discovery yeniden denenmedi,
gerçek hesap veya credential okunmadı. Gerçek BTC/ETH/SOL/USDC feed kimlikleri,
ölçekleri ve entitlement **ERTELENDİ / AÇIK**, tamamlanmış değildir.
Bu eksikliği gidermek için kaynak, quote veya 1 USDC = 1 USD varsayımı eklenmedi.

## Tamamlanan dar akış

`chainlink-streams-client::report_pair::PreparedPair`, mevcut istemcinin iki
`UnverifiedReport` çıktısını açık `Policy` ve market kimliğiyle eşler.
İki rapor da doğru network/feed olmalı; ayrı receipt saatleri ve pair zamanı
uyumlu olmalıdır. Kaynak yaşı ve çift zaman farkı, değişmeyen aday normalizasyon
koduyla kontrol edilir. Kullanımda `for_operation(now_ms)` aynı kontrolleri
tekrar yapar ve `Normalized` + `PairEvidence` döndürür. API kaynak zamanını,
publisher imzasını veya gateway state'ini değiştirmez; DON doğrulaması yapmaz.

`report_archive::ReportArchive`, bu çiftin full-report baytlarını ve receipt
metadata'sını tek, kanonik kayıtta saklar. Kayda credential/auth header girmez.
Politika bağı; mevcut policy hash'ine ek olarak chain/network, verifier proxy
ve oracle wrapper adreslerini içerir. Restore çağrısı beklenen `ArchiveId`,
politika ve market kimliğini ayrı argümanlar olarak ister. Arşiv kendi politikasını
veya beklenen hash'ini seçip kendisini doğrulayamaz.

`ArchiveId` kanonik kaydın SHA-256 değeridir. Aynı prepared pair tekrar yazıldığında
aynı ID döner, var olan dosya değiştirilmez. Bu bütün observation'lar arasında
küresel dedup değildir: farklı receipt metadata'sı farklı kayıt üretir.
Tam rapor imzasının gerçekliği Chainlink verifier'da ayrıca doğrulanmalıdır.
Sahte fakat biçimsel olarak doğru rapor da arşivlenebilir; bu bir fiyat kabulü değildir.

## Yazım ve kurtarma sözleşmesi

Yalnız Unix (Mac/Linux) host modülü; yeni root dizini 0700, dosyalar 0600 açılır.
`create` yeni dizin ister; `open_existing` eksik dizinde yeni genesis oluşturmaz.
Dosya limiti 32 KiB, her full report mevcut decoder'ın 4096 bayt sınırındadır.
Kayıt ID'si 64 küçük-harf hex karakterdir, path veya URL değildir.

Yazım sırası: aynı dizinde create_new geçici dosya; tam yazım; dosya sync_all;
hedefi ezmeyen hard_link ile görünürlük; hedef ve dizin sync_all; yalnız bu
çağrının geçici dosyasını temizleme; dizin sync_all; başarı sonucu.
Mevcut hedefte yalnız baytları ve hash'i eşit kayıt idempotent başarıdır.
Bozuk, eksik, symlink, dizin veya fazla büyük hedef yerine yeni kayıt uydurulmaz.
Disk/izin/link/sync hatası başarı gibi dönmez. Root'un gözlemlenen inode/device
kimliği değişirse işlem reddedilir.

Yayın öncesi kesinti, yalnız .pending dosyası bırakabilir: bu dosya restore
kanıtı olarak kullanılmaz. Yayın sonrası fakat yanıt öncesi kesinti belirsiz
sonuçtur: `id_for(pair)` ile önceden bilinen aynı ID okunarak uzlaştırılır.
Başka veya en yeni rapor otomatik seçilmez. Arşiv eski kayıtları ve önceki
kesintilerden kalan dosyaları otomatik silmez.

Tarihi kaydın geri yüklenmesi, o verinin şu anda taze olduğunu göstermez.
Yeni işlemde güncel güvenilir işlem saatiyle `for_operation` yeniden çağrılır;
özgün işlemin yeniden yürütülmesinde o işlemin orijinal saati kullanılır.
Çağıran hizmet beklenen ID'yi kendi kalıcı, bütünlüğü korunan journal'ına
bağlamalıdır. #44'te mühürlenmiş pencere için bu bağlantı authenticated v6
journal ile vardır. A1 devamında açık pencerenin özgün kabul indeksi,
gateway state'i ve tam politika bağı aynı authenticated DPCAS2 checkpoint
kesitine alınır. Başarıyla yazılmış bu snapshot'tan restart, seçilmiş özgün
ID'leri ve op sırasını geri kurar; yeni işlem tazeliği yine ayrıca sınanır.

Checkpoint kesiti sonrası her admission için ayrı WAL garantisi verilmez.
Arşiv kaydının diskte bulunması, sonraki state değişiminin de kalıcı olduğunu
göstermez. Mevcut pre-seal `SealNeverPersisted` recovery davranışı ve RPO
sınırı korunur; bu paket sıfır veri kaybı iddiası değildir.

## Kullanım sırası

1. İki Request, dışarıdan doğrulanıp sabitlenmiş aynı Policy'den oluşturulur.
2. Client.fetch_latest ile alınan iki rapor PreparedPair::new'e verilir.
3. Archive.store başarı vermeden caller kayıt dayanıklılığını varsaymaz.
4. Dönen ArchiveId, ilgili işlem/journal ile kalıcı olarak eşleştirilir.
5. Restore, aynı ID/policy/market ile load eder; yeni işlem öncesi tazelik yeniden kontrol edilir.

Bu sıra kütüphane sözleşmesidir. #44 aday gateway scheduler/admission bağlantısını
ekler; bu, çalışan canlı oracle veya settlement hizmeti iddiası değildir.
Canlı feed pinleri atlandığı için örnek production
konfigürasyonu veya varsayılan ekonomik eşik eklenmedi.

## Test kapsamı ve sınırlar

Önceki 40 istemci testi korunur. 22 yeni test; pair/feed/network/para birimi,
USDC depeg, zaman farkı, receipt, arşiv yeniden açma, eksik/bozuk/kanonik olmayan
kayıt, politika/adres/ölçek bağı, symlink/dizin/root değişimi, eşzamanlı aynı
kayıt yazımı, idempotent davranış ve API → disk → PairEvidence yolunu kapsar.
Gerçek HTTP testi iki sahip olunan loopback sunucusundan sentetik rapor alır.

Bir parent test, dört ayrı child sürecini yazım aşamalarında `exit(77)` ile
sonlandırır; destructor çalışmadığı ve .pending dosyasının kaldığı doğrulanır.
Parent her child'ın tam 77 kodunu ister; başlatma/test hatası beklenen kesinti
sayılmaz. Child helper normal test koşusunda ignored'dır; parent onu açıkça
--ignored ile dört kez çağırır. Bu SIGKILL, güç kesilmesi veya disk denetleyicisi
kalıcılık testi değildir. Ek failpoint testleri programlı I/O hatalarını sınar.

Arşiv ve üst dizinler güvenilen servis hesabının kontrolünde olmalıdır. Stat/open
kontrolleri kötü niyetli aynı-UID/root sürecine veya eşzamanlı düşmanca path
swap'e karşı dosya sistemi sandbox'ı değildir. Özel dizin izinleri bu güven
modelinin parçasıdır. Gerçek disk bozulması, NFS/özel dosya sistemi kalıcılığı,
fiziksel GC ve üretim kapasitesi ayrıca değerlendirilmelidir. A2 sonlu mantıksal
kota ekler; fiziksel disk blok garantisi vermez.
SHA-256, güvenilir beklenen ID ile bütünlük kontrolüdür; zincir doğrulaması değildir.

## Yeniden çalıştırma

```sh
rustup run 1.99.0 cargo test --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml
rustup run 1.99.0 cargo test --release --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml
rustup run 1.99.0 cargo clippy --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml --all-targets -- -D warnings
```

İki guest programı/pinleri, reviewed root Cargo.toml, public input ve risk
eşikleri korunur. Kök lock host facade girdileri nedeniyle değişmiştir;
244 registry kimliği değişmemiştir. Production ayarı ve gerçek fon değişmedi.
Bu dal A2 indeks retention ve kapasiteyi uygular. Sıradaki yazılım: bütün fiyat
kullanan yollar (A3); ayrı aday prover/settlement protokolü (A4). Canlı feed erişimi ayrıca
ertelenmiş açık kapıdır.
Yeni aday witness reviewed v2 prover'a gönderilmez.

A3 devamı bu dalda özgün rapor seçimini order/tick/matching/funding/liquidation/
close/withdrawal fiyat kullanımından önce doğrular; normal withdrawal artık
publisher zamanını yeniden damgalamaz. Eksik binding bütün checkpoint/recovery
yollarında HOLD eder. Gerçek gateway normal ve liquidation akışlarından üretilmiş
iki sentetik v3 witness native ve sabitlenmiş SP1 CPU commitment'larını eşleştirir;
üç negatif guest exit 1/boş çıktı verir. Canlı DON veya proof kapısı kapanmaz.
Kanıt: [A3 fiyat yaşam döngüsü](audits/2026-10-11-chainlink-price-lifecycle/README.md).

11 Ekim 2026 güncellemesi: gateway/journal bağlantısı bu dalda eklendi
(`crates/gateway/src/report_archive_binding.rs`, journal sürümü `DPRBJL6\0`,
opt-in env `DARKPERP_CHAINLINK_ARCHIVE=candidate` + `DARKPERP_CHAINLINK_ARCHIVE_DIR`
+ `DARKPERP_CHAINLINK_POLICY_JSON`; kanıt `audits/2026-10-11-chainlink-archive-gateway-binding/`).
Geçerli v5 legacy journal yazımı korunur; trailing plaintext artık reddedilir.
Aday modda bağlanamayan oracle op'lu pencere seal edilmez; recovery eksik/bozuk/
uyumsuz kayıtta HOLD eder. `admit_with` arşiv-kabul-indeks bağlantısını tek kilit
kesitinde kurar; ilk seçilen ID sonradan eşdeğer fiyatlı kayıtla değiştirilemez.
İndeks 4096 gerçekten canlı girdide sessiz eviction yerine reddeder.
A1 devamı: aday snapshot authenticated plaintext zarfı `DPCAS2\0\0` içinde
state/açık pencere, tam politika bağı ve kanonik ilk kabul ID'lerini taşır.
Gateway → archive kilit sırası intake/seal/checkpoint için aynıdır; kesit
tam zarf olarak mühürlenip atomik yazılır. Startup, politika bağı ile her
seçilmiş kayıt/transcript'i ve restore edilen gerçek op akışını doğrular.
Eksik/bozuk seçilmiş kayıt yerine alternatif kullanılmaz. Yanlış politika,
tekrarlı/kanonik olmayan veya kapasiteyi aşan indeks güvenli ret nedenidir.
Legacy snapshot baytları aynıdır.
Eski `DPCAS1\0\0` kabul indeksi içermediğinden dosya uzlaştırma için korunur
ve açılış reddedilir; eksik referanslar tahmin edilip otomatik upgrade yapılmaz.

Doğrulanmış authenticated v6 journal, snapshot'tan daha yeni özgün ID'leri
recovery kararı öncesinde yeniden indekse kurar. Mevcut canonical seçimle
çatışma veya kapasite aşımı dahil bir hata indeksin kısmen kurulmasına izin
vermez; WAL korunur ve startup HOLD eder. Bu, journal'ın bildirmediği bütün
admission'ların ayrıca kalıcı olduğu anlamına gelmez. A1 yeni test/yayın
kanıtı eski `e283958` sonuçlarından ayrı kaydedilir.
Sıfır-oracle ve wind-down dahil aday normal gönderim/exact-resume eski v2 yolda
HOLD olur. Native MockProverClient replay gerçek SP1 proof değildir.

## A2: indeks retention, WAL beklentisi ve arşiv kotası

Checkpoint açık fiyatlı op'ların, halen seçilmiş market oracle'larının ve
authenticated v6 WAL'ın özgün referanslarını doğrular. Önerilen indeks state ile
birlikte kalıcı yazılmadan kurulmaz; başarısız/eski plan hiçbir seçimi değiştirmez.
Runtime capture, kalıcı dosya yazımı ve indeks kurulumu aynı gateway mutasyon
kilidini tutan, çağıranın iptaliyle kesilmeyen worker içinde tamamlanır.
Yeni authenticated `DPCAS3` checkpoint'i WAL beklentisini taşır. Beklenen WAL'ın
kaybı/bozulması HOLD eder. `DPCAS2` okuma uyumluluğu ve `DPCAS1` reddi korunur;
recovery çözülmüş kesiti kalıcılaştırdıktan sonra WAL'ı siler. Snapshot RPO
sınırı ve ayrı tüm-admission WAL'ın bulunmaması değişmez.

Yalnız kabul indeksi emekliye ayrılır; tam rapor dosyaları append-only kalır.
Backup/export/eski checkpoint referansları uzlaştırılmadan fiziksel GC yoktur.
Varsayılan mantıksal sınır 256 MiB / 65.536 girdidir. Candidate modda opsiyonel
`DARKPERP_CHAINLINK_ARCHIVE_MAX_BYTES` ve
`DARKPERP_CHAINLINK_ARCHIVE_MAX_RECORDS` ile ayarlanır; sıfır/geçersiz veya
candidate dışındaki kısmi konfigürasyon reddedilir. Canonical kayıtlar ve crash
`.pending` dosyaları sınırlı envanterle sayılır; foreign/symlink/güvensiz izin/
geçersiz boyut HOLD eder. Tek özel arşiv sahibi varsayılır; süreçler arası
dağıtık kota kilidi eklenmedi. Yeni ID kota doluyken callback/state değişiminden
önce reddedilir; mevcut özgün ID byte/hash/sync doğrulamasıyla idempotent kalır.
`archive_pressure` log olayı sabit ve redacted'dır; alarm teslimi dayanıklılık
kararının parçası değildir. Gerçek I/O hataları ayrıca fail-closed'dur.

Birincil uygulama referansları:
- https://doc.rust-lang.org/std/fs/fn.hard_link.html
- https://doc.rust-lang.org/std/fs/struct.File.html#method.sync_all
- https://docs.chain.link/data-streams/reference/report-schema-v3
