# Chainlink: özgün rapor çifti arşivi ve witness hazırlığı

11 Ekim 2026. **PRODUCTION RELEASE HOLD.**
PreparedPair/ReportArchive host istemci bileşenidir. #44 bunu opt-in aday
gateway intake, authenticated v6 journal ve aday snapshot etiketiyle bağlar.
Legacy varsayılan davranış korunur; aday prover/settlement yolu kapalıdır.
Güncel exact-code kanıtı: [son doğrulama](audits/2026-10-11-chainlink-archive-gateway-binding/README.md).
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
journal ile vardır. Açık, henüz mühürlenmemiş pencerenin bellek içi admission
indeksi henüz kalıcı değildir; restart sonrası tam kurtarma tamamlanmamıştır.

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
toplam disk kotası, retention/GC ve üretim kapasitesi ayrıca değerlendirilmelidir.
SHA-256, güvenilir beklenen ID ile bütünlük kontrolüdür; zincir doğrulaması değildir.

## Yeniden çalıştırma

```sh
cargo +1.99.0 test --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml
cargo +1.99.0 test --release --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml
cargo +1.99.0 clippy --locked --offline --manifest-path crates/chainlink-streams-client/Cargo.toml --all-targets -- -D warnings
```

İki guest programı/pinleri, reviewed root Cargo.toml, public input ve risk
eşikleri korunur. Kök lock host facade girdileri nedeniyle değişmiştir;
244 registry kimliği değişmemiştir. Production ayarı ve gerçek fon değişmedi.
Sıradaki yazılım: açık-pencere kabul indeksinin authenticated snapshot/state ile
kalıcılığı; güvenli kapasite/retention; bütün fiyat kullanan yollar; ayrı aday
prover/settlement protokolü. Canlı feed erişimi ayrıca ertelenmiş açık kapıdır.
Yeni aday witness reviewed v2 prover'a gönderilmez.

11 Ekim 2026 güncellemesi: gateway/journal bağlantısı bu dalda eklendi
(`crates/gateway/src/report_archive_binding.rs`, journal sürümü `DPRBJL6\0`,
opt-in env `DARKPERP_CHAINLINK_ARCHIVE=candidate` + `DARKPERP_CHAINLINK_ARCHIVE_DIR`
+ `DARKPERP_CHAINLINK_POLICY_JSON`; kanıt `audits/2026-10-11-chainlink-archive-gateway-binding/`).
Geçerli v5 legacy journal yazımı korunur; trailing plaintext artık reddedilir.
Aday modda bağlanamayan oracle op'lu pencere seal edilmez; recovery eksik/bozuk/
uyumsuz kayıtta HOLD eder. `admit_with` arşiv-kabul-indeks bağlantısını tek kilit
kesitinde kurar; ilk seçilen ID sonradan eşdeğer fiyatlı kayıtla değiştirilemez.
İndeks 4096 girdide sessiz eviction yerine reddeder; uzun süreli retention açık.
Aday snapshot authenticated plaintext etiketi `DPCAS1\0\0` ile mod düşürmeyi
engeller; kabul indeksini veya politikanın tamamını kendiliğinden geri kurmaz.
Sıfır-oracle ve wind-down dahil aday normal gönderim/exact-resume eski v2 yolda
HOLD olur. Native MockProverClient replay gerçek SP1 proof değildir.

Birincil uygulama referansları:
- https://doc.rust-lang.org/std/fs/fn.hard_link.html
- https://doc.rust-lang.org/std/fs/struct.File.html#method.sync_all
- https://docs.chain.link/data-streams/reference/report-schema-v3
