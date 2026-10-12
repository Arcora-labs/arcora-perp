# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 12 Ekim 2026. **PRODUCTION RELEASE HOLD**.
Bu belge güncel çalışma sırasıdır; tarihsel `NEXT_STEPS.md` yerine kullanın.
Bu paketin başlangıç main'i: `60eceef733613fe6d491548d35eb4fdb7c0809bd` (#56).
#44 ve #45, güncel yayın head'lerinde ayrı ayrı 19/19 başarılı kontrol sonrası
normal merge edildi; repository korumaları değiştirilmedi. #44 merge kimliği
`e697b2f19d74b1021ba3a32b64b4f15ceb159880`, #45 merge kimliği
`c82dd492f74a47ab3806395dd05b46b3dff884e4`.
#45'in main ile güncellenmiş kontrol head'i `0f2fc42964bd25d5cd36e20f98d8edc61ab22210`;
test edilmiş A1 ağacıyla eşitliği doğrulandı. Gözlem kaydı:
[merge-observations.json](audits/2026-10-11-chainlink-archive-retention/merge-observations.json).
A2 kapasite/indeks retention #46, `b3a9507` head'inde 19/19 başarılı kontrolden
sonra normal merge edildi: `c32432f69bf60610e41ff6ef87fb0c5f5981e79d`.
A3 fiyat yaşam döngüsü #47, main ile güncellenmiş `15bdf54` head'inde yeniden
19/19 başarılı kontrolden sonra normal merge edildi: `969ecec2fecd29621c5508ab58fb778617b9bce2`.
#47 güncellenmiş head'i, önceki test edilmiş `095ab735` head'i ve merge edilmiş
o aşamadaki main aynı `bccdbe38e617500595c68744c839470bc951344e` kaynak ağacını taşır.
A4 ilk offline protokol #48, `f0f1d406` head'inde 19/19 başarılı kontrol sonrası
11 Ekim 2026 16:34:36 Türkiye saatinde normal merge edildi. Merge edilmiş main
ve kontrol edilmiş head aynı `1780f76c675566a8ca526ec18c078ecb03ab6288` ağacıdır.
[Güncel merge kaydı](audits/2026-10-11-chainlink-registration-recovery/merge-observations.json).
A4 ara kayıt recovery #49, `9567f23` head'inde 19/19 başarılı kontrol sonrası
11 Ekim 2026 17:40:27 Türkiye saatinde normal merge edildi. Kontrol edilmiş
head ve merge aynı `9da8cbb602996d863b84daba881cb6f62b737b9f` ağacıdır.
[Son #49 merge kaydı](audits/2026-10-11-chainlink-native-contract-bridge/merge-observations.json).
A4 tam native kontrat köprüsü #50, `d792d323d53fda6974096aa474f9b8313b8e7adb`
head'inde güncel 19/19 SUCCESS sonrası normal merge edildi:
`0ea5048627840cbe7e125d7b914b1303b109b224` (11 Ekim 23:26:38 Türkiye saati).
Kontrol ve merge ağacı aynı `146b6da49f322bcabf68a7e5fca1e216aea52c45`.
[Son #50 merge kaydı](audits/2026-10-11-chainlink-broadcast-outcome/merge-observations.json).
#51 offline broadcast sonuç/kilit paketi, `176549478079536b274862d487133ba053b0edb1`
yayın head'inde 19/19 SUCCESS sonrası normal merge edildi:
`56f91ab740d5cce42edcc287ded4b0c39eb4f9f8` (12 Ekim 00:42:38 Türkiye saati).
Kontrol ve merge ağacı aynı `9bcb4f9b257494c9b1e055e4368da297c64c15e4`.
Repository korumaları değiştirilmedi. Bu dal registration'ı yerel lease altında
Prepared'a kadar koordine eder; yerel sonuç ve yayın head'inin CI sonucu ayrıdır.
#52 registration → durable Prepared paketi, `41c1ed8bc561b2cf29868d94619fd223732068c9`
yayın head'inde 19/19 SUCCESS sonrası 12 Ekim 02:55:16 Türkiye saatinde normal
merge edildi: `f9a0f2f59ffae651163fc10a43a995054a07ebcc`. Kontrol ve merge aynı
`dda7aaf842c90df4a0ef35f44d577177dcd67b3d` ağacını taşır; korumalar değiştirilmedi.
Bu yeni final paket Prepared → broadcast handoff, offline aday kimliği ve belge
düzeltmelerini kapsar. Kod `c9ce9ce51faf78bb8d3f031f612a5d4335dc2a8e`; aşağıdaki
yerel sonuçlar yeni yayın head'inin CI/merge kaydı yerine geçmez.

## Birleşmiş ve korunan çalışmalar

#33 DH/zeroize/deployment policy; #35 zorunlu restore; #36 bağımsız ARM64 cold
build; #37 paired journal/cursor recovery; #38 oracle intake main'dedir.
Bu alt ölçütler yeniden açık iş sayılmaz; canlı kullanım kabulü değildir.

#39 iki borsa host kontrolü, 17/17 başarılı kontrolle normal merge edildi:
`2d3349486e868ad0caf84f89eaee0e5177ffac78`.
#40 ayrı Chainlink rapor-bağlı aday core/guest/sözleşme paketi, #39 ile güncellenip
18/18 başarılı kontrolle normal merge edildi:
`40b8c61cba9755e80fc17e0cf01950ee8aaa4574`.
#40 merge ağacı kontrol edilmiş `a4a6ae8a8181eaa1cd9e61daa8c0b1c50769bd96`
ağacıyla aynıdır. Önceki merge engeli bu turda sürmedi; korumalar gevşetilmedi.

## Birleşmiş #41: Chainlink adayında uptime/grace

#41, 10 Ekim 2026 20:02:20 Türkiye saatinde 17/17 başarılı kontrolle normal
merge edildi: `9483e33607f964138108094b04ca8b27dedcd637`.
Merge ağacı test edilmiş `7e1adb9` kaynak ağacıyla aynıdır.
Solidity aday wrapper'ına zorunlu, immutable uptime feed ve açık grace süresi
bağlandı. Özgün işlem zamanı, rapor kaydı ve settlement aynı sağlıklı uptime
dönemiyle sınırlandı. Eski proof toparlanma sonrası başka döneme taşınamaz.
Fiyat gerektirmeyen wind-down/exit yolları uptime arızasına bağımlı bırakılmadı.

Yerel: 161 sözleşme testi (20 yeni uptime testi dahil), ayrı 15 Rust testi,
format, candidate lock/release ve 21/21 reviewed v2 kaynak pini başarılı.
Ayrıntılar: `CHAINLINK_SEQUENCER_GUARD.md` ve
`audits/2026-10-10-chainlink-uptime/`. Bu kayıt yerel kapsamı bildirir;
Bu PR artık main'dedir; merge sonrası push CI ayrı kayıttır.

## Birleşmiş #42: aday guest CPU yürütmesi

Dal: `feat/chainlink-guest-replay-20261010`, taban main `9483e33`.
19 sabit, açık sentetik witness ve bunları gerçek SP1 CPU yürütücüsünde çalıştıran
`replay-chainlink` eklendi. 4 başarıda native public commitment birebir eşleşti;
15 negatifte gerçek guest exit 1 ve sıfır public çıktı görüldü. Beş ayrı gerçek
süreç guard'ı da geçti. Fixture/kanıt denetimi için 12 Python testi ve native
kaynakta 16 test geçti; açık export testi ayrıca bir kez çalıştırıldı.
Ayrı aday ELF aynı Mac'te yeniden üretildi; önceki adayla byte-byte aynı kaldı.
Ölçülen aday vkey: `0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.
Eski reviewed guest'in 21 pini ve aday runtime'ın 9 girdisi değişmedi.
CI'a gerçek CPU adımı eklendi. #42, 18/18 başarılı exact-head kontrolüyle
10 Ekim 2026 20:37:31 Türkiye saatinde normal merge edildi: `e552bbab6868b070ff9c3b8f4ed3b9dec1230288`.
Merge ağacı `2598acf` kaynak ağacıyla eşittir; push CI ayrı kayıttır.
Kılavuz: `CHAINLINK_GUEST_REPLAY.md`; kanıt: `audits/2026-10-10-chainlink-guest-replay/`.
Bu 4 başarılı senaryo önceki 4 normal-wallet exact witness değildir; funding ve
boş batch regresyonlarıdır. CPU setup/execution, proof veya gerçek DON değildir.

## Chainlink geçişi henüz canlı değildir

Mevcut gateway hâlâ önceki fiyat yolunu kullanır. #39 opt-in iki-borsa modu
USDT/USDC eşleşme engelini gizlemez; iki publisher quorum'u değildir.
#40'ın ayrı guest'i için yeni yerel CPU yürütmesi ve setup/vkey kimliği
doğrulandı: 4 sentetik başarılı girdi + 15 çıktısız guest reddi. Yeni gerçek
proof ve production guest/deployment kabulü tamamlanmadı. Normalizasyon açık asset/USD ÷ USDC/USD aday tarifidir;
üretim ekonomik onayı yoktur ve backup alanı bağımsız TWAP değildir.

## PR #43: REST istemcisi runtime doğrulaması (BİRLEŞTİRİLDİ)

Dal `feat/chainlink-streams-client-20261010` (head 2a03bb0) main'e birleştirildi
(merge commit c34fb56, 11 Ekim 2026 salt-okuma kontrolü). Aşağıdaki kayıt
tarihseldir:
Dört gerçek regresyon düzeltildi: ileri saat adımında eksik I/O yaş hesabı,
+ işaretli Content-Length, yinelenen ve desteklenmeyen Transfer-Encoding.
Önceki 34 test değişmedi; 6 deterministik saat testi eklendi. Yerel debug ve release
sonuçlarının her biri 40 PASS, 0 FAIL, 0 IGNORE. Clippy/format/lock/release kontrolleri geçti;
21 reviewed v2 ve 9 aday runtime girdisi değişmedi. Exact-head PR CI sonucu
ayrıca doğrulanmalı; eski compile-only yeşil CI yeni test yerine geçmez.

Önceki yazma engeli kullanıcının yeniden deneme talebinde sürmedi; kaynak
hash'i doğrulanarak yama uygulandı. Araç güvenlik/OS izin ayarı değiştirilmedi.
Eski başarısız test kayıtları korunmuştur. Güncel kaynak/komut/çıktı kanıtı:
`audits/2026-10-10-chainlink-client-fixed/` ve `CHAINLINK_STREAMS_CLIENT.md`.

## Kullanıcı kararı: canlı feed keşfi şimdilik ertelendi

10 Ekim 2026: önceki public discovery testnet/mainnet HTTP403 bulgusu nedeniyle
kullanıcı feed erişimi/keşfi adımını atlayıp raporda açık tutmamızı istedi.
Bu tur yeniden discovery çağrısı yapılmadı. Gerçek feed/scale/USDC/entitlement
kimlikleri **ERTELENDİ / AÇIK**; güvenlik kabulünden çıkarılmadı veya tamamlandı
sayılmadı. Varsayılan feed, USD=USDC eşitliği veya gerçek credential eklenmedi.

## PR #43 birleştirildi (11 Ekim 2026 salt-okuma kontrolü)

Main artık c34fb56 (merge PR #43, head 2a03bb0). Bu dala (#43 sonrası main
tabanlı) daha önce yerel/commitlenmemiş olarak kalan PreparedPair, ReportArchive
ve rapor-arşivi belge/audit kayıtları taşındı; kullanıcının o checkout'undaki
özgün yerel çalışması korundu, başka bir arşiv yeniden inşa edilmedi.

## Aktif paket: arşiv → gateway → mühürlü journal → recovery bağı (aday)

Yeni opt-in/candidate gateway kodu eklendi (PRODUCTION RELEASE HOLD sürüyor;
reviewed v2 guest/ELF/vkey/public input ve prover yönlendirmesi DEĞİŞMEDİ):

- `DARKPERP_CHAINLINK_ARCHIVE=disabled` (varsayılan, davranış aynen korunur) |
  `candidate` + `DARKPERP_CHAINLINK_ARCHIVE_DIR` + `DARKPERP_CHAINLINK_POLICY_JSON`.
- Aday intake: politika marketleri için base/USD + USDC/USD çifti çekilir
  (`DARKPERP_CHAINLINK_ACCESS_KEY`/`_SECRET` yoksa canlı pull DEFERRED kalır),
  **önce** ReportArchive'e kalıcı yazılır, **sonra** normalleşmiş fiyatın
  gateway imzalı transcript'i admission olarak uygulanır.
- Window seal (`begin_journaled_window_settle`): gerçek Fill/AccrueFunding/
  Liquidate/Unbind op akışı (sıralı, tekrarlı kullanım dahil) arşiv kayıtlarına
  **ilk kabul edilmiş (market, transcript) kimliği → özgün ArchiveId** ile
  bağlanır; bağlanamayan pencere seal edilmez (fail-closed).
- Rollback journal yeni açık sürüm `DPRBJL6\0`: v5 journal + authenticated
  ArchiveEnvelope (policy binding + op başına archive ID). v5 ok/yaz davranışı
  geçerli eski payload'lar için korunur; trailing plaintext/sürüm karışıklığı
  reddedilir. Aday-gerekli modda legacy journal, legacy modda v6 journal
  reddedilir. `resume_exact` aday journal'ı ilk noktada reddeder; v2 yola yazmaz.
- Boot recovery: açılan aday journal'ın her referanslı kaydı var olmalı,
  policy/market/op zamanıyla çözümlenmeli ve op transcript'iyle birebir
  eşleşmeli. Authenticated v6 journal'ın referansları ilk seçilmiş özgün
  ID'leri kabul indeksine geri kurar; mevcut ID ile çatışma veya kapasite
  aşımı dahil her hata recovery kararından önce HOLD eder ve WAL korunur.
- Sıralı dayanıklılık engelleri: arşiv kalıcı → state değiştiren admission;
  authenticated journal kalıcı → herhangi bir submission'dan önce kontroller.
- Candidate modda v2 submission YOK: pencere seal+journal sonrası HOLD eder
  (v3 chainlink proving bağlanana kadar; sıfır-oracle pencere dahil). Sayaçlı
  prover testi reddedilen yolda 0 çağrı doğrular.
- Candidate modda legacy feed intake bastırılır (startup, politika tüm marketleri
  kapsamıyorsa reddeder); varsayılan feed'li market setleriyle candidate artık
  erişilebilir. DEMO boot'un tohum fiyatları candidate'da bağlanamaz — pencere
  seal edilmez (bilinçli sınır; üretim postürü + archive intake kullanılır).
- Aday mod journal yolu yapılandırılmamışsa (DARKPERP_STATE yok) reddeder;
  zehirlenmiş arşiv mutex'i settlement'ı HOLD eder, asla v5 downgrade yok.

- `admit_with`, kapasite → arşiv kalıcılığı → gateway kabulü → ilk ID seçimini
  aynı kilit kesitinde yapar; ret indekse girmez, alternatif kayıt seçilmiş ID'yi
  değiştirmez. 4096 gerçekten canlı girdide sessiz eviction yoktur.
- A1 aday checkpoint'i authenticated plaintext içinde `DPCAS2\0\0` taşır:
  gateway state'i/açık op penceresi, tam politika bağı ve kanonik
  `(market, transcript) → ilk ArchiveId` kabul indeksi birlikte saklanır.
  Intake/seal/checkpoint aynı gateway → archive kilit sırasıyla tek tutarlı
  kesit alır. Startup seçilmiş her özgün kaydı ve restore edilmiş op akışını
  doğrular; yanlış politika, eksik/bozuk kayıt, kanonik olmayan/tekrarlı
  indeks ve uyumsuz op başlangıcı reddeder. Legacy snapshot baytları korunur.
- Eski `DPCAS1\0\0` yalnız modu işaretlediği için uzlaştırma amacıyla
  korunarak reddedilir; eksik kabul referansları tahmin edilip otomatik
  yükseltme yapılmaz. Marker kaybı/ayar eksikliği legacy açılışa dönüşmez.

A1 dayanıklılığı, başarıyla kalıcı yazılan snapshot kesitinin state ve kabul
ID'lerini kapsar. Son snapshot'tan sonraki her admission için ayrı WAL veya
sıfır veri kaybı garantisi eklenmedi. Mevcut pre-seal `SealNeverPersisted`
recovery satırı ve RPO sınırı korunur. Yeni kodun doğrulama kaydı:
[A1 kabul indeksi recovery](audits/2026-10-11-chainlink-admission-recovery/README.md).

A2, indeksin yalnız açık op penceresi, halen seçilmiş oracle ve authenticated
v6 WAL referanslarını tutmasını sağlar. Seçilmiş kayıtlar doğrulanır; state ve
önerilen indeks aynı başarılı atomik checkpoint'ten sonra kurulur. Runtime
capture/write/install aynı iptal edilemeyen worker ve gateway mutasyon kilidi
içindedir; başarısız veya eskimiş plan indeks değiştirmez. Yeni `DPCAS3` zarfı
WAL beklentisini de saklar; eksik/bozuk beklenen WAL startup/checkpoint HOLD'udur.
`DPCAS2` okunur; çözülmüş state kalıcılaştırılmadan recovery WAL'ı silinmez.

Tam rapor dosyaları append-only kalır; backup/tarihsel referanslar için fiziksel
GC yapılmaz. Yeni kimlikler 256 MiB / 65.536 girdi varsayılan mantıksal arşiv
kotasıyla admission öncesinde sınırlanır. Candidate opsiyonel MAX_BYTES ve
MAX_RECORDS ayarları, `.pending`/orphan sayımı ve değişmeyen özgün ID ile
kapasite doluyken idempotent kabul ayrıca sınanır. Gerçek disk blok garantisi
ve süreçler arası dağıtık kota kilidi iddiası yoktur. Kanıt:
[A2 indeks retention ve kapasite](audits/2026-10-11-chainlink-archive-retention/README.md).

A3, gerçek order/tick/matching/funding/liquidation/close/withdrawal yollarında
özgün seçilmiş raporu fiyat kullanımından önce doğrular. Withdrawal kaynak zamanı
yeniden damgalanmaz. Eksik binding seal, checkpoint ve WAL silme yollarında
legacy dönüşe izin vermez. Aday demo sentetik fiyatlı mutasyonları reddedilir;
fiyat gerektirmeyen terminal wind-down korunur. Gerçek gateway normal lifecycle
ve liquidation pencerelerinden üretilmiş v3 witness'ların native/CPU çıktıları
eşittir; üç negatif guest exit 1/boş public çıktı verir. Nihai gateway 550 PASS,
47 guard ve Clippy/format temizdir. Sentetik raporlar DON doğrulaması veya proof
değildir. Kanıt: [A3 fiyat yaşam döngüsü](audits/2026-10-11-chainlink-price-lifecycle/README.md).

## Önce kapanacak GPU'suz yazılım paketleri

| Sıra | İş | Kapanış ölçütü |
|---|---|---|
| A0 | #44 final evidence ve eski audit düzeltmesi | #44 yayın head'i `5cb1470`, 19/19 başarılı kontrol sonrası normal merge edildi. |
| A1 | Açık pencerenin özgün kabul ID'lerini kalıcılaştırma | #45 güncel head `0f2fc42`, 19/19 başarılı kontrol sonrası normal merge edildi. DPCAS2 + özgün v6 journal ID recovery; snapshot sonrası her admission için ayrı WAL garantisi yok. |
| A2 | İndeks kapasitesi ve retention | #46 güncel head `b3a9507`, 19/19 başarılı kontrol sonrası normal merge edildi. Referansları doğrulayan checkpoint sonrası indeks retirement, DPCAS3 WAL beklentisi ve admission öncesi sonlu arşiv kotası uygulandı. 4.100 admission/restart dahil nihai yerel sonuç ayrı A2 kanıt kaydındadır; fiziksel GC yapılmaz. |
| A3 | Fiyat kullanan bütün gateway yolları | Aday priced mutasyon preflight'ları ve özgün withdrawal transcript'i uygulandı. 550 gateway PASS; iki gerçek gateway sentetik lifecycle witness'ında native/gerçek SP1 CPU commitment eşit, üç negatif exit 1/boş public çıktı. #47 güncel head `15bdf54`, 19/19 başarılı kontrol sonrası normal merge edildi; submission HOLD. |
| A4 | Ayrı aday prover/settlement protokolü | Offline harness #48, DPCINT4 recovery #49, native kontrat köprüsü #50, broadcast outcome/lease #51 ve registration→Prepared #52, kendi yayın head'lerinde 19/19 kontrol sonrası normal merge edildi. Son dual-lease handoff ve offline identity paketi aşağıda yerel kanıtıyla kayıtlıdır. Gerçek proof, canlı servis/target ve L1 uzlaşma kabulü açık; A4 tümü kapatılmaz. |

Canlı feed keşfi/entitlement kullanıcı kararıyla ertelenmiştir; A1–A4 yazılım
hazırlığını durdurmaz. Yeniden discovery/credential denemesi veya feed/eşik
tahmini yapılmaz. DON doğrulaması, yeni proof ve canlı deployment kabulü olmadan
aday gönderim engeli kaldırılmaz; v3 witness v2 prover'a GÖNDERİLMEZ.
Ücretli erişim, gerçek credential/fon ve kamu zinciri işlemi ayrıca yetki ister.
A4'ün ilk ayrı yazılım paketi, [önceki offline protokol tasarımı](audits/2026-10-11-chainlink-price-lifecycle/next-a4-design.md)
doğrultusunda uygulandı. Yeni protokol modülleri yalnız `cfg(test)`
kapsamındadır; canlı bir transport veya `PreparedSettle` dönüşümü eklemez. V3
witness v2 inner clock kullanır; full-report ABI input hash'i evidence body
hash'inden ayrıdır ve uptime epoch wrapper kayıt durumudur. Authenticated
`DPCINT3` intent/prepared kaydı immutable request/material/target/epoch ile
restart/retry sınar. Final CPU corpus iki actual gateway sentetik akışından
gelir; contract parity gerçek wrapper'lar ve mock DON/SP1/uptime ile sınanır.
İlk #48 kontrat fixture'ının R/N kökleri native tam commitment yerine geçmez. Kanıt:
[A4 offline aday protokolü](audits/2026-10-11-chainlink-candidate-protocol/README.md).

Birleşmiş #49 A4 yazılım paketi, yalnız `cfg(test)` kapsamında DPCINT4 ile Intent →
ClockPending → ClockObserved → ReportsPending → ReportsObserved → Prepared
aşamalarını ayrı ve authenticated olarak saklar. Resume hiçbir registration
çağrısını tekrarlamaz; özgün tx/block/hash/epoch ve request baytlarını koruyarak
lookup yapar. Absent/pending/unknown/reorg, kaydetme belirsizliği veya finalite
gerilemesi sonraki çağrıyı durdurur. Lookup finalitesi caller-owned mock bilgisidir;
RPC/consensus/ancestry kabulü değildir. #49'un tarihsel runner'ında son tip geçmişi restart'lar arasında
saklanmaz; broadcast sonuç WAL'i ve process'ler arası writer koordinasyonu o runner'da açık kalır.
Yerel final test sonucu: [ara kayıt recovery kanıtı](audits/2026-10-11-chainlink-registration-recovery/README.md).
Tam gateway 597 PASS / 0 FAIL / 18 IGNORE; 25 odaklı recovery ve 10 özgün
protokol regresyon testi başarılı. Workspace Clippy/format ve 47 guard geçti;
21 reviewed / 9 candidate pin ve dört golden builder değişmedi. Bu pakette
Foundry veya CPU yeniden çalıştırılmadı; #48'in aynı corpus/kaynak kanıtı korunur.
Birleşmiş #50'de [tam native-to-contract köprü](audits/2026-10-11-chainlink-native-contract-bridge/README.md)
uygulandı. Özgün iki FINAL2 witness/full container korunur; gerçek yerel kontrat
bağlamından yeni canonical witness, material ve açıkça yeni sentetik arşiv
kayıtları üretilir. Yedi kök ve count=9/nonzero tip, gerçek SP1 adapter/clock/
oracle/settlement ile açık mock DON/SP1/uptime/prefix ledger üzerinden sınanır.
Nihai tam Foundry 183 PASS (yeni köprü 15); Rust odaklı 5 PASS ve Clippy
başarılı. Yeni witness ile taze SP1 CPU yürütmesinde 2/2 exact public32 eşleşti
(27.237.960 + 24.293.454 cycle). Nihai tam gateway **602 PASS / 0 FAIL / 20
intentional IGNORE**, 47 guard ve 21/9 pin geçti. İlk tam koşuda eski iki
saniyelik HTTP fixture 400 döndü; özgün yanıt gövdesi yoktu. Kontrollü gecikme
aynı aşamada arşiv zaman reddini yeniden üretti. Eski golden/süre/beklentiler
korunarak nihai tam test ve CI workspace paralelliği iki thread ile sınırlandı.
Başarısız ilk ve başarılı final kayıtları yeni köprü kanıt paketinde saklanır.
Gerçek proof, fon/custody ve canlı kabul değildir.

## Birleşmiş #51: offline broadcast outcome ve yerel lease

Birleşmiş #51'de ayrı `cfg(test)` dispatcher, terminal DPCINT4 Prepared'ı doğrular;
tarihsel runner'ı çağırmaz. Immutable Plan'da bütün yedi root, count/tip,
program/target pinleri, public32, exact settlement ABI ve precomputed **mock**
tx/attempt ID tutulur. Authenticated DPCBTX1 Pending kalıcı onaylanmadan yayın
callback'i çağrılmaz. Resume yalnız özgün attempt'i lookup eder; terminal
success/revert kaydı sıfır callback ile döner. Absent/pending/unknown/reorg,
bozuk ya da uyumsuz kayıt ve belirsiz kalıcılık HOLD'dur; yeniden gönderim yoktur.

Stable private lock inode'u invocation boyunca tutulur ve authenticated kayda
bağlanır. Aynı handle, bağımsız handle ve gerçek süreçlerde Busy sıfır callback
döndürür; gerçek dispatcher SIGKILL sonrası özgün Pending üzerinden lookup-only
resume edildi. Koordinasyon aynı configured sidecar path içindir; ayrı path/kopya
ve doğrudan eski runner kullanımı kapsam dışıdır. Son Fresh tip restart boyunca
saklanmaz; özgün Prepared anchor baseline'ı korunur. Gerçek RPC/consensus/proof,
chain exactly-once veya fiziksel güç kaybı kabulü değildir.

İlk kod `44b81edd3ac4c2781e91ddbbb75f9bd9dd882d44`; ilk yerel tam gateway
**628 PASS / 0 FAIL / 21 intentional IGNORE**, yeni odaklı **26 PASS**,
47 guard, Clippy `-D warnings`, format ve 21/9 pin başarılı. İlk Cargo 1.99
komutlarının child araçları PATH üzerinden Homebrew Rust/Clippy 1.95 seçmiş;
ilk yerel sonuçlar 1.95 kanıtıdır. İlk Linux CI'da gerçek Rust 1.99 ile tam
628/0/21 geçti; üç iş aynı yeni hex helper lint'inde durdu. Dar düzeltme kodu
`92d469335c67967d45fa7d0360d7345329e57bb1`, çift uzunluk kontrolünü koruyarak
`as_chunks` kullanır. Güncel kontrol seti child araçları da explicit Rust 1.99
bin dizininden seçer: yeni odaklı **26/0/1**, Clippy, format, **47 guard** ve
**21/9 pin** başarılı. Önceki loglar tarihsel olarak saklanır. Yayın commit'inin
19/19 başarılı CI sonucu normal merge'den önce ayrıca doğrulanır. İlk workspace
işi 20 dakikalık job limitinde iptal edildi; assertion hatası yoktu, no_std adımı
çalışmadı. `eb07a79297dcf2e4ac3e8b6506c8a7b5007a96bc` yalnız bu job'un limitini
20→30 dakika yapar; bütün komutlar/assertion'lar ve iki thread korunur. 1.926
önceki dosya hash'i aynı; tek mevcut dosya değişikliği bu exact CI süre satırıdır.
Özgün 13/7/62 dirty checkout içerikleri korunur. Yerelde Foundry/SP1 CPU bu
host-only pakette yeniden çalıştırılmadı; #50 corpus/kontrat/kaynak ve kanıt
hash'leri değişmedi. [Yeni kanıt](audits/2026-10-11-chainlink-broadcast-outcome/README.md).

## Birleşmiş #52: registration → durable Prepared koordinasyonu

Kod `606894c7dbe7faf688fd1e8d169e7e89430c07f0`, yalnız `cfg(test)` kapsamındadır.
Yeni coordinator kaynak DPCINT4 store'unu kendi içinde tutar. Aynı kaynak için
deterministik, stable private lock bütün invocation boyunca alınır; request ve
lock inode kimliği ayrı authenticated DPCREG1 binding'e bağlanır. Fresh mevcut
kayıtları sıfırlamaz; Resume binding veya source eksikse HOLD eder. Eski bir
staged cut yalnız açık, callback'siz adoption ile semantik doğrulamadan sonra
bağlanır. Callback ve kayıt yazımları öncesi/sonrası source, binding ve lease
yeniden doğrulanır; belirsiz kalıcılık sonraki callback'i durdurur.

Preparation transport broadcast metodu taşımaz ve yalnız kalıcı Prepared'da
döner. Eski runner'ın 11 Fresh / 3 Prepared Resume callback sırası ve aynı
invocation watermark'ı korunur. DPCINT3/4 ve DPCBTX1 framing, eski testler,
golden builder'lar, #50 corpus, reviewed/candidate runtime pinleri değişmedi.
Mac'te uppercase source basename aynı fiziksel dosyaya erişebiliyordu; önce
hata veren regresyon kaydedildi. Yeni basename yalnız küçük ASCII/rakam/`._-`
kabul eder; binding/lock adları fiziksel parent dev/ino/uid ve basename'den
türetilir. Authenticated exact kaynak yolu digest'i ayrıca korunur.

Yerel final: **28 odaklı PASS / 1 intentional helper IGNORE**, değişmemiş
**17 recovery PASS**, Clippy Rust 1.99 `-D warnings`, format, **47 guard** ve
**21/9 pin** başarılı. Tam gateway **656 PASS / 0 FAIL / 22 intentional IGNORE**
(gerçek Rust 1.99); bütün kaynak/komut/log hash'leri
[yeni kanıt paketinde](audits/2026-10-12-chainlink-prepared-lease/README.md).
Gerçek register callback'inde kilitli süreç SIGKILL edildi; rakip süreç Busy ile
sıfır callback yaptı, successor özgün Pending'den registration tekrarlamadan
Prepared'a geldi. Bu cooperative yerel koordinasyondur; başka path/kopya,
legacy writer, hostile filesystem, chain exactly-once veya güç kesintisi kabulü
değildir. Adoption sırasında eski writer'lar durmuş olmalıdır. Son gözlenen
tip restart'a taşınmaz; özgün saved anchor baseline'ı korunur. Prepared save
başarısızlığından sonra mock proof yeniden çalışabilir.

Sonraki handoff tasarımı aşağıdaki yeni pakette uygulandı; önceki
[tasarım belgesi](audits/2026-10-12-chainlink-prepared-lease/next-gpu-free-a4.md)
tarihsel plan olarak korunur.

## Son GPU'suz paket: Prepared → broadcast ve offline aday kimliği

`c9ce9ce51faf78bb8d3f031f612a5d4335dc2a8e` kodunda yalnız `cfg(test)` handoff,
kendi sahibi olduğu authenticated exact Prepared kaynağının lease'ini önce,
sabit fiziksel kaynak lane'inin broadcast lease'ini sonra alır. İkisi callback,
yazma, readback ve dönüş boyunca tutulur. Request/proof/bridge/sender/nonce
değişikliği yeni bir broadcast yolu seçemez. Fresh özgün recheck/broadcast/lookup
sırasını, Pending Resume lookup-only, terminal dönüş sıfır callback'i korur.
Kaynak/binding/lock/broadcast değişimi ve belirsiz kalıcılık HOLD'dur. Gerçek
Broadcast/Lookup callback'lerinde iki ayrı SIGKILL testi; rakipte Busy/sıfır
callback ve successor'da özgün Pending lookup-only toparlanması geçti.

Nihai kodda Rust 1.99 odaklı **17 PASS / 0 FAIL / 1 ignored child helper**,
workspace Clippy `-D warnings`, format ve **47 guard** başarılı. Tam yerel
gateway **673 PASS / 0 FAIL / 23 intentional IGNORE**, dört yeni lint-only
`inspect_err` düzeltmesinden önceki `995d204` kodunda çalıştı; final kodun tam
Linux gateway/workspace CI koşusu normal merge öncesi ayrıca zorunludur.
Eski callback gövdeleri, framing, goldens, #50 corpus ve 21/9 pinler korunur.

Yeni [offline candidate identity](CHAINLINK_CANDIDATE_IDENTITY.md) CLI'si ayrı
schema ile committed ELF/metadata, tarihsel key, 21/9 ve iki ayrı test-only pin,
yerel kaynak/derleyici template'i ve açık public config'i doğrular. **19 unit
PASS**; gerçek yedi compiler artifact + 353 kaynaklı CLI demo create/validate
başarılı; scope sahteciliği ve overwrite reddedildi. Demo adres/runtime/policy
değerleri açıkça sentetiktir. Gerçek target/runtime/servis gözlemi, yeni
setup/proof veya submission kabulü değildir; çıktı her zaman HOLD'dur. Mevcut
v2 manifest 36 testte OK (bir optional Anvil yerelde skip), eski schema/guard
aynıdır. A11'e yalnız yeni unit discovery satırı eklenmiştir.

SECURITY'deki uygulanmış rejection membership/refund yolu doğru kapsamıyla
düzeltildi; guest'te ret gerekçesi meşruiyeti ve matching fairness açık kaldı.
[Policy durum belgesi](REPOSITORY_POLICY_STATE.md), canlı review=0 ile önerilen
review=1 şablonunu ayırır; **19 gözlenen CI ≠ 11 zorunlu context**. Politika
değiştirilmedi. [Son kanıt paketi](audits/2026-10-12-chainlink-offline-finalization/README.md).

Bir sonraki aşama onaylı hedef/servis/feed/quote/scale/USDC/uptime/grace ve
operatör policy bağlarını tamamlamak; signed transport, ayrı aday prover ve L1
uçtan uca bağlantısını gerçek proof/custody kabulüyle sınamaktır. Feed discovery
kullanıcı kararıyla ertelenmiştir. GPU'suz offline hazırlık bu gerçek kimlikleri
ve proof'u tahmin ederek kapatamaz. Production HOLD devam eder.

## Açık işler ve kapanış ölçütleri

#56 fixture HTTP, `bb3e9da7703ed9adb24e836c434faeae8a180889` yayın head'inde
19/19 esas SUCCESS (+ Preview) sonrası normal merge edildi:
`60eceef733613fe6d491548d35eb4fdb7c0809bd`. Test/merge/yerel ağaç
`2210378bbf3edb040c591e02286a25a4dfb58a41`; üç main push koşusu da artık
SUCCESS. Eski raporlar, 13/7/62 dirty checkout ve korumalar korunmuştur.

Son GPU'suz kod `52600351c4a3e5a9ad0c565175dc3c9561f30dfd`, yalnız `cfg(test)`
signed/sealed fixture kanalını ekler. Ayrı path/type/domain, configured signing ve
X25519 public peer pins, session/request/program/direction/action/exchange/payload
bağları; canonical low-S imza → bounded box/DH/decryption → exact inner frame
kontrolü uygulanır. Mevcut kripto bileşenleri ve katkısız DH ret kontrolü kullanılır.
Signature yalnız configured ECDSA key possession; sender static-X25519 private
possession, attestation veya operatör onayı değildir. Yeni backend/production
route, plaintext fallback, tekrar mutasyon ya da submission açılmadı.

Bounded session replay exchange/mutation-effect kaydını peer etkisinden önce
ayırır; dolunca eviction yapmadan ret/HOLD. Yeni session/peer process veya reset
kalıcı/global exactly-once garantisi vermez. Eski coordinator/store/physical lane
korunur; üç lost ACK dalı aynı lookup ve absent-report HOLD davranışına sahiptir.
Yeni 19 test, iki tam native sealed HTTP akışı ve geçerli imza altında bozuk
AEAD/tag, düşük dereceli epk, high-S ve post-decrypt context retlerini içerir.
Eski 18 plain HTTP test dosyası byte-exact kalmıştır. Her owned HTTP fault fresh
fixture kullanır; pure codec matrix kendi Pair/input'unu alan retleri için tekrar
kullanabilir. Captured wire literal plaintext yokluğu process memory/CC gizliliği
değildir; proof/finality/settlement hâlâ opaque fixture beyanlarıdır.

Final yerel **716 PASS / 0 FAIL / 23 intentional IGNORE**, focused yeni **19/0/0**,
Python builder/preflight **25 PASS**, workspace format/Clippy PASS; 375 covered
source öncesi/sonrası `ec07ccd9cba6f2b52b7600e149715805bd7d58e84195c4a947e4c75102cf9b89`.
21/9/AUX2 pinler, root Cargo dosyaları, eski guest/core/ELF/vkey/store/fixtures
korunur. [Signed/sealed kapsam](CANDIDATE_FIXTURE_SEALED_CHANNEL.md) ve
[yerel kanıt](audits/2026-10-12-candidate-fixture-sealed/README.md).
Yerel sonuç yeni yayın head'inin CI/normal merge gözlemi yerine geçmez.
Gerçek candidate backend/deployment transport, onaylı target/policy/service/key
girdileri, fresh proof, gerçek CC/key release/DON/custody/operations/release
kabulü açık; DPCLK3 production compatibility REFUSED ve PRODUCTION HOLD sürer.
Live feed discovery ertelemesi korunur.

#55 public-service identity, `e221ddf9a9af47d80b723770392bcbcf97784de8`
yayın head'inde 19/19 esas SUCCESS (+ Preview) sonrası normal merge edildi:
`29be35c7a66c20563fb83812039eaaf1aa05d80a`. Test/merge/yerel ağaç
`fd456f6e4ca8c519cf1153cf375f999d3cfe4095`; üç main push koşusu da artık
SUCCESS. Korumalar değişmedi; eski 13/7/62 dirty checkout korunmuştur.

Son GPU'suz kod paketi `a716f0c0fe6305749844d4f16cabbff19541b2d2`, aday
protokol için yalnız `cfg(test)` loopback HTTP fixture adapter'ıdır. Sabit ayrı
path/domain ve canonical action/request/program/exchange/payload bağları,
bağımsız configured/native/plan kontrolü ve bounded tek exchange kullanılır.
Eski DPCINT4/DPCREG1/DPCBTX1 store, checkpoint ve fiziksel lane değişmez;
mevcut coordinator source/lease/durability otoritesidir. Üretim rotası/backend,
legacy prover fallback'i veya canlı gönderim açılmadı.

İki normal/liquidation native HTTP pozitif akışı aynı test sürecinde baseline
barrier'ı oluşturur; her ret ayrı temiz fixture/state/lane kullanır. Clock ACK
kaybı Resume'da rapor kaydı uydurmaz: rapor yoksa ReportsPending/Absent/HOLD.
Rapor/broadcast ACK kaybı yalnız mevcut sonucu lookup eder; aynı mutasyonu
otomatik tekrar etmez. Tamamlanmış outcome'un terminal handoff replay'i HTTP yapmaz.
Opaque mock proof ve finality beyanları gerçek proof/chain kabulü değildir.

Kaynakta 18 yeni test vardır; final yerel sonuç ve yeni yayın head'inin CI/merge
kaydı ayrı kanıtlanır. [HTTP fixture sınırları](CANDIDATE_FIXTURE_HTTP.md) ve
[kanıt paketi](audits/2026-10-12-candidate-fixture-http/README.md).
İlk kaynakta yerel gateway **697 PASS / 0 FAIL / 23 intentional IGNORE** (18 yeni HTTP
testi dahil), Python builder/preflight **25 PASS**, workspace format/Clippy PASS.
373 covered source `69e33918…` hash'iyle test öncesi/sonrası eşleşti; 21/9/AUX2
pinler ve root Cargo manifestleri byte-exact. PR56 ilk yayın head'i `8181880…`
CI'da yeni derleyicinin `fetch_update` deprecation hatası nedeniyle merge edilmedi.
Yalnız sayaçta checked `compare_exchange_weak` döngüsüne geçildi; Relaxed ordering,
önceki ID dönüşü ve taşmada ret korunur. Yeni `644a6c7c…` kaynakta 18 HTTP testi,
25 Python testi, workspace format/Clippy yeniden PASS; eski tam 697 sonucuyla
yeni focused sonuç ayrı kayıtlıdır. [Uyumluluk ek kanıtı](audits/2026-10-12-candidate-fixture-http-compatibility/README.md).
Bu yerel sonuç yeni yayın head'inin
CI'ı yerine geçmez; kaynak/komut/çıktı ve başarısız-önce/geçti-sonra kayıtları
ayrı kanıt paketindedir.
Mevcut gerçek servisler legacy/DPCLK2 kalır; production service preflight'ında
DPCLK3 uyumluluğu REFUSED'dur. Gerçek candidate backend, sealed/authenticated
witness transport, onaylı target/policy/servis config ve gerçek proof/receipt
kabulü hâlâ açık. Live feed discovery ertelenmiş; production HOLD sürer.

#54 readonly target observer, `39d8def8355e3cb945ebc52b7922d2d4d8060b7a`
head'inde 17/17 esas SUCCESS (+ Preview) sonrası normal merge edildi:
`8f5e97bc690c1d9a6d796fdc3725526d283e077d`. Test/merge/yerel ağaç
`87b173f50291a60b1de35ba202db2b4ba3435252`; ardından üç main push koşusu da
SUCCESS. A01/A10 path filtrelerine girmedi ve başarılı sayılmadı. Korumalar aynı.

Son GPU'suz public-service identity kodu `9c7347870d7212ec2ca66a92729ee5b433ca9efb`
ile gateway ve mevcut prover'a yalnız `GET /identity` eklendi. Baked public
kaynak-map SHA, çözülmüş public config ve mevcut prover'ın embedded ELF/captured
vkey beyanı verilir; evidence kind açıkça `self_reported_unattested` olur.
Kaynak checksum'u binary/compiler/process attestation değildir. Mevcut backend
legacy/DPCLK2 kalır; DPCLK3/candidate desteklenmez, gönderim engeli kalkmaz.
İmza, token, seal root, URL/keystore/archive/snapshot path veya account body
yayınlanmaz. Eski startup/setup/prove/handshake ve finansal yollar korunur.

Yerel final gateway **679 PASS / 0 FAIL / 23 intentional IGNORE**, yeni Python
builder/preflight **25 PASS**, prover dependency-light gerçek router/socket
harness **6 PASS** ve Clippy, workspace Clippy/format, mevcut **148 guard OK
(bir optional legacy Anvil skip)**. SDK6.1 actual prover-service typecheck'i
owned registry/target ve committed ELF ile geçti; backend/setup/prove başlatılmadı.
21 reviewed/9 candidate/AUX2 pinler ve root Cargo manifest/lock aynı kaldı.
Yeni publication CI/merge bu yerel kayıttan ayrı doğrulanır.

Dosya tabanlı preflight, bağımsız beklenen public build/config/program ile iki
snapshot'ı karşılaştırır. `DECLARATIONS_MATCH` yalnız beyan/checksum eşleşmesidir;
candidate compatibility her zaman REFUSED/false, attestation ve approval false,
release HOLD'dur. [Kılavuz](PUBLIC_SERVICE_IDENTITY.md) ve
[kanıt paketi](audits/2026-10-12-public-service-identity/README.md).
Gerçek onaylı target/policy/servis input'ları bulunmadı. Bu yazılım mekanizması
R02 gerçek deployment/servis kabulünü kapatmaz; discovery ertelemesi korunur.

#53 dual-lease handoff/offline identity, `0d14d01cb31fd90e443ea740d81888517e2459bb`
yayın head'inde 19/19 esas SUCCESS (+ Preview Comments ek SUCCESS) sonrası
12 Ekim 04:12:58 Türkiye saatinde normal merge edildi:
`0b20e6a4ad7223d394cfb0632507f20c9ed0d776`. Test/merge ağacı aynı
`579ee2a02a358f704e3d6e2aadbc7801629400de`; merge sonrası main'in ci,
A11 release evidence ve Chainlink candidate push koşuları da SUCCESS.
Son yayın Linux debug/release gateway **673 PASS / 0 FAIL / 23 intentional
IGNORE**, workspace/serde/no_std ve ayrı CPU/Foundry kapılarını geçti. Eski
yerel 995d204 tam koşu, yeni CI sonucu yerine geçirilmez.

Yeni GPU'suz yazılım paketi [candidate target observer](CHAINLINK_TARGET_OBSERVER.md)
ile yalnız read-only finalized RPC kimlik kontrolüdür. Eski candidate/v2
manifest şemaları ve guarded source/ELF/vkey değişmez. On EVM code hash'i,
yedi compiler template/immutable kimliği, candidate stack'in on bir bağlantısı,
clock/key/policy/grace ve explicit operatör declaration'ları eşleşmelidir.
Kod/getter okumaları aynı EIP-1898 anchor'da tekrarlanır; güncel finalized tip
gerileyemez ve en fazla 64 parent ile özgün anchor'a bağlanmalıdır. Bu tek
RPC'nin tutarlılığıdır; bağımsız consensus/ancestry kanıtı değildir.

Public gerçek candidate hedef/servis config'i bulunmadı. Salt yerel owned Anvil
provasında yedi gerçek sözleşme + mock token/DON proxy/uptime kullanılır.
Uptime sağlığı, gerçek DON, yeni proof, çalışan servis, custody ve production
kabulü açık kalır; sonuç başarılı kimlik eşleşmesinde bile HOLD'dur. Yeni Python
kaynakları covered inventory'yi değiştirdiği için #53'ün 353-source manifest
demo'su tarihsel olarak korunur; yeni bir manifest ayrı pathname'de hazırlanır.
Bu paketin yerel sonuç/kanıtı ve yeni yayın head'inin CI'ı ayrı kaydedilir.

| Öncelik | İş | Kapanış ölçütü |
|---|---|---|
| P0 | Dört exact wallet witness proof'u | Yeni gerçek proof + gerçek SP1/clock/settlement/claim doğrulaması; CPU execution/setup sayılmaz |
| P0 | Deployment/servis kimliği | Hedef chain, runtime/immutable/config/vkey ve çalışan servis eşleşmesi; yeni wrapper'ın uptime feed/grace immutables dahil |
| P0 | NVIDIA CC/key release | Gerçek backend, evidence, nonce/measurement pinleri ve canlı handshake; mevcut backend fail-closed stub |
| P1 | Chainlink canlı entegrasyon | Yetkili stream erişimi; gerçek feed/decimal/quote pinleri; DON verifier; yeni guest kimliği/proof; gateway/prover/L1 uçtan uca bağlantı |
| P1 | Uptime canlı kabulü | Resmi hedef feed/runtime, onaylı grace, gateway observer ve gerçek ağ/servis tatbikatı; mevcut testler sentetiktir |
| P1 | Kesinti sonrası pending batch recovery | Yeni uptime döneminde eski clock/rapor kaydını yeniden kullanmadan HOLD, uzlaşma, rollback/yeniden admission ve wind-down senaryoları |
| P1 | Oracle ekonomisi | USD/USDC değerleme, rapor zaman politikası ve likidite zarfı dış değerlendirme; TWAP/quorum iddiası yok |
| P1 | Prover kapasite/finalite | Gerçek proof p95/RSS, yükte admission duruşu ve risk eşikleri |
| P1 | Operatör/prover/governance kaybında exit | Yeni withdrawal ve bağımsız claim verisi erişimi, gerçek verifier ile fon senaryoları |
| P1 | Matching fairness/ret meşruiyeti | Sıra ve ret kurallarının guest içinde doğrulanması; ayrı guest-affecting çalışma |
| P2 | Operasyonel recovery | Canlı anahtarlarla farklı makine, L1/pending tx uzlaşması, ölçülmüş RTO/RPO ve alarm teslimi |
| P2 | Bağımsız audit | Protokol/custody/proof/sözleşme/ekonomi dış incelemesi |

## Değişmez sınırlar

Gerçek credential dosyaları okunmaz veya yayınlanmaz. Ücretli abonelik, GPU/prover,
kamu zincirine işlem, state migration ve production rollout yapılmadı.
Mock uptime/DON/SP1 testleri canlı doğrulama veya gerçek proof değildir.
Ayrı aday guest, reviewed v2 ELF/vkey'nin yerine geçirilmez.

## #44 kanıt yayını ve sonuçların doğru kapsamı

11 Ekim 2026: #43 main'de (c34fb56). #44 kodu e283958 için gerçek yerel sonuç:
528 gateway PASS/16 IGNORE (22 binding testi dahil), istemci debug/release ayrı
ayrı 62 PASS/1 yardımcı IGNORE, 47 Python guard; 21 reviewed + 9 aday kaynak
pini aynı. Son koşu 10 Ekim 22:35–22:36 UTC / 11 Ekim 01:35–01:36 Türkiye.

`audits/2026-10-11-chainlink-archive-gateway-binding/final-verification.json`
artık bu pakette izlenir. Özgün JSON hash'i 51586580224bb7c6c9358beb8471b618e9139db528a69266901b77a9dfd0caa0;
18 kaynak ve 13 yerel log hash'i yeniden doğrulanmıştır. Bu yeni test koşusu
değildir. README eski yanlış pin/host-only/snapshot testi/tarih/proof iddialarını
düzeltir; özgün ara notlar `historical-notes.md` içinde tarihsel olarak korunur.

Recheck kaydındaki e283958 CI 19/19 SUCCESS'tir. Dokümantasyonun yayınlandığı
`5cb1470` head'i de 19/19 SUCCESS sonrası #44 ile main'e birleşti.
Native MockProverClient replay gerçek SP1 proof değildir. PRODUCTION RELEASE
HOLD sürer. Birincil masaüstü checkout'un yerel değişiklikleri korunur.
