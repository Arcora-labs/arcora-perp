# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 11 Ekim 2026. **PRODUCTION RELEASE HOLD**.
Bu belge güncel çalışma sırasıdır; tarihsel `NEXT_STEPS.md` yerine kullanın.
Son doğrulanan main: `0ea5048627840cbe7e125d7b914b1303b109b224` (#50).
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
Repository korumaları değiştirilmedi. Bu dal A4'ün offline broadcast sonuç/kilit
paketidir; her paketin yerel kanıtı ve yayın head'inin CI sonucu ayrı kaydedilir.

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
| A4 | Ayrı aday prover/settlement protokolü | İlk offline harness #48, 19/19 başarılı kontrol sonrası normal merge edildi. DPCINT4 ara kayıt recovery ve mock finality uzlaşması #49 ile 19/19 başarılı kontrol sonrası birleşti: 597 gateway, 25 odaklı recovery, 47 guard PASS. Tam native kontrat köprüsü #50, 19/19 kontrol sonrası birleşti. Yeni host-only broadcast sonuç/yerel lease paketi bu dalda 628 gateway ve 26 odaklı PASS ile doğrulandı; yayın CI ayrı. Gerçek proof, canlı servis/target ve L1 uzlaşma kabulü açık. |

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

## Yeni A4 paketi: offline broadcast outcome ve yerel lease

Bu dalda ayrı `cfg(test)` dispatcher, terminal DPCINT4 Prepared'ı doğrular;
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

Final kod `44b81edd3ac4c2781e91ddbbb75f9bd9dd882d44`; yerel tam gateway
**628 PASS / 0 FAIL / 21 intentional IGNORE**, yeni odaklı **26 PASS**,
47 guard, Clippy `-D warnings`, format ve 21/9 pin başarılı. 1.927 önceki dosya
hash'i ve özgün 13/7/62 dirty checkout içerikleri korunur. Foundry/SP1 CPU bu
host-only pakette yeniden çalıştırılmadı; #50 corpus/kontrat/kaynak ve kanıt
hash'leri değişmedi. [Yeni kanıt](audits/2026-10-11-chainlink-broadcast-outcome/README.md).
Yayın head'inin CI sonucu ayrıca doğrulanır.

Sıradaki GPU'suz yazılım adımı: [registration'ı lease altında Prepared'a kadar
koordine etmek](audits/2026-10-11-chainlink-broadcast-outcome/next-gpu-free-a4.md).
Bu yalnız tasarımdır; tarihsel broadcast tail, kayıt formatları ve callback
schedule korunarak ayrı preparation transport gerekir. Gerçek proof, deployment,
DON/uptime/custody ve production kabul kapıları açık kalır.

## Açık işler ve kapanış ölçütleri

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
| P2 | Repository policy belgeleri | Canlı review=0 ile eski şablon farkını açıkça çözme; korumaları sessizce değiştirmeme |

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
