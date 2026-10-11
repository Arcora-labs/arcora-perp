# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 11 Ekim 2026. **PRODUCTION RELEASE HOLD**.
Bu belge güncel çalışma sırasıdır; tarihsel `NEXT_STEPS.md` yerine kullanın.
Son doğrulanan main: `c34fb56b05db13ce09efc0104c2d44abba6d6895` (#43).
Aktif PR #44; doğrulanmış kod `e283958109fc6b434b7049d523bbd3378e2e6c27`.
A0 dokümantasyonu `5cb1470` ile yayımlandı. A1 checkpoint/recovery kodu bu
devam çalışmasında uygulandı; yeni yerel kanıt ve yayın head'inin CI sonucu
ayrıca kaydedilir. Eski test sonucu yeni kodu kapsamaz.

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
  değiştirmez. 4096 sınırında sessiz eviction yoktur; kapasite çözümü açık.
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

## Önce kapanacak GPU'suz yazılım paketleri

| Sıra | İş | Kapanış ölçütü |
|---|---|---|
| A0 | #44 final evidence ve eski audit düzeltmesi | Exact kod SHA'sına bağlı JSON ve düzeltilmiş audit `5cb1470` ile yayımlandı; yayın head'inin CI kontrolü ayrı. |
| A1 | Açık pencerenin özgün kabul ID'lerini kalıcılaştırma | DPCAS2 checkpoint ve doğrulanmış v6 journal'dan özgün ID recovery uygulandı. 535 gateway PASS (29 binding/restart dahil), 47 guard ve Clippy/format temiz; yeni PR head CI ayrı. Snapshot kesiti sonrası admission'lar için tüm-admission WAL garantisi yok. |
| A2 | İndeks kapasitesi ve retention | 4096'yı aşan uzun koşuda aktif açık pencere/journal/recovery referanslarını kaybetmeden güvenli serbest bırakma; disk/indeks doluluk duruşu ve restart tutarlılığı. |
| A3 | Fiyat kullanan bütün gateway yolları | Fill/funding/liquidation/close/mark/matching ve withdrawal aday yaşam döngüsü; eksik/eski/yanlış raporda ret; yeni guest CPU/native karşılaştırması ayrı. |
| A4 | Ayrı aday prover/settlement protokolü | Doğru witness/program/vkey/report/clock/uptime bağları; yanlış sürümde sıfır registration/prove/broadcast; yerel harness ardından gerçek proof/verifier kabulü. |

Canlı feed keşfi/entitlement kullanıcı kararıyla ertelenmiştir; A1–A4 yazılım
hazırlığını durdurmaz. Yeniden discovery/credential denemesi veya feed/eşik
tahmini yapılmaz. DON doğrulaması, yeni proof ve canlı deployment kabulü olmadan
aday gönderim engeli kaldırılmaz; v3 witness v2 prover'a GÖNDERİLMEZ.
Ücretli erişim, gerçek credential/fon ve kamu zinciri işlemi ayrıca yetki ister.

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
head ve merge durumu GitHub'dan ayrıca okunur; eski yeşil sonuç aktarılmaz.
Native MockProverClient replay gerçek SP1 proof değildir. PRODUCTION RELEASE
HOLD sürer. Birincil masaüstü checkout'un yerel değişiklikleri korunur.
