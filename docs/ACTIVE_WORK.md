# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 10 Ekim 2026. **PRODUCTION RELEASE HOLD**.
Bu belge güncel çalışma sırasıdır; tarihsel `NEXT_STEPS.md` yerine kullanın.
Son birleşen main: `e552bbab6868b070ff9c3b8f4ed3b9dec1230288`.

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
  **değer eşleşmesiyle** bağlanır; bağlanamayan pencere seal edilmez (fail-closed).
- Rollback journal yeni açık sürüm `DPRBJL6\0`: v5 journal + authenticated
  ArchiveEnvelope (policy binding + op başına archive ID). v5 ok/yaz davranışı
  aynen korunur; aday-gerekli modda legacy journal reddedilir; legacy modda v6
  journal reddedilir; saat modu `resume_exact` zarfı düşürmeden yazar.
- Boot recovery: açılan aday journal'ın her referanslı kaydı var olmalı,
  policy/market/op zamanıyla çözümlenmeli ve op transcript'iyle birebir
  eşleşmeli; eksik/bozuk/uyumsuz kayıt = sürümlü HOLD (dosya korunur, başlangıç reddedilir).
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

Sıradaki yazılım: canlı Data Streams entitlement sonrası uçtan uca aday döngü,
v3 chainlink guest'in gerçek prover bağlantısı (şu an açıkça devre dışı;
v3 witness v2 prover'a GÖNDERİLMEZ), admission dedup/scheduler. İstemci ve arşiv
sonucu DON açısından doğrulanmamıştır. Ücretli erişim ve gerçek credential
kullanımı ayrıca yetki ister.

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

## Son yayın durumu: aday gateway bağlantısı PR'ı açık

11 Ekim 2026: #43 main'de (c34fb56). Bu dal (#43 sonrası main tabanlı) önceki
yerel arşiv çalışmasını taşır ve üzerine opt-in candidate gateway intake/seal/
journal/recovery bağını ekler; PR main'e açıktır, merge yapılmadı, PRODUCTION
RELEASE HOLD sürüyor. Kanıt: `audits/2026-10-11-chainlink-archive-gateway-binding/`.
