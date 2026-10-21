# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 16 Ekim 2026. **PRODUCTION RELEASE HOLD** · candidate submission kapalı.

Bu belge kısa güncel durum ve açık kabul kapılarıdır. 9–14 Ekim çalışma günlüğü
(PR33–PR71, paket başına yerel sonuçlar ve CI düzeltmeleri)
[ACTIVE_WORK_HISTORY.md](ACTIVE_WORK_HISTORY.md)'ye taşındı; daha eski
`NEXT_STEPS.md` de tarihseldir.

"Depoda uygulandı", "testte geçti", "çalışan hedefte doğrulandı" ve "üretime
onaylandı" ayrı düzeylerdir; bu belge birini diğerinin yerine kullanmaz.

## Güncel durum

| Alan | Durum (16 Ekim 2026 salt-okuma) |
|---|---|
| main | #72–#75 normal merge ile birleşti (16 Ekim); bu PR #75'ten sonra birleşir |
| PR kabulü | #72–#75'in her biri kendi head'inde 19–20 kontrolün tamamı SUCCESS iken, head'e sabitlenmiş normal merge ile birleşti |
| Açık PR | Bu belge güncellemesi dışında yok |
| Ürün konumu | Custodial testnet alpha ([README](../README.md), [SECURITY](SECURITY.md)) |
| Release | **HOLD**. Candidate submission kapalı; v3 witness v2 prover'a gönderilmez |
| Kabul kapıları | G1–G6'nın altısı da açık. G1 ve G5'te GPU gerektirmeyen ilerleme var (aşağıda) |

## Çalışan sistem gözlemi

- Public web istemcisi canlı bir gateway'e bağlı değildir: yayındaki bundle'da
  `VITE_API_URL` boştur ve istemci mock modda çalışır.
- Kayıtlı Base Sepolia dağıtımı
  ([base-sepolia.json](../contracts/deployments/base-sepolia.json), 11 Temmuz)
  main'den önceki program key'ine bağlıdır. Settlement `batchCount` = 3.
- 16 Ekim: Ops host'unda Haziran tarihli eski bir prototip gateway bulundu. Bu
  gateway, repo'da kayıtlı olmayan bir test stack'ine yaklaşık 30 saniyede bir
  boş batch settle ediyordu. Servis durduruldu ve devre dışı bırakıldı.
- main'in gateway'i ops host'unda yalnız tatbikat için, demo modda ve
  `deploy/` unit'leriyle çalıştırıldı. `/identity` kaynak checksum'ı CI
  artifact'ıyla eşleşti. Tatbikattan sonra durduruldu. L1'e bağlı çalışan bir
  servis yoktur; prover host'unun durumu doğrulanmadı.
- Repo merge'i web sitesini, servis binary'sini, on-chain bytecode'u veya
  program anahtarını kendiliğinden güncellemez.

## Son birleşen paketler (PR63–PR71)

Hepsi normal merge. Daha önceki paketler ve her paketin yerel test sayıları
[tarihsel günlüktedir](ACTIVE_WORK_HISTORY.md).

| PR | Merge | Konu | Kanıt |
|---|---|---|---|
| #63 | `c929c719` | Prover bearer'ı curl argv dışında tutma | [bearer-header-privacy](audits/2026-10-13-bearer-header-privacy/README.md) |
| #64 | `c387dbe2` | Plaintext allocation öncesi witness boyutu kontrolü | [plaintext-preflight](audits/2026-10-14-plaintext-preflight/README.md) |
| #65 | `16fde84b` | Önceki pencere baseline'ını witness'a taşıma | [seal-window-ownership](audits/2026-10-14-seal-window-ownership/README.md) |
| #66 | `d5d200d8` | v6 journal'ı borrowed view ile serialize etme | [journal-v6-view](audits/2026-10-14-journal-v6-view/README.md) |
| #67 | `c0694613` | Sınırlı hazırlama CPU tanı ölçümleri | [preparation-cpu-profile](audits/2026-10-14-preparation-cpu-profile/README.md) |
| #68 | `a4b35e20` | Native roots'u yeniden kullanma; Rustls advisory düzeltmesi | [clock-roots-carry](audits/2026-10-14-clock-roots-carry/README.md) |
| #69 | `93ac853e` | Sabit fixture'larla native hazırlama CPU/RSS ölçümü | [finite-preparation-profile](audits/2026-10-14-finite-preparation-profile/README.md) |
| #70 | `98cded40` | Withdrawal Merkle katmanlarını çağrı başına bir kez kurma | [merkle-levels](audits/2026-10-14-merkle-levels/README.md) |
| #71 | `c31d1647` | Profil runner'ında sahipli process-group temizliği | [process-supervision](audits/2026-10-14-process-supervision/README.md) |

Ölçümler sentetik fixture ve tekil süreç gözlemleridir; gerçek proof süresi,
throughput, servis gecikmesi veya kapasite garantisi değildir.

## 16 Ekim: GPU ve para gerektirmeyen paket (PR72–)

| PR | Konu | Kanıt |
|---|---|---|
| #72 | Bu belgenin kısaltılması; 9–14 Ekim günlüğünün ayrı dosyaya taşınması | [ACTIVE_WORK_HISTORY](ACTIVE_WORK_HISTORY.md) |
| #73 | Canlı yedek, dış sağlık izleyicisi, alarm yeniden denemesi, `deploy/` systemd/Caddy dosyaları | [RECOVERY_RESTORE](RECOVERY_RESTORE.md), [deploy](../deploy/README.md) |
| #74 | Kişiye özel claim dosyası ve operatörden bağımsız claim kontrol aracı | [FUNDS_LIFECYCLE](FUNDS_LIFECYCLE.md) |
| #75 | `--print-genesis-root`, release artifact'larıyla deploy aracı, env tabanlı frontend adresleri, Linux release binary workflow'u | [clock-stack-deploy-kit](audits/2026-10-16-clock-stack-deploy-kit/README.md) |
| #76 | Restore/alarm tatbikatı; `RestartMode=direct` düzeltmesi | [g5-restore-alarm-drill](audits/2026-10-16-g5-restore-alarm-drill/README.md) |
| #91 | Settle edilemeyecek clock penceresi restart gerektirmeden çözülür: settle döngüsünde kurtarma, faz-0 pencerenin canlı void'i, kullanıcı olayları ve `/api/state` `clockRecovery`/`settlementVoid`; kimlik rotasyonu ve sigorta bootstrap düzeltmeleri | [PROVING-RUNBOOK](PROVING-RUNBOOK.md) (§ Dead clock window) |

## Açık kabul kapıları

| Kapı | Eksik olan | Kapanış kanıtı | Önceki öncelik satırı |
|---|---|---|---|
| **G1** Çalışan hedef ve servis kimliği | Onaylı chain ve kontratlar; çalışan gateway/prover sürümü; config/program/peer/key kimlikleri; uptime feed/grace immutables. *16 Ekim:* Genesis ve deploy araçları ile Linux release binary'si hazır. Kendi SP1 stack'imizle Base Sepolia fork'unda VERIFIED; Succinct gateway'iyle BLOCKED. Gerçek deploy prover (G3) ve attestation (G4) bekliyor | Aynı kesite bağlı deployment manifest'i, [public-service identity](PUBLIC_SERVICE_IDENTITY.md) karşılaştırması ve finalized zincir gözlemleri. Beyan eşleşmesi attestation değildir | P0 deployment/servis kimliği · P1 uptime canlı kabulü |
| **G2** Gerçek DPCLK3 backend ve kalıcı recovery | Aday protokolün gerçek transport/servis/backend'e bağlanması; yetkili Chainlink stream, gerçek feed/decimal/quote pinleri, DON verifier | Gerçek backend ile başarı akışı ve kesinti matrisi (pending, cevap/ACK kaybı, restart, finalize olmamış sonuç); tekrar kayıt veya broadcast yok | P1 Chainlink canlı entegrasyon · P1 kesinti sonrası pending batch recovery |
| **G3** Exact witness → gerçek proof → zincir kabulü | Dört exact wallet witness için yeni proof; SP1/clock/settlement/claim doğrulaması. CPU yürütmesi ve setup/vkey yeterli değildir | Witness hash, guest/ELF/vkey, proof, public değerler, hedef settlement/claim sonucu; yanlış proof/program/batch/chain ve tekrar claim negatifleri; ölçülmüş proof süresi, p95 ve RSS | P0 dört exact wallet witness · P1 prover kapasite/finalite |
| **G4** Donanım doğrulaması ve anahtar teslimi | Gerçek CC/TEE backend; nonce, measurement ve quote bağları; canlı handshake. Mevcut backend fail-closed stub'dır | Olumlu attestation/key release; yanlış measurement, eski nonce, geçersiz quote ve uygunsuz peer için ret kanıtı | P0 NVIDIA CC/key release |
| **G5** Custody, çıkış verisi ve operasyonel kurtarma | Başka makinede restore, L1/pending işlem uzlaşması, kullanıcı exit verisine erişim, RTO/RPO, alarm teslimi. *16 Ekim:* Canlı yedek, dış izleyici, alarm yeniden denemesi, kişiye özel claim dosyası ve operatörsüz claim kontrolü eklendi. Demo modda başka makinede restore yapıldı (RTO 9,6 s) ve alarm gerçek ntfy topic'ine teslim edildi. Kalan: L1/pending uzlaşması, hedef RTO/RPO, sorumlular, fencing | Restore tutanağı, ölçülmüş süre ve veri kaybı, alarm teslim kaydı, operatör/prover/governance kaybında claim ve withdrawal yolları | P1 operatör kaybında exit · P2 operasyonel recovery |
| **G6** Ekonomi, fairness ve bağımsız release | Oracle değerlemesi ve USD/USDC ilişkisi; rapor zaman politikası; guest içinde matching fairness ve ret meşruiyeti; bağımsız denetim | Kritik bulguları kapanmış dış denetim, onaylı oracle/çalışma politikaları ve açık release kararı | P1 oracle ekonomisi · P1 matching fairness · P2 bağımsız audit |

Önerilen sıra: hedef ve release girdilerini dondur → G1 → G2 → G4 → G3 →
kapasite ve operasyon tatbikatı (G5) → G6 ve release kararı. G4 ile backend
geliştirmesi kısmen paralel yürüyebilir. Bu sıra bir öneridir, tamamlanma
yüzdesi veya süre tahmini değildir.

## Operatör kararı bekleyen girdiler

- **Hedef:** 11 Temmuz stack'i main ile uyumsuz. Öneri, kendi SP1 verifier ve
  gateway'imizle yeni bir Base Sepolia dağıtımı
  ([runbook](REDEPLOY-CC-RUNBOOK.md)). Succinct gateway'ini kullanmak,
  manifest'e onların bytecode'unu ekleyen ayrı bir karar gerektirir.
- **Makineler:** Gateway ve prover host'ları; CC/TEE donanımı.
- **Chainlink stream erişimi:** 10 Ekim'de kullanıcı kararıyla ertelendi; G2 bunu
  bekler. Ertelenme sürdükçe discovery veya credential denemesi yapılmaz;
  varsayılan feed ve USD=USDC eşitliği eklenmez.
- **Public web istemcisi:** Canlı gateway'e mi bağlanacak, yoksa açıkça demo/mock
  olarak mı etiketlenecek?
- **Sorumlular:** Recovery/alarm sorumluları, bağımsız denetim kapsamı ve release
  karar sahibi.
- **Hedef RTO/RPO:** Ölçüm yöntemi ve ilk ölçüm var; kabul edilecek hedef
  değerler operatör kararıdır.

## Küçük açık işler

- PR71 supervisor suite'inin yetkili bir OS ortamında tam kabulü. Bağlı Mac'te
  grup sinyalleri `Operation not permitted` verdi; o koşu başarı sayılmaz.
- Repository politikası: canlı ruleset 0 review, önerilen şablon 1 review ister.
  Değişiklik ayrı bir karardır ([policy durumu](REPOSITORY_POLICY_STATE.md)).

## Değişmez sınırlar

- Gerçek credential dosyaları okunmaz veya yayınlanmaz.
- Ücretli erişim, GPU/prover, gerçek fon, kamu zincirine işlem, state migration
  ve production rollout ayrıca yetki ister.
- Mock uptime/DON/SP1 testleri canlı doğrulama veya gerçek proof değildir.
- Ayrı aday guest, reviewed v2 ELF/vkey'in yerine geçirilmez.
- Tarihsel kanıt paketlerindeki "pass" veya "pending" satırları, ait oldukları
  commit dışına taşınarak yorumlanmaz.

## Bu belgenin bakımı

Bu dosya kısa tutulur ve yerinde güncellenir; append-only değildir. Paket başına
ayrıntılı sonuçlar ilgili `docs/audits/<tarih>-<konu>/` paketine ve PR
açıklamasına yazılır. Burada yalnız tablo satırı ve kapı durumu değişir.
Merge ve main CI okunduğunda ilgili satır aynı gün güncellenir.
