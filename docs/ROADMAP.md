# Dark-perp / Arcora Perp: audit ve canlıya çıkış roadmap'i

**Güncelleme:** 19 Eylül 2026. **Kod tabanı:** `main@b3372caef14ff847f57e949dc3ccf2df30759350`.

**Durum: tam codebase audit'i bitmedi. Gerçek SP1 ELF/vkey/proof/deployment doğrulaması yapılmadı. Gerçek para için yayın onayı yok.**

Bu belge eski faz roadmap'inin ve kaldırılan `GO_LIVE_ROADMAP.md` dosyasının yerine geçen tek güncel iş planıdır. Tarihli audit raporları silinmez; kendi commit'leri için kanıt olarak korunur. Eski README, runbook veya PR açıklamalarındaki testnet/proof/test sayıları bu sürümün doğrulaması sayılmaz.

Yeni oturum doğrudan [AUDIT_HANDOFF.md](AUDIT_HANDOFF.md) ile başlamalıdır. Makinece okunabilir gözlem kaydı: [19 Eylül roadmap kanıtı](audits/2026-09-19-roadmap-evidence.json).

## 1. Doğrulanmış başlangıç noktası

GitHub kayıtları 19 Eylül 2026 tarihinde yeniden okundu:

- `main`: `b3372caef14ff847f57e949dc3ccf2df30759350`.
- [PR #12](https://github.com/Kubudak90/dark-perp/pull/12): kapalı ve **merged**; merge zamanı `2026-09-19T12:02:49Z`.
- PR #12 son head: `c633c642dc5d1deb125bbbd8b1c7e9eff4b04839`; dal `fix/a07-recovery-ui-hotfix-2026-09-19`.
- [PR #11](https://github.com/Kubudak90/dark-perp/pull/11) de merged. Eski roadmap'teki “#11 açık” ve “A07 modül bildirimi eksik, current main derlenmiyor” durumu artık güncel değildir.
- Bu dokümantasyon dalı oluşturulmadan önce açık PR listesi boştu. Sonraki oturum bunu yeniden sorgulamalıdır.

Bu kimlikler bir başlangıç kaydıdır, gelecekteki `main` için sabit varsayım değildir. Her yeni iş önce güncel main, açık PR'lar, seçilen head ve o head'in CI durumunu okumalıdır.

## 2. Yapılan işler: merge edilmiş kapsam, genel güvenlik onayı değil

Aşağıdaki özet PR kayıtlarına dayanır. Her satırın değişikliği tekrar sıfırdan audit edilmiş veya fiziksel/canlı ortamda doğrulanmış değildir.

| İş | Birleşen çalışma | Uygulanan kapsam | Açık kalan sınır |
|---|---|---|---|
| Başlangıç audit'i | [#1](https://github.com/Kubudak90/dark-perp/pull/1) | A01–A11 sınıflandırması ve eski kaynak üzerinde sekiz hata karakterizasyonu | Karakterizasyon testinin geçmesi açığın kapandığı anlamına gelmez |
| A02, A03, A08, A09 | [#2](https://github.com/Kubudak90/dark-perp/pull/2) | Snapshot ACK öncesi izin imzasını engelleme; imzalı receipt teslimi; production sentetik depth'in kaldırılması; oracle kaynak zamanının korunması; snapshot sıra/timeout/fsync düzeltmeleri | Gerçek crash drill, receipt'in bağımsız challenge kullanımı ve uçtan uca piyasa verisi yeniden incelenecek |
| A04 | [#4](https://github.com/Kubudak90/dark-perp/pull/4) | Canlı maker kalanının owner-scoped, dayanıklı iptali; önceki fill'leri koruma; canlı kısmi emri geçmiş temizliğinden koruma | İptal/fill/rollback/rotation birleşik yarışları ve eski kayıp geçmiş kayıtları ayrıca incelenecek |
| A01 | [#5](https://github.com/Kubudak90/dark-perp/pull/5) | Finalized, hash-pinned L1 sırasından otonom ingestion; immutable market/purpose/payer yönlendirmesi; insurance ayrımı; dedup, atomiklik, ACK ve restart kontrolleri | Canlı RPC/finality/reorg ve fiziksel dayanıklılık kanıtı yok; belirsiz legacy kayıtlar açık uzlaştırma ister |
| A05 | [#6](https://github.com/Kubudak90/dark-perp/pull/6) | Gerçek kümülatif fill, kalan miktar, tam hassasiyetli VWAP ve settled/unsettled ayrımı; DPSNAP7 execution göçü | Native execution metadata bağımsız matching-fairness ZK kanıtı değildir; bilinmeyen geçmiş uydurulmaz |
| A06 | [#7](https://github.com/Kubudak90/dark-perp/pull/7) | Karşı emirsiz CloseOnly wind-down; phase-1 SettleAll ve phase-2 exit; ordinary/finalSettle/finalExit proof-commitment ayrımı | Guest semantiği değişti. Yeni ELF/vkey/gerçek proof zorunlu; ekonomik ve tam çıkış incelemesi bitmedi |
| A07 temel akış | [#8](https://github.com/Kubudak90/dark-perp/pull/8) | Mevcut signer veya bound wallet yetkisiyle API-key rotation; owner sabit kimlik; deployment/owner/nonce bağlı imza; DPSNAP8 recovery generation | HTTP dayanıklılığı, eşzamanlı rotation ve açık WS oturumlarının iptali kapanmış sayılmaz |
| A10 | [#9](https://github.com/Kubudak90/dark-perp/pull/9) | README/security/litepaper/public-site güven iddiaları trusted-gateway / custodial sınırına daraltıldı | Custody/oracle yetkileri mimari olarak ayrıştırılmış değildir |
| A11 altyapı | [#11](https://github.com/Kubudak90/dark-perp/pull/11) | Dependency, release regression ve source/deployment-record evidence workflow'u eklendi | Workflow'un varlığı güncel release kanıtı değildir; A11'in gerçek prover/deployment bölümü açık |
| A07 entegrasyon ve A07/A01 | [#12](https://github.com/Kubudak90/dark-perp/pull/12) | Recovery modül bildirimi, wallet recovery UI, heading testi, v7/v8 migration regresyonları ve rotation sırasında deposit referanslarının taşınması | Bu sınırlı hotfix tam frontend/gateway/codebase audit'i değildir |

PR #3 eski bir stacked A04/A05 çalışmasıdır; ayrı ve güncel bir release doğrulaması olarak sayılmaz. Solana deneyi PR #10 kapalı ve **unmerged** durumdadır; dark-perp remediation tamamlanma listesine dahil değildir.

### PR #12'de özellikle korunacak düzeltmeler

`recover_account` hesabı yeni API key'e taşırken aynı `Gw` kilidi altında yalnız ilgili hesabın `deposits.routes[*].key` ve `deposits.credits[*].route.key` referanslarını da taşır. Owner, payer, market/purpose, tutar, event kimliği, deposit prefix ve replay semantiği değiştirilmez; diğer hesabın kayıtlarına dokunulmaz.

Regresyonlar pending collateral/insurance izinlerini, başka hesabın iznini, credited receipt'leri, nonce replay reddini, snapshot restore'u ve native replay eşitliğini kapsar. Bunlar localhost/mock kaynak ve kontrollü ACK kullanır; canlı L1 veya fiziksel disk kesintisi testi değildir.

Recovery UI, `durability: confirmed` sonucundan sonra yeni credential'ı kaydeder. App testi erişilebilir recovery başlığını hedefler. V7 çıktısı açıkça üretilerek migration test edilir; yalnızca yeni V8 roundtrip'e bakılıp V7 uyumluluğu varsayılmaz. Mevcut UI canlı recovery capability yoksa açıklama gösterir; demo seed-scan veya gerçek seed recovery garantisi yoktur.

## 3. CI: hangi sonuç, hangi SHA için?

Aşağıdaki GitHub run ve job/step sonuçları bu dokümantasyon çalışmasında yeniden okundu. **Bu, testlerin bu oturumda yeniden çalıştırıldığı anlamına gelmez.**

| Kaynak head | Workflow / run | Gözlenen sonuç | Kapsam |
|---|---|---|---|
| `b3372ca` (tam SHA bölüm 1) | [main CI 35441756911](https://github.com/Kubudak90/dark-perp/actions/runs/35441756911) | completed / success; 4 iş başarılı | Rust workspace, frontend, Foundry, excluded prover typecheck |
| `c633c642` (PR #12 head) | [CI 35437539311](https://github.com/Kubudak90/dark-perp/actions/runs/35437539311) | completed / success; 4 iş başarılı | PR head'ine ait normal CI |
| `c633c642` | [A07 integration 35437539277](https://github.com/Kubudak90/dark-perp/actions/runs/35437539277) | completed / success; 2 iş başarılı | Gateway/fmt/Clippy ve frontend test/build |
| `c633c642` | [A01 ingestion 35437539274](https://github.com/Kubudak90/dark-perp/actions/runs/35437539274) | completed / success; 1 iş başarılı | A01 regresyonları ve ayrıca loopback JSON-RPC cast testi |

Main CI, merge commit'ine aittir; PR head sonuçlarından varsayılmadı. `b3372ca` için sorgulanan run listesinde yalnız normal CI vardı. A11'in aynı merge SHA üzerinde yeniden çalıştığı veya güncel dependency triage'ın tamamlandığı iddia edilmez.

**Prover sınırı:** main run içindeki `105893659414` numaralı işin ham logu yeniden okundu. `SP1_SKIP_PROGRAM_BUILD=true`, boş ELF dosyası için `touch`, guest build'inin atlandığı uyarısı ve iki `cargo check` çağrısı açıkça mevcut. Bu yalnız typecheck'tir. “zkVM-guest builds (no_std...)” adlı workspace adımı da native crate build kontrolleridir; gerçek SP1 guest ELF üretimi sayılmaz.

Eski 609/630/636/684 gibi test toplamları farklı kaynak ve seçimlere aittir; bu sürümün test sayısı olarak birleştirilmez. Başarılı bir job, içindeki ignored/skipped testleri otomatik olarak geçmiş yapmaz. Yeni kod veya dokümantasyon PR'ının CI sonucu kendi head'i için ayrıca okunur.

## 4. Sonraki audit sırası ve kabul ölçütleri

Aşağıdaki kutular **açıktır**. Bunlar doğrulanmış yeni açıklar listesi değil, inceleme ve doğrulama borcudur. Somut bug bulunursa önce yeniden üretim, sonra dar düzeltme ve regresyon testi yapılır; bulunmazsa incelenen yollar ve test kanıtı kaydedilir.

### S1. Recovery HTTP dayanıklılığı, yetki ve WS oturum iptali

Başlangıç: `crates/gateway/src/main.rs`, `account_recovery.rs`, `snapshot.rs`, mevcut recovery ve deposit testleri.

- [ ] Recovery imzasında owner, chain/vault domain'i, mevcut authorizer, nonce/replay ve nonce taşması; yanlış signer, rebind ve eşzamanlı recovery yolları incelendi.
- [ ] HTTP başarı yanıtının ilgili recovery generation'ını kapsayan dayanıklı ACK'e bağlı olduğu gerçek handler testleriyle gösterildi. Writer yokluğu, kapalı/dolu kuyruk, disk hatası, timeout ve request iptali başarı/secret sızdırmıyor.
- [ ] Rotation sonrası ACK belirsizliği ve kayıp HTTP yanıtı için güvenli yeniden deneme tanımlandı. Bellek/disk ayrışması sessiz rollback, nonce sıfırlama veya kullanıcıyı geri dönüşsüz kilitleme ile örtülmüyor. Eşzamanlı rotation ile superseded key teslimi ayrıca ele alındı.
- [ ] Eski API key ile önceden açılmış authenticated WebSocket oturumu rotation sonrasında özel veri alamıyor ve işlem yapamıyor. Kuyruktaki özel olaylar/komutlar, subscription ve reconnect yolları test edildi; yalnız sabit owner filtresi yeterli varsayılmadı.
- [ ] PR #12'nin pending permit/credited receipt taşıması, hesap/emir kimliği ve deposit prefix/replay özellikleri bozulmadı.

**Bitiş kanıtı:** ilgili gerçek HTTP/WS yollarında negatif testler; kontrollü ACK/failure testlerinin mock sınırı; exact base/head, komutlar, exit kodları ve aynı head CI. Fiziksel crash kanıtı ayrıca S6'dadır.

### S2. Frontend credential storage ve eşzamanlı hesap yenileme

Başlangıç: `frontend/src/api/realClient.ts`, `wallet.ts`, `client.ts`, `RecoveryPanel.tsx` ve ilgili testler.

- [ ] Credential'ın kalıcı/geçici saklanma politikası, XSS/CSP ve log/URL/telemetry sızıntısı, bozuk veya erişilemeyen storage ve owner/deployment scope'u incelendi. Bir storage türünü değiştirmek tek başına güvenlik çözümü sayılmadı.
- [ ] `401`, `503`, `durability: unknown`, timeout, bozuk yanıt ve wallet reddi eski kullanılabilir credential'ı yanlışlıkla silmiyor veya başarısız recovery'yi başarılı göstermiyor.
- [ ] Rotation öncesi başlayan account/register/refresh isteğinin geç yanıtı yeni credential veya hesap state'ini ezemiyor. Tekrarlı tıklama, çok sekme, hesap/ağ değişimi ve WS reconnect yarışları test edildi.
- [ ] Owner/domain/nonce ve büyük tamsayıların Rust↔TypeScript wire uyumu doğrulandı. Recovery sonrası yanlış hesaba emir, bakiye veya receipt gösterilmiyor.
- [ ] Gerçek frontend↔gateway yerel E2E ve sürüm uyumsuzluğu testleri tamamlandı; mock bileşen testi bunun yerine kullanılmadı.

### S3. V8 snapshot extension ayrıştırması ve göç

Başlangıç: `main.rs`, `snapshot.rs`, `account_recovery.rs`, `execution.rs`, `execution_regression_tests.rs`, A01 migration fixture'ları.

- [ ] DPSNAP5/6/7/8 dispatch, authenticated envelope ve positional prefix/extension sınırları birlikte incelendi.
- [ ] Extension sınırı veri içinde rastgele magic-byte aramasına dayanarak yanlış ayrıştırılamıyor. Truncation, fazla byte, bilinmeyen/tekrarlı extension, payload içinde marker, sıra hatası ve boyut sınırları test edildi.
- [ ] Recovery owner kayıtlarında duplicate/missing/orphan kontrolü; nonce downgrade/replay, V7 execution trailer kaybı ve A01 routing tutarlılığı korunuyor.
- [ ] Bozuk/önceden tutarsız snapshot açık hata ve uzlaştırma yoluna gidiyor. Snapshot silerek, sıfırlayarak veya recovery nonce'u sessizce düşürerek boot ettirilmiyor.

**Bitiş kanıtı:** frozen eski fixture'lar, V7→V8 native replay/root eşitliği, roundtrip ve adversarial parser testleri. Format değişirse açık sürümleme ve upgrade/rollback uyumluluk planı gerekir.

### S4. Matcher, sequencer, prover, contracts ve CI bütünlüğü

S1–S3 sonrasında paketleri ayrı PR'lara bölerek ilerle; bu tablo bir tamamlanma iddiası değildir.

| Katman | İncelenecek güvenlik özellikleri |
|---|---|
| `perp-core` | Teminat korunumu; funding/fee/rounding; margin/liquidation/ADL; nullifier/withdrawal; overflow ve hata atomikliği; A06 haircut ve tüm pozisyonların çıkışı |
| `matcher` | Price-time; IOC/FOK/PostOnly/GTC/STP; partial/cancel/expiry; risk reddinde defter/state atomikliği; order identity; bounded history |
| `sequencer` ve gateway lifecycle | ACCEPTED/MATCHED/SETTLED ayrımı; özgün receipt; manifest; window seal; rollback journal; duplicate/restart; cancel/fill/settle yarışları ve native replay kökleri |
| `prover`, SP1 guest/host, prover-service | Witness/public input bağlama; native↔guest parity; yanlış/eksik proof reddi; authenticated sealed transport; retry/session rotation; phase 0/1/2 ayrımı |
| `contracts` | Vault/deposit/withdraw muhasebesi; root/nonce/replay/domain; challenge/slash; finalSettle/finalExit; verifier/vkey; access control; pause/CloseOnly ve reentrancy |
| Oracle, attestation, archive | Kaynak zamanı/freshness/confidence; gateway oracle yetkisi; quote/measurement/expiry/replay; key rotation; archive confidentiality ve gerçek restore |
| HTTP/WS ve operasyon | Tüm route'larda production/demo/admin ayrımı; rate/body sınırları; secret handling; shutdown; disk ve bellek baskısı; sürüm uyumu |
| CI ve supply chain | Tetikleme kapsamı; gerçek checkout SHA; lockfile ve excluded crate çözümlemeleri; features/no_std/release; dependency triage; izinler/pinler; skipped/zero-test/timeout'un başarı sayılmaması |

CI incelemesinde özellikle A11'in gateway/core/matcher/sequencer değişikliklerinde tetiklenme kapsamını, toolchain `components` flow-YAML kullanımını ve `--release` testlerinde profil bayraklarının gerçekten uygulandığını doğrula. Source hash/deployment JSON export'u gerçek deployment eşleşmesi değildir. Bu dokümantasyon PR'ı workflow veya güvenlik denetimi değiştirmez.

### S5. Aynı release SHA üzerinde gerçek SP1 kanıt zinciri

- [ ] Bütün gerekli kaynak düzeltmeleri sonrasında release SHA ve Rust/Node/pnpm/Foundry/Solidity/SP1 sürümleri sabitlendi; tam dependency kimliği kaydedildi.
- [ ] Güncel guest gerçek SP1 toolchain ile derlendi; gerçek ELF ve SHA-256 kaydedildi. Stub dosya kullanılmadı.
- [ ] Aynı witness için native ve guest public output byte-exact eşit; normal batch ve A06 phase 1/2 pozitif/negatif vektörleri mevcut.
- [ ] Vkey tam o ELF'den türetildi; gerçek Groth16 proof üretildi ve amaçlanan verifier yolunda doğrulandı.
- [ ] Source SHA, toolchain, dependency graph, ELF, vkey, witness/public inputs ve proof tek hash-bağlı evidence bundle'da.

**Açık engel:** A06 guest semantiğini değiştirdi. Temmuz Base Sepolia deployment kaydındaki vkey'in bu kaynakla aynı olduğu varsayılamaz. Eşleşme henüz hesaplanıp doğrulanmadığı için “kesin farklı” sonucu da uydurulmaz.

### S6. Deployment uyumu ve kontrollü dayanıklılık provaları

Bu bölüm görev/yayın planıdır; canlı eylem yetkisi değildir.

- [ ] İzole Anvil/yerel prova: constructor/admin/sequencer/enclave/oracle/vault değerleri, runtime code hash'leri ve genesis/root bağları.
- [ ] Deposit → partial trade → cancel → gerçek proof settlement → withdraw; CloseOnly → SettleAll → finalExit; recovery old-key reject/new-key accept. Eksik/yanlış proof ve duplicate işlemler reddediliyor.
- [ ] Disk failure, process kill/restart, dolu snapshot kuyruğu, kayıp ACK/HTTP yanıtı, prover restart, RPC timeout/disagreement/reorg ve frontend/backend sürüm uyumsuzluğu provaları.
- [ ] Hedef deployment'ın chain id, blok numarası/hash'i, code hash, verifier/vkey ve contract bağları salt-okunur, pinlenmiş RPC kanıtıyla karşılaştırıldı. Repository JSON'u canlı zincir okumasının yerine geçmedi.
- [ ] Snapshot backup/restore ve legacy uzlaştırma runbook'u; hiçbir kayıp izin, çift kredi/withdraw veya sessiz state reset yok.

Staging'e yazma, deploy/upgrade/verifier rotation, gerçek zincir işlemi veya ücretli proving ancak ayrı açık kullanıcı onayıyla ele alınır. Bu roadmap bunları başlatmaz.

### S7. Operasyon, bağımsız inceleme ve yayın kararı

- [ ] Custody/admin/sequencer/enclave/oracle/prover anahtar envanteri, erişim ve rotation/revocation/compromise runbook'ları.
- [ ] Deposit cursor/halt, snapshot ACK/dirty state, finality/settlement lag, prover hata/latency, oracle age/deviation, RPC disagreement ve vault-engine reconciliation alarmları.
- [ ] Incident response, CloseOnly, restore ve iletişim/escalation provaları.
- [ ] Tam codebase coverage kaydı ve bağımsız dış inceleme; açık critical/high bulgular giderildi veya yayın durduruldu.
- [ ] Kullanıcının açık yayın kararı; ancak bundan sonra ayrı onaylı canary ve düşük limitli izleme planı. İlk 24 saat ve 7 gün günlük muhasebe uzlaştırması, limit artışı için ölçütler.

Her release gate aynı release kimliğine bağlı olmalıdır. **Bilinmiyor, atlandı veya eski SHA'da geçti: release için tamamlandı değildir.**

## 5. Güvenlik işlerince ertelenen ürün/mimari backlog

Önceki roadmap'in uzun vadeli hedefleri kaybolmasın diye burada tutulur; var olan model/scaffold, tamamlanmış production özelliği sayılmaz:

- Proof-v2 ile matching/ordering adaletinin kanıt kapsamı; native determinism testinden farklıdır.
- Gerçek attested confidential prover ve gateway custody/oracle yetkilerinin ayrıştırılması.
- Private bridge/Aztec/DA entegrasyonu; ekonomik ve gizlilik tehdit modeliyle ayrı değerlendirme.
- Committee-of-enclaves, gerçek dağıtık key generation, quorum'un sequencer yoluna bağlanması ve provider çeşitliliği.

Bu işler S1–S7'nin veya hesap/fon güvenliğinin yerine geçmez.

## 6. Değişmeyecek çalışma kuralları

**Otomatik merge/auto-merge, deployment, canlı zincir işlemi veya güvenlik/onay denetimi aşma yok.** Çalışan kullanıcının worktree'si korunur; her kod düzeltmesi taze main'den izole dalda hazırlanır. Hata testini silmek, fuzz kapsamını azaltmak, `continue-on-error` eklemek veya snapshot'ı sıfırlamak düzeltme sayılmaz.

Her dar iş paketinin raporu şu bilgileri taşır: base/head SHA, değişen dosyalar, somut bulgu veya “bulunmadı” kanıtı, komut/exit kodu/test seçimi, mock ve skipped sınırları, CI run/job kimlikleri, kalan riskler ve sonraki tek iş. Toplam audit ilerlemesine uydurma yüzde verilmez.

Kimi MCP kullanılacaksa önce araçları keşfet ve mevcut görevleri kontrol et. Kabul edilmiş `job_id` yoksa görev başladı denmez. Mac/tunnel sağlığına dair kullanıcı bildirimi ile ChatGPT connector erişimi ayrı gözlemlerdir; sandbox DNS sorunu Mac arızası olarak raporlanmaz. Ajan çıktısı exact diff ve aynı head kanıtıyla bağımsız kontrol edilir.
