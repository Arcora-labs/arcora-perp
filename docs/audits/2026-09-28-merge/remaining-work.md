# Arcora — birleştirme sonrası kalan iş planı

**15 üst görev açık: 10 kısmi, 5 engelli. Yayın kararı HOLD.** Kullanıcının kod birleştirme yetkisi production deploy veya yayın onayı değildir; birleştirme bu görevlerin kabul koşullarını kendiliğinden kapatmaz. Birleştirilen kodun kapsamı ve son kontroller [birleştirme kaydında](README.md); aşağıdaki maddeler production kabulü için açık kalır.

Önce yerelde ilerletilebilen settlement/prover/restart senaryolarını aynı akışta birleştirin. Paralelde gerçek extension cüzdanlı test profili, erişilebilir salt-okunur RPC ve olay sahibi/reviewer erişimini hazırlayın. Gerçek proof ve tam fon döngüsü, A06 inceleme kapısı ve proving altyapısı açıldıktan sonra izole test ortamında ilerlemelidir.

## Korunan yerel kanıt

- Gateway **401 geçti / 2 ignored**; gerçek `cast` taşıma testi ayrıca **1/1 geçti**. Diğer ignored test 21 SIGKILL vakasında kullanılan çocuk fixture'ıdır. [Gateway](../2026-09-28-runtime/checks/gateway.json), [cast](../2026-09-28-runtime/checks/cast-loopback.json).
- Snapshot/journal için **21 gerçek SIGKILL**; gateway SIGTERM için **3 senaryo / 4 sahip olunan süreç, hepsi exit 0**. [Kesinti matrisi](../2026-09-28-runtime/crash-matrix.md), [gateway süreçleri](../2026-09-28-runtime/gateway-process/result.json).
- Prover **8 geçti**: kabul edilmiş worker, HTTP istemcisi kopsa da runtime kapanmadan tamamlanıyor. [Kanıt ve sınır](../2026-09-28-runtime/prover-shutdown.md).
- Frontend **396 geçti / 1 canlı-gateway testi atlandı**, Chromium/WebKit **72 geçti**. Son tek satırlık dar ekran düzeltmesi ayrıca **24 bileşen testi**, 320/390 pikselde görsel kontrol ve build ile doğrulandı. [Komutlar ve kaynak ayrımı](../2026-09-28-runtime/reconciliation-checks.json).

Bu sayılar birleştirme öncesi runtime kayıtlarının kapsamıdır. Merge için gereken son kontrol ve kaynak eşlemesi ayrıca korunmalıdır; eski loglar yeni kaynakta tekrar çalışmış gibi sunulmamalıdır. [Kaynak manifesti](../2026-09-28-runtime/source-manifest.json), [kanıt eşlemesi](../2026-09-28-runtime/source-validation.json), [ayrıntılı durum](../2026-09-28-runtime/remaining-status.md).

## 15 görev ve somut sonraki adım

| Görev | Durum | Sonraki adım / kapanış koşulu |
|---|---|---|
| **S2-01 — İki sekme ve kurtarma** | Kısmi | Ayrı profilde gerçek extension cüzdanını Rust gateway HTTP/WS'ye bağlayıp iki sekme, imza reddi, rotation ve reload matrisini kaydet. Mevcut gerçek Chromium→Rust bağlantısı sentetik imza sağlayıcısı kullanır; WebKit, Safari değildir. |
| **S2-02 — Legacy / session-only** | Kısmi | S2-01 ortamında legacy kayıt, yanlış deployment ve storage yazma hatasını tekrarla; ikinci recovery reddinde uyarı/kayıt korunumunu ve reload'u doğrula. Session-only erişimi kalıcı saklama sayma. |
| **S2-03 — Deposit / mutation yarışları** | Kısmi | Gerçek test cüzdanı, token, RPC ve gateway ile deposit'i uzlaştır. Hash'siz unknown işlem için from/to/chain/input/value doğrulayan keşif tasarımı, reverted işlem için açık çözüm akışı gerekli. Mevcut UI yalnız özgün bilinen hash'i sorgular; yeni send veya kayıt silme ile belirsizlik çözülmez. |
| **S2-04 — CSP / saklama** | Kısmi | Hedef ortamla eşdeğer CSP/header altında gerçek extension bağlantı, imza, recovery ve WS'yi çalıştır; secret içermeyen ihlal raporlarını kaydet. Production header'ları ve aynı-origin JavaScript/localStorage güven sınırı açık; S2-02 bağımlılığı sürüyor. |
| **S4-03 — Finality / journal** | Kısmi | Nonce/tx-hash ve tutarlı finality gözlemini gerçek yerel transaction yaşam döngüsüne bağla; geç pending sonuç, rollback/roll-forward ve withdrawal root eşliğini aynı kesinti matrisinde doğrula. Kesin non-landing kanıtı yokken prepared journal korunmalı ve retry kapalı kalmalı. |
| **S4-05 — Prover taşıması** | Kısmi | S4-03 ile restart, session expiry, retry, batch/previous-root/phase retlerini birleştir; proof öncesi SETTLED/claimable olmadığını doğrula. Kopmuş istemci için kalıcı sonuç alma ve takılmış gerçek backend'in çözümü ayrıca tasarlanmalı. |
| **S4-07 — HTTP/WS / kapanış** | Kısmi | Gerçek uzun proof/settlement sırasında drain'i ölç; pre-upgrade TCP/HTTP idle sınırları, IP adaleti ve kapasite sınamalarını tamamla. Geçen sentetik shutdown, takılmış backend'i güvenle zorla sonlandırmayı veya production kapasitesini kanıtlamaz. |
| **S5-01 — Release kaynağı / ELF** | Kısmi | Üst kapılar sonrası release SHA/toolchain'i seç; bütün artefaktları bu kimliğe bağla ve bağımsız temiz container'da ELF yeniden üretimini doğrula. Mevcut hash/cache eşliği bağımsız üretim veya proof değildir. |
| **S5-02 — Native / guest eşitliği** | **Engelli** | A06 otomatik güvenlik incelemesinin **BLOCKED** kararını desteklenen inceleme sürecinde çöz. Kapı açılmadan prompt değiştirerek yeniden yürütme yapılmamalı. Ardından normal + phase 1/2 ortak witness, byte-exact çıktı ve gerçek guest negatiflerini kaydet. |
| **S5-03 — Gerçek proof / verifier** | **Engelli** | S5-02 sonrasında yerel proving altyapısını doğrula; gerçek proof ve hedef verifier kabulü, yanlış vkey/input/proof retleri, source→ELF→vkey→witness→proof hash zincirini tamamla. Son ortam kontrolünde Docker daemon erişilemiyordu; servis testi gerçek proof değildir. |
| **S6-01 — Fon döngüsü / acil çıkış** | **Engelli** | S5-03 + S2-03 sonrası izole Anvil'de test-token deposit→finalized ingest→trade/cancel→gerçek proof settlement→withdraw/claim ve CloseOnly/finalExit çalıştır. Her adımda gateway–engine–vault muhasebesi, duplicate/proof retleri ve token bakiye farkları uyuşmalı. |
| **S6-02 — Disk / kill / restore** | Kısmi | Mevcut 21 dosya sınırı vakasını recovery/deposit/cancel/settlement ACK ve fon sınırlarıyla birleştir; restart'ta eski key, çift kredi/claim ve root sürekliliğini karşılaştır. S6-01 açık; syscall içi kesinti, disk arızası/farklı dosya sistemleri ve güç kesintisi kanıtlanmadı. |
| **S6-03 — RPC / deployment eşliği** | Kısmi | Yerelde bağımsız RPC disagreement/quorum ve birleşik reorg/finality/fon matrisini tamamla. Erişilebilir salt-okunur endpoint'ten chain/block/code/rol/vault/verifier/vkey manifestini doğrula. Son Base Sepolia sorgusu **HTTP 403**; repo deployment JSON'u güncel zincir kanıtı değildir. |
| **S7-01 — Olay sahipleri / runbook** | **Engelli** | Gerçek sorumlular ve escalation hedeflerini belirle; snapshot failure, stale oracle ve prover stop ile alarm teslimini ölç. Runbook'u yazmayan kişi restore/CloseOnly provası yapmalı; S6-02/S6-03 açık. Olay sahibi veya teslim edilmiş alarm varsayılmamalı. |
| **S7-02 — Dış inceleme / yayın** | **Engelli** | Bağımsız dış reviewer'a tek release kaynağına bağlı kanıt paketini ver; proof/fon/operasyon kapıları ve **rsa 0.9.10 / RUSTSEC-2023-0071** kararını tamamla. Sonrasında açık yayın kararı al. Dar yerel inceleme, yeşil testler veya merge yayın onayı değildir. |

Yerel incelemede bulunan cross-gateway Resume, bozuk journal, eksik receipt hash'i ve status-only kayıt oluşturma hataları düzeltildi; prover'ın iptal edilmiş HTTP sonrası erken runtime kapanışı testle kapandı. Bunlar tam dış denetim kapsamına genişletilmez. [Deposit incelemesi](../2026-09-28-runtime/reconciliation-review.md), [prover incelemesi](../2026-09-28-runtime/prover-shutdown.md).

Bu kanıt turunda deploy, canlı zincir mutasyonu, gerçek wallet transferi, engelli A06 guest doğrulaması/gerçek proof yürütmesi veya ücretli/uzak prover kullanımı yapılmadı. Gerçek extension, proving altyapısı, canlı RPC eşliği, olay sahibi ve dış reviewer birbirinden ayrı kapılardır. Kod birleştirilse de bu koşullar sağlanmadan **yayın HOLD** kalır.
