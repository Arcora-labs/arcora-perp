> Bu rapor önceki 11-iş durumunu korur. Güncel rapor: [7 kalan iş](../2026-09-28-wallet-rpc/remaining-work.md).

# Arcora — güncel kalan 11 özgün iş

**Başlangıç 15 → kapanan 4 → kalan 11: 6 kısmi, 5 engelli.** S4-03, S4-05, S4-07 ve S5-01 kapandı. [Kapanış kanıtı](README.md), [özgün kriterleri koruyan makine kaydı](task-status.json). Production yayın kararı HOLD.

| Özgün görev | Durum | Kalan özgün koşul / sonraki adım |
|---|---|---|
| **S2-01 — Gerçek tarayıcıda iki sekme ve kurtarma** | Kısmi | Gerçek extension cüzdanıyla recovery/imza reddi/rotation/reload matrisi. Chromium→Rust ve kontrollü iki sekme kayıtları ayrı kapsamlarında geçti. |
| **S2-02 — Eski hesap geçişi ve session-only UX** | Kısmi | S2-01 gerçek cüzdan bağımlılığı; kısıtlı storage, legacy/yanlış deployment ve session-only reload doğrulaması. Yerel kabul kontrolleri geçti. |
| **S2-03 — Emir, çekim ve piyasa seçimi yarışları** | Kısmi | Deposit dahil immutable mutation matrisi artık geçti. Özgün S2-01 gerçek cüzdan bağımlılığı açık. Hash'siz unknown işlemler duplicate göndermeden korunuyor. |
| **S2-04 — XSS, CSP ve credential saklama** | Kısmi | Hedefe eşdeğer CSP altında gerçek extension wallet bağlantı/imza/recovery/WS uyumu; S2-02. Yerel fixture CSP sonucu production uyumu sayılmaz. |
| **S5-02 — Native/guest byte-exact eşitliği** | Engelli | S5-01/S4-03 artık açık bağımlılık değil. Kayıtlı A06 otomatik inceleme engeli sürüyor; normal ve phase 1/2 ortak witness, byte eşliği ve guest negatifleri tamamlanmalı. |
| **S5-03 — Vkey, gerçek proof ve verifier** | Engelli | S5-02 sonrası gerçek proof üretimi ve verifier kabul/negatifleri; tam hash zinciri. Bu tur proving ortamı açılmadı; önceki daemon erişimsizliği güncel erişim iddiası değildir. |
| **S6-01 — Yerel tam fon akışı ve acil çıkış** | Engelli | S5-03 + S2-03; izole Anvil'de gerçek test-token deposit→trade/cancel→proof settlement→withdraw/claim ve CloseOnly/finalExit muhasebesi. |
| **S6-02 — Disk hatası, process kill ve restore** | Kısmi | 21 dosya/journal SIGKILL vakası geçti. S6-01 tam fon akışının ACK/recovery/deposit/cancel/settlement sınırlarına bağlanan crash/restart uzlaşması hâlâ açık. |
| **S6-03 — RPC/finality/reorg ve deployment** | Kısmi | Sabit finalized hash okuması geçti. Bağımsız RPC anlaşmazlık politikası, birleşik fon/reorg matrisi ve S6-01 bağımlılığı açık. Son kayıtlı canlı salt-okunur sorgu 403; yeni canlı eşleşme gözlemi yapılmadı. |
| **S7-01 — Anahtarlar, gözlem ve olay runbook'ları** | Engelli | Gerçek olay sahipleri/escalation hedefleri, alarm teslimi ve bağımsız restore/CloseOnly provası; S6-02/S6-03. |
| **S7-02 — Bağımsız inceleme ve yayın kararı** | Engelli | Dış inceleme, açık risk kararı, bütün release/deployment kanıtı ve ayrı yayın kararı. Yerel adayın belirlenmesi, RSA 0.9.10 bulgusunu veya proof/fon/operasyon kapılarını kapatmaz. |

## Sonradan bulunan ek işler — 11 özgün işin sayısına eklenmedi

- **Tamamlandı:** bilinen hash'li, kesinleşmiş revert için kayıt koruyan ve yalnız açık Resume ile yeniden gönderen çözüm.
- **Açık:** hash'siz unknown wallet gönderimini güvenilir transaction kimliğine eşleme. Veri silmek veya otomatik yeni transfer çözüm sayılmaz.
- **Açık:** kanıtlanmış non-landing için nonce/tx-hash uzlaştırması ve kullanılabilirlik iyileştirmesi. Mevcut belirsiz prepared kaydı tutma davranışı özgün S4-03 güvenlik koşulunu karşılar.
- **Açık:** kopmuş prover istemcisi için kalıcı sonuç alma; takılmış backend için güvenli operasyonel çözüm.
- **Açık:** pre-header TCP idle sınırları, IP adaleti ve production kapasite ölçümü.
- **Açık kanıt sınırı:** bağımsız temiz container ELF yeniden üretimi. Özgün S5-01 aynı makine/cache tekrar üretimi sınırını açıkça kabul ediyordu; bu nedenle geriye dönük yeni kapanış koşulu yapılmadı.

En yakın bağımlılık açıcı iş, ayrı test profiliyle gerçek extension cüzdanı matrisidir: S2-01 kapanınca S2-02/S2-03/S2-04'ün kalan koşulları aynı ortamda tamamlanabilir. Proving/A06 inceleme yolu, fon testleri ve olay/dış reviewer işleri ayrı engeller taşır.
