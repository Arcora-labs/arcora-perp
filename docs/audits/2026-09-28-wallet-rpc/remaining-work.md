# Arcora — kalan 7 özgün iş

**Önceki tur 11 → bu tur kapanan 4 → kalan 7: 2 kısmi, 5 engelli. Başlangıçtaki15 işten toplam 8 kapandı.** Bu tur S2-01, S2-02, S2-03, S2-04 kapandı. [Kanıt](README.md), [özgün kriter/dependency kaydı](task-status.json). Production kararı HOLD; PR23 inceleme için açık.

| Görev | Durum | Kalan özgün koşul |
|---|---|---|
| S5-02 — Native/guest byte eşliği | Engelli | Normal ve A06 phase 1/2 ortak witness, byte eşliği ve guest negatifleri. Önceki kayıttaki A06 otomatik inceleme engeli bu tur yeniden denenmedi. |
| S5-03 — Gerçek proof ve verifier | Engelli | S5-02 sonrası gerçek proof, verifier kabul/negatifleri ve vkey/hash zinciri. Proving ortamının güncel erişimi bu tur sınanmadı; eski Docker sonucu güncelmiş gibi kullanılmadı. |
| S6-01 — Tam fon akışı ve acil çıkış | Engelli | S2-03 artık kapalı. S5-03 ardından izole Anvil gerçek test-token deposit→trade/cancel→proof settlement→withdraw/claim ve CloseOnly/finalExit muhasebesi. |
| S6-02 — Fon akışında crash/restore | Kısmi | Önceki21 gerçek SIGKILL/journal vakası korunur. S6-01 tam fon akışındaki ACK/recovery/deposit/cancel/settlement sınırlarını birlikte sınamak gerekiyor. |
| S6-03 — RPC/finality/reorg/deployment | Kısmi | Audit okuyucusunun ikinci RPC anlaşmazlık kontrolü tamamlandı. Runtime gateway quorum, birleşik fon/reorg matrisi ve source-bytecode eşliği açık. 28 Eylül 12:44:39 UTC yapılandırılmış public RPC sorgusu HTTP 403; başarılı canlı deployment gözlemi yok. |
| S7-01 — Olay sahipleri, alarm, runbook | Engelli | Gerçek sorumlular/escalation hedefleri, alarm teslimi ve bağımsız restore/CloseOnly provası; S6-02/S6-03. |
| S7-02 — Dış inceleme ve yayın | Engelli | Bağımsız dış inceleme, açık risk kararı, proof/fon/operasyon/deployment kanıtı ve yayın kararı. RSA 0.9.10/RUSTSEC-2023-0071 bulgusu bu tur çözülmedi veya bastırılmadı. |

Özgün kriter metinleri ve bağımlılıklar değişmedi. S2-03 için önceki turda tamamlanan deposit mutation matrisi yeniden geçti; bu tur gerçek cüzdan bağımlılığı kalktı. S2-02/S2-04 için depolama/legacy/CSP kontrolleri gerçek eklentiyle de çalıştı. Dört yeni ürün özelliği yazıldığı iddia edilmiyor; dört açık doğrulama başlığı tamamlandı.

Önceki rapordaki [ek kullanılabilirlik/operasyon işleri](../2026-09-28-resolution/remaining-work.md#sonradan-bulunan-ek-işler--11-özgün-işin-sayısına-eklenmedi) ayrı listede korunur. Hash'siz unknown transaction eşleme, non-landing uzlaştırması, kalıcı prover sonucu, production kapasite ve bağımsız temiz-container yeniden üretimi bu 7 özgün işin sayısına eklenmedi.
