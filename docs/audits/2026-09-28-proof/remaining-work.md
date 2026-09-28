# Arcora — kalan 7 özgün iş

**Önceki tur 7 → bu tur tam kapanan 0 → kalan 7. Başlangıçtaki 15 işten toplam 8 kapalı.** Kriterler ve bağımlılıklar değişmedi. Yeni bulgular mevcut işlerin içinde izleniyor.

Bu tur iki LRU unsoundness bildirimi giderildi; gerçek SP1 verifier/gateway/adapter test yolu kuruldu. Normal proof gerçekten denendi, ancak son Docker/Groth16 adımı bu denemeye ayrılan 5 GiB bellek sınırında OOM/137 ile durdu. Tamamlanmış proof veya onun EVM kabulü yok.

| İş | Durum | Kalan özgün koşul / ilerleme |
|---|---|---|
| S5-02 — Native / guest byte-exact eşitliği | Engelli | Normal parity kanıtı korunuyor. A06 üzerinde çalışan ajanın eski içerik sınıflandırması engeli açıklığa kavuşturuldu; A06 phase 1/2 doğrulaması yeniden denenmedi. |
| S5-03 — Vkey, gerçek proof ve verifier doğrulaması | Engelli | SP1/LRU düzeltmesi ve gerçek verifier yolu hazır. Gerçek normal proof denemesi son Docker/Groth16 aşamasında 5 GiB limitinde OOM/137 ile durdu; tamamlanmış proof, SDK kabulü veya uygulama proof'u için EVM pozitif sonucu yok. Yeterli proving belleği ve S5-02 bağımlılığı açık. |
| S6-01 — Yerel tam fon akışı ve acil çıkış | Engelli | Gerçek yerel test-token deposit→trade/cancel→proof settlement→withdraw/claim ve acil çıkış muhasebesi açık; sentetik normal witness bu akışı tamamlamıyor. |
| S6-02 — Disk hatası, process kill ve restore provası | Kısmi | Önceki 21 gerçek SIGKILL vakası korunuyor; tam fon akışındaki kesinti/restore matrisi ve S6-01 bağımlılığı açık. |
| S6-03 — RPC/finality/reorg ve deployment eşlemesi | Kısmi | Önceki finalized recovery/RPC witness kontrolleri korunuyor. Diğer L1 okumaları, birleşik fon/reorg matrisi ve canlı deployment gözlemi açık. |
| S7-01 — Anahtarlar, gözlem ve olay runbook’ları | Engelli | Gerçek olay sahipleri/escalation hedefleri, alarm teslimi ve restore/CloseOnly provası ile S6 bağımlılıkları açık. |
| S7-02 — Bağımsız inceleme ve yayın karar kapısı | Engelli | İki LRU unsoundness bildirimi bastırılmadan kaldırıldı; bağımsız dar kod incelemesi tamamlandı. Dış inceleme, eksiksiz proof/fon/operasyon/deployment kanıtı ve ayrı yayın yetkisi açık. |

Kod ve kanıt: [PR #24](https://github.com/Kubudak90/dark-perp/pull/24), [makine kaydı](task-status.json), [doğrulama özeti](README.md).

Belirlenen bellek engeli 5 GiB denemeye aittir; 16 GiB Mac’in her yapılandırmada imkânsız olduğu iddia edilmez. PK header’ı tek başına 7,46 GiB kalıcı dizi tahsisinin alt sınırını gösterir; R1CS ve diğer çalışma tamponları buna eklenir. Daha geniş proving kapasitesi olmadan aynı deneme tekrarlanmadı.
