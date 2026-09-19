# Yeni oturum başlangıcı: dark-perp audit devamı

> **S1 devamı (19 Eylül 2026):** PR #14 `f997f8b` ile birleşti, ancak S1'i
> kapatmadı. HTTP ACK/rotation ve WS check/send/idle eksikleri bağımsız testlerle
> yeniden üretildi. [Devam raporu](audits/2026-09-19-s1-fence-followup.md) ve
> [kaynak-bağlı kanıt](audits/2026-09-19-s1-fence-evidence.json) esas alınmalıdır.
> Final-head CI ve kalan S1 matrisi henüz kapanış kanıtı değildir; S2'ye geçmeyin.

**Tarih:** 19 Eylül 2026. **Tek güncel plan:** [ROADMAP.md](ROADMAP.md).

**Tam codebase audit'i bitmedi. Gerçek SP1 ELF/vkey/proof/deployment doğrulaması yapılmadı.** Bu handoff belge güncellemesidir; yeni recovery/WS/frontend/snapshot düzeltmesi yapıldığı anlamına gelmez.

## Son doğrulanmış durum

- Repository: `Kubudak90/dark-perp`.
- Main: `b3372caef14ff847f57e949dc3ccf2df30759350`.
- PR #12 merged; son head `c633c642dc5d1deb125bbbd8b1c7e9eff4b04839`.
- PR #12 dalı: `fix/a07-recovery-ui-hotfix-2026-09-19`.
- PR #11 merged. PR #10 Solana deneyi kapalı/unmerged; audit kapsamına dahil etme.
- Main CI `35441756911`: completed/success, dört iş başarılı.
- PR #12 head CI `35437539311`, A07 `35437539277`, A01 `35437539274`: completed/success.
- Bunlar bu kaynakların yeniden okunmuş CI kayıtlarıdır, yeni head'in başarı kanıtı değildir. Güncel durum ve loglar tekrar okunmalıdır.
- Main prover işi `105893659414`: `SP1_SKIP_PROGRAM_BUILD=true` + stub ELF + typecheck; gerçek proof değil.

Bu belgeyi taşıyan dal: `docs/audit-roadmap-handoff-2026-09-19`. Belge PR'ı henüz main'e alınmadıysa dokümanları bu daldan oku; **kod düzeltmesinin tabanını yine taze doğrulanmış main'den seç**. Belge PR'ını veya başka bir PR'ı kendin merge etme.

## Önce okunacaklar

1. Bu dosya ve [ROADMAP.md](ROADMAP.md).
2. [Gözlem kaydı](audits/2026-09-19-roadmap-evidence.json).
3. [İlk audit](audits/2026-09-17-continuation.md) ve [ilk remediation](audits/2026-09-17-remediation.md).
4. [A04 raporu](audits/2026-09-18-a04-cancellation.md), [A04 kanıtı](audits/2026-09-18-a04-verification.json).
5. [A01 raporu](audits/2026-09-18-a01-ingestion.md), [A01 kanıtı](audits/2026-09-18-a01-verification.json).
6. [A06 raporu](audits/2026-09-18-a06-close-only.md), [A11 sınırları](audits/2026-09-18-a11-release-evidence.md), güncel PR #6/#8/#11/#12 açıklamaları ve gereken diff'ler.

Tarihli rapordaki “açık”, “CI sürüyor” veya test toplamını güncel durum diye kopyalama. PR #12'nin heading, V7/V8 migration ve A07/A01 referans taşıma düzeltmelerini kaybetme. Repo talimatlarını da güncel checkout'tan oku.

## İlk dar iş: S1

**Recovery HTTP durability/yetki ve eski authenticated WebSocket oturumlarının iptali.**

Kaynak başlangıcı:

- `crates/gateway/src/main.rs`: recovery HTTP handler'ları, snapshot ACK akışı, authenticated WS handshake/loop/event delivery ve account lookup.
- `crates/gateway/src/account_recovery.rs`, `account_recovery_tests.rs`.
- `crates/gateway/src/snapshot.rs`.
- `crates/gateway/src/deposit_ingestion/tests.rs` ve `execution_regression_tests.rs`.

Başarı yalnız ilgili recovery generation'ını kapsayan dayanıklı ACK'ten sonra dönmeli. Writer yokluğu, hata, timeout, iptal, kayıp HTTP yanıtı, eşzamanlı rotation, stale signature ve güvenli yeniden deneme birlikte incelenmeli. In-memory mutation ile durable mutation aynı kabul edilmemeli; bilinmeyen sonuç nonce/state sıfırlanarak örtülmemeli.

Eski key ile daha önce açılmış WS oturumları, rotation sonrası özel veri alamamalı veya komut çalıştıramamalı. Owner değişmediği için yalnız owner filtresi kontrolünü yeterli sayma. Kuyruktaki olaylar, command execution, idle session ve reconnect yollarını gerçek route/WS testleriyle incele.

Deposit permit ve credited receipt içindeki key referansları aynı hesap rotation'ıyla taşınmaya devam etmeli; owner/payer/market/purpose/event/prefix ve native replay değişmemeli. Yeni bug yoksa bunu kanıtıyla yaz; sırf PR çıkarmak için refactor yapma.

## S1'den sonra sırayla

**S2:** frontend credential storage, pending/failed recovery ve eşzamanlı account/register/refresh/çok-sekme yarışları.

**S3:** V8 snapshot extension framing/ayrıştırması; authenticated version, V5/V6/V7 göçü, truncation/duplicate/orphan/downgrade ve replay.

**S4:** core/matcher/sequencer/prover/contracts/oracle/attestation/archive/CI bütünü. Dar PR'lar; her katman için coverage ve kabul ölçütleri ROADMAP'te.

**S5–S7:** gerçek SP1 source→ELF→vkey→proof zinciri, deployment eşleşmesi, fiziksel/operasyonel provalar ve bağımsız review. Bunlar yapılmış değildir; canlı eylemler için ayrıca açık yetki gerekir.

## Araç ve iş teslimi

Önceki oturumda GitHub connector okuma çalıştı; Kimi araçları `kimi-bridge` / `kimi-mcp` keşfinde görünmedi. **Kabul edilmiş audit-devam `job_id` ve doğrulanmış yeni ajan sonucu yok.** Kabul yanıtı olmayan eski submit girişimini tamamlanmış iş sayma; yeni submit öncesi erişilebilen görev listesini kontrol et.

Kullanıcı Mac'te tunnel'ın live/ready, bridge'in 0.2.0 ve 10 araçlı, GitHub DNS/HTTP'nin sağlam olduğunu bildirdi. Bu kullanıcı bildirimi ChatGPT'den bağımsız doğrulanmış MCP erişimi değildir. `127.0.0.1:8766` Mac'in yerel izleme adresidir; ChatGPT sandbox'ının loopback'i değildir. Eski sandbox DNS hatasını Mac arızası diye yorumlama.

Kimi erişilebilir olursa gerçek şemasına göre `repo=Kubudak90/dark-perp`, `base=main` ile S1'i, izole worktree ve dar draft PR koşuluyla devret. Repo/branch/izin kısıtlarını genişletme, onay etkileşimlerini kullanıcı yerine kabul etme. Dönen job ID'yi bildir; diff'i ve exact head CI/test kanıtını bağımsız incele. Connector yoksa kısa gerçek engel bildir, görev/başarı uydurma.

## Yeni sohbete doğrudan verilecek görev

```text
Kubudak90/dark-perp güvenlik audit'ine devam et.
Önce GitHub'dan güncel main'i, PR #12 ve açık PR'ların gerçek head/merge durumunu,
seçilen head'e ait workflow run/job/loglarını oku. Tarihsel başarıyı yeni head'e taşıma.

Önce docs/AUDIT_HANDOFF.md ve docs/ROADMAP.md oku. Bu dokümanların PR'ı main'e
alınmadıysa docs/audit-roadmap-handoff-2026-09-19 dalından oku, fakat uygulama
çalışmasını güncel doğrulanmış main'den başlat. Son bilinen main b3372ca, PR #12
merged ve son head c633c642; bunları varsayım değil yeniden kontrol edilecek kayıt say.

İlk iş yalnız S1: recovery HTTP durability/yetki ve eski authenticated WebSocket
oturumlarının rotation sonrası iptali. Somut bugları yeniden üret, dar düzeltme ve
regresyon testleri ekle. PR #12'nin A07/A01 permit/credited receipt key taşımasını,
V7/V8 migration testlerini ve owner/deposit-prefix/replay invariants'ını koru.

Yerel veya Kimi ajanı kullanılacaksa önce mevcut görevleri ve worktree durumunu kontrol et;
izole dal kullan, kabul edilmiş job_id olmadan görev başladı deme. Ajan çıktısını bağımsız
incele. Focused testlerden sonra ilgili full CI'ı aynı head üzerinde doğrula. Her komutun
exit kodunu, mocked/ignored/skipped kapsamı ve run/job/head kimliklerini kaydet.

Sonraki sıra: S2 frontend credential storage/concurrent account refresh; S3 V8 extension
framing; ardından core/matcher/sequencer/prover/contracts/CI bütünlüğü.

**S1 ilerlemesi (19 Eylül 2026, bu dal):** recovery HTTP durability wedge (post-mutation ACK
hatasında kalıcı kilitlenme) ve rotation sonrası eski WS oturumlarının iptali düzeltildi;
gerçek route/WS regresyon testleri eklendi. Rapor: `docs/audits/2026-09-19-s1-recovery-ws.md`,
kanıt: `docs/audits/2026-09-19-s1-recovery-ws-evidence.json`.
Tam codebase audit'i bitmedi. Gerçek SP1 ELF/vkey/proof/deployment doğrulaması yapılmadı.
Stub typecheck veya eski deployment kaydı gerçek proof/release kanıtı değildir.

Merge, auto-merge, deployment, canlı zincir işlemi, ücretli network proving veya
herhangi bir güvenlik/onay denetimi aşma yapma. Workflow'u tetiklemeden önce eylem
kapsamını incele. Yalnız gerçek sonuçları ve gerçek engelleri kısa Türkçe bildir.
```
