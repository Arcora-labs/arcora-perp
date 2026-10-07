# Arcora — 27 Eylül 2026 yerel çalışma sonucu

**Durum: PARTIAL. 27 görevden 12 PASS, 10 PARTIAL, 5 BLOCKED. Yayın kapısı kapalı.** Güncel GitHub `origin/main` çekildi ve rehberin tabanı ile eşleşti: `098e4952c189f92e4293ed7d49f81222b626e406`, tree `c6e9d4af0257531cd77e45ca5b3939c6ea7a0fa4`. Çalışma `audit/arcora-local-20260927` dalında, `<repo>` dizinindedir.

Masaüstündeki asıl checkout'un durumu ve 62 kaydedilmiş dosya hash'i değişmedi. O checkout `f997f8b9` üzerinde bırakıldı; yeni kod ve düzeltmeler ayrı worktree'dedir. İlk yerel değerlendirme sırasında push, PR, merge veya deploy yapılmamıştı. Kullanıcının sonraki merge talebiyle [PR #21](https://github.com/Kubudak90/dark-perp/pull/21) açıldı; birleştirme durumu PR üzerinden doğrulanmalıdır. Yayın kapısı kapalıdır. Base CI run 36337867266'nın dört işi de güncel olarak başarılı gözlendi; bu uzak koşu yerel değişiklikleri kapsamaz.

[Kalan 15 iş — HTML](kalan-isler.html) · [Durumlu çalışma rehberi](arcora-ilerleme.html) · [27 görev ve kabul ölçütleri](task-status.json) · [Son kanıt manifest'i](final-evidence-manifest.json) · [Kaynak parmak izi](source-manifest.json) · [Yayın kararı ve kalanlar](release-decision.md)

## Doğrulama

| Son seçim | Sonuç | Sınır |
|---|---|---|
| Birleşik Rust workspace | 746 geçti, 0 başarısız, 1 varsayılan ignored | Gateway 378 bu toplama dahildir; ayrıca toplanmaz. |
| Gerçek `cast` JSON-RPC testi | 1/1 geçti | Yukarıdaki ignored test ayrıca çalıştırıldı; hedef loopback fixture. |
| Core debug / kontrollü release |Her biri 162 geçti | Örtüşen seçimler; release debug/overflow kontrolleri açık. |
| Foundry | 96 geçti | Verifier testleri mock; gerçek Groth16 kanıtı değildir. |
| Frontend unit | 317 geçti, 1 mevcut HTTP skip | Atlanan HTTP testi ayrıca gerçek yerel gateway ile 1/1 geçti. |
| Chromium + WebKit | 38/38 geçti | Gerçek iki sekme/locks/storage/fetch; kontrollü API/provider yanıtları. Gerçek cüzdan extension'ı değil. |
| Prover-service | 11/11 geçti; gerçek ELF ile typecheck geçti | Session/bearer handler testleri; Groth16 üretimi yok. |
| Rustfmt, Clippy, frontend typecheck/build |Geçti | Son ilgili kaynak üzerinde; derleme testi çalıştırma sayılmaz. |
| Gerçek gateway kill/restore |Geçti | Kendi süreci, geçici demo state, periodic snapshot sonrası SIGKILL; tüm ACK sınırları değil. |

Son çalışma logları `checks/*-integrated.*` içindedir. Önceki başarısız assertion'lar ve kurulum hataları korunur; eski başarılı seçimler yeni test toplamına eklenmez. `finalize_evidence.py` son log hash'lerini, kaynak farklarını, kanıt bağlantılarını ve graph kapısını denetler.

## Yapılan düzeltmeler

- **Recovery ve işlem bağlamı:** Legacy public owner geçiş yolu; withdrawal market/credential sabitleme; eski cancel/list yanıtını reddetme; storage-denied açılış ve ikinci başarısız recovery sırasında session-only uyarısını koruma. Sekiz gerçek tarayıcı hata senaryosu düzeltildi.
- **Snapshot:** Marker araması yerine typed framing; execution/recovery extension'larını mutasyondan önce doğrulama; recovery generation düşmesini reddetme; 64 MiB dosya/payload sınırı. Dört eski writer'ın V5–V8 fixture'ları ve 713 iç / 216 dış mutation vektörü doğrulandı.
- **Gateway/core:** Açık `GATEWAY_BIND_ADDRESS` ile loopback desteği; rebind ve core batch counter taşmalarında mutasyondan önce ret. Diğer teorik window-counter yollarının tamamı kapandı iddiası yok.
- **Settlement journal:** Yapılandırılmış journal yazımı başarısızsa proving/broadcast devam etmiyor. Gerçek ENOTDIR/ENAMETOOLONG dosya hataları önce iki assertion'ı düşürdü; düzeltme sonrası dört kontrol geçti. Kalan crash/chain belirsizlikleri [raporda](rollback_journal/README.md).
- **CI/bağımlılıklar:** A11'in yanlış TEST profile değişkenleri RELEASE'e düzeltildi ve gerçek iki-assertion kontrolü eklendi. Tetikleme ve `--locked` kapsamı düzeltildi; üç SP1 lockfile takip ediliyor. Rustls ve uyumlu frontend geçişli paketler güncellendi; kalan advisories açık kaydedildi.

## Gerçek SP1 ve açık işler

Pinlenmiş SP1 CLI/SDK 6.0.0 ve succinct toolchain ile gerçek RISC-V ELF üretildi. Aynı kaynak/ortamda zorlanmış tekrar build hash'i eşleşti. Normal deposit/withdraw witness'ının native ve guest public commitment'ı eşit çıktı. ELF→vkey bağı [release manifest'inde](protocol/release-manifest.json); gerçek Groth16 proof/receipt yok.

A06 guest doğrulaması alt ajanın otomatik güvenlik incelemesinde “olası siber güvenlik riski” nedeniyle durdu. Bekleyen derleme kapatıldı; doğrulanmamış taslak ayrı tutuldu ve çalıştırılabilir host, önceden geçen normal harness'e geri alındı. Bu dal tamamlandı işaretlenmedi veya başka ajanla yeniden denenmedi.

Gerçek cüzdan, A06/Groth16, gerçek proof ile tam fon akışı, tüm crash sınırları, canlı deployment eşlemesi ve operasyon/reviewer koşulları açık. Base Sepolia'nın public RPC'si salt-okunur gözleme 403 verdi; mevcut code/role/vkey durumu bilinmiyor. Taslak graph ve lane raporları bu engelleri ayrı gösterir.

## Tekrar çalıştırma

Repo kökünde `CARGO_TARGET_DIR=/tmp/arcora-gateway-target cargo test --workspace --locked`; frontend'de `pnpm install --frozen-lockfile`, `pnpm test`, `pnpm build`, `pnpm test:browser`; contracts'ta `forge test -vvv`. Gerçek SP1 için `protocol/sp1-toolchain.json` ve `checks/sp1-host-with-protoc.json` içindeki pinlenmiş PATH/PROTOC kurulumunu kullan; sistem Rust'ı succinct target'ının yerine kullanma.

Gateway'i yalnız temiz test ortamında `GATEWAY_BIND_ADDRESS=127.0.0.1` ile başlat. `scripts/local-verification/smoke_gateway.py` yalnız kendisinin oluşturduğu süreç/geçici state üzerinde çalışır. Graph Engineering uygulandı; Jev değerlendirildi, deterministik yetki/finans/parser yollarına model tabanlı karar eklenmedi.

## Birleştirme öncesi CI düzeltmesi

`ac9db962` üzerindeki ilk GitHub koşusunda gateway 378/378 geçti. Yeni Clippy 1.98, testteki altı byte literalinin eşdeğer byte-string biçimini istedi; uyarı bastırılmadan düzeltildi. `ci-clippy-correction.json` ve `checks/merge-*` kayıtları bu ek değişikliği kapsar. İlk `final-evidence-manifest.json` önceki kaynak anının kanıtıdır; sonraki birleştirme değişikliklerini test etmiş gibi sunulmaz.

GitHub shell varsayılanının pipefail içermediği canlı log ile doğrulandı. A11 audit adımlarına `set -o pipefail` eklendi; RSA advisory kaynaklı hata artık `tee` ile gizlenmez. `ci-pipeline-correction.json` ayrıntıyı kaydeder. Bağımlılık ve yayın engelleri açık kalır.
