# Arcora — merge sonrası devam

**PR #23 merge edildi:** `f866a94d383d507d0993bc00403f27bbdb25f192`. Merge edilen head üzerinde 13 kontrol başarılı, RSA advisory kontrolü başarısızdı; bu durum saklanmadan merge edildi. Bu devam çalışması RSA bağımlılığını kaldırıyor, settlement kurtarmasına ikinci RPC doğrulaması ekliyor ve SP1 6.1.0 üzerinde normal guest kanıtını yeniliyor.

**Kalan özgün iş sayısı 7 → 7.** Bu tur yeni bir özgün görev kapatılmadı veya eklenmedi. Başlangıçtaki 15 işten toplam 8 kapalı, 2 kısmi ve 5 engelli. [Kalan işler](remaining-work.md), [özgün kriterler ve bağımlılıklar](task-status.json). Production kararı **HOLD**.

Kaynak commit'i `31f626529b655a6ee14a400f587fbfa3f78661a0`; 677 kaynak/config/lock/vendor dosyasının içerik SHA-256'sı `c2fd3dcf6f0f6afb9d9528a6ca218be34284dba1ba4b2d0b9aaf9dcfc69be6d2`. [Kaynak doğrulaması](source-validation.json), [release kimliği](release-manifest.json).

## Tamamlanan alt kapsam

- **RSA kaldırıldı.** Azure vTPM ve DCAP ring kullanıyor. Gerçek Intel/Azure fixture'ları, bozuk mesaj/imza, zayıf/geçersiz anahtar ve TPM zarfı negatifleri geçti. Cargo'nun kullanılmayan weak optional dependency lock davranışı için yalnız vendored manifest düzeltildi; 20 Rust dosyası ve lisans upstream ile aynı. Alternatif rustcrypto seçeneği hâlâ RSA'yı görünür biçimde çözüyor. [Kanıt ve uyarılar](rsa/README.md).
- **Settlement kurtarması ikinci RPC ile doğrulanıyor.** Opsiyonel `L1_RPC_WITNESS`, başlangıç chain kimliğini ve aynı finalized/canonical hash üzerindeki batch/root/bond değerlerini gerektiriyor. Uyuşmazlık veya erişim hatası kurtarmayı durduruyor; endpoint bilgileri hata metnine taşınmıyor. Bu yalnız settlement recovery kapsamıdır. [Kullanım ve sınırlar](../../L1_RPC_WITNESS.md).
- **SP1 6.1.0'a geçildi.** Önceki 6.0.0, resmi [recursion soundness duyurusundan](https://github.com/succinctlabs/sp1/security/advisories/GHSA-63x8-x938-vx33) etkileniyordu. Guest/host/prover ve transitive SP1/slop ailesi birlikte 6.1.0'a sabitlendi. CI, eski/karışık sürüm ailesini reddediyor ve beş uygulama lock dosyasını audit ediyor.
- **Normal guest doğrulaması yenilendi.** Aynı 956 bayt witness native ve gerçek guest'e verildi; 32 bayt commitment eşit. İki gerçek guest negatifi beklenen hatayla, public çıktı üretmeden reddedildi. [Yürütme kaydı](normal/README.md). A06 guest ve gerçek Groth16 çalıştırılmadı.
- **ELF/vkey kimliği yenilendi.** Boş, ayrı target dizinindeki ikinci build aynı 515.336 bayt ELF'i üretti. Vkey setup ile yeniden hesaplandı. Prover-service'in eski cache ELF'ine işaret eden ilk çalışması kabul edilmedi; doğru ELF ile yeniden derleme ve 8 test geçti. [ELF bağı](rsa/prover-elf-binding.json).

## Doğrulama

| Kontrol | Sonuç |
|---|---|
| Workspace | 789 test geçti; normal koşuda 4 özel ignored test |
| Gerçek cast/loopback | 2 yeni witness matris testi ve 1 deposit RPC testi ayrıca geçti; diğer ignored test SIGKILL üst testlerinin çağırdığı worker |
| Attestation | Gerçek fixture ve negatifler dahil 39 test geçti |
| Host | 5 birim testi; gerçek normal guest pozitif + 2 negatif; setup-only vkey |
| Prover-service | Yeni ELF ile 8 test geçti; özel worker SIGTERM üst testince çağrıldı |
| Sürüm/vendor guard | 5 regresyon, 104 SP1/slop lock girdisi ve 29 upstream dosya kontrolü geçti |
| Statik/consumer | Workspace fmt ve clippy (-D warnings), TEE consumer check geçti |
| Audit | 5 lock dosyasında 0 vulnerability-category bulgusu, boş ignore listesi; diğer uyarılar açık |

Test sırasında yalnız iki kullanım dokümanı eklendi; erken guest build sonrasında host helper'ları tamamlandı. İlgili input kümeleri değişmedi; son guest/vkey/prover/runtime kontrolleri birleşik kaynakla eşleşiyor. [13 kontrolün source/hash uzlaştırması](source-validation.json), [Graph raporu](report.json), [inceleme](review.md).

SP1'in `lru 0.12.5` bağımlılığındaki iki unsoundness uyarısı açık. Sıfır vulnerability-category bulgusu, bütün güvenlik risklerinin kapandığı anlamına gelmiyor. Gerçek proof/target verifier, A06 phase 1/2, tam test-token fon akışı, birleşik crash/reorg matrisi, canlı deployment/operasyon ve dış inceleme gereklilikleri sürüyor. Önceki A06 otomatik inceleme engeli aşılmaya çalışılmadı.

Desktop checkout'un HEAD'i, 62 dosya hash'i ve NUL-ayrımlı Git durumu korunuyor. [Koruma kaydı](desktop-preserved.json). Canlı fon işlemi, deployment, ücretli/uzak prover veya dış kişiye mesaj yok. Yeni PR incelemeye hazırlanır; PR23 merge yetkisi yeni PR için tekrar kullanılmış sayılmaz.
