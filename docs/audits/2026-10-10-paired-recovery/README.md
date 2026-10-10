# Arcora Perp: eşli snapshot/journal kurtarma raporu

Tarih: 10 Ekim 2026
İşlevsel commit: `27023614509acf5c676433b72f50a46678d76622`
Dal: `fix/paired-recovery-20261010`
PR: #37, hedef main. Production **RELEASE HOLD**.

## Tamamlananlar

Önce bağımsız cold-build paketi #36, 17 başarılı kontrol sonrasında main'e
merge edildi. Merge commit'i `29b9790746890d92b50b94b541bc00789219c301`.
Bu yeni paket snapshot ile rollback journal'ın birlikte seçilmesi ve kurtarma
sırasında deposit cursor/receipt kayıtlarının korunmasına odaklanır.

`DARKPERP_RESTORE_JOURNAL=<64 hex|absent>` eklendi. SHA-256 değeri beklenen journal'ı;
`absent` ise o checkpoint'te journal bulunmaması gerektiğini belirtir. Her ikisi
geçerli snapshot SHA-256 pin'i gerektirir. Eksik, yanlış veya beklenmeyen journal
başlangıcı durdurur. Ayar unset ise legacy keşif korunur; eksik yedek journal'ını
bu modun kendiliğinden saptadığı iddia edilmez.

Hash'i kontrol edilmiş journal baytları mevcut MAC/format decoder'ına doğrudan
verilir, dosya tekrar açılmaz. Çözülememiş journal bellek içinde de takip edilir;
dosyanın sonradan yok olması başarılı kurtarma sayılmaz. Snapshot mutasyonu
kalıcı yazılamazsa journal çözülmüş sayılmaz. Persist-before-delete sırası korunur.
Journal symlink/nonregular girişleri reddedilir; bu bir dosya sistemi sandbox'ı değildir.

## Birleşik durum testi

Gerçek ingestion ve snapshot/journal koduyla üç sentetik deposit oluşturuldu.
Bir deposit ilk pencere mühürlendikten sonra geldi; ilk pencerede imzalı bir
çekimin yaprağı da bulunuyor. Şifreli snapshot/journal çifti taşındı ve şu koşullar
sınandı: belirsiz zincir durumunda HOLD ve sıfır mutasyon; rollback sonrası aynı
çekimin yeniden mühürlenmesi; üç deposit'in birer kez replay edilmesi; roll-forward
sonrasında claim verisinin korunması; tekrar commit'in durumu değiştirmemesi.
Eski deposit sayfası tekrar credit edilemez. Count/tip/anchor, domain ve üç receipt
kaydı korunur. Restore, taze L1 doğrulaması olmadan deposit admission'ı açmaz.

Deposit cursor alanları snapshot içindedir; ayrı taşınacak cursor sidecar'ı yoktur.
Challenge tarama cursor'u kalıcı değildir, restart'ta challenge penceresini geri
tarayarak yeniden kurulur. Uzun kesintide kaçmış deadline'lar kapanmış sayılmaz.

## Platformlar arası kanıt

Açık test fixture'ı asıl ARM64 Mac'te yeni sentetik hesaplardan üretildi; kullanıcı
snapshot'ı, gerçek anahtar veya fon kullanılmadı. Bilinen açık test seed'i kaynakta
bulunur. Aynı snapshot/journal baytları GitHub-hosted x86_64 Linux üzerinde gerçek
serializer, recovery ve replay fonksiyonlarından geçti.

- Run: `38054411406`; iş: `114219817507`, gateway RPC, crash and alert drills.
- İş tamamlandı ve başarılı. Sağlayıcı runner bilgisi GitHub API'den doğrulandı.
- Artifact ZIP indirildi; SHA-256 değeri GitHub API digest'iyle eşleşti.
- Linux checkpoint hash'leri ve doğrulama alanları Mac sonucuyla karşılaştırıldı.
- Synthetic PR merge ağacının işlevsel head ile aynı olduğu ve iki parent'ının
  beklenen main/head olduğu doğrulandı. Ayrıntılar `github-provenance.json` içinde.

Bu sonuç canlı gateway'in, attestation'ın, gerçek anahtar temininin veya L1 bağlantısının
başka makineye taşındığı anlamına gelmez. Fixture'ın zincir gözlemleri ve inner prover'ı
özellikle test girdisi/mock olarak kalır. Yeni gerçek SP1 proof üretilmedi.

## Son doğrulamalar

| Kontrol | Sonuç |
|---|---|
| Gateway'in tüm yerel testleri | 478 PASS, 0 FAIL, 16 IGNORE |
| Python paketi, gerçek yerel Anvil dahil | 136 PASS, 0 SKIP |
| Gerçek demo süreçleriyle restore | 17 güvenli ret, 2 başarılı restore |
| Önceki ACK/crash matrisi | 9 PASS, 27 gerçek SIGKILL çıkışı |
| Gateway tüm hedefler Clippy / workspace format | PASS |
| Mac fixture'ı Linux CI'da kurtarma | PASS |
| Reviewed guest kaynak pinleri | 21/21 aynı |

Beş yeni checkpoint testi ve iki yeni recovery testi gateway toplamına dahildir.
16 ignored testten biri yeni, yalnız açıkça seçilerek çalışan fixture dışa aktarma
testidir; bu test ayrıca çalıştırılıp başarılı oldu. Diğer ignored testler eski
opt-in testlerdir. Yerelde tüm Rust workspace/fuzz ve frontend paketi yeniden
koşturulmadı; normal CI ayrı değerlendirilir. Guest/proof pinleri, snapshot/journal
formatı, dependency lock'ları, sözleşmeler ve ekonomik kurallar değiştirilmedi.
İlk test derlemesinde Cursor'ın Serialize uygulaması olmadığı ve ortak hex20
helper'ı bulunmadığı görüldü; yalnız test kodu düzeltilerek yukarıdaki son sonuçlar
alındı. Protokol tiplerine yeni serialization eklenmedi.

## Açık sınırlar

İki hash bir canlı backup'ın atomik/koordineli alındığını veya dosyaların en güncel
olduğunu kanıtlamaz. Operatör aynı incelenmiş checkpoint kaydını kullanmalı ve
backup sırasında yazıcıları durdurmalı veya koordineli snapshot sağlamalıdır.
Eski dosya ve eski pin birlikte onaylanırsa güncellik bu mekanizmadan çıkmaz.

Gerçek servis/anahtarlarla farklı makine kurtarması; canlı L1 prefix/anchor ve
pending transaction uzlaşması; gerçek fonlu exit; ölçülmüş production RTO/RPO;
yeni wallet proof'ları; NVIDIA CC/key release; oracle ve matching fairness;
bağımsız güvenlik incelemesi hâlâ açıktır. Yerel iki kısa restore ölçümünden
production gecikmesi, RPO veya p95 türetilmez. **RELEASE HOLD devam eder.**

Kullanım: `docs/RECOVERY_RESTORE.md`. Kalıcı kanıtlar bu klasörde, ham yerel
kayıtlar `target/paired-recovery-20261010/` altındadır. Yayın kopyalarında yalnız
home yolu ve satır sonu boşlukları normalize edilmiştir; ham/yayınlanan hash'ler
`verification.json` içinde ayrıdır. Bu rapor sonradan eklenmiştir; işlevsel
kaynak hash'leri sabittir, son PR head'inin genel CI durumu ayrıca kontrol edilmelidir.
