# Arcora kalan işler: doğrulama ve alpha düzeltmeleri

Tarih: 2026-10-09 (Europe/Istanbul). Başlangıç kaynağı:
`b2a3c357c6b345726a7a85b5cc55484d6bef8c98` (GitHub main / PR #31).
Yerel dal: `fix/remaining-work-20261009`.
Kapsam kararı: kullanıcı **mevcut custodial alpha modelini sağlamlaştırmayı** seçti.

Bu çalışma rapordaki R01–R10'u güncel kaynak, yerel testler ve GitHub API'siyle
karşılaştırır. İki somut hata düzeltildi: aynı blok içindeki geç settlement'ın
itiraz teminatını yanlış tarafa vermesi ve prover panic durumunda açılmış witness
baytlarının temizlenmemesi. Clock duraklaması API/arayüzde görünür hale getirildi;
normal cüzdan yaşam döngüsü testi ve sürüm manifesti eklendi. GitHub main koruması
etkinleştirildi. Kod değişiklikleri yerel dalda incelemeye hazırdır; kaynak push,
merge, deployment veya fon/state taşıma yapılmadı.

**Bütün yayın paketleri kapanmış değildir.** Gerçek SP1 kanıtı eksik sayılmıyor:
PR #31 fixture'ının mevcut kanıtı bu çalışmada güncel Solidity sözleşmeleriyle tekrar
24 testten geçti. Yeni cüzdan/HTTP yaşam döngüsü ise native replay + açıkça
MockZkVerifier kullanır; bu iki kanıt aynı uçtan uca gerçek-proof çalıştırması değildir.
Gerçek fonla yayın kararı **HOLD**.

## Yapılan düzeltmeler

1. **İtiraz teminatı:** Challenge açılırken `batchCount` kaydedilir. Ardından aynı
   blokta bile kesinleşen batch inclusion/rejection cevabında teminat kullanıcıya
   döner. Challenge öncesi yayımlanmış batch için önceki teminat kuralı korunur.
   Getter ABI'si değişmedi. İki regresyon önce başarısız, sonra başarılı oldu;
   işlem sırası fuzz testi ve tekrar/yeniden challenge kontrolleri eklendi.
2. **Clock kullanılabilirliği:** `/api/state`, `/v1/system/status` ve bütün public
   WebSocket snapshot yolları gerçek `clockAdmission` durumunu taşır. Finansal tick
   dururken read-only durum yayını sürer. Arayüz closes/cancel/margin/withdrawal
   isteklerinin de durduğunu gösterir; yeni emir önizlemesi engellenir ve onay anında
   durum tekrar okunur. Otomatik emir tekrarı eklenmedi. Eski sabit çekim süresi
   iddiası kaldırıldı. API snapshot'ı izin bileti değildir; yarışları sunucu gate'i kapatır.
3. **Witness temizliği:** Açılan yerel byte buffer, `zeroize` kullanan Drop guard ile
   normal dönüş, decode hatası ve panic unwind sırasında temizlenir. Başarısız-önce
   regresyon aynı canlı tamponda plaintext kaldığını gösterdi; düzeltme debug ve
   optimize release testlerinden geçti. Backend/decoded kopyalar, register'lar ve
   abort/SIGKILL için tam bellek temizliği iddiası yoktur.
4. **Sürüm kimliği:** Yeni manifest aracı reviewed guest kaynak/ELF/vkey kimliğini,
   güncel derlenmiş altı sözleşmeyi ve public gateway/prover ayarlarını bağlar.
   Yanlış anahtar, eski artifact, config sapması ve sahte readiness flag reddedilir.
   Eski `read_deployment.py` 27 Eylül logu yerine reviewed clock-v2 anahtarını karşılaştırır.
5. **Repo koruması:** GitHub'da main için PR + bağımsız bir onay, son push onayı,
   eski onayın düşürülmesi, review-thread çözümü, güncel dal üzerinde 11 zorunlu
   GitHub Actions kontrolü, force-push/silme engeli aktif. Bypass listesi boş.
   Yerel A11 workflow bütün PR'larda çalışacak ve yeni manifest/policy/RPC/lifecycle
   testlerini içerecek şekilde güncellendi.
6. **Ürün açıklamaları:** README, litepaper'ın kaynak/servis HTML kopyaları,
   Security/API/Architecture/Decisions/wind-down runbook ve UI; custody, publisher,
   prover plaintext erişimi, yeni çıkışlarda operator/prover/governance bağımlılığı
   ve kaynak ile deployment ayrımı bakımından düzeltildi. Ekonomik kural değiştirilmedi.

## R01–R10 güncel durum

| Paket | Bu turdaki sonuç | Açık kabul kapısı |
|---|---|---|
| R01 | **KISMİ:** Gerçek loopback HTTP + Anvil üzerinde üç normal cüzdan yatırması, 50.000 test USDC, dört imzalı şifreli emir, pozisyon açma/kapatma, dört batch, 20.000 claim; kalan kasa 30.000 ve kökler/prefix/muhasebe uzlaşıyor. Şifreli snapshot/WAL gerçek dosyalardan geri yüklendi. | Aynı normal-cüzdan akışı fresh gerçek clock/SP1 proof ve üretim servis döngüsüyle; kesinti halinde bütün fon akışının devamı. Mock lifecycle ile gerçek fixture kanıtı birleştirilmiş sayılmaz. |
| R02 | **KISMİ:** Offline source/ELF/vkey/contract/public-config manifesti ve mismatch testleri geçti; tarihsel deployment key uyumsuzluğu yeniden doğrulandı. | Temiz araç zincirinden tekrar build, hedef chain/address/runtime/immutable/config bağları, state/not/çekim hakkı taşıma provası. Public RPC okuması HTTP 403 ile durdu. |
| R03 | **KISMİ:** Duraklama görünürlüğü, pause sırasında read-only yayın, onay anı kontrolü ve otomatik emir tekrarı olmaması test edildi. | Hesap/not/batch yük basamaklarında gerçek prover p95 süre/RSS, finalite gecikmesi, finansal kabulün kapalı süresi ve risk kabulü. Native mock akış süresi bir kapasite sonucu değildir. |
| R04 | **KISMİ:** Aynı blokta haksız teminat kesintisi düzeltildi ve test edildi. Üç adversarial characterization testi guest'in keyfî ret/sıra/duplikasyonu hâlâ ispatlamadığını gösterir. | İmzalı intent, ilgili önceki durum, matcher kuralı ve ret meşruiyetini guest'e bağlayan Proof-v2 tasarımı. Mevcut teminat düzeltmesi bu garantiyi sağlamaz. |
| R05 | **ALPHA KARARI TAMAM:** Kullanıcı custodial alpha yolunu seçti; gateway anahtarı/publisher güveni ve sınırları açık yazıldı. | Bu karar non-custodial güvence değildir. Kullanıcı-denetimli model ayrı intent/nonce/expiry/deployment/rotation mimarisi ister. |
| R06 | **KISMİ:** Mevcut imza/freshness/confidence/deviation testleri geçti. Tek publisher'ın fiyat ve backup'ı birlikte 100x aşağı/yukarı imzalayınca kabul edildiği regression ile görünür. | Bağımsız doğrulanabilir kaynak/çoklu publisher politikası. Custodial alpha'nın mevcut publisher güveni kaldırılmadı. |
| R07 | **KISMİ:** Mevcut giriş-fiyatından kapama, önce rezervler sonra pozitif collateral/notlara oransal kesinti kuralı kesin tutarlarla sınandı; governance/grace testleri geçti. Çıkış beyanları düzeltildi. | Hedef ortamda operator/prover/governance kaybı, bağımsız claim verisine erişim ve yeni çıkışların gerçek bağımlılık tatbikatı; ekonomik kabul. |
| R08 | **KISMİ:** Panic temizliği kapatıldı; attestation, reauth ve expiry kontrolleri yerelde geçti. | Gerçek hedef donanım/measurement/quote/anahtar bırakma. NVIDIA CC probe halen false ve quote/verify backend'i tamamlanmamış. Backend witness kopyaları ve dump/disk/backup temizliği ayrıca incelenmeli. |
| R09 | **KISMİ:** Main koruması canlı API'de aktif ve `protected=true`; 11 check GitHub Actions kimliğine bağlı. | Başarısız/eksik check ile kontrollü gerçek merge-ret tatbikatı yapılmadı. Yeni CI değişiklikleri henüz yerel. R01–R10 yerel takip kodlarıdır; yeni GitHub issue açılmadı. |
| R10 | **KISMİ:** Yanıltıcı kaynak/canlı sürüm, custody, gizlilik ve çıkış metinleri düzeltildi. Yerel alarm, şifreli kurtarma, reauth ve SIGKILL testleri tekrar çalıştı. | Hedef altyapıda farklı makineye restore ve ölçülü RTO/RPO, anahtar kaybı/rotasyon, gerçek operatöre alarm teslimi ve bağımsız protokol/ekonomi denetimi. |

## Kanıtlar ve sınırları

Makine özeti: [verification.json](verification.json). Bütün kaynak farklarını
bağlayan son dosya hashleri: [source-final.json](source-final.json).
Temel commit tek başına commit edilmemiş değişikliklerin kimliği değildir.

- [Rust workspace](workspace-final.log), [Clippy](clippy-final.log) ve [gateway build](gateway-build-final.log): PASS; opt-in ignored testler ayrı listelenir.
- [Gerçek binary ACK/SIGKILL/restart](ack-crash/result.json): 9/9 durum, 27 sonlandırılmış yerel süreç; yeni tam-SP1 fon akışı değildir.
- [Solidity](foundry-final.log): 126/126; iki invariant grubu ve yeni işlem-sırası fuzz'ı.
- [Gerçek clock fixture doğrulaması](real-clock-proof/verification.json): 24/24;
  güncel settlement/vault/clock adapter ve gerçek verifier, yerel EVM. Yeni proof
  üretilmedi; fixture'da sentetik payer/adresler ve mock token var.
- [Frontend](frontend-tests-final.log): 496 PASS, 1 SKIPPED; [build](frontend-build-final.log) PASS.
  Bu sonuç unit/DOM testidir, fiziksel telefon veya hedef canlı site testi değildir.
- [Python guard testleri](python-tests-final.log): 69 PASS (19 manifest, 30 deployment reader,
  3 repo-policy ve mevcut diğer guard testleri dahil).
- [Final native/mock cüzdan akışı](funds-lifecycle-final.json) ve
  [kapsam/komut](funds-lifecycle.md). Son native/mock ölçüm 8.24 saniye; gerçek proof süresi değildir.
- [Panic wipe önce](prover-privacy/panic-wipe-before.log),
  [sonra](prover-privacy/prover-after-wipe-tests.log),
  [optimize release](prover-privacy/panic-wipe-release.log).
- [R04/R06/R07 ayrıntısı](../2026-10-09-rejection-boundary.md).
- [Prover/attestation/operasyon incelemesi](prover-privacy/review.json): source incelemesi
  ve yerel native/loopback/owned-subprocess testleri; hedef donanım incelenmedi.
- [Main koruma doğrulaması](repository-protection-verification.json),
  [uygulanan kurallar](main-effective-rules.json),
  [GitHub ruleset](https://github.com/Arcora-labs/arcora-perp/rules/24812584).
- [Deployment okuması](deployment-observation.json): `eth_chainId` aşamasında
  `https://sepolia.base.org` HTTP 403 döndü; hiçbir runtime bytecode veya canlı key
  doğrulanmış sayılmadı.
- [Manifest](release-manifest.json) ve [örnek public config](manifest-public-config.example.json):
  adresler sentetiktir, chain 31337; `release_gate=HOLD` her zaman korunur.
  [Kullanım ve kalan kapılar](../../RELEASE_MANIFEST.md).

## İşletim/devam notları

Yerel check'ler için Rust 1.99.0 kullanıldı. Bu Mac'in varsayılan Homebrew `cargo`
komutu Rust 1.95.0'a gider; CI ile aynı sürüm için:

```sh
/Users/huseyinarslan/.cargo/bin/cargo +1.99.0 test --workspace --locked
/Users/huseyinarslan/.cargo/bin/cargo +1.99.0 clippy --workspace --all-targets --locked -- -D warnings
python3.11 -m unittest discover -s scripts/local-verification -p 'test_*.py'
forge test --root contracts
pnpm --dir frontend test
pnpm --dir frontend build
```

Manifest aracı Python 3.11+ ister. `cargo prove` bu Mac'in mevcut komut yolunda
bulunmuyor; Docker linux/aarch64 çalışıyor, ancak bu durum yeni guest build veya
proving kapasitesi kanıtı değildir. Hedef prover/TEE ortamı bu checkout'ta tanımlı değil.

Yeni A11 workflow merge edilene kadar eski workflow'un path filtresine takılan
belge-only PR'lar zorunlu A11 check'lerini bekleyebilir. Koruma ayarı yönetici bypass'ı
vermez; en son push'tan bağımsız gerçek bir onay gerekir. Başarısız kontrolleri
atlamak için kuralları sessizce gevşetmeyin.

Hedef ortam bilgisi sağlandığında sıradaki kabul çalışması R01+R02+R03'tür:
aynı kaynakla normal cüzdan/HTTP/clock/gerçek proof/finalite/çekim akışını, birden fazla
batch ve kesintiyle ölçmek; ardından R07/R08/R10 altyapı kapılarını tamamlamak.
