# GitHub teslimi ve custodial alpha devam doğrulaması

Çalışma 9 Ekim’de başladı; devam kontrolleri 10 Ekim 2026 (Europe/Istanbul) tarihine uzandı.

İlk paket [PR #32](https://github.com/Arcora-labs/arcora-perp/pull/32) ile GitHub'a gönderildi.
Custodial alpha kararı, ekonomik kurallar ve reviewed guest kaynakları korunuyor.
Bu klasör, [ilk doğrulama raporunun](../2026-10-09-remaining-work/README.md) devamıdır.
İlk rapordaki yerel/push edilmedi ifadeleri ilk kanıt alındığı ana aittir.
**Yayın kapısı HOLD; R01–R10 topluca kapanmış değildir.**

## Yeni kapatılan açıklar ve doğrulamalar

- **R08 özel prover çıktıları:** SP1 debug/dump/trace ayarları başlangıçta ve
  witness anahtarı bırakılmadan önce reddedilir. Aynı süreçte plaintext açıp diske
  yazabilen debug ayarı artık kabul edilmez. [Ayrıntı ve önce/sonra kanıtı](../2026-10-09-prover-diagnostic-privacy.md).
- **R07 çekim komutu:** Gateway verisi sabit uzunluklu hex adres/hash, güvenli nonce
  ve uint256 tutar olarak doğrulanır. Shell metakarakterli ve hatalı girdiler hem
  API sınırında hem komut/wallet çıktı sınırında reddedilir. Önce başarısız olan
  regresyon düzeltmeden sonra geçti. Bu kontrol Merkle kanıtını veya root yayımını
  doğrulamaz; bunları vault yapar. Chain/RPC seçimi mevcut Base Sepolia akışıdır.
- **R02 hedef kimliği aracı:** `release_manifest.py observe-target` finalized blok
  hash'ine bağlı altı kontrat runtime/immutable eşleşmesini, sözleşme bağlantılarını,
  guest anahtarını, clock politikasını ve aktif verifier rotasını okur. Gerçek
  constructor'larla oluşturulmuş yerel Anvil stack'inde geçti; rota dondurulunca
  reddetti. Hedef canlı deployment ve servis kimliği bu deneyle doğrulanmış değildir.
- **R01/R07 clock ve mevcut çekimler:** Yeni yerel lifecycle gerçek ClockBoundVerifier
  ve açıkça mock iç verifier kullanır. Dört pencerenin v2 witness'ları kaydedilir;
  gateway kapatıldıktan sonra saklanan Merkle verisiyle iki cüzdan doğrudan claim eder.
  [Kapsam ve komutlar](../../FUNDS_LIFECYCLE.md). Aynı dört tam witness, reviewed
  SP1 ELF üzerinde CPU ile yürütüldü; tüm public commitment’lar native sonuçla
  birebir eşleşti. [Kanıtlar](clock-lifecycle/verification.json).
- **R02 build bulgusu:** Aynı guest kaynaklarının doğrudan ve yol eşleme ile iki
  fresh derlemesi reviewed ELF hash’inden farklı çıktı. Araç mismatch’i reddetti.
  Dört batch’in başarılı SP1 yürütmesi açıkça mevcut sabitlenmiş ELF’i kullanır;
  fresh source→ELF→vkey tekrar üretilebilirliği hâlâ açık.

## Tamamlanan kontroller

| Kontrol | Sonuç | Sınır |
|---|---|---|
| [Rust workspace](workspace.log), [Clippy](clippy.log), format | PASS | Workspace ve tüm target’lar; opt-in testler ayrıca çalıştırıldı |
| [Frontend](frontend-tests.log) | 509 PASS, 1 SKIPPED | Birim/DOM testleri |
| [Frontend build](frontend-build.log) | PASS | TypeScript + Vite |
| [Tarayıcı](browser-tests.log) | 78 PASS | Chromium + WebKit; yerel, sentetik HTTP/wallet fixture |
| [Python](python-tests.log) | 85 PASS, 1 SKIPPED | Anvil opt-in testi ayrı çalıştırıldı |
| [Manifest Anvil](manifest-tests.log) | 36 PASS | [Gerçek yerel runtime/route sonucu](manifest-anvil.json); canlı hedef değil |
| [Clock cüzdan akışı](clock-lifecycle/witnesses/lifecycle.json) | 4 batch, 2 gateway kapalı claim PASS | Gerçek clock adapter + mock inner verifier |
| [SP1 guest replay](clock-lifecycle/guest-replay/manifest.json) | 4/4 native eşitliği PASS | Reviewed ELF; fresh proof üretimi yok |
| [Replay girdi kontrolleri](clock-lifecycle/guards/verification.json) | Pozitif kontrol + 7 negatif PASS | Eksik/sırasız/değişmiş/symlink witness reddi |
| [Claim komutu önce](frontend-claim-before.log) | EXPECTED FAILURE | Zararlı biçimdeki alanın komuta kabul edildiğini gösterir |

CI artık dört sentetik cüzdan witness’ını reviewed guest üzerinde yürütür; yeni witness
export ve altı sözleşmeli manifest testi de gateway job’ına eklendi. Eski
`prover crates (excluded, typecheck)` job adı required check uyumluluğu için korundu;
step adları typecheck, native guard ve gerçek guest execution kapsamlarını ayırır.

Test loglarında terminal renk kodları, satır sonu boşlukları ve sondaki boş satırlar
ayıklanır; test assertion/sonuç metni değiştirilmez. Önceki ham log baytları ilk
commit'te korunur; ilk paketin dönüşümü ayrıca `log-normalization.json` ile kayıtlıdır.

## Açık kabul kapıları

Normal cüzdan akışının aynı v2 witness'larıyla fresh gerçek proof üretimi ve chain
settlement; hedef ortam source/build/runtime/service bağları; gerçek proof p95/RSS,
finansal duraklama ve finalite ölçümü; ret meşruiyeti/matching fairness; bağımsız fiyat
politikası; yeni çıkışların operator/prover/governance bağımlılığı; gerçek TEE;
farklı makineye restore ve gerçek operatöre alarm teslimi açık kalır. PR bağımsız
inceleme/onay gerektirir; merge ve production rollout yapılmadı.
