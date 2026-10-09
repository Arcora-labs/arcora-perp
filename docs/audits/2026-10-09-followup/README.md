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
- **R02 yerel build eşleşmesi:** İlk iki fresh derlemedeki farkın Cargo crate
  kimlikleri ve kaynak yolu bilgisinden geldiği doğrulandı. Aynı 21 kaynak piniyle,
  yalnızca iki crate kimliği ve derleme yolu normalize edilince yeni boş target’ta
  derlenen 525.824 baytlık ELF reviewed ELF ile birebir eşleşti
  (`df59a19b…79967c5`). Bu yeni ELF üzerinden CPU setup ile türetilen program
  anahtarı da mevcut `0x0017893c…62994b8353` piniyle eşleşti.
  Kaynak veya ELF yamalanmadı; reviewed pin değişmedi.
  Bu aynı makinenin compiler ve dependency cache’iyle alınmış yerel build
  kanıtıdır; farklı ortamda bağımsız derleme ve gerçek proof kabulü açık kalır.
  [Tekrar üretim komutu ve kanıtlar](clock-lifecycle/reproducible-build/README.md).

## Tamamlanan kontroller

| Kontrol | Sonuç | Sınır |
|---|---|---|
| [Rust workspace](workspace.log), [Clippy](clippy.log), format | PASS | Workspace ve tüm target’lar; opt-in testler ayrıca çalıştırıldı |
| [Frontend](frontend-tests.log) | 509 PASS, 1 SKIPPED | Birim/DOM testleri |
| [Frontend build](frontend-build.log) | PASS | TypeScript + Vite |
| [Tarayıcı](browser-tests.log) | 78 PASS | Chromium + WebKit; yerel, sentetik HTTP/wallet fixture |
| [Python son kontrol](python-final-tests.log) | 93 PASS, 1 SKIPPED | 8 build-recipe regresyonu dahil; Anvil opt-in testi ayrıca çalıştırıldı |
| [Manifest Anvil](manifest-tests.log) | 36 PASS | [Gerçek yerel runtime/route sonucu](manifest-anvil.json); canlı hedef değil |
| [Clock cüzdan akışı](clock-lifecycle/witnesses/lifecycle.json) | 4 batch, 2 gateway kapalı claim PASS | Gerçek clock adapter + mock inner verifier |
| [SP1 guest replay](clock-lifecycle/guest-replay/manifest.json) | 4/4 native eşitliği PASS | Reviewed ELF; fresh proof üretimi yok |
| [Replay girdi kontrolleri](clock-lifecycle/guards/verification.json) | Pozitif kontrol + 7 negatif PASS | Eksik/sırasız/değişmiş/symlink witness reddi |
| [Claim komutu önce](frontend-claim-before.log) | EXPECTED FAILURE | Zararlı biçimdeki alanın komuta kabul edildiğini gösterir |

CI artık dört sentetik cüzdan witness’ını reviewed guest üzerinde yürütür; yeni witness
export ve altı sözleşmeli manifest testi de gateway job’ına eklendi. Eski
`prover crates (excluded, typecheck)` job adı required check uyumluluğu için korundu;
step adları typecheck, native guard ve gerçek guest execution kapsamlarını ayırır.
Yaklaşık 98 milyon guest cycle için host `--release` ile derlenir; tanık ve
commitment assertion’ları korunur. Yerel optimize yürütme 32,48 saniyede tamamlandı;
bu süre Linux CI veya production kapasite ölçümü değildir.

Test loglarında terminal renk kodları, satır sonu boşlukları ve sondaki boş satırlar
ayıklanır; test assertion/sonuç metni değiştirilmez. Önceki ham log baytları ilk
commit'te korunur; ilk paketin dönüşümü ayrıca `log-normalization.json` ile kayıtlıdır.

## Linux CI düzeltmesi

İlk devam commit’inin Linux CI koşusunda Anvil 1.8.5 port duyurusunu stdout’a
yazdı; yalnızca stderr okuyan test başlamadan durdu. Her iki çıktı kanalı artık
sahip olunan alt süreçten okunup temizlenir. Eski davranış zorlanınca regresyon
başarısız oldu; düzeltmeden sonra hem stderr hem stdout üzerinden tam clock/claim
akışı geçti. Port 0 tahsisi, gateway/writer kapanışını bekleme ve bütün mali
assertion’lar korundu. [Önce/sonra ve kaynak kanıtı](clock-lifecycle/anvil-stream-fix/verification.json).

## Açık kabul kapıları

Normal cüzdan akışının aynı v2 witness'larıyla fresh gerçek proof üretimi ve chain
settlement; hedef ortam source/build/runtime/service bağları; gerçek proof p95/RSS,
finansal duraklama ve finalite ölçümü; ret meşruiyeti/matching fairness; bağımsız fiyat
politikası; yeni çıkışların operator/prover/governance bağımlılığı; gerçek TEE;
farklı makineye restore ve gerçek operatöre alarm teslimi açık kalır. PR bağımsız
inceleme/onay gerektirir; merge ve production rollout yapılmadı.
