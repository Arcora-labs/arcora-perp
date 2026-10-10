# Chainlink aday guest: sabit girdilerle SP1 CPU yürütmesi

**PRODUCTION RELEASE HOLD.** Bu yol canlı oracle geçişi veya yeni proof değildir.
Mevcut reviewed v2 guest yerine geçmez. Ayrı adayın SP1 yürütmesi ve program
anahtarı, açıkça sentetik bir regresyon kümesi üzerinde kontrol edilir.

## Sabit aday kimliği

- SP1 SDK ve aday guest ailesi: `6.1.0`.
- ELF: `contracts/integration/fixtures/chainlink-candidate-v1/guest.elf`.
- ELF boyutu: `540704` bayt.
- ELF SHA-256: `48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f`.
- Ölçülen program vkey: `0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.

Bu değerler aday test kimliğidir, production için onaylanmış pin değildir.
Dokuz aday runtime/manifest/lock girdisi ayrıca sabitlenir. Eski reviewed v2'nin
21 kaynak pini, ELF'i ve vkey'si aynen korunur. Kaynak değişikliği, pin dosyasını
çıktıya uydurarak saklanamaz; yeni aday kimlik ve doğrulama değerlendirmesi gerekir.

## Tam test kümesi

`crates/chainlink-oracle/tests/fixtures/replay-v1/` altında 19 sabit witness vardır.
Tümü test kodundan üretilen açık, sentetik veridir. Feed kimlikleri, sözleşme
adresleri, raporlar ve publisher anahtarı test değerleridir. Ham Chainlink DON
imzaları, gerçek hesap/credential dosyaları veya gerçek kullanıcı verisi içermez.

Dört başarılı girdi: tek funding işlemi; USDC fiyatı 0.80 USD iken funding;
iki ayrı kaynak zamanlı funding işlemi; fiyat gerektirmeyen boş batch.
15 ret girdisi: eksik/fazla kanıt, yanlış market/feed, eski/gelecek quote,
funding/fill/liquidation/unbind için raporla uyuşmayan publisher fiyatları,
yanlış zincir/clock, bozuk market-state bağı, trailing byte ve eski wire sürümü.

Native testler aynı witness baytlarını yeniden üretir ve her beklenen hata türünü
kontrol eder. SP1 yürütücüsü her pozitif girdide exit 0 ve tam beklenen 32 public
baytı, her negatif girdide gerçek guest panic/exit 1 ve sıfır public bayt ister.
Executor hatası veya timeout negatif test başarısı olarak kabul edilmez.
Guest panic kodu, tek başına panic'in hangi kaynak satırında olduğunu kanıtlamaz.

Pozitif küme tam cüzdan fon yaşam döngüsü değildir. Geçerli pozisyonlu fill,
liquidation veya unbind için uçtan uca başarı bu kümeyle gösterilmez. Önceki dört
exact normal-wallet witness'ın yeni gerçek proof eksikliği ayrıca devam eder.

## Tekrar çalıştırma

Host derlemesi `protoc` ve kilitli SP1 bağımlılıklarını gerektirir:

```sh
cargo +1.99.0 test --locked --manifest-path crates/chainlink-oracle/Cargo.toml
SP1_SKIP_PROGRAM_BUILD=true cargo +1.99.0 build --release --locked \
  --manifest-path crates/sp1-host/Cargo.toml --bin replay-chainlink
python3 scripts/local-verification/run_chainlink_replay.py \
  --binary crates/sp1-host/target/release/replay-chainlink \
  --elf contracts/integration/fixtures/chainlink-candidate-v1/guest.elf \
  --output-dir /tmp/arcora-chainlink-replay-NEW
```

Çıktı klasörü yeni ve checkout dışında olmalıdır. Önceki kayıtlar ezilmez.
`SP1_SKIP_PROGRAM_BUILD=true` yalnız host derlemesinin eski reviewed guest'i
üretmesini engeller; çalıştırılacak ayrı aday ELF SHA-256 ile doğrulanır.
Bu komutlar fresh guest build iddiası değildir. Adayı yeniden derlemek için ayrı
`build_chainlink_candidate.py` aracı kullanılır. Mevcut cache kullanan aynı Mac
build'i bağımsız/cold build olarak sunulmaz.

Runner'ın girdileri binary içine gömülüdür; kullanıcıdan key veya witness dosyası
istemez. CPU backend açıkça seçilir, prover network seçeneği yoktur. Driver,
HOME/TMPDIR ve thread limitleri dışında ortamı yeniden kurar; credential, proxy,
prover-backend ve diagnostic ayarlarını miras almaz. Bu bir ağ sandbox kanıtı değildir.

Beş gerçek süreç guard'ı; yanlış ELF, symlink ELF, ELF yerine dizin, yinelenen
argüman ve mevcut çıktı klasörünü reddetmelidir. Bunlar 19 guest vakasından ayrıdır.
Kanıt manifest'i ancak bütün guest vakaları geçince yazılır. Dış doğrulayıcı,
beklenen vkey, 19 sıralı girdi, guest exit/cycle bilgileri, public baytlar ve
artifact hash'lerini ayrıca karşılaştırır. JSON duplicate ve nonfinite değerler,
eksik/tekrarlı vaka ve yanlış evidence iddiası reddedilir. Bu self-produced yerel
kanıt, bağımsız denetçi imzası veya uzak attestation değildir.

## CI ayrımı

Standalone Chainlink job'ı native yeniden üretim, no_std/lint ve Python evidence
guard testlerini çalıştırır. Mevcut `prover crates (excluded, typecheck)` job'ına
ayrı adayın gerçek CPU yürütmesi de eklenmiştir; job'ın eski adındaki typecheck,
bu yeni adımın yalnız typecheck olduğu anlamına gelmez. CI kontrolünün gerçekten
çalışıp bitmesi ayrıca doğrulanmalıdır; workflow dosyası eklemek başarı kanıtı değildir.

CI, depodaki ayrı aday ELF'i yürütür; kendi guest derlemesini yaptığını iddia etmez.
Başarılı yerel run, sonraki CI veya başka makine koşusu yerine geçmez.

## Açık kalan bağlar

Gerçek signed stream erişimi/istemcisi, canlı feed/decimal/USDC pinleri,
gateway-prover-L1 rapor taşıma ve kalıcılık/kurtarma bağlantısı, yeni gerçek proof,
canlı DON doğrulaması, deployment/servis kimliği, uptime canlı kabulü ve ekonomik
inceleme açık kalır. Bu pakette gateway, guest/engine/sözleşme semantiği, risk
eşikleri, yayın ayarları veya gerçek fon/state değiştirilmez.

SP1'nin resmi örneğinde execution, vkey setup ve proof üretimi ayrı işlemlerdir:
https://github.com/succinctlabs/sp1-project-template
