# Zorunlu snapshot restore ve yerel kurtarma tatbikatı

## Başlangıç güvenlik koşulları

İlk kurulum ile kurtarma amaçlı yeniden başlatma aynı işlem değildir. Normal
başlangıçta `DARKPERP_STATE` dosyası bulunmazsa yeni genesis açılabilir. Kurtarma
sırasında yanlış dosya yolu veya eksik yedek, yeni genesis için izin sayılmamalıdır.

Gateway iki açık başlangıç ayarı sunar:

| Ayar | Davranış |
|---|---|
| `DARKPERP_REQUIRE_RESTORE=1` | Snapshot yolu ve okunabilir snapshot zorunludur. Eksik dosyada yeni genesis açılmaz. |
| `DARKPERP_RESTORE_SHA256=<64 hex>` | Seçilen şifreli snapshot'ın SHA-256 özeti eşleşmelidir. Tek başına da zorunlu restore anlamına gelir. |

`DARKPERP_REQUIRE_RESTORE` yalnızca `0` veya `1` kabul eder; unset eski davranışı
korur. Boş/yanlış değerler reddedilir. Hash, `0x` öneki olmadan 64 ASCII hex
karakteridir; büyük/küçük harf eşdeğerdir. Hash verilmişse `...REQUIRE_RESTORE=0`
bile onu devre dışı bırakamaz. UTF-8 olmayan politika ayarları reddedilir.

Snapshot tek kez okunur. Hash kontrolü ile mevcut MAC/doğrulama ve state açma
adımı **aynı baytları** kullanır; hash kontrolünden sonra başka dosya tekrar
okunmaz. Yanlış hash, okunamayan dosya veya bozuk/yanlış anahtarla açılan snapshot
HTTP listener ve fresh genesis başlamadan reddedilir. Hata çıktısı girilen hash
veya anahtar değerini içermez. Dosya otomatik silinmez, düzeltilmez veya yeni
snapshot ile değiştirilmez.

Bu kontrol bir donanım güvenlik sınırı veya dosya yolu sandbox'ı değildir.
Servis ayarları, parent dizinler ve checkpoint kaydı güvenilen operatör sınırındadır.

## Güvenilen checkpoint ile çalıştırma

`APPROVED_SNAPSHOT_SHA256`, hedef dosyadan yeni hesaplanıp otomatik onaylanan bir
değer değil, korunmuş ve incelenmiş yedek kaydından gelmelidir. Aday dosyanın
hash'ini hesaplayıp aynı adayın doğruluğuna kanıt yapmak, eski yedeği de onaylar.

```sh
DARKPERP_STATE=/restore/gateway.snapshot \
DARKPERP_REQUIRE_RESTORE=1 \
DARKPERP_RESTORE_SHA256="$APPROVED_SNAPSHOT_SHA256" \
  ./gateway
```

Bu örnek yalnızca ek restore ayarlarını gösterir. Mevcut güvenli seed/key-release,
production, L1 ve diğer servis ayarlarının yerine geçmez. Gerçek anahtarlar bu
belgeye, komut geçmişine veya doğrulama raporuna yazılmamalıdır.

Pin **başlangıç için seçilmiş şifreli dosyayı** bağlar. Normal snapshot yazıcısı
aynı semantik durumu yeni nonce ile tekrar şifreleyebilir; hash değişir. Sonraki
başlangıç için doğru onaylı checkpoint kaydı seçilmelidir. Eski hash'i kalıcı
servis ayarında unutmak, sonraki açılışı haklı olarak durdurabilir. Sürekli yazılan
canlı dosyaya rastgele yeni hash onayı vermek bir yedek politikası değildir.

## Kanıtın sınırı

SHA-256 eşleşmesi seçilen dosyanın bütünlüğüdür, güncellik veya zincir mutabakatı
değildir. Eski ama geçerli bir snapshot, kendi eski pin'i güvenilir kabul edilirse
yüklenebilir. Snapshot MAC'i, rollback-journal tutarlılığı, L1 yeniden uzlaşması,
deposit/withdrawal muhasebesi ve anahtar yetkileri ayrı kontroller olarak kalır.
Yeni snapshot biçimi, veri migration'ı, guest veya public input değişikliği yoktur.

Gerçek kurtarmada snapshot dışındaki gerekli yan dosyalar, rollback journal,
L1 cursor'ları, doğrulanmış binary/config kimlikleri, anahtar temini ve depolama
kurtarma süreci de birlikte değerlendirilmelidir. Bu paket onların taşınmasını
veya farklı makinede restore edildiğini iddia etmez. Production **RELEASE HOLD**
devam eder.

## GPU gerektirmeyen gerçek süreç tatbikatı

```sh
cargo build --locked -p gateway
pnpm --dir frontend install --frozen-lockfile
python3 scripts/local-verification/gateway_restore_drill.py \
  --gateway-bin target/debug/gateway \
  --output-dir /tmp/arcora-restore-FRESH
```

Çıktı dizini önceden mevcut olamaz. Binary build'inin kaynak kimliği ayrıca
kaydedilmelidir; runner binary/script hash'i alır, verilen binary'nin hangi
kaynakla derlendiğini yalnızca `git HEAD` üzerinden varsaymaz.

Runner yeni, kendisine ait loopback gateway süreçlerini kullanır. Test seed ve
cüzdan anahtarları oluşturulur; kullanıcı anahtarı/RPC parametresi kabul edilmez.
Şifreli test snapshot'ları geçici dizinlerde tutulur ve temizlenir. Rapor, özel
anahtar/API key, plaintext hesap dökümü veya snapshot gövdesi içermez.

Tatbikat; hesap açma, cüzdan adresi bağlama, demo teminat, gerçekleşmemiş emir,
emir iptali ve dayanıklı credential recovery akışını gerçek HTTP üzerinden
çalıştırır. Kaynak süreç durdurulur, özgün snapshot yolu kaldırılır ve seçilen
şifreli yedek iki kez farklı boş dizine taşınır. Her restore'da sekiz hesap alanı,
özgün emir receipt'i ve iptal durumu doğrulanır; eski API key 401, eski recovery
imzası 400 alır. Deposit route ve idempotent iptal sonucu korunur.

On yedi reddetme durumu ayrıca çalışır: eksik state ayarı, eksik dosya, yalnız pin
ile eksik dosya, bozuk mode/hash ayarı, yanlış seed, kesik/tahrif edilmiş snapshot,
eski veya yanlış checkpoint, `0` ile pin'i devre dışı bırakma girişimi ve dosya
yerine dizin; ayrıca eksik/yanlış journal, beklenmeyen sidecar, snapshot pin'i
olmadan journal seçimi ve doğru hash'li fakat geçersiz journal. Reddedilen mevcut dosya byte-byte korunur; eksik dosyanın yerine
yeni snapshot üretilmez.

`copy_to_verified_state_seconds` yalnız yerel kopyadan HTTP/state doğrulamasına
kadar olan örnektir. Arıza tespiti, makine kurma, uzak yedek indirme, anahtar elde
etme veya gerçek L1 finalitesi bu süreye dahil değildir. `confirmed_observations_lost=0`
sadece sınanan onaylı gözlemler içindir; üretim RPO/SLA ya da tüm bekleyen işlemler
hakkında garanti değildir. İki yerel örnekten p95/kapasite çıkarılmaz.

Public demo fiyat okumaları kapatılmamıştır; loopback listener, dış ağa tam
izolasyon demek değildir. Gerçek fon, proof üretimi, production rollout veya
operator/prover kaybı altında gerçek çekim bu tatbikatın kapsamında değildir.

CI mevcut gateway drill işinde bu tatbikatı çalıştırır ve sonucu artifact olarak
saklar. Saf karşılaştırma regresyonları ayrıca çalışır:

```sh
python3 -m unittest discover -s scripts/local-verification \
  -p test_gateway_restore_drill.py -v
cargo test --locked -p gateway snapshot::tests::restore_
```


## Snapshot ve journal'ı birlikte sabitleme

`DARKPERP_RESTORE_JOURNAL=<64 ASCII hex>` beklenen `.rollback` dosyasını bağlar.
`DARKPERP_RESTORE_JOURNAL=absent` seçilen checkpoint'te journal bulunmadığını
**açıkça** belirtir. Her iki durumda da geçerli `DARKPERP_RESTORE_SHA256` gerekir;
yalnız journal'ı sabitlemek ilgili snapshot'ı bağlamaz. Değer unset ise mevcut
journal keşfi sürer; bu legacy mod eksik bir journal'ın yedekten unutulduğunu
tek başına saptayamaz. Yanlış/bilinmeyen/boş değerler reddedilir.

Örnek (değerler daha önce incelenmiş aynı checkpoint kaydından gelmelidir):

```sh
DARKPERP_STATE=/restore/state.snapshot \
DARKPERP_REQUIRE_RESTORE=1 \
DARKPERP_RESTORE_SHA256="$APPROVED_SNAPSHOT_SHA256" \
DARKPERP_RESTORE_JOURNAL="$APPROVED_JOURNAL_SHA256_OR_ABSENT" \
  ./gateway
```

Journal hash'i eşleşse bile MAC, format ve recovery tablosu kontrolü devam eder.
Hash'i doğrulanan journal baytları yeniden dosya açılmadan decoder'a verilir.
Yüklenmiş fakat çözülememiş journal bellek içi olarak da takip edilir; dosyanın
sonradan yok olması çözüldüğü anlamına gelmez. Mutasyonun kalıcı kaydı başarısızsa
başlangıç kapalı kalır. Symlink ve nonregular journal girişleri reddedilir;
parent dizinler ve servis ayarları yine güvenilen operatör sınırındadır.

Snapshot/journal kopyası alınırken yazıcıların durdurulması veya koordineli bir
checkpoint alınması gerekir. İki ayrı hash birbirleriyle semantik uyumu ya da
son zincir durumunu kendiliğinden kanıtlamaz. Çalışan gateway'i durdurmadan
koordineli çift almak için aşağıdaki [canlı yedek](#canlı-yedek-ve-başka-makinede-restore)
aracını kullanın. Rollback korumalı uzaktan imza veya key release servisi yoktur.

**Cursor yerleşimi:** deposit domain, tüketilen count/tip, receipt ledger ve
finalized anchor snapshot içindedir; ayrıca taşınacak bir deposit-cursor dosyası
yoktur. Restore sonrası L1 prefix/anchor doğrulaması yeniden gerekir. Challenge
tarama cursor'u kalıcı dosya değildir; boot'ta mevcut challenge penceresini geri
sararak yeniden kurulur. Uzun kesintide kaçmış challenge deadline'ları bu testle
kapanmış sayılmaz.

`deposit_ingestion::paired_recovery_tests` üç sentetik deposit (biri pencere
mühürlendikten sonra), imzalı bir çekim ve gerçek şifreli snapshot/journal ile
HOLD, rollback/reseal, roll-forward ve tekrar commit senaryolarını sınar. Deposit
cursor/ledger kaybolmamalı, eski sayfa yeniden credit edilmemeli ve çekim yaprağı
korunmalıdır. Zincir gözlemleri test girdisi, prover açıkça mock'tur.

`crates/gateway/tests/fixtures/paired-recovery/` fixture'ı ARM64 macOS'te yalnız
yeni oluşturulmuş test hesaplarından üretilmiştir. Bilinen açık test seed'iyle
şifrelenir; kullanıcı/üretim verisi veya kullanılabilir fon içermez. Linux CI bu
aynı baytları gerçek decoder/recovery fonksiyonlarıyla açar. Bu, fixture ve
kurtarma mantığının platformlar arası testidir; canlı production servisi, RPC,
attestation, anahtar temini ve gerçek fonların başka makineye taşınması değildir.

## Canlı yedek ve başka makinede restore

[`scripts/ops/gateway_backup.py`](../scripts/ops/gateway_backup.py), çalışan
gateway'i durdurmadan snapshot ve `.rollback` journal çiftini kopyalar.
[`deploy/`](../deploy/README.md) altındaki timer bunu 30 dakikada bir çalıştırır.

**Tutarlılık gerekçesi.** Gateway iki dosyayı da yalnız atomik `rename` ile
değiştirir (`snapshot.rs` `write_atomic`). Araç her dosyanın
`(dev, inode, boyut, mtime_ns)` kimliğini kopyadan önce ve sonra okur. İkisi de
değişmediyse iki kopya diskte aynı anda var olmuştur. Bu çift, gateway o anda
çökseydi diskte kalacak çiftle aynıdır ve boot kurtarma tablosu (Stale,
SealNeverPersisted, RollBack, RollForward, Hold) tam olarak bu durumlar için
vardır. Kimlik değiştiyse deneme silinir ve yeniden denenir; varsayılan en
fazla 5 deneme yapılır. Candidate arşiv modu (`<state>.chainlink`) kapsanmaz,
eksik yedek üretmek yerine reddedilir.

**Checkpoint kaydı.** Her yedek dizini `manifest.json` taşır. İçindeki
`restore_env` alanında `DARKPERP_REQUIRE_RESTORE=1`, `DARKPERP_RESTORE_SHA256`
ve `DARKPERP_RESTORE_JOURNAL` (hash veya `absent`) bulunur. Bu değerler kopyalanan
baytlardan yedek anında hesaplanır. Yukarıdaki kural geçerlidir: restore sırasında
hash hedef dosyadan yeniden hesaplanmaz, manifest'ten alınır. Manifest'in
korunması için yedeği başka bir makineye kopyalayın
(`DARKPERP_BACKUP_OFFSITE`).

**Yedekle taşınmayanlar.** Snapshot ve journal `ENCLAVE_SEED` altında
şifrelidir. Anahtarlar yedekte bulunmaz ve ayrı, güvenli bir kanalla taşınmalıdır:
- `ENCLAVE_SEED`
- `L1_SEQUENCER_KEY`
- `GATEWAY_SIGNER_KEY`
- `ORACLE_SIGNER_KEY` (genesis sonrası değişirse oracle kesintisi olur)
- `FIN_ADMIN_KEY`
- `PROVER_SEAL_ROOT`

Bunlara ek olarak L1 adresleri ve attestation paketi de ayrıca taşınır.

### Restore adımları

1. **Eski hostu durdurun ve kapalı tutun.** İki aktif gateway aynı sequencer
   anahtarıyla settle göndermemelidir. Split-brain'i önleyen otomatik bir
   fencing mekanizması yoktur.
2. Yeni makinede [deploy kurulumunu](../deploy/README.md) yapın. Gateway'i
   henüz başlatmayın.
3. En yeni yedeğin `state.snap` (ve varsa `state.snap.rollback`) dosyasını
   `/var/lib/darkperp/` altına kopyalayın. Sahip `darkperp`, mod `0600` olmalı.
4. Manifest'teki `restore_env` değerlerini `/etc/darkperp/gateway.env`'e yazın,
   anahtarları ayrı kanaldan ekleyin ve servisi başlatın.
5. `/api/state` ile durumu doğrulayın.
6. Başarılı açılıştan sonra `DARKPERP_RESTORE_*` satırlarını kaldırın.
   Snapshot yazıcısı dosyayı yeni nonce ile yeniden şifreler; eski pin bir
   sonraki açılışı haklı olarak durdurur.

L1 modunda boot, snapshot'ın settle edilmiş root'unun zincirdeki finalized
`currentStateRoot` ile birebir eşleşmesini ister (`main.rs` boot continuity).
Son finalized settle'dan eski bir yedek reddedilir; tek istisna, journal'da
ileri sarılabilecek tek penceredir. Bu yüzden en yeni yedek seçilir. Settle'dan
hemen sonra alınmış bir yedek, o settle finalize olana kadar reddedilebilir.

### RTO ve RPO nasıl ölçülür

- **RTO:** Restore kararından, yeni hostta `/api/state`'in beklenen
  `settlement_health` ile yanıt verdiği ana kadar geçen süre. Adım adım
  kaydedilir: makine hazırlığı, yedek indirme, anahtar teslimi, boot doğrulaması.
  Yukarıdaki `copy_to_verified_state_seconds` bunun yalnız son adımıdır.
- **RPO:** Kayıp penceresi, son yedekten (timer 30 dakika) arıza anına kadar
  geçen süredir. Canlı hostun kendi kaybı, snapshot aralığıyla (30 s) sınırlıdır.
  Yalnız şu onaylar diske yazıldıktan sonra verilir:
  - deposit yetkilendirme/rota,
  - hesap kurtarma,
  - iptal,
  - wind-down.

  Emirler ve withdrawal istekleri ise diske yazılmadan onaylanır; son
  snapshot'tan sonraki onaylar kaybolabilir.

Hedef RTO/RPO değerleri henüz belirlenmedi.

**İlk ölçüm (16 Ekim 2026, demo modu):** Linux ops host'undan alınan yedek,
bir macOS makinesinde pinlerle restore edildi. Ölçülen RTO 9,6 s:

| Adım | Süre |
|---|---|
| Aktarım | 3,3 s |
| Anahtar teslimi | 1,3 s |
| Boot ve status | 5,0 s |

Arıza tespiti ve makine hazırlığı bu süreye dahil değildir. Bu tatbikatta RPO
0'dır, çünkü yedek düzgün bir durdurmadan sonra alındı. Ayrıntılar:
[tatbikat kaydı](audits/2026-10-16-g5-restore-alarm-drill/README.md). L1 ve pending tx
uzlaşması L1 modu gerektirir; bu nedenle prover ve attestation kapılarına
bağlıdır.
