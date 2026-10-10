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

On iki reddetme durumu ayrıca çalışır: eksik state ayarı, eksik dosya, yalnız pin
ile eksik dosya, bozuk mode/hash ayarı, yanlış seed, kesik/tahrif edilmiş snapshot,
eski veya yanlış checkpoint, `0` ile pin'i devre dışı bırakma girişimi ve dosya
yerine dizin. Reddedilen mevcut dosya byte-byte korunur; eksik dosyanın yerine
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
