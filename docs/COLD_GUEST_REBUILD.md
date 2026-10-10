# Reviewed SP1 guest: temiz ortamda yeniden derleme

## Amaç ve kabul sınırı

`cold_rebuild_reviewed_guest.py`, mevcut ARM64 Mac tarifini yeni Cargo cache,
HOME, geçici dizin ve build target ile çalıştırır. Yerel kurulu SP1 toolchain'i
kullanmaz: resmi `succinct-1.93.0-64bit` arşivini bağımsız SHA-256 piniyle açar.
Tüm guest kaynakları, ELF ve program key önceki reviewed kimliklerinde kalır.

Başarı ölçütü derlenen ELF'in SHA-256 değerinin
`df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5`
olmasıdır. Beklenen boyut 525824 bayttır. Başarıya ulaşmak için ELF, kaynak,
program key veya pin değiştirilmez. Derleme çıktısı fixture'dan kopyalanmaz.

## Araçlar ve bağımlılıklar

Python 3.12, doğrudan Cargo 1.99.0 binary'si ve ARM64 macOS gerekir. SP1 arşivi:

```text
https://github.com/succinctlabs/rust/releases/download/succinct-1.93.0-64bit/rust-toolchain-aarch64-apple-darwin.tar.gz
SHA-256: 8ee4ea0f27efbf73ddfe8a2038ced4c0802fdcf9e1ee109349763b9f4a808cf6
rustc SHA-256: 985c33069083f55ed42b68ef51a8528d0cb1632e43428ffdb5c489306154f964
```

Arşiv pini resmi GitHub release asset metadata'sından alındı; rustc binary pini
önceki reviewed compiler ile karşılaştırıldı. Bu, derleyicinin kaynak kodundan
bağımsız bootstrap edildiği veya upstream'in mutlak güvenli olduğu anlamına gelmez.
Cargo'nun tam sürümü denetlenir, binary hash'i rapora yazılır; Cargo upstream
kurulumuna güven devam eder. Sistem SDK/linker ve işletim sistemi de güven sınırıdır.

Çıktı dizini önceden mevcut olamaz ve checkout dışında olmalıdır. Kullanıcının
CARGO_HOME'u, Cargo profil değişkenleri, wrapper'ları, token'ları, proxy ayarları
ve Rust flags devralınmaz. Checkout ve üst dizinlerindeki Cargo config'leri
reddedilir; guest kaynak/config korumaları ayrıca çalışır.

`cargo fetch --locked` paketleri yeni cache'e indirir. İndirilen **bütün** registry
arşivleri guest lock checksum'larıyla eşleşmelidir; alternatif registry/git kaynağı,
eksik/fazla paket ve duplicate kimlik reddedilir. Açılmış kaynak dosyaları da
arşiv üyeleriyle byte/hash bazında eşleşmelidir. Ek build script/modül ve symlink
reddedilir; yalnız Cargo'nun `.cargo-ok` işaretçisine izin verilir. Bu kontrol
derlemeden önce ve sonra yapılır.

Asıl compile `--locked --offline` ile çalışır. Bu Cargo'nun offline modudur;
process seviyesinde ağ sandbox'ı değildir. Bağımlılık build script'leri veya
compromised host için tam izolasyon iddia edilmez.

## Kontrollü normalizasyon

Önceki reviewed tarifteki iki workspace crate metadata değeri ve checkout yolu
korunur. Ayrıca yeni Cargo cache yolu, reviewed ELF'te gömülü registry yollarına
normalize edilir. Dependency crate metadata'sı değiştirilmez; host derlemelerine
bu hedef normalizasyonu uygulanmaz. Önceden gelen remap argümanları reddedilir.
Her değiştirilmiş compiler çağrısı asıl ve normalize argümanlarıyla kaydedilir.
Bu source-path normalizasyonudur, ELF üzerinde sonradan binary yaması değildir.

## Çalıştırma

Aşağıdaki arşiv yeni bir dosyaya indirilmeli ve aynı pin ile doğrulanmalıdır:

```sh
curl --fail --location --retry 2 --max-time 300 \
  https://github.com/succinctlabs/rust/releases/download/succinct-1.93.0-64bit/rust-toolchain-aarch64-apple-darwin.tar.gz \
  --output /tmp/sp1-reviewed-toolchain.tar.gz
python3.12 scripts/local-verification/cold_rebuild_reviewed_guest.py \
  --cargo "$(rustup which --toolchain 1.99.0 cargo)" \
  --archive /tmp/sp1-reviewed-toolchain.tar.gz \
  --output-dir /tmp/arcora-cold-guest-NEW
```

Script arşiv hash'ini extraction'dan önce doğrular. Cargo yolu doğrudan binary
olmalıdır; rustup symlink/shim bu girişte kabul edilmez. Mevcut dosyalar/target
silinmez. Timeout olduğunda yalnız runner'ın açtığı process group sonlandırılır.
Hata varsa `verification.json` FAIL ve faz bilgisi içerir; kısmi output başarı
olarak kabul edilmez. Ön kontrol hatasında henüz çıktı dizini oluşmamış olabilir.

## GitHub'da bağımsız ortam

`guest-cold-rebuild.yml`, standart `macos-14` ARM64 GitHub-hosted runner kullanır.
Build cache restore etmez; yalnız `contents: read` izni vardır. Repository key,
cloud/GPU hesabı veya wallet gerektirmez. Bu ek workflow mevcut 11 zorunlu
kontrolü, review kararını veya dal korumalarını değiştirmez.

Artifact yalnız ELF, build/fetch logları, compiler çağrıları, doğrulama kaydı ve
runner-context içerir. Toolchain/cache dizinleri artifact'e alınmaz. Runner-context
ortam değişkenlerinden geldiği için tek başına makine bağımsızlığı kanıtı sayılmaz.
GitHub run API'sindeki repository, head SHA, workflow, event, job runner ve başarı
sonucu ayrıca kontrol edilmeli; indirilen artifact'in ELF/hash'leri eşleştirilmelidir.
`machine_independence_asserted` script raporunda bu nedenle false kalır.

## Açık kalanlar

Bu işlem yeni SP1 proof üretmez, guest'i yürütmez, program key için yeni setup
çalıştırmaz, canlı TEE attest etmez veya gerçek fon yaşam döngüsünü doğrulamaz.
Byte-identical build ile operasyonel proof/servis kimliği farklı kabul ölçütleridir.
Linux/Intel üzerinde aynı çıktının üretilmesi de bu ARM64 macOS tarifinin iddiası
değildir. Production **RELEASE HOLD** devam eder.

Tekrarlanabilir CPU guard testleri:

```sh
python3.12 -m unittest discover -s scripts/local-verification \
  -p test_cold_rebuild_reviewed_guest.py -v
```

Kaynaklar: Rust Cargo Book `cargo fetch` ve environment variables belgeleri;
GitHub Docs standart runner tanımları; succinctlabs/rust resmi release asset'i.
