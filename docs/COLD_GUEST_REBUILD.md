# Reviewed SP1 guest: temiz ortamda yeniden derleme

## Amaç ve kabul sınırı

`cold_rebuild_reviewed_guest.py`, mevcut ARM64 Mac tarifini yeni Cargo cache,
HOME, geçici dizin ve build target ile çalıştırır. Yerel kurulu SP1 toolchain'i
kullanmaz: resmi `succinct-1.93.0-64bit` arşivini bağımsız SHA-256 piniyle açar.
Tüm guest kaynakları, ELF ve program key `REVIEWED_GUEST` pinlerinde kalır.

Başarı ölçütü derlenen ELF'in SHA-256 değerinin
`a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df`
olmasıdır. Beklenen boyut 535904 bayttır. Başarıya ulaşmak için ELF, kaynak,
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

Tek istisna guest'in commit ile pinlenmiş git bağımlılığıdır: Succinct'in
tiny-keccak 2.0.2 yaması (`patch-2.0.2-sp1-6.0.0` etiketi, SP1 >= 6.0.0 ve < 6.2
için). zkVM hedefinde keccak-f'i SP1'in `KECCAK_PERMUTE` precompile'ı ile çalıştırır;
host kod yolu değişmez. Kimliği `check_sp1_release.GUEST_GIT_DEPENDENCY` içindedir:

```text
repository: https://github.com/sp1-patches/tiny-keccak
commit:     957430a459f7a2332ab5bab4a12f9b473bb95c87
kaynak ağacı SHA-256 (33 dosya): 6bff63bc9c6a4cc1405d13a824992d3a4485f9b810bda9fe817571710af20b9d
```

Guest manifest'i bu bağımlılığı yalnız `[patch.crates-io]` altında bu URL ve
`rev` ile almalı, lock'taki kaynak da tam bu URL ve commit olmalıdır. Başka git
kaynağı, başka commit, tag/branch ile seçim, checksum taşıyan git girdisi veya ikinci
bir git paketi reddedilir (`check_sp1_release.py`, `registry_inventory`). `cargo fetch`
bu commit'i yeni cache'e klonlar ve checkout eder. Cache'in `git/` dizininde yalnız bu
bağımlılığın veritabanı, tek checkout'u ve Cargo'nun `CACHEDIR.TAG` işaretçisi
bulunabilir. Checkout'taki dosyalar (`.git` meta verisi ve `.cargo-ok` hariç, symlink
yok) yukarıdaki kaynak ağacı özetiyle eşleşmelidir; özet, `{yol: sha256}`
haritasının sıralı JSON'unun SHA-256'sıdır. Bu kontrol de derlemeden önce ve sonra
yapılır. cargo-audit git kaynaklı bu paketi lock'taki haliyle crates.io danışma
kayıtlarıyla eşleştirmez; kimliğini commit ve kaynak ağacı pini taşır. Bu yüzden
`a11-release-evidence.yml` guest lock'unu bir kez daha denetler: bu paketi upstream
crates.io kimliğiyle yazan bir kopya (`check_sp1_release.py --upstream-audit-lock`)
`cargo audit`'ten geçer.

Asıl compile `--locked --offline` ile çalışır. Bu Cargo'nun offline modudur;
process seviyesinde ağ sandbox'ı değildir. Bağımlılık build script'leri veya
compromised host için tam izolasyon iddia edilmez.

## Kontrollü normalizasyon

Önceki reviewed tarifteki iki workspace crate metadata değeri ve checkout yolu
korunur. Ayrıca yeni Cargo cache yolu, reviewed ELF'te gömülü registry ve git
checkout yollarına normalize edilir. Git checkout dizininin adı
(`git/checkouts/tiny-keccak-39e1bab27f4c71da/957430a`) Cargo'nun URL özetinden ve
kısa commit'ten gelir; aynı Cargo sürümü aynı yolu üretir. Dependency crate metadata'sı değiştirilmez; host derlemelerine
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
cloud/GPU hesabı veya wallet gerektirmez. Bu ek workflow zorunlu kontrolleri,
review kararını veya dal korumalarını değiştirmez. Önerilen ruleset şablonu
([.github/main-ruleset.json](../.github/main-ruleset.json)) 12 zorunlu kontrol
listeler (`reviewed guest execution (CPU)` dahil); GitHub'da uygulanan ruleset bu
yeni kontrolü, depo sahibi şablonu ayrıca uygulayana kadar zorunlu kılmaz
([REPOSITORY_POLICY_STATE.md](REPOSITORY_POLICY_STATE.md)).

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
