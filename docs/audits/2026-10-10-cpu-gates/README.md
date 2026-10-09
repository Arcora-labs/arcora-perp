# Arcora Perp: GPU'suz güvenlik ve deployment kontrol paketi

**Tarih:** 10 Ekim 2026
**Dal:** `fix/cpu-release-gates-20261010`
**Başlangıç commit'i:** `1a900dd6f370b4b1535865f52395ea8f87cd3a9c`
**Karar:** CPU paketi doğrulandı. Production **RELEASE HOLD** devam ediyor.

## Tamamlanan işler

### 1. Karşılıklı attestation oturumunun güvenliği

`dh_shared()` artık hataya açık X25519 eş anahtarlarının ürettiği katkısız,
tamamı sıfır ortak sonucu `SharedSecret::was_contributory()` ile reddeder.
`Result` ve `AttestError::NonContributoryKey` gateway/prover çağrılarına taşındı.
Üretim kontrolü sabit bir anahtar kara listesine değil, hesaplanan sonuca dayanır.

Regresyonlar yedi düşük mertebeli kodlama ile bunların yüksek-bit eşlerini,
14 anahtarı iki yönde ve dört farklı yerel özel anahtarla doğrudan 56 durumu kapsar.
Test attestor'u ölçümü ve verilen eş anahtarı önce bağlar; reddin nedeni yanlış
nonce değildir. Düzeltmeden önce iki yönde de hatalı oturumlar türetilebildiği
kayıt altındadır. Bu, çalışan canlı NVIDIA attestation'a saldırı gösterimi değildir:
mevcut NVIDIA backend hâlâ fail-closed stub'dır.

Süresi dolmuş `not_after` ile oturum türetme de engellendi. Kontrol I/O ve
attestation doğrulamasından sonra, türetmeden hemen önce yapılır. Mevcut kabul
sınırı korunur: `now_ms <= not_after_ms`. KDF, transcript sırası, token biçimi ve
geçerli test oturumunun byte çıktısı değişmedi.

### 2. Gizli anahtarların bellek yaşam süresi

Standalone prover'ın Clippy kontrolü mevcut bir hatayı ortaya çıkardı:
`drop(pv_sk)` yorumlarda silme vaat etmesine rağmen `x25519-dalek` için varsayılan
özellikler kapalı, `zeroize` özelliği ise açık değildi. Uyarı bastırılmadı.
Attestation bağımlılığı artık silen `Drop` özelliğini açıkça ister.

Gateway/prover'ın sahip olduğu IKM ve kopyalanmış DH tamponları `Zeroizing` ile
korunur. IKM anahtar kurulunca bırakılır; DH tamponu türetme sonunda veya hata
çıkışında bırakılır. Test, iki dalek sır tipinin silen destructor gerektirdiğini ve
açık `Zeroize` çağrısının test anahtarını sıfırladığını denetler. Bu, bütün süreç
belleğinin, tüm olası derleyici kopyalarının veya SIGKILL sonrası belleğin silindiği
iddiası değildir.

Mevcut paket sürümleri yükseltilmedi. Workspace lock'una `zeroize_derive 1.5.0`
eklendi; aynı sürüm standalone prover lock'unda zaten vardı. Diğer lock farkları
etkinleşen bağımlılık bağlarıdır. Reviewed guest'in 21 kaynak pini, guest lock'u,
ELF ve program key değişmedi.

### 3. Deployment için açık operatör/politika bağları

Manifest'in isteğe bağlı `operator_policy` alanı altı yetkili adresini ve beş
settlement parametresini açıkça bağlar. `observe-target --require-operator-policy`
eksik politikayı RPC okumalarından önce reddeder. Politika verilmişse karşılaştırma,
bu bayrak olmasa da zorunludur; eksik/bozuk alanlar için varsayılan değer atanmaz.

On bir politika getter'ı, altı gerçek sözleşmenin runtime ve mevcut bağlarıyla aynı
finalized blok hash'inden okunur. Toplam **23 bağ** kontrol edilir. Zincir/kaynak
son kontrolü başarısızsa politika eşleşmesi başarılı gösterilmez.

`operator_and_settlement_policy_matches` yalnızca eşleşmeyi bildirir.
`operator_and_settlement_policy_approved` **false** kalır: deklarasyonla eşleşme,
bağımsız güvenlik veya ekonomik politika onayı değildir. Açıkça yazılmış sıfır
adres/değerler ifade edilebilir, fakat güvenli sayılmaz. Eski config'ler gözlem
modunda kullanılabilir; politika eşleşmesi iddia edemezler.

### 4. RPC/JSON belirsizliklerinin reddi

Manifest/config ve target RPC parser'ı yinelenen JSON anahtarlarını ve
`NaN`/`Infinity` değerlerini reddeder. RPC hata çıktısı kullanıcı verisini veya
sağlayıcı yanıtını dışarı taşımaz. Okuma allowlist'i ve finalized/hash zorunluluğu
korundu. Yeni 15 politika/transport testi mevcut CI işine eklendi.

## Doğrulama sonuçları

| Kontrol | Sonuç |
|---|---|
| Son tam Rust workspace testi | **874 PASS, 0 FAIL, 16 IGNORE** |
| Son Python paketi, gerçek yerel Anvil dahil | **109 PASS, 0 SKIP** |
| Standalone prover admission testleri | **6 PASS**, kapsam dışı 3 test filtrelendi |
| Workspace Clippy, tüm hedefler, `-D warnings` | PASS |
| Standalone prover tüm hedefler typecheck ve Clippy | PASS |
| Workspace ve standalone format kontrolü | PASS |
| SP1 manifest/lock release guard | PASS |
| Reviewed guest kaynak bağları | 21/21 değişmedi |

Ignored Rust testleri depodaki mevcut opt-in testlerdir; bu paket onları etkinleştirmez
veya geçmiş olduklarını iddia etmez. 46 attestation testi workspace toplamına
dahildir, ayrıca toplanmamalıdır. Python toplamı yerel Anvil testini içerir.
Standalone testleri gerçek SP1 SDK bağımlılığı ile derlendi; yalnızca guest build
atlandı. İzole host target'a **hash'i doğrulanmış gerçek reviewed ELF** kopyalandı,
boş ELF/dummy verilmedi. **Yeni proof üretilmedi.**

Yerel Anvil, testin açtığı yeni 127.0.0.1 sürecidir. Gerçek altı sözleşme gerçek
constructor'larla dağıtıldı; token mock'tur. Doğru konfigürasyon geçti. Yanlış
governance, yanlış challenge bond ve gerçekten dondurulmuş SP1 route reddedildi.
Kullanıcı RPC'si, mevcut node, gerçek cüzdan anahtarı veya kamu zinciri seçilemez.

Düzeltme öncesi kanıt: handshake regresyonunda 4 PASS/3 beklenen FAIL; duplicate
JSON regresyonunda 3 beklenen FAIL; standalone Clippy'de eksik silen Drop hatası.
Son kontrollerde bunlar çözüldü. İlk yerel denemelerdeki TMPDIR/protoc/izole ELF
araç sorunları giderildi. Standalone bağımlılıklarında mevcut `vtpm.rs` deprecation
uyarıları ve `proc-macro-error2` gelecek-uyumluluk uyarısı vardır; bu uyarılar paket
sürümü yükseltilerek veya lint bastırılarak gizlenmedi.

## Komutlar ve kanıt sınırı

Python 3.12, Cargo/Rust 1.99.0, mevcut Foundry araçları ve önceden indirilmiş
protoc 29.3 kullanıldı. Ham yerel kayıtlar `target/cpu-gates-20261010/` altındadır.
Paylaşılan kopyalarda kullanıcı home/protoc yolu ve satır sonu boşlukları normalize edilmiştir;
ham ve paylaşılan SHA-256 değerleri `verification.json` içinde bulunur.

```sh
cargo +1.99.0 test --workspace --locked --offline
cargo +1.99.0 clippy --workspace --all-targets --locked --offline -- -D warnings
cargo +1.99.0 fmt --all --check
cargo +1.99.0 fmt --manifest-path crates/prover-service/Cargo.toml -- --check
ARCORA_RUN_MANIFEST_ANVIL=1 python3.12 -m unittest discover \
  -s scripts/local-verification -p 'test_*.py' -v
python3.12 scripts/local-verification/check_sp1_release.py
```

Standalone komutları `SP1_SKIP_PROGRAM_BUILD=true`, `CARGO_NET_OFFLINE=true`,
`PROTOC=<mevcut-protoc>` ve izole `CARGO_TARGET_DIR` ile çalıştırıldı. Bu target'ın
`elf-compilation/riscv64im-succinct-zkvm-elf/release/perp-core-guest` dosyası
reviewed fixture'dan doğrulanarak alınmalıdır.

```sh
cargo +1.99.0 check --locked --offline \
  --manifest-path crates/prover-service/Cargo.toml --all-targets
cargo +1.99.0 clippy --locked --offline \
  --manifest-path crates/prover-service/Cargo.toml --all-targets --no-deps -- -D warnings
cargo +1.99.0 test --locked --offline \
  --manifest-path crates/prover-service/Cargo.toml --bin prover-service admission::tests
```

Feature etkinleştirilirken iki host lock'u offline çözüldü; sürüm değişikliği
olmadığı ayrıca karşılaştırıldı. Guest'in ayrı lock'u değişmedi. Buradaki manifest
ve Anvil gözlemi test anının tarihsel kanıtıdır; yeni source commit veya gerçek
deployment için tekrar üretilmelidir. Hash kayıtları bağımsız inceleme/imza değildir.

## Açık kalan kabul kapıları

Gerçek dört wallet witness için yeni SP1 proof ve tam gerçek verifier/clock/
settlement/claim fon döngüsü; hedef deployment ve çalışan servis kimlikleri;
bağımsız makinede tekrarlanabilir build; gerçek NVIDIA CC evidence, nonce/measurement
bağları ve güvenli key release; ölçülmüş proof kapasitesi/finalite; gerçek exit,
farklı makineye restore ve RTO/RPO tatbikatı; oracle güven modeli ve proof içinde
matching fairness; bağımsız protokol/custody/ekonomik güvenlik incelemesi açıktır.

Bu ilk paket GPU'suz yapılabilecek her işin bitirildiği anlamına gelmez. Sonraki
CPU paketi için kurtarma/exit tatbikatı otomasyonu ve bağımsız build hazırlığı
önceliklidir; oracle/fairness guest değişiklikleri reviewed proof kimliğinden ayrı
planlanmalıdır. NVIDIA stub'ı değiştirilmedi. Main'e merge, branch-protection
gevşetme, production deploy, kamu zincirinde işlem veya fon/state migration yapılmadı.

**Sonuç: İncelemeye sunulabilir CPU düzeltmeleri; production RELEASE HOLD.**

## Teknik kaynaklar

- RFC 7748, §6.1 ve §7: https://www.rfc-editor.org/rfc/rfc7748
- Dalek 2.0.1 özellikleri: https://docs.rs/crate/x25519-dalek/2.0.1/features
- Dalek contributory kontrolü: https://docs.rs/x25519-dalek/2.0.1/x25519_dalek/struct.SharedSecret.html
