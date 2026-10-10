# Arcora Perp: GPU'suz kurtarma paketi

Tarih: 10 Ekim 2026
Dal: `fix/cpu-recovery-drill-20261010`
Kaynak: `e9e3f23f2f2bb72f15d5755182684bc94c96287a` üstüne ayrı değişiklik paketi.
Durum: Yerel doğrulama tamamlandı. Production **RELEASE HOLD**.

## Yapılanlar

`DARKPERP_REQUIRE_RESTORE=1` artık snapshot olmadan yeni genesis açılmasını
engeller. `DARKPERP_RESTORE_SHA256` seçilmiş şifreli yedeğin hash'ini doğrular;
bu ayar tek başına da restore zorunluluğu getirir. Boş/yanlış ayarlar reddedilir.
Hash doğrulanan baytlar ile MAC/state açma adımına verilen baytlar aynıdır.
Mevcut dosya hata halinde korunur; eksik yedek yerine yeni snapshot yazılmaz.

İlk kurulumun varsayılan fresh-genesis davranışı korunur. Bu paket var olan bir
restore-only ayarını düzeltmekten çok, daha önce bulunmayan açık bir kurtarma
başlangıç sözleşmesi ekler. Önceki binary'de üç yeni ayarın dikkate alınmadan
listener açıldığı, kaynak/binary hash'iyle kayıt altına alınmıştır.

Yeni gerçek süreç tatbikatı; cüzdan adresi, demo bakiye, gerçekleşmemiş emir,
emir iptali ve dayanıklı erişim anahtarı değişimini oluşturur. Kaynak süreç
kapatıldıktan sonra özgün snapshot yolu kaldırılır ve yedek iki farklı boş
klasörden yeniden açılır. Sekiz hesap alanı, iptal durumu ve özgün receipt
korunur. Eski API key 401, kullanılmış recovery imzası 400 alır. Deposit route
ve idempotent iptal doğrulanır.

Eksik dosya/ayar, bozuk ayar, yanlış seed, kesik/tahrif edilmiş snapshot, eski
veya yanlış hash, pin'i 0 ile etkisizleştirme ve dizin kullanımı dahil 12
reddetme durumu sınanır. İki restore örneği ve tüm reddetmeler başarılıdır.

## Son doğrulamalar

| Kontrol | Sonuç |
|---|---|
| Gateway'in bütün testleri | 471 PASS, 0 FAIL, 15 mevcut opt-in IGNORE |
| Python testleri, yerel Anvil dahil | 116 PASS, 0 SKIP |
| Yeni restore tatbikatı | 12 güvenli ret, 2 başarılı yeni-klasör restore |
| Eski ACK/crash tatbikatı | 9 PASS, 27 gerçek SIGKILL çıkışı |
| Gateway tüm hedefler Clippy `-D warnings` | PASS |
| Workspace format kontrolü | PASS |
| SP1 manifest/lock guard | PASS |
| Reviewed guest kaynak pinleri | 21/21 değişmedi |

Tam Rust workspace/fuzz paketi ve frontend paketi bu değişiklikte yeniden
çalıştırılmadı; gateway'in bütün testleri çalıştırıldı. Python toplamı yedi yeni
saf karşılaştırma testini ve mevcut Anvil testini içerir; gerçek restore runner'ı
ayrıca çalıştırıldı. Beş yeni Rust restore-policy testi gateway toplamına dahildir.
Yeni bağımlılık sürümü veya paket eklenmedi: mevcut kilitli `sha2 0.10.9` gateway
manifest'inde doğrudan kullanıma açıldı; lock farkı yalnız bağımlılık bağıdır.

İlk test yazımında statik hata metnindeki boşluk için fazla geniş bir kontrol,
Clippy'nin `as_chunks` önerisi ve Python testlerine repo-içi TMPDIR aktarılması
sorunları giderildi. Son kayıtlar yukarıdaki başarılı sonuçlardır; uyarılar
bastırılmadı. Ham yerel denemeler `target/cpu-recovery-20261010/` altında tutuldu.

## Kanıt sınırları ve açık işler

Bu aynı makinede, yeni dizinlerde yapılan gerçek gateway demo tatbikatıdır;
farklı makine, uzak yedek depolama veya donanım key-release doğrulaması değildir.
Kopyadan HTTP/state doğrulamasına ölçülen iki süre üretim RTO/SLA değildir.
Sınanan onaylı gözlemlerde kayıp olmaması, genel üretim RPO garantisi değildir.

Hash'in güvenilir ve doğru checkpoint kaydından gelmesi gerekir. Eski dosyayla
birlikte eski hash de onaylanırsa bu mekanizma güncelliği belirleyemez. Periyodik
snapshot yazısı yeni nonce/hash üretebilir; pin her başlangıçta seçilen onaylı
dosyaya aittir. Çalışan dosyaya rastgele yeni hash onayı vermek güvenli backup
politikası sayılmaz.

Rollback journal, L1 cursor'ları, gerçek hesap/fon muhasebesi, farklı makineye
taşıma, anahtar temini/rotasyonu, oracle güven modeli, proof içindeki matching
fairness ve bağımsız güvenlik incelemesi açık kalır. Yeni SP1 proof üretilmedi,
NVIDIA CC stub'ı değiştirilmedi; gerçek fonlu exit veya production yayın yapılmadı.

Kullanım ve ayrıntılı sınırlar: `docs/RECOVERY_RESTORE.md`.
Kaynak/binary ve yayınlanan kanıt hash'leri: `verification.json`.
Kanıt kopyalarında yalnız home yolu ve satır sonu boşlukları normalize edildi.
Build güncel çalışma ağacında Cargo 1.99.0 `--locked --offline -p gateway` ile
yapıldı; bu bağımsız tekrarlanabilir build kanıtı değildir.

## Tekrar çalıştırma

```sh
cargo +1.99.0 test --locked --offline -p gateway
cargo +1.99.0 clippy --locked --offline -p gateway --all-targets -- -D warnings
cargo +1.99.0 fmt --all --check
cargo +1.99.0 build --locked --offline -p gateway
ARCORA_RUN_MANIFEST_ANVIL=1 python3.12 -m unittest discover \
  -s scripts/local-verification -p 'test_*.py' -v
python3.12 scripts/local-verification/gateway_restore_drill.py \
  --gateway-bin target/debug/gateway --output-dir /tmp/arcora-restore-FRESH
python3.12 scripts/local-verification/gateway_ack_crash_drill.py \
  --gateway-bin target/debug/gateway --output-dir /tmp/arcora-ack-FRESH
```

Python testleri geçici dosyaların checkout dışında olduğunu sınadığından,
Rust derlemesi için seçilmiş repo-içi TMPDIR Python'a aktarılmamalıdır.
Çıktı dizinleri yeni olmalıdır; var olan raporlar otomatik ezilmez.
