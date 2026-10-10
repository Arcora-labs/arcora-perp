# Arcora Perp: oracle kaynak kabulü güvenlik paketi

Tarih: 10 Ekim 2026
Dal: `fix/oracle-feed-safety-20261010`
Başlangıç main: `0bcb0dd901da72422b933537693d636db205c176`
Karar: Yerel CPU doğrulaması tamamlandı. **Production RELEASE HOLD** devam eder.

## Merge ve kapsam

PR #37, tam head SHA'sı kontrol edilerek 17/17 başarılı kontrolden sonra normal
merge yöntemiyle main'e alındı. Merge commit'i `0bcb0dd901da72422b933537693d636db205c176`.
Review şartı, required CI, force-push ve silme korumalarında değişiklik yapılmadı.
Bu yeni paket oracle-feed ve gateway'in host-side fiyat kabul sınırını güçlendirir.

## Tamamlanan düzeltmeler

**Gerçek kaynak zamanı korunur.** Eksik/sıfır timestamp yerel saatle doldurulmaz,
gelecek zaman şimdiye kırpılmaz. Gateway stale ama ilerleyen bir veri serisini
her yanıtta yeniden imzalayıp taze hale getirmez. Gelen imza, source-age ve market
sınırları fiyat/state değiştirilmeden kontrol edilir; kabul edilen transcript
byte-byte saklanır. Receipt zamanı yalnız telemetry olarak tutulur. Yanlış
publisher, unknown market, bozuk confidence ve out-of-order/duplicate veri
önceki fiyatı veya receipt zamanını yenilemez.

**Yanıt kimliği doğrulanır.** HTTP200, sayısal code0, doğru method, tek satır ve
istenen instrument zorunludur. Typed decoder kritik alan tekrarlarını, kaçışlı
aynı alan adlarını, eksik/bozuk tipleri ve trailing JSON'u reddeder. Ek kritik
olmayan metadata yok sayılabilir; bütün bilinmeyen alanların reddi iddia edilmez.

**Eksik book tamamlanmış gibi gösterilmez.** Bid/ask artık last ile doldurulmaz.
Eksik/null/negatif/bozuk veya crossed book reddedilir. Çift işaretle pozitifleşen
fiyat parser hatası ve i128 book-midpoint taşması giderildi. Sekiz basamak sonrası
kesme ve normal girdinin imza/değer çıktıları korunur.

**HTTP okuması sınırlıdır.** Ticker64KiB/candle1MiB gerçek bayt sınırı; no-redirect;
5s yapılandırılmış timeout; gövde/URL sızdırmayan sabit hata kategorileri kullanılır.
Gerçek loopback ureq testleri redirect hedefinin hiç çağrılmadığını, büyük chunked
ve EOF gövdeleri ile yarım veya duran yanıtların reddedildiğini doğrular.
Bu, sistem DNS davranışı veya dış ağ izolasyonu için mutlak garanti değildir.

**Production fiyat uydurmaz.** Production başlangıcı ve restore sırasında runtime
fiyat kabulü taze kaynak gelene kadar geçersizdir. Tick simülasyonu production'da
çalışmaz; normal demo simülasyonu korunur. Bilinen public dev oracle signer açıkça
config'e yazılmış olsa bile production'da reddedilir. UTF-8 olmayan signer ayarı
unset gibi ele alınmaz. Gerçek servis ayarlarına/anahtarlarına dokunulmadı.

## Son testler

| Kontrol | Sonuç |
|---|---|
| Tam Rust workspace | **915 PASS, 0 FAIL, 17 IGNORE** |
| Gateway, workspace toplamına dahil | **490 PASS, 16 IGNORE** |
| Oracle-feed default özelliği | **15 PASS** |
| Oracle-feed HTTP özelliği | **28 PASS** |
| Python, gerçek yerel Anvil dahil | **136 PASS, 0 SKIP** |
| Gerçek gateway restore tatbikatı | **17 güvenli ret + 2 restore** |
| ACK/crash tatbikatı | **9 PASS, 27 SIGKILL** |
| Workspace Clippy tüm hedefler, -D warnings | PASS |
| Workspace format kontrolü | PASS |
| Reviewed guest kaynak pinleri | 21/21 değişmedi |

Ayrı oracle koşuları ve gateway sayısı workspace toplamına tekrar eklenmemelidir.
Mevcut ignored testler geçmiş sayılmadı. Baseline'da 7 gateway ve 5 feed regresyonu
beklenen şekilde başarısız oldu; son durumda geçti. Düzeltme öncesi assertion
çıktılarındaki sentetik state dump'ları yayınlanmadı; failure adları/sayıları ve
ham log hash'leri `evidence/baseline-regressions.json` içinde.

Mevcut bir public timestamp testi `12345` kaynak zamanını bugünün saatiyle kabul
ettiriyordu. Yeni doğru freshness kontrolü onu reddetti. Test deterministik
`20000` receipt saatiyle güncellendi; aynı kaynak timestamp, tekrar-ret ve restore
sonrası bilinmeyen freshness kontrolleri korundu. Kontrol devre dışı bırakılmadı.

## Kaynak kimliği ve sınırlamalar

Guest, perp-core, sözleşmeler, proof/public-input biçimi, risk eşikleri ve
snapshot/journal biçimleri değiştirilmedi. SP1 release guard geçti. Cargo lock'ta
yalnız mevcut serde paketinin oracle-feed'e bağımlılık bağı eklendi; paket sürümü,
checksum veya kaynağı değişmedi. Frontend paketi yerelde yeniden çalıştırılmadı;
normal PR CI durumu ayrıca kontrol edilmelidir.

**R06 tek kaynak/tek publisher güven modeli kapanmadı.** Aynı book'un midpoint'i
`backup_twap` alanına yazılmaya devam eder; bağımsız TWAP değildir. Yetkili
publisher'ın tutarlı sahte fiyat imzalayabildiğini gösteren mevcut
`trusted_publisher_can_reprice_primary_and_backup_together` testi değişmeden geçti.
Input doğrulaması kaynak doğruluğu, quorum veya ekonomik manipülasyon direnci
kanıtı sayılmaz. Gerçek çoklu kaynak ve bağımsız publisher modeli ayrı iştir.

Yeni proof, gerçek fon yaşam döngüsü, CC/key release, production rollout, gerçek
servislerle farklı makineye kurtarma veya ekonomik güvenlik incelemesi yapılmadı.
**RELEASE HOLD** ve diğer kabul kapıları sürer. Eksik book/stale/future kaynaklar
artık uygun biçimde reddedildiğinden hatalı feed altında kullanılabilirlik azalabilir.
Saat senkronizasyonu operatör sorumluluğudur; gecikme timestamp onarımıyla gizlenmez.

## Tekrar çalıştırma ve kanıt

```sh
cargo +1.99.0 test --locked --offline -p oracle-feed
cargo +1.99.0 test --locked --offline -p oracle-feed --features http
cargo +1.99.0 test --workspace --locked --offline
cargo +1.99.0 clippy --workspace --all-targets --locked --offline -- -D warnings
cargo +1.99.0 fmt --all --check
cargo +1.99.0 build --locked --offline -p gateway
ARCORA_RUN_MANIFEST_ANVIL=1 python3.12 -m unittest discover \
  -s scripts/local-verification -p 'test_*.py' -v
python3.12 scripts/local-verification/gateway_restore_drill.py \
  --gateway-bin target/debug/gateway --output-dir /tmp/arcora-oracle-restore-FRESH
python3.12 scripts/local-verification/gateway_ack_crash_drill.py \
  --gateway-bin target/debug/gateway --output-dir /tmp/arcora-oracle-ack-FRESH
```

Rust derlemesinin repo-içi TMPDIR ayarı Python testlerine aktarılmadı. HTTP
regresyonları yalnız owned loopback kullanır. Genel gateway demo drill'leri halka
açık fiyat okumaları yapabilir; gerçek fon/proof göndermezler. Dış schema için
ayrıca bir bounded Crypto.com ticker GET yapıldı; bu bir doğruluk/finality kanıtı
olarak sayılmadı. Ayrıntılı sözleşme: `docs/ORACLE_INTAKE.md`.
Ham yerel kayıtlar `target/oracle-feed-20261010/`; kaynak/binary ve yayınlanmış
kanıt hash'leri `verification.json`; log kopyalarında yalnız home yolu ve trailing
whitespace normalize edildi. Baseline state dump'ı yerine özet yayınlandığı açıkça
belirtildi. Başarılı local test, bağımsız güvenlik incelemesi veya final CI değildir.
