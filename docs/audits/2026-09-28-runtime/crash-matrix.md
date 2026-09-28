# S6-02 — dosya kalıcılığı için gerçek SIGKILL matrisi

**Yerel süreç çökmesi kapsamı geçti: 4 test, 21 ayrı alt süreç, 21 doğrulanmış SIGKILL. S6-02 bütünü hâlâ PARTIAL.** Son koşu 28 Eylül 2026'da macOS üzerinde, izole çalışma ağacında çalıştı. Gerçek `write_atomic`, journal okuma/yazma, snapshot açma ve boot recovery kodu kullanıldı; gerçek gateway HTTP süreci veya zincir çalıştırılmadı.

Kanıt: [tam komut ve kaynak kimliği](crash-matrix/snapshot-sigkill-21.json), [ham çıktı](crash-matrix/snapshot-sigkill-21.log), [21 vaka ve SHA-256 manifesti](crash-matrix/snapshot-sigkill-21.cases.json). Koşu sırasında kaynak kimliği değişmedi; `exit_code=0`, `4 passed; 0 failed`, test süresi 1,87 saniye. Önceki 16 vakalık deneme `snapshot-sigkill.*` dosyalarında korunur; son kabul kanıtı `snapshot-sigkill-21.*` dosyalarıdır.

## Doğrulanan durumlar

| Durum | SIGKILL sayısı | Restore kabulü |
|---|---:|---|
| Mevcut snapshot → yeni snapshot | 5 | Rename öncesi eski şifreli dosya, rename sonrası yeni şifreli dosya byte düzeyinde aynı; açılan tüm state beklenen eski/yeni state ile aynı. Geride kalan geçici dosya sonraki yazmayı engellemiyor. |
| Journal yok → stage 1 journal | 5 | Rename öncesi journal yok; sonrası doğrulanabilir stage 1. Önceki pre-seal snapshot byte düzeyinde korunuyor; yeniden seal, aynı state root ve withdrawal proof setini üretiyor. |
| Stage 1 journal → prepared journal | 5 | Eski stage 1 veya eksiksiz yeni prepared payload okunuyor. Stage 1 rollback sonrası yeniden üretim aynı root/proof setini veriyor. Prepared ve ilerlememiş zincir sayacı `KeepJournal`; state ve journal değişmiyor. |
| Prepared journal → commit snapshot | 6 | Kalıcı prepared journal ile snapshot yazımı arasındaki boşluk ve snapshot'ın beş yazma sınırı. Restore tüm state olarak eski sealed veya yeni committed durumla aynı. Eski zincir gözlemi journal'ı koruyor; eşleşen landed gözlemi bir kez roll-forward veya mutasyonsuz stale çözümü üretiyor. Resolution snapshot'ı kalıcılaştıktan sonra journal siliniyor; ikinci restore aynı withdrawal proof setini taşıyor. |

Beş dosya sınırı: geçici dosya açıldı / yazma başlamadı; `write_all` döndü / dosya `sync_all` başlamadı; dosya `sync_all` döndü / rename başlamadı; rename döndü / üst dizin `sync_all` başlamadı; üst dizin `sync_all` döndü / fonksiyon dönmedi.

Çocuk test süreci ilgili sınırda stdout pipe'a işaret yazıp flush eder; stdin pipe'ında bekler. Ebeveyn bu işareti aldıktan sonra yalnızca elindeki `Child` handle'ını öldürür, reap eder ve çıkış sinyalinin 9 olduğunu doğrular. 15 saniyelik timeout yalnızca bozuk testin sonsuza dek beklemesini engeller; kesme anını seçmez. Testlerin kendilerine ait rastgele geçici dizinleri ve işaret dosyaları vardır; başka süreç veya state yolu öldürülmez/silinmez.

[Writer hook'ları](../../../crates/gateway/src/snapshot.rs) ve [worker/matris](../../../crates/gateway/src/snapshot_crash_tests.rs) yalnızca `cfg(all(test, unix))` altında derlenir. Üretim yoluna ortam değişkeniyle açılabilen failpoint eklenmedi. Alt süreç worker'ı sıradan test koşusunda `ignored`; dört ebeveyn test onu tam adıyla başlatır. Bu tur `main.rs` veya `rollback_journal.rs` davranışını değiştirmedi.

## Tekrar çalıştırma

```sh
python3 scripts/local-verification/run_check.py \
  --output-dir docs/audits/2026-09-28-runtime/crash-matrix \
  snapshot-sigkill-21 -- \
  env CARGO_TARGET_DIR=/tmp/arcora-gateway-target CARGO_BUILD_JOBS=2 \
  cargo test --locked -p gateway --bin gateway sigkill_ -- \
  --test-threads=1 --nocapture
```

Kaynak SHA-256:

| Dosya | SHA-256 |
|---|---|
| `snapshot.rs` | `aea94834c18039da544ce5025759a207bb9459c649578be8b671e0afc5e48316` |
| `snapshot_crash_tests.rs` | `1b1547490cd3fd64bd9fa2d66019214c0c17c7061d8d9922f0a1c684a3f47b48` |
| `rollback_journal.rs` | `9f7c73825e98d1262f33acf68ebc67aae9de004463a95fad99bd4208069dcd11` |
| `main.rs` — çağrılan recovery yardımcılarının koşu anındaki sürümü | `03cf6023295e9d44b1df84fcd3bb6114ab538861bd3d20434e054128386d6448` |

## Kalan sınırlar

SIGKILL kernel disk önbelleğini yok etmez. Bu kanıt güç kesintisi, kernel çökmesi, dosya sisteminin `fsync` garantisi, disk arızası veya syscall'ın içindeki kısmi yazma garantisi değildir. Rename sonrası yeni dosyanın gözlenmesi süreç çökmesi sonucudur; dizin sync öncesi güç kesintisi garantisi olarak okunmamalıdır.

Prepared→commit aralığı gerçek persistence/recovery yardımcılarıyla test edildi; zincir gözlemleri sentetik ve hazırlık `MockProverClient` ile yerel native replay'dir. A06, SP1 guest, gerçek proof backend veya işlem yayını çalıştırılmadı. Gerçek gateway'nin kabul edilmiş HTTP/WS/settle işlerini sinyalle drain etmesi ayrı kanıt gerektirir. Gerçek mevduat/çekim/claim, farklı dosya sistemleri ve bütün settlement yaşam döngüsünün uçtan uca crash matrisi açık kalır. Bu sonuç üretim fon güvenliği ya da S6-02 tam kapanışı sayılmaz.
