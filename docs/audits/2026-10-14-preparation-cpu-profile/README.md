# Sabit girdilerle hazırlama CPU gözlemi

GPU’suz yerel ölçüm tamamlandı. Üretim davranışı değişmedi: main.rs yalnız cfg(test) modül bildirimi ekler; yeni modül ve standart kütüphaneli Python CLI test/ölçüm araçlarıdır. Prover client, journal, sequencer, dependency/lock, guest/program, ağ/backend ve korumalar değişmedi. Candidate submission kapalı; PRODUCTION HOLD sürer.

Kaynak BASE `d5d200d83a1e85e4625c66c3ed9fc0462da84b23`; 382 dosyalı current source map `31d74fdd003299a7a64ff505537d50ca40578b552bcea2d8cfcf14ac013df23f`. Source-freeze tüm current public kaynakları bağlar. Dört eski PR65 .bin girdisi değiştirilmeden include_bytes ile kullanılır: normal Seq3105/witness1639byte/4timedop; rollback-resealed Seq3670/witness2062byte/6timedop. Her ikisinde notes0 ve withdrawals0; claim-path veya büyük state maliyeti ölçülmedi.

Apple M4/macOS26.5.1/Rust1.99 release build’inde 11aşama×2girdi×5batch=110 örnek; her batch10çağrı, bir warmup. macOS SDK’nin CLOCK_THREAD_CPUTIME_ID16 ve clock_gettime_nsec_np çağrısı gerçek çalışan Rust test thread’inin CPU nanosaniyesini verir. Instant wall süreleri ayrıca saklanır. Setup, warmup, assertion ve output cleanup dışarıda; input destruction, output-vector push, stub atomic counters/32byte synthetic proof allocation içeridedir. Her output byte/root/receipt kontrolünden geçer; her batch sonunda orijinal Seq/witness byte’ları değişmemiş olmalıdır. Süre eşiği assertion’ı yok; aşamalar örtüşür ve toplanmaz. Batch sürelerinin10’a bölünmesi tek çağrı latency dağılımı değildir.

Release CPU medyanları (µs/çağrı; bu makine ve bu girdiler):

| Aşama | Normal | Rollback/resealed |
|---|---:|---:|
| Snapshot preview kesiti | 59.275 | 31.800 |
| State clone | 0.221 | 0.108 |
| prepare_unproved | 369.492 | 471.738 |
| Ek replay + clock validate | 319.058 | 472.942 |
| Legacy hazırlık + cached stub | 317.833 | 472.158 |
| Clock hazırlık + cached stub | 638.683 | 945.892 |

Küçük girdilerde clone maliyeti ek replay’den çok küçüktür. Sonraki dar inceleme adayı, prepare_unproved sırasında oluşan DerivedRoots’u clock validasyona güvenli şekilde taşımaktır; bu çalışmada uygulanmadı. Normal isolated replay medyanı475µs iken daha sonraki hot prepare/extra örnekleri318–369µs’dır; bunlardan additive veya kesin nedensel tasarruf hesabı yapılmaz. Ölçümler üretim throughput/kapasite, RSS/OOM/input cap, taze proof, gerçek backend/CC veya release kanıtı değildir.

Snapshot preview yalnız mevcut Seq postcard encode→owned decode→kopyada seal_window kesitidir; tam Gw checkpoint/archive I/O ölçümü değildir. Decode’un enclave/retention serde default’ları korunur; original enclave’i geri takıp farklı bir yol ölçülmez. Preview ops/pre-state/counter immutable kalır. Clock totals gerçek prove_and_prepare yolunu kullanır; cached client constructor’da commitment’i hesaplar, callback içinde replay/hash/proving yapmaz. Clock invalid ise prove callback sayısı0’dır. Synth proof yalnız diagnostic byte kontrolüdür.

Doğrulama: actual release Rust2PASS/0FAIL/0IGNORE;110distinctrows. Format ve clippy(-Dwarnings) geçti. Python CLI raw footer/110closedrows/fixedmetadata/duplicatefields/numerictypes doğrular; bir örneği eksik bırakılan kontrol exit2 ile reddedildi ve output oluşmadı. Linux CI yalnız platformdan bağımsız correctness testini çalıştırır; macOS CPU testi cfgmacos+ignore ile açık çağrı gerektirir.

```sh
cargo test --release -p gateway --bin gateway --locked cpu_profile_tests -- --include-ignored --test-threads=1 --nocapture
python3 scripts/local-verification/summarize_preparation_cpu.py --log /path/to/fresh/cpu.log --profile release --output /path/to/fresh/summary.json
```

İlk build Python3.9.6 seçimiyle tomllib/Python3.11+ preflight’ında durdu ve test kabulü değildir; raw kayıtlar historical/ altında korunur. Debug sonuçları 7d097b5e test-modül cut’ına aittir; son opaque-input-barrier/source382 release ölçümünün yerine geçmez. Release derlemesinde rust-objcopy/libLLVM stripping uyarıları rawstderr’de tutulur; optimized executable gerçekten çalıştı ve testler geçti. Global toolchain değişikliği veya yayımlanmış binary üretimi yapılmadı.
