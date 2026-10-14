# seal_window baseline sahipliği — PR65 yayın öncesi kanıt

`seal_window` içindeki iki tam `State` kopyası bire indirildi. Eski pencere başlangıç state'i artık witness'a sahipliğiyle taşınıyor; Counter B arttıktan sonra sonraki başlangıç state'inin kopyası hazırlanıp `mem::replace` ile yer değiştiriliyor. Manifest kurulumu, ops sırası ve normal successful-path witness/wire davranışı korunuyor.

Bu paket yerel doğrulama aşamasını gösterir. **PR CI ve merge sonrası main kontrolleri henüz BEKLEMEDE; PRODUCTION RELEASE HOLD.** Beklenen tam gateway CI sonucu 763 PASS / 0 FAIL / 24 IGNORE yalnız iki ek normal testten türetilmiştir; bu yayının gerçek CI sonucu olarak sunulmaz.

| Kimlik | Kayıt |
| --- | --- |
| Başlangıç commit'i | `c387dbe2de0392a996d6028f745f81fa963809dd` |
| Final kaynak | 380 dosya / `1ed0b332badb55ea9c64d673cdf0955aa67fdcb9cc232a4ff613171a0d9392e3` |
| Final source-freeze SHA-256 | `2860a29f0134b500ee3dd1a6d18c6757435e776f976160fac4421552bb85d240` |
| Eski sequencer blob SHA-256 | `04ea88b2e96ff6407496aadb5ff110c549d40a333372234c1648551fbb65487a` |
| Eski/yeni fixture builder SHA-256 | `ea0c311afa366d800dbde696e094d9a691e17a6897748cd8d0ff894ed4133669` |
| Paket | 58 mapped dosya + README + ledger = 60 fiziksel dosya |

## Gerçek eski davranıştan referans

[old_export/result.json](local/old_export/result.json) gerçek eski sequencer kaynağında yalnız geçici ignored exporter'ı seçerek koştu: **1 PASS / 0 FAIL / 0 IGNORE**. Bu, eski gateway suite'inin tamamının koşulduğu anlamına gelmez. Eski kaynak, test harness'ı ve test modülü eklenmiş parent dosyası `baseline-export/*.txt` olarak korunur.

[old-output-map.json](baseline-export/old-output-map.json) 10 normal ve 11 rollback satırının 21 tam binary çıktısını uzunluk/SHA-256 ile bağlar. Bunlar aynı klasördeki `.bin` dosyalarıdır. Final normal testler `include_bytes!` ile bütün bytes'ı karşılaştırır; yalnız hash karşılaştırması veya yeni koddan üretilmiş beklenti kullanılmaz. [golden-integration.json](baseline-export/golden-integration.json), builder bytes eşitliğini ve geçici exporter'ın final kaynaktan kaldırılmasını kaydeder.

Fixture'lar sabit enclave seed/epoch/measurement, iki fonlanmış hesap, sabit saatli gerçek oracle publisher imzaları, gerçek fill'ler, signed receipt doğrulaması ve açık Expired rejection kullanır. Pure Sequencer API'sine plaintext Order verilir; gateway order-ingress imzası veya canlı kullanıcı/servis kabulü iddiası yoktur. `Gw::boot`, wall clock, ağ, backend, proof ve GPU kullanılmaz.

İlk normal senaryo serialized witness, legacy tuple, DPCLK2 tuple ve tam serialized Sequencer kayıtlarını karşılaştırır. Sonradan live Deposit/tick mutation eski witness'ı değiştirmez; ikinci pencerenin baseline'ı post-bump Counter B değerini taşır. İkinci senaryo müdahil tick'lerden sonra rollback/reseal yapar: aynı pencere ID'si, değişmeyen Counter A, eski + müdahil op/ordered/rejected sırası, tarihsel oracle hash'leri ve tick→window map'leri korunur. Bağımsız `derive_roots` replay'i canlı root ile eşittir. Serialized durum eşitliği serde tarafından atlanan runtime alanların kapasite eşitliğini kanıtlamaz.

## Yerel kontroller ve tarihsel hazırlık hatası

| Final kaynakta gerçek kontrol | Sonuç |
| --- | --- |
| ownership_v2 | 2 PASS / 0 FAIL / 0 IGNORE |
| client | 48 PASS / 0 FAIL / 0 IGNORE |
| sequencer lib | 33 PASS / 0 FAIL / 0 IGNORE |
| sequencer spine | 31 PASS / 0 FAIL / 0 IGNORE |
| format | exit 0, PASS |
| clippy | exit 0, PASS |

Bu filtreler örtüşür; test adetleri toplanarak full suite sonucu çıkarılmaz. Sekiz koşunun stdout/stderr/result kayıtları [local-summary.json](local-summary.json) ile bağlıdır.

**HISTORICAL — kabul edilmeyen hazırlık koşusu:** [local/ownership/result.json](local/ownership/result.json), placeholder beklentiler henüz gerçek eski çıktıya bağlanmadan 0 PASS / 2 FAIL / 1 IGNORE ve exit 101 verdi. Exporter JSON işaretleyicisinin test adı sonrasında gelmesi nedeniyle ilk parser hazırlığı da durdu. Ham kayıtlar değiştirilmedi; marker ayrıştırması düzeltilip tam eski bytes entegre edildikten sonra ownership_v2'nin gerçek 2/0 sonucu alındı. İlk başarısız kayıt PASS olarak sunulmaz.

[Bağımsız scoped review](independent/scoped-review.json) mevcut patch, public fixture'lar ve kayıtları salt okunur olarak inceledi; Cargo/test çalıştırmadı.

## Koruma ve kapsam

[baseline-summary.json](baseline-summary.json), 4 748 girdili tam approved baseline'ın SHA-256'sına ve başlangıç 379-source cut'ına referans verir. Büyük tam harita ignored target kaydında korunur; Git paketinde yeniden çoğaltılmaz. [frozen-source-preservation.json](frozen-source-preservation.json) gerçek koruma koşusunda 4 746 eski girdiyi, 32 pin'i, 8 manifest/lock'u, 9 program/proof artifact'ini ve üç dirty checkout'taki 82 public dosyayı doğruladı. `docs/ACTIVE_WORK.md` yalnız eski 53 373-byte prefix korunarak append edildi; küçük readback pakettedir. Yayın/stage öncesi yeni metadata listesiyle ayrı son koruma kontrolü gerekir.

Değişiklik bir eski baseline'ın clone allocation'ını kaldırır. Taşınan State içindeki Vec/tree-index capacity'leri korunur; allocation sırası değişir. Counter artışı replacement hazırlığından önce kalır. **OOM/panic recovery eşdeğerliği, ölçülmüş CPU/RSS kazancı, aggregate witness input sınırı, production throughput veya proving kapasitesi garantisi verilmez.** Journal/replay/rollback'taki diğer clone'lar değiştirilmedi.

Önceki plaintext output bütçesi korunur; bu çalışma input hazırlama allocation'larının tamamını sınırlamaz. Yeni proof, canlı backend/DPCLK3, CC/key release, zincir settlement/claim, custody/restore ve bağımsız release kapıları açılmadı. Candidate submission kapalı; **PRODUCTION RELEASE HOLD** sürüyor.

[ledger.json](ledger.json) yalnız 58 mapped girdiyi içerir; README ve ledger kendisini bu haritaya eklemez. Her kopya original dosyanın bytes/SHA-256 değerleriyle eşleşir.
