# Dark-perp: 17 Eylül 2026 düzeltme paketi

## Kapsam ve doğrulama

Audit başlangıcı: `5eeb37fde378336fc9daae7c6798637317ffb319`. Uygulama düzeltme commit'i: `f9244ca1eee3bb19e91c46648756fe844e12e2a4`.

Bu paket A02, A03, A08 ve A09'un aşağıdaki uygulama sorunlarını düzeltir; A11'in mevcut Clippy engelini de kaldırır. **Audit'in tamamı kapanmış değildir.** Özellikle A01, A04, A05, A06 ve A07 bu pakette düzeltilmemiştir. Mainnet açılış onayı veya bağımsız güvenlik denetimi değildir.

[GitHub Actions doğrulaması](https://github.com/Kubudak90/dark-perp/actions/runs/35269526191), doğrulama işi `105365057718`, kaynak yayımlama işi `105367600947`: ikisi de başarılı. [Ham CI kanıtı](https://github.com/Kubudak90/dark-perp/actions/runs/35269526191/artifacts/10518448550).

| Kontrol | Yeni sonuç |
|---|---|
| Rust workspace | 609 geçti, 0 başarısız; 14 yeni regresyon bu sayıya dahil |
| Ayrı perp-core serde testi | 156 geçti; workspace ile örtüşür, toplama eklenmez |
| Frontend | 261 geçti; 1 canlı gateway testi atlandı; 3 yeni test dahil |
| Frontend production build | Geçti |
| Rust format ve Clippy -D warnings | Geçti |
| perp-core no_std + serde derlemesi | Geçti |
| git diff --check | Geçti |

İlk tam workspace denemesi 480 saniyede zaman aşımına uğradı; başarı sayılmadı. Nihai çalışmada bütün fuzz örnekleri korundu, test profili `opt-level=2`, `debug-assertions=true`, `overflow-checks=true` olarak çalıştı. Gerçek SP1 proof üretimi, fiziksel güç kesintisi, canlı TEE veya gerçek ödeme bu testlerde yoktur. Sözleşme kaynakları değiştirilmedi; bu özel doğrulama işi Foundry çalıştırmadı.

Test edilen patch SHA-256: `b896ad8da6ffe296f5222d49db3fc4417fc4c619726da5c8e81fff1b90af3aa7`.

İndirilen CI kanıt ZIP'i SHA-256: `84f29eadaf250653ecc968a936daacf25edfc6e129ce077431571a4bf2805a41`; GitHub artifact kaydıyla eşleştirildi. Çalıştırıcı kaynak commit'i `54b1e1b52057568996fb47a8e01c3ef6832fbd30`; doğrulanan patch daha sonra uygulama commit'i olarak yayımlandı. Geçici taşıma dosyaları ve yayımlama iş akışları son ağaçtan kaldırıldı; uygulama kaynakları ve regresyon testleri kalıcıdır.

## A02: dayanıklı yatırma yetkilendirmesi

`POST /v1/accounts/deposit/authorize`, snapshot yazıcısı yoksa izin oluşturmadan HTTP 503 döndürür. İzin kaydedildikten sonra hesap kilidi bırakılır, dayanıklı yazım onayı beklenir; imza ancak onaydan sonra üretilir ve kullanıcıya verilir. Yazıcı hatası/zaman aşımında imza verilmez. `i128::MAX` üstü tutarlar kayıt oluşturmadan reddedilir.

Bekleyen izin varken yatırma adresini değiştirmek reddedilir; aynı adrese yeniden bağlama idempotent kalır. Böylece eski adres için önceden verilmiş, zincirde hâlâ geçerli imza daha sonra ödenip kredilenemez hale gelmez. **Operasyonel bedel:** zincir üstü izin iptali/süre sonu yoktur; kullanılmamış izinler adres değiştirmeyi engelleyebilir. Geç tamamlanan disk yazımı veya başarısız HTTP sonrasında kalan kayıtlar incelenmelidir. İmzası verilmiş olabilecek kayıtları körlemesine silmek güvenli değildir.

A01 ayrı kalır: yatırmalar hâlâ kullanıcı onay çağrılarıyla L1 sırasına göre kredilenir. Bu paket otonom L1 okuyucusu eklemez.

## A09: snapshot bekleme ve yazma sözleşmesi

30 saniyelik süre, kuyrukta yer beklemeyi ve yazıcının yanıtını birlikte kapsar. Periyodik ve kapanış yazıcıları aynı sıralama kilidini, durumu yakalamadan önce alır. Bloklayan dosya görevi bu kilidi sonuna kadar tutar; çağıran async görev iptal olsa da eski yakalama yeni kaydı ezemez.

`write_atomic`: rastgele adlı kardeş dosya, `create_new`, Unix 0600 izinleri, yazım, dosya senkronizasyonu, atomik rename, üst dizin senkronizasyonu. Hata başarı onayına çevrilmez. Önceden oluşturulmuş `.tmp` sembolik bağlantısı izlenmez. Başarısız yazım yalnızca kendi geçici dosyasını temizler. Donanımın/dosya sisteminin fsync sözleşmesini yerine getirmesi varsayımı devam eder.

## A03: imzalı kabul makbuzu teslimi

Emir oluşturma yanıtı ve emir listesi saklanan kabul alanları üzerinden aynı `r || s || v` imzasını ve enclave imzalayıcı adresini verir. Hash, sıra numarası ve kabul zamanı sorgu sırasında değiştirilmez. Aynı enclave anahtarıyla kimliği doğrulanmış restore imzayı yeniden üretir. `windowId` mevcut L1 sözleşmesindeki gibi imzasız ipucudur.

İstemci isteğe bağlı `signature` ve `enclaveSigner` alanlarını korur; eski sunucunun vermediği imzayı uydurmaz. İstemcideki biçim kontrolü, imzanın kriptografik doğrulaması değildir. Kullanıcı adına canlı challenge işlemi gönderilmez. 4096 girdilik, yalnızca açık makbuz materyali tutan ve snapshot'a yazılmayan önbellek, sık sorguların geçmişteki bütün emirleri tekrar imzalamasını önler.

## A08: dürüst piyasa verisi

Üretimde REST, WebSocket ve ortak durum görünümü sentetik alış/satış seviyeleri yayımlamaz: `unavailable: true`, boş seviye dizileri ve açık arayüz mesajı kullanılır. Bu, likiditenin sıfır olduğu değil derinliğin yayımlanmadığı anlamına gelir. İnce bir dark-market defterini açığa çıkarmak yerine gizlilik korunur. Demo seviyeleri simülasyon olarak etiketlenir.

`publishTimeMs` sorgu saati yerine fiyatın kaynak gözlem zamanıdır; `/v1` yanıtında `receivedTimeMs` ayrı taşınır. Aynı/eski zamanlı feed güncellemeleri fiyatı veya tazelik saatini yenilemez. Restore sonrası kaynak zamanı bilinmiyorsa 0 kalır. Gateway'in oracle anahtarını tutması şeklindeki A10 güven varsayımı kaldırılmış değildir.

## A11'in dar bir parçası

Mevcut `drain(..).collect()` ifadesi `std::mem::take` ile değiştirilmiştir. Bu, güncel Clippy engelini kaldırır; bağımlılık güvenlik uyarıları, gerçek proving ve canlı binary/verifier eşleşmesini doğrulamaz.

## Uyumluluk ve yayın

`perp-core`, sözleşmeler, guest programı, public-input commitment, çapraz katman test vektörleri ve witness kodlaması değiştirilmedi. Saklanan `WReceipt` alanları aynı; imza wire görünümüne eklenir. Yeni önbellek `serde(skip)` olduğundan mevcut `DPSNAP5` şeması korunur.

Gateway ve frontend birlikte güncellenmelidir. Eski frontend yeni veri-yok durumunu doğru anlatmayabilir. `DARKPERP_STATE` ve çalışan dayanıklı snapshot yazıcısı olmadan yatırma yetkilendirmesi artık bilinçli olarak reddedilir. Hiçbir merge, deployment veya canlı zincir işlemi yapılmadı.

Yeniden doğrulama:

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=2 CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build -p perp-core --no-default-features --features serde --locked
(cd frontend && pnpm install --frozen-lockfile && pnpm test && pnpm build)
```

## Açık işler

- **A01:** otonom, kesinleşme/reorg doğrulamalı sıralı L1 yatırma okuyucusu.
- **A04/A05:** sealed maker iptali; çoklu batch'e yayılan gerçek fill miktarı, ağırlıklı fiyat ve execution/finality yaşam döngüsü. Bu pakette düzeltilmediler.
- **A06/A07:** karşı emir gerektirmeyen kanıtlı CloseOnly çıkışı ve tarayıcı API anahtarı kaybında güvenli hesap kurtarma.
- **A10/A11 kalanı:** gateway custody/oracle güvenini ayrıştırma, ürünün bütün güvenlik iddialarını uzlaştırma, bağımlılık taraması, gerçek SP1 proving ve canlı ortam doğrulaması.

Native testlerin geçmesi bu açıkları kapatmaz; gerçek para açılışı için bu paket tek başına yeterli değildir.
