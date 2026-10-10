# Oracle: bağımsız borsa kontrolü ve para birimi engeli

Tarih: 10 Ekim 2026. **Production RELEASE HOLD sürüyor.**
Bu paket isteğe bağlı, host-side Crypto.com + OKX kontrolüdür. Guest tarafından
doğrulanan çoklu publisher quorum'u değildir. Mevcut varsayılan feed değiştirilmedi.

## Önce açık kalan birim problemi

| Gateway etiketi | Mevcut Crypto.com spot feed | Aynı birimli OKX spot eşlemesi |
|---|---|---|
| BTC/USDC | BTC_USDT | BTC-USDT |
| ETH/USDC | ETH_USDT | ETH-USDT |
| SOL/USDC | SOL_USDT | SOL-USDT |

Sağdaki iki kaynak USDT birimindedir. USDC veya USD ile eşdeğer sayılmaz.
Perpetual kontrat fiyatı da spot fiyat yerine otomatik kabul edilmez.
**Tablo üretimde doğru USDC fiyatı sağlandığını değil, mevcut uyumsuzluğu gösterir.**
Crypto.com dokümantasyonu da `BTC_USDT` spot leg ile `BTCUSD-PERP` perp leg'i
ayrı gösterir. Kaynakların fiyatları, ürünlerin bölgesel erişimi ve canlı enstrüman
mevcudiyeti bu yerel testlerle doğrulanmış değildir.

Yeni mod yalnız `DARKPERP_ORACLE_CROSSCHECK_MAX_DEVIATION_PPM` ayarı açıkça
verildiğinde etkinleşir. Unset, eski tek kaynak modunu korur. Ayar boş, yanlış
UTF-8, işaretli, kesirli veya sınır dışıysa başlangıç reddedilir. Kabul edilen
tam sayı aralığı 0..1000000 ppm'dir; 0 yalnız birebir fiyat eşleşmesidir.
Bu bir **yapılandırma aralığıdır**, güvenli ekonomik eşik önerisi değildir.
Üretim için onaylanmış bir eşik seçilmedi; testlerdeki 1000 ppm yalnız sentetiktir.

Başlangıçta her piyasanın `BASE/QUOTE` etiketi, `BASE_QUOTE` primary feed'iyle
birebir eşleştirilir. Üç mevcut piyasa da USDT/USDC kontrolünden geçemediği için
**bu ayarı bugünkü MARKETS ile açmak başlangıcı durdurur**. Kısmi kurulum yapılmaz.
Mevcut servise bu ayar uygulanmadı. USDC kaynağı veya açık USDT/USDC dönüşümü,
ekonomik ve deployment bağlarıyla birlikte ayrı incelenmelidir; burada piyasa
etiketi/kontratı/teminat birimi değiştirilmedi ve peg varsayımı eklenmedi.

## Veri sözleşmesi

Crypto.com primary endpoint'i mevcut sabit HTTPS adresidir:
`https://api.crypto.com/exchange/v1/public/get-tickers?instrument_name=BASE_QUOTE`.
Aynı typed parser ve aynı son fiyat/spread/midpoint dönüşümü kullanılır.

OKX secondary endpoint'i:
`https://openapi.okx.com/api/v5/market/ticker?instId=BASE-QUOTE`.
20 Mayıs 2026 tarihli resmi değişiklik kaydı, `openapi.okx.com` adresini global
REST için önerilen alan adı olarak tanımlar; eski www alan adı da desteklenir.
Bu kod bölgesel domain/kimlik seçimi veya yönlendirme ile otomatik kaynak değiştirmez.
Deployment bölgesine uygunluk ayrıca doğrulanmalıdır; erişim hatası ret sonucudur.

OKX için HTTP 200, string `code: "0"`, boş string `msg`, tam bir satır,
`instType: "SPOT"`, birebir `instId`, string last/bid/ask ve string tam sayı
milisaniye `ts` gerekir. Crypto.com'un code/t alanları sayısaldır; bu fark kaybolmaz.
Kritik eksik/tekrarlı/yanlış tipli alanlar, trailing JSON, sıfır/gelecek timestamp,
eksik/negatif/crossed book ve hatalı fiyat reddedilir. Ek kritik olmayan metadata
yok sayılabilir. Fiyat parser'ının sekiz basamak sonrası kesme davranışı korunur.

Her gövde gerçek okunan baytlarda 64 KiB ile sınırlıdır. Redirect takibi yoktur.
İstek başına 5 saniyelik ureq timeout vardır. İki seri istek yaklaşık 10 saniye
ve platform/DNS davranışını gerektirebilir; bu toplam 5 saniyelik SLA değildir.
İlk kaynak başarısızsa ikinciye geçilmez; ikinci başarısızsa primary tek başına
başarılı sonuç olarak dönmez. Farklı marketler mevcut worker'da seri taranır.
Tüm döngü kapasitesi/freshness uygunluğu ayrıca ölçülmelidir.

## Kabul ve duruş

İki kaynak aynı açık spot base/quote'a ait, doğru sırada iki farklı borsa olmalıdır.
İkisinin imzası, source-age, confidence ve same-book deviation değerleri mevcut
market validator'ıyla gerçek gateway receipt zamanında yeniden doğrulanır.
Her iki kaynak timestamp'i kendi son kabul zamanından kesinlikle ilerlemelidir.
Aynı timestamp'li güncelleme, değişmiş fiyat taşısa dahi reddedilir.

Hem son fiyatlar hem iki book midpoint'i şu simetrik eşitsizlikten geçer:

```
abs(a - b) * RATE_SCALE <= min(a, b) * explicitly_configured_max_deviation_ppm
```

Hesap taşarsa ret verilir; bölümle yuvarlama veya kaynaktan eşik tahmini yapılmaz.
Kontratların mevcut confidence, deviation, leverage ve staleness eşikleri değişmez.

**Yaş bağı korunur:** secondary timestamp, primary timestamp'ten eski olamaz.
Çünkü değişmeyen guest transcript'inde yalnız primary zamanı bulunur. Daha eski
secondary'yi kabul etmek, primary guest'te hâlâ tazeyken secondary'nin bayatlamasını
gizleyebilirdi. Yerel saati veya primary imzasını değiştirmek yerine bu çift reddedilir.
Bu muhafazakâr kural kaynaklar arası zaman farkında kullanılabilirliği azaltır;
yeni bir clock-skew toleransı veya ekonomik eşik icat edilmez.

Başarılı çiftte primary transcript **aynen** sequencer'a geçer. Fiyat ortalaması,
yeni publish timestamp veya farklı `backup_twap` üretilmez. `backup_twap` hâlâ
primary'nin aynı book midpoint'idir, gerçek zaman pencereli TWAP değildir.

Opt-in modunda tek kaynaklı intake yolu geçerli publisher imzasıyla bile bu
kontrolü atlayamaz. Pair/transport/task hatası veya tekrarlı veri, ilgili sequencer
oracle'ını imzasız ve geçersiz sentinel ile **hemen** durdurur. Son görüntülenen
fiyat ile başarılı receipt/source zamanları korunur; geçersiz sentinel yeni
fiyat/evidence değildir. Mevcut guest validator onu reddeder. Bu, önceki
tek-kaynak modunun yalnız eski transcript'i tutma davranışından açıkça farklıdır.
Bekleyen/önceden mühürlenmiş işlerin geri alınması iddia edilmez.

İlk veriden önce ve duruşta demo tick'i de opt-in market için fiyat uydurmaz.
Duruştan çıkmak için iki kaynağın da son başarılı kabul zamanını aşan, geçerli
bir çift gerekir. Başarısız veya downstream tarafından reddedilen çift, bu
watermark'ları ilerletmez. Watermark'lar runtime-only'dir; snapshot şeması değişmez.
Restore sonrasında yapılandırma yeniden bağlanır ve taze çift beklenir. Bu,
kalıcı cross-restart replay koruması veya yeni recovery kanıtı değildir.

## Güven sınırı ve kapsam

Her iki transcript **aynı operatör publisher anahtarıyla** imzalanır. Borsa etiketleri
host transport/parser kökenidir, borsalardan kriptografik imza değildir. Ele geçirilmiş
host/publisher iki kaynağı da uydurabilir. Bunu gösteren yeni karakterizasyon testi ve
mevcut `trusted_publisher_can_reprice_primary_and_backup_together` testi bu riski açık
bırakır. **R06 kapanmadı.** Kaynaklar ekonomik olarak da bağımsız olmayabilir.

Bu mod mevcut konfigürasyonda kapalıdır ve strict quote binding nedeniyle açılamaz.
İki-kaynak happy-path gateway testleri yalnız test belleğinde açıkça USDT etiketli
sentetik market eşlemesi kurar; gerçek MARKETS/guest/kontrat dosyaları değiştirilmez.
Bu yüzden sonuç, çalışan canlı iki-kaynaklı USDC deployment kanıtı değildir.

Reviewed guest, perp-core, ELF/vkey, public input, commitment, risk parametreleri,
kontratlar, bağımlılık sürümleri ve snapshot/journal wire biçimi değiştirilmedi.
Yeni proof, canlı attestation/key release, gerçek fonlu exit, ücretli altyapı veya
production deployment çalıştırılmadı. Eski yayın engelleri sürer.

## Test ve kanıt

Saf parser/kabul testleri yanında aynı production request fonksiyonu iki ayrı,
kendimize ait loopback sunucusuyla sınanır. Eksik/hatalı/tekrarlı/eski/gelecek
kaynaklar, yanlış spot/quote, sapma ve midpoint farkı, overflow, redirect hedefinin
çağrılmaması, Content-Length/chunked/EOF sınırları, kısmi ve duran gövde kapsanır.
Mac test düzeneğinde accepted socket'in O_NONBLOCK bayrağı açıkça kapatılır;
üretim HTTP istemcisinin timeout veya ret kontrolleri test geçirmek için gevşetilmez.
Bunlar canlı borsa TLS/fiyat doğruluğu testleri değildir.

```
cargo +1.99.0 test --locked --offline -p oracle-feed
cargo +1.99.0 test --locked --offline -p oracle-feed --features http
cargo +1.99.0 test --locked --offline -p gateway oracle_crosscheck
cargo +1.99.0 test --workspace --locked --offline
cargo +1.99.0 clippy --workspace --all-targets --locked --offline -- -D warnings
```

Kayıt: `docs/audits/2026-10-10-oracle-crosscheck/`. Ham geliştirme/test log'ları
ignored `target/oracle-crosscheck-20261010/` altındadır.

## Resmi API kaynakları (10 Ekim 2026 kontrolü)

- Crypto.com REST ticker ve spot/perp ayrımı:
  https://exchange-developer.crypto.com/exchange/v1/docs/api/rest-single-page/
- OKX global REST ve get-ticker alanları:
  https://www.okx.com/docs-v5/en/
- Güncel OKX get-ticker şema referansı:
  https://tr.okx.com/docs-v5/
- OKX 20 Mayıs 2026 REST domain değişikliği:
  https://www.okx.com/docs-v5/log_en/
