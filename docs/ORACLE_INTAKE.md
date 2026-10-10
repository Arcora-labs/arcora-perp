# Oracle kaynak kabulü ve kalan güven sınırı

Bu belge 10 Ekim 2026 tarihli host-side fiyat kabul paketini açıklar.
**Production RELEASE HOLD devam eder.** Tek borsa ve tek güvenilen publisher
modeli bu paketle çoklu kaynak/quorum modeline dönüşmez.

## İstenen fiyat ile gelen yanıtın eşleşmesi

Canlı ticker istemcisi sabit Crypto.com HTTPS adresini kullanır. Enstrüman adı
sınırlı ASCII biçiminde doğrulanır ve query parametresi olarak kodlanır.
Yanıtın HTTP 200, sayısal `code: 0`, `method: public/get-tickers` olması ve tam
bir ticker satırı taşıması gerekir. Satırın `i` alanı istenen enstrümanla aynı
olmalıdır. `a`, `b`, `k` fiyatları string; `t` pozitif tam sayı milisaniyedir.

Typed JSON decoder eksik, yanlış tipli veya yinelenen kritik alanları reddeder.
Kaçışlı alan adları da aynı alan olarak değerlendirilir. Trailing JSON ve
NaN/Infinity kabul edilmez. Borsanın ek kritik olmayan metadata alanları ileri
uyumluluk için yok sayılır; bütün bilinmeyen/tekrarlı alanların reddedildiği
iddia edilmez.

Last/bid/ask alanlarının hepsi pozitif olmalıdır. Eksik, null veya bozuk bid/ask
son işlem fiyatıyla doldurulmaz; ters book (`bid > ask`) da reddedilir. Onluk
parser 96 bayt ile sınırlı, ASCII tabanlı ve taşma kontrollüdür. `.5`, `1.` ve
sekiz basamak sonrası kesme davranışı korunur; çift işaret, `+`, exponent ve
bozuk sayı kabul edilmez. Spread ve orta fiyat hesabı taşma/panic üretmez.

**Önemli:** `backup_twap` protokol alanının adı değişmedi, fakat burada taşıdığı
değer aynı order book'un orta fiyatıdır. Bu bağımsız bir TWAP veya farklı bir
kaynağın doğrulaması değildir. Eksik book'u son fiyatla doldurmamak kaynak
bağımsızlığı sağlamaz; yalnız eksik kanıtın uydurulmasını engeller.

## Kaynak zamanı, imza ve receipt zamanı

Eksik/sıfır kaynak zamanı yerel saatle doldurulmaz. Gelecek zaman `now` değerine
kırpılmaz. Request-start zamanı ile cevap gelmesi arasındaki monotonic süre
kontrollü toplanır; bu, istek sürerken yayınlanan normal bir ticker'ın yanlışlıkla
gelecek sayılmasını engeller. Kaynağın imzalanan `t` alanı değişmez.

Gateway gelen transcript'i şu koşullar sağlanmadan ne market fiyatına ne de
sequencer'a yazar: bilinen market, pozitif kaynak zamanı, negatif olmayan
confidence, doğru publisher imzası ve mevcut marketin freshness/confidence/
backup-deviation sınırları. Mevcut guest validator aynen çağrılır. Kaynak zamanı
ve imza yeniden yazılmaz. Kabulden sonra `feed_ts` kaynağın zamanını, `px_ms`
yalnız yerel receipt zamanını kaydeder. Tekrar veya sıra dışı veri receipt zamanını
yenilemez. Yavaş ama sürekli ilerleyen eski bir fiyat serisi artık taze olamaz.

Saat farkı/bozuk saat otomatik onarılarak fiyat kabul edilmez. Gerçek servislerde
zaman senkronizasyonu sağlanmalıdır. Bir feed yanıtı gelirken hâlâ taze olsa bile
uzun kuyruk/işlem gecikmesinde gateway kontrolü onu yeniden reddedebilir.

Production modu etkinleştirilirken ve snapshot restore sonrasında mevcut runtime
oracle'ları geçersizleştirilir. Yeni geçerli kaynak verisi gelmeden demo/seed fiyatı
ile kabul açılamaz. Production tick'i rastgele fiyat yürümesi üretmez. Normal demo
modunun simülasyonu korunur. Canlı feed kesilirse en son gerçek transcript aynen
kalır ve kendi kaynak zamanına göre bayatlar; simülasyon veya yeni timestamp ile
kurtarılmaz. Bu güvenlik tercihi feed arızasında kullanılabilirliği azaltabilir.

## HTTP ve signer sınırları

Ticker gövdesi 64 KiB, chart candle gövdesi 1 MiB ile sınırlıdır. Boyut sınırı
Content-Length olmayan ve chunked yanıtlarda da gerçek okunan baytlara uygulanır.
Yönlendirme takibi kapalıdır. 5 saniyelik ureq request timeout'u yapılandırılmıştır;
bu bir dış ağ sandbox'ı veya her platformun DNS/sistem çağrıları için mutlak
sonlanma garantisi değildir. HTTP/read/parser hataları yanıt gövdesini veya URL'yi
loglara taşımaz. Candle içeriğinin tüm semantik kontrolleri bu paketin kapsamında
değildir; candle yolu yalnız bounded transport'tan yararlanır.

`ORACLE_SIGNER_KEY` yalnız gerçekten unset ise demo anahtarına düşer. UTF-8 olmayan
veya bozuk ayar reddedilir. Bilinen public demo signer açıkça ayara yazılsa da
production başlangıcında reddedilir. Bunun dışındaki bir anahtarın gizli veya
sızmamış olduğu bu karşılaştırmadan çıkarılamaz. Gerçek anahtar rotasyonu, güvenli
key-release ve publisher bağımsızlığı ayrıca doğrulanmalıdır.

## Test kapsamı

Saf dönüşüm ve parser testleri yanında gerçek ureq ile yalnız kendimize ait
loopback HTTP sunucuları kullanılır. Sağlıklı yanıt, yanlış enstrüman, kritik alan
tekrarı, yanlış tip, eksik/gelecek zaman, aşırı büyük Content-Length/chunked/EOF
gövde, yarım gövde, server hatası ve duran bağlantı sınanır. Redirect hedefinin
hiç bağlantı almadığı ayrıca doğrulanır. Bu testler harici TLS uç noktasının
kimliğini veya borsanın fiyat doğruluğunu bağımsız kanıtlamaz.

Gateway testleri yanlış publisher'ın yeniden imzalanmaması, eski/gelecek veya
sınır dışı verinin marketi değiştirmemesi, tam kaynak imzasının korunması,
sınırdaki staleness, tekrarların receipt zamanını yenilememesi ve production
restart'ın taze veri beklemesini doğrular. Önceki public-oracle timestamp testi
sentetik saatle yürütülür; artık yıllar önceki timestamp'i bugünün saatiyle kabul
ettiren bir test değildir. Aynı timestamp/receipt/restore iddiaları korunur.

```sh
cargo +1.99.0 test --locked -p oracle-feed
cargo +1.99.0 test --locked -p oracle-feed --features http
cargo +1.99.0 test --locked -p gateway oracle_intake_tests
cargo +1.99.0 test --locked --workspace
cargo +1.99.0 clippy --locked --workspace --all-targets -- -D warnings
```

## Değişmeyen riskler

Yetkili publisher bütün fiyat alanlarını tutarlı biçimde uydurabilir; mevcut
`trusted_publisher_can_reprice_primary_and_backup_together` testi bunu açıkça
karakterize eder. Çoklu kaynak, bağımsız publisher, manipülasyon direnci ve gerçek
TWAP politikası hâlâ tasarım/kanıt gerektirir. Source parser'ının geçmesi ekonomik
fiyat doğruluğu veya proof içinde kaynak konsensüsü anlamına gelmez.

Reviewed guest, `perp-core`, proof/public-input biçimi, ELF/vkey pinleri,
sözleşmeler, ekonomik risk eşikleri ve snapshot/journal biçimleri değiştirilmedi.
Bu paket yeni proof, canlı CC attestation, gerçek fonlu exit veya production
yayını kabulü değildir.

## Kaynaklar

- Crypto.com Exchange REST get-tickers alanları ve başarı kodu:
  https://exchange-developer.crypto.com/exchange/v1/docs/api/rest/public-get-tickers
- Kilitli ureq 2.12.1 uygulama ve API davranışı:
  https://docs.rs/crate/ureq/2.12.1
