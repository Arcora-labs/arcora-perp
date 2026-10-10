# Chainlink Data Streams REST istemcisi: doğrulanmış host paketi

Tarih: 10 Ekim 2026. **PRODUCTION RELEASE HOLD.**
Bu bir canlı oracle geçişi değildir. Yeni paket gateway'e bağlı değildir ve
üretim fiyat kaynağı değiştirilmemiştir.

## Uygulanan kod

`crates/chainlink-streams-client` ayrı, host-only Rust paketidir. Mevcut root ve
iki guest manifest/lock/pin dosyası değiştirilmez. HTTP, kimlik bilgileri veya
HMAC işlemleri guest içine taşınmaz. Resmi REST API'nin yalnız
`/api/v1/reports/latest?feedID=...` yolu uygulanır; WebSocket, history/bulk/page
istemcisi ve rapor arşivi bu pakette yoktur.

Çağıran uygulama `Credentials::new(Network, username, secret)` ile kimliği açıkça
sağlar. Ortam değişkeni, credential dosyası veya varsayılan demo anahtarı aranmaz.
Network kimlikle ve istekle bağlanır; yalnız iki sabit HTTPS origin vardır.
Kimlik bilgileri URL'ye konmaz; redirect ve ortamdan proxy keşfi kapalıdır.
Owned credential ve string-to-sign tamponları Zeroizing ile korunur; HTTP
kütüphanesinin/derleyicinin bütün bellek kopyalarının silindiği iddia edilmez.
Credential Debug çıktısı maskelidir. Hatalar provider gövdesini taşımayan sabit
kategorilerdir; daha üst katmanlarda hassas HTTP debug log'ları açılmamalıdır.

GET imzası HMAC-SHA256 ile method, tam query path, boş gövdenin SHA256'sı,
kullanıcı UUID'si ve milisaniye zamanından üretilir. Her denemede saat tekrar
örneklenir. Sıfır veya geriye giden saat reddedilir; sunucu saatini otomatik
kabul edip yerel saat/rapor zamanı değiştirilmez. Saat senkronizasyonu operatörün
sorumluluğudur.

İstek başına 5 saniye, toplam 12 saniye ve en fazla 3 deneme bütçesi tanımlıdır.
Transport hataları ve HTTP 500/502/503/504 için 100/200 ms bekleme uygulanır.
400/401/403/404 ve 429 otomatik tekrar edilmez; quota veya yetki hatası başarılı
eski rapora dönüştürülmez. Bu süre ayarları DNS/işletim sistemi çağrılarının her
platformda mutlak süre garantisi veya servis SLA'sı değildir. 429 için üst
katmanın ayrıca backoff/operasyon politikası gerekir.

HTTP 200 dışı yanıt başarı değildir. Gövde 64 KiB gerçek okuma sınırına tabidir;
signed fullReport ayrıca mevcut aday decoder'ın 4096 bayt sınırını kullanır.
Sıkıştırılmış gövde ve belirsiz Content-Length/Transfer-Encoding kombinasyonları
reddedilir. Typed JSON kritik duplicate alanları, yanlış tipleri ve trailing
JSON'u reddeder; kritik olmayan ek metadata yok sayılır.

İstenen feed kimliği, JSON metadata'sı ve ABI içindeki feed/zaman alanları aynı
olmalıdır. Raporun kaynak zamanı ve expiresAt değeri korunur, mevcut aday parser
ve freshness kontrolü çağrılır. `Request` explicit maksimum yaş gerektirir;
burada production için onaylı feed, scale veya risk eşiği seçilmez.

Sonuç `UnverifiedReport` tipidir. Full report baytları değişmeden saklanır.
HTTP/HMAC başarısı, JSON decode veya nonzero signature alanları gerçek DON
imzası değildir. Aynı original fullReport daha sonra gerçek Chainlink verifier'a
verilmelidir. İstemci oracle fiyatını yeniden imzalamaz veya settlement'e göndermez.
Kuyruk gecikmesinde `check_freshness` çağrısı gerekir; receipt zamanı kaynak zamanının
yerine geçmez. Replay/dedup, gateway admission ve kalıcı rapor eşlemesi sonraki iştir.

## Güncel çalışma zamanı doğrulaması

10 Ekim 2026 devamında dört ret regresyonu düzeltildi. Önceki 34 test
aynen korundu; altı deterministik saat testi eklendi. Debug ve release koşularının her birinde
**40 PASS, 0 FAIL, 0 IGNORE**. Clippy, format, reviewed release ve candidate lock
kontrolleri başarılı; 21 reviewed v2 ve 9 aday runtime girdisi aynı.
PR CI sonucu bu yerel sonuçtan ayrı kayıttır.

`ReceiptClock`, ileri saat sıçramasında yeni monotonic referans kurar. Duvar saati
sonra dursa bile istek/retry süresi ve alt-milisaniye kalanı kaybolmaz. Normal
ilerleyen duvar saati ile geçen süre iki kez toplanmaz. Sıfır/geriye giden saat,
ters monotonic referans ve aritmetik taşma reddedilir. HMAC zamanı gerçek duvar
saati örneğidir; hesaplanan receipt alt sınırıyla auth zamanı veya raporun
kaynak zamanı yeniden yazılmaz.

Content-Length yalnız ASCII rakamlarından oluşabilir; + işareti kabul edilmez.
Transfer-Encoding ya yoktur ya da tek `chunked` alanıdır. Yinelenen alanlar,
desteklenmeyen kodlama/listeler ve Content-Length ile birlikte bulunması,
gövde decoder'ına geçilmeden reddedilir. Geçerli chunked ve EOF yanıtları mevcut
bayt sınırıyla kabul edilebilir. Bu sıkı politika genel amaçlı bütün HTTP
kodlamalarını destekleme iddiası değildir.

Testlerde yalnız açık sentetik UUID/secret ve sahte, sıfır olmayan imza kelimeleri
kullanılır. 13 saf HMAC/parser testi, 21 gerçek owned-loopback HTTP testi ve
6 deterministik saat testi vardır. Gerçek credential dosyası okunmaz. HMAC
known-answer değeri Python stdlib ile bağımsız hesaplanmış vektördür, canlı
Chainlink cevabı değildir. Redirect hedefinin hiç bağlantı almadığı, tekrar
sınırları, partial/stalled/oversize yanıtlar, metadata ve kaynak yaşı sınanır.
HTTP/parser başarısı DON imzası doğrulaması değildir. Public HTTPS hedef kısıtı,
TLS ve proxy/redirect davranışı gevşetilmedi; test origin'i private yoldan verilir.

Önceki yazma reddinin ayrıntılı nedeni bu oturumda doğrulanamadı. Kullanıcının
tekrar deneme talebi üzerine aynı yetkili Mac'te yazma başarılı oldu; hiçbir
araç güvenlik ayarı veya işletim sistemi izni değiştirilmedi. Önceki 30/4 sonuçları
`audits/2026-10-10-chainlink-client-regressions/` altında tarihsel kayıt olarak
korundu. Güncel dört düzeltme ve test kayıtları:
`audits/2026-10-10-chainlink-client-fixed/`.

## Kalan kabul ölçütleri

İstemci yerel runtime testi alt işi tamamlandı. Gerçek account/feed erişimi,
feed/scale/quote kimliklerinin bağımsız doğrulanması, gateway scheduler/admission,
DON doğrulaması, rapor kalıcılığı/kurtarma ve uçtan uca yaşam döngüsü açık kalır.
Mevcut gateway'in fiyat kaynağı değiştirilmedi. Gerçek credential, ücretli erişim,
kamu zincirine işlem, state migration veya production rollout yapılmadı.
Önceki kimliksiz discovery HTTP403 gözlemleri tarihsel olup sebebi belirlenmemiştir.
Bu paketin testleri canlı erişimi veya TLS endpoint kimliğini doğrulamaz.

## Resmi referanslar (10 Ekim 2026 okuması)

- Authentication: https://docs.chain.link/data-streams/reference/data-streams-api/authentication
- REST endpoint ve yanıt sözleşmesi: https://docs.chain.link/data-streams/reference/data-streams-api/interface-api
- v3 şema: https://docs.chain.link/data-streams/reference/report-schema-v3
- Public discovery: https://docs.chain.link/data-streams/reference/data-streams-api/discovery-endpoint

- HTTP Content-Length: https://www.rfc-editor.org/rfc/rfc9110.html#name-content-length
- HTTP/1.1 framing: https://www.rfc-editor.org/rfc/rfc9112.html#name-transfer-encoding

Güncel ham kayıtlar: `target/chainlink-client-fix-20261010T190741085776Z/`.
Önceki compile-only ve başarısız regresyon kayıtları tarihsel olarak korunur.
