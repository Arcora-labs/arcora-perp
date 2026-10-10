# Chainlink Data Streams REST istemcisi: testleri bekleyen taslak

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

## Gerçekte doğrulanan kapsam ve araç engeli

Yerel compile/typecheck, format ve Clippy çalıştırıldı. **Yeni istemci runtime
ve loopback testleri çalıştırılmadı.** Bunları ekleyen tek araç çağrısı güvenlik
kontrolü tarafından reddedildi; dosyaların oluşmadığı doğrulandı. Engellenen test
paketi başka yoldan tekrarlanmadı. Oluşmamış test dosyalarına ait module bildirimleri
kaldırıldı; boş/sahte testlerle PASS üretilmedi. Bu taslak merge için hazır değildir.

Yeni CI işi açıkça `compile-only, runtime tests pending` adı taşır. Bu işin
başarısı çalışma zamanı güvenliği veya canlı authentication testi sayılmaz.

Gerçek kimlik bilgisi kullanılmadı. Ayrı, kimliksiz public discovery denemesinde
testnet ve mainnet endpoint'leri bu ortamdan HTTP 403 döndürdü. Bu sonuç
endpoint'in mutlaka ücretli/auth-required olduğu anlamına gelmez; erişim nedeni
burada belirlenemedi. Feed/scale/quote kimlikleri gözlemlenemediği için seçilmedi.
Bu deneme yeni Rust istemcisinin authentication testi değildir.

## Tamamlama ölçütleri

Önce gerçek HMAC known-answer ve request-path/header eşitliği testleri; katı
JSON/ABI/feed/time retleri; owned-loopback timeout, redirect, bounded body,
retry-budget ve error-redaction testleri geçmelidir. Ardından doğru account
entitlement ve gerçek v3 feed metadata/scale bağları doğrulanmalıdır. Sonraki
paketler gateway-prover-L1 bağlantısı, rapor kalıcılığı/kurtarma ve tam yaşam
döngüsüdür. Ücretli erişim, gerçek credential veya zincir yazısı ayrıca yetki ister.

## Resmi referanslar (10 Ekim 2026 okuması)

- Authentication: https://docs.chain.link/data-streams/reference/data-streams-api/authentication
- REST endpoint ve yanıt sözleşmesi: https://docs.chain.link/data-streams/reference/data-streams-api/interface-api
- v3 şema: https://docs.chain.link/data-streams/reference/report-schema-v3
- Public discovery: https://docs.chain.link/data-streams/reference/data-streams-api/discovery-endpoint

Ham yerel kayıtlar: `target/chainlink-client-20261010T173729Z/`.
Kalıcı kanıt: `docs/audits/2026-10-10-chainlink-client-draft/`.
