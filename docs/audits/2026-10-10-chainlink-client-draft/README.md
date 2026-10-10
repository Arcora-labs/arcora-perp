# Arcora Perp: Chainlink REST istemcisi taslağı

10 Ekim 2026. **PRODUCTION RELEASE HOLD. Taslak, merge için hazır değil.**
Taban main: `e552bbab6868b070ff9c3b8f4ed3b9dec1230288`.

## Tamamlanan işlem

#42 exact head `2598acf78d7256121e915dcef29a51eeb55692a8` için 18/18 kontrol
başarılıyken normal merge edildi. Merge ağacı kaynak ağacıyla eşittir.
Merge saati 20:37:31 Türkiye; yeni main `e552bba`. Koruma değişikliği yok.
Merge sonrası push CI, bu PR kabulünden ayrı kayıttır.

## İstemci kaynak kodu

Yeni standalone host paketi `crates/chainlink-streams-client`: explicit network/
credential, HMAC-SHA256 GET, sabit HTTPS origin, no-redirect/no-env-proxy, sınırlı
HTTP okuma ve tekrar denemesi, metadata/ABI/feed/time eşleşmesi. Original rapor
UnverifiedReport olarak korunur; DON imzası doğrulandığı veya fiyatın trading'e
kabul edildiği iddia edilmez. Gateway/prover-service/guest entegrasyonu yapılmadı.

## Gerçek doğrulama

Cargo build, Clippy (-D warnings), format, reviewed release ve candidate lock
kontrolleri başarılı. 21 eski reviewed kaynak pini ve 9 aday runtime girdisi
aynı. Yeni host lock'ta 99 registry package var; root lock'a göre yeni registry
name/version/source/checksum kimliği eklenmedi. Bu, güvenlik audit'i değildir.

**Yeni istemci runtime test sayısı: 0.** Test dosyalarını ekleyen çağrı araç
kontrolüne takıldı. Dosyalar oluşmadı; aynı engellenen işlem farklı yolla
yürütülmedi. Oluşmamış dosyaların module bildirimleri temizlendi. Boş cargo test
koşusu veya eski testler bu istemci için PASS gösterilmedi. Compile-only CI açıkça
adlandırıldı; bütün CI yeşil olsa da taslak runtime testi eksik kalır.

Kimliksiz public discovery testnet ve mainnet GET'leri HTTP403 döndürdü. Gerçek
feed/scale/quote/entitlement doğrulanmadı; 403 nedeni belirlenmedi. Bu sorgular
Rust istemci veya gerçek authentication testi değildir. Gerçek key, ücretli
kaynak, zincir işlemi veya production ayar değişikliği kullanılmadı.

## Takip

Önce HMAC/HTTP/parser/freshness/retry runtime testleri, ardından gerçek feed
kimlikleri ve doğru hesap yetkisi. Sonra gateway bağlantısı, kalıcı rapor arşivi,
recovery ve tam işlem yaşam döngüsü. Ayrıntı `docs/CHAINLINK_STREAMS_CLIENT.md`;
tüm backlog `docs/ACTIVE_WORK.md`.

`verification.json` gerçek komut/exit/log ve kaynak hash'lerini içerir. Ham loglar
ignored `target/chainlink-client-20261010T173729Z/` içinde korunur. Yeni program key
ve proof üretilmedi; önceki CPU yürütmeleri bu çalışma için yeniden koşulmuş sayılmaz.
