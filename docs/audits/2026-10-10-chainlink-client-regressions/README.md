# Chainlink REST istemcisi: runtime regresyonları

10 Ekim 2026. Dal: `feat/chainlink-streams-client-20261010`, PR #43.
Başlangıç kaynak: `8eab00f23a4c02c0fd9eca86decf8759290fd71e`.
**DRAFT / MERGE HOLD / PRODUCTION RELEASE HOLD.**

## Sonuç

Önceki istemci taslağında runtime testi yoktu. Bu tur 13 saf test ile 21 gerçek
owned-loopback HTTP testi eklendi. Son koşu **30 PASS, 4 FAIL, 0 IGNORE**.
İlk 32-test koşusunda 30 geçti, 2 ret beklentisi başarısız oldu. İki ilave framing
testi de düzeltme öncesi başarısız oldu. Son 34-test koşusu aynı dört hatayı gösterdi.
Üç koşunun sayıları toplanmaz. Format, Clippy ve git whitespace kontrolü başarılı.

## Açık bulgular

| Bulgu | Testin gösterdiği durum |
|---|---|
| Request-clock ileri adımı | Başlangıç saati 1 ms, request/receipt saati 110000 ms, kaynak 100 s ve 40 ms HTTP gecikmesi: max-age 10000 ms sınırına rağmen kabul |
| Content-Length işareti | `+N` uzunluk biçimi kabul ediliyor |
| Yinelenen Transfer-Encoding | Geçerli chunk'larla iki chunked header kabul ediliyor |
| Desteklenmeyen Transfer-Encoding | Geçerli chunk'larla gzip bildirimi reddedilmeyebiliyor |

Bunlar owned test yanıtlarıyla gösterilen istemci davranışlarıdır; canlı feed
istismarı, fon kaybı veya üretimde gerçekleşmiş olay iddiası değildir.

## Engellenen düzeltme ve doğru CI durumu

Kaynak düzeltmesi çağrısı araç güvenlik kontrolünde yürütülmeden engellendi.
Sonraki salt-okuma git diff yalnız cfg(test) module eklerini gösterdi; runtime
koduna düzeltme uygulanmadı. Aynı işlem başka kanaldan tekrar edilmedi.

CI işi gerçek cargo test ile genişletildi, continue-on-error veya ignore yok.
Bu dört hata düzeltilmeden işin başarısız olması beklenir. PR taslak tutulur;
başarılı derleme/Clippy sonucuyla merge edilmez. Uzak CI sonucu ayrıca okunmalıdır.

## Güven sınırı

Yalnız public sentetik kimlikler, raporlar ve sahip olunan loopback süreçleri
kullanıldı. HMAC testi Python stdlib bağımsız vektörüyle eşleşir. Bu gerçek
Chainlink hesabı, DON imzası, proof veya dış ağ TLS doğrulaması değildir.
Gateway, guest, proof pinleri, sözleşmeler, risk eşikleri, credential dosyaları
ve production ayarları değiştirilmedi. 21 eski ve 9 aday runtime pini aynı.
Gerçek fon, ücretli kaynak ve kamu zinciri yazısı kullanılmadı.

`verification.json` komutları, exit kodlarını, kaynak ve ham log hash'lerini
kaydeder. `test-results.txt` yalnız seçilmiş sonuç satırlarıdır; ham log değildir.
Önceki compile-only audit değiştirilmedi. Güncel iş sırası docs/ACTIVE_WORK.md.

Resmi kontrol kaynakları:
- https://docs.chain.link/data-streams/reference/data-streams-api/authentication
- https://docs.chain.link/data-streams/reference/data-streams-api/interface-api

## Yayınlanmamış yerel çalışma kaydı

Son kontrol: 10 Ekim 2026 21:24:32 Europe/Istanbul.
Commit/push komutu da araç kontrolünde yürütülmeden engellendi. HEAD ve uzak
PR #43 head'i hâlâ `8eab00f23a4c02c0fd9eca86decf8759290fd71e`; PR OPEN/DRAFT.
Bu turdaki 10 dosyalık değişiklik yerelde, commit edilmemiş ve staged değildir.
Yeni testler ve gerçek-test CI tanımı henüz GitHub'a ulaşmadı. Uzak eski CI'ın
yeşil sonucu bu yerel 34 testi kapsamıyor. Merge yapılmadı; düzeltme uygulanmadı.
Yerel dosyalar silinmedi, reset/stash yapılmadı. Bu durum sonraki oturumda
okunmadan yeni bir dal veya ikinci kopya oluşturulmamalıdır.
