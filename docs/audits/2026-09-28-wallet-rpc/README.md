# Arcora — gerçek cüzdan doğrulaması ve RPC okuyucu

**S2-01, S2-02, S2-03 ve S2-04 kapandı: 11→7 kalan özgün iş.** Başlangıç 15, toplam kapanan 8. [Kalan 7 iş](remaining-work.md), [kriter bazında kayıt](task-status.json). Production yayın kararı **HOLD**.

Kaynak commit'i `9bc9ae59e842206f36528e87978fbcd3defa20ac`; kaynak içerik SHA-256 `08137009327fd66fac659face0eb611aa3104ec0900add759d39fb127e2c0e74`. [Manifest](source-manifest.json). Bu tur uygulama/gateway/proof kodu değişmedi; salt-okunur deployment okuyucusu, onun testleri ve doğrulama kaydı kapsamı değişti. Önceki S4/S5 kapanışlarının kendi kaynak ve kapsam kayıtları korunur.

## Tamamlanan işler

- **Gerçek MetaMask + Rust gateway:** iki sekmede native kilit, gerçek imza reddi, credential rotation, eski anahtarın HTTP/WS reddi, yeni anahtarın sibling tab'a geçişi ve reload. Gateway aynı snapshot'tan yeniden başlatıldıktan sonra iki sekmede gerçek `authOk` frame'i ve generation 3/HTTP 200 görüldü.
- **Storage/legacy/CSP:** kontrollü yazma hatasında session-only uyarısı ve reload; yanlış deployment/corrupt kayıtların korunması ve sıfır credential gönderimi; gerçek wallet yetkisiyle legacy hesabın kurtarılması. Uygulanan katı yerel CSP altında eklenti çalıştı. [Cüzdan kanıtı ve sınırlar](wallet/README.md).
- **İkinci RPC tanıklığı:** opsiyonel endpoint aynı finalized blok hash'i üzerinde chain/code/15 getter eşliği gerektirir. Yanlış, gecikmiş, erişilemeyen veya biçimsiz yanıt başarılı gözleme dönüşmez. Provider hata payload'ları ve URL/transport hataları credential parçalarını rapora taşımaz. Bağımsız incelemede bulunan redaksiyon hatası önce yeniden üretildi, sonra düzeltildi. [RPC kapsamı](rpc/README.md).

## Doğrulama

| Kontrol | Sonuç |
|---|---|
| Gerçek eklenti + native gateway | [01–08 CLI kodu/logu/sonucu](wallet/README.md), tüm nihai assertions geçti; controlled storage/lock/scope faults ayrı etiketli |
| Frontend unit | 481 geçti, 1 explicit canlı-gateway fixture skip |
| Chromium/WebKit fixture matrisi | 78 geçti; sentetik provider/API kapsamı gerçek eklentiden ayrı |
| RPC okuyucu | 29 test normal Python ve `python -O` altında geçti |
| Kaynak eşliği | Frontend93 kaynak/config/dependency dosyası test öncesi/sonrası/güncel aynı; wallet build 79 dosyası aynı. [Detay](checks/frontend-verification.json) |
| Public RPC | Tek salt-okunur güncel deneme HTTP 403; başarılı canlı eşlik iddia edilmedi |

Browser fixture koşusunda genel kaynak fingerprint'i yalnız `.gitignore` ve devam eden ham tarayıcı çıktılarının kaynak listesinden çıkarılması nedeniyle değişti; uygulama kaynakları değişmedi. Başarısız ilk ortam/smoke ve test-harness varsayımları [cüzdan kaydında](wallet/README.md) açıklandı, nihai başarılı kanıtla karıştırılmadı. [Bağımsız inceleme](review.md), [Graph kontratı](contract.json), [Graph raporu](report.json).

Gerçek token/proof, A06 guest yürütmesi, production dağıtımı, fon transferi veya dış kişiye mesaj yapılmadı. Desktop'taki önceki kullanıcı checkout'u değiştirilmedi. Test profilleri ve süreçleri için kapanış kayıtları cüzdan/runtime altında tutulur.
