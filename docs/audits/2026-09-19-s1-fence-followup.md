# S1 devamı: recovery yanıtı ve WebSocket rotation sınırı

Taban: `f997f8b96279bd06ec1808f6b9cb2a6aeb25cc5e` (PR #14 birleşmiş).
Kaynak hash'leri, komut/exit kodları ve doğrulama run'ı
`2026-09-19-s1-fence-evidence.json` içindedir. Bu run final-head CI değildir.

## Bulgular ve düzeltmeler

- PR #14 HTTP handler'ı ACK beklerken superseded olan key'i confirmed diye
  döndürebiliyordu. Hesap başına sabit exclusive fence; mutation, ACK ve yanıt
  oluşturmayı birlikte sıralar. Son kontrolde key, owner, nonce, fence kimliği
  ve güncel authorizer yeniden doğrulanır. Conflict yanıtında key bulunmaz.
- WS generation kontrolü ile async gönderim arasında yarış vardı. AuthOk ve
  authenticated gönderim aynı hesap fence'inin read lease'ini transport yazımı
  boyunca tutar. Genel Gw kilidi ağ bekleyişinde tutulmaz.
- Boşta oturum artık trafiğe ihtiyaç duymadan watch bildirimiyle iptal edilir.
  Gönderim ve lease bekleyişi iki saniye ile sınırlıdır. Başarısızlıkta socket
  düşürülür; fence dışında tekrar flush yapılmaz.
- Fence serde-skip'tir, key rotation sırasında aynı hesapla taşınır ve restore'da
  yeniden oluşur. Snapshot formatı ve deposit referansları değiştirilmedi.
- Recovery yanıtları Cache-Control: no-store taşır.

## Kanıtın sınırı

İki değişmeden kullanılan gerçek route/socket testi PR #14 tabanında assertion
ile başarısız, yamalı kaynakta başarılıdır. Diğer testler devam eden gönderim,
gönderim timeout'u, kuyruktaki özel event, dolu/kapalı snapshot kuyruğu, kesin
noktada request iptali, gerçek şifreli snapshot write/fsync/restore ve ACK sonrası
authorizer kontrolünü kapsar. Send-stall future ve authorizer değişimi kontrollü
fixture'dır; tam TCP backpressure veya rebind E2E kanıtı değildir.

ACK, seri snapshot writer'ın capture/write işleminden sonra gelir. HTTP fence'i
aynı hesabın sonraki rotation'ını yanıt oluşturulana kadar bekletir. Daha sonra
bilinçli yapılan rotation ağdaki yanıtı geçersizleştirebilir; TCP'ye daha önce
verilen byte'lar geri alınamaz. Garanti sunucu mutation/gönderim sıralamasıdır,
istemcinin ağdan teslim alma anıyla atomiklik değildir.

PR #14 raporundaki eski davranış için 'kalıcı kilitlenme' ifadesi fazla güçlüydü:
wallet authorizer yeni public challenge okuyup tekrar yetki verebilirdi.
Idempotency kaydı halen process-local'dir. Restart sonrası gerçek restore nonce'u
okunmalıdır, körlemesine nonce+1 kullanılmaz. Nonce tükenmesi fail-closed kalır.

## Açık kalanlar

Exact final-head CI ve kalan yetki/rebind/transport/failure matrisi doğrulanana
kadar S1 kapanmadı. Fiziksel crash drill, gerçek SP1, deployment ve canlı zincir
işlemi yapılmadı. S2 ancak S1 sonrasında ele alınır.
