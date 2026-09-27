# Arcora Perp: doğrudan S1/S2 düzeltmesi

Tarih: 27 Eylül 2026. Taban: PR #19, `7e2f1768d452633c7e8a2fe8f9eb513b473097b1`.
Bu değişiklik doğrudan hazırlanmıştır; yeni Kimi işi yoktur. PR #16'nın hesap başına
fence/watch tasarımı kaynak olarak incelenip uyarlanmıştır. Ana dala merge veya
canlı deployment yapılmaz. Tam codebase audit'i ve gerçek para yayın onayı değildir.

## Düzeltilen davranış

Gateway snapshot kuyruğunda `try_reserve` ile mutasyondan önce kapasite ayırır.
Gerçek istek yalnız başarılı key rotation SONRASINDA, Gw kilidi altında `permit.send`
ile yayımlanır. Writer bu noktadan sonra state yakalar. Hesap başına sabit runtime
fence mutation, durable ACK ve response oluşturma boyunca tutulur. Gw kilidi disk/ağ
beklerken tutulmaz. Son kontrolde key, owner, recovery generation, control kimliği ve
güncel authorizer doğrulanır. Bütün HTTP recovery işlemi tek dış deadline ile sınırlıdır.

AuthOk ve authenticated WS gönderimleri aynı hesabın read lease'ini bounded send
boyunca tutar. Watch boşta duran eski oturumu trafik gerektirmeden uyandırır. Başka
hesabın disk ACK'i beklenirken diğer hesap özel event almaya devam eder. Timeout'tan
sonra socket tekrar flush edilmez. Kullanılmış recovery imzası replay kabul edilmez;
unknown outcome sonrasında GET ile güncel challenge okunur ve yeniden imzalanır.

Frontend kayıtları schema 2, canonical gateway URL + chainId + vault + owner + sunucu
recoveryNonce'u ile doğrulanır. Cross-tab yazımlar Web Locks ile sıralanır; localStorage
read/set çifti atomik kabul edilmez. Aynı istemcide recovery single-flight, sekmeler
arasında aynı owner için imza/POST öncesinde ifAvailable kilidi vardır. Kilit desteği
olmayan ortam recovery'yi mutasyondan önce reddeder.

Init/register/aggregate refresh ve eski WS callback'leri epoch, intent ve socket
kimliğiyle sınırlandırılır. Aggregate refresh tek credential kullanır. 401/503, bozuk
veri ve ağ hatası otomatik replacement account oluşturmaz. Yeni API key 32-byte hex,
owner ve nonce+1 ile doğrulanır; HTTP deadline gövde okumasını da kapsar.

Confirmed rotation sonrası storage yazılamazsa yeni key bellekte tutulur ve UI açıkça
**yalnız bu sekmede erişim** uyarısı gösterir. Eski key baytlarını saklamak onu sunucuda
geçerli kılmaz; reload sonrası fresh challenge ve wallet recovery gerekebilir.

## Uyumluluk ve migration

**Gateway ve frontend birlikte güncellenmelidir.** Yeni frontend public status'ta
chainId/vault yoksa credential göndermeden durur. Eski `darkperp.v1Account` kaydı
unscoped olduğundan otomatik başka deployment'a gönderilmez, silinmez ve yerine
boş hesap açılmaz. Kullanıcı eski kaydındaki public owner id ve mevcut yetkili cüzdanı
ile recovery yapar. Bu migration bakiyeyi, snapshot'ı veya zincir durumunu sıfırlamaz.
A01 permit/credited receipt key taşıması ve snapshot formatı korunur; core, SP1 guest,
contracts ve dependency lock'ları değiştirilmez.

## Yeni doğrulama

Gateway read-only koşusu: [36334230430](https://github.com/Kubudak90/dark-perp/actions/runs/36334230430),
job `108661883657`, artifact `10937275122`. Üç `direct_` testi eski PR19 üzerinde
**0 geçti / 3 assertion hatası** verdi; derleme hatası başarı sayılmadı. Adayda S1
**27 geçti**, gateway **356 geçti / 1 ignored**, workspace **722 geçti / 1 ignored**.
Bu seçimler örtüşür, birbirine eklenmez. Fmt ve workspace/all-targets Clippy
`--locked -- -D warnings` başarılı. Ignored test mevcut A01 localhost JSON-RPC cast
testidir; bu koşuda çalıştırılmış veya canlı zincir testi sayılmaz.

Frontend read-only koşusu: [36334644779](https://github.com/Kubudak90/dark-perp/actions/runs/36334644779),
artifact `10936728674`. Aynı üç malformed string-key testi eski PR19 client'ında
beklenen assertion ile düştü. Aday frontend **316 geçti / 1 skipped**, production
TypeScript/Vite build başarılı. Recovery dosyası 35 testtir. Atlanan mevcut HTTP
E2E testi GATEWAY_URL gerektirir. Yerel frontend koşusu da aynı sonuç verdi.

İndirilen iki artifact ZIP'inin SHA-256'ı API digest'leriyle karşılaştırıldı. Aday
kaynak, hash'i doğrulanan backend/frontend patch'lerinin birleşimidir. Sonrasında
yalnız eski davranışı anlatan bir kod yorumu ve audit belgeleri düzeltilmiştir.
Makine kaydı: `2026-09-27-direct-evidence.json`. Normal PR CI ve varsa localhost
HTTP entegrasyon sonucu kendi run/head kimlikleriyle PR açıklamasında ayrı verilir.

## Açık kalan sınırlar

Gerçek SP1 ELF/vkey/proof/deployment, canlı TEE/L1, fiziksel kill/power-loss ve bağımsız
review yapılmadı. Gerçek dosya write/fsync/open/boot-restore testi fiziksel güç kesintisi
değildir. Web Locks testleri kontrollü mock kullanır; gerçek tarayıcı multi-tab stress
kanıtı değildir. Önceden TCP'ye verilmiş byte'lar geri alınamaz; sonraki meşru rotation
önceki response key'ini kullanıcıya ulaşmadan iptal edebilir. Tam recovery/rebind ve
transport stress matrisi, XSS/CSP, genel frontend mutation yarışları ve S3-S7 açıktır.
