# Chainlink aday yolu: Base sequencer kesinti kontrolü

10 Ekim 2026. **PRODUCTION RELEASE HOLD.** Bu değişiklik yalnız ayrı Chainlink
aday sözleşme yolundadır. Mevcut gateway, reviewed v2 guest/ELF/vkey, clock,
settlement ve vault kaynakları değiştirilmez. Canlı ağa deploy yapılmadı.

## Uygulama sözleşmesi

`ChainlinkOracleVerifier` yapıcısı ayrıca `uptimeFeed_` adresi ve açık,
sıfırdan büyük `graceSeconds_` ister. Feed adresinde sözleşme kodu bulunmalıdır.
İkisi immutable'dır; ayarı kapatan setter veya varsayılan ekonomik eşik yoktur.
Testlerdeki 10 saniye yalnız sentetik fixture değeridir, üretim tavsiyesi değildir.
Bu yeni yapıcı ABI'si eski aday deployment tarifiyle karıştırılmamalıdır.

`SequencerUptime.read` doğrudan yapılandırılmış feed'in `latestRoundData()`
sonucunu okur. Durum tam olarak `0` olmalı, durum başlangıcı pozitif ve gelecekte
olmamalı, `block.timestamp - startedAt > graceSeconds` sağlanmalıdır. Eşitlikte
henüz kabul yoktur. Sıfır round, hatalı uint80 ABI dolgu bitleri, farklı yanıt
uzunluğu, çağrı hatası, unknown/negative status ve uygunsuz zaman güvenli rettir.

Yanıt için sabit 160 baytlık çıktı tamponu kullanılır; daha büyük returndata belleğe
tamamıyla kopyalanmaz. Bu, feed'in çalışma/gas maliyetine mutlak bir sınır koymaz.
`updatedAt` fiyat heartbeat'i gibi değerlendirilmez: uzun süredir değişmeyen
sağlıklı durumun eski olması kendi başına kesinti değildir. Round numarası ve
`startedAt` birlikte uptime dönemi kimliği olarak saklanır.

### Kayıt ve gerçekleşmiş işlem zamanı

Fiyat kullanan bir batch'in raporları kayıt edilirken uptime kontrol edilir.
İlk işlemin **özgün** milisaniye zamanı da aynı uptime döneminin grace süresinden
sonra olmalıdır; saniyeye aşağı yuvarlanmış zaman üzerinden aynı katı `>` sınırı
uygulanır. Yalnız kayıt zamanının toparlanmadan sonra olması yeterli değildir.
Dış DON verifier çağrıları bittikten sonra kayıt yazılmadan kontrol tekrarlanır.
Arada durum/dönem değişmişse bütün kayıt işlemi revert olur.

Tam kayıt tekrarı dahi güncel kesinti kontrolünü atlayamaz; aynı kayıt başka uptime
dönemine yeniden bağlanamaz. Report hash'i, kaynak zamanları ve clock receipt'i
bu sebeple değiştirilmez. Aynı sağlıklı dönemde proof üretim gecikmesiyle raporun
expiry'si geçmişse önceki doğrulanmış kayıt yeniden tarihlenmeden kullanılabilir.

### Settlement sırasında yeniden kontrol

Kayıttan sonra sequencer kesilirse daha önceki kayıt settlement'ı yetkilendirmez.
Grace bitmiş olsa bile başka uptime dönemine geçen eski proof reddedilir.
Aynı `startedAt` ile farklı round veya aynı round ile farklı `startedAt` da
eski kayıt için geçerli değildir. Proxy/round değişiminin muhafazakâr duruşa neden
olabilmesi bilinçlidir; kullanılabilirlik için otomatik istisna eklenmedi.

`uptimeStatus()` gelecekteki gateway observer'ı için aynı kontrolü salt-okuma
olarak sunar. Bu metot bütün protokolün hazır/yayınlanabilir olduğunu bildirmez;
yeni gateway/prover bağlantısı henüz uygulanmış değildir.

### Fiyat gerektirmeyen çıkışlar

Clock anchor'ın `timedOps=0` olduğu ve boş rapor listesiyle bağlanan fiyat gerektirmeyen
batch, uptime feed arızasına bağımlı bırakılmaz. Yeni guest gerçek işlemleri tarayıp
oracle kullanan her işlem için rapor zorunlu tuttuğundan, boş listeyle fiyat kullanan
batch'i çıkış gibi göstermek geçerli proof üretmez. Sözleşme de liste sayısını
clock'a eşitler. Gerçek `finalSettle` ve `finalExit` girişleri sentetik DON/SP1
arka uçlarıyla feed kapalıyken sınanır. Bu gerçek fonlu exit/proof kanıtı değildir.
Base ağı blok üretemiyorsa bu kod zincir işlemlerinin gönderilebilmesini garanti etmez.

## Yeni bir kurtarma sınırı

Kesinti öncesinde mühürlenmiş fakat henüz sonuçlanmamış, fiyat kullanan batch'in
clock/rapor kaydı yeni uptime döneminde otomatik yeniden kullanılamaz. Özgün işlemlerin
saatini değiştirmek, yeni imza üretmek veya kayıt üzerine yazmak çözüm değildir.
Operasyonel reconciler bu durumu HOLD olarak ele almalı; yeniden admission/rollback
ve gerekirse fiyat gerektirmeyen wind-down kararı ayrıca doğrulanmalıdır.
Bu paket journal kurtarma otomasyonunu tamamlamaz ve bir state migration yapmaz.

## Bağlama ve canlı kabul

Oracle wrapper adresi zaten aday proof commitment'ine bağlıdır; uptime adresi/grace
onun immutable konfigürasyonudur. Rust proof/witness/policy biçimi değişmedi.
Buna karşılık wrapper runtime/yapıcı ABI kimliği değişti; yeni deployment manifest'i
iki immutable değeri ve bu kodu ayrıca doğrulamalıdır. Mevcut manifest aracının
bunu zaten yaptığı iddia edilmez.

Resmi belge Base mainnet için uptime proxy adresini
`0xBCF85224fc0756B9Fa45aA7892530B47e10b6433` olarak listeler (10 Ekim 2026 erişimi).
Bu adres otomatik deploy edilmedi veya yerelde canlı doğrulanmış sayılmadı.
Yapıcıdaki `code.length` testi adresin resmi Chainlink feed'i olduğunu kanıtlamaz.
Base Sepolia için resmi uptime adresi bu sayfada listelenmiyor; mainnet adresi
kopyalanmaz ve mock feed resmi ağ kanıtı olarak gösterilmez.

Chainlink uptime feed'i son bilinen durumu bildirir. L1/L2 mesaj gecikmesi, veri
sağlayıcı kesintisi, ekonomik grace seçimi ve ağ finalitesi ayrıca değerlendirilmelidir.
Canlı feed pinleri, authenticated stream erişimi, rapor kalıcılığı/recovery, gateway
bağlantısı, yeni guest execution/vkey/proof ve bağımsız audit hâlâ açık kapılardır.

## Kaynaklar

- Chainlink: L2 Sequencer Uptime Feeds (durum, grace ve Base proxy listesi):
  https://docs.chain.link/data-feeds/l2-sequencer-feeds
- Chainlink: Onchain report verification (DON özgünlüğü ile uygulama kabulünün ayrımı):
  https://docs.chain.link/data-streams/reference/data-streams-api/onchain-verification

## Yerel yeniden doğrulama

```sh
cd contracts
forge test --match-path 'test/Chainlink*.t.sol' -vv
forge test --summary
forge fmt --check src/SequencerUptime.sol src/ChainlinkOracleVerifier.sol \
  test/ChainlinkOracleVerifier.t.sol test/ChainlinkSequencerUptime.t.sol \
  test/utils/MockSequencerUptime.sol
```

Uptime, DON ve SP1 kaynakları testlerde açıkça mock'tur. Gerçek clock/settlement
kodu ile ret/atomiklik/çıkış akışı sınanması canlı attestation veya gerçek proof
anlamına gelmez. Ücretli hizmet ve gerçek anahtar kullanılmadı.
