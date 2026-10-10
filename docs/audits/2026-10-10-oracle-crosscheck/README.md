# Arcora Perp: bağımsız oracle kaynak kontrolü

Tarih: 10 Ekim 2026. Başlangıç main: `8ed3fc2fb2776a6e711ac24d6e804ab6539cfd6a`.
Dal: `feat/oracle-crosscheck-20261010`.

**Karar: Yerel CPU doğrulaması geçti. PRODUCTION RELEASE HOLD devam ediyor.**
Bu kayıt PR açılmadan önce üretildi; sonraki PR/CI durumunun yerine geçmez.

## Sonuç ve açık etkinleştirme engeli

Crypto.com + OKX için sınırlı HTTP gövdeli iki-kaynak adapter'i ve isteğe bağlı
gateway kontrolü uygulandı. Ancak **mevcut varsayılan hâlâ tek kaynaktır**.
USDC etiketli piyasalar BTC_USDT/ETH_USDT/SOL_USDT spot feed'leri kullanıyor.
Yeni mod, bu birimleri eşdeğer saymamak için bugünkü konfigürasyonda başlangıcı
reddeder. Kaynak/para birimi politikası düzeltilmeden çalışan canlı iki-kaynaklı
USDC deployment iddiası yoktur.

`DARKPERP_ORACLE_CROSSCHECK_MAX_DEVIATION_PPM` açık ayarı dışında mod açılmaz;
varsayılan/tahmini ekonomik eşik eklenmedi. Testlerde 1000 ppm ve test belleğinde
aynı USDT birimindeki market etiketleri kullanıldı. Gerçek MARKETS, hizmet ayarları,
piyasa kimliği, teminat veya ekonomik risk parametreleri değiştirilmedi.

## Uygulanan kabul sözleşmesi

OKX'in SPOT/instId/code/msg/last/bid/ask/ts alanları strict typed decode edilir.
Aynı source-pair ve market zorunludur; kritik tekrar, yanlış tip, eksik veri,
gelecek/sıfır zaman, yanlış quote veya perpetual ikamesi reddedilir. İki istek de
64 KiB gövde sınırı, no-redirect ve istek başına 5 saniye timeout kullanır.
Global endpoint, resmi 20 Mayıs 2026 domain güncellemesine göre `openapi.okx.com`.
Bölgesel erişim/canlı instrument uygunluğu ayrı deployment kontrolüdür.

Her iki kaynak gerçek gateway receipt anında aynı mevcut validator'dan geçer.
Her birinin kaynak zamanı kendi son başarılı kabulünü aşmalıdır. Secondary,
primary'den eski olamaz: değişmeyen guest yalnız primary zamanını taşıdığından,
eski secondary'nin daha yeni primary arkasında gizlenmesi reddedilir. Yeni saat
veya skew toleransı üretilmez. Son fiyatlar ve book midpoint'leri açık, simetrik,
taşma kontrollü sapma sınırını ayrı ayrı geçer.

Başarıda primary'nin fiyatı, zamanı, imzası ve commitment girdileri aynen korunur.
Başarısız pair/transport/task sonucu tek-kaynak fallback'e dönüşmez. Opt-in modda
oracle kabulü geçersiz/imzasız sentinel ile hemen durur; son görüntülenen fiyat
ve receipt/source zamanları yenilenmez. Sentinel yeni fiyat veya evidence değildir.
Aynı modda demo tick'i de fiyat uyduramaz; tek imzalı intake kontrolü atlayamaz.
Watermark'lar yalnız downstream kabulüyle birlikte ilerler; runtime-only olduğundan
snapshot/journal wire biçimi değişmez. Restore taze ve doğru eşlenmiş çift bekler.

## Doğrulanan sonuçlar

| Kontrol | Sonuç ve kapsam |
|---|---|
| Tam Rust workspace | **947 PASS, 0 FAIL, 17 IGNORE** |
| Gateway, workspace toplamına dahil | **500 PASS, 0 FAIL, 16 IGNORE** |
| Oracle HTTP, workspace toplamına dahil | **50 PASS: 45 library + 5 integration** |
| Oracle default, ayrı koşu | **27 PASS** |
| Yeni test sayısı | **32**: 12 host-core + 10 HTTP + 10 gateway |
| Gerçek gateway başlangıcı | **3/3 beklenen güvenli ret, exit 1** |
| Workspace Clippy, tüm hedefler, -D warnings | PASS |
| Format / git diff whitespace | PASS |
| perp-core no_std check | PASS |
| SP1 release guard | PASS |
| Reviewed guest kaynak pinleri | **21/21 aynı** |
| Reviewed ELF SHA-256 | Aynı; manifest içinde |

Gateway ve HTTP testleri workspace üzerine tekrar eklenmez. Ignored testler
geçmiş sayılmadı. Workspace dışı SP1 host/prover-service, frontend, sözleşme ve tam
Python/Anvil/restore/ACK-crash paketleri bu turda ayrıca yerelde çalıştırılmadı;
bunların önceki sonuçları yeni çalıştırma diye sunulmaz.

Yeni HTTP testleri aynı production fetch fonksiyonunu iki kendimize ait loopback
sunucusuyla kullanır. Yanlış quote, kısmi/duran/aşırı büyük/chunked/EOF gövde,
redirect hedefinin çağrılmaması ve ikinci kaynak yokken primary başarısı üretilmemesi
sınanır. İlk geliştirme koşularında macOS accepted socket üzerinde kalmış O_NONBLOCK
bayrağı test kararsızlığına yol açtı; test düzeneğinde blocking I/O açıkça kuruldu.
Üretim timeout/ret kontrolleri gevşetilmedi ve geçici diagnostics kaldırıldı.
Yeni API testlerinin eski kodda çalışıp başarısız olduğu iddia edilmez.

Gerçek gateway binary'si üç ayrı boş dizinde ve miras alınmayan minimal ortamda
çalıştırıldı. Mevcut USDT/USDC bağ uyuşmazlığı, boş threshold ve UTF-8 olmayan
threshold ayrı ayrı beklenen hata ile exit 1 verdi. Gerçek servis/anahtar/state
kullanılmadı. Bu testler dış ağ için sandbox/izolasyon kanıtı değildir.

## Korunan sınırlar

**R06 hâlâ açık.** İki kaynak aynı operatör anahtarıyla imzalanır; kaynak etiketleri
exchange-signed kriptografik evidence değildir. Ele geçirilmiş publisher/host iki
kaynağı da uydurabilir. Mevcut `trusted_publisher_can_reprice_primary_and_backup_together`
ve yeni same-host fabrication karakterizasyon testleri bu sınırı açık tutar.
`backup_twap` hâlâ primary'nin aynı book midpoint'idir; gerçek TWAP değildir.

Guest/perp-core, ELF/vkey pinleri, public input, sözleşmeler, dependency lock ve
mevcut risk eşikleri başlangıç main ile aynı kaldı. Review/CI korumalarına dokunulmadı.
Yeni vkey setup veya proof üretilmedi. Canlı CC/key-release, gerçek fonlu exit,
ücretli kaynak, production rollout veya state migration yapılmadı.

## Kalıcı kanıt ve sonraki paket

`verification.json` komutları, gerçek exit kodlarını, test sayılarını, final kaynak
hash'lerini, reviewed pinleri ve yerelde tutulan ham log hash/yollarını içerir.
`evidence/workspace-results.txt` seçilmiş test/sonuç satırlarıdır, tam ham log değildir.
`evidence/startup-refusals.json` üç gerçek süreç ret sonucunu ve binary hash'ini verir.
Ham geliştirme ve final test log'ları ignored `target/oracle-crosscheck-20261010/`
altında korundu. Bu kayıt bağımsız audit veya CI sonucu değildir.

Ayrıntılı veri/konfigürasyon sözleşmesi ve resmi API referansları:
[ORACLE_CROSSCHECK.md](../../ORACLE_CROSSCHECK.md).
Sonraki ayrı paket, USDC fiyat kaynağı veya açık USDT/USDC dönüşümünün ekonomik ve
kimlik bağlarını kararlaştırıp test etmelidir; burada risk kararı tahmin edilmedi.
