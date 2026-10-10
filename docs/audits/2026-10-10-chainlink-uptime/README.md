# Arcora Perp: Chainlink adayında sequencer kesinti kontrolü

Tarih: 10 Ekim 2026. **PRODUCTION RELEASE HOLD.**
Bu paket, PR #40 adayına ayrı ve zorunlu uptime/grace kontrolü ekler.
Yerel çalışma tabanı: `a4a6ae8a8181eaa1cd9e61daa8c0b1c50769bd96`.
Bu, #39 main'e alındıktan sonra güncellenmiş #40 ağacıdır.

## Uygulanan sonuç

Yapıcıda kodu olan açık uptime feed adresi ve sıfırdan büyük açık grace süresi
zorunludur. Durum kodu, status-change zamanı, ABI boyutu/dolgu bitleri ve grace
sınırı kontrol edilir. Rapor kaydının hem öncesinde hem dış DON çağrılarından
sonra sağlık doğrulanır. İlgili işlemlerin özgün saatleri aynı grace sınırını
geçmelidir: geç kayıt, kesinti sırasında gerçekleşen işlemi aklamaz.

Kayıt `(roundId, startedAt)` dönemine bağlanır. Settlement, güncel sağlığı ve
aynı dönemi tekrar arar; eski proof yeni toparlanma döneminde kullanılamaz.
Tam kayıt tekrarı da kontrolü atlayamaz. Fiyat gerektirmeyen, clock ve yeni
proof ile bağlanmış boş oracle akışı uptime arızasına bağımlı bırakılmaz.
Gerçek `finalSettle` ve `finalExit` yolları sentetik arka uçlarla sınandı.

## Son doğrulama

| Kontrol | Sonuç |
|---|---|
| Tüm Foundry sözleşme testleri | **161 PASS, 0 FAIL, 0 SKIP** |
| Yeni uptime regresyonları (161'in içinde) | **20 PASS** |
| Önceki Chainlink aday testleri (161'in içinde) | **15 PASS** |
| Standalone Chainlink Rust testleri, ayrı kapsam | **15 PASS** |
| Değişen sözleşmelerin format kontrolü | PASS |
| Candidate lock / reviewed SP1 release kontrolü | PASS |
| Reviewed v2 kaynak pinleri | **21/21 değişmedi** |

Foundry invariant tablosundaki handler çağrı/revert sayıları test başarısına veya
başarısızlığına eklenmez. Rust workspace, frontend, gerçek proof, guest execution,
canlı Chainlink veya gerçek gateway tatbikatları bu turda yeniden koşulmuş sayılmaz.
Ek iki fuzz testini ekleyen çağrı araç güvenlik engeline takıldı; dosyada bulunmadıkları
okunarak doğrulandı. Bu çağrı yeniden denenmedi ve test sayısına eklenmedi.

Uptime, DON ve SP1 kaynakları açıkça mock'tur. Gerçek clock/settlement kodundaki
ret ve atomiklik testleri gerçek ağ outage/finality/proof kanıtı değildir.
Test grace değeri 10 saniye yalnız fixture'dır. Onaylı production grace değeri yoktur.

## Korunan sınırlar ve takip işi

Bu değişiklik Solidity aday wrapper runtime'ını ve yapıcı ABI'sini değiştirir.
Reviewed v2 guest, ayrı aday Rust guest kaynakları, witness/public input, ELF/vkey,
mevcut ekonomik eşikler, clock, settlement ve vault kaynakları değiştirilmez.
Yeni uptime immutable'larının deployment manifest'ine bağlanması ayrıca gereklidir.

Kesinti öncesinde mühürlenip henüz sonuçlanmamış fiyat kullanan batch, yeni uptime
dönemine taşınamaz. Reconciler'ın HOLD/rollback/yeniden admission ve gerekirse
fiyat gerektirmeyen wind-down davranışı ayrı açık kabul kapısıdır. Timestamp,
rapor veya journal otomatik değiştirilmedi. Yeni state migration/deploy yapılmadı.

Canlı signed stream istemcisi, feed/decimal/USDC pinleri, gateway/prover/L1 bağlantısı,
rapor kalıcılığı/kurtarma, gerçek DON, yeni guest execution/vkey/proof ve bağımsız
audit henüz tamamlanmış değildir. `docs/ACTIVE_WORK.md` güncel iş listesidir.

Detaylar ve resmi kaynaklar: `docs/CHAINLINK_SEQUENCER_GUARD.md`.
`verification.json` gerçek komut/exit/log hash'lerini ve kaynak hash'lerini içerir.
`contract-results.txt` seçilmiş test/sonuç satırlarıdır; tam ham log değildir.
Ham loglar ignored `target/chainlink-uptime-20261010T160847Z/verification/` altında
korunur. Bu kayıt yerel test kanıtıdır; PR CI veya bağımsız audit değildir.

## PR tabanı

#40, güncel head üzerinde 18/18 kontrol tamamlandıktan sonra normal merge edildi.
Yeni iş dalı `40b8c61cba9755e80fc17e0cf01950ee8aaa4574` main commit'inden açıldı.
Merge ağacı test edilmiş `a4a6ae8` ağacıyla eşittir. Bu paketin test edilmiş
beş kod dosyası SHA-256 karşılaştırmasıyla aynen yeni dala taşındı.
