# Chainlink arşiv / gateway / journal bağı: son doğrulanmış kanıt

Tarih: 11 Ekim 2026. **PRODUCTION RELEASE HOLD.**
Kod commit'i: `e283958109fc6b434b7049d523bbd3378e2e6c27`.
Taban main: `c34fb56b05db13ce09efc0104c2d44abba6d6895` (#43).
PR: #44, varsayılanı kapalı aday entegrasyon.

## Kanıtın kimliği ve kapsamı

[final-verification.json](final-verification.json), özgün yerel doğrulama
kaydının **baytları değiştirilmemiş kopyasıdır**. SHA-256:

```text
51586580224bb7c6c9358beb8471b618e9139db528a69266901b77a9dfd0caa0
```

Gerçek test koşusu: **10 Ekim 2026 22:35:04–22:36:40 UTC**, yani
**11 Ekim 2026 01:35:04–01:36:40 Europe/Istanbul**. Bu yayın adımı yeni bir
geniş test koşusu değildir. [evidence-recheck.json](evidence-recheck.json)
18 kaynak hash'inin hem çalışma ağacı hem exact kod commit'iyle, 13 özgün
log hash'inin yerel kayıtlarla yeniden eşleşmesini kaydeder. 21 reviewed-v2
ve 9 aday runtime kaynak pini ayrıca yeniden kontrol edildi.

Ham test logları `target/independent-binding-review-20261010T223319Z/`
altındadır; kamu paketine eklenmemiştir. Kamuya açık dosya komutları, exit
kodlarını, kaynak/log hash'lerini ve test özetlerini taşır. Okuyucu kaynakları
exact commit'ten doğrulayabilir; ham logların bağımsız incelenmesi için özgün
loglara erişim gerekir. Özel snapshot/witness/anahtar/credential yayınlanmaz.

`verified_code_commit` test edilen kodu belirtir. Bu belgeyi ekleyen Git
commit'i farklıdır; yeni dokümantasyon head'i için CI ayrıca kontrol edilmelidir.
Recheck'teki **19/19 SUCCESS**, yalnız `e283958` head'inin tarihli gözlemidir;
daha yeni head'e veya production kabulüne taşınmış sayılmaz.

## Devam tabanı ve yayın durumu

11 Ekim devam kontrolü [continuation-recheck.json](continuation-recheck.json)
içindedir. Özgün validation dosyasıyla kopyanın baytları, 18 kaynak hash'i,
13 yerel log hash'i ve 21 reviewed / 9 aday pini yeniden doğrulandı. Kaynak
kontrolü doğrudan `e283958` Git nesnelerini okur; sonraki çalışma ağacı
değişiklikleri bu eski test sonucuna dahil edilmez. Testler yeniden koşulmadı.

Korunan birincil checkout `2a03bb0`'dadır. #44 head'i `e283958`, bu commit'in
14 commit ilerisindedir; birincil checkout'un benzersiz commit'i yoktur.
Birincil checkout'un 13 yerel dosyasından 8'i kaynak iş checkout'uyla aynı
baytlardadır. İki kaynak farkı daha yeni `ArchiveId` serde derive'ları ve
`policy_binding`'in public yapılması ve açıklamasıdır; üç belge daha yeni gateway/recovery
durumuyla ilerletilmiştir. Benzersiz birincil kaynak işi bulunmadı; iki
özgün checkout korunarak yeni çalışma daha ileri soy üzerinde sürdürülür.

Kayıt zamanında GitHub PR #44 **OPEN, draft=false**, head `e283958`, base
`c34fb56` olarak okundu. Bu gözlem sonraki yayın head'inin CI veya merge
sonucunu doğrulamaz. Önceki `evidence-recheck.json` tarihli kaydı korunur.

## Gerçek sonuçlar

| Kontrol | Sonuç |
|---|---|
| Gateway tam paket | 528 PASS, 0 FAIL, 16 IGNORE |
| Arşiv-bağlama testleri | 22 PASS; 528 toplamının içinde |
| Standalone istemci / arşiv debug | 62 PASS, 0 FAIL, 1 ignored yardımcı child sürücüsü |
| Standalone istemci / arşiv release | Aynı 62 test: 62 PASS, 0 FAIL, 1 ignored yardımcı child sürücüsü |
| Python artifact / release / policy guard | 47 PASS |
| Workspace all-target Clippy | `-D warnings` ile PASS |
| Workspace ve standalone istemci format / Clippy | PASS |
| Aday no_std, SP1 release, aday lock | PASS |
| Reviewed v2 / aday kaynak pinleri | 21/21 ve 9/9 aynı |
| Kök Cargo.toml | Tabanla baytları aynı |
| Kök Cargo.lock registry kimlikleri | 244/244 aynı; dosyanın bütünü değişmemiş değildir |

Gateway'deki 16 ignored test geçmiştir denmez. İstemcideki ignored child
sürücüsü, parent test tarafından açıkça çağrılır; debug/release toplamı 124
farklı test değildir. Son yerel koşu tam workspace testini yeniden çalıştırmış
sayılmaz; GitHub workspace CI ayrı kayıttır. `chainlink-oracle` için eski
16-test sonucu bu 13-komut final koşusuna eklenmiş gibi sunulmaz.

## Bağlanan gerçek yol

`ArchiveBinding::admit_with`, arşiv kilidi ve gateway state kilidi altında
kapasite kontrolünü, özgün çiftin kalıcı yazımını, fiyat kabulünü ve ilk kabul
edilen ArchiveId seçimini birleştirir. Reddedilen rapor seçilebilir indekse
girmez. Aynı normalleştirilmiş fiyatı veren alternatif kayıt, ilk seçilmiş
özgün ID'nin yerini alamaz. Eksik kayıt yerine en yeni dosya aranmaz.

Gerçek Fill / AccrueFunding / Liquidate / Unbind oracle kullanımları işlem
sırası ve tekrarlarıyla bağlanır. `DPRBJL6\0`, v5 içerik ile arşiv zarfını
aynı authenticated journal içinde taşır. Geçerli v5 yazım biçimi korunur;
trailing plaintext ve sürüm karışıklığı reddedilir, v6 kanonik kodlama ister.

Aday snapshot plaintext'inin içinde doğrulanan `DPCAS1\0\0` etiketi vardır.
`.chainlink` marker kaybı ve aday ayarının unutulması legacy açılışı sağlamaz.
Marker ayrıca politika bağını taşır. Bu etiket tek başına açık pencerenin
politikasını veya kabul edilmiş rapor indeksini geri kurmaz.

Normal gönderim ve exact-resume, **sıfır-oracle ve wind-down dahil bütün aday
pencerelerini**, eski v2 clock-registration / prove / broadcast yolundan önce
reddeder. Yeni aday prover/settlement yolu henüz yoktur; journal sonrası HOLD
bir güvenlik sınırıdır, tamamlanmış bir settlement hizmeti değildir.

## Eski audit iddialarının açık düzeltmeleri

Önceki metin [historical-notes.md](historical-notes.md) içinde korunur; güncel
kanıt değildir. Özgün Git geçmişi de değişmemiştir.

| Eski iddia | Doğrusu |
|---|---|
| Root exclude değişirken bütün pinler geçti | `298e30f` öncesi root pinleri başarısızdı. Bu commit root manifest'i eski baytlarına döndürdü. |
| chainlink-oracle yalnız host bağımlılığıdır | Aday guest de kullanır. Host facade aynı özgün kaynakları derler; kopya veya yeni guest kimliği değildir. |
| a4e1c3e snapshot/marker-loss testini içerir | O commit'te test yoktu. Gerçek test `e283958` ile eklendi ve çalıştırıldı. |
| Snapshot wire bytes untouched | Legacy biçim korunur; aday authenticated plaintext'ine yeni sürümlü etiket eklenir. |
| Marker açık pencerenin tam recovery'sini kapattı | Yalnız mod düşürme engeli sağlar. Bellekteki kabul indeksi restart'ta boş başlar. |
| Real replay prove / identical commitments | Native MockProverClient replay; gerçek SP1 proof veya DON doğrulaması değildir. |
| 12 Ekim review başlıkları | Yanlış tarih. Son gerçek koşu 10 Ekim UTC / 11 Ekim Türkiye saatindedir; ara aşamalar için bilinmeyen saat uydurulmaz. |
| 16 SUCCESS / 3 pending | `e283958` için recheck gözleminde 19/19 SUCCESS; sonraki head ayrıca doğrulanır. |

## Doğrulanmış kod head'inde sonraki işler ve kabul sınırı

1. Açık pencerenin özgün kabul ID'lerini politika/state/checkpoint ile aynı
   authenticated kesitte kalıcılaştırma; restart'ta aynı op sırası ve aynı
   ID'lerle seal. Eksik/bozuk kayıt, yanlış politika, marker kaybı, eşdeğer
   alternatif, yarım kabul ve snapshot yazım hatasında güvenli ret.
2. 4096 girdilik indeks için güvenli retention/kapasite; aktif açık pencere,
   journal ve recovery referanslarını silmeden uzun koşu ve doluluk yönetimi.
3. Funding / liquidation / close / mark / matching dahil bütün fiyat kullanan
   yolların olumlu ve olumsuz aday yaşam döngüsü testleri.
4. Ayrı aday witness / program / vkey / DON-report / settlement bağlantısı;
   yanlış sürümde sıfır registration/prove/broadcast. Gerçek proof ve canlı
   kabul olmadan production gönderim engeli kaldırılmaz.

Canlı feed keşfi/entitlement kullanıcı kararıyla ertelenmiştir. Yeniden
sorgulanmadı, feed/decimal/anahtar tahmini yapılmadı. Gerçek DON, yeni proof,
deployment kimliği, canlı CC/key release, fon/exit kabulü ve bağımsız audit
açıktır. GPU, ücretli servis, gerçek fon, kamu zincirine yazı, state migration
ve production rollout bu paketin kapsamı değildir.
