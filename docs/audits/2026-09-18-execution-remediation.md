# Dark-perp: emir iptali ve gerçekleşme takibi

Tarih: 18 Eylül 2026
Başlangıç: PR #2, `3b15ee469dfde89a4b0477d8d2a62edfc4f020b1`.
Kapsam: A04 ve A05 için native matcher/sequencer/gateway akışı ve arayüzü.
Doğrulanmış uygulama commit’i: `d1f5ffb0c70fa199caf657582f0b7dbfa8d678f5`.
Dal: `fix/execution-2026-09-18`; PR #2 üzerine eklenir. Merge, deployment veya canlı zincir işlemi yapılmadı.

## Doğrulama sonucu

GitHub Actions `35313262794`: verify job `105499526092` ve publish job `105500446865` başarıyla tamamlandı. Runner commit’i `1b078e5d95737f3a4d371a38fb00322df600f591`; çalışma kodu geçici kopyada patch uygulanıp biçimlendirildikten sonra test edildi ve aynı byte’lar ayrı publish adımında dala yazıldı.

| Kontrol | Sonuç |
|---|---|
| Rust workspace | 633 geçti, 0 başarısız, 0 atlanan; önceki 609’a göre 24 yeni test |
| Özel execution testleri | 17 geçti; workspace sayısına dahildir |
| İptal dayanıklılığı testleri | 2 geçti; workspace sayısına dahildir |
| Eski PR #2’ye aynı execution testleri | 1 geçti, 16 beklenen davranış hatası; derleme başarılı, test exit 101 |
| Ayrı core-serde | 156 geçti; workspace ile örtüşür, toplama eklenmez |
| Frontend | 268 geçti, 0 başarısız, 1 canlı gateway testi atlandı; 7 yeni test |
| Foundry | 89 geçti, 0 başarısız, 0 atlanan |
| Clippy `-D warnings`, Rust biçim kontrolü | Başarılı |
| Core `no_std + serde`, matcher `no_std` | Başarılı |
| Frontend production build, `git diff --check` | Başarılı |

Test profili `opt-level=2`; debug assertions ve overflow checks açık. Fuzz örnek sayıları azaltılmadı. Eski sürümün beklenen davranış hataları yeni kodun başarısıyla karıştırılmamalıdır; 16 başarısız test 16 ayrı güvenlik açığı demek değildir. Önceki iptal edilmiş/başarısız denemeler son kanıt olarak kullanılmaz.

[Doğrulama çalışması](https://github.com/Kubudak90/dark-perp/actions/runs/35313262794) · [Ham log/status/patch ZIP](https://github.com/Kubudak90/dark-perp/actions/runs/35313262794/artifacts/10534382422)

İndirilen ZIP SHA-256: `dffb316845abfc8db33733606b93289c9c954ed575fc7f00628ed22ca422786c`, GitHub artifact digest’iyle eşleşti. Test edilen nihai patch SHA-256: `630593ce385d307dc7df947fbf6abe26e514903235c4871059dc6a8c03dee721`.

Son dokümantasyon/temizlik commit’i uygulama kodunu değiştirmez; geçici payload ve çalıştırma workflow’unu kaldırır. Standart PR CI ayrı bir çalışmadır. Bu rapor gerçek SP1 proof, gerçek TEE veya canlı deployment doğrulaması değildir.

## Davranış

Emrin `sealed` olması veya daha önce `SETTLED` olması, kalan canlı miktarın iptalini engellemez. İptal yalnızca caller-scoped hesabın ilgili order hash'ine ulaşır; gerçekleşmiş miktarı/pozisyonu geri almaz. İptal edilmiş satır ve ilk kabul makbuzu geçmişte kalır. Aynı kullanıcı iptalinin tekrarı idempotenttir; tamamen dolmuş ve artık defterde olmayan emir `ORDER_NOT_LIVE` döndürür.

Üretim DELETE akışında persistence yoksa mutasyon yapılmadan 503 döner. İptal uygulandıktan sonra snapshot ACK başarısızsa 503 `DURABILITY_UNKNOWN` döner; iptal tersine çevrilmez. Tekrar aynı iptalden devam edip yeni ACK istenebilir. Başarı bildirimi genel WS üzerinden değil owner-filtered hesap event kanalı üzerinden iletilir.

Gerçekleşme yalnızca başarılı ledger Fill operasyonlarının matcher order hash eşlemesine dayanır. Başarısız deneme veya yeniden eşleştirme turundaki geçersiz fill raporlanmaz. Maker ve taker için miktar ve gerçek işlem fiyatı olayları üretilir; SETTLED geçişi ikinci bir fill olayı üretmez. Cumulative VWAP, tekrarlanan yuvarlamalardan kaçınmak için 256-bit sum(size*price)/sum(size) hesabıdır.

`Finality` ve execution ayrı eksenlerdir. Önceden SETTLED emir sonradan kısmi fill alırsa finality geriye yazılmaz; yeni fill'ler `unsettledSize` içinde tutulur. Yalnızca daha önce sertleşmiş miktar `settledSize` içinde görünür. Mevcut bir SETTLED etiketi kalan miktarın dolduğu veya tüm sonraki miktarın sertleştiği anlamına gelmez.

## Kanıt sınırı

Mevcut guest, matcher'ı baştan çalıştırmaz; `perp-core::derive_roots` ile ledger op'larını ve manifesti işler. İptal ve tick, gateway'nin aynı kilidi altında atomik/sıralı çalışır; iptal ledger'a gizli bir finansal mutasyon eklemez. İptal hash'i mevcut window rejection manifestine `Cancelled` olarak kaydedilir. Sonraki seal'in ledger replay'i aynı root'u üretmelidir.

Execution metadata gateway/native verisidir. Fill miktar/fiyatları başarılı ledger op'larına karşılık gelir; order hash eşlemesi, lifecycle kararının doğruluğu ve eşleştirme adaleti ayrıca ZK kanıtlanmış değildir (`proven: false`). Aynı pencerede daha önce fill alan veya sıralanmış hash, mevcut window union modelinde ordered ve daha sonra cancelled/rejected kanıtlarında bulunabilir. Bu bir yeni kriptografik lifecycle kanıtı değildir. İtiraz yanıtı ilk sıralanma kanıtını tercih etmeye devam eder.

## Kayıt geçişi

Yeni snapshot envelope `DPSNAP6` kullanır. Önceki `(Gw, market dynamics)` prefix'inin field sırası değiştirilmez. Yeni execution alanı prefix içinde serde-skipped'dir; ayrı `DPEXEC1` trailer kayıtları taşır. Yeni okuyucu v5 envelope'u açıkça kabul eder ve eski hesapları/bakiyeleri/defterleri/makbuzları korur. Eski yazılım v6 envelope'u reddeder. Yeni sürüm başlığı ayrıca MAC girişine bağlanır; başlığı v5 olarak değiştirip bu korumayı aşmak doğrulama hatası üretir. Eski v5 MAC düzeni yalnızca geriye uyumlu okumada kullanılır. Eski bakiyeler sıfırlanmaz.

Eski yazılımın geçmiş fill miktarları uydurma olabildiğinden geçmişten gerçek VWAP türetilemez. Böyle kayıtlar `available: false`, flat fill/average `null` taşır. Defterdeki gerçek kalan miktar yine okunur ve iptal edilebilir. Geçmişi bilinmeyen emrin son kalan miktarı sonradan gerçekleşirse kalan 0 olur; toplam geçmiş uydurulmaz.

Bir düşürme/rollback için eski çalıştırılabilir dosyayı yeni snapshot'a yönlendirmeyin. Yeni yazılıma geçmeden state/journal'ın tutarlı, gizli yedeğini alın. Gateway ve frontend birlikte güncellenmelidir. Bu çalışma deployment yapmaz.

## Bu paketin dışında

A01 otonom L1 yatırma okuyucusu; A06 CloseOnly tek taraflı pozisyon kapatma; A07 hesap kurtarma; A10 custody/oracle güven mimarisi; A11 bağımlılık, gerçek guest/prover ve canlı deployment doğrulamaları. E3 tasarımındaki tam tarihçe indeksleme/bounded challenge archive ve mock-client matching modeli de bu native gateway düzeltmesiyle tamamlanmış sayılmaz. Gerçek SP1 proof, canlı TEE ve fiziksel güç kesintisi ayrı doğrulama gerektirir.

## API uyumluluğu

Servis edilen OpenAPI iptal açıklaması ve 400/503 sonuçları yeni davranışla güncellendi. Yeni alanların ayrıntısı `2026-09-18-execution-api.md` ekinde bulunur; önceki API referansındaki pre-seal-only iptal açıklamasının yerine bu ek geçer. API referansının tüm diğer bölümleri bu pakette yeniden denetlenmiş değildir.
