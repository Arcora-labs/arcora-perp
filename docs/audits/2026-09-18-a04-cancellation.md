# Dark-perp: A04 emir iptali düzeltmesi

**18 Eylül 2026**

## Kapsam ve kaynak

Birleştirilmiş PR #1 ve #2 sonrasındaki `main` (`48e03ac3db123cdf159c10f1e0c86262043a377e`) üzerine hazırlanmıştır. Bu çalışma A04'ü ve iptali yeniden erişilemez hale getiren canlı emir geçmişi temizliği hatasını kapsar. Tam ürün güvenliği veya mainnet hazırlığı sertifikası değildir.

- Düzeltme dalı: `fix/a04-cancellation-verified-2026-09-18`.
- Yayımlanan uygulama commit'i: `8c42bc2ebf6e043b4b552e05ac985653e281d217`.
- Tam doğrulama: [GitHub Actions 35316179109](https://github.com/Kubudak90/dark-perp/actions/runs/35316179109).
- Kanıt ZIP SHA-256: `ea24fb18ba01ef4c7d142e5cfc9b421db826e1a923f5bd67c296f12f0471093f`.
- Test edilmiş kaynak yaması SHA-256: `c20590cf927ed1735a6f441f8f9b53bf326ea2bcd0ac82969e8b92c3c0da7538`.

## Değişiklikler

İptal artık yalnızca `ACCEPTED` veya `sealed=false` koşuluna bağlı değildir. Kullanıcıya ait emrin defterdeki gerçek kalan miktarı esas alınır. Kısmen gerçekleşmiş ve gerçekleşen kısmı `SETTLED` olmuş emirlerin kalan kısmı iptal edilebilir. Önceki gerçekleşmeler ve pozisyon muhasebesi geri alınmaz.

İptal ve eşleştirme tick'i aynı gateway durum kilidi altında tamamlanır. Bu nedenle iptal ve fill birbirlerinin ortasına giremez; iki sıralama ayrı regresyon testlerinde yeniden oynatılır. Mevcut `Cancelled` gerekçesi açık pencerenin manifest'ine yazılır. Eski tick rollback kopyalarından da emir kaldırılır; snapshot restore ve pencere rollback senaryoları test edilir.

Üretimde kalıcı kayıt yapılandırması yoksa iptal mutasyondan önce reddedilir. Kalıcı kayıt varsa HTTP başarı yanıtı snapshot onayını bekler. Dosya yazımı başarısızlığı veya zaman aşımı `503` ve `durability: "unknown"` verir. Bellekte emrin görünmemesi tek başına kalıcı iptal kanıtı değildir; bu durumda yeni karşılık emir göndermeden önce dayanıklı durum teyidi gerekir.

Hesaba özel emir görünümü `cancellable`, başarılı iptal yanıtı `cancelledSize` taşır. Arayüz kalan parça için iptal düğmesini gösterebilir ve belirsiz kayıt sonucunda başarı bildirimi üretmez. Kamuya açık gizli emir defteri yayınlanmaz.

**Ek düzeltme:** 500 kayıt sınırındaki geçmiş temizliği `SETTLED` etiketini tamamlanmış emir sanıyordu. Bu, kısmen gerçekleşmiş canlı maker'ın tek API satırını silebiliyordu. Temizlik artık defterde canlı kalan emri tutar; yalnızca defterde bulunmayan, sealed ve SETTLED kayıtları eler. Canlı emir sayısı sınırı aşarsa erişilebilirlik korunur; bu sınır canlı emirleri düşürmek için kullanılmaz. Önceden eski sürüm tarafından silinmiş geçmiş satırları otomatik yeniden oluşturulmaz.

## Yeni doğrulama

| Kontrol | Sonuç |
|---|---|
| Rust workspace | 630 geçti, 0 başarısız |
| A04 odaklı gateway testleri | 11 geçti; workspace toplamına dahil |
| A04 odaklı sequencer testleri | 10 geçti; workspace toplamına dahil |
| Ayrı `perp-core + serde` | 156 geçti; workspace ile örtüşür |
| Frontend | 270 geçti, 1 canlı gateway testi atlandı |
| Clippy `-D warnings`, Rust format | Başarılı |
| TypeScript + frontend production build | Başarılı |
| Core `no_std + serde`, matcher `no_std` | Başarılı |
| İki negatif kontrol | Eski sealed ret ve eski geçmiş temizliği ayrı ayrı geri kondu; her biri tam 1 çalıştırılmış testi beklenen şekilde düşürdü |
| Sağlam kodun geri yüklenmesi | Baytlar aynen geri kondu; gateway regresyonları tekrar geçti |

Önceki birleşmiş sürüme göre **21 yeni Rust ve 9 yeni frontend test durumu** bulunur. Test profili optimize edilmiştir; debug assertion ve taşma kontrolleri açıktır. Fuzz örnekleri azaltılmamıştır. Alt kümeler, tekrar çalıştırmalar ve serde sonuçları bağımsız testlermiş gibi toplanmamalıdır.

İlk run `35315094200`, uygulama testleri ve derlemeleri geçmiş olsa da negatif kontrol betiğinin biçimlendirmeye bağlı metin aramasında durmuştur; tam başarılı çalışma olarak sayılmamıştır. Son tur hem bu betik sorununu hem de ek geçmiş temizliği düzeltmesini kapsar.

## Güven ve uyumluluk sınırı

`perp-core`, SP1 guest, sözleşmeler, `PublicInputs::commitment`, çapraz katman vektörleri ve snapshot/WAL şema kaynağı değiştirilmedi. Gateway ve frontend birlikte güncellenmelidir. Native `derive_roots` yeniden oynatması gerçek SP1 proof üretimi değildir. Manifest'e kayıt eklenmesi, iptal yetkisinin veya eşleştirme adaletinin ZK ile bağımsız kanıtlandığı anlamına gelmez.

Canlı TEE, gerçek ödeme, gerçek SP1 proof, fiziksel güç kesintisi ve yayındaki binary/vkey eşleşmesi denenmedi. Bu doğrulama işi Foundry çalıştırmadı; sözleşmeler değiştirilmedi. Yeni PR'nin normal CI sonucu bu tamamlanmış özel doğrulamadan ayrı değerlendirilmelidir.

**Merge, deployment veya canlı zincir işlemi yapılmadı.**

## Açık işler

A01 otomatik sıralı yatırma işleme; A05 gerçek gerçekleşme miktarı, kalan miktar, ortalama fiyat ve kalıcı emir geçmişi; A06 CloseOnly açık pozisyondan çıkış; A07 hesap kurtarma; A10 güven sınırları ve A11 bağımlılık/gerçek prover/deployment doğrulaması açık kalır.

A05 özellikle bu paketle kapanmaz: iptal edilen satır listeden kaldırılmaya devam eder ve mevcut kısmi gerçekleşme raporlama hatası düzeltilmiş değildir. A04 iptali bu hatalı `filledSize` alanına bağımlı değildir.
