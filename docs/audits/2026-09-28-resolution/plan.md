# Arcora — kalan işlerin somut kapanışı

Başlangıç: `98e0c51f27b42daa4454d22f183aaa96d165b1e5`, ayrı çalışma kopyası. Desktop'taki mevcut çalışma korunur. Başlangıçtaki 15 üst görev ve kabul koşulları değiştirilmez; tamamlanan alt işler ve sonradan bulunan ek işler ayrı kaydedilir.

Bu turdaki sabit kapsam:

1. **S2-03 / kayıtlı başarısız işlem çözümü:** Kullanıcının ayrı eylemi, yalnız özgün kayıtlı hash için kesinleşmiş revert'i doğrular; journal kimliği, hesap/cüzdan/deployment ve sekme kilidi korunur. Başarılı ön adımlar tekrar gönderilmez, eski hash/kanıt kalıcı saklanır. Çözüm eylemi imza veya transfer göndermez; yeni işlem ayrıca Resume ile başlar. Pending, unknown, başarılı, kesinleşmemiş veya çelişkili RPC yanıtı ilerlemeyi açmaz. Doğrulama: RPC/journal birim testleri, UI ve Chromium/WebKit akışı.
2. **S4-03/S4-05 / birleşik native restart ve prover taşıması:** Gerçek loopback HTTP istemcisiyle session expiry/tek yenileme, yanlış batch/previous-root reddi, snapshot+journal restart ve landed-root sonrası idempotent commit. Doğrulama: native gateway testleri; gerçek proof/zincir kabulü sayılmaz.
3. **Teslim raporu:** Başlangıçtan tamamlanan alt işler, açık kalan özgün koşullar ve yeni bulunan işler ayrı listelenir. Başarılı test sayısı üst görev kapanışı yerine kullanılmaz.

Hash'siz unknown işlem keşfi, gerçek extension cüzdanı, gerçek guest/proof ve zincir fon döngüsü bu iki alt işin kapanış koşuluna sonradan eklenmez; üst görevlerde açık kalır. Mevcut A06 yürütme engelini aşacak işlem yapılmaz. Production deploy veya canlı fon işlemi yok.

Durum: İki uygulama/doğrulama alt işi tamamlandı. Özgün ZIP ölçütlerinin ayrı incelemesi S4-03/S4-05/S4-07 kapanışını doğruladı. S4-05 bağımlılığı kalkınca özgün S5-01 de ilerletildi: kaynak adayı `79396952d3422b6cda5c83d05cf60bfa1cded410`, 21 guest/core dosya eşliği, ELF/vkey, güncel lockfile ve araç kimlikleri [release manifestine](release-manifest.json) bağlandı. Dört özgün başlık kapandı, 11 kaldı. Yeni koşul eklenmedi; bağımsız container tekrar üretimi başlangıçtaki kanıt sınırı olarak korundu.
