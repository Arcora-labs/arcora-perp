# Plaintext allocation öncesi bounded preflight

14 Ekim 2026, PR63 sonrası base `c929c719e366e62fe4a95f0da9d4e327755116ec`.
Yalnız gateway `prover_client.rs` uygulama kaynağı değişti. 379 kaynak dosyasının
haritası `b43fe139894f3b8f36692c3b43ddc8b7ba0647ab8003828413b18fe011e33c38`;
client SHA `a66f16cd2aeaf0c663f9a7b4bced9af5c0b5b268865bc7f212085c39fc4bd3f7`.

Önceki yol JSON sınırını ilk `postcard::to_allocvec` sonrasında kontrol ediyordu.
Şimdi aynı `15 + 2 * (P + varint(P) + 96)` expansion fonksiyonunun checked,
monotonic inverse'ü izin verilen plaintext boyutunu hesaplar. Stack counter
Flavor her push/extend için checked_add ve inclusive sınır uygular. Legacy
başlangıcı0, DPCLK2 magic başlangıcı8; prefix sığmıyorsa tuple traversed edilmez.
Bütçe aşımında plaintext output encoder çağrılmaz. Kabul edilen yol eski encoder'ı
kullanır; postplain expansion, actual sealed envelope ve final HTTP entity guard'ları
korunur. Nonzero/tiny byte refusal fixed Http (401 değil); zero Configuration,
bütçe dışı postcard error Decode kalır. Count/actual length uyuşmazlığı
allocation sonrasında, nonce/provider/seal öncesinde Decode ile ret edilir.

## Gerçek kontroller ve bağımsız review

- Local client46 PASS /0 FAIL; eski35 test gövdesi ve bearer module4 testi aynı,
  yedi test eklendi. Real-curl HTTP20 PASS; Clippy ve format PASS.
- İki gerçek küçük WindowWitness: deposit+withdraw ve no-deposit cumulative fixture.
  Legacy/clock × software/attested-secret toplam8 deterministic seal çıktısı
  bağımsız eski tuple/nonce/provider/postcard/hex referansıyla byte-exact aynı.
- Aynı production gate'e verilen panic encoder, bu gerçek tuple'larda zero/tiny/
  exact−1 bütçeler reddedilince hiç çağrılmadı; exact bütçe encoder'ı bir kez çağırdı.
  Bu callback cut, bütün canlı backend/key-release/child/peer kontrolü değildir.
- Counter push/extend/usize overflow, JSON209/210/211, varint127/128 ve16383/16384,
  clock prefix-only refusal ve early traversal retleri doğrulandı. Production
  maxP268435348 yalnız integer hesabıdır; 512 MiB payload oluşturulmadı.
- Independent design/source review ve 379 dosyanın frozen readback'i PASS.

Yeni head için GitHub CI kabulü bu pre-publication belgede henüz gerçekleşmedi.
Beklenen full gateway761 PASS /0 FAIL /24 IGNORE; actual yayın/main sonucu
merge sonrasında ayrı final kanıtlarla teslim edilecek.

## CPU ve allocation sınırı

Kabul edilen yol iki serializer geçişi ve bounded inverse hesabı yapar. Ayrı,
tek-thread debug CPU ölçümü iki gerçek küçük witness için legacy/clock olmak
üzere4case ×5 alternating paired sample ×500 encoding çağrısı içerir. Witness
plaintext2516–2741 byte, median count+encode /old encode oranları2.07–2.11.
Raw20 sample `local-cpu/` ve aggregate `cpu-observation-summary.json` içindedir.
Bu diagnostic sample için timing threshold yok; production throughput, peak RSS,
giant allocation veya proving kapasitesi kabulü değildir. Input construction,
önceden hazırlanmış state/ops/manifest allocation'ı ve sealing/proving/transport
ölçüme dahil değildir.

Generic seam private ve production'da bilinen borrowed immutable derived tuple'lara
uygulanır. Arbitrary Serialize allocation, CPU/depth veya interior mutation için
genel limit sağlamaz. İkinci encoder bounded değildir: length drift yalnız sonradan
yakalanır; same-length content drift'i counting yakalamaz. Bu sınırlar testte ve
review'de açıkça kaydedilmiştir. Code/dependency/core/guest değişiklikleri bu
bilinen witness contract'ının yeniden değerlendirilmesini gerektirir.

Reviewed21/candidate9/auxiliary2 source pin, sekiz manifest/lock ve dokuz
program/proof artifact unchanged. Önceki rapor/kanıt dosyaları ve üç dirty checkout
korunur. Yeni ELF/setup/proof/CC/key-release/deployment/financial transaction yok.
Candidate submission kapalı; custodial alpha model aynı;
**PRODUCTION RELEASE HOLD** sürüyor.

`ledger.json` her seçilmiş public kanıtın exact copied-from path, size ve SHA-256
haritasıdır. README/ledger self-map dışında kalır. Binaries, caches, temporary
header files, private config ve yeni network keşfi pakete dahil değildir.

Inventory v1 prose fixture label `Deposit + Fill` is historical. Inventory v2
corrects it to the actual controlled unit-test `Deposit + signed withdrawal`;
source and execution evidence are unchanged.
