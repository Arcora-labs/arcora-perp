# Arcora Perp: ayrı Chainlink aday guest CPU doğrulaması

Tarih: 10 Ekim 2026. Dal: `feat/chainlink-guest-replay-20261010`.
Taban main: `9483e33607f964138108094b04ca8b27dedcd637`.
**PRODUCTION RELEASE HOLD.** Bu kayıt yerel kapsamı gösterir; sonraki PR CI değildir.

## Merge sonucu

#41, exact head `7e1adb9c4d34934459f202172c081f1854a3c192` üzerinde görülen
17/17 başarılı kontrol ve CLEAN durumu sonrasında normal merge edildi.
Merge: `9483e33607f964138108094b04ca8b27dedcd637`; 20:02:20 Türkiye saati.
Merge tree, test edilmiş kaynak tree ile birebir eşittir. Admin bypass,
force-push veya ruleset değişikliği yapılmadı. Yeni dal güncel main'den açıldı.
Merge sonrası main push CI, PR kontrollerinden ayrı olarak takip edilir.

## Tamamlanan dar kapsam

Ayrı aday guest artık yalnız derlenmiş değildir: gerçek SP1 6.1.0 CPU executor'unda
19 sabit sentetik witness ile yürütüldü. Dört başarıda beklenen native 32 baytlık
commitment aynı çıktı; 15 negatifte gerçek guest exit 1 ve sıfır public çıktı görüldü.
Eksik/düşmüş test, executor hatası, timeout veya yanlış public value başarı sayılmaz.

Pozitifler: funding, USDC 0.80 USD depeg funding, iki observation funding ve
fiyat gerektirmeyen boş batch. Negatifler: kanıt/market/feed/zaman uyuşmazlıkları,
dört oracle-bearing op türünde raporla uyuşmayan fiyat, yanlış zincir/clock,
bozuk market-state, trailing bytes ve eski wire formatı.
Bu dört pozitif, önceki dört normal-wallet exact witness değildir. Pozisyonlu
fill/liquidation/withdrawal başarı döngüsü veya gerçek para burada kanıtlanmadı.

ELF SHA-256: `48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f`.
Boyut: 540704 bayt. Aday vkey:
`0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.
Ayrı pinned SP1 derleyicisiyle aynı Mac'te yeniden derleme byte-byte aynı ELF'i
verdi. Mevcut cache kullanıldı: bağımsız veya cold build değildir.
Yeni vkey setup ve guest execution yapıldı; yeni kriptografik proof üretilmedi.

## Yerel doğrulama

| Kontrol | Sonuç |
|---|---|
| Gerçek SP1 CPU guest corpus | 4 başarılı çıktı eşleşmesi + 15 beklenen çıktısız ret |
| Ayrı gerçek süreç girdi/çıktı guard'ları | 5/5 beklenen ret |
| Standalone Chainlink Rust | 16 PASS, 0 FAIL, 1 IGNORE |
| Açık fixture export testi | Ayrı komutla 1 PASS |
| Python evidence guard testleri | 12 PASS |
| Candidate core ve yeni host binary Clippy, -D warnings | PASS |
| Core no_std / core ve host format | PASS |
| Candidate lock / reviewed release / kaynak pinleri | PASS; 21 eski + 9 aday runtime aynı |
| Aday yeniden derleme | PASS; önceki aday ELF ile byte-byte aynı |

Sayılar birbirine eklenmez. Rust'taki tek ignored test açık export testidir ve
ayrı komutla çalıştırıldı. Python guard'larının kendi raporları yapısal test
double'larıdır; gerçek CPU sonucu `cpu-execution/` altındaki ayrı kayıttır.
Host build ve lint, kilitli proc-macro-error2 bağımlılığı için future-incompatibility
uyarısı verdi; bu mevcut derleme hatası değildi, bağımlılıklar değiştirilmedi.
Tam Rust workspace, frontend, sözleşmeler, tam Python/Anvil/restore/ACK-crash
paketleri bu turda yerelde yeniden çalıştırılmış sayılmaz; runtime'ları değişmedi.

## Kaynaklar ve tekrarlanabilirlik

`verification.json`, final kaynak/artifact hash'lerini ve gerçek komut/exit
kayıtlarını bağlar. `build-verification.json` aynı makine build kaydıdır.
`cpu-execution/manifest.json` ve public-values dosyaları gerçek runner çıktılarıdır;
`execution-results.txt` yalnız 20 seçilmiş çıktı satırıdır, tam ham log değildir.
`execution-verification.json` beş süreç guard'ını ve tamamlanan CPU komutunu kaydeder.
Yayımlanan komutlarda home/checkout/run yolları normalize edildi; ham dosya ve
log hash'leri saklandı. Yerel kayıtlar `target/chainlink-replay-20261010T170217Z/`
ve kayıtlı `/private/tmp/arcora-chainlink-cpu-20261010T171252Z/` altındadır.
Kılavuz: `docs/CHAINLINK_GUEST_REPLAY.md`.

CI'a aynı pinned candidate ELF ile gerçek CPU yürütmesi eklendi. Workflow
satırının varlığı uzaktaki koşunun başarıyla tamamlandığını göstermez; exact head
üzerinde PR CI sonucu ayrıca doğrulanmalıdır. Required check/timeout politikası
ve repository korumaları değiştirilmedi.

## Açık kalanlar

Mevcut reviewed v2 programı, aday runtime semantiği, gateway/prover-service,
sözleşmeler, risk eşikleri, witness/public-input biçimleri ve tüm dependency
lock'ları aynı kaldı. Aday key/ELF mevcut production pininin yerine geçirilmedi.
Bu sentetik raporlar gerçek DON imzası değildir. Gerçek proof, canlı stream
istemcisi ve feed/decimal/USDC pinleri, gateway-prover-L1 bağlantısı, rapor
kalıcılığı/kurtarma, deployment kimliği ve ekonomik kabul hâlâ açık.
Ücretli altyapı, gerçek key, kamu zincirine işlem, fon hareketi veya deployment yok.
`docs/ACTIVE_WORK.md` güncellenmiştir; production yayın kararı değişmedi.
