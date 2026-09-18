# Dark-perp / Arcora Perp — audit devam raporu

**Tarih:** 17 Eylül 2026  
**İncelenen kaynak:** `Kubudak90/dark-perp`, `main`, `5eeb37fde378336fc9daae7c6798637317ffb319`  
**Kapsam:** Yarım kalan Codex audit kaydının kaynak üzerinden tamamlanması; önceliklendirilmiş bulgular, izole yeniden üretim testleri ve düzeltme kabul ölçütleri.  
**Karar:** Bu kaynak sürümü için gerçek para/mainnet açılışı önerilmez. Bu bir bağımsız dış denetim veya tüm sistemin güvenli olduğuna dair sertifika değildir.

## 1. Kaynak, kanıt ve değişiklik sınırı

GitHub `main` başı ile devralınan oturumun incelediği commit aynı. İlgili gateway kodu, snapshot yazıcısı, sequencer eşleştirme/finality akışı ve zincir üstü itiraz arayüzü bu oturumda GitHub üzerinden yeniden okundu. Eski oturumdaki her testin yeniden çalıştığı varsayılmadı.

Bu dal yalnızca rapor, test kaynağı ve izole çalıştırıcı ekler. Uygulama kaynakları, çalışan servisler, sözleşmeler, genesis, SP1 programı, public-input commitment, cross-layer vektörleri ve postcard snapshot şeması değiştirilmez. Hiçbir canlı zincir işlemi gönderilmez.

### Kanıt sınıfları

- **S — Statik:** Kaynakta erişilebilir akış incelendi. Çalışan ortamda exploit veya gerçek para etkisi gösterildiği anlamına gelmez.
- **H — Devralınmış:** Ekli eski oturumdaki komut çıktısı. Yeni doğrulama değildir.
- **D — Yeni dinamik:** Yalnızca yeni çalıştırıcının gerçek logunda ilgili testin başarıyla tamamlandığı durumda kullanılır.

**Yeni dinamik doğrulama tamamlandı:** GitHub Actions run `35262638192`, job `105341894922`, 17 Eylül 2026 19:05 UTC. Sekiz karakterizasyon testi derlendi ve çalıştı: **8 passed, 0 failed, 0 ignored**; `status.json` içinde `completed=true`, `cargo_exit=0`, `all_reproduced=true`. Testler `5eeb37f` kaynak commit'inin geçici kopyasında çalıştı; test kodu commit'i `2fcdb19d67b9c09cb338a1b47deaaef37dd77694`.

[Çalışma kaydı](https://github.com/Kubudak90/dark-perp/actions/runs/35262638192) · [Ham kanıt ZIP'i](https://github.com/Kubudak90/dark-perp/actions/runs/35262638192/artifacts/10515301495)

İndirilen kanıt ZIP'inin SHA-256 değeri GitHub yükleme loguyla karşılaştırıldı: `48fb92daa4d71b82ea715a92b56b8488878fd9dc469444385da67fc34398b432`. İçindeki `gateway-repros.log` ve `status.json` okundu. Test kaynağının SHA-256 değeri: `9719c176e85eeaa3268f58c062b7cfe9fba5328ecf3d8a5d7b107ff37645baac`.

| Yeni test | Doğrulanan davranış |
|---|---|
| A01 — yatırma sırası | B, A'nın eksik prefix girdisi tamamlanmadan kredi alamıyor; A tamamlanınca aynı B isteği geçiyor |
| A02 — önceki snapshot'a dönüş | Son snapshot'tan sonra oluşturulan izin kaydı restore sonrası yok; kredi reddediliyor |
| A03 — receipt | Kabul yanıtı ve emir listesi imza baytı taşımıyor |
| A04 — maker iptali | Gerçekleşmemiş sealed maker iptal reddinden sonra defterde kalıyor |
| A05 — kısmi fill | Gerçek miktar `2500000`, API miktarı `10000000` (ölçek 1e8: 0.025 yerine 0.1) |
| A08 — depth | Üretim genesis'inde gerçek defter boş, sunulan bids/asks dolu |
| A08 — zaman damgası | Eski fiyat gözlemi, endpoint çağrısının yeni zamanı ile sunuluyor |
| A09 — timeout | Dolu kanal, snapshot ACK timeout'u başlamadan beklemeyi uzatıyor |

Bunlar izole Rust testleridir: fiziksel güç kesintisi, gerçek L1 ödeme, canlı TEE veya gerçek SP1 proof testi değildir. Python sözdizimi ayrıca yerel ortamda kontrol edildi; Rust testleri yerel makinede değil GitHub runner'ında çalıştırıldı.

### Mevcut normal CI'ın yeni sonucu

Ayrı run `35262638184` (`ci`, aynı test kodu commit'i) incelendi. Frontend install/test/build ve Foundry build/test işleri **başarılı**. Rust `fmt` başarılı, `clippy` **başarısız**: `crates/gateway/src/main.rs:4300` satırındaki `self.pending_settle.drain(..).collect::<Vec<_>>()`, `clippy::drain_collect` nedeniyle `-D warnings` altında exit 101 üretiyor. Logun önerisi `std::mem::take(&mut self.pending_settle)`. Bu satır bu dalda değiştirilmedi; audit testleri uygulama workspace'ine eklenmediği için hata mevcut gateway kodundan geliyor.

Clippy başarısız olduğu için bu run'ın workspace test, serde witness ve no_std adımları **atlanmış**; bunları yeni geçmiş testler olarak saymıyoruz. Excluded prover typecheck işi ilk kontrolde tamamlanmamıştı; başarı kanıtı olarak kullanılmıyor. [Normal CI kaydı](https://github.com/Kubudak90/dark-perp/actions/runs/35262638184). Dolayısıyla genel CI için “tamamı yeşil” sonucu yoktur.

**Önemli:** Bu testler *karakterizasyon testidir*. Yeşil sonuç, bilinen hatalı davranışın eski commit üzerinde yeniden üretildiği anlamına gelir; açığın kapandığı veya ürünün güvenli olduğu anlamına GELMEZ. Düzeltme dalında tersine çevrilmiş güvenlik özelliği testleri gerekir.

## 2. Öncelikli bulgular

| Kimlik | Önem | Durum / kanıt | Özet |
|---|---|---|---|
| A01 | Yüksek — yatırma erişilebilirliği | Açık / S + D | Yatırma kuyruğunun ilerlemesi ilk kullanıcının onay çağrısına bağımlı |
| A02 | Yüksek — fon kilitlenmesi | Açık / S + D | İmzalı yatırma izni, gizli kayıt kalıcılaştırılmadan veriliyor |
| A03 | Yüksek — hesap verebilirlik | Açık / S + D | Kullanıcıya verilen makbuzda on-chain challenge için gereken imza yok |
| A04 | Yüksek — işlem riski | Açık / S + D | Batch'e giren fakat henüz dolmayan maker emri iptal edilemiyor |
| A05 | Yüksek — işlem verisi doğruluğu | Açık / S + D | Kısmi gerçekleşme, API'de tam emir büyüklüğü olarak raporlanıyor |
| A06 | Yüksek — çıkış erişilebilirliği | Açık tasarım boşluğu / S | CloseOnly sırasında karşı emirsiz açık pozisyon için genel çıkış yok |
| A07 | Yüksek — hesap kurtarma | Belgelenmiş ürün kısıtı / S | Tarayıcı API anahtarı kaybında gerçek hesap kurtarma akışı yok |
| A08 | Orta — piyasa verisi | Açık / S + D (iki test) | Gerçek olmayan derinlik ve eski fiyatın yeni zaman damgasıyla sunulması |
| A09 | Orta; A02 ile birleşince yüksek | Açık / S; timeout için D | Snapshot kuyruğu timeout dışı bekleyebiliyor; iki yazıcı ve directory fsync açığı |
| A10 | Mimari/mainnet engeli | Güven varsayımı / S | ZK iddiası gateway custody ve gateway-imzalı oracle sınırlarını aşmamalı |
| A11 | Doğrulama borcu | Yeni CI hatası + H; bağımlılık taraması yenilenmedi | Clippy engeli, bağımlılık taraması, gerçek prover ve deployment kanıtı tamamlanmalı |

### A01 — Sıralı yatırma kuyruğu kullanıcı işbirliğine bağlı

**Kaynak:** `crates/gateway/src/main.rs::validated_deposit`, `account_confirm_deposit`, `post_v1_deposit_onchain` (özellikle 2180–2290 ve 5927–5983); `crates/perp-core/src/engine.rs` içindeki sıralı deposit tüketimi.

Gateway yalnızca `deposit_id == consumed_deposit_count` olan girdiyi krediye çevirir. Bu güvenlik kontrolü doğrudur: L1 deposit zincirinde atlama, yeniden sıralama ve tekrar tüketim engellenmelidir. Ancak mevcut kullanıcı akışında L1'e ödeme yapıldıktan sonra ilgili hesabın kimlik doğrulamalı `/deposit/onchain` çağrısını yapması gerekir. A kullanıcısının girdisi N, B'ninki N+1 olduğunda, A çağrıyı yapmazsa B sıradaki geçerli ödemesini kredileyemez.

Bu, bütün settlement'ın anında durduğunu kanıtlamaz: daha eski, geçerli deposit prefix'i üzerinde settlement devam edebilir. Doğrudan gösterilen sorun yeni yatırmaların kredi kuyruğudur. Kuyruğun başındaki eksik kayıt giderilemiyorsa etkisi kalıcılaşır.

**Düzeltme hedefi:** Son yeterince onaylı L1 cursor'undan ilerleyen otonom deposit ingester; kalıcı `ownerCommit -> hesap/izin kaydı` çözümlemesi; kimliği doğrulanmış kullanıcı callback'inin yalnızca hızlandırıcı/idempotent yardımcı olması. API anahtarını zincire koyma, depozit atlama veya L1 prefix kontrolünü kaldırma kabul edilemez.

**Kabul ölçütü:** A ödemeyi yapıp tarayıcısını kapatsın; B kendi API anahtarıyla devam edebilsin. Otomatik ingester N ve N+1'i tam bir kez, doğru hesaplara kredilesin. Restart, yinelenen log, pagination ve reorg senaryoları ayrıca doğrulansın.

### A02 — İzin veriliyor ama izin kaydı henüz dayanıklı değil

**Kaynak:** `main.rs::account_authorize_deposit` (2104 civarı), `post_v1_deposit_authorize` (5989–6030), `snapshot_now`; `contracts/src/CollateralVault.sol` içindeki SEC-028 durability notları.

`ownerCommit` ön-görülemez bir `deposit_blind` ile üretilip hesap belleğine ekleniyor. HTTP handler, bu kaydın başarılı bir snapshot ile kalıcılaştığını beklemeden gateway imzasını kullanıcıya veriyor. Önceki snapshot'a dönülen bir çökmede blind kayboluyor; kullanıcı elindeki geçerli imzayla L1'e ödeme yapmış olsa bile gateway girdiyi çözemiyor. A01 ile birleştiğinde tek kayıp izin sonraki kullanıcıları da etkiliyor.

Vault'taki `usedDepositAuthorization` bu sorunu çözmez: o, aynı imzanın tekrar kullanılmasını engeller. Tek ve meşru bir iznin kaydının kaybolması ayrı hata sınıfıdır. Mevcut tekrar-kullanım düzeltmesi geri alınmamalıdır.

**Düzeltme hedefi:** İzin kaydı kaydedilsin, doğrulanmış dayanıklılık bariyeri tamamlanmadan imza dışarı verilmesin. Snapshot/disk hatasında imza içermeyen 503 dönülsün. `App.gw` kilidi snapshot beklerken tutulmasın. A09'daki yazıcı sıralaması ve timeout sorunu aynı iş paketinde ele alınmalı. Sonradan gelen eski snapshot'ın yeni kaydı ezememesi gerekir.

**Kabul ölçütü:** Başarılı HTTP yanıtından hemen sonra süreç sonlandırılıp geri açılsın; izin kredilenebilsin. Disk hatası, dolu request kuyruğu, yanıt timeout'u ve SIGTERM yarışı altında başarılı izin sızmasın. İzin verildikten sonra adres rebind edilmesi de ayrıca incelenmeli: mevcut kredi doğrulaması güncel bağlı adresi okur; salt snapshot bariyeri bu ayrı yaşam döngüsünü çözmez.

### A03 — Makbuzun imzası istemciye taşınmıyor

**Kaynak:** `main.rs::WReceipt` (912–918), `account_place_order`, `v1_orders_json`; `contracts/src/DarkPerpSettlement.sol::challengeInclusion` (457–486).

Dönen makbuz beş alan içeriyor: `orderHash`, `seqNo`, `recvTimeMs`, `batchIdHint`, `windowId`. İmza baytları yok. Sözleşmenin challenge girişi ise `v/r/s` ile enclave signer doğrulaması istiyor. Makbuzun JSON içinde bulunması, imzalı ve bağımsız kullanılabilir bir itiraz kanıtının teslim edildiğini göstermiyor. Aynı eksik şekil `/v1/orders` listesinden de dönüyor.

**Düzeltme hedefi:** Kabul anındaki özgün enclave imzasını ve imzalanmış tuple'ı byte-exact biçimde kullanıcıya teslim et ve dışa aktarılabilir sakla. Yeniden oluşturulmuş veya başka batch/window'a ait imza verme. `windowId` ile sözleşmenin `batchIdHint` semantiğini karıştırma.

**Kabul ölçütü:** API'den alınan gerçek makbuz, yalnızca istemcinin elindeki verilerle ve gateway tekrar erişilebilir olmadan Foundry üzerinde `challengeInclusion` doğrulamasını geçsin. Yanlış tuple/signer ve bozulmuş imza reddedilsin. Snapshot'a alan eklenecekse postcard'ın konumsal yapısı nedeniyle uyumluluk/migrasyon ayrıca tasarlansın.

### A04 — Sealed olması, iptal edilemez olmasıyla karıştırılıyor

**Kaynak:** `main.rs::account_cancel` (3188–3203); mevcut SEC-025-E2 tasarımı.

`sealed == true` veya finality `ACCEPTED` değilse iptal reddediliyor. Oysa bir GTC/PostOnly emir batch'e girdikten sonra tamamen veya kısmen emir defterinde bekleyebilir. Henüz gerçekleşmemiş kısmın iptal edilememesi, kullanıcı/maker'ın fiyatını ve kalan riskini yönetmesini engeller. Bu, E1'de düzeltilmiş olan yanlış hesaptaki `o1` emrini iptal etme sorunundan farklıdır.

**Düzeltme hedefi:** Yalnızca çağıranın emrinin kalan kısmını gerçek matcher'dan kaldır; gerçekleşmiş işlemi geri alma. Cancellation'ın receipt, manifest, inclusion/rejection challenge, rollback ve restart etkilerini birlikte ele al.

**Kabul ölçütü:** Unsealed, resting, partially-filled ve fully-filled emirlerde doğru davranış; aynı `orderId`'ye sahip başka hesap etkilenmesin; iptal edilmiş kalan miktar restart/rollback sonrası hayalet emir olarak geri gelmesin.

### A05 — Gerçekleşen miktar gerçek fill kayıtlarından gelmiyor

**Kaynak:** `main.rs::tick` (4338–4360); `v1_orders_json`; mevcut SEC-025-E3 tasarımı.

Finality `MATCHED` veya `SETTLED` durumuna geçtiğinde `o.filled = o.order.size` ve `o.avg_fill = o.order.limit_price` atanıyor. Dolayısıyla yalnızca dörtte biri gerçekleşmiş maker da tamamen dolmuş görünebilir. Market emrinde `limit_price == 0` olduğundan fiyat raporu da gerçek execution fiyatı olmayabilir. Finality değişimleri üzerinden fill olayı üretmek, aynı işlemin ikinci kez duyurulması riskini ayrıca doğurur; bu ikincil senaryo bu raporda dinamik olarak kanıtlanmış sayılmaz.

**Düzeltme hedefi:** Uygulanmış fill kayıtlarından kümülatif gerçekleşen miktar ve hacim ağırlıklı fiyat üret. `executionStatus` ile `finality` ayrı modeller olsun. Gerçekleşmeyen/rejected/cancelled kalan miktarı açıkça göster.

**Kabul ölçütü:** 0.1 birim maker'ın 0.025 birimi eşleştiğinde API 0.025 gerçekleşme ve 0.075 kalan göstermeli; pozisyon, REST ve kişisel WS aynı toplamı vermeli. Aynı order'ın sonraki fill'i, finality ilerlemesi ve rollback çift sayılmamalı.

### A06 — CloseOnly bütün pozisyonlar için tek taraflı çıkış sağlamıyor

**Kaynak:** `docs/superpowers/specs/2026-07-26-sec026-sec027-open-findings.md` içindeki SEC-027; `crates/perp-core/src/engine.rs::BatchOp`, `op_unbind`; `DarkPerpSettlement.sol::finalSettle`.

Mevcut tasarımda CloseOnly, iki tarafın da yeni risk açmasını engeller. Likidasyon/ADL sonrasında karşı tarafı kalmayan açık pozisyon oluşabilir. Kullanıcıyı kapatacak yeni karşı pozisyon açılamaz; Unbind açık pozisyonun marjını boşaltamaz. Governance `finalSettle` yalnızca zaten geçerli bir transition'ı zincire taşır, eksik force-close transition'ını yaratmaz.

**Sınır:** Bu, geçerli withdrawal leaf'i önceden yayınlanmış bir claim'in kullanılamadığı iddiası değildir. Hazır claim ile açık pozisyon teminatını ayırmak gerekir.

**Düzeltme hedefi:** SEC-027/027a kapsamındaki deterministik wind-down/settlement-price mekanizması; fiyat zaman bağlama, zarar dağılımı, oracle yokluğu, sıralama ve toplam solvency birlikte tasarlanmalı. Fonları açık pozisyondan çekilebilir hale getiren tüm yol uçtan uca test edilmeli. Bu alan konumsal witness/guest/VKey değişikliği gerektirebilir; sessizce mevcut deployment'a uygulanmamalı.

### A07 — Tarayıcı anahtarı kaybı için live hesap kurtarma yok

**Kaynak:** `frontend/src/components/RecoveryPanel.tsx` (canlı gateway uyarısı), `frontend/src/api/realClient.ts` içindeki `darkperp.v1Account`; authenticated withdrawal/proof uçları.

Live hesap tarayıcıdaki `/v1` API anahtarına bağlı. Seed recovery demo yüzeyiyle sınırlı. EOA'ya sahip olmak mevcut API erişimini kendiliğinden geri getirmiyor. Önceden istenmiş bir withdrawal'ın zincir üstü claim'i ayrı bir durumdur; gerekli Merkle proof'u önceden kaydetmemiş kullanıcı, anahtar kaybıyla proof endpoint'ine erişimi de kaybedebilir.

**Düzeltme hedefi:** EOA veya önceden tanımlı recovery anahtarıyla nonce'lu, deployment-domain-bound hesap erişimi yenileme; eski API anahtarlarının iptali. Bir imzayla yalnızca adres sahipliği ispatlandı diye başka kullanıcı hesabını devralma yolu açılmamalı. Claim paketinin istemcide güvenli dışa aktarımı ayrı bir kazanımdır, genel hesap kurtarmanın yerine geçmez.

### A08 — Public depth ve fiyat tazeliği yanlış anlam taşıyor

**Kaynak:** `main.rs::book_around` (4424 civarı), `v1_orderbook_json`, `v1_public_json`, `v1_oracle_json` (3325–3336); mevcut SEC-025-E4 tasarımı.

Depth, matcher'ın gerçek emirlerinden değil orta fiyat çevresinde sabit sentetik seviyelerden üretiliyor. Üretim genesis'inde gerçek defter boşken bile dolu bids/asks sunulabilir. Public oracle endpoint'i de fiyatın kaynak zamanını taşımak yerine `publishTimeMs = now_ms()` üretir.

**Önemli ayrım:** Public timestamp hatası, engine'in kendi oracle staleness kontrolünün bypass edildiğini tek başına kanıtlamaz; engine tick akışı gerçek feed zamanını ayrı kullanıyor. Bulguyu API/UX doğruluğu sınırında tutuyoruz.

**Düzeltme hedefi:** Production'da gerçek/sınırları açıkça belirtilmiş agregat depth veya açıkça unavailable durum; demo verisi production verisi olarak sunulmasın. Fiyat için kaynak timestamp'i ve stale/unavailable bayrağı taşınsın. Dark-order gizlilik hedefiyle yayınlanacak depth'in kapsamı açık karara bağlansın.

### A09 — Snapshot ACK sözleşmesi tam değil

**Kaynak:** `main.rs::snapshot_now` (4945 civarı); periodic/shutdown yazıcıları (7800–7895); `snapshot.rs::write_atomic` (158–178).

Timeout yalnızca ACK alıcısını sarıyor; öncesindeki `tx.send(...).await` kanal doluysa timeout başlamadan bekleyebilir. Ayrıca periyodik ve shutdown görevleri aynı dosya/.tmp yolunu yazabiliyor. Salt dosya seviyesinde atomik rename, daha eski yakalanmış snapshot'ın daha yeni durumu ezmesini önlemez. Son olarak dosyanın `sync_all` çağrısı var, rename sonrası üst dizinin senkronizasyonu yok.

**Düzeltme hedefi:** Kuyruğa gönderme ve yanıt beklemeyi tek son-tarihle sınırla. Shutdown dahil tek yazıcı veya snapshot yakalama + yazmayı kapsayan ortak sıralama kullan. Rename sonrası dizin dayanıklılığını desteklenen platformda sağla, hatayı ACK'e taşı. Tek başına rastgele temp dosya adı stale-write problemini çözmez.

**Kabul ölçütü:** Dolu queue, durmuş writer, disk hatası, ACK kaybı, timeout ve eşzamanlı shutdown testleri. Power-loss dayanıklılığı bu oturumda fiziksel cihaz üstünde sınanmadı.

### A10 — ZK güvenlik iddiasının doğru sınırı

**Kaynak:** `docs/superpowers/specs/2026-07-26-sec02x-threat-model.md`; `BatchOp::Fill`; gateway oracle signer ve account wallet custody; README'deki kapsamlı güvenlik iddiaları.

ZK, guest programının doğruladığı transition'ı kanıtlar; programın kontrol etmediği kullanıcı niyetini veya dış dünyanın fiyat doğruluğunu kendiliğinden kanıtlamaz. Gateway hem custody spend key'lerini hem de oracle publisher yetkisini elinde tutuyorsa gateway kompromisi, yalnızca gizlilik kaybı varsayımıyla sunulmamalı. Bu bir Groth16 kriptografisi kırma gösterimi değildir ve yalnızca sealed witness alan prover'a aynı yetkiler atfedilmemelidir.

**Gerekli karar:** Alpha'yı trusted-gateway/custodial sınırıyla açıkça tanımla; daha güçlü güvence için kullanıcı yetkisinin proof'a bağlanması, oracle trust separation ve anahtar-kurtarma modeli ayrı tasarım ve dış audit konusu olsun. README, litepaper ve UI aynı sınırı anlatmalı.

### A11 — Bağımlılıklar, prover ve canlı deployment için kanıt boşlukları

Devralınan oturumda `cargo audit` ve `pnpm audit` exit 1; normal testlerin yeşil olması bunu ortadan kaldırmıyor. O çıktılardaki advisory başlıklarını bu oturumda yeniden çekilmiş güncel güvenlik duyuruları olarak sunmuyoruz. Yeni taramada advisories, lockfile, dependency path, reachable kullanım ve patched sürüm birlikte kaydedilmeli. Guest bağımlılığı değişirse yeniden ELF/VKey üretimi ve native/guest parity kapısı gerekir; kör toplu upgrade yapılmamalı.

Devralınan çıktıda 595 Rust, 89 Solidity, 258 frontend testi ve 1 atlanan live e2e var. Bunlar **H sınıfı** kanıttır. Önceki snapshot'ta `fmt`, `clippy` ve frontend build de başarılı görünür. Yeni normal CI sonucu bölüm 1’de run kimliğiyle ayrıldı: frontend ve Foundry başarılı, Rust Clippy başarısız; workspace test adımları atlandı. Eski 595 Rust testi yeni çalıştırılmış sayılmaz.

Excluded prover crate'lerinin typecheck'i, gerçek SP1 proof üretimi veya release modda native/guest commitment eşitliği değildir. Aynı şekilde repository commit'i, canlı gateway binary'si ve zincirdeki verifier/VKey'nin eşleştiği bu oturumda ölçülmedi. Eski deployment tabloları güncel çalışma kanıtı yerine kullanılmamalı.

## 3. Düzeltme sırası ve kapanış ölçütleri

**Paket 1 — Yatırma ve dayanıklılık (A01, A02, A09).** Dayanıklı izin kaydı, tek ve sıralı snapshot yazıcısı, tam timeout, otonom L1 ingester. İlk kullanıcı çevrimdışıyken ikinci kullanıcı kredilenebilmeli; başarılı izin yanıtından sonra restart güvenli olmalı. Engine'in no-skip ve L1-prefix bağlarını gevşetme.

**Paket 2 — İşlem ve itiraz doğruluğu (A03, A04, A05, A08).** Özgün imzalı receipt teslimi ve Foundry challenge round trip; kalan maker iptali; gerçek fill ledger'ı; execution/finality ayrımı; doğru public veri. İlgili E2/E3/E4 tasarımlarını mevcut kodla yeniden karşılaştır; sadece frontend'de mesaj değiştirerek kapatma.

**Paket 3 — Çıkış ve kurtarma (A06, A07).** CloseOnly'de açık pozisyondan ödemeye kadar kanıtlı yol, kullanıcı anahtarı kurtarma, bağımsız claim paketi. Protokol değişiklikleri için mevcut cross-layer vektörlerini sessizce değiştirme; migration/yeniden deployment açık iş olarak tanımlansın.

**Paket 4 — Yayın güvenliği (A10, A11).** Doğru trust model, güncel bağımlılık değerlendirmesi, guest/native parity, gerçek proving, release testleri, L1 reorg/finality incelemesi, canlı crash-recovery tatbikatı ve bağımsız dış denetim.

Bir bulgu ancak güvenlik özelliğini sınayan test önce eski kodda beklenen sebeple başarısız olup düzeltmeden sonra geçtiğinde, ilgili regresyonlar ve mimari etkiler de incelendiğinde kapatılmalı. Bu dalın karakterizasyon testlerinin geçmesi kapanış ölçütü değildir.

## 4. Yeniden üretim

Gereksinimler: Git, Python 3.12+, Rust/Cargo ve lockfile bağımlılıklarını indirebilen ortam. Repository kökünden:

```sh
python3 scripts/audit/2026-09-17/run.py
```

Çalıştırıcı yalnızca sabit audit commit'inin izole kopyasını test eder. Yerel çalışma ağacındaki sonradan yapılmış bir düzeltmeyi sınadığını iddia etmez. `status.json` içindeki baseline, kaynak blobları, test kaynağı SHA-256'sı, komut ve exit code birlikte okunmalıdır. Eksik toolchain, derleme hatası, timeout veya sıfır test başarılı audit diye kabul edilmez.
