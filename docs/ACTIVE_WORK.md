# Arcora Perp: aktif iş ve kalan kabul kapıları

Güncelleme: 10 Ekim 2026. **PRODUCTION RELEASE HOLD**.
Bu belge güncel çalışma sırasıdır; tarihsel `NEXT_STEPS.md` yerine kullanın.
Başlangıç main: `8ed3fc2fb2776a6e711ac24d6e804ab6539cfd6a`.

## Korunan tamamlanmış işler

#33 DH/zeroize/deployment policy; #35 zorunlu restore; #36 bağımsız ARM64 cold
guest build; #37 paired journal/cursor recovery; #38 oracle intake main'dedir.
Bu alt ölçütler yeniden açık iş sayılmaz; canlı kullanım kabulü değildir.
#39 iki borsa host kontrolünün 17/17 CI kontrolü başarılıdır, fakat merge çağrısı
araç güvenlik engeline takıldı. Başka kanalla merge denenmedi; PR açık bırakıldı.
Chainlink dalı doğrudan main'den açıldı, #39'a bağımlı değildir.

## Aktif paket: Chainlink Data Streams

Amaç: authenticated rapor alma, katı v3 decode, açık USD/USDC dönüşümü ve
kullanılan HER oracle işlemini DON tarafından doğrulanan rapora bağlayan ayrı
v3 aday proof yolu. Mevcut reviewed v2 ELF/vkey/pinleri değiştirilmez.
Kaynak değişimi, mevcut oracle listesini manifest'e koymakla yeterli olmaz:
reviewed derive_roots manifest.oracle_updates ile op oracle'larını eşleştirmez.
Yeni yol doğrudan Fill/AccrueFunding/Liquidate/Unbind işlemlerini taramalıdır.

API istemcisini yazan araç çağrısı ayrıca güvenlik engeline takıldı; aynı işlem
başka yoldan denenmedi. Bu turda canlı/authenticated API istemcisi tamamlanmış
sayılmaz. Çalışma odağı offline rapor doğrulama ve aday proof bağıdır.

## Açık işler ve kapanış ölçütleri

| Öncelik | İş | Kapanış ölçütü |
|---|---|---|
| P0 | Dört exact wallet witness proof'u | Yeni gerçek proof + gerçek SP1/clock/settlement/claim doğrulaması; CPU execution/setup sayılmaz |
| P0 | Deployment/servis kimliği | Hedef chain, runtime/immutable/config/vkey ve çalışan servis eşleşmesi |
| P0 | NVIDIA CC/key release | Gerçek backend, evidence, nonce/measurement pinleri ve canlı handshake; mevcut backend fail-closed stub |
| P1 | Chainlink canlı entegrasyon | Yetkili stream erişimi; gerçek feed/decimal/quote pinleri; DON verifier; yeni guest kimliği ve proof; gateway/prover/L1 uçtan uca bağlantı |
| P1 | Oracle ekonomisi | USD/USDC değerleme, rapor zaman politikası ve likidite zarfı bağımsız değerlendirme; TWAP/quorum iddiası yok |
| P1 | Prover kapasite/finalite | Gerçek proof p95/RSS, yükte admission duruşu ve risk eşikleri |
| P1 | Operatör/prover/governance kaybında exit | Yeni withdrawal ve bağımsız claim verisi erişimi, gerçek verifier ile fon senaryoları |
| P1 | Matching fairness/ret meşruiyeti | Sıra ve ret kurallarının guest içinde doğrulanması; ayrı guest-affecting çalışma |
| P2 | Operasyonel recovery | Canlı anahtarlarla farklı makine, L1/pending tx uzlaşması, ölçülmüş RTO/RPO ve alarm teslimi |
| P2 | Bağımsız audit | Protokol/custody/proof/sözleşme/ekonomi dış incelemesi |
| P2 | Repository policy belgeleri | Canlı review=0 ile eski şablon farkını açıkça çözme; korumaları sessizce değiştirmeme |

## Değişmez sınırlar

Gerçek key/seed/credential dosyaları okunmaz veya yayınlanmaz. Ücretli abonelik,
GPU/prover, zincir yazısı, state migration ve production rollout bu pakette yok.
Mock DON/SP1 testleri canlı imza veya proof değildir. Yeni aday guest kaynakları,
reviewed guest'in yerine geçirilmez. Gerçek fonlu yayın kararı açık kalır.
