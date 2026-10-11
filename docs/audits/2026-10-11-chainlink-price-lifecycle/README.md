# Chainlink aday gateway: fiyat yaşam döngüsü

11 Ekim 2026. **PRODUCTION RELEASE HOLD.**

Normal withdrawal önceki akışta kabul edilmiş oracle'ın kaynak zamanını işlem
zamanıyla yeniden damgalıyordu; bu Unbind özgün arşiv kimliğine bağlanamıyordu.
Yeni aday akış özgün transcript/zaman/imzayı korur. Order, gerçek tick/matching,
funding/liquidation ve withdrawal fiyat kullanmadan önce seçilmiş tam raporu ve
işlem-zamanı politikasını doğrular. Eksik, bozuk, eski, yanlış veya kilidi
zehirlenmiş kaynak finansal state/book/nonce/root/op değişiminden önce reddedilir.

Runtime-only candidate bayrağı kayıp binding'de legacy davranışa dönüşü engeller.
Seal op'ları özgün zamanda doğrulamadan pencereyi ilerletmez veya journal yazmaz.
Runtime/final/recovery checkpoint'leri ve mutated=false/true WAL silme yolları da
eksik binding'de HOLD eder. Candidate sentetik demo ADL/pool/withdrawal yolları
reddedilir; fiyat gerektirmeyen terminal wind-down akışı korunur.

Gerçek gateway kodundan iki sentetik pozitif pencere üretildi:

- Normal açılış/fill → funding → reduce-only close → imzalı withdrawal;
  snapshot/restart ve yeni özgün rapor admission'ı dahil. 10 op / 9 evidence.
- Bakım marjını aşmış gerçek pozisyon liquidation'ı. 8 op / 8 evidence.

Her pencere özgün arşiv PairEvidence ve ClockContext ile DPCLK3 witness'ına
dönüştürülür. Native v3 public commitment, sabitlenmiş aday ELF'in **gerçek SP1
CPU yürütmesiyle** birebir eşleşti. Üç negatif witness (eksik evidence, yanlış
market, eski quote) guest exit 1 ve boş public çıktı verdi. Toplam 52.839.398
guest instruction cycle ölçüldü. Bu sentetik kaynaklar DON doğrulaması veya
SP1 proof değildir; SDK setup vkey ölçümü de production onayı değildir.

Tam test edilmiş kaynak `7f74867fe9313998fe6e7e4dfe5cffe83fe09c4f`, A2 belge
tabanına yeniden kurulmuş kod `e476ff1868a5e5320b8d1cd077253c87ed299e55`.
Dört kaynak dosyasının hash'i birebir aynıdır. Taban A2 yayın head'i
`b3a9507ad5bda336511aba6869745b19b7b66f19` (#46); #44/#45 main'dedir.
Nihai gateway **550 PASS / 0 FAIL / 17 IGNORE**; bunun içinde 9 yeni lifecycle
regresyonu ve A2'nin 4.100 admission/restart testi vardır. Export ignored helper
açıkça çalıştırıldı: 1 PASS. Workspace ve yeni host binary Clippy `-D warnings`,
format, 47 Python guard, 21 reviewed + 9 aday kaynak pini başarılıdır.

ELF SHA: `48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f`.
Ölçülen vkey: `0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590`.
Beş fixture'ın manifest SHA'sı:
`cb7bbbb3b02fccdd25df8938c3c70e4eb45bb5079011c3abe11fe6d7c88b540b`.
`fixtures/`, `cpu-execution/`, `process-guards.json` ve `verification.json`
public sentetik girdiyi/çıktıyı, kaynak/komut/log hash'lerini taşır. Yanlış ELF,
manifest, bozuk witness, eksik zorunlu pencere ve symlink için beş ayrı süreç
kontrolü setup/çıktı öncesinde reddi gösterir. Ham loglar yerel
`target/a3-verification/` ve continuation checkout'undaki
`target/lifecycle-validation-20261011/` altında korunur.

Mevcut CPU CI işine gerçek gateway exporter + yeni lifecycle binary yürütmesi
eklendi. Önceki 19-case corpus korunur. Aynı adım yerelde Rustup/offline/yerel
target yolu uyarlamalarıyla başarılı çalıştırıldı; YAML ve kaynak hash'leri
doğrulandı. Yeni PR head'inin GitHub CI sonucu ayrı kapıdır.

Yeniden CPU yürütmesi (yeni output dizini gerekir):

```sh
SP1_SKIP_PROGRAM_BUILD=true rustup run 1.99.0 cargo build --release --locked \
  --manifest-path crates/sp1-host/Cargo.toml --bin replay-chainlink-lifecycle
crates/sp1-host/target/release/replay-chainlink-lifecycle \
  --elf contracts/integration/fixtures/chainlink-candidate-v1/guest.elf \
  --input-dir docs/audits/2026-10-11-chainlink-price-lifecycle/fixtures \
  --manifest-sha256 cb7bbbb3b02fccdd25df8938c3c70e4eb45bb5079011c3abe11fe6d7c88b540b \
  --output-dir /tmp/arcora-lifecycle-NEW
```

Host SDK build'i protoc ve mevcut include-ELF artefaktını ister; CI bunları
hazırlar. Yukarıdaki CPU binary kendi sabitlenmiş aday ELF'ini yükler ve guest
derlemesi/prove/registration/broadcast yapmaz.

Aday normal submission ve exact v2 resume engelleri korunur. Sonraki A4 için
[offline protocol tasarımı](next-a4-design.md) hazırlanmıştır; uygulama veya
kapanış iddiası değildir. DPCLK3 witness, v2 inner clock ve uptime wrapper
kimliği farklı bağlardır; yeni prover/settlement rotası ayrıca gerekir.
