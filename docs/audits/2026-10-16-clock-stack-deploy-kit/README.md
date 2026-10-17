# Clock-stack deploy kit — dry runs (16 Ekim 2026)

**PRODUCTION RELEASE HOLD.** Bu pakette gerçek bir zincire işlem gönderilmedi.
Her deploy, sahibi bu test olan yerel bir Anvil'de ya da Base Sepolia'nın yerel
Anvil fork'unda yapıldı. Anahtar olarak yalnız Anvil'in herkese açık geliştirme
hesapları kullanıldı.

## Araçlar

- `darkperp-gateway --print-genesis-root`: `ORACLE_SIGNER_KEY` için
  markets-only production genesis root'unu yazdırır (`GENESIS_ROOT=0x…`). L1,
  attestation, prover, listener ya da state dosyasına dokunmadan önce çıkar;
  yerleşik geliştirme anahtarını reddeder. Test:
  `crates/gateway/tests/print_genesis_root.rs` (3 test). Testler root'un
  deterministik olduğunu ve oracle anahtarına bağlı olduğunu, dosya
  yazılmadığını, dev anahtarının ve fazla argümanın reddedildiğini doğrular.
- `scripts/local-verification/deploy_clock_stack.py`: `release_manifest.py`'nin
  doğruladığı derlenmiş artifact'ları, CI'daki sahipli-Anvil manifest testinin
  sırasıyla `cast send --json` üzerinden deploy eder. Program anahtarı
  yapılandırılamaz. Anvil dışındaki her istemci `--allow-public-chain` ister.
  İmzalayıcı bayrakları `--` sonrasında verilir; araç anahtar okumaz. Başarısız
  bir işlemde `<output>.partial.json` yazılır.
- Frontend: `VITE_MOCK_USDC` / `VITE_COLLATERAL_VAULT` derleme zamanı
  adresleri. Boş bırakılırsa 11 Temmuz kaydı kullanılır; biçimsiz bir değer
  derlemeyi durdurur.

**Neden Foundry script'i değil:** `forge script` içinde `new SP1Verifier()`,
vendor'daki SP1 sözleşmelerini projenin solc 0.8.24 derleyicisiyle yeniden
derler. Manifest ise 0.8.20 vendor artifact'larının runtime kod hash'ini
sabitler. Bu yüzden araç doğrudan bu artifact'ları gönderir.

## Sonuçlar

| Deneme | Dosya | Sonuç |
|---|---|---|
| Sahipli Anvil (31337), kendi SP1 stack'imiz | `owned-anvil.json` | `VERIFIED_AT_FINALIZED_BLOCK`; 6 kontrat; operatör politikası eşleşiyor |
| Base Sepolia fork (84532), Succinct gateway `0x397A…` ve route verifier `0xb69f…` yeniden kullanılarak | `base-sepolia-fork-reuse-succinct-gateway.json` | Deploy başarılı, gözlem **BLOCKED: runtime size mismatch: sp1_gateway** |
| Base Sepolia fork (84532), kendi SP1 verifier ve gateway'imiz | `base-sepolia-fork-own-sp1-stack.json` | `VERIFIED_AT_FINALIZED_BLOCK`; 6 kontrat; politika eşleşiyor |

İkinci denemeden sonra on-chain kod vendor artifact'larıyla doğrudan
karşılaştırıldı:
- Succinct gateway on-chain 1.975 B, artifact 1.931 B; metadata çıkarılsa
  da farklı.
- Route verifier 6.741 B'a 6.741 B; CBOR metadata dışında aynı, ama manifest
  birebir kod hash'i ister.

Base Sepolia'da route mevcut ve dondurulmamış:
- `routes(0x4388a21c)` = `0xb69f2584…f4e2`
- `VERIFIER_HASH` = `0x4388a21c…e696`
- gateway sahibi `0xBaB2c2aF…1126`

**Sonuç:** GPU günü deploy'u kendi SP1 verifier ve gateway'imizle yapılır.
Succinct gateway'ini kullanmak, manifest'e onların bytecode'unu sabitleyen ayrı
bir release kararı gerektirir.

`fork_dry_run.py`, fork denemesinin script'idir (kendi stack'imizle olan
sürüm). Succinct varyantında yalnız `sp1_gateway`, `sp1_verifier` ve
`operator_policy.sp1_gateway.owner` değerleri farklıdır.

**17 Ekim 2026 notu:** `fork_dry_run.py`, settlement ABI version 3'ün yapılandırma
anahtarlarına güncellendi: clock bölümüne `anchor_timeout_ms`, settlement
politikasına `challenge_grace_blocks`, `progress_batches` ve
`slash_payout_cap_usdc`, üst düzeye `deposit_permit_ttl_secs` eklendi;
`challenge_window_blocks` kaldırıldı. Yukarıdaki
JSON kayıtları önceki sözleşme setiyle ve script'in önceki sürümüyle üretildi;
tarihsel kanıttır, yeni sözleşmeler için yeniden çalıştırılmadı.

## Doğrulanmayanlar

- Gerçek Base Sepolia'ya deploy yapılmadı. Prover olmadan kontratlar boşta
  kalır.
- Fork dry run'larındaki genesis root sentetik bir değerdir (`0x4d…`); gerçek
  root, gerçek `ORACLE_SIGNER_KEY` ile `--print-genesis-root`'tan alınır.
- Gerçek proof, attestation, prover ve settle döngüsü kapsam dışıdır
  (G3/G4).
