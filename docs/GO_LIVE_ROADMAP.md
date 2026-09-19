# Dark-perp / Arcora Perp — security remediation & go-live roadmap

**Tarih:** 18 Eylül 2026  
**Durum:** remediation büyük ölçüde tamamlandı; gerçek para deployment henüz onaylı değil.  
**Referans:** A10 sonrası `main@21d31ff1396db07df99384b0b6a43dbbe60d626b`; A11 PR #11 açık.

Bu belge audit sonrasında yaptıklarımızı ve canlıya çıkmadan önce kapanması gereken release kapılarını tek yerde tutar. Unit testin yeşil olması tek başına deployment onayı değildir; prover/vkey, key custody, oracle, snapshot ve operasyon kanıtları aynı release SHA'ya bağlanmalıdır.

## 1. Yaptıklarımız

| Bulgu | Durum | Sonuç |
|---|---|---|
| A01 | merge | Finalized L1 sırasından otomatik deposit ingestion; confirm yalnız yardımcı; explicit market/purpose; insurance ayrımı; replay/reorg/restart/durability bariyerleri |
| A02 | A01 içinde | Deposit authorization + blind snapshot ACK olmadan imza dışarı verilmiyor |
| A03 | merge | Challenge için gerekli signed receipt materyali kullanıcıya taşındı |
| A04 | merge | Resting/partial emrin yalnız kalan kısmı iptal; fill geri alınmıyor; rollback/restart dayanıklılığı |
| A05 | merge | filled/remaining/VWAP gerçek execution kayıtlarından türetiliyor |
| A06 | merge | Counterparty-free CloseOnly wind-down; phase-1 SettleAll + phase-2 exit; phase proof commitment'a bağlı |
| A07 | merge, entegrasyon düzeltmesi gerekli | Wallet-authorized API-key rotation; replay nonce; DPSNAP8 migration |
| A08 | remediation | Synthetic depth/stale timestamp audit kapsamına alındı; release smoke'ta tekrar doğrulanacak |
| A09 | A01/A04 ile güçlendirildi | Snapshot ACK/restart/persistence bariyerleri; fiziksel crash drill release gate'te şart |
| A10 | merge | Trusted-gateway/custodial ve gateway-oracle sınırı README/security/litepaper'da açık |
| A11 | açık PR #11 | Dependency audit, release regression, Foundry/frontend ve prover/deployment evidence gate |

Korunan ana invariants: deposit prefix atlanmaz/çift kredilenmez; insurance kullanıcı collateral'ı olmaz; migration state reset değildir; cancellation fill'i geri almaz; finality fill uydurmaz; wind-down ordinary batch'e gizlenemez; recovery public owner bilgisinden credential üretmez; ZK user intent veya external price truth kanıtlıyor diye sunulmaz.

## 2. Şu anki kırmızı gate

A11 release CI gerçek bir A07 entegrasyon hatası yakaladı: current main'de `account_recovery::...` kullanımları var fakat release checkout'unda `mod account_recovery;` deklarasyonu yok. Gateway bu nedenle derlenmiyor ve release regression exit 101.

**Current main deploy edilemez.** Önce A07 hotfix:
- module/compile binding düzeltilecek;
- recovery + stale/replay signature testleri;
- DPSNAP5/6/7 → DPSNAP8 migration testleri;
- normal CI ve A11 release CI tamamen yeşil.

A11'in dependency, Foundry, frontend ve source/deployment-record işleri yeşil olsa da bu kırmızı gate'i geçersiz kılmaz.

## 3. Canlıya çıkış fazları

### Faz 0 — Release freeze
A07 hotfix ve A11 merge sonrası tek release SHA/tag sabitlenir. Rust, Node/pnpm, Foundry, Solidity ve SP1 toolchain sürümleri manifest'e yazılır; lockfile'lar frozen; binary/artifact SHA-256'ları kaydedilir. SHA değişirse source-bound kanıt yeniden üretilir.

**GO:** tek SHA, temiz tree, bütün required CI yeşil.

### Faz 1 — Supply chain
`cargo audit` ve `pnpm audit --prod` artifact'leri triage edilir. Reachable critical/high açık kalmaz. SP1/crypto dependency'leri scanner susturmak için körlemesine upgrade edilmez. Actions/container sürümleri mümkün olduğunca immutable SHA/digest'e pinlenir; SBOM/provenance üretilir.

### Faz 2 — Full regression
Aynı SHA üzerinde fmt, Clippy `-D warnings`, full Rust workspace, serde/no_std, A01/A04/A05/A06/A07 özel regresyonları, full Foundry, frontend test/build ve gerçek `GATEWAY_URL` E2E çalışır. Uzun fuzz/property testleri azaltılmaz; timeout başarı değildir.

**GO:** 0 failure; her ignored/skipped test isimli gerekçeli.

### Faz 3 — SP1 source → ELF → vkey → proof
A06 guest semantiğini değiştirdiği için Temmuz deployment vkey'i current source için kanıt değildir.

1. Current `crates/sp1-guest` gerçek SP1 toolchain ile build.
2. ELF SHA-256 ve toolchain identity kaydı.
3. Aynı witness'ta native ↔ zkVM guest public output byte-exact parity.
4. O ELF'den program vkey türetme.
5. Gerçek Groth16 proof üretme.
6. Intended verifier path ile proof doğrulama.
7. A06 phase 0/1/2 cross-layer KAT.
8. source SHA + ELF + vkey + proof + public inputs tek immutable evidence bundle.

**GO:** bu zincirin her halkası aynı release SHA'ya hash ile bağlı.

### Faz 4 — Deployment dry-run
Anvil/fork üzerinde gerçek deployment script'i çalıştırılır. Constructor/admin/sequencer/enclave/oracle/vault parametreleri, runtime bytecode hash'leri ve genesis root doğrulanır. Deposit → trade → partial fill → cancel → settle → withdraw; CloseOnly → SettleAll → finalExit; recovery old-key reject/new-key accept; duplicate deposit/proof/withdraw negatif yolları denenir.

### Faz 5 — Key custody / oracle
Envanter: deployer/admin, sequencer, enclave signer, gateway custody keys, oracle publisher, prover/attestation identity, emergency/CloseOnly authority. Her biri için storage, erişim, rotation, compromise etkisi ve revoke/recovery runbook yazılır.

Mainnet hedefinde gateway-held user spend authorization ve gateway-controlled oracle ayrıştırılmadıkça ürün A10'da yazdığı gibi **trusted-gateway/custodial** işletilmelidir.

### Faz 6 — Staging rehearsal
Production'a benzeyen staging/Base Sepolia'da:
- browser kapanmışken ordered deposits;
- duplicate event, RPC timeout/disagreement/reorg;
- snapshot disk failure + SIGKILL + restart;
- prover restart/proof retry;
- partial fill/cancel yarışı;
- settlement restart;
- CloseOnly full exit;
- API-key loss + wallet recovery;
- gateway kapalıyken permissionless withdrawal;
- frontend/backend version mismatch.

**GO:** çift kredi/withdraw, kayıp izin, hayalet emir veya sessiz state reset yok.

### Faz 7 — Observability / incident response
Minimum alarm: deposit cursor lag/halt; snapshot dirty/ACK; settlement lag; prover latency/failure; RPC disagreement; oracle age/deviation; vault-engine accounting invariant; withdrawal failures; recovery nonce/signature failures; CloseOnly activation; restart/disk/memory pressure.

Runbook: trading/deposit/settlement pause, CloseOnly, RPC/oracle failover, snapshot restore, prover failover, key compromise, verifier mismatch ve iletişim/escalation. En az bir tabletop + bir staging drill yapılır.

### Faz 8 — Independent review
İç remediation bağımsız audit değildir. Dış review en az perp-core accounting, matcher/finality, deposits, snapshot/migration/recovery, A06 economics, SP1 binding, contracts/vault/withdraw/challenge, oracle/key custody ve deployment scripts'i kapsar. Critical/high açıkken gerçek para açılmaz.

### Faz 9 — Production
Release evidence dondurulur; chain id/RPC consensus kontrol edilir; contract deploy/upgrade sonrası runtime code hash, verifier/vkey ve genesis/state root tekrar doğrulanır. Gateway/prover/frontend aynı manifest ile başlar. Küçük canary deposit → trade → real proof settlement → withdraw → recovery yapılır. Limitler ancak smoke temizse kademeli artırılır.

### Faz 10 — İlk 24 saat / 7 gün
İlk 24 saat düşük limit + sürekli deposit/finality/proof/snapshot/oracle/vault invariant gözlemi. İlk 7 gün günlük reconciliation, recovery/cancel/withdraw hata oranı, RPC/oracle disagreement, prover memory/latency trend ve kontrollü restart drill. Limit artışı yalnız temiz veriyle.

## 4. Final GO / NO-GO checklist

Gerçek para deployment için aynı release SHA üzerinde hepsi **EVET**:
- [ ] Current main/release derleniyor ve bütün required CI yeşil.
- [ ] A07 recovery hotfix + snapshot migration testleri yeşil.
- [ ] Dependency audit triage tamam.
- [ ] Full Rust/Foundry/frontend/E2E + fuzz tamam.
- [ ] Current SP1 guest ELF hash kaydı.
- [ ] Native ↔ guest parity byte-exact.
- [ ] Current ELF'den vkey türetildi.
- [ ] Gerçek Groth16 proof intended verifier ile doğrulandı.
- [ ] Contract code hashes/deployment params/current vkey doğrulandı.
- [ ] Snapshot crash/restart ve L1 RPC/reorg drill başarılı.
- [ ] CloseOnly full-exit ve account-recovery rehearsal başarılı.
- [ ] Oracle/key custody inventory + rotation runbook hazır.
- [ ] Monitoring/incident runbook staging'de test edildi.
- [ ] Bağımsız review'da açık critical/high yok.
- [ ] Canary deposit/trade/proof/withdraw başarılı.

Bir madde **HAYIR/BİLİNMİYOR** ise sonuç **NO-GO**.

## 5. Sonraki iş sırası

1. **A07 integration hotfix** — current main yeniden derlenebilir hale getir.
2. **PR #11 / A11'i yeşile getir ve merge et.**
3. Release SHA freeze.
4. SP1 current ELF/vkey/real-proof evidence.
5. Deployment fork rehearsal + crash/reorg drills.
6. Key/oracle operational hardening.
7. Independent audit.
8. Canary testnet/release.
9. Gerçek para production, düşük limitlerle kademeli açılış.

Bu roadmap bir “mainnet hazır” sertifikası değil; tam tersine, hangi kanıt yoksa onu görünür tutan release sözleşmesidir.
