# Hız + Dark Perp — Mimari (v2)

**Attested-TEE confidential execution · ZK vault safety · protocol-level
fairness/liveness · note-shielded state**
Ethereum settlement · Aztec opsiyonel privacy bridge · CELARI wallet

> Bu belge protokolün kanonik referansıdır. Kod (`crates/`) bu belgedeki bölüm
> numaralarına (§) atıfla yorumlanmıştır. v2 üç zorunlu deliği kapatır — **order
> inclusion accountability**, **forced exit / recovery**, **note recovery
> archive** — ve güven köklerini dürüst etiketler.

---

## 0. Tasarım tezi (düzeltilmiş güven kökleri)

Hız ve dark fiziksel olarak çekişir. Bunu *pratik latency'de* bir arada veren
bileşen TEE'dir — ama **TEE güveni yok etmez, başka köke taşır**, ve
fairness/liveness/recovery ayrı protokol yükümlülükleridir.

| Kök | Ne sağlar | Ne sağlamaz |
|---|---|---|
| **TEE = low-latency confidential execution root** | operatör-kör matching, native-hız continuous CLOB | liveness, fairness, censorship-resistance, recovery |
| **Protokol = order-commitment log + forced exit + slashing** | sequencing accountability, liveness, fair access | gizlilik, fon validity |
| **ZK = fund safety / state validity root** | vault güvenliği, state geçiş geçerliliği | inclusion/ordering/censorship (kendiliğinden) |

**Kritik incelik:** ZK "bu batch içindeki state transition geçerli" der. "Batch'e
hangi emirler girdi/girmedi, hangi sırayla, kim sansürlendi" demez. O boşluğu
**receipt + timeout + slashing** kapatır (§2). TEE kırılırsa vault'tan fon
**çalınamaz** (ZK korur), ama gizlilik + fair access + preconf güvenilirliği +
market integrity kırılabilir (§10).

**Dürüstlük notu (SEC-019):** yukarıdaki "ZK = fund safety" satırının bir istisnası
var — deposit bütünlüğü bugün **enclave-köklü, ZK-köklü değil**. `BatchOp::Deposit`
proof commitment'ında bir L1 deposit-event root'una bağlanmaz (kod:
`perp-core::commitment::derive_roots`), bu yüzden sequencer key'ini elinde tutan
çökmüş bir enclave arkasız bir not (unbacked note) basabilir. ZK deposit-binding
**P3** (planlandı, henüz teslim edilmedi).

---

## 1. Katman haritası

```
CLIENT (CELARI) ──encrypted order──► SEQUENCER/MATCHER (TEE, operatöre KÖR)
   ▲  scan view-key                     │ decrypt → in-memory CLOB → native match
   │                                    │ signed receipt (ACCEPTED) · preconf (MATCHED)
   │                                    │ shielded state · sürekli solvency (likidasyon)
   │                                    │ append-only ENCRYPTED ORDER LOG
   │                                    ▼ sealed batch + batch_manifest
   │                         PROVER (ATTESTED confidential workers — SOĞUK)
   │                                    │ witness yalnızca attested measurement'a decrypt
   │                                    │ Proof-v1: invariant'lar · Proof-v2: matching determinism
   │                                    ▼ proof + state root + DA blob
   │                         SETTLEMENT — Ethereum L1
   │                                    │ ZK verifier → hard finality
   │                                    │ collateral vault + withdrawal queue
   │                                    │ FORCED-EXIT / close-only emergency module
   │                                    │ DA: EIP-4844 blob
   └──────────────── ENCRYPTED NOTE ARCHIVE / INDEXER (kalıcı) ◄──────────────┘
                     ciphertext arşivi · view-key ile taranır · redundancy

ORACLE — Pyth (pull) → enclave; oracle transcript + sanity bound + close-only breaker (§8)
PRIVACY BRIDGE — Aztec (opsiyonel, Faz 4): padding/batching/relayer
```

---

## 2. Sequencing accountability — order inclusion

ZK eksik evren verilirse yalan söylemez; sadece eksik evreni doğrular. Inclusion
ayrı kanıtlanır.

**Her kabul edilen emir için imzalı receipt:**
```
order_hash = H(encrypted_order, user_ephemeral_key, nonce, expiry, market_id)
receipt    = Sign_enclave(order_hash, seq_no, recv_time, batch_id_hint)
```

**Her batch bir manifest yayınlar:**
```
batch_manifest = {
  previous_state_root, batch_id,
  ordered_order_hashes[], rejected_order_hashes[] + reason_codes[],
  oracle_update_hashes[], matching_rule_version,
  enclave_measurement, sequencer_pubkey_epoch
}
```

**Boşluk paylaşımı:** ZK → manifest'teki sıralı emirler altında fill doğruluğu
(Proof-v2). Inclusion açığı **ripeness gate + challenge/answer + slashUnanswered**
ile kapanır (SEQ-001, implemente edildi): imzalı `recvTimeMs`'den
`inclusionDeadlineSecs` sonra bir emir challenge edilebilir hale gelir (erken/spam
challenge açılamaz — `DarkPerpSettlement.challengeInclusion`). Sequencer
`answerChallenge` ile emri gerçekten SETTLED bir batch'in `orderedRoot`'unda
kanıtlarsa: inclusion challenge açıldıktan SONRA gerçekleştiyse (forced inclusion)
challenger'ın stake'i challenger'a **refund** edilir (slash YOK); challenge
açılmadan ÖNCE zaten dahil edilmişse (gürültü/griefing) stake sequencer'a kalır.
Hiçbir cevap gelmezse `slashUnanswered` sequencer bond'unu challenger'a **slash**
eder ve sistemi close-only'e sokar. İkisi *birlikte* censorship/withholding'i
kapatır.

*(Kod: `order.rs` — `Order::order_hash`, `Receipt`, `BatchManifest`;
`contracts/DarkPerpSettlement.sol` — `challengeInclusion`, `answerChallenge`,
`slashUnanswered`.)*

---

## 3. Finality semantics — üç katman + failure matrisi

```
ACCEPTED = enclave emri aldı, seq_no + receipt verdi
MATCHED  = fill preconfirmation imzalandı (soft)
SETTLED  = ZK proof Ethereum'da verify oldu (hard)
```

| Durum | Sonuç |
|---|---|
| MATCHED + batch prove edildi | Normal → SETTLED |
| MATCHED + batch prove edilemedi | Batch reddedilir; etkilenen fill'ler **rollback**; insurance yalnızca kanıtlı protokol hatasında |
| MATCHED + enclave crash | Önceden yayımlanmış çekim kökü ve Merkle verisiyle claim yapılabilir; receipt + state root tek başına çıkış hakkı değildir. Yeni çıkış operator/prover ve final wind-down sırasında governance gerektirir |
| MATCHED var, L1 hard root yok | Withdraw **mümkün değil** |
| Receipt var, MATCHED yok, timeout aşıldı | Inclusion ihlali → slashing + forced-exit |

İlke: **bağlayıcı olan SETTLED'dır.** *(Kod: `order.rs` — `Finality::is_withdrawable`.)*

---

## 4. Proof obligations — staged

**Proof-v1 (invariant'lar — MVP, Phase 0'da kodlandı):** collateral conservation;
valid nullifiers (double-spend yok); fill sonrası margin yeterliliği; oracle price
freshness + confidence (§8); funding formülü; liquidation threshold.

**Dürüstlük notu (ZK-001/ORA-001):** oracle price bugün **imzasız bir prover
witness'ı** — `OracleTranscript` publisher imzası taşımaz, `derive_roots` onu
authenticated bir kaynağa bağlamaz; yani yukarıdaki freshness/confidence
"invariant"'ları bugün **prover-satisfiable** (prover transcript'i istediği gibi
kurup geçirebilir). Publisher-signature binding **P3** (planlandı, henüz teslim
edilmedi).

**Proof-v2 (matching determinism):** committed order log üzerinde deterministic
price-time priority; cancel/replace ordering, self-trade prevention, partial fill,
expiry; order tipleri (IOC/FOK/post-only/reduce-only); likidasyon emir önceliği.

v1'de matching doğruluğu için **receipt + manifest + slashing**; v2'de kriptografik
determinism.

---

## 5. Liquidation — hız+dark altında

Enclave plaintext pozisyonları public oracle'a karşı sürekli değerlendirir →
**anında** tetikler. **Liveness varsayımı yok:** kullanıcı offline olsa da likide
edilir. Public'e per-position açıklama **yok**; yalnızca aggregate + ZK proof.
*(Kod: `position.rs` — `is_liquidatable`; `engine.rs` — `op_liquidate`.)*

---

## 6. Forced exit / escape hatch

```
Withdrawals only from hard-finalized state.
Sequencer/enclave unavailable for T blocks
   → user initiates forced action against last hard root
   → system enters CLOSE-ONLY emergency mode
   → settled balances stay claimable (CollateralVault.claim) against any published
     withdrawals root; open perps wind down via reduce-only closes + a governance
     finalSettle landing pad
   → insurance fund covers protocol-fault shortfall, not market loss
```
Açık pozisyon collateral'ı **pozisyon kapatılmadan** çekilemez. **Bugün teslim
edilen mekanizma (EXIT-001):** `CollateralVault.claim()` close-only'de de açık
kalır — herhangi bir yayınlanmış withdrawals root'una karşı, settle edilmiş
bakiyeler her zaman çekilebilir (yetki hep verified state'te, operatörde değil).
Açık pozisyonlar close-only'de reduce-only kapanışlarla küçülür; bu kapanışların
withdrawals root'a girmesi için governance-only `DarkPerpSettlement.finalSettle`
bir landing pad sağlar (close-only + `closeOnlyBlock + finalSettleGraceBlocks`
grace penceresi + proof-gated — bkz. `docs/FINAL_SETTLE_RUNBOOK.md`).
**Muhafazakâr-TWAP forced-close (pencere TWAP'ında otomatik kapanış) henüz
implemente değil** — kullanıcı/operatör pozisyonu reduce-only ile manuel kapatır.
Tam trustless forced-close **P3**. Kullanıcı **son hard state'e** döner. *(Kod:
`state.rs` — `Mode::CloseOnly`; `engine.rs` — `EnterCloseOnly`;
`contracts/DarkPerpSettlement.sol` — `finalSettle`; `contracts/CollateralVault.sol`
— `claim`.)*

---

## 7. Note recovery / DA

4844 blob'ları geçici (~haftalar). **Encrypted Note Archive / Indexer (zorunlu):**
public ciphertext arşivi; view-key ile taranır; `batch_id → note_commitment →
ciphertext`; redundancy + forced-exit-uyumlu retention. Cihaz kaybında: seed →
view-key → arşivi tara → pozisyonu yeniden kur. *(Kod temeli: append-only
commitment tree, `merkle.rs`; Faz 2'de arşiv servisi.)*

---

## 8. Oracle — transcript + sanity

```
oracle_transcript = { signed_price, publish_time, confidence_interval,
  max_staleness_ms, max_deviation_vs_backup }
```
ZK (Proof-v1): publish_time pencerede; confidence ≤ threshold; |primary −
backup_twap| ≤ sanity_bound; likidasyon kabul edilen snapshot'ı kullandı.
**Kalibrasyon:** Pyth-primary + TWAP backup sanity bound + anomalide close-only
breaker. **Dürüstlük notu (ZK-001/ORA-001):** `signed_price` adı yanıltıcı — bugün
fiilen **imzasız**. `OracleTranscript` (kod: `oracle.rs`) publisher imzası taşımaz
ve `derive_roots` onu authenticated bir kaynağa bağlamaz, yani yukarıdaki
freshness/confidence kontrolleri bugün **prover-satisfiable**. Publisher-signature
binding **P3** (planlandı, henüz teslim edilmedi). *(Kod: `oracle.rs` —
`OracleTranscript::validate`.)*

---

## 9. Liquidation privacy — dürüst leakage modeli

Per-position gizli; market-seviyesi baskı (funding/OI/insurance) indirgenemez
görünür. Policy: no per-position disclosure; aggregate count/range only;
delayed/batched accounting; ZK validity without exposing account/size.
**Dummy-event padding'e şüpheciyiz** — batching/aggregation tercih edilir.

---

## 10. TEE risk — daraltılmış hasar cümlesi

```
TEE compromise CANNOT directly bypass the L1 vault validity rules,
but CAN break: confidentiality, fair access, preconfirmation reliability,
liveness (forced-exit yoksa), and market integrity.
```
Hasar sınırlama: vault → ZK; liveness → forced exit (§6); fairness/inclusion →
order log + slashing (§2); confidentiality redundancy → committee-of-enclaves
(§11). Side-channel geçmişi gerçek (Foreshadow, Plundervolt, ÆPIC, SGX.Fail).

---

## 10b. Confidential proving boundary — prover witness gizliliği

**ZK witness'ı VERIFIER'dan gizler, PROVER'dan değil.** Çıplak prover farm her
pozisyonu/fill'i plaintext görür → **prover layer çıplak sunucu olamaz.**

**v1 policy (attested prover):** matcher enclave → sealed witness package →
ATTESTED PROVER (TDX/Nitro) measurement'a decrypt → ZK proof → Ethereum verifier;
witness yalnızca attested measurement'ında açılır; job bitince silinir.

**Bugünkü durum (SEC-020):** prover'a bugün bir localhost SSH reverse tunnel
üzerinden ulaşılıyor ve attestation bir **stub** — sabit `0xAB` measurement +
public seal-root default'u (`0x5E`), gerçek bir TDX/Nitro quote/attestation
DEĞİL (kod: `crates/gateway/src/prover_client.rs`). Gerçek TDX/Nitro attestation
verification **P3** (bkz. `docs/ROADMAP.md` Faz 1 "Enclave attestation
verification").

**Sonuç:** Private batch'i public proving network / outsourced GPU proving ile
üretemezsin. Self-hosted attested prover şart.

**Spektrum:** attested-TEE prover (v1) → collaborative/MPC proving (hardening) →
client-side proving (Aztec modeli, paylaşımlı batch'e ölçeklenmez). **Hibrit:**
kullanıcı kendi note consume/create'lerini client-side ispatlar; TEE prover yalnız
cross-user matching/aggregation. **Length leakage:** fixed-size (padded) circuit /
recursion ile normalize et. **Memory zarfı:** confidential prover enclave memory
limitiyle zorlanır → sıcak circuit'ler tighter olmak *zorunda*. **Faz timing:**
production (Faz 2+) gereği, Faz 0 değil — Faz 0'da açıkta prove et.

---

## 11. Güven kökü spektrumu + mainnet duruşu

| Seçenek | Hız | Karanlık | Güven kökü |
|---|---|---|---|
| Pure TEE | en hızlı (continuous CLOB) | operatör-kör | donanım |
| TEE + MPC (committee-of-enclaves) | hızlı | operatör-kör + threshold | donanım **ve** t-of-n |
| Pure MPC (Renegade) | batch-auction (orta) | kriptografik | t-of-n |
| FHE | çok yavaş | kriptografik (en güçlü) | matematik |

**Taksonomi:** *Protocol completeness* (order log, forced exit, oracle transcript,
note archive) → HER versiyonda zorunlu. *Enclave redundancy* (committee) → yalnız
confidentiality/integrity tek-nokta-kırılması. **Mainnet duruşu:** tek enclave +
tam completeness + muhafazakâr cap'ler savunulabilir mainnet-beta; committee
**fast-follow** (quorum round-trip hızı vergiler).

---

## 12. Deterministik risk çekirdeği

Risk motoru (margin, likidasyon eşikleri, max leverage, oracle sanity bound'ları)
enclave içinde **deterministik kod** + ZK'da yeniden kanıtlanır. Takdir yok,
bound'suz oracle güveni yok. *(Kod: `market.rs` deterministik parametreler;
`position.rs` + `funding.rs` + `oracle.rs` deterministik integer aritmetik.)*

---

## 13. İnşa sıralaması

- **Faz 0 — Local / Sepolia ZK perp core (Aztec YOK, TEE YOK).** Note tree, margin
  + funding + liquidation validity, zkVM benchmark. Proving açıkta. **← şu an burası.**
- **Faz 1 — TEE order gateway + receipt + preconf.**
- **Faz 2 — Batch manifest + ZK settlement + fund safety + confidential proving +
  forced-exit + note archive.**
- **Faz 3 — Fair-sequencing hardening (inclusion timeout, slashing, Proof-v2).**
- **Faz 4 — Aztec private bridge.**
- **Faz 5 — Committee-of-enclaves.**

---

## 14. Düşmanca DD — ölümcül sorulara cevap

1. **Emir alınmadı/gecikti, nasıl kanıtlanır?** → signed receipt + inclusion timeout → L1 slashing/forced-exit (§2).
2. **Preconf var, batch prove olmadı, pozisyon var mı?** → Hayır; bağlayıcı SETTLED. Rollback + kanıtlı-fault insurance (§3).
3. **ZK tüm order book'u mu kanıtlıyor?** → v1: invariant'lar; matching receipt+manifest+slashing. v2: committed-log determinism (§4).
4. **Sequencer kapanırsa hangi fiyat?** → close-only, conservative TWAP, son hard state (§6).
5. **Cihaz kaybında recovery?** → view-key ile encrypted note arşivi (§7).
6. **Likidasyon timing ifşa eder mi?** → aggregate/batched + delayed ile azaltılır; market-baskısı residual (§9).
7. **Enclave-içi oracle seçimi?** → transcript + sanity bound + close-only breaker, ZK-bağlı (§8).
8. **LP'ler neden likidite koysun?** → §15, varoluşsal.
9. **Witness'ı proof üretirken kim görüyor?** → attested confidential prover; public proving yasak (§10b).

---

## 15. Artık tradeoff'lar + asıl varoluşsal risk

- **"Dark"** = public + operatöre + **prover'a** karanlık (§10b); gizlilik kökü
  TEE'de. Per-position likidasyon gizli, market-baskısı görünür.
- **"Fast"** = sıcak yolda HFT-sınıfı; withdraw proof+finality bekler (dakikalar).
  MATCHED ≠ SETTLED.
- **Asıl risk teknoloji değil, likidite.** LP'siz dark book = kriptografik
  mezarlık. v1 kitabını enclave-içi market-maker botuyla tohumla, spread riskini
  dış venue'da hedge et.
- **Aztec bağımlılığı hafif** (yalnız Faz 4), Ethereum-direct bridge ile önce çık.
