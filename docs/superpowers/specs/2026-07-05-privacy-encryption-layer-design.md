# Arcora Perp — Privacy / Encryption Layer (production-grade)

**Status:** Design approved 2026-07-05. Ready for implementation planning.
**Scope owner:** Kubudak90
**Relates to:** `docs/ARCHITECTURE.md` (§0 trust roots, §1 layer map, §7 note archive),
`docs/ROADMAP.md` (rows: *Encrypted order ingress + enclave key epoch* 🟡, *Append-only
encrypted order log* ⬜, note encryption stand-in).

---

## 1. Goal

Replace the three privacy **stand-ins / pending pieces** with real, production-grade
cryptography so the "dark" property rests on cryptography **in addition to** the TEE,
not on the TEE alone:

1. **Real note encryption** — replace the XOR-keystream stand-in in `note-archive` with
   authenticated public-key encryption, so whoever hosts the note archive cannot read
   balances or positions.
2. **Encrypted order ingress** — the client encrypts each order to the enclave's attested
   epoch key; only code inside the TEE decrypts it. Protects raw order terms and trader
   identity from everything outside the enclave.
3. **Append-only encrypted order log** — every ingested order is written to a
   hash-chained, encrypted, append-only log whose running head is committed on-chain via
   the existing batch manifest. Gives sequencing accountability + a prover witness while
   keeping contents confidential.

### Non-goals (explicit, YAGNI)

- **Not** hiding aggregate orderbook depth. Depth stays **public** — a deliberate product
  decision (users want to see the book). "Dark" here = hidden identity + hidden
  per-account balances/positions + operator-blind order flow, **not** a dark pool.
- **Not** migrating custody client-side. Phase-0 server custody stays (the enclave holds
  account spend keys). Order ingress encrypts *to the enclave's* key, which needs no
  custody migration.
- **Not** the ZK verifier. Real SP1/Risc0 is a **separate, subsequent mainnet gate** (see
  §9). This design is deliberately compatible with it but does not implement it.
- **Not** the Aztec privacy bridge (roadmap Faz 4).

### Threat model boundary (honest)

Protects the raw order flow, trader identity, and account state against: the operator /
VPS host / cloud provider, the gateway process boundary outside the enclave, logs, passive
network observers, and the note-archive host.

**Does not** protect against a **compromised TEE** — a CLOB must see plaintext orders inside
the enclave to match them. This is exactly the boundary `ARCHITECTURE.md §0` already states
("TEE kırılırsa gizlilik kırılabilir; fonları ZK korur"). This work adds defense-in-depth
*beyond* the TEE; it does not remove the TEE trust root.

---

## 2. Decisions (locked)

| Decision | Choice |
|---|---|
| Scope | All three pieces (note enc + order ingress + order log) |
| Maturity target | **Mainnet production-grade** (test vectors, epoch rotation, audit-ready) |
| Encryption scheme | **X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305** everywhere |
| Signing / identity | Unchanged — **secp256k1** (this layer is encryption-only) |
| Nonce strategy | 24-byte **random** nonce (XChaCha20) — no counter/nonce-reuse management |
| Orderbook depth | **Public** (unchanged) |
| Custody | **Server-side** (enclave-held), unchanged |
| Client crypto dep | `@noble` (curves/hashes/ciphers) — small, audited; matches RustCrypto |

---

## 3. Architecture — one primitive, three consumers

```
                         ┌────────────────────────────────────────────┐
                         │  sealed-box  (new crate, no_std-friendly)   │
                         │  seal / unseal:                             │
                         │   X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305 │
                         └───────────────┬─────────────┬──────────────┘
                                         │             │
     ┌───────────────────────────┐      │             │      ┌──────────────────────────┐
     │ note-archive               │◄─────┘             └─────►│ gateway (enclave)         │
     │  seal notes to owner       │                           │  order epoch keypair       │
     │  viewing pubkey            │                           │  unseal ingress orders     │
     └───────────────────────────┘                           │  append encrypted log      │
                                                              └──────────────────────────┘
     ┌───────────────────────────┐                           ┌──────────────────────────┐
     │ frontend (browser)         │  seal order to enclave    │ prover (attested, cold)   │
     │  @noble sealed-box mirror  │  epoch pubkey             │  unseal log/witness        │
     └───────────────────────────┘                           └──────────────────────────┘
```

### 3.1 `sealed-box` primitive

A single hybrid PKE construction, used identically in Rust and TS. Byte-for-byte
compatible (pinned by cross-language test vectors).

**`seal(recipient_pub: X25519Pub, plaintext: &[u8], aad: &[u8]) -> SealedBox`:**
1. Generate an ephemeral X25519 keypair `(esk, epk)` from a CSPRNG.
2. `shared = X25519(esk, recipient_pub)`.
3. `key = HKDF-SHA256(ikm = shared, salt = epk ‖ recipient_pub, info = "arcora/sealed-box/v1" ‖ aad)[..32]`.
   — binding `epk` and `recipient_pub` into the KDF salt prevents key/identity confusion;
     `info` carries the caller's domain AAD.
4. `nonce = random(24)`; `ct = XChaCha20-Poly1305.encrypt(key, nonce, plaintext, aad)`.
5. Output `SealedBox { epk (32), nonce (24), ct (len + 16 tag) }`.

**`unseal(recipient_sk, box, aad) -> Option<Vec<u8>>`:** recompute `shared`, `key`; AEAD
decrypt; `None` on tag failure or AAD mismatch. Constant-time where the library provides it.

**Rust deps:** `x25519-dalek`, `hkdf`, `sha2`, `chacha20poly1305` (XChaCha20 variant), `rand_core`.
All RustCrypto, no_std-capable (the crate is shared with the `no_std` `note-archive`/guest paths).
**TS deps:** `@noble/curves/ed25519` (x25519), `@noble/hashes/hkdf` + `sha256`, `@noble/ciphers/chacha` (xchacha20poly1305).

**Wire encoding:** `SealedBox` serializes as `epk(32) ‖ nonce(24) ‖ ct||tag`. A `version`
byte (0x01) prefixes it so the scheme can rotate. All multi-byte integers little-endian to
match existing `perp-core` conventions.

### 3.2 Key material (all HKDF-derived from existing seeds — no new stored secrets)

New `Domain` variants (append to `perp-core::hash::Domain`, next free = 24):

| Domain | Purpose |
|---|---|
| `X25519ViewKey = 24` | per-account note viewing keypair derivation |
| `X25519OrderEpoch = 25` | enclave order-ingress epoch keypair derivation |
| `X25519LogKey = 26` | enclave/audit order-log keypair derivation |
| `NoteEncryptAad = 27` | AAD domain tag for note ciphertexts |
| `OrderEncryptAad = 28` | AAD domain tag for order ciphertexts |
| `LogEncryptAad = 29` | AAD domain tag for order-log entries |

- **Account viewing keypair:** `view_sk = HKDF(seed, info=Domain::X25519ViewKey)`, clamped to
  a valid X25519 scalar; `view_pk = X25519_base(view_sk)`. This X25519 viewing key *is* the
  new scan capability — it supersedes the keccak `view_key` for note reading. The **spend
  key path is unchanged** (still secp256k1-derived, still the only nullifier authority), so
  the view/spend split is preserved with real crypto: a `view_sk` holder reads, cannot spend.
- **Enclave order epoch keypair:** derived inside the TEE from `ENCLAVE_SEED` +
  `Domain::X25519OrderEpoch` + `epoch_id`. Rotates (see §6). Sealed to the measurement like
  the existing state snapshot.
- **Log keypair:** derived from `ENCLAVE_SEED + Domain::X25519LogKey`. The log viewing secret
  is released only to an attested prover measurement (mirrors the existing `WitnessSeal`
  "decrypt-only-to-attested-measurement" pattern).

---

## 4. Piece 1 — Real note encryption (`note-archive`)

**Replaces:** `ciphertext = serialize(note) XOR keystream(view_key, commitment)`
(`note-archive/src/lib.rs`, the "documented stand-in").

**Encrypt (enclave, when a note is created for `owner`):**
```
aad       = Domain::NoteEncryptAad ‖ commitment          // binds ct to the note commitment
note_ct   = seal(owner.view_pk, serialize(note), aad)
archive.append(commitment, note_ct)                      // store (commitment, SealedBox)
```

**Scan / recover (owner, offline capable):**
```
for (commitment, note_ct) in archive:
    if let Some(pt) = unseal(view_sk, note_ct, aad = Domain::NoteEncryptAad ‖ commitment):
        note = deserialize(pt)
        assert note.commitment() == commitment           // belt-and-suspenders
        recovered.push(note)
```
AEAD tag success is the ownership test; the commitment re-check defends against a malformed
archive. Only the matching `view_sk` decrypts → **the archive host reads nothing.**

**Optimization (optional, note in plan):** a per-account 8-byte *detection tag* derived from
`view_sk` and stored alongside each entry lets a scanner skip non-matching entries without a
full AEAD trial-decrypt (Zcash-style). Ship the correct version first; add the tag if scan
cost matters.

**Migration:** the current testnet has no real user notes worth preserving (fresh genesis
after each redeploy). Cut over at the next gateway genesis — no archive migration path
needed. The `NoteKeystream = 10` domain and XOR path are deleted (not kept as a fallback).

---

## 5. Piece 2 — Encrypted order ingress

### 5.1 Enclave epoch key publication

- Enclave derives the current epoch keypair inside the TEE.
- New endpoint **`GET /v1/enclave/epoch`** returns:
  ```json
  { "epochId": <u64>, "x25519Pub": "0x…(32)", "notAfterMs": <u64>,
    "measurement": "0x422890f6…", "sig": "0x…(65)" }
  ```
  where `sig` is a **secp256k1 signature by the attested `EnclaveIdentity`** over
  `keccak(Domain::X25519OrderEpoch ‖ epochId ‖ x25519Pub ‖ notAfterMs)`.
- The client verifies `sig` recovers to the enclave signer **and** `measurement` equals the
  pinned attestation measurement the UI already shows. This **binds the epoch pubkey to the
  attested measurement** — a rogue gateway cannot substitute its own key to MITM ingress.

### 5.2 Client seal

```
terms   = canonical_order_terms(marketId, side, size, limitPrice, tif, reduceOnly, nonce)
aad     = Domain::OrderEncryptAad ‖ epochId ‖ owner
order_ct = seal(enclave_epoch_pub, serialize(terms), aad)
POST /v1/orders  { "epochId", "sealed": { epk, nonce, ct } }   // no plaintext terms on the wire
```
The order's `ciphertext_commit` / `order_hash` binding is unchanged and computed by the
enclave post-decrypt (and, for caller-signed accounts, the signature still covers the
order hash — verified after unseal).

### 5.3 Enclave unseal + match

```
terms = unseal(epoch_sk[epochId], sealed, aad)   // inside the TEE; reject unknown/expired epoch
→ existing admission → matcher → depth published (UNCHANGED, still public)
```
One XChaCha unseal per order — negligible latency. Backwards-compat window: accept a
plaintext order only in non-production/demo mode; production (`DARKPERP_PROD=1`) requires
sealed ingress.

**What it protects:** raw order (account, exact size/price, timing) from transport (beyond
TLS), the gateway process boundary, logs, the operator, and passive network → shrinks the
front-running/MEV surface and hides per-order identity linkage. Depth remains public because
it is derived *after* decryption inside the enclave.

---

## 6. Piece 3 — Encrypted order log

- **Entry:** on each ingested order, after decrypt, append
  ```
  entry_ct   = seal(log_pub, serialize(canonical_order), aad = Domain::LogEncryptAad ‖ seq)
  entry_hash = keccak(prev_entry_hash ‖ commitment ‖ entry_ct)
  log_head   = entry_hash
  ```
  Hash-chained → append-only + tamper-evident.
- **On-chain anchoring:** `log_head` at batch seal is folded into the **existing batch
  manifest** (`Domain::BatchManifest`) that is already committed on-chain via `settleBatch`.
  Rewriting log history diverges from the committed head → detectable. No new contract call.
- **Storage:** a sealed, append-only file alongside the state snapshot now; later a DA blob
  (EIP-4844) per `ARCHITECTURE.md`. This scope = local encrypted log + on-chain head.
- **Witness / recovery:** the attested prover reads the log to reconstruct the batch; the log
  viewing secret is released only to the attested prover measurement. This is the witness the
  ZK circuit will consume (§9) — the log format is designed to be that witness.

---

## 7. Cross-cutting requirements

- **Domain separation:** distinct `Domain` tags + AAD per purpose (note/order/log); no key or
  nonce reuse across purposes. Enforced by construction (different HKDF `info`).
- **Epoch rotation + forward secrecy:** the order epoch key rotates (default: per boot and
  every `EPOCH_ROTATE_HOURS`, config); the previous epoch is retained for a grace window so
  in-flight orders still decrypt. Ephemeral sender keys give per-message forward secrecy;
  epoch rotation bounds the recipient-key exposure window.
- **Attestation binding:** epoch and log public keys are signed by the attested
  `EnclaveIdentity` and carry the measurement (§5.1).
- **Constant-time / misuse-resistance:** rely on RustCrypto/@noble constant-time ops; random
  nonces (XChaCha) remove nonce-reuse foot-guns; AEAD provides integrity.
- **Cross-language byte-exact test vectors:** pin `seal`/`unseal` and key-derivation vectors
  across Rust (enclave/archive/prover) and TS (browser), exactly like the existing
  commitment / receipt-digest vectors in `docs/DECISIONS.md`. This is the production gate.

---

## 8. Testing strategy

**Unit (`sealed-box`):** roundtrip; tamper → AEAD reject; wrong recipient key → reject; AAD
mismatch → reject; ephemeral-key uniqueness; version-byte handling.

**Cross-language vectors:** fixed seed + fixed ephemeral (test hook) → identical `SealedBox`
bytes; Rust-sealed decrypts in TS and vice-versa.

**Note archive:** owner scan finds exactly their notes; a `view_sk`-only holder reads but
`spend_key` is still required to produce a nullifier (view/spend split holds); a party with
neither key sees only ciphertext.

**Order ingress:** client-sealed order decrypts + matches in the enclave; unknown/expired
epoch rejected; tampered ciphertext rejected; **depth still published**; caller-signed order
signature still verified post-decrypt; production mode refuses plaintext ingress.

**Order log:** append + chain integrity; `log_head` equals the value folded into the manifest;
tamper detected; audit/prover key decrypts, others cannot.

**Integration / e2e (testnet):** register → fetch + verify enclave epoch key → sealed order →
match → depth visible → sealed note in archive → scan/recover with view key → withdraw/claim
unaffected. Negative: operator with no keys observes only ciphertext end-to-end.

---

## 9. Sequencing & relationship to the ZK verifier

This spec is the **privacy/encryption** workstream. The **real ZK verifier (SP1/Risc0)** is
the **next and final mainnet gate**, tracked separately, and is intentionally **out of scope
here**. The two connect at exactly one seam:

- The **encrypted order log (Piece 3) is the prover witness.** Its format, the
  attested-measurement key release, and the `log_head` manifest anchoring are designed so the
  ZK circuit can consume the log to prove matching/ordering determinism without revealing
  plaintext on-chain.
- Nothing in this design blocks the verifier swap: on-chain still sees only roots +
  commitments; replacing `MockZkVerifier` with a real verifier is orthogonal to encryption.

**Recommended order:** (1) `sealed-box` core + vectors → (2) note encryption → (3) order
ingress → (4) order log → **(5, separate spec) real ZK verifier**, consuming the log witness.

---

## 10. Open questions / risks

- **`@noble` bundle size / SRI:** confirm the added browser deps stay small and are pinned
  (the frontend currently ships zero crypto deps). Mitigation: import only the needed
  submodules.
- **Epoch key sealing on reboot:** the epoch key is derived from `ENCLAVE_SEED`; a reboot that
  re-pins the measurement must not change the *derivation* (seed-based, not
  measurement-based) — same guarantee the state snapshot already relies on.
- **Scan cost at scale:** trial-decryption is O(archive). The detection-tag optimization (§4)
  is the escape hatch if it bites.
- **Detection-tag privacy:** if added, ensure the tag does not leak linkability across an
  account's notes (derive per-note, not per-account-static).
```
