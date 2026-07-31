# SEC-025-E2 — a sealed resting order cannot be cancelled

**Status:** design. Second of four in the 025-E decomposition. Small, and it is what makes E1's
cancel wiring actually do something.

**Do not deploy from this spec.** Merge only.

---

## The gap

`Gw::account_cancel` (`crates/gateway/src/main.rs:2770`) refuses any order carrying
`sealed == true`. Every order becomes sealed within one 700 ms tick (`main.rs:3829`).

With no house market maker funding orders in production, **resting is the normal case** — so
`DELETE /v1/orders/:id` is dead exactly where it matters. A user cannot withdraw a quote they
no longer want at that price.

The primitive already exists and works: `MatchingEngine::cancel_order`
(`crates/matcher/src/lib.rs:86`) has exactly one caller today — SEC-022's ban loop, which uses
it to remove an offending maker from the rematch base.

## Why "sealed" is the wrong gate

`sealed` means *this order has been handed to a `seal_batch` call*, not *this order is finished*.
The two diverge permanently the moment an order rests: the gateway stops tracking it while the
matcher's book keeps it live across batches and windows. `sealed` is a submission marker being
read as a lifecycle state.

A cancel should be refused when the order is **not live in the book** — which the matcher can
answer and the gateway currently cannot.

## Scope

- Let a cancel reach the resting book for an order that is sealed but still live, routing to
  `MatchingEngine::cancel_order`.
- Give the cancellation a **manifest entry**, so it is provable. A cancel that leaves no
  on-chain record puts the user in the same position as the silent removals E3 documents: an
  enclave receipt, no visible outcome, and an inclusion challenge as the only apparent move —
  which forfeits their bond.
- Refuse on a genuine "not live" (already filled, already cancelled, expired, never existed)
  with a reason the caller can act on, distinct from today's blanket `sealed` refusal.

## The ordering hazard, which is the whole difficulty

The sequencer is **replayed in-circuit**. A cancel racing a fill in the same tick must resolve
identically in the gateway and in the guest, or the window's derived roots diverge from the
proof's and the settle breaks at `settleBatch`.

So the cancel cannot be applied as a side effect at the moment the HTTP request arrives. It has
to enter the same ordered stream the fills do, and be a `BatchOp` the replay sees — or be
applied at a tick boundary where no fill can be interleaved. **Decide which explicitly**: the
first is more invasive (`crates/perp-core` changes move the vkey) and the second constrains
latency. This spec does not pick, because the choice needs the sequencer's tick structure read
carefully first, and a wrong guess here is a settle-breaking bug rather than a UX one.

**Whichever is chosen, it must be stated why the race cannot produce divergence** — not asserted
that it does not.

## What this does NOT fix

- **It does not make the order's status visible.** After a successful cancel the order still
  reports `ACCEPTED` with `filled = 0`, because `Finality` has no terminal variant for it. That
  is E3, and until E3 lands a user who cancels sees the same silence as a user whose order was
  banned.
- **It does not touch the three silent book removals** (self-trade prevention, resting expiry
  reap, liquidation cancel-all). Those need the same manifest treatment and are E3's.

## What must be tested

1. A resting, sealed order **can** be cancelled, and the size leaves the book. Must fail before
   the fix.
2. The cancellation appears in the manifest, so it is provable — assert the entry, not just the
   absence from the book.
3. A cancel for an order that is genuinely not live is refused with the specific reason, not the
   blanket one.
4. **The race:** a cancel and a fill for the same order in one tick produce the same result in
   a replay as in the live sequencer. This is the test that matters; the others are ordinary.
   If it cannot be written against the current tick structure, that is a finding about the
   design choice above, not a reason to ship without it.
