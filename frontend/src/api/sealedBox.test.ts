import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import { x25519KeypairFromIkm, domainAad, sealWithEphemeral, unseal } from "./sealedBox";

const hx = (s: string) => hexToBytes(s);

// CRYPTO MERGE GATE: this suite reads the SAME fixture the Rust side pinned
// (tests/fixtures/sealed-box-vectors.json, produced by a REAL Rust run). The
// fixture is the source of truth — if these tests fail, fix the TS mirror,
// never the fixture.
describe("sealed-box cross-language parity", () => {
  const v = JSON.parse(
    readFileSync(new URL("../../../tests/fixtures/sealed-box-vectors.json", import.meta.url), "utf8"),
  );

  it("produces the pinned Rust ciphertext byte-for-byte", () => {
    const { public: rpk } = x25519KeypairFromIkm(hx(v.recipient_ikm), hx(v.recipient_info));
    const aad = domainAad(v.domain, hx(v.aad_extra));
    const wire = sealWithEphemeral(rpk, hx(v.plaintext), aad, hx(v.esk), hx(v.nonce));
    expect(bytesToHex(wire)).toBe(v.sealed_hex);
  });

  it("unseals a Rust-sealed box", () => {
    const { secret } = x25519KeypairFromIkm(hx(v.recipient_ikm), hx(v.recipient_info));
    const aad = domainAad(v.domain, hx(v.aad_extra));
    const pt = unseal(secret, hx(v.sealed_hex), aad);
    expect(pt && bytesToHex(pt)).toBe(v.plaintext);
  });

  it("unseal fails closed (null, no throw) on tamper, AAD mismatch, and low-order epk", () => {
    const { secret } = x25519KeypairFromIkm(hx(v.recipient_ikm), hx(v.recipient_info));
    const aad = domainAad(v.domain, hx(v.aad_extra));

    // Tag/ciphertext tamper → null (matches Rust None).
    const tampered = hx(v.sealed_hex);
    tampered[57] ^= 0xff;
    expect(unseal(secret, tampered, aad)).toBeNull();

    // AAD mismatch → null.
    expect(unseal(secret, hx(v.sealed_hex), domainAad(v.domain, new Uint8Array([0x00])))).toBeNull();

    // Low-order (all-zero) epk: @noble getSharedSecret THROWS here, while Rust
    // computes a zero shared secret and fails AEAD → None. The widened
    // try/catch in unseal must convert the throw to null, not propagate it.
    const zeroEpk = hx(v.sealed_hex);
    zeroEpk.fill(0, 1, 33);
    expect(unseal(secret, zeroEpk, aad)).toBeNull();
  });

  it("domainAad rejects a non-byte domain tag instead of truncating mod 256", () => {
    // 284 & 0xff === 28 (OrderEncryptAad): silent truncation would collide two
    // distinct "domains" — it must throw, matching the 1-byte wire contract.
    expect(() => domainAad(284, new Uint8Array())).toThrow(RangeError);
    expect(() => domainAad(-1, new Uint8Array())).toThrow(RangeError);
    expect(() => domainAad(1.5, new Uint8Array())).toThrow(RangeError);
    expect(() => domainAad(256, new Uint8Array())).toThrow(RangeError);
    // the full byte range stays accepted
    expect(domainAad(0, new Uint8Array([9]))).toEqual(new Uint8Array([0, 9]));
    expect(domainAad(255, new Uint8Array())).toEqual(new Uint8Array([255]));
  });
});
