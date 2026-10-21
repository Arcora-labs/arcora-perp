#!/usr/bin/env python3
"""Verify a committed real clock-bound Groth16 proof in an owned local EVM.

Two identities are pinned separately and never stand in for each other:

* REVIEWED_GUEST / REVIEWED_FIXTURE: the guest program this checkout must build
  (sources, ELF, setup key) and the outputs of its reviewed normal fixture.
* PROOF_FIXTURE: the committed real proof that the Solidity gate verifies.

The forge environment's setup key and public commitment, and the identity in the
evidence, come only from PROOF_FIXTURE; the proof bytes are the verified
artifact's own. proof_status() reads the committed proof files from disk and is
PROVEN only when they pass the same validation and are the committed proof of
the reviewed fixture under the reviewed guest; otherwise it is PENDING_REPROOF.
Release creation and deployment to a chain that is not an owned test chain
require PROVEN.

This new-development guest pin does not replace the legacy production release pin.
No live RPC, deployment, mock proof, or artifact-selected guest identity is allowed.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from types import MappingProxyType
import verify_real_proof as target

PROVEN = "PROVEN"
PENDING_REPROOF = "PENDING_REPROOF"
SDK_VERSION = "6.1.0"
CLOCK_ARTIFACTS = ("proof-evidence.json", "clock.witness.bin", "guest.elf", "program-vkey.bin",
                   "proof.bin", "public-values.bin", "proof.sdk.json")

# The guest program the checkout is reviewed to build. Its independently pinned
# source inputs mean a supplied proof manifest cannot choose a different program
# and still pass. `identity_dir` holds that program's ELF and setup key.
REVIEWED_GUEST = {
    "elf": "a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df",
    "vkey": "0x009cfc02120c4255b1a8c3eebbcc31f92a9ce0891c88641e78e0af23aae098ec",
    "identity_dir": "contracts/integration/fixtures/clock-pkg3-reviewed",
    "sources": {
        "Cargo.toml": "e3144a0ae3447244776e65b04cfff39267c238e410c2d9abf20b53e6b837bbfa",
        "crates/perp-core/Cargo.toml": "3bfb6981fa34a967185ce75abd07683e5262a694ebd60eb45a4f5c55aaf9704c",
        "crates/perp-core/src/clock.rs": "1d936a79121040bb6415cff2aa0e0459734222bfbf8c7f4452d52452389f85a2",
        "crates/perp-core/src/commitment.rs": "02ccf0ead5b545fc6b06948df5f5cd31c4126b417bf5097c972f725e412fa801",
        "crates/perp-core/src/engine.rs": "e42c15a7ef7473b6ba15faea7aa0a974b1799cc525802159edc0a48ec32794aa",
        "crates/perp-core/src/error.rs": "d1e146386deb79870fd288732265347bd207b91c153633c079e42ec7c63a8c20",
        "crates/perp-core/src/fixed.rs": "6d5a39e6d4c9facada98d0dba398990efb8db1bc9705d0dc58f86b6333fd69c2",
        "crates/perp-core/src/funding.rs": "d3f393138b31ed843a24c63943fb15ec0f07a860ac629ce1ca15feb40d93fea9",
        "crates/perp-core/src/hash.rs": "88430a8c2558b247bcf241035ad48fa1dbf8a3e77a0d176dfdbd608c930f93b9",
        "crates/perp-core/src/lib.rs": "d69657981bfd0d7f8e97230e7f0cbcf0d548d9fa5b69e8fb1c941864db1e9d50",
        "crates/perp-core/src/market.rs": "8053e89a9b1021d6e461d46d733dfb1935aff5fc2a45be8121f96560fa4ddc2d",
        "crates/perp-core/src/merkle.rs": "2cbddc2a07b738dbe6ede79e447acfa6ab68499036ca48db50e53f9a97890ad2",
        "crates/perp-core/src/note.rs": "5cece4d513537c10464bd64b4612f829cd32cb9c1a80d3c8e40c573aace62423",
        "crates/perp-core/src/nullifier.rs": "c396e40e5d757849e507d60be6b0fbab34443f1fb0d6e091feff047fad3544a8",
        "crates/perp-core/src/oracle.rs": "91ae09655e35432aafa1135b23588d6f1f324b41a278ac640ebc30f106d17da2",
        "crates/perp-core/src/order.rs": "38f1321b773e5ca2f7978059381059340e67011750faac253af4fb21382c712f",
        "crates/perp-core/src/position.rs": "c56b36e5adf77300eae6f237d04260aa25f535bf730b566a17c16e07e121e821",
        "crates/perp-core/src/state.rs": "fcb6719b4f91f95e2dce88166cd80302144c049b97a3edab085e66353d2aea55",
        "crates/sp1-guest/Cargo.lock": "6352cf76bf63ed1a0dfd44e54aa9832cfc1c67b9facb6ce3396270f2d15fff33",
        "crates/sp1-guest/Cargo.toml": "c4310424be580e30f351f98644e47211dc286c2c020f6d81c1967cd6343a2bd6",
        "crates/sp1-guest/src/main.rs": "8dc8437f4f3938fa430efc43e27b7ffcdd0ab4447462db036a08afef92d2fa9a",
    },
}

# Expected outputs of the reviewed guest on its normal fixture: the witness, the
# bound public commitment, each rejected negative witness, and the case witnesses,
# each {"witness_sha256", "commitment"} by case name. All of them are the outputs
# of `clock-proof --elf <identity_dir>/guest.elf --no-prove`, committed under
# identity_dir; check_reviewed_guest_execution.py re-executes them on CPU in CI.
REVIEWED_FIXTURE = {
    "witness_sha256": "70b90edcb2cf4e673053ca91b3b811865ca917388ff28a9a0aa696b740f5fa4a",
    "commitment": "0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab",
    "negatives": {
        "wrong-bounds": "cb9174c67eccb190aa94f952e62ac767acfa1bd51356923eddbefac2cd57fd6b",
        "wrong-count": "c0e211d721459f6076a68fb94044eccad767a52dcb87283604a3a27ae374e81e",
        "wrong-batch": "d308e98fea20da6c25f77b0a75d5182763581c386c86fe09938e3d0a91314520",
        "wrong-base": "2d118241670e93d3b46cd9be4f711986a5bd43345dc7c3c87220f4950bde59c5",
        "backdated": "b94ee21774e8047f32d95e5c12293bbbd87139f36d3de32ab62b13a7fe36d4b3",
        "bad-manifest": "c572b38d672a01dadd99f428310fd8b5c75a7ff8e6537268b0731df6725c0314",
        "unauthorized-withdrawal": "765b222c711697700dc39942c5fa60c3bde7e4042bbe7195dd471135bd32135e",
        "market-id-not-map-key": "849dc44beff8bb3c1d4f8a4a941575f9da12cfbcee7613b7fe5cc27cc75408b0",
        "forged-nullifier-log": "fb483e26e9b4619e3fb76858845f2e9e4f3418c37df7ad856a2aa53bb57909af",
        "erased-tree-history": "94a7c18009573fd98fc0e4760300a44a0697e7aea6813afc996af9252c7fb473",
        "depth-64-tree": "dfa78adb977a6a1b932acaf4b31dea7801e63d0531fa7e27df612aa660c4aa56",
        "overfull-tree": "70d0601451d4932a3eed02dee991bd5ffa8291daf8b4e62d4fb0def01ff7553a",
        "duplicate-withdrawal-nonce": "9d288f47546f1d75a3ddf8177ec702a8b014884070416faeb08e34c09cb6902b",
        "unfunded-dust-fill": "406037b43dd759a5ba263b415aacb42eef0fd6877791112dea2b2248f1d94769",
        "under-floor-fill": "31433a9d6ecff1f58ee643a060b572f0e832c7d7fc31fd39440e6759073339bc",
        "deposit-in-close-only": "3f79ad7ea77105bb9f71f63a56ff1b2903944a9151ad795fb94e362c9b56f678",
        "legacy-tuple": "1dde2f621b7d6f04fc910e5b61015315fedb51de4a36d40cbee55ab4c344f929",
        "empty-input": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "seven-byte-magic": "c9b279fdf496b7b8306d1dd2b4d354a7056f3f178434dc7bcffc4b570378dcde",
        "dpclk2-magic": "b842e66fde09c47c99312091f79d236931b57a50907eda8366911f37041816a6",
        "dpclk3-magic": "061cc6adfc6e5c5262b2ff0d6c9d274f49a9d19b81b5fdb0e00ae4462a52af26",
        "trailing-byte": "2f46c18bd27c21be3342c047f455cba2278272ac3b28b1ede0bbb18d1045d552",
    },
    "cases": {
        "epoch-price-refresh": {"witness_sha256": "b83319577b2db742eb13f6939a078ed8b7f0d93ddd2dcb8e2397b6b20827f5e7",
                                "commitment": "0xd1d933cad0323ca4b7a0dca2017da7b7a6007f4bfc4e6e4fd57f8be72c9f15d2"},
        "pause-reopen-fill": {"witness_sha256": "a4759a507b6945bc7c2fc812096475fbe02794b38a428ce3f10c753e5a2904ea",
                              "commitment": "0x6bec4bfbe9e7d2dd917f402502556d6e3d854105cdd293dbde2b46cbc2501cea"},
        "bad-debt-treasury-adl": {"witness_sha256": "5e9e4268cf9a9a5487191282419b3289ee11e24201e6a07d9975afbc577c559f",
                                  "commitment": "0x05d29866e9ebf45f62aec2f7e16c2c94a85a2a32a91ddfddd00d540d16564db8"},
        "debt-top-up-prune": {"witness_sha256": "4cdb2225a4136ea06e1b8c8b39b9416bd81dbcee3785cecc50e4cb9447e3898c",
                              "commitment": "0xcb0c459aa520bc736e9cd88405ae59daf4dd1b466a797c475c2574d81883b032"},
        "debt-top-up-next-batch": {"witness_sha256": "c9becc2b21847c1b0efd3854dc934ecdad2a7d90b9f6956fc1f82f22666be559",
                                   "commitment": "0xb813ecfd08db2557ec763e2ffb6ec335f45044b906e61fe2a92fa1f882e68f66"},
        "full-exit-prune": {"witness_sha256": "ce73e851598af145075a36bdf19c29a3ab6fd23129b57c7ada3c9b0e37d98a00",
                            "commitment": "0x6fb83abf2a8f2e17f3785ed6b11ab978848fe53e22e32ece14f30782cfe0ab12"},
        "empty-keepalive": {"witness_sha256": "5a95daffab5531f5aa2a400a392be7f5dbbaca11da4b3b43c9ea95c4ec1a29ce",
                            "commitment": "0x5045303a589c01e45d962855ee6639ae4f4a38f34985dd0a554e3cf9111e043a"},
        "settle-all-two-markets": {"witness_sha256": "fa7c07195d89b5ace497336f611a2d4032be4c44704b5af35de9f96385bfe07f",
                                   "commitment": "0xedc4c0a86b495f1cdbcb00636ed96faca085f9710cc868e0a2336780762b8aa7"},
        "phase-two-exit": {"witness_sha256": "6b0690c798b55ce5b3e2fd14b8253af158428ccce7039c24bac04de9bb117a01",
                           "commitment": "0xbf98b0229914a4654ba1f53aa49dad00169aae718d430bb4464fc0bc50b714b4"},
    },
}

# Frozen record of the clock-v2 guest source pins as first reviewed. Provenance
# only: it is never compared with the checkout.
HISTORICAL_V2_GUEST_SOURCES = MappingProxyType({
    "Cargo.toml": "e3144a0ae3447244776e65b04cfff39267c238e410c2d9abf20b53e6b837bbfa",
    "crates/perp-core/Cargo.toml": "3bfb6981fa34a967185ce75abd07683e5262a694ebd60eb45a4f5c55aaf9704c",
    "crates/perp-core/src/clock.rs": "e89e50e11b3ffb3a4a1a89ab6dd4854b61606cc17eb1236492994df0b59d50e7",
    "crates/perp-core/src/commitment.rs": "43582ef5048d0d725e53976e3c2a1dfcf32984ed2ad1bb2ebd2032463e26ea92",
    "crates/perp-core/src/engine.rs": "4d6037f1189939a71a41e31882012e6fa50b887087b5ccc2bfce4502b61d0f9e",
    "crates/perp-core/src/error.rs": "0738da822be5639737e67f04a0f500af57fcc1f085dd64bec7fbe3b016c515c6",
    "crates/perp-core/src/fixed.rs": "fc77559a31c1cfdd7a641cafbd773871aeb203849e165dbd158aa7a1b65ef7cd",
    "crates/perp-core/src/funding.rs": "8f782cf3a4403c717eda44c6d2955789c31e4ef2a04bb4fdac8e61916018e781",
    "crates/perp-core/src/hash.rs": "88430a8c2558b247bcf241035ad48fa1dbf8a3e77a0d176dfdbd608c930f93b9",
    "crates/perp-core/src/lib.rs": "8f070fbec0f4b3d3fab5e594bcf808845803a59ece403dc42cb0f0df6e6253b5",
    "crates/perp-core/src/market.rs": "8053e89a9b1021d6e461d46d733dfb1935aff5fc2a45be8121f96560fa4ddc2d",
    "crates/perp-core/src/merkle.rs": "173f4667178ba4aa4048e43c2aeb9fa337918d6225b98c6597c004b59bc3a8f6",
    "crates/perp-core/src/note.rs": "5cece4d513537c10464bd64b4612f829cd32cb9c1a80d3c8e40c573aace62423",
    "crates/perp-core/src/nullifier.rs": "a252799c62dc42ec37c91ba6fd7674117b33c98c7f83e86b168f70898966ea78",
    "crates/perp-core/src/oracle.rs": "91ae09655e35432aafa1135b23588d6f1f324b41a278ac640ebc30f106d17da2",
    "crates/perp-core/src/order.rs": "99bb9b2be4948bcf8365c3022ef444be5941201ec6535de73d45a777e5a206d7",
    "crates/perp-core/src/position.rs": "99d120139086092d2dae4ed11d3a677906c1cf3efd7aff9e58f27f3437f2ae66",
    "crates/perp-core/src/state.rs": "e1026c1e2b56cfcbee4eff812e88ff3dcde052e46818deab980a071fcdbec388",
    "crates/sp1-guest/Cargo.lock": "113518cb212208aa46a629608af9d946f9a4006ac211035a15e9cb8c022fb8c3",
    "crates/sp1-guest/Cargo.toml": "d0ed7050076bb3548b9e3410f63066068752382f4dab31e344096c9c3e42dc85",
    "crates/sp1-guest/src/main.rs": "c0d33ff8645ebdcc8994d4d65729b8a60a224bcda18415423da15ed875c16f5c",
})


# The guest source pins the package-3 proof was generated under (the reviewed pins
# when it was proven, 2026-10-21). Provenance only: never compared with the checkout.
PKG3_PROOF_GUEST_SOURCES = MappingProxyType({
    "Cargo.toml": "e3144a0ae3447244776e65b04cfff39267c238e410c2d9abf20b53e6b837bbfa",
    "crates/perp-core/Cargo.toml": "3bfb6981fa34a967185ce75abd07683e5262a694ebd60eb45a4f5c55aaf9704c",
    "crates/perp-core/src/clock.rs": "1d936a79121040bb6415cff2aa0e0459734222bfbf8c7f4452d52452389f85a2",
    "crates/perp-core/src/commitment.rs": "02ccf0ead5b545fc6b06948df5f5cd31c4126b417bf5097c972f725e412fa801",
    "crates/perp-core/src/engine.rs": "e42c15a7ef7473b6ba15faea7aa0a974b1799cc525802159edc0a48ec32794aa",
    "crates/perp-core/src/error.rs": "d1e146386deb79870fd288732265347bd207b91c153633c079e42ec7c63a8c20",
    "crates/perp-core/src/fixed.rs": "6d5a39e6d4c9facada98d0dba398990efb8db1bc9705d0dc58f86b6333fd69c2",
    "crates/perp-core/src/funding.rs": "d3f393138b31ed843a24c63943fb15ec0f07a860ac629ce1ca15feb40d93fea9",
    "crates/perp-core/src/hash.rs": "88430a8c2558b247bcf241035ad48fa1dbf8a3e77a0d176dfdbd608c930f93b9",
    "crates/perp-core/src/lib.rs": "d69657981bfd0d7f8e97230e7f0cbcf0d548d9fa5b69e8fb1c941864db1e9d50",
    "crates/perp-core/src/market.rs": "8053e89a9b1021d6e461d46d733dfb1935aff5fc2a45be8121f96560fa4ddc2d",
    "crates/perp-core/src/merkle.rs": "2cbddc2a07b738dbe6ede79e447acfa6ab68499036ca48db50e53f9a97890ad2",
    "crates/perp-core/src/note.rs": "5cece4d513537c10464bd64b4612f829cd32cb9c1a80d3c8e40c573aace62423",
    "crates/perp-core/src/nullifier.rs": "c396e40e5d757849e507d60be6b0fbab34443f1fb0d6e091feff047fad3544a8",
    "crates/perp-core/src/oracle.rs": "91ae09655e35432aafa1135b23588d6f1f324b41a278ac640ebc30f106d17da2",
    "crates/perp-core/src/order.rs": "38f1321b773e5ca2f7978059381059340e67011750faac253af4fb21382c712f",
    "crates/perp-core/src/position.rs": "c56b36e5adf77300eae6f237d04260aa25f535bf730b566a17c16e07e121e821",
    "crates/perp-core/src/state.rs": "fcb6719b4f91f95e2dce88166cd80302144c049b97a3edab085e66353d2aea55",
    "crates/sp1-guest/Cargo.lock": "6352cf76bf63ed1a0dfd44e54aa9832cfc1c67b9facb6ce3396270f2d15fff33",
    "crates/sp1-guest/Cargo.toml": "c4310424be580e30f351f98644e47211dc286c2c020f6d81c1967cd6343a2bd6",
    "crates/sp1-guest/src/main.rs": "8dc8437f4f3938fa430efc43e27b7ffcdd0ab4447462db036a08afef92d2fa9a",
})


# The committed real proof and the identity it was generated under. The Solidity
# real-proof gate verifies exactly this proof; it says nothing about another guest.
# `sources` are the source pins of that proof's own guest, recorded beside its ELF
# in the evidence (provenance only; the checkout is checked against REVIEWED_GUEST).
PROOF_FIXTURE = {
    "dir": "contracts/integration/fixtures/clock-pkg3-verified",
    "kind": "clock-pkg3-native-guest",
    "elf": "a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df",
    "vkey": "0x009cfc02120c4255b1a8c3eebbcc31f92a9ce0891c88641e78e0af23aae098ec",
    "witness_sha256": "70b90edcb2cf4e673053ca91b3b811865ca917388ff28a9a0aa696b740f5fa4a",
    "commitment": "0x6e382af92ac5b4872e4a1f6c0f6bdf6d1a246bb2ca6f834dc7aeb3748edab5ab",
    "proof_sha256": "28d6804949242eac9a44e0d90542674a4e3325c15fbac30f258215505e6084db",
    "negatives": {
        "wrong-bounds": "cb9174c67eccb190aa94f952e62ac767acfa1bd51356923eddbefac2cd57fd6b",
        "wrong-count": "c0e211d721459f6076a68fb94044eccad767a52dcb87283604a3a27ae374e81e",
        "wrong-batch": "d308e98fea20da6c25f77b0a75d5182763581c386c86fe09938e3d0a91314520",
        "wrong-base": "2d118241670e93d3b46cd9be4f711986a5bd43345dc7c3c87220f4950bde59c5",
        "backdated": "b94ee21774e8047f32d95e5c12293bbbd87139f36d3de32ab62b13a7fe36d4b3",
        "bad-manifest": "c572b38d672a01dadd99f428310fd8b5c75a7ff8e6537268b0731df6725c0314",
        "unauthorized-withdrawal": "765b222c711697700dc39942c5fa60c3bde7e4042bbe7195dd471135bd32135e",
        "market-id-not-map-key": "849dc44beff8bb3c1d4f8a4a941575f9da12cfbcee7613b7fe5cc27cc75408b0",
        "forged-nullifier-log": "fb483e26e9b4619e3fb76858845f2e9e4f3418c37df7ad856a2aa53bb57909af",
        "erased-tree-history": "94a7c18009573fd98fc0e4760300a44a0697e7aea6813afc996af9252c7fb473",
        "depth-64-tree": "dfa78adb977a6a1b932acaf4b31dea7801e63d0531fa7e27df612aa660c4aa56",
        "overfull-tree": "70d0601451d4932a3eed02dee991bd5ffa8291daf8b4e62d4fb0def01ff7553a",
        "duplicate-withdrawal-nonce": "9d288f47546f1d75a3ddf8177ec702a8b014884070416faeb08e34c09cb6902b",
        "unfunded-dust-fill": "406037b43dd759a5ba263b415aacb42eef0fd6877791112dea2b2248f1d94769",
        "under-floor-fill": "31433a9d6ecff1f58ee643a060b572f0e832c7d7fc31fd39440e6759073339bc",
        "deposit-in-close-only": "3f79ad7ea77105bb9f71f63a56ff1b2903944a9151ad795fb94e362c9b56f678",
        "legacy-tuple": "1dde2f621b7d6f04fc910e5b61015315fedb51de4a36d40cbee55ab4c344f929",
        "empty-input": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "seven-byte-magic": "c9b279fdf496b7b8306d1dd2b4d354a7056f3f178434dc7bcffc4b570378dcde",
        "dpclk2-magic": "b842e66fde09c47c99312091f79d236931b57a50907eda8366911f37041816a6",
        "dpclk3-magic": "061cc6adfc6e5c5262b2ff0d6c9d274f49a9d19b81b5fdb0e00ae4462a52af26",
        "trailing-byte": "2f46c18bd27c21be3342c047f455cba2278272ac3b28b1ede0bbb18d1045d552",
    },
    "sources": PKG3_PROOF_GUEST_SOURCES,
}

def verify_guest_source():
    """Require the checkout's guest inputs to equal REVIEWED_GUEST's source pins."""
    sources = REVIEWED_GUEST["sources"]
    for name, digest in sources.items():
        path = target.ROOT / name
        target.require(path.is_file() and not path.is_symlink(), f"missing/nonregular guest source: {name}")
        target.require(target.sha256(path.read_bytes()) == digest, f"guest source changed; rebuild and reprove: {name}")
    return dict(sources)


def read_clock_artifacts(directory):
    files = {}
    for name in CLOCK_ARTIFACTS:
        path = directory / name
        target.require(not path.is_symlink() and path.is_file(), f"missing/nonregular clock artifact: {name}")
        target.require(path.stat().st_size <= 64 * 1024 * 1024, f"oversized artifact: {name}")
        files[name] = path.read_bytes()
    return files


def check_evidence(manifest):
    """Kind, SDK and verification fields of a committed proof's evidence record."""
    target.require(manifest.get("kind") == PROOF_FIXTURE["kind"], PROOF_FIXTURE["kind"] + " evidence required")
    target.require(manifest.get("sdk_version") == SDK_VERSION, "wrong SP1 SDK")
    for field in ("proof_generated", "native_guest_equal"):
        target.require(manifest.get(field) is True, f"incomplete proof evidence: {field}")
    sdk_verified = manifest.get("local_sdk_verified") is True
    rust_verified = (manifest.get("rust_sp1_verifier_verified") is True
                     and manifest.get("rust_verifier_version") == SDK_VERSION)
    target.require(sdk_verified or rust_verified, "incomplete proof evidence: cryptographic verification")


def check_sdk_proof(files):
    sdk = json.loads(files["proof.sdk.json"])
    target.require(isinstance(sdk, dict) and str(sdk.get("sp1_version", "")).removeprefix("v") == SDK_VERSION,
                   "wrong SDK proof version")


def load_clock_proof(directory):
    """Validate a proof artifact directory against PROOF_FIXTURE and return its forge inputs.

    The evidence, ELF, setup key, witness, public values and rejected negatives must
    be PROOF_FIXTURE's. The proof bytes are the artifact's own: their shape and
    verifier selector are checked here and their cryptography by the forge suites,
    so a re-wrapped proof of the same fixture is verified, not refused by its hash.
    """
    files = read_clock_artifacts(directory.resolve())
    manifest = json.loads(files["proof-evidence.json"])
    target.require(isinstance(manifest, dict), "invalid proof evidence")
    check_evidence(manifest)
    target.require(files["guest.elf"].startswith(b"\x7fELF"), "actual guest ELF required")
    target.require(target.sha256(files["guest.elf"]) == PROOF_FIXTURE["elf"], "wrong rebuilt clock guest")
    target.require(manifest.get("elf_sha256") == PROOF_FIXTURE["elf"], "ELF evidence mismatch")
    target.require(target.sha256(files["clock.witness.bin"]) == PROOF_FIXTURE["witness_sha256"],
                   "wrong signed-clock fixture")
    target.require(manifest.get("witness_sha256") == PROOF_FIXTURE["witness_sha256"], "witness evidence mismatch")
    target.require("0x" + files["program-vkey.bin"].hex() == PROOF_FIXTURE["vkey"], "wrong setup vkey")
    target.require(manifest.get("program_vkey") == PROOF_FIXTURE["vkey"], "vkey evidence mismatch")
    target.require("0x" + files["public-values.bin"].hex() == PROOF_FIXTURE["commitment"], "wrong public digest")
    target.require(manifest.get("commitment") == PROOF_FIXTURE["commitment"], "native digest mismatch")
    proof = files["proof.bin"]
    check_proof_shape(proof)
    check_sdk_proof(files)
    expected = PROOF_FIXTURE["negatives"]
    negatives = manifest.get("negatives", [])
    target.require(isinstance(negatives, list) and len(negatives) == len(expected)
                   and all(isinstance(n, dict) and isinstance(n.get("name"), str) for n in negatives)
                   and {n["name"] for n in negatives} == set(expected),
                   "clock guest negative set incomplete")
    target.require(all(n.get("guest_exit") == 1 and n.get("public_bytes") == 0 for n in negatives),
                   "guest rejection evidence incomplete")
    target.require(all(n.get("witness_sha256") == expected[n["name"]] for n in negatives),
                   "guest rejection witness mismatch")
    return files, forge_environment(proof)


def check_proof_shape(proof):
    target.require(len(proof) == 356 and proof[:4].hex() == target.VERIFIER_HASH[:8], "wrong Groth16 shape/selector")


def forge_environment(proof):
    """The real-proof suites' inputs: PROOF_FIXTURE's key and commitment, and the given proof bytes."""
    check_proof_shape(proof)
    return {"ARCORA_REAL_PROGRAM_VKEY": PROOF_FIXTURE["vkey"],
            "ARCORA_REAL_PUBLIC_COMMITMENT": PROOF_FIXTURE["commitment"],
            "ARCORA_REAL_PROOF": "0x" + proof.hex()}


def proof_status(root=None):
    """PROVEN only if the committed proof files on disk are a proof of the reviewed fixture.

    Every value is read from PROOF_FIXTURE["dir"]; editing a dict alone never
    changes the status. Required: the files pass load_clock_proof (the validation
    verify_clock_proof applies: evidence kind, SDK and verification fields, recorded
    identity, ELF, setup key, witness, public values, proof shape and the rejected
    negatives), the proof is the committed one (PROOF_FIXTURE["proof_sha256"]), the
    ELF and setup key equal REVIEWED_GUEST, and the witness and public values equal
    REVIEWED_FIXTURE.
    """
    root = target.ROOT if root is None else Path(root)
    try:
        files, _ = load_clock_proof(root / PROOF_FIXTURE["dir"])
        on_disk = (target.sha256(files["guest.elf"]), "0x" + files["program-vkey.bin"].hex(),
                   target.sha256(files["clock.witness.bin"]), "0x" + files["public-values.bin"].hex())
        proven = (target.sha256(files["proof.bin"]) == PROOF_FIXTURE["proof_sha256"]
                  and on_disk == (REVIEWED_GUEST["elf"], REVIEWED_GUEST["vkey"],
                                  REVIEWED_FIXTURE["witness_sha256"], REVIEWED_FIXTURE["commitment"]))
    except (ValueError, KeyError, OSError, UnicodeError):
        return PENDING_REPROOF
    return PROVEN if proven else PENDING_REPROOF


# Recorded next to `scope` in the real-proof evidence files.
IDENTITY_SCOPE = ("The forge suites verify the proof under PROOF_FIXTURE's setup key and public commitment. "
                  "The top-level guest fields (ELF, setup key, source pins) and proof_fixture describe that "
                  "proof's own guest; reviewed_guest and the reviewed_guest_source(s)_sha256 pins describe the guest "
                  "this checkout is pinned to build, which is the proof's guest only if "
                  "proof_matches_reviewed_guest is true.")


def proof_matches_reviewed_guest():
    return (PROOF_FIXTURE["elf"], PROOF_FIXTURE["vkey"]) == (REVIEWED_GUEST["elf"], REVIEWED_GUEST["vkey"])


def identities():
    """Both identities, recorded side by side in every real-proof evidence file."""
    return {"proof_fixture": {"dir": PROOF_FIXTURE["dir"], "kind": PROOF_FIXTURE["kind"],
                              "guest_elf_sha256": PROOF_FIXTURE["elf"], "program_vkey": PROOF_FIXTURE["vkey"],
                              "guest_sources_sha256": dict(PROOF_FIXTURE["sources"]),
                              "witness_sha256": PROOF_FIXTURE["witness_sha256"],
                              "public_commitment": PROOF_FIXTURE["commitment"],
                              "proof_sha256": PROOF_FIXTURE["proof_sha256"]},
            "reviewed_guest": {"identity_dir": REVIEWED_GUEST["identity_dir"],
                               "guest_elf_sha256": REVIEWED_GUEST["elf"], "program_vkey": REVIEWED_GUEST["vkey"],
                               "fixture_witness_sha256": REVIEWED_FIXTURE["witness_sha256"],
                               "fixture_commitment": REVIEWED_FIXTURE["commitment"]},
            "proof_matches_reviewed_guest": proof_matches_reviewed_guest(),
            "real_proof_status": proof_status()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, default=target.ROOT / PROOF_FIXTURE["dir"],
                        help="the committed proof's directory (default: PROOF_FIXTURE's)")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    verify_guest_source()
    vendor = target.verify_vendor()
    files, proof_env = load_clock_proof(args.artifact_dir)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(proof_env)
    env["FOUNDRY_PROFILE"] = "default"
    target.run(["forge", "build", "--root", str(target.VENDOR)], output, "upstream-build", env)
    env["FOUNDRY_PROFILE"] = "real_proof"
    raw = target.run(["forge", "test", "--root", str(target.CONTRACTS), "--match-contract",
                      "(SP1Real(VerifierGuard|Proof)Test|ClockBoundRealProofTest)", "--json"], output, "real-target-tests", env)
    counts = {}
    for suite_name, suite in json.loads(raw).items():
        name = suite_name.rsplit(":", 1)[-1]
        results = suite["test_results"]
        target.require(all(t["status"] == "Success" for t in results.values()), f"failed/skipped suite: {name}")
        counts[name] = len(results)
    target.require(counts == {"SP1RealVerifierGuardTest": 8, "SP1RealProofTest": 10, "ClockBoundRealProofTest": 6}, "missing actual target suites")
    compiled = {
        "upstream_verifier": target.compiled_identity(Path("out/sp1-upstream/SP1VerifierGroth16.sol/SP1Verifier.json")),
        "upstream_gateway": target.compiled_identity(Path("out/sp1-upstream/SP1VerifierGateway.sol/SP1VerifierGateway.json")),
        "sp1_adapter": target.compiled_identity(Path("out/SP1ZkVerifier.sol/SP1ZkVerifier.json")),
        "clock_adapter": target.compiled_identity(Path("out/ClockBoundVerifier.sol/ClockBoundVerifier.json")),
        "settlement": target.compiled_identity(Path("out/DarkPerpSettlement.sol/DarkPerpSettlement.json")),
        "vault": target.compiled_identity(Path("out/CollateralVault.sol/CollateralVault.json")),
    }
    for name, identity in compiled.items():
        expected = "0.8.20+" if name.startswith("upstream_") else "0.8.24+"
        target.require(identity["compiler"].startswith(expected), f"unexpected compiler: {name}")
    paths = [Path(__file__), target.ROOT / "scripts/local-verification/verify_real_proof.py"]
    paths += sorted((target.CONTRACTS / "integration").glob("*.sol"))
    paths += [target.CONTRACTS / "src" / name for name in
              ("SP1ZkVerifier.sol", "ClockBoundVerifier.sol", "DarkPerpSettlement.sol", "CollateralVault.sol")]
    checked_sources = {str(path.relative_to(target.ROOT)): target.sha256(path.read_bytes()) for path in paths}
    report = {"status": "PASS", "kind": "clock-v2-real-sp1-target-verification", "local_evm_only": True,
              "mock_proof_used": False, "production_deployed": False, "full_token_lifecycle": False,
              "clock_adapter_full_lifecycle": False, "clock_adapter_synthetic_settlement_verified": True, "synthetic_vault_claim_verified": True, "mock_token_used": True, "fixture_address_constructors": True, "synthetic_zero_payer_impersonated": True, "application_proof_accepted": True,
              "scope": "Real clock-v2 proof through SP1 verifier, clock adapter, actual settlement and vault; fixed synthetic addresses and a mock token, not live payer provenance or full order/HTTP/production lifecycle.",
              "identity_scope": IDENTITY_SCOPE,
              "guest_elf_sha256": PROOF_FIXTURE["elf"], "program_vkey": PROOF_FIXTURE["vkey"],
              "public_commitment": PROOF_FIXTURE["commitment"], "tests": counts,
              **identities(),
              "input_artifacts": {name: {"sha256": target.sha256(data), "size_bytes": len(data)} for name, data in files.items()},
              "runner_sha256": target.sha256(Path(__file__).read_bytes()),
              # The existing key pairs with guest_elf_sha256: the proof's own guest. The
              # checkout's pins (verified above) are under the reviewed record's name.
              "guest_sources_sha256": dict(PROOF_FIXTURE["sources"]),
              "reviewed_guest_sources_sha256": dict(REVIEWED_GUEST["sources"]), "source_sha256": checked_sources,
              "compiled_contracts": compiled, "vendor_upstreams": vendor["upstreams"]}
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
        print(f"Clock target verification refused: {error}", file=sys.stderr)
        sys.exit(1)
