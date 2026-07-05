use sealed_box::*;

#[derive(serde::Deserialize)]
struct Vec1 {
    recipient_ikm: String,
    recipient_info: String,
    esk: String,
    nonce: String,
    domain: u8,
    aad_extra: String,
    plaintext: String,
    sealed_hex: String,
}
fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn cross_language_vector() {
    let v: Vec1 =
        serde_json::from_str(include_str!("../../../tests/fixtures/sealed-box-vectors.json"))
            .unwrap();
    let (_, rpk) = x25519_keypair_from_ikm(&h(&v.recipient_ikm), &h(&v.recipient_info));
    let aad = domain_aad(v.domain, &h(&v.aad_extra));
    let esk: [u8; 32] = h(&v.esk).try_into().unwrap();
    let nonce: [u8; 24] = h(&v.nonce).try_into().unwrap();
    let sb = seal_with_ephemeral(&rpk, &h(&v.plaintext), &aad, &esk, &nonce);
    let got = hex::encode(sb.to_bytes());
    if v.sealed_hex == "PIN_AFTER_FIRST_RUN" {
        eprintln!("PIN THIS into sealed-box-vectors.json: {got}");
        panic!("vector not pinned");
    }
    assert_eq!(got, v.sealed_hex);
}
