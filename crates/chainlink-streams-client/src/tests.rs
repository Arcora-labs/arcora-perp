//! Public synthetic fixtures only. No account, credential file or external service.
use super::*;
use serde_json::{json, Value};

pub(crate) const NOW: u64 = 100_000;
pub(crate) const USER: &str = "12345678-1234-1234-1234-123456789abc";
pub(crate) const SECRET: &[u8] = b"synthetic-secret-do-not-use";
pub(crate) fn credentials() -> Credentials {
    Credentials::new(Network::Testnet, USER.into(), SECRET.to_vec()).unwrap()
}
pub(crate) fn feed() -> FeedId {
    FeedId::parse_v3(&format!("0x0003{}", "11".repeat(30))).unwrap()
}
pub(crate) fn request() -> Request {
    Request::new(Network::Testnet, feed(), 10_000).unwrap()
}
fn word(n: u64) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
pub(crate) fn full_report() -> Vec<u8> {
    // Canonical ABI container with deliberately FAKE nonzero signature words.
    // Syntax acceptance never establishes DON authenticity.
    let mut full = vec![0; 672];
    for (i, n) in [(3, 224), (4, 544), (5, 608), (7, 288), (17, 1), (19, 1)] {
        full[i * 32..(i + 1) * 32].copy_from_slice(&word(n));
    }
    full[256..288].copy_from_slice(&feed().bytes());
    for (i, n) in [
        (1, 100),
        (2, 100),
        (5, 160),
        (6, 6_000_000_000_000),
        (7, 5_999_900_000_000),
        (8, 6_000_100_000_000),
    ] {
        full[256 + i * 32..256 + (i + 1) * 32].copy_from_slice(&word(n));
    }
    full[576..608].fill(0x11);
    full[640..672].fill(0x22);
    full
}
pub(crate) fn value() -> Value {
    json!({"report": {"feedID":feed().hex(),"validFromTimestamp":100,
        "observationsTimestamp":100,"fullReport":format!("0x{}",hex(&full_report()))}})
}
pub(crate) fn response() -> Vec<u8> {
    serde_json::to_vec(&value()).unwrap()
}
fn parse(v: &Value) -> Result<UnverifiedReport> {
    parse_response(&serde_json::to_vec(v).unwrap(), &request(), NOW)
}

#[test]
fn hmac_matches_independent_python_hashlib_vector() {
    // Computed with Python stdlib hmac/hashlib using the documented single-space
    // METHOD PATH EMPTY_BODY_SHA256 USER TIMESTAMP input. Not a Chainlink response.
    assert_eq!(
        credentials()
            .sign_get(&request().path(), NOW)
            .unwrap()
            .as_str(),
        "8d4c0cc73a3f73e3c35c9bc545a626d8f448ce9c0b7c73e13bb7f9c2e93bba37"
    );
    assert_eq!(
        credentials()
            .sign_get(&request().path(), NOW + 1)
            .unwrap()
            .as_str(),
        "3bcb0a665bcb7b0c23a6d461a6fddfee97a17d47ad2c4d37a25fdeffdff9d5e5"
    );
}
#[test]
fn hmac_binds_path_identity_time_and_secret_without_demo_fallback() {
    let c = credentials();
    let original = c.sign_get(&request().path(), NOW).unwrap();
    assert_ne!(
        *original,
        *c.sign_get("/api/v1/reports/latest?feedID=changed", NOW)
            .unwrap()
    );
    let other_user =
        Credentials::new(Network::Testnet, USER.replace('a', "b"), SECRET.to_vec()).unwrap();
    assert_ne!(
        *original,
        *other_user.sign_get(&request().path(), NOW).unwrap()
    );
    let other_secret = Credentials::new(
        Network::Testnet,
        USER.into(),
        b"other-synthetic-secret".to_vec(),
    )
    .unwrap();
    assert_ne!(
        *original,
        *other_secret.sign_get(&request().path(), NOW).unwrap()
    );
    assert_eq!(c.sign_get(&request().path(), 0).unwrap_err(), Error::Clock);
}
#[test]
fn credentials_reject_missing_malformed_and_header_injection_values() {
    for user in [
        "",
        "not-a-uuid",
        "12345678_1234-1234-1234-123456789abc",
        "12345678-1234-1234-1234-123456789abz",
        "\r\nAuthorization: injected",
    ] {
        assert_eq!(
            Credentials::new(Network::Testnet, user.into(), SECRET.to_vec()).unwrap_err(),
            Error::Credentials
        );
    }
    for secret in [vec![], vec![1; 4097]] {
        assert_eq!(
            Credentials::new(Network::Testnet, USER.into(), secret).unwrap_err(),
            Error::Credentials
        );
    }
    assert!(Credentials::new(Network::Mainnet, USER.to_uppercase(), vec![1; 4096]).is_ok());
}
#[test]
fn credential_debug_is_redacted_and_errors_do_not_contain_input() {
    let printed = format!("{:?}", credentials());
    assert!(!printed.contains(USER));
    assert!(!printed.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(printed.contains("REDACTED"));
    let error = parse_response(b"private-provider-sentinel", &request(), NOW).unwrap_err();
    assert!(!error.to_string().contains("private-provider-sentinel"));
}
#[test]
fn networks_and_feed_path_are_explicit_not_response_selected() {
    assert_eq!(
        Network::Testnet.origin(),
        "https://api.testnet-dataengine.chain.link"
    );
    assert_eq!(
        Network::Mainnet.origin(),
        "https://api.dataengine.chain.link"
    );
    assert_ne!(Network::Mainnet.origin(), Network::Testnet.origin());
    assert_eq!(
        request().path(),
        format!("/api/v1/reports/latest?feedID={}", feed().hex())
    );
    assert_eq!(
        FeedId::parse_v3(&feed().hex().replace("11", "AA"))
            .unwrap()
            .hex(),
        feed().hex().replace("11", "aa")
    );
    for bad in [
        "".to_owned(),
        "0x0003".into(),
        "0X".to_owned() + &feed().hex()[2..],
        feed().hex().replace("0003", "0002"),
        feed().hex() + "&feedID=other",
        format!("0x0003{}", "gg".repeat(30)),
    ] {
        assert!(FeedId::parse_v3(&bad).is_err());
    }
    assert_eq!(
        Request::new(Network::Testnet, feed(), 0).unwrap_err(),
        Error::Stale
    );
}
#[test]
fn original_full_report_and_source_times_survive_parsing_exactly() {
    let report = parse(&value()).unwrap();
    assert_eq!(report.full_report(), full_report());
    assert_eq!(report.body().0, full_report()[256..544]);
    assert_eq!(report.decoded().observations, 100);
    assert_eq!(report.received_ms(), NOW);
    assert_eq!(report.network(), Network::Testnet);
    // Nonzero fake signature words passed syntax only: type remains UnverifiedReport.
    assert_eq!(report.full_report()[576], 0x11);
}
#[test]
fn stale_future_zero_and_queue_delay_are_not_restamped() {
    assert!(parse_response(&response(), &request(), NOW + 10_000).is_ok());
    for t in [0, NOW - 1, NOW + 10_001, u64::MAX] {
        assert_eq!(
            parse_response(&response(), &request(), t).unwrap_err(),
            Error::Stale
        );
    }
    let report = parse(&value()).unwrap();
    assert_eq!(
        report.check_freshness(NOW + 10_001, 10_000),
        Err(Error::Stale)
    );
    assert_eq!(report.check_freshness(NOW, 0), Err(Error::Stale));
    assert_eq!(report.check_freshness(160_001, u64::MAX), Err(Error::Stale));
    assert_eq!(report.decoded().observations, 100);
}
#[test]
fn outer_metadata_cannot_override_abi_feed_or_timestamp() {
    for field in ["validFromTimestamp", "observationsTimestamp"] {
        let mut v = value();
        v["report"][field] = json!(99);
        assert_eq!(parse(&v).unwrap_err(), Error::Metadata);
    }
    let mut v = value();
    v["report"]["feedID"] = json!(feed().hex().replace("11", "22"));
    assert_eq!(parse(&v).unwrap_err(), Error::Metadata);
    let mut full = full_report();
    full[258] = 0x22;
    let mut v = value();
    v["report"]["fullReport"] = json!(format!("0x{}", hex(&full)));
    assert_eq!(parse(&v).unwrap_err(), Error::Metadata);
}
#[test]
fn critical_fields_are_required_and_strictly_typed() {
    for field in [
        "feedID",
        "fullReport",
        "validFromTimestamp",
        "observationsTimestamp",
    ] {
        let mut v = value();
        v["report"].as_object_mut().unwrap().remove(field);
        assert_eq!(parse(&v).unwrap_err(), Error::Json);
        for wrong in [json!(null), json!(true), json!([]), json!({})] {
            let mut v = value();
            v["report"][field] = wrong;
            assert_eq!(parse(&v).unwrap_err(), Error::Json);
        }
    }
    for field in ["validFromTimestamp", "observationsTimestamp"] {
        for wrong in [json!("100"), json!(100.0), json!(-1), json!(u64::MAX)] {
            let mut v = value();
            v["report"][field] = wrong;
            assert_eq!(parse(&v).unwrap_err(), Error::Json);
        }
    }
    for v in [
        json!({}),
        json!({"report":[]}),
        json!({"report":null}),
        json!([]),
    ] {
        assert_eq!(parse(&v).unwrap_err(), Error::Json);
    }
}
#[test]
fn duplicate_critical_fields_including_escaped_names_are_rejected() {
    let source = String::from_utf8(response()).unwrap();
    for (old, new) in [
        ("\"report\":", "\"report\":{},\"report\":"),
        ("\"feedID\":", "\"feedID\":\"ignored\",\"feedID\":"),
        (
            "\"fullReport\":",
            "\"fullReport\":\"ignored\",\"fullReport\":",
        ),
        (
            "\"validFromTimestamp\":100",
            "\"validFromTimestamp\":100,\"validFromTimestamp\":100",
        ),
        (
            "\"observationsTimestamp\":100",
            "\"observationsTimestamp\":100,\"\\u006fbservationsTimestamp\":100",
        ),
    ] {
        assert!(source.contains(old));
        assert_eq!(
            parse_response(source.replacen(old, new, 1).as_bytes(), &request(), NOW).unwrap_err(),
            Error::Json
        );
    }
}
#[test]
fn trailing_invalid_utf8_and_nonfinite_json_are_rejected() {
    for bytes in [
        b"NaN".to_vec(),
        b"Infinity".to_vec(),
        vec![0xff],
        [response(), b"{}".to_vec()].concat(),
    ] {
        assert_eq!(
            parse_response(&bytes, &request(), NOW).unwrap_err(),
            Error::Json
        );
    }
    let mut v = value();
    v["metadata"] = json!({"future-compatible":true});
    assert!(parse(&v).is_ok());
}
#[test]
fn report_hex_abi_offsets_and_signature_syntax_are_bounded() {
    for bad in [
        "".into(),
        "0x0".into(),
        "0xgg".into(),
        "ff".repeat(MAX_FULL_REPORT + 1),
    ] {
        let mut v = value();
        v["report"]["fullReport"] = json!(bad);
        assert!(parse(&v).is_err());
    }
    for index in [96, 127, 159, 191, 192, 576, 640] {
        let mut b = full_report();
        if index == 576 || index == 640 {
            b[index..index + 32].fill(0);
        } else {
            b[index] = 0xff;
        }
        let mut v = value();
        v["report"]["fullReport"] = json!(hex(&b));
        assert!(parse(&v).is_err(), "invalid offset/signature index {index}");
    }
}
#[test]
fn response_byte_limit_is_inclusive_and_applies_before_decode() {
    let mut exact = response();
    exact.resize(MAX_RESPONSE_BYTES, b' ');
    assert!(parse_response(&exact, &request(), NOW).is_ok());
    exact.push(b' ');
    assert_eq!(
        parse_response(&exact, &request(), NOW).unwrap_err(),
        Error::ResponseTooLarge
    );
}
