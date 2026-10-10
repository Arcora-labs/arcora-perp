use super::*;
use crate::crosscheck::{CrosscheckGate, CrosscheckPolicy};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};
const NOW: u64 = 1_000_000;
fn key() -> SigningKey {
    SigningKey::from_slice(&[0x33; 32]).unwrap()
}
fn pair() -> SpotPair {
    SpotPair::new("BTC", "USDT").unwrap()
}
fn valid() -> Value {
    json!({"code":"0","msg":"","data":[{"instType":"SPOT",
    "instId":"BTC-USDT","last":"100.01","bidPx":"100","askPx":"100.02","ts":"999900"}]})
}
fn crypto() -> Vec<u8> {
    serde_json::to_vec(&json!({"code":0,"method":"public/get-tickers",
    "result":{"data":[{"i":"BTC_USDT","a":"100","b":"99.99","k":"100.01","t":999800}]}}))
    .unwrap()
}
fn parse(v: &Value) -> Result<SourceTick, String> {
    parse_okx_spot_response(&serde_json::to_vec(v).unwrap(), &pair(), NOW, 0, &key())
}
#[test]
fn okx_exact_spot_identity_and_source_timestamp_preserved() {
    let s = parse(&valid()).unwrap();
    assert_eq!(
        s.transcript,
        transcript_from_ticker("100.01", "100", "100.02", NOW - 100, 0, &key()).unwrap()
    );
    assert_eq!(s.exchange, Exchange::Okx);
}
#[test]
fn wrong_status_count_kind_base_or_quote_never_falls_back() {
    for (field, value) in [
        ("code", json!(0)),
        ("code", json!("1")),
        ("msg", json!("error")),
        ("data", json!([])),
        ("data", json!([{}, {}])),
    ] {
        let mut v = valid();
        v[field] = value;
        assert!(parse(&v).is_err());
    }
    for (field, values) in [
        ("instType", vec!["SWAP", "MARGIN", "FUTURES", "spot"]),
        (
            "instId",
            vec!["BTC-USDC", "BTC-USD", "ETH-USDT", "BTC-USDT-SWAP"],
        ),
    ] {
        for value in values {
            let mut v = valid();
            v["data"][0][field] = json!(value);
            assert!(parse(&v).is_err());
        }
    }
}
#[test]
fn required_fields_wrong_types_books_and_timestamps_rejected() {
    for field in ["instType", "instId", "last", "bidPx", "askPx", "ts"] {
        let mut v = valid();
        v["data"][0].as_object_mut().unwrap().remove(field);
        assert!(parse(&v).is_err());
        for value in [json!(null), json!(true), json!(1), json!({}), json!([])] {
            let mut v = valid();
            v["data"][0][field] = value;
            assert!(parse(&v).is_err());
        }
    }
    for ts in [
        "0",
        "1000001",
        "+999900",
        "-1",
        "999900.0",
        " 999900",
        "18446744073709551616",
    ] {
        let mut v = valid();
        v["data"][0]["ts"] = json!(ts);
        assert!(parse(&v).is_err());
    }
    for field in ["last", "bidPx", "askPx"] {
        for price in ["", "0", "-1", "--1", "NaN", "1e2"] {
            let mut v = valid();
            v["data"][0][field] = json!(price);
            assert!(parse(&v).is_err());
        }
    }
    let mut v = valid();
    v["data"][0]["bidPx"] = json!("101");
    assert!(parse(&v).is_err());
}
#[test]
fn critical_duplicates_escaped_names_trailing_and_oversized_json_rejected() {
    let source = serde_json::to_string(&valid()).unwrap();
    for (old, new) in [
        ("\"code\":\"0\"", "\"code\":\"0\",\"code\":\"0\""),
        ("\"msg\":\"\"", "\"msg\":\"\",\"msg\":\"\""),
        ("\"data\":", "\"data\":[],\"data\":"),
        (
            "\"ts\":\"999900\"",
            "\"ts\":\"999900\",\"\\u0074s\":\"999900\"",
        ),
    ] {
        assert!(source.contains(old));
        assert!(parse_okx_spot_response(
            source.replacen(old, new, 1).as_bytes(),
            &pair(),
            NOW,
            0,
            &key()
        )
        .is_err());
    }
    for field in ["instType", "instId", "last", "bidPx", "askPx"] {
        let val = serde_json::to_string(&valid()["data"][0][field]).unwrap();
        let old = format!("\"{field}\":{val}");
        let new = format!("{old},{old}");
        assert!(source.contains(&old));
        assert!(parse_okx_spot_response(
            source.replacen(&old, &new, 1).as_bytes(),
            &pair(),
            NOW,
            0,
            &key()
        )
        .is_err());
    }
    let mut bytes = source.into_bytes();
    bytes.extend_from_slice(b"{}");
    assert!(parse_okx_spot_response(&bytes, &pair(), NOW, 0, &key()).is_err());
    bytes.resize(live::TICKER_LIMIT + 1, b' ');
    assert!(parse_okx_spot_response(&bytes, &pair(), NOW, 0, &key()).is_err());
    for bad in [b"NaN".as_slice(), b"Infinity", b"private-sentinel", b"\xff"] {
        let error = parse_okx_spot_response(bad, &pair(), NOW, 0, &key()).unwrap_err();
        assert!(!error.contains("private-sentinel"));
    }
}
fn wire(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{extra}\r\n").into_bytes();
    v.extend_from_slice(body);
    v
}
fn response(body: &[u8]) -> Vec<u8> {
    wire(
        "200 OK",
        &format!("Content-Length: {}\r\n", body.len()),
        body,
    )
}
fn serve(bytes: Vec<u8>, stall: bool) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/ticker", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let start = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_secs(3) =>
                {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return String::new(),
            }
        };
        // macOS may inherit O_NONBLOCK from the listening socket; explicitly
        // restore blocking I/O before applying per-stream read/write deadlines.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                return String::new();
            }
            header.push(byte[0]);
            assert!(header.len() < 8192);
        }
        let _ = stream.write_all(&bytes);
        if stall {
            thread::sleep(Duration::from_millis(800));
        }
        String::from_utf8(header).unwrap()
    });
    (url, task)
}
fn fetch_with_secondary(
    secondary: Vec<u8>,
    stall: bool,
) -> Result<(SourceTick, SourceTick), String> {
    let (p, pt) = serve(response(&crypto()), false);
    let (s, st) = serve(secondary, stall);
    let result = fetch_pair_at(
        &pair(),
        NOW,
        0,
        &key(),
        &p,
        &s,
        if stall {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        },
    );
    let primary_request = pt.join().unwrap();
    let secondary_request = st.join().unwrap();
    assert!(
        primary_request.starts_with("GET /ticker?instrument_name=BTC_USDT "),
        "request={primary_request:?}, result={result:?}"
    );
    assert!(
        secondary_request.starts_with("GET /ticker?instId=BTC-USDT "),
        "request={secondary_request:?}, result={result:?}"
    );
    result
}
#[test]
fn real_two_loopback_sources_feed_same_production_request_path() {
    let (p, s) =
        fetch_with_secondary(response(&serde_json::to_vec(&valid()).unwrap()), false).unwrap();
    let mut m = perp_core::Market::conservative(0);
    m.oracle_pubkey = crate::signer_address(&key());
    let mut gate = CrosscheckGate::new(pair(), 0, CrosscheckPolicy::new(1_000).unwrap());
    assert_eq!(gate.accept(&p, &s, &m, NOW).unwrap(), p.transcript);
}
#[test]
fn real_second_source_errors_identity_and_partial_body_do_not_yield_primary_success() {
    let mut wrong = valid();
    wrong["data"][0]["instId"] = json!("BTC-USDC");
    for bytes in [
        wire("503 Unavailable", "Content-Length: 0\r\n", b""),
        response(&serde_json::to_vec(&wrong).unwrap()),
        wire("200 OK", "Content-Length: 100\r\n", b"{}"),
        response(b"private-sentinel"),
    ] {
        let error = fetch_with_secondary(bytes, false).unwrap_err();
        assert!(!error.contains("private-sentinel"));
    }
}
#[test]
fn real_second_source_missing_transport_or_stalled_body_fails_closed() {
    assert!(fetch_with_secondary(wire("200 OK", "Content-Length: 100\r\n", b"{"), true).is_err());
    let (p, pt) = serve(response(&crypto()), false);
    let missing = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ticker", missing.local_addr().unwrap());
    // Keep this owned listener bound but unaccepted: a released ephemeral port
    // could be reused by another parallel test (or an unrelated local service).
    assert!(fetch_pair_at(
        &pair(),
        NOW,
        0,
        &key(),
        &p,
        &url,
        Duration::from_millis(500)
    )
    .is_err());
    pt.join().unwrap();
}
#[test]
fn real_second_source_declared_eof_and_chunked_size_limits_apply() {
    let huge = vec![b' '; live::TICKER_LIMIT + 1];
    let mut chunk = format!("{:x}\r\n", huge.len()).into_bytes();
    chunk.extend_from_slice(&huge);
    chunk.extend_from_slice(b"\r\n0\r\n\r\n");
    for bytes in [
        response(&huge),
        wire("200 OK", "", &huge),
        wire("200 OK", "Transfer-Encoding: chunked\r\n", &chunk),
    ] {
        assert!(fetch_with_secondary(bytes, false).is_err());
    }
}
#[test]
fn real_second_source_redirect_never_contacts_target() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let bytes = wire(
        "302 Found",
        &format!(
            "Location: http://{}/forbidden\r\nContent-Length: 0\r\n",
            target.local_addr().unwrap()
        ),
        b"",
    );
    assert!(fetch_with_secondary(bytes, false).is_err());
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn primary_failure_does_not_contact_secondary_or_return_partial_pair() {
    let (p, pt) = serve(wire("500 Error", "Content-Length: 0\r\n", b""), false);
    let secondary = TcpListener::bind("127.0.0.1:0").unwrap();
    secondary.set_nonblocking(true).unwrap();
    let url = format!("http://{}/ticker", secondary.local_addr().unwrap());
    assert!(fetch_pair_at(
        &pair(),
        NOW,
        0,
        &key(),
        &p,
        &url,
        Duration::from_millis(500)
    )
    .is_err());
    pt.join().unwrap();
    assert_eq!(
        secondary.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
